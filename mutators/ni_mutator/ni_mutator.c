#include "ni_mutator.h"
#include <mutators.h>

#include <utils.h>
#include <jansson_helper.h>
#include <global_types.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//Uncomment this line to make the killerbeez ni mutator use the same random number generator
//as ni and take the seed value from the $RANDSEED environment variable. This is useful when
//comparing the output of this mutator against the ni executable to ensure their behavior
//matches
//#define NI_COMPARISON_TESTING

typedef struct sample {
	char * content;
	int length;
} sample_t;

struct ni_state
{
	char * input;
	size_t input_length;

	//Protects the fields below, i.e. the iteration count, mutate buffer information, and random state
	mutex_t mutate_mutex;

	int iteration;
	uint8_t * mutated_buffer;
	uint64_t mutated_buffer_length;
	uint64_t max_mutated_buffer_length;

	uint64_t random_state[2];
	char ** sample_filenames;
	size_t num_samples;
	sample_t ** samples;
};
typedef struct ni_state ni_state_t;

mutator_t ni_mutator = {
	FUNCNAME(create),
	FUNCNAME(cleanup),
	FUNCNAME(mutate),
	FUNCNAME(mutate_extended),
	FUNCNAME(get_state),
	ni_free_state,
	FUNCNAME(set_state),
	FUNCNAME(get_current_iteration),
	ni_get_total_iteration_count,
	FUNCNAME(get_input_info),
	FUNCNAME(set_input),
	FUNCNAME(help)
};

////////////////////////////////////////////////////////////////////////////////////////////
//// Ni mutator methods ////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

#define RAND(state,x)    ((x)?(rnd(state)%(x)):0)

/*
 * xoroshiro128plus by David Blackman and Sebastiano Vigna
 */
static inline uint64_t util_RotL(const uint64_t x, int k)
{
	return (x << k) | (x >> (64 - k));
}

static inline uint64_t rnd64(ni_state_t * state) {
	const uint64_t s0 = state->random_state[0];
	uint64_t s1 = state->random_state[1];
	const uint64_t result = s0 + s1;
	s1 ^= s0;
	state->random_state[0] = util_RotL(s0, 55) ^ s1 ^ (s1 << 14);
	state->random_state[1] = util_RotL(s1, 36);
	return result;
}

/**
 * This function generates a positive random number
 * @param state - a mutator specific structure previously created by the create function.
 * @return the randomly generated number
 */
static inline long long rnd(ni_state_t * state) {
#ifdef NI_COMPARISON_TESTING
	//If testing to compare output against the ni binary, use random()
	return random(); //instead of our own random number generator
#else
	long long r = rnd64(state);
	if (r < 0) r = -r;
	return r;
#endif
}

/**
 * This function returns a fresh copy of the input buffer or a sample provided by the
 * mutator options.
 * @param state - a mutator specific structure previously created by the create function.
 * @param index - The index of the sample file to retrieve. To retrieve the input buffer,
 * specify -1 for the index.
 * @param len - A pointer to a size_t used to return the length of the retrieved buffer
 * @return A pointer to the copy of the input buffer or sample
 */
static char * get_sample(ni_state_t * state, int index, size_t *len)
{
	char * content, * copy;
	size_t length;

	if(index < 0) {
		length = state->input_length;
		content = state->input;
	} else {
		length = state->samples[index]->length;
		content = state->samples[index]->content;
	}
	copy = malloc(length);
	memcpy(copy, content, length);
	*len = length;
	return copy;
}

/**
 * This function picks a random sample provided by the mutator options or the input buffer
 * and returns a copy to it.
 * @param state - a mutator specific structure previously created by the create function.
 * @param len - A pointer to a size_t used to return the length of the retrieved buffer
 * @return A pointer to the copy of the input buffer or sample
 */
static char * get_random_sample(ni_state_t * state, size_t *len)
{
	int index = RAND(state, state->num_samples + 1);
	if(index == state->num_samples)
		return get_sample(state, -1, len);
	return get_sample(state, index, len);
}

/*
 * This code in this section below was taken from the ni mutator, available
 * at: https://github.com/aoh/ni . The ni project does not provide a
 * license for this code.
 *
 * It has been modified from the original to suit the purposes of this
 * project.
 */

#define AIMROUNDS  256
#define AIMAX      512
#define AIMLEN     1024
#define MIN(a, b)  (((a) < (b)) ? a : b)
#define BUFSIZE    4096

static char * random_block(ni_state_t * state, size_t orig_len, size_t * new_len) {
	size_t sample_len, start, len;
	char * sample, * block;

	sample = get_random_sample(state, &sample_len);
	if(sample_len < 3) {
		free(sample);
		return NULL;
	}

	start = RAND(state,sample_len-2);
	len = sample_len - start;
	if (len > 4 * orig_len)
		len = 4 * orig_len;
	len = RAND(state,len);
	len = MIN(len, sample_len - start);

	block = malloc(len);
	memcpy(block, sample + start, len);
	*new_len = len;
	free(sample);
	return block;
}

static void write_all(ni_state_t * state, const char *data, size_t n) {
	size_t num_bytes = MIN(n, state->max_mutated_buffer_length - state->mutated_buffer_length);
	if(num_bytes != 0) {
		memcpy(state->mutated_buffer + state->mutated_buffer_length, data, num_bytes);
		state->mutated_buffer_length += num_bytes;
	}
}

static void output_num(ni_state_t * state, char *buff, size_t buflen, long long n) {
	int negp = 0;
	if (n < 0) {
		n *= -1;
		negp = 1;
	}
	if (n == 0) {
		buff[0] = '0';
		write_all(state, buff, 1);
	} else {
		size_t p = buflen - 1;
		while(n && p) {
			buff[p--] = n % 10 + '0';
			n /= 10;
		}
		if (negp || !(rnd(state)&63))
			buff[p--] = '-';
		p++;
		write_all(state, buff + p, buflen - p);
	}
}

static int sufscore(const char *a, size_t al, const char *b, size_t bl) {
	int last = 256;
	int n = 0;
	while(al-- && bl-- && *a == *b && n < AIMAX) {
		if (*a != last)
			n += 32;
		last = *a++;
		b++;
	}
	return n;
}

/* note, could have a separate aimer for runs */
static void aim(ni_state_t * state, const char *from, size_t fend, const char *to, size_t tend, size_t *jump, size_t *land) {
	size_t j, l;
	int best_score = 0, score, rounds = 0;
	if (!fend) {
		*jump = 0;
		*land = tend ? RAND(state,tend) : 0;
		return;
	}
	*jump = RAND(state,fend);
	if (!tend) {
		*land = 0;
		return;
	}
	*land = RAND(state,tend);
	rounds = RAND(state,AIMROUNDS);
	score = 0;
	while(rounds--) {
		int maxs = AIMLEN;
		j = RAND(state,fend);
		l = RAND(state,tend);
		while(maxs-- && l < tend && from[j] != to[l]) {
			l++;
		}
		score = sufscore(from + j, fend - j, to + l, tend - l);
		if (score > best_score) {
			best_score = score;
			*jump = j;
			*land = l;
		}
	}
}

static int delim_of(char c) {
	int d = 0;
	switch(c) {
		//case '"': d = '"'; break;
		case '<': d = '>'; break;
		case '\n': d = '\n'; break;
		case '(': d = ')'; break;
		case '[': d = ']'; break;
		case '{': d = '}'; break;
		//case '\'': d = '\''; break;
		//case ' ': d = ' '; break;
		//case ',': d = ','; break;
	}
	return d;
}

static int drange_start(ni_state_t * state, const char *pos, size_t end, size_t *start, char *open, char *close) {
	int rounds = 32;
	while (rounds--) {
		size_t o = RAND(state, end);
		int n = AIMLEN;
		o = RAND(state, o+1); /* prefer beginning */
		while(o < end && n--) {
			char c = pos[o], d;
			if (c & 128)
				return 1;
			d = delim_of(c);
			if (d) {
				*start = o; *open = c; *close = d;
				return 0;
			}
			o++;
		}
	}
	return 1;
}

static int drange_start_of(ni_state_t * state, const char *pos, size_t end, char del, size_t *start) {
	int rounds = 32;
	while (rounds--) {
		size_t o = RAND(state, end);
		int n = AIMLEN;
		while(o < end && n--) {
			char c = pos[o];
			if (c & 128) {
				return 1;
			} else if (c == del) {
				*start = o;
				return 0;
			} else {
				o++;
			}
		}
	}
	return 1;
}

/* return 0 for failure, called after open  */
static size_t drange_end(ni_state_t * state, const char *data, size_t end, size_t pos, char open, char close) {
	int depth = 1;
	while(pos < end) {
		char c = data[pos++];
		if (c == close) {
			depth--;
			if (depth == 0) {
				size_t next;
				if (rnd(state) & 3)
					return pos;
				next = drange_end(state, data, end, pos, open, close);
				if (next)
					return next;
				return pos;
			}
		} else if (c == open) {
			depth++;
		} else if (c & 128) {
			return 0;
		}
	}
	return 0;
}

static int drange(ni_state_t * state, const char *data, size_t end, size_t *rs, size_t *rl) {
	size_t s, e;
	char o, c;
	if (drange_start(state, data, end, &s, &o, &c))
		return 1;
	e = drange_end(state, data, end, s+1, o, c);
	if (e) {
		*rs = s;
		*rl = e - s;
		return 0;
	}
	return 1;
}

static int other_drange(ni_state_t * state, const char *data, size_t end, size_t fs, size_t *r2s, size_t *r2l) {
	char open = data[fs];
	char close = delim_of(open);
	int tries = 10;
	size_t os = fs;
	while(tries--) {
		if (drange_start_of(state, data, end, open, &os))
			return 1;
		if (os != fs) {
			size_t oe = drange_end(state, data, end, os+1, open, close);
			if (oe) {
				*r2s = os;
				*r2l = oe - os;
				return 0;
			}
		}
	}
	return 1;
}

static void seek_num(ni_state_t * state, const char *pos, size_t end, size_t *ns, size_t *ne) {
	size_t o = RAND(state, end);
	while(o < end && (pos[o] < '0' || pos[o] > '9')) {
		if (pos[o] & 128)
			return;
		o++;
	}
	if (o == end)
		return;
	*ns = o++;
	while(o < end && pos[o] >= '0' && pos[o] <= '9') {
		o++;
	}
	*ne = o;
}

static int read_num(const char *pos, size_t end, long long *res) {
	long long n = 0;
	size_t p = 0;
	while(p < end) {
		n = n * 10 + pos[p++] - '0';
		if (n < 0)
			return 1;
	}
	*res = n;
	return 0;
}

static long long twiddle(ni_state_t * state, long long val) {
	do {
		switch(RAND(state,3)) {
			case 0:
				val = rnd(state);
				break;
			case 1:
				val ^= (1 << RAND(state,sizeof(long long)*8 - 1));
				break;
			case 2:
				val += RAND(state,5) - 2;
				break;
		}
	} while (rnd(state) & 1);
	return(val);
}

static void mutate_area(ni_state_t * state, const char *data, size_t end) {
	char buff[BUFSIZE];
	int choice;
retry:
	choice = rnd(state) % 35;
	switch(choice) {
		case 0: { /* insert a random byte */
			size_t pos = (end ? rnd(state) % end : 0);
			write_all(state, data, pos);
			buff[0] = rnd(state) & 255;
			write_all(state, buff, 1);
			write_all(state, data + pos, end - pos);
			break;
		}
		case 1: { /* drop a byte */
			size_t pos = (end ? rnd(state) % end : 0);
			if (pos+1 >= end)
				goto retry;
			write_all(state, data, pos);
			write_all(state, data+pos+1, end-(pos+1));
			break;
		}
		case 2:
		case 3: { /* jump in a sequence */
			size_t s, e;
			if (!end)
				goto retry;
			s = rnd(state) % end;
			e = rnd(state) % end;
			if (s == e)
				goto retry;
			write_all(state, data, e);
			write_all(state, data+s, end-s);
			break;
		}
		case 4:
		case 5: { /* repeat */
			size_t a, b, s, e, l;
			int n = 8;
			while (rnd(state) & 1 && n < 20000)
				n <<= 1;
			n = rnd(state) % n + 2;
			if (!end)
				goto retry;
			a = (end ? rnd(state) % end : 0);
			b = (end ? rnd(state) % end : 0);
			if (a == b) {
				goto retry;
			} else if (a > b) {
				s = b; e = a;
			} else {
				s = a; e = b;
			}
			l = e - s;

			write_all(state, data, s);
			if (l * n > 134217728)
				l = rnd(state) % 1024 + 2;
			while(n--)
				write_all(state, data+s, l);
			write_all(state, data+s, end-s);
			break;
		}
		case 6: { /* insert random data */
			size_t pos = (end ? rnd(state) % end : 0);
			int n = rnd(state) % 1022 + 2;
			int p = 0;
			while (p < n)
				buff[p++] = rnd(state) & 255;
			write_all(state, data, pos);
			write_all(state, buff, p);
			write_all(state, data+pos, end-pos);
			break;
		}
		case 7:
		case 8:
		case 9:
		case 10:
		case 11:
		case 12: { /* aimed jump to self */
			size_t j=0, l=0;
			if (end < 5)
				goto retry;
			while (j == l)
				aim(state, data, end, data, end, &j, &l);
			write_all(state, data, j);
			write_all(state, data+l, end-l);
			break;
		}
		case 13:
		case 14:
		case 15:
		case 16:
		case 17:
		case 18:
		case 19:
		case 20:
		case 21: { /* aimed random block fusion */
			size_t j, l, dm, sm;
			char *buff, *block;
			size_t bend, block_len;
			if (end < 8) goto retry;
			block = random_block(state, end, &block_len);
			if (block_len < 8)
				goto retry;
			dm = end >> 1;
			sm = block_len >> 1;
			aim(state, data, dm, block, sm, &j, &l);
			write_all(state, data, j);
			data += j;
			end -= j;
			buff = block + l;
			bend = block_len - l;
			aim(state, buff, bend , data, end, &j, &l);
			write_all(state, buff, j);
			write_all(state, data + l, end - l);
			free(block);
			break;
		}
		case 22:
		case 23: { /* insert semirandom bytes */
			size_t p = 0, n = RAND(state,BUFSIZE);
			size_t pos = (end ? rnd(state) % end : 0);
			n = RAND(state,n+1);
			n = RAND(state,n+1);
			n = RAND(state,n+1);
			n = RAND(state,n+1);
			n = (n > 1) ? n : 2;
			if (!end)
				goto retry;
			write_all(state, data, pos);
			while(n--)
				buff[p++] = data[RAND(state,end)];
			write_all(state, buff, p);
			write_all(state, data + pos, end - pos);
			break;
		}
		case 24: { /* overwrite semirandom bytes */
			size_t a, b, p = 0;
			if (end < 2)
				goto retry;
			a = RAND(state,end-2);
			b = a + 2 + ((rnd(state) & 1) ? RAND(state,MIN(BUFSIZE-2, end-a-2)) : RAND(state,32));
			write_all(state, data, a);
			while(a + p < b)
				buff[p++] = data[RAND(state,end)];
			write_all(state, buff, p);
			if (end > b)
				write_all(state, data + b, end - b);
			break;
		}
		case 25:
		case 26:
		case 27:
		case 28: { /* textual number mutation */
			int n = RAND(state,AIMROUNDS);
			long long val;
			size_t ns, ne;
			ns = ne = 0;
			if (!end)
				goto retry;
			while(n-- && !ne) {
				seek_num(state, data, end, &ns, &ne);
			}
			if (!ne)
				goto retry;
			write_all(state, data, ns);
			if (read_num(data + ns, ne - ns, &val) == 0)
				output_num(state, buff, BUFSIZE, twiddle(state,val));
			else
				output_num(state, buff, BUFSIZE, twiddle(state,0));
			write_all(state, data + ne, end - ne);
			break;
		}
		case 29:
		case 30:
		case 31:
		case 32:
		case 33:
		case 34: { /* delimited swap */
			size_t r1s, r1l, r2s, r2l;
			if (!end || drange(state, data, end, &r1s, &r1l) || other_drange(state, data, end, r1s, &r2s, &r2l))
				goto retry;
			write_all(state, data, r1s);
			write_all(state, data + r2s, r2l);
			if (r2s > (r1s + r1l)) /* these can overlap */
				write_all(state, data + r1s + r1l, r2s - (r1s + r1l));
			write_all(state, data + r1s, r1l);
			write_all(state, data + r2s + r2l, end - (r2s + r2l));
			break;
		}
		default: {
			printf("ni: bad mutation (choice=%d)\n", choice);
			exit(1);
		}
	}
}

static void ni_area(ni_state_t * state, const char *data, size_t end, int n) {
	if (n == 0) {
		write_all(state, data, end);
		return;
	} else if (n == 1 || end < 256) {
		mutate_area(state, data, end);
	} else if (!end) {
		return;
	} else {
		size_t r = RAND(state,end);
		int m = RAND(state,n / 2);
		ni_area(state, data, r, (n - m));
		ni_area(state, data + r, end - r, m);
	}
}

/**
 * This function generates a new mutation from the input buffer and samples
 * @param state - a mutator specific structure previously created by the create function.
 */
static void ni(ni_state_t* state) {
	char *data;
	char *datap;
	size_t j, l, end, endp;
	int m, n = 0;

	data = get_sample(state, -1, &end);

	m = ((rnd(state) & 3) == 1) ? 1 : 2 + RAND(state,((unsigned int) state->input_length >> 12) + 8);
	if (RAND(state,30)) {
		ni_area(state, data, end, m);
	} else { /* small chance of global tail flip */
		m--;
		if (m) {
			n = RAND(state,m);
			m =- n;
		}
		datap = get_random_sample(state, &endp);
		aim(state, data, end, datap, endp, &j, &l);
		ni_area(state, data, j, m);
		ni_area(state, datap + l, endp - l, n);
		free(datap);
	}
	free(data);
}

////////////////////////////////////////////////////////////////////////////////////////////
//// API methods ///////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

#ifndef ALL_MUTATORS_IN_ONE

/**
 * This function fills in the supplied mutator_t with all of the function
 * pointers for this mutator.
 * @param m - a pointer to a mutator_t structure
 */
NI_MUTATOR_API void init(mutator_t * m)
{
	memcpy(m, &ni_mutator, sizeof(mutator_t));
}

#endif

/**
 * This function creates and initializes a ni_state_t object based on the passed in JSON options.
 * @return the newly created ni_state_t object or NULL on failure
 */
static ni_state_t * setup_options(char * options)
{
	ni_state_t * state;
	size_t i;
	state = (ni_state_t *)malloc(sizeof(ni_state_t));
	if (!state)
		return NULL;
	memset(state, 0, sizeof(ni_state_t));

	//Setup defaults
	state->random_state[0] = (((uint64_t)rand()) << 32) | rand();
	state->random_state[1] = (((uint64_t)rand()) << 32) | rand();
	state->mutate_mutex = create_mutex();
	if (!state->mutate_mutex) {
		free(state);
		return NULL;
	}

	if (!options || !strlen(options))
		return state;

	PARSE_OPTION_UINT64T_TEMP(state, options, random_state[0], "random_state0", FUNCNAME(cleanup), temp1);
	PARSE_OPTION_UINT64T_TEMP(state, options, random_state[1], "random_state1", FUNCNAME(cleanup), temp2);
	PARSE_OPTION_ARRAY(state, options, sample_filenames, num_samples, "samples", FUNCNAME(cleanup));

	if(state->num_samples) {
		state->samples = calloc(state->num_samples, sizeof(void *));
		if(!state->samples) {
			FUNCNAME(cleanup)(state);
			return NULL;
		}
		for(i = 0; i < state->num_samples; i++) {

			state->samples[i] = malloc(sizeof(sample_t));
			if(!state->samples[i]) {
				FUNCNAME(cleanup)(state);
				return NULL;
			}
			state->samples[i]->length = read_file(state->sample_filenames[i], &state->samples[i]->content);
			if(state->samples[i]->length < 0) {
				printf("Could not read file %s\n", state->sample_filenames[i]);
				FUNCNAME(cleanup)(state);
				return NULL;
			}
		}
	}

	return state;
}

/**
 * This function will allocate and initialize the mutator state. The mutator state should be
 * freed by calling the cleanup function.
 * @param options - a json string that contains the ni specific options.
 * @param state - optionally, a previously dumped state (with the get_state() function) to load
 * @param input - The input that this mutator will later be mutating
 * @param input_length - the size of the input parameter
 * @return a mutator specific structure or NULL on failure. The returned value should
 * not be used for anything other than passing to the various Mutator API functions.
 */
NI_MUTATOR_API void * FUNCNAME(create)(char * options, char * state, char * input, size_t input_length)
{
	ni_state_t * ni_state = setup_options(options);
	if (!ni_state)
		return NULL;

	ni_state->input = (char *)malloc(input_length);
	if (!ni_state->input || !input_length)
	{
		FUNCNAME(cleanup)(ni_state);
		return NULL;
	}
	memcpy(ni_state->input, input, input_length);
	ni_state->input_length = input_length;
	if (state && FUNCNAME(set_state)(ni_state, state)) {
		FUNCNAME(cleanup)(ni_state);
		return NULL;
	}
	return ni_state;
}

/**
 * This function will release any resources that the mutator has open
 * and free the mutator state structure.
 * @param mutator_state - a mutator specific structure previously created by
 * the create function. This structure will be freed and should not be referenced afterwards.
 */
NI_MUTATOR_API void FUNCNAME(cleanup)(void * mutator_state)
{
	size_t i;
	ni_state_t * ni_state = (ni_state_t *)mutator_state;

	destroy_mutex(ni_state->mutate_mutex);
	for(i = 0; i < ni_state->num_samples; i++) {
		if(ni_state->samples) {
			if(ni_state->samples[i])
				free(ni_state->samples[i]->content);
			free(ni_state->samples[i]);
		}
		free(ni_state->sample_filenames[i]);
	}
	free(ni_state->sample_filenames);
	free(ni_state->samples);
	free(ni_state->input);
	free(ni_state);
}

/**
 * This function will mutate the input given in the create function and return it in the buffer argument.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param buffer - a buffer that the mutated input will be written to
 * @param buffer_length - the size of the passed in buffer argument
 * @return - the length of the mutated data, 0 when the mutator is out of mutations, or -1 on error
 */
NI_MUTATOR_API int FUNCNAME(mutate)(void * mutator_state, char * buffer, size_t buffer_length)
{
	ni_state_t * ni_state = (ni_state_t *)mutator_state;
	//Can't mutate an empty buffer
	if (buffer_length == 0)
		return -1;

#ifdef NI_COMPARISON_TESTING
	//If we're trying to compare against the actual ni binary, we should set the random number generator
	//to a known state that ni can match.
	srandom(atoi(getenv("RANDSEED")));
#endif

	//Setup the mutated buffer
	ni_state->mutated_buffer = (uint8_t *)buffer;
	ni_state->mutated_buffer_length = 0;
	ni_state->max_mutated_buffer_length = buffer_length;

	//Now mutate the buffer
	ni_state->iteration++;
	ni(ni_state);
	return (int)ni_state->mutated_buffer_length;
}

/**
 * This function will mutate the input given in the create function and return it in the buffer argument.
 * This function also accepts a set of flags which instruct it how to mutate the input. See global_types.h
 * for the list of available flags.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param buffer - a buffer that the mutated input will be written to
 * @param buffer_length - the size of the passed in buffer argument.
 * @param flags - A set of mutate flags that modify how this mutator mutates the input.
 * @return - the length of the mutated data, 0 when the mutator is out of mutations, or -1 on error
 */
NI_MUTATOR_API int FUNCNAME(mutate_extended)(void * mutator_state, char * buffer, size_t buffer_length, uint64_t flags)
{
  SINGLE_INPUT_MUTATE_EXTENDED(ni_state_t, state->mutate_mutex);
}

/**
 * This function will return the state of the mutator. The returned value can be used to restart the
 * mutator at a later time, by passing it to the create or set_state function. It is the caller's
 * responsibility to free the memory allocated here by calling the free_state function.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @return - a buffer that defines the current state of the mutator. This will be a mutator specific JSON string.
 */
NI_MUTATOR_API char * FUNCNAME(get_state)(void * mutator_state)
{
	ni_state_t * ni_state = (ni_state_t *)mutator_state;
	json_t *obj, *temp;
	char * ret;

	obj = json_object();
	ADD_INT(temp, ni_state->iteration, obj, "iteration");
	ADD_UINT64T(temp, ni_state->random_state[0], obj, "random_state0");
	ADD_UINT64T(temp, ni_state->random_state[1], obj, "random_state1");
	ret = json_dumps(obj, 0);
	json_decref(obj);
	return ret;
}

/**
 * This function will set the current state of the mutator.
 * This can be used to restart a mutator once from a previous run.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param state - a previously dumped state buffer obtained by the get_state function.
 * @return 0 on success or non-zero on failure
 */
NI_MUTATOR_API int FUNCNAME(set_state)(void * mutator_state, char * state)
{
	ni_state_t * ni_state = (ni_state_t *)mutator_state;
	int result, temp_int;
	uint64_t temp_uint64t;

	if (!state)
		return 1;

	GET_INT(temp_int, state, ni_state->iteration, "iteration", result);
	GET_UINT64T(temp_uint64t, state, ni_state->random_state[0], "random_state0", result);
	GET_UINT64T(temp_uint64t, state, ni_state->random_state[1], "random_state1", result);
	return 0;
}

/**
 * This function will return the current iteration count of the mutator, i.e.
 * how many mutations have been generated with it.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @return value - the number of previously generated mutations
 */
NI_MUTATOR_API int FUNCNAME(get_current_iteration)(void * mutator_state)
{
	GENERIC_MUTATOR_GET_ITERATION(ni_state_t);
}

/**
 * Obtains information about the inputs that were given to the mutator when it was created
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param num_inputs - a pointer to an integer used to return the number of inputs given to this mutator
 * when it was created. This parameter is optional and can be NULL, if this information is not needed
 * @param input_sizes - a pointer to a size_t array used to return the sizes of the inputs given to this
 * mutator when it was created. This parameter is optional and can be NULL, if this information is not needed.
 */
NI_MUTATOR_API void FUNCNAME(get_input_info)(void * mutator_state, int * num_inputs, size_t **input_sizes)
{
	SINGLE_INPUT_GET_INFO(ni_state_t);
}

/**
 * This function will set the input(saved in the mutators state) to something new.
 * This can be used to reinitialize a mutator with new data, without reallocating the entire state struct.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param new_input - The new input used to produce new mutated inputs later when the mutate function is called
 * @param input_length - the size in bytes of the input buffer.
 * @return 0 on success and -1 on failure
 */
NI_MUTATOR_API int FUNCNAME(set_input)(void * mutator_state, char * new_input, size_t input_length)
{
	GENERIC_MUTATOR_SET_INPUT(ni_state_t);
}

/**
 * This function sets a help message for the mutator.
 * @param help_str - A pointer that will be updated to point to the new help string.
 * @return 0 on success and -1 on failure
 */
NI_MUTATOR_API int FUNCNAME(help)(char ** help_str)
{
	GENERIC_MUTATOR_HELP(
"ni - ni-based mutator\n"
"Options:\n"
"  random_state0         The first half of the seed to honggfuzz's random\n"
"                          number generator\n"
"  random_state1         The second half of the seed to honggfuzz's random\n"
"                          number generator\n"
"  samples               An array of files containing other samples to mutate\n"
"                          with the given input\n"
"\n"
	);
}
