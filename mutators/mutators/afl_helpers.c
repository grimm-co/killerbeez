#include "mutators.h"
#include "afl_helpers.h"
#include "afl_config.h"
#include "afl_debug.h"
#include "afl_types.h"

#include <utils.h>

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#endif

static inline uint64_t rotl(const uint64_t x, int k) {
	return (x << k) | (x >> (64 - k));
}

/**
 * xoroshiro128plus by David Blackman and Sebastiano Vigna
 * @param info - an mutate_info_t that holds the current random generator state
 * @return - a random uint64_t
 */
static inline uint64_t rnd64(mutate_info_t * info) {
	const uint64_t s0 = info->random_state[0];
	uint64_t s1 = info->random_state[1];
	const uint64_t result = s0 + s1;
	s1 ^= s0;
	info->random_state[0] = rotl(s0, 55) ^ s1 ^ (s1 << 14);
	info->random_state[1] = rotl(s1, 36);
	return result;
}

/* Generate a random number (from 0 to limit - 1). This may have slight bias. */
MUTATORS_API u32 UR(mutate_info_t * info, u32 limit) {
	return rnd64(info) % limit;
}

//Mutates a buffer, running through each of the passed in mutate functions, updating the mutate_info_t
//with the current progress through the mutation functions
MUTATORS_API int mutate_one(mutate_info_t * info, mutate_buffer_t * buf, int(*const*mutate_funcs)(mutate_info_t *, mutate_buffer_t *), size_t num_funcs) {
	int length = MUTATOR_DONE;
	while ((length == MUTATOR_DONE || length == MUTATOR_TRY_AGAIN) && info->stage < num_funcs)
	{
		length = mutate_funcs[info->stage](info, buf);
		if (length == MUTATOR_TRY_AGAIN)
			info->stage_cur++;
		else if (length == MUTATOR_DONE)
		{
			info->stage++;
			info->stage_cur = 0;
			if (info->one_stage_only) { //if we're only doing one stage, set the stage to the end
				info->stage = num_funcs; //so the next call to mutate_one doesn't return a mutated buffer
				break;
			}
		}
	}
	info->stage_cur++;
	if (length == MUTATOR_DONE && info->stage == num_funcs) //If we've reached
		info->stage_cur = 0; //the end of the mutators cycle, reset the stage to 0
	return length;
}

static void clear_splice_files(mutate_info_t * info)
{
	size_t i;
	if (info->splice_files)
	{
		for (i = 0; i < info->splice_files_count; i++) {
			free(info->splice_files[i]->s);
			free(info->splice_files[i]);
		}
		free(info->splice_files);
		info->splice_files = NULL;
		info->splice_files_count = 0;
	}
}

/**
 * Loads the splice files into the given afl state
 * @param info - the mutate_info_t to load the splice files for
 * @return - 0 on success, nonzero on failure
 */
MUTATORS_API int load_splice_files(mutate_info_t * info, char ** splice_filenames, size_t splice_filenames_count)
{
	char * contents;
	int length;
	size_t i;
	string_t * splice_file;

	clear_splice_files(info);
	for (i = 0; i < splice_filenames_count; i++)
	{
		length = read_file(splice_filenames[i], &contents);
		if (length < 0)
		{
			printf("Could not read file %s\n", splice_filenames[i]);
			clear_splice_files(info);
			return 1;
		}

		splice_file = (string_t *)malloc(sizeof(string_t));
		info->splice_files = (string_t **)realloc(info->splice_files, sizeof(string_t *) * (info->splice_files_count + 1));
		if (!info->splice_files || !splice_file)
		{
			printf("Memory error while allocating splice files\n");
			free(contents);
			free(splice_file);
			clear_splice_files(info);
			return 1;
		}
		splice_file->len = length;
		splice_file->s = (u8 *)contents;
		info->splice_files[info->splice_files_count] = splice_file;
		info->splice_files_count++;
	}
	return 0;
}

static void clear_dictionary_files(mutate_info_t * info)
{
	size_t i;
	if (info->dictq)
	{
		for (i = 0; i < info->dictionary_count; i++) {
			free(info->dictq[i]->s);
			free(info->dictq[i]);
		}
		free(info->dictq);
		info->dictq = NULL;
		info->dictionary_count = 0;
	}
}

MUTATORS_API void cleanup_mutate_info(mutate_info_t * info)
{
	//Free any dictionary/splice files that were loaded
	clear_dictionary_files(info);
	clear_splice_files(info);
	destroy_mutex(info->mutate_mutex);
	info->mutate_mutex = NULL;
}

/**
 * Cleans up the old mutate_info_t struct and reinitializes it back to defaults
 * @param info - the mutate_info_t struct to reset
 * @return - 0 on success, nonzero on failure
 */
MUTATORS_API int reset_mutate_info(mutate_info_t * info)
{
	cleanup_mutate_info(info);

	//Setup the default options
	info->random_state[0] = (((uint64_t)rand()) << 32) | rand();
	info->random_state[1] = (((uint64_t)rand()) << 32) | rand();
	info->queue_cycle = 1;
	info->havoc_div = 1;
	info->perf_score = 100;
	info->mutate_mutex = create_mutex();
	return info->mutate_mutex == NULL; //1 if the mutex creation failed, 0 otherwise
}

MUTATORS_API int add_mutate_info_to_json(json_t * obj, mutate_info_t * info)
{
	json_t *temp, *temp2, *dictionary_list, *dictionary_item;
	uint64_t i;

	ADD_UINT64T(temp, info->random_state[0], obj, "random_state0");
	ADD_UINT64T(temp, info->random_state[1], obj, "random_state1");
	ADD_INT(temp, info->stage_cur, obj, "stage_cur");
	ADD_INT(temp, info->stage, obj, "stage");
	ADD_INT(temp, info->should_skip_previous, obj, "should_skip_previous");
	ADD_INT(temp, info->one_stage_only, obj, "one_stage_only");
	ADD_INT(temp, info->queue_cycle, obj, "queue_cycle");
	ADD_INT(temp, info->havoc_div, obj, "havoc_div");
	ADD_INT(temp, info->perf_score, obj, "perf_score");

	dictionary_list = json_array();
	if (!dictionary_list)
		return 0;
	for(i = 0; i < info->dictionary_count; i++)
	{
		dictionary_item = json_object();
		temp = json_mem((const char *)info->dictq[i]->s, info->dictq[i]->len);
		temp2 = json_integer(info->dictq[i]->len);

		if (!temp || !temp2 || !dictionary_item) {
			if(dictionary_item)
				json_decref(dictionary_list);
			if (temp)
				json_decref(temp);
			if (temp2)
				json_decref(temp2);
			return 0;
		}
		if (json_object_set_new(dictionary_item, "s", temp))
		{
			json_decref(dictionary_list);
			json_decref(dictionary_item);
			json_decref(temp2);
			return 0;
		}
		if (json_object_set_new(dictionary_item, "len", temp2))
		{
			json_decref(dictionary_list);
			json_decref(dictionary_item);
			return 0;
		}
		json_array_append_new(dictionary_list, dictionary_item);
	}
	if (json_object_set_new(obj, "dictionary", dictionary_list))
		json_decref(dictionary_list);

	return 1;
}

MUTATORS_API int get_mutate_info_from_json(char * state, mutate_info_t * info)
{
	int temp_int, result, inner_result;
	uint64_t temp_uint64t;
	char * tempstr;
	json_t *dictionary_obj;

	clear_splice_files(info);
	clear_dictionary_files(info);

	GET_UINT64T(temp_uint64t, state, info->random_state[0], "random_state0", result);
	GET_UINT64T(temp_uint64t, state, info->random_state[1], "random_state1", result);
	GET_INT(temp_int, state, info->stage_cur, "stage_cur", result);
	GET_INT(temp_int, state, info->stage, "stage", result);
	GET_INT(temp_int, state, info->should_skip_previous, "should_skip_previous", result);
	GET_INT(temp_int, state, info->one_stage_only, "one_stage_only", result);
	GET_INT(temp_int, state, info->queue_cycle, "queue_cycle", result);
	GET_INT(temp_int, state, info->havoc_div, "havoc_div", result);
	GET_INT(temp_int, state, info->perf_score, "perf_score", result);

	FOREACH_OBJECT_JSON_ARRAY_ITEM_BEGIN(state, modules, "dictionary", dictionary_obj, result)

		GET_ITEM(dictionary_obj, temp_uint64t, temp_uint64t, get_uint64t_options_from_json, "len", inner_result);
		tempstr = get_mem_options_from_json(dictionary_obj, "s", &inner_result);
		if (inner_result <= 0) {
			FOREACH_OBJECT_JSON_ARRAY_ITEM_FREE(modules);
			return 1;
		}

		info->dictq = (string_t **)realloc(info->dictq, (info->dictionary_count + 1) * sizeof(string_t *));
		if (!info->dictq) {
			free(tempstr);
			FOREACH_OBJECT_JSON_ARRAY_ITEM_FREE(modules);
			return 1;
		}
		info->dictq[info->dictionary_count] = (string_t *)malloc(sizeof(string_t));
		if (!info->dictq[info->dictionary_count]) {
			free(tempstr);
			FOREACH_OBJECT_JSON_ARRAY_ITEM_FREE(modules);
			return 1;
		}

		info->dictq[info->dictionary_count]->len = temp_uint64t;
		info->dictq[info->dictionary_count]->s = (u8*)tempstr;
		info->dictionary_count++;

	FOREACH_OBJECT_JSON_ARRAY_ITEM_END(modules);
	if (result < 0)
		return 1;

	return 0;
}


////////////////////////////////////////////////////////////////////////////////////////////
//// AFL Mutation Functions ////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

/*
   The code in this section (AFL Mutation Functions) is taken from and/or based
   on AFL and falls under the following license:

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013, 2014, 2015, 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   The code in this section has been modified from the original to suit the
   purposes of this project.
*/

/* Interesting values, as per config.h */
static s8  interesting_8[] = { INTERESTING_8 };
static s16 interesting_16[] = { INTERESTING_8, INTERESTING_16 };
static s32 interesting_32[] = { INTERESTING_8, INTERESTING_16, INTERESTING_32 };

/* Helper to choose random block len for block operations in fuzz_one().
Doesn't return zero, provided that max_len is > 0. */
static u32 choose_block_len(mutate_info_t * info, u32 limit) {

	u32 min_value, max_value;
	u32 rlim = MIN(info->queue_cycle, 3);

	switch (UR(info, rlim)) {

	case 0:
		min_value = 1;
		max_value = HAVOC_BLK_SMALL;
		break;

	case 1:
		min_value = HAVOC_BLK_SMALL;
		max_value = HAVOC_BLK_MEDIUM;
		break;

	default:
		if (UR(info, 10)) {
			min_value = HAVOC_BLK_MEDIUM;
			max_value = HAVOC_BLK_LARGE;
		}
		else {
			min_value = HAVOC_BLK_LARGE;
			max_value = HAVOC_BLK_XL;
		}
	}

	if (min_value >= limit)
		min_value = 1;

	return min_value + UR(info, MIN(max_value, limit) - min_value + 1);
}

/* Helper function to compare buffers; returns first and last differing offset. We
use this to find reasonable locations for splicing two files. */
static void locate_diffs(u8* ptr1, u8* ptr2, u32 len, s32* first, s32* last) {

	s32 f_loc = -1;
	s32 l_loc = -1;
	u32 pos;

	for (pos = 0; pos < len; pos++) {

		if (*(ptr1++) != *(ptr2++)) {

			if (f_loc == -1) f_loc = pos;
			l_loc = pos;

		}

	}

	*first = f_loc;
	*last = l_loc;

	return;
}

/* Helper function to see if a particular change (xor_val = old ^ new) could
be a product of deterministic bit flips with the lengths and stepovers
attempted by afl-fuzz. This is used to avoid dupes in some of the
deterministic fuzzing operations that follow bit flips. We also
return 1 if xor_val is zero, which implies that the old and attempted new
values are identical and the exec would be a waste of time. */
static u8 could_be_bitflip(u32 xor_val) {

	u32 sh = 0;

	if (!xor_val) return 1;

	/* Shift left until first bit set. */

	while (!(xor_val & 1)) { sh++; xor_val >>= 1; }

	/* 1-, 2-, and 4-bit patterns are OK anywhere. */

	if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

	/* 8-, 16-, and 32-bit patterns are OK only if shift factor is
	divisible by 8, since that's the stepover for these ops. */

	if (sh & 7) return 0;

	if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
		return 1;

	return 0;

}

/* Helper function to see if a particular value is reachable through
arithmetic operations. Used for similar purposes. */
static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

	u32 i, ov = 0, nv = 0, diffs = 0;

	if (old_val == new_val) return 1;

	/* See if one-byte adjustments to any byte could produce this result. */

	for (i = 0; i < blen; i++) {

		u8 a = old_val >> (8 * i),
			b = new_val >> (8 * i);

		if (a != b) { diffs++; ov = a; nv = b; }

	}

	/* If only one byte differs and the values are within range, return 1. */

	if (diffs == 1) {

		if ((u8)(ov - nv) <= ARITH_MAX ||
			(u8)(nv - ov) <= ARITH_MAX) return 1;

	}

	if (blen == 1) return 0;

	/* See if two-byte adjustments to any byte would produce this result. */

	diffs = 0;

	for (i = 0; i < blen / 2U; i++) {

		u16 a = old_val >> (16 * i),
			b = new_val >> (16 * i);

		if (a != b) { diffs++; ov = a; nv = b; }

	}

	/* If only one word differs and the values are within range, return 1. */

	if (diffs == 1) {

		if ((u16)(ov - nv) <= ARITH_MAX ||
			(u16)(nv - ov) <= ARITH_MAX) return 1;

		ov = SWAP16(ov); nv = SWAP16(nv);

		if ((u16)(ov - nv) <= ARITH_MAX ||
			(u16)(nv - ov) <= ARITH_MAX) return 1;

	}

	/* Finally, let's do the same thing for dwords. */

	if (blen == 4) {

		if ((u32)(old_val - new_val) <= ARITH_MAX ||
			(u32)(new_val - old_val) <= ARITH_MAX) return 1;

		new_val = SWAP32(new_val);
		old_val = SWAP32(old_val);

		if ((u32)(old_val - new_val) <= ARITH_MAX ||
			(u32)(new_val - old_val) <= ARITH_MAX) return 1;

	}

	return 0;

}

/* Describe integer as memory size. */

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
    if (val < (_divisor) * (_limit_mult)) { \
      snprintf((char *)tmp[cur], sizeof(tmp[cur]), _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur]; \
    } \
  } while (0)

static u8* DMS(u64 val) {

	static u8 tmp[12][16];
	static u8 cur;

	cur = (cur + 1) % 12;

	/* 0-9999 */
	CHK_FORMAT(1, 10000, "%llu B", u64);

	/* 10.0k - 99.9k */
	CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

	/* 100k - 999k */
	CHK_FORMAT(1024, 1000, "%llu kB", u64);

	/* 1.00M - 9.99M */
	CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

	/* 10.0M - 99.9M */
	CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

	/* 100M - 999M */
	CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

	/* 1.00G - 9.99G */
	CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

	/* 10.0G - 99.9G */
	CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

	/* 100G - 999G */
	CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

	/* 1.00T - 9.99G */
	CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

	/* 10.0T - 99.9T */
	CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

	/* 100T+ */
	strncpy((char *)tmp[cur], "infty", sizeof(tmp[cur]));
	return tmp[cur];
}

/* Last but not least, a similar helper to see if insertion of an
interesting integer is redundant given the insertions done for
shorter blen. The last param (check_le) is set if the caller
already executed LE insertion for current blen and wants to see
if BE variant passed in new_val is unique. */
static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {

	u32 i, j;

	if (old_val == new_val) return 1;

	/* See if one-byte insertions from interesting_8 over old_val could
	produce new_val. */

	for (i = 0; i < blen; i++) {

		for (j = 0; j < sizeof(interesting_8); j++) {

			u32 tval = (old_val & ~(0xff << (i * 8))) |
				(((u8)interesting_8[j]) << (i * 8));

			if (new_val == tval) return 1;

		}

	}

	/* Bail out unless we're also asked to examine two-byte LE insertions
	as a preparation for BE attempts. */

	if (blen == 2 && !check_le) return 0;

	/* See if two-byte insertions over old_val could give us new_val. */

	for (i = 0; i < blen - 1; i++) {

		for (j = 0; j < sizeof(interesting_16) / 2; j++) {

			u32 tval = (old_val & ~(0xffff << (i * 8))) |
				(((u16)interesting_16[j]) << (i * 8));

			if (new_val == tval) return 1;

			/* Continue here only if blen > 2. */

			if (blen > 2) {

				tval = (old_val & ~(0xffff << (i * 8))) |
					(SWAP16(interesting_16[j]) << (i * 8));

				if (new_val == tval) return 1;

			}

		}

	}

	if (blen == 4 && check_le) {

		/* See if four-byte insertions could produce the same result
		(LE only). */

		for (j = 0; j < sizeof(interesting_32) / 4; j++)
			if (new_val == (u32)interesting_32[j]) return 1;

	}

	return 0;

}

/* Read the dictionary from a file */
static int load_dictionary_file(mutate_info_t * info, char * fname, u32* min_len, u32* max_len, u32 dict_level) {

	FILE* fp;
	char buf[MAX_LINE];
	u8 *lptr;
	u32 cur_line = 0;
	char* hexdigits = "0123456789abcdef";
	string_t ** temp_dictq;

	fp = fopen(fname, "r");
	if (!fp) {
		printf("Unable to open dictionary file '%s'", fname);
		return 1;
	}

	while ((lptr = (u8 *)fgets(buf, MAX_LINE, fp))) {

		u8 *rptr, *wptr, *new_item;
		u32 klen = 0;

		cur_line++;

		// Trim on left and right.
		while (isspace(*lptr)) lptr++;
		rptr = lptr + strlen((char *)lptr) - 1;
		while (rptr >= lptr && isspace(*rptr)) rptr--;
		rptr++;
		*rptr = 0;

		// Skip empty lines and comments.
		if (!*lptr || *lptr == '#') continue;

		// All other lines must end with '"', which we can consume.
		rptr--;
		if (rptr < lptr || *rptr != '"') {
			printf("Malformed name=\"value\" pair in dictionary file %s on line %u.", fname, cur_line);
			fclose(fp);
			return 1;
		}
		*rptr = 0;

		// Skip alphanumerics and dashes (label).
		while (isalnum(*lptr) || *lptr == '_') lptr++;

		// If @number follows, parse that.
		if (*lptr == '@') {
			lptr++;
			if (atoi((char *)lptr) > dict_level) continue;
			while (isdigit(*lptr)) lptr++;
		}

		// Skip whitespace and = signs.
		while (isspace(*lptr) || *lptr == '=') lptr++;

		// Consume opening '"'.
		if (*lptr != '"') {
			printf("Malformed name=\"keyword\" pair in dictionary file %s on line %u.", fname, cur_line);
			fclose(fp);
			return 1;
		}

		lptr++;
		if (!*lptr) {
			printf("Empty keyword in dictionary file %s on line %u.", fname, cur_line);
			fclose(fp);
			return 1;
		}


		// Okay, let's allocate memory and copy data between "...", handling
		// \xNN escaping, \\, and \".
		wptr = new_item = (u8 *)malloc(rptr - lptr);
		if (!new_item) {
			printf("Failed allocating memory while parsing dictionary file %s, line %u.", fname, cur_line);
			fclose(fp);
			return 1;
		}

		while (*lptr) {
			if ((*lptr >= 1 && *lptr <= 31) || (*lptr >= 128 && *lptr <= 255)) {
				printf("Non-printable characters in dictionary file %s on line %u.", fname, cur_line);
				free(new_item);
				fclose(fp);
				return 1;
			}

			if (*lptr == '\\') {
				lptr++;

				if (*lptr == '\\' || *lptr == '"') {
					*(wptr++) = *(lptr++);
					klen++;
				}
				else {
					if (*lptr != 'x' || !isxdigit(lptr[1]) || !isxdigit(lptr[2])) {
						printf("Invalid escaping (not \\xNN) in dictionary file %s on line %u.", fname, cur_line);
						free(new_item);
						fclose(fp);
						return 1;
					}

					*(wptr++) =
						((strchr(hexdigits, tolower(lptr[1])) - hexdigits) << 4) |
						(strchr(hexdigits, tolower(lptr[2])) - hexdigits);
					lptr += 3;
					klen++;
				}
			}
			else {
				*(wptr++) = *(lptr++);
				klen++;
			}
		}

		if (klen > MAX_DICT_FILE) {
			printf("Keyword too big in line %u (%s, limit is %s)", cur_line, DMS(klen), DMS(MAX_DICT_FILE));
			free(new_item);
			fclose(fp);
			return 1;
		}

		if (*min_len > klen) *min_len = klen;
		if (*max_len < klen) *max_len = klen;

		temp_dictq = (string_t **)realloc(info->dictq, (info->dictionary_count + 1) * sizeof(string_t *));
		if (!temp_dictq) {
			printf("Failed allocating memory while parsing dictionary file %s, line %u.", fname, cur_line);
			free(new_item);
			fclose(fp);
			return 1;
		}
		info->dictq = temp_dictq;

		info->dictq[info->dictionary_count] = (string_t *)malloc(sizeof(string_t));
		if (!info->dictq[info->dictionary_count]) {
			printf("Failed allocating memory while parsing dictionary file %s, line %u.", fname, cur_line);
			free(new_item);
			fclose(fp);
			return 1;
		}

		info->dictq[info->dictionary_count]->s = new_item;
		info->dictq[info->dictionary_count]->len = klen;
		info->dictionary_count++;
	}
	fclose(fp);
	return 0;
}

/* Read the dictionary from the dictionary directory */
MUTATORS_API int load_dictionary(mutate_info_t * info, char * path) {
	u32 min_len = MAX_DICT_FILE, max_len = 0, dict_level = 0;
	char * x, * file_contents;
	char filename[MAX_PATH];
	int length, ret;
	string_t ** temp_dictq;

	/* If the name ends with @, extract level and continue. */
	if ((x = strchr(path, '@'))) {
		*x = 0;
		dict_level = atoi(x + 1);
	}

	ACTF("Loading extra dictionary from '%s' (level %u)...", path, dict_level);

#ifdef _WIN32
	WIN32_FIND_DATA fdata;
	HANDLE h;
	wchar_t * wide_pattern;

	if (path[strlen(path) - 1] == '\\')
		snprintf(filename, sizeof(filename), "%s*", path);
	else
		snprintf(filename, sizeof(filename), "%s\\*", path);
	wide_pattern = convert_char_array_to_wchar(filename, NULL);
	h = FindFirstFile(wide_pattern, &fdata);
	free(wide_pattern);

	if (h == INVALID_HANDLE_VALUE) {
		ret = load_dictionary_file(info, path, &min_len, &max_len, dict_level);
		if (ret)
			return ret;
		goto check_dictionary;
	}

	if (x) {
		printf("Dictionary levels not supported for directories.");
		FindClose(h);
		return 1;
	}

	do {
		if (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			continue;

		snprintf(filename, sizeof(filename), "%s\\%s", path, fdata.cFileName);
		if (_access(filename, 0)) {
			printf("Unable to access dictionary file '%s'", filename);
			FindClose(h);
			return 1;
		}
		if ((fdata.nFileSizeHigh > 0) || (fdata.nFileSizeLow > MAX_DICT_FILE)) {
			printf("Dictionary item '%s' is too big (%s, limit is %s)", filename, DMS(fdata.nFileSizeLow), DMS(MAX_DICT_FILE));
			FindClose(h);
			return 1;
		}

		if (min_len > fdata.nFileSizeLow) min_len = fdata.nFileSizeLow;
		if (max_len < fdata.nFileSizeLow) max_len = fdata.nFileSizeLow;

		length = read_file(filename, &file_contents);
		if (length < 0) {
			printf("Unable to open dictionary file '%s'", filename);
			FindClose(h);
			return 1;
		}

		temp_dictq = (string_t **)realloc(info->dictq, (info->dictionary_count + 1) * sizeof(string_t *));
		if (!temp_dictq) {
			printf("Failed allocating memory while parsing dictionary file %s.", filename);
			free(file_contents);
			FindClose(h);
			return 1;
		}
		info->dictq = temp_dictq;

		info->dictq[info->dictionary_count] = (string_t *)malloc(sizeof(string_t));
		if (!info->dictq[info->dictionary_count]) {
			printf("Failed allocating memory while parsing dictionary file %s.", filename);
			free(file_contents);
			FindClose(h);
			return 1;
		}

		info->dictq[info->dictionary_count]->len = length;
		info->dictq[info->dictionary_count]->s = (u8*)file_contents;
		info->dictionary_count++;

	} while (FindNextFile(h, &fdata));

	FindClose(h);

#else

	DIR* d;
	struct dirent* de;
	struct stat st;
	int fd;

	d = opendir(path);
	if (!d) {
		ret = load_dictionary_file(info, path, &min_len, &max_len, dict_level);
		if (ret)
			return ret;
		goto check_dictionary;
	}

	if (x) {
		printf("Dictionary levels not supported for directories.");
		return 1;
	}

	while ((de = readdir(d))) {

		snprintf(filename, sizeof(filename), "%s/%s", path, de->d_name);
		if (lstat(filename, &st) || access(filename, R_OK)) {
			printf("Unable to access dictionary file '%s'", filename);
			return 1;
		}

		/* This also takes care of . and .. */
		if (!S_ISREG(st.st_mode) || !st.st_size)
			continue;

		if (st.st_size > MAX_DICT_FILE) {
			printf("Dictionary item '%s' is too big (%s, limit is %s)", filename, DMS(st.st_size), DMS(MAX_DICT_FILE));
			return 1;
		}

		if (min_len > st.st_size) min_len = st.st_size;
		if (max_len < st.st_size) max_len = st.st_size;

		info->dictq = (string_t **)realloc(info->dictq, (info->dictionary_count + 1) * sizeof(string_t *));
		info->dictq[info->dictionary_count] = (string_t *)malloc(sizeof(string_t));

		length = read_file(filename, (char **)&info->dictq[info->dictionary_count]->s);
		if (length < 0) {
			printf("Unable to open dictionary file '%s'", filename);
			return 1;
		}
		info->dictq[info->dictionary_count]->len = length;
		info->dictionary_count++;
	}

	closedir(d);

#endif

check_dictionary:
	if (!info->dictionary_count) {
		printf("No usable dictionary files in '%s'", path);
		return 1;
	}

	OKF("Loaded %llu dictionary tokens, size range %s to %s.", info->dictionary_count, DMS(min_len), DMS(max_len));
	if (max_len > 32)
		WARNF("Some tokens are relatively large (%s) - consider trimming.", DMS(max_len));
	if (info->dictionary_count > MAX_DET_EXTRAS)
		WARNF("More than %u tokens - will use them probabilistically.", MAX_DET_EXTRAS);

	return 0;
}

MUTATORS_API int single_walking_bit(mutate_info_t * info, mutate_buffer_t * buf)
{
	if (info->stage_cur >= buf->length << 3)
		return MUTATOR_DONE;
	FLIP_BIT(buf->buffer, info->stage_cur);
	return (int)buf->length;
}

MUTATORS_API int two_walking_bit(mutate_info_t * info, mutate_buffer_t * buf)
{
	if (info->stage_cur >= (buf->length << 3) - 1)
		return MUTATOR_DONE;
	FLIP_BIT(buf->buffer, info->stage_cur);
	FLIP_BIT(buf->buffer, info->stage_cur + 1);
	return (int)buf->length;
}

MUTATORS_API int four_walking_bit(mutate_info_t * info, mutate_buffer_t * buf)
{
	if (info->stage_cur >= (buf->length << 3) - 3)
		return MUTATOR_DONE;
	FLIP_BIT(buf->buffer, info->stage_cur);
	FLIP_BIT(buf->buffer, info->stage_cur + 1);
	FLIP_BIT(buf->buffer, info->stage_cur + 2);
	FLIP_BIT(buf->buffer, info->stage_cur + 3);
	return (int)buf->length;
}

MUTATORS_API int walking_byte(mutate_info_t * info, mutate_buffer_t * buf)
{
	if (info->stage_cur >= buf->length)
		return MUTATOR_DONE;
	buf->buffer[info->stage_cur] ^= 0xFF;
	return (int)buf->length;
}

MUTATORS_API int two_walking_byte(mutate_info_t * info, mutate_buffer_t * buf)
{
	if (info->stage_cur >= buf->length - 1 || buf->length < 2)
		return MUTATOR_DONE;
	*(u16*)(buf->buffer + info->stage_cur) ^= 0xFFFF;
	return (int)buf->length;
}

MUTATORS_API int four_walking_byte(mutate_info_t * info, mutate_buffer_t * buf)
{
	if (info->stage_cur >= buf->length - 3 || buf->length < 4)
		return MUTATOR_DONE;
	*(u32*)(buf->buffer + info->stage_cur) ^= 0xFFFFFFFF;
	return (int)buf->length;
}

MUTATORS_API int one_byte_arithmetics(mutate_info_t * info, mutate_buffer_t * buf)
{
	uint64_t index, round;
	u8 old_value, new_value, arith_value;

	if (info->stage_cur >= 2 * buf->length * ARITH_MAX)
		return MUTATOR_DONE;

	index = info->stage_cur / (2 * ARITH_MAX);
	round = (info->stage_cur / ARITH_MAX) % 2;
	arith_value = (u8)(info->stage_cur % (ARITH_MAX));

	old_value = buf->buffer[index];

	if (round == 0) //one byte addition
		new_value = old_value + (arith_value + 1);
	else //one byte subtraction
		new_value = old_value - (arith_value + 1);

	// Do arithmetic operations only if the result couldn't be a product of a bitflip.
	if (info->should_skip_previous && could_be_bitflip(old_value ^ new_value))
		return MUTATOR_TRY_AGAIN;

	buf->buffer[index] = new_value;
	return (int)buf->length;
}

MUTATORS_API int two_byte_arithmetics(mutate_info_t * info, mutate_buffer_t * buf)
{
	uint64_t index, round;
	u16 old_value, new_value, arith_value;

	if (info->stage_cur >= 4 * (buf->length - 1) * ARITH_MAX || buf->length < 2)
		return MUTATOR_DONE;

	index = info->stage_cur / (4 * ARITH_MAX);
	round = (info->stage_cur / ARITH_MAX) % 4;
	arith_value = (info->stage_cur % (ARITH_MAX)) + 1;
	old_value = *(u16*)(buf->buffer + index);

	if (round == 0) //little endian addition
		new_value = old_value + arith_value;
	else if (round == 1) //little endian subtraction
		new_value = old_value - arith_value;
	else if (round == 2) //big endian addition
		new_value = SWAP16(SWAP16(old_value) + arith_value);
	else //big endian subtraction
		new_value = SWAP16(SWAP16(old_value) - arith_value);

	// Try little endian addition and subtraction first, then big endian. Do it only
	// if the operation would affect more than one byte (hence the & 0xff overflow checks)
	// and if it couldn't be a product of a bitflip.
	if ((info->should_skip_previous && could_be_bitflip(old_value ^ new_value))
		|| (round == 0 && (old_value & 0xff) + arith_value <= 0xff)
		|| (round == 1 && (old_value & 0xff) > arith_value)
		|| (round == 2 && (old_value >> 8) + arith_value <= 0xff)
		|| (round == 3 && (old_value >> 8)  > arith_value))
		return MUTATOR_TRY_AGAIN;

	*(u16*)(buf->buffer + index) = new_value;
	return (int)buf->length;
}

MUTATORS_API int four_byte_arithmetics(mutate_info_t * info, mutate_buffer_t * buf)
{
	uint64_t index, round;
	u32 old_value, new_value, arith_value;

	if (info->stage_cur >= 4 * (buf->length - 3) * ARITH_MAX || buf->length < 4)
		return MUTATOR_DONE;

	index = info->stage_cur / (4 * ARITH_MAX);
	round = (info->stage_cur / ARITH_MAX) % 4;
	arith_value = (info->stage_cur % (ARITH_MAX)) + 1;
	old_value = *(u32*)(buf->buffer + index);

	if (round == 0) //little endian addition
		new_value = old_value + arith_value;
	else if (round == 1) //little endian subtraction
		new_value = old_value - arith_value;
	else if (round == 2) //big endian addition
		new_value = SWAP32(SWAP32(old_value) + arith_value);
	else //big endian subtraction
		new_value = SWAP32(SWAP32(old_value) - arith_value);

	// Little endian first. Same deal as with 16-bit: we only want to
	// try if the operation would have effect on more than two bytes.
	if ((info->should_skip_previous && could_be_bitflip(old_value ^ new_value))
		|| (round == 0 && (old_value & 0xffff) + arith_value <= 0xffff)
		|| (round == 1 && (old_value & 0xffff) > arith_value)
		|| (round == 2 && (SWAP32(old_value) & 0xffff) + arith_value <= 0xffff)
		|| (round == 3 && (SWAP32(old_value) & 0xffff) > arith_value))
		return MUTATOR_TRY_AGAIN;

	*(u32*)(buf->buffer + index) = new_value;
	return (int)buf->length;
}

MUTATORS_API int interesting_one_byte(mutate_info_t * info, mutate_buffer_t * buf)
{
	uint64_t index;
	u8 old_value, new_value;

	if (info->stage_cur >= buf->length * ARRAY_SIZE(interesting_8))
		return MUTATOR_DONE;

	index = info->stage_cur / ARRAY_SIZE(interesting_8);
	old_value = buf->buffer[index];
	new_value = interesting_8[info->stage_cur % ARRAY_SIZE(interesting_8)];

	// Skip if the value could be a product of bitflips or arithmetics.
	if (info->should_skip_previous && (could_be_bitflip(old_value ^ new_value) || could_be_arith(old_value, new_value, 1)))
		return MUTATOR_TRY_AGAIN;

	buf->buffer[index] = new_value;
	return (int)buf->length;
}

MUTATORS_API int interesting_two_byte(mutate_info_t * info, mutate_buffer_t * buf)
{
	uint64_t index, round;
	u16 old_value, new_value;

	if (info->stage_cur >= 2 * (buf->length - 1) * ARRAY_SIZE(interesting_16) || buf->length < 2)
		return MUTATOR_DONE;

	index = info->stage_cur / (2 * ARRAY_SIZE(interesting_16));
	round = (info->stage_cur / ARRAY_SIZE(interesting_16)) % 2;
	old_value = *(u16*)(buf->buffer + index);
	new_value = interesting_16[info->stage_cur % ARRAY_SIZE(interesting_16)];
	if (round) //second round, use reverse endian
		new_value = SWAP16(new_value);

	/* Skip if this could be a product of a bitflip, arithmetics,
	single-byte interesting value insertion, or if on the reverse endian
	round and the value is the same in both endians */
	if ((info->should_skip_previous &&
		(could_be_bitflip(old_value ^ new_value)
		|| could_be_arith(old_value, new_value, 2)
		|| could_be_interest(old_value, new_value, 2, round)))
		|| (round == 1 && new_value == SWAP16(new_value)))
		return MUTATOR_TRY_AGAIN;

	*(u16*)(buf->buffer + index) = new_value;
	return (int)buf->length;
}

MUTATORS_API int interesting_four_byte(mutate_info_t * info, mutate_buffer_t * buf)
{
	uint64_t index, round;
	u32 old_value, new_value;

	if (info->stage_cur >= 2 * (buf->length - 3) * ARRAY_SIZE(interesting_32) || buf->length < 4)
		return MUTATOR_DONE;

	index = info->stage_cur / (2 * ARRAY_SIZE(interesting_32));
	round = (info->stage_cur / ARRAY_SIZE(interesting_32)) % 2;
	old_value = *(u32*)(buf->buffer + index);
	new_value = interesting_32[info->stage_cur % ARRAY_SIZE(interesting_32)];
	if (round) //second round, use reverse endian
		new_value = SWAP32(new_value);

	/* Skip if this could be a product of a bitflip, arithmetics,
	single-byte interesting value insertion, or if on the reverse endian
	round and the value is the same in both endians */
	if ((info->should_skip_previous && 
		(could_be_bitflip(old_value ^ new_value)
		|| could_be_arith(old_value, new_value, 4)
		|| could_be_interest(old_value, new_value, 4, round)))
		|| (round == 1 && new_value == SWAP32(new_value)))
		return MUTATOR_TRY_AGAIN;

	*(u32*)(buf->buffer + index) = new_value;
	return (int)buf->length;
}

MUTATORS_API int dictionary_overwrite(mutate_info_t * info, mutate_buffer_t * buf)
{
	uint64_t index;
	string_t * dictionary_item;

	if (!info->dictionary_count || !info->dictq || info->stage_cur > buf->length * info->dictionary_count)
		return MUTATOR_DONE;

	index = info->stage_cur / info->dictionary_count;
	dictionary_item = info->dictq[info->stage_cur % info->dictionary_count];

	// Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
	// skip if there's no room to insert the payload or if the token is redundant.
	if ((info->dictionary_count > MAX_DET_EXTRAS && UR(info, info->dictionary_count) >= MAX_DET_EXTRAS)
		|| dictionary_item->len > buf->max_length - index
		|| !memcmp(dictionary_item->s, buf->buffer + index, dictionary_item->len))
		return MUTATOR_TRY_AGAIN;

	memcpy(buf->buffer + index, dictionary_item->s, dictionary_item->len);
	buf->length = MAX(buf->length, index + dictionary_item->len);
	return (int)buf->length;
}

MUTATORS_API int dictionary_insert(mutate_info_t * info, mutate_buffer_t * buf)
{
	uint64_t index;
	string_t * dictionary_item;

	if (!info->dictionary_count || !info->dictq || info->stage_cur > buf->length * info->dictionary_count)
		return MUTATOR_DONE;

	index = info->stage_cur / info->dictionary_count;
	dictionary_item = info->dictq[info->stage_cur % info->dictionary_count];

	// Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
	// skip if there's no room to insert the payload or if the token is redundant.
	if ((info->dictionary_count > MAX_DET_EXTRAS && UR(info, info->dictionary_count) >= MAX_DET_EXTRAS)
		|| dictionary_item->len > buf->max_length - index
		|| buf->length + dictionary_item->len > buf->max_length
		|| !memcmp(dictionary_item->s, buf->buffer + index, dictionary_item->len))
		return MUTATOR_TRY_AGAIN;

	memmove(buf->buffer + index + dictionary_item->len, buf->buffer + index, buf->length - index);
	memcpy(buf->buffer + index, dictionary_item->s, dictionary_item->len);
	buf->length += dictionary_item->len;
	return (int)buf->length;
}

MUTATORS_API int havoc(mutate_info_t * info, mutate_buffer_t * buf)
{
	uint64_t use_stacking, i;
	u32 pos, num32, del_from, del_len, insert_at, use_extra;
	u32 copy_from, copy_to, copy_len;
	u32 clone_from, clone_to, clone_len;
	u16 num16;
	u8  actually_clone;
	string_t * dictionary_item;

	use_stacking = 1ULL << (1 + UR(info, HAVOC_STACK_POW2));
	for (i = 0; i < use_stacking; i++)
	{
		switch (UR(info, 15 + (info->dictionary_count ? 2 : 0)))
		{
		case 0: // Flip a single bit somewhere. Spooky!
			FLIP_BIT(buf->buffer, UR(info, buf->length << 3));
			break;

		case 1: // Set byte to interesting value.
			buf->buffer[UR(info, buf->length)] = interesting_8[UR(info, sizeof(interesting_8))];
			break;

		case 2: // Set word to interesting value, randomly choosing endian.
			if (buf->length < 2)
				break;

			if (UR(info, 2)) {
				*(u16*)(buf->buffer + UR(info, buf->length - 1)) =
					interesting_16[UR(info, sizeof(interesting_16) >> 1)];
			}
			else {
				*(u16*)(buf->buffer + UR(info, buf->length - 1)) =
					SWAP16(interesting_16[UR(info, sizeof(interesting_16) >> 1)]);
			}
			break;

		case 3: // Set dword to interesting value, randomly choosing endian.
			if (buf->length < 4)
				break;

			if (UR(info, 2)) {
				*(u32*)(buf->buffer + UR(info, buf->length - 3)) =
					interesting_32[UR(info, sizeof(interesting_32) >> 2)];
			}
			else {
				*(u32*)(buf->buffer + UR(info, buf->length - 3)) =
					SWAP32(interesting_32[UR(info, sizeof(interesting_32) >> 2)]);
			}
			break;

		case 4: // Randomly subtract from byte.
			buf->buffer[UR(info, buf->length)] -= 1 + UR(info, ARITH_MAX);
			break;

		case 5: // Randomly add to byte.
			buf->buffer[UR(info, buf->length)] += 1 + UR(info, ARITH_MAX);
			break;

		case 6: // Randomly subtract from word, random endian.
			if (buf->length < 2)
				break;

			pos = UR(info, buf->length - 1);
			num16 = 1 + UR(info, ARITH_MAX);
			if (UR(info, 2))
				*(u16*)(buf->buffer + pos) -= num16;
			else
				*(u16*)(buf->buffer + pos) = SWAP16(SWAP16(*(u16*)(buf->buffer + pos)) - num16);
			break;

		case 7: // Randomly add to word, random endian.
			if (buf->length < 2)
				break;

			pos = UR(info, buf->length - 1);
			num16 = 1 + UR(info, ARITH_MAX);
			if (UR(info, 2))
				*(u16*)(buf->buffer + pos) += num16;
			else
				*(u16*)(buf->buffer + pos) = SWAP16(SWAP16(*(u16*)(buf->buffer + pos)) + num16);
			break;

		case 8: // Randomly subtract from dword, random endian.
			if (buf->length < 4)
				break;

			pos = UR(info, buf->length - 3);
			num32 = 1 + UR(info, ARITH_MAX);
			if (UR(info, 2))
				*(u32*)(buf->buffer + pos) -= num32;
			else
				*(u32*)(buf->buffer + pos) = SWAP32(SWAP32(*(u32*)(buf->buffer + pos)) - num32);
			break;

		case 9: // Randomly add to dword, random endian.
			if (buf->length < 4)
				break;

			pos = UR(info, buf->length - 3);
			num32 = 1 + UR(info, ARITH_MAX);
			if (UR(info, 2))
				*(u32*)(buf->buffer + pos) += num32;
			else
				*(u32*)(buf->buffer + pos) = SWAP32(SWAP32(*(u32*)(buf->buffer + pos)) + num32);
			break;

		case 10:
			/* Just set a random byte to a random value. Because,
			why not. We use XOR with 1-255 to eliminate the
			possibility of a no-op. */
			buf->buffer[UR(info, buf->length)] ^= 1 + UR(info, 255);
			break;

		case 11:
		case 12:
			/* Delete bytes. We're making this a bit more likely
			than insertion (the next option) in hopes of keeping
			files reasonably small. */
			if (buf->length < 2)
				break;

			del_len = choose_block_len(info, buf->length - 1);
			del_from = UR(info, buf->length - del_len + 1);
			memmove(buf->buffer + del_from, buf->buffer + del_from + del_len,
				buf->length - del_from - del_len);
			buf->length -= del_len;
			break;

		case 13: //Clone bytes (75%) or insert a block of constant bytes (25%).
			if (buf->length + HAVOC_BLK_XL >= MAX_FILE)
				break;

			actually_clone = UR(info, 4);
			if (actually_clone) {
				clone_len = choose_block_len(info, buf->length);
				clone_len = MIN(clone_len, buf->max_length - buf->length);
				clone_from = UR(info, buf->length - clone_len + 1);
			}
			else {
				clone_len = choose_block_len(info, HAVOC_BLK_XL);
				clone_len = MIN(clone_len, buf->max_length - buf->length);
				clone_from = 0;
			}

			clone_to = UR(info, buf->length);
			memmove(buf->buffer + clone_to + clone_len, buf->buffer + clone_to, buf->length - clone_to);
			if (actually_clone)
				memmove(buf->buffer + clone_to, buf->buffer + clone_from, clone_len);
			else
				memset(buf->buffer + clone_to,
					UR(info, 2) ? UR(info, 256) : buf->buffer[UR(info, buf->length)], clone_len);
			buf->length += clone_len;
			break;

		case 14: // Overwrite bytes with a randomly selected chunk (75%) or fixed bytes (25%).
			if (buf->length < 2)
				break;

			copy_len = choose_block_len(info, buf->length - 1);
			copy_from = UR(info, buf->length - copy_len + 1);
			copy_to = UR(info, buf->length - copy_len + 1);

			if (!UR(info, 4))
				memset(buf->buffer + copy_to,
					UR(info, 2) ? UR(info, 256) : buf->buffer[UR(info, buf->length)], copy_len);
			else if (copy_from != copy_to)
				memmove(buf->buffer + copy_to, buf->buffer + copy_from, copy_len);
			break;

		case 15: // Overwrite bytes with a dictionary item
			use_extra = UR(info, info->dictionary_count);
			dictionary_item = info->dictq[use_extra];

			if (dictionary_item->len > buf->length)
				break;

			insert_at = UR(info, buf->length - dictionary_item->len + 1);
			memcpy(buf->buffer + insert_at, dictionary_item->s, dictionary_item->len);
			break;

		case 16: // Insert an extra. Do the same dice-rolling stuff as for the previous case.
			insert_at = UR(info, buf->length + 1);
			use_extra = UR(info, info->dictionary_count);
			dictionary_item = info->dictq[use_extra];

			if (buf->length + dictionary_item->len >= buf->max_length)
				break;

			memmove(buf->buffer + insert_at + dictionary_item->len, buf->buffer + insert_at,
				buf->length - insert_at);
			memcpy(buf->buffer + insert_at, dictionary_item->s, dictionary_item->len);
			buf->length += dictionary_item->len;
			break;
		}
	}

	return (int)buf->length;
}

MUTATORS_API int splice_buffers(mutate_info_t * info, mutate_buffer_t * buf)
{
	string_t * target = NULL;
	u32 attempts = 0, split_at;
	s32 f_diff = -1, l_diff = -1;

	// Splicing takes the current input file, randomly selects another input, and
	// splices them together at some offset, then relies on the havoc code to mutate that blob.
	if (info->splice_files_count == 0)
		return MUTATOR_DONE;

	//Pick a target to splice with
	while (target == NULL || ((f_diff < 0 || l_diff < 2 || f_diff == l_diff) && (attempts < 2 * info->splice_files_count)))
	{
		attempts++;
		target = info->splice_files[UR(info, info->splice_files_count)];
		locate_diffs(buf->buffer, target->s, MIN(buf->length, target->len), &f_diff, &l_diff);
	}
	if (f_diff < 0 || l_diff < 2 || f_diff == l_diff)
		return MUTATOR_TRY_AGAIN;

	// Split somewhere between the first and last differing byte.
	split_at = f_diff + UR(info, l_diff - f_diff);

	buf->length = target->len;
	memcpy(buf->buffer + split_at, target->s + split_at, target->len - split_at);
	return havoc(info, buf);
}
