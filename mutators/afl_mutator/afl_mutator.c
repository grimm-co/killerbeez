#include <afl_config.h>
#include <afl_helpers.h>
#include <afl_types.h>
#include <mutators.h>
#include "afl_mutator.h"

#include <global_types.h>
#include <jansson_helper.h>
#include <utils.h>

#include <string.h>

struct afl_state
{
	int skip_deterministic;

	char * input;
	size_t input_length;
	int iteration;

	mutate_info_t info;
};
typedef struct afl_state afl_state_t;

mutator_t afl_mutator = {
	FUNCNAME(create),
	FUNCNAME(cleanup),
	FUNCNAME(mutate),
	FUNCNAME(mutate_extended),
	FUNCNAME(get_state),
	afl_free_state,
	FUNCNAME(set_state),
	FUNCNAME(get_current_iteration),
	afl_get_total_iteration_count,
	FUNCNAME(get_input_info),
	FUNCNAME(set_input),
	FUNCNAME(help)
};

static int afl_havoc(mutate_info_t * info, mutate_buffer_t * buf)
{
	if (info->stage_cur > MAX(HAVOC_MIN, (info->queue_cycle > 1 ? HAVOC_CYCLES : HAVOC_CYCLES_INIT) * (info->perf_score / info->havoc_div) / 100))
		return MUTATOR_DONE;
	return havoc(info, buf);
}

static int afl_splice(mutate_info_t * info, mutate_buffer_t * buf)
{
	if (info->stage_cur > MAX(HAVOC_MIN, SPLICE_HAVOC * (info->perf_score / info->havoc_div) / 100))
		return MUTATOR_DONE;
	return splice_buffers(info, buf);
}

static int(*const mutate_funcs[])(mutate_info_t *, mutate_buffer_t *) = {
	single_walking_bit,
	two_walking_bit,
	four_walking_bit,
	walking_byte,
	two_walking_byte,
	four_walking_byte,
	one_byte_arithmetics,
	two_byte_arithmetics,
	four_byte_arithmetics,
	interesting_one_byte,
	interesting_two_byte,
	interesting_four_byte,
	dictionary_overwrite,
	dictionary_insert,
	afl_havoc,
	afl_splice,
};

/* Fuzzing stages */
enum {
	/* 00 */ STAGE_FLIP1,
	/* 01 */ STAGE_FLIP2,
	/* 02 */ STAGE_FLIP4,
	/* 03 */ STAGE_FLIP8,
	/* 04 */ STAGE_FLIP16,
	/* 05 */ STAGE_FLIP32,
	/* 06 */ STAGE_ARITH8,
	/* 07 */ STAGE_ARITH16,
	/* 08 */ STAGE_ARITH32,
	/* 09 */ STAGE_INTEREST8,
	/* 10 */ STAGE_INTEREST16,
	/* 11 */ STAGE_INTEREST32,
	/* 12 */ STAGE_EXTRAS_UO,
	/* 13 */ STAGE_EXTRAS_UI,
	/* 14 */ STAGE_HAVOC,
	/* 15 */ STAGE_SPLICE,
};


////////////////////////////////////////////////////////////////////////////////////////////
//// API methods ///////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

#ifndef ALL_MUTATORS_IN_ONE

/**
 * This function fills in m with all of the function pointers for this mutator.
 * @param m - a pointer to a mutator_t structure
 * @return none
 */
AFL_MUTATOR_API void init(mutator_t * m)
{
	memcpy(m, &afl_mutator, sizeof(mutator_t));
}

#endif

/**
 * This function creates and initializes a afl_state_t object based on the passed in JSON options.
 * @param options - a JSON of options for the afl mutator
 * @return the newly created afl_state_t object or NULL on failure
 */
static afl_state_t * setup_options(char * options)
{
	afl_state_t * state;
	state = (afl_state_t *)malloc(sizeof(afl_state_t));
	if (!state)
		return NULL;
	memset(state, 0, sizeof(afl_state_t));

	//Setup defaults
	if (reset_mutate_info(&state->info)) {
		free(state);
		return NULL;
	}
	state->info.should_skip_previous = 1;
	if (!options || !strlen(options))
		return state;

	PARSE_MUTATE_INFO_OPTIONS(state, options, FUNCNAME(cleanup), 0, 0);
	PARSE_OPTION_INT(state, options, skip_deterministic, "skip_deterministic", FUNCNAME(cleanup));
	if (state->skip_deterministic)
		state->info.stage = STAGE_HAVOC;
	return state;
}

/**
 * This function will allocate and initialize the mutator state used in the other Mutator API
 * functions.  
 * @param options - a json string that contains the mutator specific string of options.
 * @param state - Optionally, used to load a previously dumped state (with the get_state()
 * function), that defines the current iteration of the mutator.
 * @param input - used to produce new mutated inputs later when the mutate function is called
 * @param input_length - the size of the input buffer
 * @return a mutator specific structure or NULL on failure.
 */
AFL_MUTATOR_API void * FUNCNAME(create)(char * options, char * state, char * input, size_t input_length)
{
	GENERIC_MUTATOR_CREATE(afl_state_t, setup_options, FUNCNAME(cleanup));
}

/**
 * This function will release any resources that the mutator has open 
 * and free the mutator state structure.
 * @param mutator_state - a mutator specific structure previously created by 
 * the create function.  This structure will be freed and should not be referenced afterwards.
 */
AFL_MUTATOR_API void FUNCNAME(cleanup)(void * mutator_state)
{
	cleanup_mutate_info(&((afl_state_t *)mutator_state)->info);
	GENERIC_MUTATOR_CLEANUP(afl_state_t)
}

static int mutate_inner(void * mutator_state, char * buffer, size_t buffer_length, int is_thread_safe)
{
	afl_state_t * state = (afl_state_t *)mutator_state;
	mutate_buffer_t buf;
	int ret;
	if (buffer_length < state->input_length)
		return -1;

	buf.buffer = (uint8_t *)buffer;
	buf.length = MIN(buffer_length, state->input_length);
	buf.max_length = buffer_length;
	memcpy(buf.buffer, state->input, buf.length);

	if(is_thread_safe && take_mutex(state->info.mutate_mutex))
		return -1;
	state->iteration++;
	while (1) {
		ret = mutate_one(&state->info, &buf, mutate_funcs, ARRAY_SIZE(mutate_funcs));
		if (ret != MUTATOR_DONE)
			break;

		//We've finished this cycle, reset back to havoc and continue
		state->info.stage = STAGE_HAVOC;
		state->skip_deterministic = 1;
		state->info.queue_cycle++;
	}
	if (is_thread_safe && release_mutex(state->info.mutate_mutex))
		return -1;

	return ret;
}

/**
 * This function will mutate the input given in the create function and return it in the buffer argument.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param buffer - a buffer that the mutated input will be written to
 * @param buffer_length - the size of the passed in buffer argument.  It must be at least as large as
 * the original input buffer.
 * @return - the length of the mutated data, 0 when the mutator is out of mutations, or -1 on error
 */
AFL_MUTATOR_API int FUNCNAME(mutate)(void * mutator_state, char * buffer, size_t buffer_length)
{
	return mutate_inner(mutator_state, buffer, buffer_length, 0);
}

/**
 * This function will mutate the input given in the create function and return it in the buffer argument.
 * This function also accepts a set of flags which instruct it how to mutate the input.  See global_types.h
 * for the list of available flags.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param buffer - a buffer that the mutated input will be written to
 * @param buffer_length - the size of the passed in buffer argument.  It must be at least as large as
 * the original input buffer.
 * @param flags - A set of mutate flags that modify how this mutator mutates the input.
 * @return - the length of the mutated data, 0 when the mutator is out of mutations, or -1 on error
 */
AFL_MUTATOR_API int FUNCNAME(mutate_extended)(void * mutator_state, char * buffer, size_t buffer_length, uint64_t flags)
{
	SINGLE_INPUT_MUTATE_EXTENDED(afl_state_t, state->info.mutate_mutex);
}

/**
 * This function will return the state of the mutator.  The returned value can be used to restart the
 * mutator at a later time, by passing it to the create or set_state function.  It is the caller's
 * responsibility to free the memory allocated here by calling the free_state function.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @return - a buffer that defines the current state of the mutator.
 */
AFL_MUTATOR_API char * FUNCNAME(get_state)(void * mutator_state)
{
	afl_state_t * state = (afl_state_t *)mutator_state;
	json_t *state_obj, *temp;
	char * ret;

	state_obj = json_object();
	ADD_INT(temp, state->iteration, state_obj, "iteration");
	ADD_INT(temp, state->skip_deterministic, state_obj, "skip_deterministic");
	if (!add_mutate_info_to_json(state_obj, &state->info))
		return NULL;
	ret = json_dumps(state_obj, 0);
	json_decref(state_obj);
	return ret;
}

/**
 * This function will set the current state of the mutator.
 * This can be used to restart a mutator once from a previous run.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param state - a previously dumped state buffer obtained by the get_state function.
 * @return 0 on success or non-zero on failure
 */
AFL_MUTATOR_API int FUNCNAME(set_state)(void * mutator_state, char * state)
{
	afl_state_t * current_state = (afl_state_t *)mutator_state;
	int result, temp_int;
	if (!state)
		return 1;
	GET_INT(temp_int, state, current_state->iteration, "iteration", result);
	GET_INT(temp_int, state, current_state->skip_deterministic, "skip_deterministic", result);
	if (get_mutate_info_from_json(state, &current_state->info))
		return 1;
	return 0;
}

/**
 * This function will return the current iteration count of the mutator, i.e.
 * how many mutations have been generated with it.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @return value - the number of previously generated mutations
 */
AFL_MUTATOR_API int FUNCNAME(get_current_iteration)(void * mutator_state)
{
	GENERIC_MUTATOR_GET_ITERATION(afl_state_t);
}

/**
 * This function will set the mutator's input to something new.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param new_input - The new input used to produce new mutated inputs later when the mutate function is called
 * @param input_length - the size in bytes of the input buffer.
 * @return 0 on success and -1 on failure
 */
AFL_MUTATOR_API int FUNCNAME(set_input)(void * mutator_state, char * new_input, size_t input_length)
{
	GENERIC_MUTATOR_SET_INPUT(afl_state_t);
}

/**
 * Obtains information about the inputs that were given to the mutator when it was created
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param num_inputs - a pointer to an integer used to return the number of inputs given to this mutator
 * when it was created.  This parameter is optional and can be NULL, if this information is not needed
 * @param input_sizes - a pointer to a size_t array used to return the sizes of the inputs given to this
 * mutator when it was created. This parameter is optional and can be NULL, if this information is not needed.
 */
AFL_MUTATOR_API void FUNCNAME(get_input_info)(void * mutator_state, int * num_inputs, size_t **input_sizes)
{
	SINGLE_INPUT_GET_INFO(afl_state_t);
}

/**
 * This function sets a help message for the mutator.
 * @param help_str - A pointer that will be updated to point to the new help string.
 * @return 0 on success and -1 on failure
 */
AFL_MUTATOR_API int FUNCNAME(help)(char ** help_str)
{
	GENERIC_MUTATOR_HELP(
"afl - afl-based mutator\n"
"Options:\n"
"  dictionary            A file or directory containing dictionary to use while\n"
"                          mangling input\n"
"  havoc_div             A divisor for determining the number of rounds that\n"
"                          the havoc stage should run (typically 1, 2, 5, or 10)\n"
"  perf_score            A performance score used to determine how long to run\n"
"                          the havoc and splice stages.  Typically 100, higher\n"
"                          results in a larger number of mutations in these\n"
"                          stages before moving on.\n"
"  queue_cycle           The queue round counter.  Used in determining how to\n"
"                          mutate input.  Generally this shouldn't need to be set\n"
"  random_state0         The first half of the seed to afl's random number\n"
"                          generator\n"
"  random_state1         The second half of the seed to afl's random number\n"
"                          generator\n"
"  skip_deterministic    Instruct AFL to skip the deterministic mutations\n"
"  splice_filenames      An array of files to use during afl's splice stage,\n"
"                          for mixing with the input\n"
"\n"
	);
}
