#include "nop_mutator.h"
#include <mutators.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <Windows.h>
#endif

struct nop_state
{
	char * input;
	size_t input_length;
	int iteration;
};
typedef struct nop_state nop_state_t;

mutator_t nop_mutator = {
	FUNCNAME(create),
	FUNCNAME(cleanup),
	FUNCNAME(mutate),
	FUNCNAME(mutate_extended),
	FUNCNAME(get_state),
	FUNCNAME(free_state),
	FUNCNAME(set_state),
	FUNCNAME(get_current_iteration),
	nop_get_total_iteration_count,
	FUNCNAME(get_input_info),
	FUNCNAME(set_input),
	FUNCNAME(help)
};

#ifndef ALL_MUTATORS_IN_ONE
NOP_MUTATOR_API void init(mutator_t * m)
{
	memcpy(m, &nop_mutator, sizeof(mutator_t));
}
#endif

NOP_MUTATOR_API void * FUNCNAME(create)(char * options, char * state, char * input, size_t input_length)
{
	nop_state_t * nop_state;
	nop_state = (nop_state_t *)malloc(sizeof(nop_state_t));
	if (!nop_state)
		return NULL;
	memset(nop_state, 0, sizeof(nop_state_t));

	nop_state->input = (char *)malloc(input_length);
	if (!nop_state->input || !input_length)
	{
		FUNCNAME(cleanup)(nop_state);
		return NULL;
	}
	memcpy(nop_state->input, input, input_length);
	nop_state->input_length = input_length;
	return nop_state;
}

NOP_MUTATOR_API void FUNCNAME(cleanup)(void * mutator_state)
{
	nop_state_t * nop_state = (nop_state_t *)mutator_state;
	free(nop_state->input);
	free(nop_state);
}

NOP_MUTATOR_API int FUNCNAME(mutate)(void * mutator_state, char * buffer, size_t buffer_length)
{
	nop_state_t * nop_state = (nop_state_t *)mutator_state;
#ifdef _WIN32
	InterlockedIncrement(&nop_state->iteration);
#else
	__sync_fetch_and_add(&nop_state->iteration, 1);
#endif
	memcpy(buffer, nop_state->input, nop_state->input_length > buffer_length ? buffer_length : nop_state->input_length);
	return nop_state->input_length;
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
NOP_MUTATOR_API int FUNCNAME(mutate_extended)(void * mutator_state, char * buffer, size_t buffer_length, uint64_t flags)
{
	if ((flags & MUTATE_MULTIPLE_INPUTS) && (flags & MUTATE_MULTIPLE_INPUTS_MASK) != 0)
		return -1;
	return FUNCNAME(mutate)(mutator_state, buffer, buffer_length);
}

NOP_MUTATOR_API char * FUNCNAME(get_state)(void * mutator_state)
{
	return "{}";
}

NOP_MUTATOR_API void FUNCNAME(free_state)(char * mutator_state)
{
}

NOP_MUTATOR_API int FUNCNAME(set_state)(void * mutator_state, char * state)
{
	return 0;
}

NOP_MUTATOR_API int FUNCNAME(get_current_iteration)(void * mutator_state)
{
	GENERIC_MUTATOR_GET_ITERATION(nop_state_t);
}

/**
 * Obtains information about the inputs that were given to the mutator when it was created
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param num_inputs - a pointer to an integer used to return the number of inputs given to this mutator
 * when it was created.  This parameter is optional and can be NULL, if this information is not needed
 * @param input_sizes - a pointer to a size_t array used to return the sizes of the inputs given to this
 * mutator when it was created. This parameter is optional and can be NULL, if this information is not needed.
 */
NOP_MUTATOR_API void FUNCNAME(get_input_info)(void * mutator_state, int * num_inputs, size_t **input_sizes)
{
	SINGLE_INPUT_GET_INFO(nop_state_t);
}

/**
* This function will set the input(saved in the mutators state) to something new.
* This can be used to reinitialize a mutator with new data, without reallocating the entire state struct.
* @param mutator_state - a mutator specific structure previously created by the create function.
* @param new_input - The new input used to produce new mutated inputs later when the mutate function is called
* @param input_length - the size in bytes of the input buffer.
* @return 0 on success and -1 on failure
*/
NOP_MUTATOR_API int FUNCNAME(set_input)(void * mutator_state, char * new_input, size_t input_length)
{
	GENERIC_MUTATOR_SET_INPUT(nop_state_t);
}

/**
* This function sets a help message for the mutator. This is useful
* if the mutator takes a JSON options string in the create() function.
* @param help_str - A pointer that will be updated to point to the new help string.
* @return 0 on success and -1 on failure
*/
NOP_MUTATOR_API int FUNCNAME(help)(char** help_str)
{
	GENERIC_MUTATOR_HELP(
		"nop - NOP mutator (doesn't mutate the input)\n"
		"Options:\n"
		"  None\n"
		"\n"
	);
}
