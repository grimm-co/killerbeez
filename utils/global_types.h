#pragma once

#include <stdlib.h>
#include <stdint.h>

/**
 * This macro can be used to mask off the rest of the flags in mutate_extended's
 * flag parameter to get just the input part's index that should be mutated when
 * the MUTATE_MULTIPLE_INPUTS bit is set.
 */
#define MUTATE_MULTIPLE_INPUTS_MASK ((1 << 16) - 1)
/**
 * This flag signifies that the mutator should mutate a specific input part,
 * defined by the index set in the bits covered by MUTATE_MULTIPLE_INPUTS_MASK
 */
#define MUTATE_MULTIPLE_INPUTS (1 << 16)
/**
 * This flag signifies that the mutations should be done in a thread safe way.
 */
#define MUTATE_THREAD_SAFE (1 << 17)

typedef struct mutator
{
	void * (*create)(char * options, char * state, char * input, size_t input_length);
	void(*cleanup)(void * mutator_state);

	int(*mutate)(void * mutator_state, char * buffer, size_t buffer_length);
	int(*mutate_extended)(void * mutator_state, char * buffer, size_t buffer_length, uint64_t flags);

	char * (*get_state)(void * mutator_state);
	void(*free_state)(char * state);
	int(*set_state)(void * mutator_state, char * state);

	int(*get_current_iteration)(void * mutator_state);
	int(*get_total_iteration_count)(void * mutator_state);
	void(*get_input_info)(void * mutator_state, int * num_inputs, size_t **input_sizes);

	int(*set_input)(void * mutator_state, char * new_input, size_t input_length);
	int(*help)(char **help_str);
} mutator_t;
