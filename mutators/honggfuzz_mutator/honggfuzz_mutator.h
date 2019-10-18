#pragma once

#include <global_types.h>
#include <mutators.h>
#include <afl_types.h> //grab the definition of MIN/MAX

#ifdef _WIN32
#ifdef HONGGFUZZ_MUTATOR_EXPORTS
#define HONGGFUZZ_MUTATOR_API __declspec(dllexport)
#else
#define HONGGFUZZ_MUTATOR_API __declspec(dllimport)
#endif
#else //_WIN32
#define HONGGFUZZ_MUTATOR_API
#endif

#define MUTATOR_NAME "honggfuzz"

HONGGFUZZ_MUTATOR_API void * FUNCNAME(create)(char * options, char * state, char * input, size_t input_length);
HONGGFUZZ_MUTATOR_API void FUNCNAME(cleanup)(void * mutator_state);
HONGGFUZZ_MUTATOR_API int FUNCNAME(mutate)(void * mutator_state, char * buffer, size_t buffer_length);
HONGGFUZZ_MUTATOR_API int FUNCNAME(mutate_extended)(void * mutator_state, char * buffer, size_t buffer_length, uint64_t flags);
HONGGFUZZ_MUTATOR_API char * FUNCNAME(get_state)(void * mutator_state);
#define honggfuzz_free_state default_free_state
HONGGFUZZ_MUTATOR_API int FUNCNAME(set_state)(void * mutator_state, char * state);
HONGGFUZZ_MUTATOR_API int FUNCNAME(get_current_iteration)(void * mutator_state);
#define honggfuzz_get_total_iteration_count return_unknown_or_infinite_total_iterations
HONGGFUZZ_MUTATOR_API void FUNCNAME(get_input_info)(void * mutator_state, int * num_inputs, size_t **input_sizes);
HONGGFUZZ_MUTATOR_API int FUNCNAME(set_input)(void * mutator_state, char * new_input, size_t input_length);
HONGGFUZZ_MUTATOR_API int FUNCNAME(help)(char ** help_str);

#ifndef ALL_MUTATORS_IN_ONE
HONGGFUZZ_MUTATOR_API void init(mutator_t * m);
#endif
