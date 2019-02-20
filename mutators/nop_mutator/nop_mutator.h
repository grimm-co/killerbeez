#pragma once

#include <global_types.h>
#include <mutators.h>

#ifdef _WIN32
#ifdef NOP_MUTATOR_EXPORTS
#define NOP_MUTATOR_API __declspec(dllexport)
#else
#define NOP_MUTATOR_API __declspec(dllimport)
#endif
#else //_WIN32
#define NOP_MUTATOR_API
#endif

#define MUTATOR_NAME "nop"

NOP_MUTATOR_API void * FUNCNAME(create)(char * options, char * state, char * input, size_t input_length);
NOP_MUTATOR_API void FUNCNAME(cleanup)(void * mutator_state);
NOP_MUTATOR_API int FUNCNAME(mutate)(void * mutator_state, char * buffer, size_t buffer_length);
NOP_MUTATOR_API int FUNCNAME(mutate_extended)(void * mutator_state, char * buffer, size_t buffer_length, uint64_t flags);
NOP_MUTATOR_API char * FUNCNAME(get_state)(void * mutator_state);
NOP_MUTATOR_API void FUNCNAME(free_state)(char * mutator_state);
NOP_MUTATOR_API int FUNCNAME(set_state)(void * mutator_state, char * state);
NOP_MUTATOR_API int FUNCNAME(get_current_iteration)(void * mutator_state);
#define nop_get_total_iteration_count return_unknown_or_infinite_total_iterations
NOP_MUTATOR_API void FUNCNAME(get_input_info)(void * mutator_state, int * num_inputs, size_t **input_sizes);
NOP_MUTATOR_API int FUNCNAME(set_input)(void * mutator_state, char * new_input, size_t input_length);
NOP_MUTATOR_API int FUNCNAME(help)(char ** help_str);

#ifndef ALL_MUTATORS_IN_ONE
NOP_MUTATOR_API void init(mutator_t * m);
#endif
