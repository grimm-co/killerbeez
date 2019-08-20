#pragma once

#ifdef _WIN32
#if defined(MUTATORS_EXPORTS)
#define MUTATORS_API __declspec(dllexport)
#elif defined(MUTATORS_NO_IMPORT)
#define MUTATORS_API
#elif defined(__cplusplus)
#define MUTATORS_API extern "C" __declspec(dllimport)
#else
#define MUTATORS_API __declspec(dllimport)
#endif
#else
#define MUTATORS_API
#endif

//If you're combining all of the mutators into one project, uncomment this to give them all
//unique names
//#define ALL_MUTATORS_IN_ONE
#ifndef ALL_MUTATORS_IN_ONE
#define FUNCNAME(name) name
#else
#define FUNCNAME(name) MUTATOR_NAME ## _ ## name
#endif

MUTATORS_API void default_free_state(char * state);
MUTATORS_API int return_unknown_or_infinite_total_iterations(void * mutator_state);

#define GENERIC_MUTATOR_CREATE(type_t, option_parser_func, cleanup_state_func) \
	type_t * new_state = option_parser_func(options);                            \
	if (!new_state)                                                              \
		return NULL;                                                               \
	new_state->input = (char *)malloc(input_length);                             \
	if (!new_state->input || !input_length)                                      \
	{                                                                            \
		cleanup_state_func(new_state);                                             \
		return NULL;                                                               \
	}                                                                            \
	memcpy(new_state->input, input, input_length);                               \
	new_state->input_length = input_length;                                      \
	if(state && FUNCNAME(set_state)(new_state, state)) {                         \
		cleanup_state_func(new_state);                                       \
		return NULL;                                                         \
	}                                                                            \
	return new_state;

#define GENERIC_MUTATOR_CLEANUP(type_t)                                        \
	type_t * cleanup_state = (type_t *)mutator_state;                            \
	free(cleanup_state->input);                                                  \
	free(cleanup_state);

#define GENERIC_MUTATOR_GET_ITERATION(type_t)                                  \
	type_t * iteration_state = (type_t *)mutator_state;                          \
	return iteration_state->iteration;

#define GENERIC_MUTATOR_SET_INPUT(type_t)                                      \
	type_t * state = (type_t *)mutator_state;                                    \
	if (state->input)                                                            \
		free(state->input);                                                        \
	state->input = (char *)malloc(input_length);                                 \
	if (!state->input)                                                           \
		return -1;                                                                 \
	state->input_length = input_length;                                          \
	memcpy(state->input, new_input, input_length);                               \
	return 0;

#define GENERIC_MUTATOR_HELP(msg)                                              \
	*help_str = strdup(msg);                                                     \
	if (*help_str == NULL)                                                       \
		return -1;                                                                 \
	return 0;                                                                    \

#define SINGLE_INPUT_GET_INFO(type_t)                                            \
	type_t * state = (type_t *)mutator_state;                                    \
	if (num_inputs)                                                              \
		*num_inputs = 1;                                                         \
	if (input_sizes) {                                                           \
		*input_sizes = malloc(sizeof(size_t));                                   \
		*input_sizes[0] = state->input_length;                                   \
	}

#define SINGLE_INPUT_MUTATE_EXTENDED(type_t, mutex)                                   \
	type_t * state = (type_t *)mutator_state;                                           \
	int ret;                                                                            \
	if ((flags & MUTATE_MULTIPLE_INPUTS) && (flags & MUTATE_MULTIPLE_INPUTS_MASK) != 0) \
		return -1;                                                                        \
	if ((flags & MUTATE_THREAD_SAFE) && take_mutex(mutex))                              \
		return -1;                                                                        \
	ret = FUNCNAME(mutate)(state, buffer, buffer_length);                               \
	if ((flags & MUTATE_THREAD_SAFE) && release_mutex(mutex))                           \
		return -1;                                                                        \
	return ret;

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u64 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

