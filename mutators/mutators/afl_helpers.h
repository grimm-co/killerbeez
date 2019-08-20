#pragma once

#include "mutators.h"
#include "afl_types.h"

#include <utils.h>
#include <jansson_helper.h>

typedef struct {
	u8* s;
	size_t len;
} string_t;

typedef struct {
	uint8_t * buffer;
	size_t length;
	size_t max_length;
} mutate_buffer_t;

typedef struct {
	int should_skip_previous;
	int one_stage_only;
	int havoc_div;
	int perf_score;

	char * dictionary_file;
	uint64_t dictionary_count;
	string_t ** dictq;

	char ** splice_filenames;
	size_t splice_filenames_count;
	uint64_t splice_files_count;
	string_t ** splice_files;

	//Used to protects the fields below, as well as any non-thread safe fields in
	mutex_t mutate_mutex; //the mutator-specific state (such as the iteration)

	uint64_t random_state[2]; //the state of the random number generator
	uint64_t stage_cur; //The current iteration number for the current mutation stage
	int stage; //The current mutation stage, an index into the mutation functions passed to mutate_one
	int queue_cycle;

} mutate_info_t;

MUTATORS_API u32 UR(mutate_info_t * info, u32 limit);
MUTATORS_API int load_dictionary(mutate_info_t * info, char * path);
MUTATORS_API int load_splice_files(mutate_info_t * info, char ** splice_filenames, size_t splice_filenames_count);
MUTATORS_API int reset_mutate_info(mutate_info_t * info);
MUTATORS_API void cleanup_mutate_info(mutate_info_t * info);
MUTATORS_API int add_mutate_info_to_json(json_t * obj, mutate_info_t * info);
MUTATORS_API int get_mutate_info_from_json(char * state, mutate_info_t * info);
MUTATORS_API int mutate_one(mutate_info_t * info, mutate_buffer_t * buf, int(*const*mutate_funcs)(mutate_info_t *, mutate_buffer_t *), size_t num_funcs);

//Individual mutation functions
MUTATORS_API int single_walking_bit(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int two_walking_bit(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int four_walking_bit(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int walking_byte(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int two_walking_byte(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int four_walking_byte(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int one_byte_arithmetics(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int two_byte_arithmetics(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int four_byte_arithmetics(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int interesting_one_byte(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int interesting_two_byte(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int interesting_four_byte(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int dictionary_overwrite(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int dictionary_insert(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int havoc(mutate_info_t * info, mutate_buffer_t * buf);
MUTATORS_API int splice_buffers(mutate_info_t * info, mutate_buffer_t * buf);

//There are no more mutations possible for this mutation function
#define MUTATOR_DONE 0
//This specific mutation can't be done, try again (i.e. we are trying a mutation
//that was already done in an earlier round)
#define MUTATOR_TRY_AGAIN -1

//A macro to parse the options used during afl fuzzing
#define PARSE_MUTATE_INFO_OPTIONS(state, options, cleanup_func, dictionary_required, splice_required) \
	PARSE_OPTION_UINT64T_TEMP(state, options, info.random_state[0], "random_state0", cleanup_func, random_state0);                     \
	PARSE_OPTION_UINT64T_TEMP(state, options, info.random_state[1], "random_state1", cleanup_func, random_state1);                     \
	PARSE_OPTION_INT_TEMP(state, options, info.stage, "stage", cleanup_func, stage);                                                   \
	PARSE_OPTION_INT_TEMP(state, options, info.stage_cur, "stage_cur", cleanup_func, stage_cur);                                       \
	PARSE_OPTION_INT_TEMP(state, options, info.should_skip_previous, "skip_previous_stages", cleanup_func, should_skip_previous);      \
	PARSE_OPTION_INT_TEMP(state, options, info.queue_cycle, "queue_cycle", cleanup_func, queue_cycle);                                 \
	PARSE_OPTION_INT_TEMP(state, options, info.havoc_div, "havoc_div", cleanup_func, havoc_div);                                       \
	PARSE_OPTION_INT_TEMP(state, options, info.perf_score, "perf_score", cleanup_func, perf_score);                                    \
	PARSE_OPTION_STRING_TEMP(state, options, info.dictionary_file, "dictionary", cleanup_func, dictionary);                            \
	PARSE_OPTION_ARRAY_TEMP(state, options, info.splice_filenames, info.splice_filenames_count, "splice_filenames", cleanup_func, ss); \
	if ((dictionary_required && !state->info.dictionary_file) ||                                                                       \
		(state->info.dictionary_file && load_dictionary(&state->info, state->info.dictionary_file)))                                   \
	{                                                                                                                                  \
		cleanup_func(state);                                                                                                           \
		return NULL;                                                                                                                   \
	}                                                                                                                                  \
	if ((splice_required && !state->info.splice_filenames_count) ||                                                                    \
		(state->info.splice_filenames_count &&                                                                                         \
			load_splice_files(&state->info, state->info.splice_filenames, state->info.splice_filenames_count)))                        \
	{                                                                                                                                  \
		cleanup_func(state);                                                                                                           \
		return NULL;                                                                                                                   \
	}                                                                                                                                  \

