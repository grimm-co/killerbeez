#pragma once
#include <global_types.h>

//Helper functions
void * setup_mutator(mutator_t * mutator, char * mutator_options, char * seed_buffer, size_t seed_length);
void print_usage(char * executable_name);

//Test functions
#define NUM_TESTS 7
int test_all(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length);
int test_mutate(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length);
int test_state(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length);
int test_thread_mutate(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length);
int test_run_forever(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length);
int test_mutate_parts(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length);
int test_mutate_once(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length);

//Test types
typedef int(*test_function)(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length);
typedef struct test_info
{
	test_function func;
	const char * usage_info;
} test_info_t;
