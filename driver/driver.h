#pragma once

#ifdef _WIN32
#include <Windows.h>
#else
#include <sys/types.h> // pid_t
#endif

#include "global_types.h"
#include "instrumentation.h"

#ifdef DRIVER_EXPORTS
#define DRIVER_API __declspec(dllexport)
#elif defined(DRIVER_NO_IMPORT)
#define DRIVER_API
#else
#define DRIVER_API __declspec(dllimport)
#endif

#ifdef __cplusplus
#define FUNC_PREFIX extern "C"
#else
#define FUNC_PREFIX
#endif

struct driver
{
	void (*cleanup)(void * driver_state);
	int (*test_input)(void * driver_state, char * buffer, size_t length);
	int (*test_next_input)(void * driver_state);
	char *(*get_last_input)(void * driver_state, int * length);
	void * state;
};
typedef struct driver driver_t;

#ifdef _WIN32
FUNC_PREFIX int generic_done_processing_input(int * fuzz_result, HANDLE process, time_t start_time, int timeout);
FUNC_PREFIX void generic_wait_for_process_completion(int * fuzz_result, HANDLE process, int timeout, instrumentation_t * instrumentation, void * instrumentation_state);
#else
FUNC_PREFIX int generic_done_processing_input(int * fuzz_result, pid_t process, time_t start_time, int timeout);
FUNC_PREFIX void generic_wait_for_process_completion(int * fuzz_result, pid_t process, int timeout, instrumentation_t * instrumentation, void * instrumentation_state);
#endif
FUNC_PREFIX int generic_test_next_input(void * state, mutator_t * mutator, void * mutator_state, char * buffer, size_t buffer_length,
	int(*test_input_func)(void * driver_state, char * buffer, size_t length), int * mutate_last_size);
FUNC_PREFIX int setup_mutate_buffer(double ratio, size_t input_length, char ** buffer, size_t * length);
FUNC_PREFIX int driver_get_fuzz_result(int * fuzz_result, instrumentation_t * instrumentation, void * instrumentation_state);
