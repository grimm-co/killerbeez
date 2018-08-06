#pragma once

#ifdef _WIN32
#include <Windows.h>
#else
#include <sys/types.h> // pid_t
#endif

#include <global_types.h>
#include <instrumentation.h>

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
FUNC_PREFIX int generic_wait_for_process_completion(HANDLE process, int timeout, instrumentation_t * instrumentation, void * instrumentation_state);
#else
FUNC_PREFIX int generic_wait_for_process_completion(pid_t process, int timeout, instrumentation_t * instrumentation, void * instrumentation_state);
#endif
FUNC_PREFIX int generic_test_next_input(void * state, mutator_t * mutator, void * mutator_state, char * buffer, size_t buffer_length,
	int(*test_input_func)(void * driver_state, char * buffer, size_t length), int * mutate_last_size);
FUNC_PREFIX int setup_mutate_buffer(double ratio, size_t input_length, char ** buffer, size_t * length);
#ifdef _WIN32
FUNC_PREFIX int send_tcp_input(SOCKET * sock, char * buffer, size_t length);
#else
FUNC_PREFIX int send_tcp_input(int * sock, char * buffer, size_t length);
#endif
