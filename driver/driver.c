#include <jansson.h>
#include <jansson_helper.h>
#include <global_types.h>
#include <utils.h>
#include <instrumentation.h>
#include "driver.h"

#include <time.h>

#ifndef _WIN32
#include <unistd.h>
#endif

/**
 * Waits for a fuzzed process to be finished processing the input, either via timing out or the
 * process exiting.
 * @param process - a HANDLE to the fuzzed process
 * @param timeout - The maximum number of seconds to wait before declaring the process done
 * @param instrumentation - used to access `is_process_done` and `get_fuzz_result`
 * @param instrumentation_state - arguments for `is_process_done` and `get_fuzz_result`
 * @return - FUZZ_HANG or FUZZ_ result (from get_fuzz_result)
 */
#ifdef _WIN32
int generic_wait_for_process_completion(HANDLE process, int timeout, instrumentation_t * instrumentation, void * instrumentation_state)
#else
int generic_wait_for_process_completion(pid_t process, int timeout, instrumentation_t * instrumentation, void * instrumentation_state)
#endif
{
	time_t start_time = time(NULL);
	int process_done = 0;

	while(1)
	{
		process_done = instrumentation->is_process_done(instrumentation_state);
		if (process_done == 1)
			return instrumentation->get_fuzz_result(instrumentation_state);
		else if (process_done == -1)
			return FUZZ_ERROR;
		// if it's zero, the process is not done, so keep looping

		// timeout
		if (time(NULL) - start_time > timeout)
			return FUZZ_HANG;

		// FUZZ_HANG isn't ever set in the instrumentation, which isn't great.
		// could be solved by adding a set_fuzz_result function to the API. I
		// am unaware of any API constraints that require it at this time. A
		// potential issue I forsee is that a second get_fuzz_result would
		// incorrectly report FUZZ_RUNNING.

		#ifdef _WIN32
		Sleep(5);
		#else
		usleep(5*1000);
		#endif
	}
}

/**
 * This function will call mutate on the given mutator state to modify the mutator buffer
 * and then, if the mutation succeeds, call the given test_input function with the mutated
 * buffer
 * @param state - a driver specific structure previously created by the driver's create function
 * @param mutator - the mutator to call to obtain a mutated input buffer
 * @param mutator_state - the state of the mutator given in the mutator parameter
 * @param buffer - the buffer to write the mutated input to
 * @param buffer_length - the length of the buffer parameter
 * @param test_input_func - the test_input function to call after mutating the input buffer
 * @param mutate_last_size - this parameter is used to return the size of the mutated input buffer
 * @return - FUZZ_CRASH, FUZZ_HANG, or FUZZ_NONE on success, FUZZ_ERROR on error, -2 if the mutator has finished generating inputs
 */
int generic_test_next_input(void * state, mutator_t * mutator, void * mutator_state, char * buffer, size_t buffer_length,
	int (*test_input_func)(void * driver_state, char * buffer, size_t length), int * mutate_last_size)
{
	if (!mutator)
		return -1;
	*mutate_last_size = mutator->mutate(mutator_state, buffer, buffer_length);
	if (*mutate_last_size < 0)
		return -1;
	else if (*mutate_last_size == 0)
		return -2;
	return test_input_func(state, buffer, *mutate_last_size);
}

/**
 * This function allocates a buffer to be used for holding the mutated input that a driver will
 * to the target program.
 * @param ratio - The desired ratio of mutate buffer size to input size.
 * @param input_length - The size of the input buffer
 * @param buffer - a pointer to a buffer pointer, used to return the allocated buffer
 * @param length - a pointer to a size_t variable, used to return the allocated buffer's length
 * @return - zero on success, non-zero on failure
 */
int setup_mutate_buffer(double ratio, size_t input_length, char ** buffer, size_t * length)
{
	size_t output_size;
	char * output_buffer;

	output_size = (size_t)(input_length * ratio);
	if (!output_size)
		return 1;

	output_buffer = malloc(output_size);
	if (!output_buffer)
		return 1;

	*buffer = output_buffer;
	*length = output_size;
	return 0;
}
