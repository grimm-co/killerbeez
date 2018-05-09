#include <jansson.h>
#include <jansson_helper.h>
#include <global_types.h>
#include <utils.h>
#include "instrumentation.h"
#include "driver.h"

#include <time.h>

/**
 * This function determines if the fuzzed process has finished processing the input that was last given to it
 * @param process - a HANDLE to the fuzzed process
 * @param start_time - The time the process was started
 * @param timeout - The number of seconds to wait before declaring the process done
 * @return - Returns 1 if the fuzzed process is done processing the input, 0 otherwise
 */
int generic_done_processing_input(HANDLE process, time_t start_time, int timeout)
{
	int status = is_process_alive(process);
	if (status == 0)
		return 1;

	return time(NULL) - start_time > timeout;
}

/**
 * Waits for a fuzzed process to be finished processing the input, either via timing out or the
 * process exiting.
 * @param process - a HANDLE to the fuzzed process
 * @param timeout - The maximum number of seconds to wait before declaring the process done
 * @param instrumentation - Optionally, an instrumentation struct that should be used to check if the process is
 * done yet
 * @param instrumentation_state - if the instrumentation parameter is provided, this parameter should define the
 * instrumentation state to check if the process is done yet.
 */
void generic_wait_for_process_completion(HANDLE process, int timeout, instrumentation_t * instrumentation, void * instrumentation_state)
{
	time_t start_time = time(NULL);

	//If the instrumentation has a wait for target completion method, use that instead.
	while (1)
	{
		if(generic_done_processing_input(process, start_time, timeout) > 0)
			break;
		if (instrumentation && instrumentation->is_process_done && instrumentation->is_process_done(instrumentation_state))
			break;
		Sleep(5);
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
 * @return - 0 on success, -1 on error, or -2 if the mutator has finished generating inputs
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