#include "stdin_driver.h"

#include <utils.h>
#include <jansson_helper.h>
#include <instrumentation.h>
#include "driver.h"

//c headers
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

//Windows API
#include <Shlwapi.h>
#include <process.h>

static void cleanup_process(stdin_state_t * state);

/**
 * This function creates a stdin_state_t object based on the given options.
 * @param options - A JSON string of the options to set in the new stdin_state_t. See the
 * help function for more information on the specific options available.
 * @return - the stdin_state_t generated from the options in the JSON options string, or NULL on failure
 */
static stdin_state_t * setup_options(char * options)
{
	stdin_state_t * state;
	size_t cmd_length;

	state = (stdin_state_t *)malloc(sizeof(stdin_state_t));
	if (!state)
		return NULL;
	memset(state, 0, sizeof(stdin_state_t));

	//Setup defaults
	state->timeout = 2;
	state->input_ratio = 2.0;

	//Parse the options
	PARSE_OPTION_STRING(state, options, path, "path", stdin_cleanup);
	PARSE_OPTION_STRING(state, options, arguments, "arguments", stdin_cleanup);
	PARSE_OPTION_INT(state, options, timeout, "timeout", stdin_cleanup);
	PARSE_OPTION_DOUBLE(state, options, input_ratio, "ratio", stdin_cleanup);

	cmd_length = (state->path ? strlen(state->path) : 0) + (state->arguments ? strlen(state->arguments) : 0) + 2;
	state->cmd_line = (char *)malloc(cmd_length);

	//Validate the options
	if (!state->path || !state->cmd_line || !file_exists(state->path) || state->input_ratio <= 0)
	{
		stdin_cleanup(state);
		return NULL;
	}

	snprintf(state->cmd_line, cmd_length, "%s %s", state->path, state->arguments ? state->arguments : "");

	return state;
}

/**
 * This function allocates and initializes a new driver specific state object based on the given options.
 * @param options - a JSON string that contains the driver specific string of options
 * @param instrumentation - a pointer to an instrumentation instance that the driver will use
 * to instrument the requested program.  This instrumentation instance should already be initialized.
 * @param instrumentation_state - a pointer to the instrumentation state for the passed in instrumentation
 * @return - a driver specific state object on success or NULL on failure
 */
void * stdin_create(char * options, instrumentation_t * instrumentation, void * instrumentation_state,
	mutator_t * mutator, void * mutator_state)
{
	stdin_state_t * state;
	int num_inputs;
	size_t *input_sizes;

	//This driver requires at least the path to the program to run. Make sure we either have both a mutator and state
	if (!options || !strlen(options) || (mutator && !mutator_state) || (!mutator && mutator_state)) //or neither
		return NULL;

	state = setup_options(options);
	if (!state)
		return NULL;

	if (mutator)
	{
		mutator->get_input_info(mutator_state, &num_inputs, &input_sizes);
		if (num_inputs != 1
			|| setup_mutate_buffer(state->input_ratio, input_sizes[0], &state->mutate_buffer, &state->mutate_buffer_length))
		{
			free(input_sizes);
			stdin_cleanup(state);
			return NULL;
		}
		free(input_sizes);
	}

	state->mutator = mutator;
	state->mutator_state = mutator_state;
	state->mutate_last_size = -1;
	state->instrumentation = instrumentation;
	state->instrumentation_state = instrumentation_state;
	return state;
}

/**
 * This function cleans up all resources with the passed in driver state.
 * @param driver_state - a driver specific state object previously created by the stdin_create function
 * This state object should not be referenced after this function returns.
 */
void stdin_cleanup(void * driver_state)
{
	stdin_state_t * state = (stdin_state_t *)driver_state;
	cleanup_process(state);

	free(state->mutate_buffer);
	free(state->path);
	free(state->arguments);
	free(state->cmd_line);
	free(state);
}

/**
 * This function will run the fuzzed program and test it with the given input. This function
 * blocks until the program has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the stdin_create function
 * @param input - the input that should be tested
 * @param length - the length of the input parameter
 * @return - FUZZ_CRASH, FUZZ_HANG, or FUZZ_NONE on success or -1 on failure
 */
int stdin_test_input(void * driver_state, char * input, size_t length)
{
	stdin_state_t * state = (stdin_state_t *)driver_state;

	//Start the process and give it our input
	if (state->instrumentation)
	{
		//Have the instrumentation start the new process, since it needs to do so in a custom environment
		state->instrumentation->enable(state->instrumentation_state, &state->process, state->cmd_line, input, length);
	}
	else
	{
		//kill any previous processes so they release the file we're gonna write to
		cleanup_process(state);

		//Start the new process
		if (start_process_and_write_to_stdin(state->cmd_line, input, length, &state->process))
		{
			cleanup_process(state);
			return -1;
		}
	}

	//Wait for it to be done
	generic_wait_for_process_completion(state->process, state->timeout, state->instrumentation, state->instrumentation_state);

	return driver_get_fuzz_result(state->instrumentation, state->instrumentation_state);
}

/**
 * This function will run the fuzzed program with the output of the mutator given during driver
 * creation.  This function blocks until the program has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the stdin_create function
 * @return - FUZZ_CRASH, FUZZ_HANG, or FUZZ_NONE on success, -1 on error, -2 if the mutator has finished generating inputs
 */
int stdin_test_next_input(void * driver_state)
{
	stdin_state_t * state = (stdin_state_t *)driver_state;
	return generic_test_next_input(state, state->mutator, state->mutator_state, state->mutate_buffer,
		state->mutate_buffer_length, stdin_test_input, &state->mutate_last_size);
}

/**
 * When this driver is using a mutator given to it during driver creation, this function retrieves
 * the last input that was tested with the stdin_test_next_input function.
 * @param driver_state - a driver specific structure previously created by the stdin_create function
 * @param length - a pointer to an integer used to return the length of the input that was last tested.
 * @return - NULL on error or if the driver doesn't have a mutator, or a buffer containing the last input
 * that was tested by the driver with the stdin_test_next_input function.  This buffer should be freed
 * by the caller.
 */
char * stdin_get_last_input(void * driver_state, int * length)
{
	stdin_state_t * state = (stdin_state_t *)driver_state;
	if (!state->mutator || state->mutate_last_size <= 0)
		return NULL;
	*length = state->mutate_last_size;
	return memdup(state->mutate_buffer, state->mutate_last_size);
}

/**
 * This function cleans up the fuzzed process, if it's not being managed
 * by the instrumentation module instead.
 * @param state - the stdin_state_t object that represents the current state of the driver
 */
static void cleanup_process(stdin_state_t * state)
{
	//If we have a process running and no instrumentation, kill it.
	//If we have an instrumentation, then the instrumentation will kill the process
	if (state->process && !state->instrumentation)
	{
		TerminateProcess(state->process, 9);
		CloseHandle(state->process);
		state->process = NULL;
	}
}

/**
 * This function returns help text for this driver.  This help text will describe the driver and any options
 * that can be passed to stdin_create.
 * @return - a newly allocated string containing the help text.
 */
char * stdin_help(void)
{
	return strdup(
		"stdin - STDIN driver (Sends mutated input to the STDIN of the target process)\n"
		"Required Options:\n"
		"\tpath                  The path to the target process\n"
		"Optional Options:\n"
		"\targuments             Arguments to pass to the target process\n"
		"\tratio                 The ratio of mutation buffer size to input size when given a mutator\n"
		"\ttimeout               The maximum number of seconds to wait for the target process to finish\n"
		"\n"
	);
}
