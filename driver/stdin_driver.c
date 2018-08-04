#include "stdin_driver.h"

#include <utils.h>
#include <jansson_helper.h>
#include <instrumentation.h>
#include "driver.h"

//c headers
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
//Windows API
#include <Shlwapi.h>
#include <process.h>
#else // linux
#include <string.h>    // memset, strlen
#include <sys/types.h> // kill
#include <signal.h>    // kill
#endif

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
 * @return - FUZZ_ on success or FUZZ_ERROR on failure
 */
int stdin_test_input(void * driver_state, char * input, size_t length)
{
	stdin_state_t * state = (stdin_state_t *)driver_state;

	//Start the process and give it our input
	if(state->instrumentation->enable(state->instrumentation_state, &state->process, state->cmd_line, input, length))
		return FUZZ_ERROR;

	//Wait for it to be done
	return generic_wait_for_process_completion(state->process, state->timeout,
		state->instrumentation, state->instrumentation_state);
}

/**
 * This function will run the fuzzed program with the output of the mutator given during driver
 * creation.  This function blocks until the program has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the stdin_create function
 * @return - FUZZ_ result on success, FUZZ_ERROR on error, -2 if the mutator has finished generating inputs
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
 * This function returns help text for this driver.  This help text will describe the driver and any options
 * that can be passed to stdin_create.
 * @param help_str - A pointer that will be updated to point to the new help string.
 * @return 0 on success and -1 on failure
 */
int stdin_help(char ** help_str)
{
	*help_str = strdup(
"stdin - Sends mutated input to the STDIN of the target process\n"
"Required Options:\n"
"  path                  The path to the target process\n"
"Optional Options:\n"
"  arguments             Arguments to pass to the target process\n"
"  ratio                 The ratio of mutation buffer size to input size when\n""                          given a mutator\n"
"  timeout               The maximum number of seconds to wait for the target\n"
"                          process to finish\n"
"\n"
	);
	if (*help_str == NULL)
		return -1;
	return 0;
}

