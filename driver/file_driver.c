#include "file_driver.h"

#include <utils.h>
#include <jansson_helper.h>
#include <instrumentation.h>
#include "driver.h"

//c headers
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#include <Shlwapi.h>
#include <process.h>
#else
#include <string.h> // memset
#include <sys/types.h> // kill()
#include <signal.h>
#include <unistd.h> // unlink
#endif

/**
 * This function creates a file_state_t object based on the given options.
 * @param options - A JSON string of the options to set in the new file_state_t. See the
 * help function for more information on the specific options available.
 * @return - the file_state_t generated from the options in the JSON options string, or NULL on failure
 */
static file_state_t * setup_options(char * options)
{
	file_state_t * state;
	size_t cmd_length;

	state = (file_state_t *)malloc(sizeof(file_state_t));
	if (!state)
		return NULL;
	memset(state, 0, sizeof(file_state_t));

	//Setup defaults
	state->timeout = 2;
	state->extension = strdup(".dat");
	state->input_ratio = 2.0;

	//Parse the options
	PARSE_OPTION_STRING(state, options, path, "path", file_cleanup);
	PARSE_OPTION_STRING(state, options, test_filename, "filename", file_cleanup);
	PARSE_OPTION_STRING(state, options, arguments, "arguments", file_cleanup);
	PARSE_OPTION_STRING(state, options, extension, "extension", file_cleanup);
	PARSE_OPTION_INT(state, options, timeout, "timeout", file_cleanup);
	PARSE_OPTION_DOUBLE(state, options, input_ratio, "ratio", file_cleanup);

	if (!state->path || !file_exists(state->path) || state->input_ratio <= 0)
	{
		file_cleanup(state);
		return NULL;
	}

	//If the user didn't specify a test filename to
	if(!state->test_filename) {//write the fuzz data to, generate a test filename now
		if(!state->arguments || !strstr(state->arguments, "@@")) {
			ERROR_MSG("Test filename not specified and the target program's arguments do not include the test filename "
				"symbol (\"@@\"). The target program will not be able to receive the mutated input data.");
			ERROR_MSG("Use the \"argument\" or \"filename\" options to pass the mutated input to the target program");
			file_cleanup(state);
			return NULL;
		}
		state->test_filename = get_temp_filename(state->extension);
	}

	if (state->arguments)
	{
		int filename_length = strlen(state->test_filename);
		char * new_arguments, *pos, *temp;

		pos = new_arguments = state->arguments;
		while (*pos != 0)
		{
			// replace the "@@" in the arguments with the temp filename
			if (*pos == '@' && *(pos + 1) == '@')
			{
				int index = pos - new_arguments;
				size_t temp_size = (filename_length - 2) + strlen(new_arguments) + 1;

				temp = (char *)malloc(temp_size);
				memset(temp, 0, temp_size);
				memcpy(temp, new_arguments, index);
				memcpy(temp + index, state->test_filename, filename_length);
				memcpy(temp + index + filename_length, pos + 2, strlen(new_arguments) - (index + 2));

				free(new_arguments);
				new_arguments = temp;
				pos = new_arguments + index + filename_length;
			}
			else
				pos++;
		}
		state->arguments = new_arguments;
	}

	cmd_length = (state->path ? strlen(state->path) : 0) + (state->arguments ? strlen(state->arguments) : 0) + 2;
	state->cmd_line = (char *)malloc(cmd_length);
	if (!state->cmd_line)
	{
		file_cleanup(state);
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
void * file_create(char * options, instrumentation_t * instrumentation, void * instrumentation_state,
	mutator_t * mutator, void * mutator_state)
{
	file_state_t * state;
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
			file_cleanup(state);
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
 * @param driver_state - a driver specific state object previously created by the file_create function
 * This state object should not be referenced after this function returns.
 */
void file_cleanup(void * driver_state)
{
	file_state_t * state = (file_state_t *)driver_state;

	free(state->mutate_buffer);

	free(state->path);
	free(state->extension);
	free(state->arguments);
	free(state->cmd_line);
	if (state->test_filename)
	{
		unlink(state->test_filename);
		free(state->test_filename);
	}
	free(state);
}

/**
 * This function will run the fuzzed program and test it with the given input. This function
 * blocks until the program has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the file_create function
 * @param input - the input that should be tested
 * @param length - the length of the input parameter
 * @return - FUZZ_ result on success or FUZZ_ERROR on failure
 */
int file_test_input(void * driver_state, char * input, size_t length)
{
	file_state_t * state = (file_state_t *)driver_state;

	//Write the input to disk
	write_buffer_to_file(state->test_filename, input, length);

	//Start the process and give it our input
	if(state->instrumentation->enable(state->instrumentation_state, &state->process, state->cmd_line, NULL, 0))
		return FUZZ_ERROR;

	//Wait for it to be done, return the termination termination status
	return generic_wait_for_process_completion(state->process, state->timeout,
		state->instrumentation, state->instrumentation_state);
}

/**
 * This function will run the fuzzed program with the output of the mutator given during driver
 * creation.  This function blocks until the program has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the file_create function
 * @return - FUZZ_ result on success, FUZZ_ERROR on error, -2 if the mutator has finished generating inputs
 */
int file_test_next_input(void * driver_state)
{
	file_state_t * state = (file_state_t *)driver_state;
	return generic_test_next_input(state, state->mutator, state->mutator_state, state->mutate_buffer,
		state->mutate_buffer_length, file_test_input, &state->mutate_last_size);
}

/**
 * When this driver is using a mutator given to it during driver creation, this function retrieves
 * the last input that was tested with the file_test_next_input function.
 * @param driver_state - a driver specific structure previously created by the file_create function
 * @param length - a pointer to an integer used to return the length of the input that was last tested.
 * @return - NULL on error or if the driver doesn't have a mutator, or a buffer containing the last input
 * that was tested by the driver with the file_test_next_input function.  This buffer should be freed
 * by the caller.
 */
char * file_get_last_input(void * driver_state, int * length)
{
	file_state_t * state = (file_state_t *)driver_state;
	if (!state->mutator || state->mutate_last_size <= 0)
		return NULL;
	*length = state->mutate_last_size;
	return memdup(state->mutate_buffer, state->mutate_last_size);
}

/**
 * This function returns help text for this driver.  This help text will describe the driver and any options
 * that can be passed to file_create.
 * @param help_str - A pointer that will be updated to point to the new help string.
 * @return 0 on success and -1 on failure
 */
int file_help(char ** help_str)
{
	*help_str = strdup(
"file - Writes mutated input to a file, that the target process uses\n"
"Required Options:\n"
"  path                  The path to the target process\n"
"Optional Options:\n"
"  arguments             Arguments to pass to the target process, with the\n"
"                          target filename specified as @@\n"
"  extension             The file extension to give the test file\n"
"  filename              The filename to give the test file\n"
"  ratio                 The ratio of mutation buffer size to input size when\n"
"                          given a mutator\n"
"  timeout               The maximum number of seconds to wait for the target\n"
"                          process to finish\n"
"\n"
	);
	if (*help_str == NULL)
		return -1;
	return 0;
}
