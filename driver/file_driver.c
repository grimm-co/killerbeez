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

static void cleanup_process(file_state_t * state);

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
	PARSE_OPTION_STRING(state, options, arguments, "arguments", file_cleanup);
	PARSE_OPTION_STRING(state, options, extension, "extension", file_cleanup);
	PARSE_OPTION_INT(state, options, timeout, "timeout", file_cleanup);
	PARSE_OPTION_DOUBLE(state, options, input_ratio, "ratio", file_cleanup);

	if (!state->path || !file_exists(state->path) || state->input_ratio <= 0)
	{
		file_cleanup(state);
		return NULL;
	}

	//Create a test filename to write the fuzz file to
	state->test_filename = get_temp_filename(state->extension);

	if (state->arguments)
	{
		int filename_length = strlen(state->test_filename);
		char * new_arguments, *pos, *temp;

		pos = new_arguments = state->arguments;
		while (*pos != 0)
		{
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
	cleanup_process(state);

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
 * @return - FUZZ_CRASH, FUZZ_HANG, or FUZZ_NONE on success or -1 on failure
 */
int file_test_input(void * driver_state, char * input, size_t length)
{
	file_state_t * state = (file_state_t *)driver_state;

	//Write the input to disk
	write_buffer_to_file(state->test_filename, input, length);

	//Start the process and give it our input
	if (state->instrumentation)
	{
		//Have the instrumentation start the new process, since it needs to do so in a custom environment
		state->instrumentation->enable(state->instrumentation_state, &state->process, state->cmd_line, NULL, 0);
	}
	else
	{
		//kill any previous processes so they release the file we're gonna write to
		cleanup_process(state);

		//Start the new process
		if (start_process_and_write_to_stdin(state->cmd_line, NULL, 0, &state->process))
		{
			cleanup_process(state);
			return -1;
		}
	}

	//Wait for it to be done
	generic_wait_for_process_completion(state->fuzz_result, state->process, state->timeout, state->instrumentation, state->instrumentation_state);

	return driver_get_fuzz_result(state->instrumentation, state->instrumentation_state);
}

/**
 * This function will run the fuzzed program with the output of the mutator given during driver
 * creation.  This function blocks until the program has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the file_create function
 * @return - FUZZ_CRASH, FUZZ_HANG, or FUZZ_NONE on success, -1 on error, -2 if the mutator has finished generating inputs
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
 * This function cleans up the fuzzed process, if it's not being managed
 * by the instrumentation module instead.
 * @param state - the file_state_t object that represents the current state of the driver
 */
static void cleanup_process(file_state_t * state)
{
	//If we have a process running and no instrumentation, kill it.
	//If we have an instrumentation, then the instrumentation will kill the process
	if (state->process && !state->instrumentation)
	{
		#ifdef _WIN32
		TerminateProcess(state->process, 9);
		CloseHandle(state->process);
		#else
		kill(state->process, SIGKILL);
		#endif
		state->process = NULL;
	}
}

/**
 * This function returns help text for this driver.  This help text will describe the driver and any options
 * that can be passed to file_create.
 * @return - a newly allocated string containing the help text.
 */
char * file_help(void)
{
	return strdup(
		"file - FILE driver (Writes mutated input to a file, that the target process uses)\n"
		"Required Options:\n"
		"\tpath                  The path to the target process\n"
		"Optional Options:\n"
		"\targuments             Arguments to pass to the target process, with the target filename specified as @@\n"
		"\textension             The file extension to give the test file\n"
		"\tratio                 The ratio of mutation buffer size to input size when given a mutator\n"
		"\ttimeout               The maximum number of seconds to wait for the target process to finish\n"
		"\n"
	);
}
