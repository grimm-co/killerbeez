// Linux-only return code instrumentation.

#include <string.h>    // memset
#include <sys/types.h> // kill
#include <signal.h>    // kill

#include "instrumentation.h"
#include "return_code_instrumentation.h"

#include <utils.h>
#include <jansson_helper.h>

////////////////////////////////////////////////////////////////
// Private methods /////////////////////////////////////////////
////////////////////////////////////////////////////////////////

/**
 * This function terminates the fuzzed process and sets the result in the
 * instrumentation state.
 *
 * @param state - The return_code_state_t object containing this
 * instrumentation's state
 */
static void destroy_target_process(return_code_state_t * state)
{
	if (state->child_handle) {
		state->last_status = get_process_status(state->child_handle);
		kill(state->child_handle, SIGKILL);
		state->child_handle = 0;
	}
}

/**
 * This function starts the fuzzed process
 * @param state - The return_code_state_t object containing this instrumentation's state
 * @param cmd_line - the command line of the fuzzed process to start
 * @param stdin_input - the input to pass to the fuzzed process's stdin
 * @param stdin_length - the length of the stdin_input parameter
 * @return - zero on success, non-zero on failure.
 */
static int create_target_process(return_code_state_t * state, char* cmd_line, char * stdin_input, size_t stdin_length)
{
	state->last_status = FUZZ_RUNNING;
	state->process_reaped = 0;

	//Create the child process
	if (start_process_and_write_to_stdin(cmd_line, stdin_input, stdin_length, &state->child_handle)) {
		state->child_handle = 0;
		ERROR_MSG("Failed to create process with command line: %s\n", cmd_line);
		return -1;
	}

	return 0;
}

////////////////////////////////////////////////////////////////
// Instrumentation methods /////////////////////////////////////
////////////////////////////////////////////////////////////////

/**
 * This function allocates and initializes a new instrumentation specific state object based on the given options.
 * @param options - a JSON string that contains the instrumentation specific string of options
 * @param state - an instrumentation specific JSON string previously returned from return_code_get_state that should be loaded
 * @return - An instrumentation specific state object on success or NULL on failure
 */
void * return_code_create(char * options, char * state)
{
	// Allocate and initialize return_code state object.
	return_code_state_t * return_code_state;
	return_code_state = malloc(sizeof(return_code_state_t));
	if (!return_code_state)
		return NULL;
	memset(return_code_state, 0, sizeof(return_code_state_t));

	if (state && return_code_set_state(return_code_state, state))
	{
		return_code_cleanup(return_code_state);
		return NULL;
	}

	return return_code_state;
}

/**
 * This function cleans up all resources with the passed in instrumentation state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the return_code_create function
 * This state object should not be referenced after this function returns.
 */
void return_code_cleanup(void * instrumentation_state)
{
	return_code_state_t * state = (return_code_state_t *)instrumentation_state;

	destroy_target_process(state);

	free(state);
}

/**
 * This function merges the coverage information from two instrumentation states.  This will always fail for the
 * return_code instrumentation, since it does not record instrumentation data.
 * @param instrumentation_state - an instrumentation specific state object previously created by the return_code_create function
 * @param other_instrumentation_state - an instrumentation specific state object previously created by the return_code_create function
 * @return - An instrumentation specific state object that contains the combination of both of the passed in instrumentation states
 * on success, or NULL on failure
 */
void * return_code_merge(void * instrumentation_state, void * other_instrumentation_state)
{
	return NULL; // No instrumentation data, so we can't ever merge
}

/**
 * This function returns the state information holding the previous execution path info.  The returned value can later be passed to
 * return_code_create or return_code_set_state to load the state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the return_code_create function
 * @return - A JSON string that holds the instrumentation specific state object information on success, or NULL on failure
 */
char * return_code_get_state(void * instrumentation_state)
{
	return_code_state_t * state = (return_code_state_t *)instrumentation_state;
	json_t *state_obj, *temp;
	char * ret;

	state_obj = json_object();
	ADD_INT(temp, state->last_status, state_obj, "last_status");
	ret = json_dumps(state_obj, 0);
	json_decref(state_obj);
	return ret;
}

/**
 * This function frees an instrumentation state previously obtained via return_code_get_state.
 * @param state - the instrumentation state to free
 */
void return_code_free_state(char * state)
{
	free(state);
}

/**
 * This function sets the instrumentation state to the passed in state previously obtained via return_code_get_state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the return_code_create function
 * @param state - an instrumentation state previously obtained via return_code_get_state
 * @return - 0 on success, non-zero on failure.
 */
int return_code_set_state(void * instrumentation_state, char * state)
{
	return_code_state_t * current_state = (return_code_state_t *)instrumentation_state;
	int result, temp_int;
	if (!state)
		return 1;

	//If a child process is running when the state is being set
	destroy_target_process(current_state); //kill it so we don't orphan it

	GET_INT(temp_int, state, current_state->last_status, "last_status", result);

	return 0; //No state to set, so just return success
}

/**
 * This function enables the instrumentation and runs the fuzzed process.  If the process needs to be restarted, it will be.
 * @param instrumentation_state - an instrumentation specific state object previously created by the return_code_create function
 * @process - a pointer to return a handle to the process that instrumentation was enabled on
 * @cmd_line - the command line of the fuzzed process to enable instrumentation on
 * @input - a buffer to the input that should be sent to the fuzzed process on stdin
 * @input_length - the length of the input parameter
 * returns 0 on success, -1 on failure
 */
int return_code_enable(void * instrumentation_state, pid_t * process, char * cmd_line, char * input, size_t input_length)
{
	return_code_state_t * state = (return_code_state_t *)instrumentation_state;
	if(state->child_handle)
		destroy_target_process(state);
	if (create_target_process(state, cmd_line, input, input_length))
		return -1;
	state->enable_called = 1;
	*process = state->child_handle;
	return 0;
}

/**
 * This function determines whether the process being instrumented has taken a new path.  The return_code instrumentation does
 * not track the fuzzed process's path, so it is unable to determine if the process took a new path.
 * @param instrumentation_state - an instrumentation specific state object previously created by the return_code_create function
 * @return - 0 when a new path wasn't detected (as it always won't be with the return_code instrumentation), or -1 on failure.
 */
int return_code_is_new_path(void * instrumentation_state)
{
	return_code_state_t * state = (return_code_state_t *)instrumentation_state;
	if(!state->enable_called)
		return -1;
	return 0; //We don't gather instrumentation data, so we can't ever tell if we hit a new path.
}

/**
 * This function will return the result of the fuzz job. It should be called
 * after the process has finished processing the tested input, which should always be the case
 * with the return_code instrumentation, since test_next_input should always wait for the process to finish.
 * @param instrumentation_state - an instrumentation specific structure previously created by the create() function
 * @return - either FUZZ_NONE, FUZZ_HANG, FUZZ_CRASH, or -1 on error.
 */
int return_code_get_fuzz_result(void * instrumentation_state)
{
	return_code_state_t * state = (return_code_state_t *)instrumentation_state;
	if(!state->enable_called)
		return -1;
	return state->last_status;
}

/**
 * Checks if the target process is done fuzzing the inputs yet.  If it has finished, it will have
 * written last_status, the result of the fuzz job.
 *
 * @param state - The return_code_state_t object containing this instrumentation's state
 * @return - 0 if the process has not done testing the fuzzed input, 1 if the process is done, -1 on error
 */
int return_code_is_process_done(void * instrumentation_state)
{
	return_code_state_t * state = (return_code_state_t *)instrumentation_state;

	if(!state->enable_called)
		return -1;

	if (state->process_reaped == 1) 
	{
		return state->last_status;
	}
	else
	{
		int fuzz_result = get_process_status(state->child_handle);

		// expects 2, 1, 0, or -1
		if (fuzz_result == FUZZ_RUNNING) // it's aliiiiive
			// don't set last_status here, because hangs are handled by the timeout in the driver.
			return 0;
		else if (fuzz_result == FUZZ_CRASH || fuzz_result == FUZZ_NONE) // crash or clean exit
		{
			state->last_status = fuzz_result;
			state->process_reaped = 1;
			return 1;
		}
		else // get_process_status returned an error
		{
			state->last_status = fuzz_result;
			return -1;
		}
	}
}

/**
 * This function returns help text for this instrumentation.  This help text will describe the instrumentation and any options
 * that can be passed to return_code_create.
 * @param help_str - A pointer that will be updated to point to the new help string.
 * @return 0 on success and -1 on failure
 */
int return_code_help(char ** help_str)
{
	*help_str = strdup(
		"return_code - Linux/Mac return_code \"instrumentation\"\n"
		"Options:\n"
		"\tnone\n"
		"\n"
	);
	if (*help_str == NULL)
		return -1;
	return 0;
}
