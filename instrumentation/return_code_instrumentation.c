// Linux-only return code instrumentation.

#include <signal.h>    // kill
#include <string.h>    // memset
#include <sys/types.h>
#include <unistd.h>

#include "instrumentation.h"
#include "return_code_instrumentation.h"
#include "forkserver_internal.h"

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
	if(state->child_pid && state->child_pid != -1) {
		if(!state->use_fork_server)
			state->last_status = get_process_status(state->child_pid);

		kill(state->child_pid, SIGKILL);
		state->child_pid = 0;

		if(state->use_fork_server)
			state->last_status = fork_server_get_status(&state->fs, 1);
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
	int i;
	char ** argv;
	char * target_path;

	state->last_status = FUZZ_RUNNING;
	state->process_reaped = 0;

	if(state->use_fork_server) {
		if(!state->fork_server_setup) {
			if(split_command_line(cmd_line, &target_path, &argv))
				return -1;

			//Start the fork server
			fork_server_init(&state->fs, target_path, argv, 1, 0, stdin_length != 0);
			state->fork_server_setup = 1;

			//Free the split up command line
			for(i = 0; argv[i]; i++)
				free(argv[i]);
			free(argv);
			free(target_path);
		}

		if(state->fs.target_stdin != -1) {
			//Take care of the stdin input, write over the file, then truncate it accordingly
			lseek(state->fs.target_stdin, 0, SEEK_SET);
			if(stdin_input != NULL && stdin_length != 0) {
				if(write(state->fs.target_stdin, stdin_input, stdin_length) != stdin_length)
					FATAL_MSG("Short write to target's stdin file");
			}
			if(ftruncate(state->fs.target_stdin, stdin_length))
				FATAL_MSG("ftruncate() failed");
			lseek(state->fs.target_stdin, 0, SEEK_SET);
		}

		//Start the new child and tell it to go
		state->child_pid = fork_server_fork_run(&state->fs);
		if(state->child_pid < 0) {
			ERROR_MSG("Fork server failed to fork a new child\n");
			return -1;
		}

	} else {
		if (start_process_and_write_to_stdin(cmd_line, stdin_input, stdin_length, &state->child_pid)) {
			state->child_pid = 0;
			ERROR_MSG("Failed to create process with command line: %s\n", cmd_line);
			return -1;
		}
	}

	return 0;
}

/**
 * This function creates a return_code_state_t object based on the given options.
 * @param options - A JSON string of the options to set in the new
 *                  return_code_state_t. See the help function for more information on
 *                  the specific options available.
 * @return the return_code_state_t generated from the options in the JSON options
 *         string, or NULL on failure
 */
static return_code_state_t * setup_options(char *options) {
	return_code_state_t * state;

	state = malloc(sizeof(return_code_state_t));
	if(!state)
		return NULL;
	memset(state, 0, sizeof(return_code_state_t));
	state->use_fork_server = 1;  // default to use the fork server

	if(options) {
		PARSE_OPTION_INT(state, options, use_fork_server, "use_fork_server", return_code_cleanup);
	}
	return state;
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
	return_code_state_t * return_code_state = setup_options(options);
	if (!return_code_state)
		return NULL;

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

	GET_INT(temp_int, state, current_state->last_status, "last_status", result);
	return 0;
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
	if(state->child_pid)
		destroy_target_process(state);
	if (create_target_process(state, cmd_line, input, input_length))
		return -1;
	state->enable_called = 1;
	*process = state->child_pid;
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
	int status;
	return_code_state_t * state = (return_code_state_t *)instrumentation_state;

	if(!state->enable_called)
		return -1;

	if (state->process_reaped == 1)
	{
		return state->last_status;
	}
	else
	{
		if(state->use_fork_server) {
			status = fork_server_get_status(&state->fs, 0);
			//it's still alive or an error occurred and we can't tell
			if(status < 0 || status == FORKSERVER_NO_RESULTS_READY)
				return 0;

			if(WIFSIGNALED(status) && WTERMSIG(status) != SIGKILL)
				state->last_status = FUZZ_CRASH;
			else
				state->last_status = FUZZ_NONE;

			state->process_reaped = 1;
			return 1;
		} else {
			int fuzz_result = get_process_status(state->child_pid);

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
		"  use_fork_server      Whether to inject the fork server library; 1=yes, 0=no (default=1)\n"
		"\n"
	);
	if (*help_str == NULL)
		return -1;
	return 0;
}
