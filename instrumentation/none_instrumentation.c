#define _CRT_RAND_S
#include <windows.h>
#include <stdlib.h>

#include "instrumentation.h"
#include "none_instrumentation.h"

#include <utils.h>
#include <jansson_helper.h>

typedef struct
{
	none_state_t * state; //the none_state_t object containing this instrumentation's state
	char * cmd_line; //the command line of the target process to start
	char * stdin_input; //input to the STDIN of the target process
	size_t stdin_length; //the length of the input to write stdin
} thread_arguments_t;

/**
 * This function creates the target process and debugs it.  This function runs in
 * a separate thread, releasing the process_creation_semaphore once it has created
 * the target process.  This function then runs the debug loop on the target, setting
 * state->last_status when the process crashes, hangs, or exits normally.
 * @param args - A thread_arguments_t object with the thread's arguments in it
 * @return - zero on success, non-zero on failure
*/
static int debugging_loop(thread_arguments_t * args)
{
	DEBUG_EVENT de;
	DWORD cont, child_pid;
	none_state_t * state = args->state;

	//Create the child process, mark it as running, and let the main thread know we're done
	if (start_process_and_write_to_stdin_flags(args->cmd_line, args->stdin_input, args->stdin_length, &state->child_handle, DEBUG_ONLY_THIS_PROCESS)) {
		free(args);
		release_semaphore(state->process_creation_semaphore);
		state->child_handle = NULL;
		ERROR_MSG("Failed to create process with command line: %s\n", args->cmd_line);
		return 1;
	}
	free(args);
	state->process_running = 1;
	release_semaphore(state->process_creation_semaphore); //Let the main thread know we've created the process and are done with args

	//Loop while debugging and look for process exits and exceptions
	child_pid = GetProcessId(state->child_handle);
	state->last_status = FUZZ_HANG;
	memset(&de, 0, sizeof(DEBUG_EVENT));
	while (state->process_running && WaitForDebugEvent(&de, INFINITE))
	{
		cont = DBG_CONTINUE;
		if (de.dwProcessId == child_pid && state->process_running) {
			if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
			{
				if (!de.u.Exception.dwFirstChance || de.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT) {
					state->last_status = FUZZ_CRASH;
					cont = DBG_EXCEPTION_NOT_HANDLED;
					state->process_running = 0;
				}
			}
			else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
			{
				state->last_status = FUZZ_NONE;
				state->process_running = 0;
			}
		}

		if (!ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)) {
			ERROR_MSG("ContinueDebugEvent: Failed to check child process health");
			state->last_status = -1;
			return -1;
		}

		memset(&de, 0, sizeof(DEBUG_EVENT));
	}

	return 0;
}

/**
 * This function terminates the fuzzed process.
 * @param state - The none_state_t object containing this instrumentation's state
 */
static void destroy_target_process(none_state_t * state) {
	if (state->child_handle) {
		state->last_child_hung = is_process_alive(state->child_handle);
		if(state->last_child_hung)
			state->process_running = 0;
		TerminateProcess(state->child_handle, 0);
		CloseHandle(state->child_handle);
		state->child_handle = NULL;
	}
	if (state->debug_thread_handle) {
		WaitForSingleObject(state->debug_thread_handle, INFINITE);
		CloseHandle(state->debug_thread_handle);
		state->debug_thread_handle = NULL;
	}
}

/**
 * This function starts the fuzzed process
 * @param state - The none_state_t object containing this instrumentation's state
 * @param cmd_line - the command line of the fuzzed process to start
 * @param stdin_input - the input to pass to the fuzzed process's stdin
 * @param stdin_length - the length of the stdin_input parameter
 * @return - zero on success, non-zero on failure.
 */
static int create_target_process(none_state_t * state, char* cmd_line, char * stdin_input, size_t stdin_length) {
	thread_arguments_t * args = malloc(sizeof(thread_arguments_t));
	args->state = state;
	args->cmd_line = cmd_line;
	args->stdin_input = stdin_input;
	args->stdin_length = stdin_length;

	state->finished_last_run = 0;
	state->last_child_hung = 0;
	state->last_status = -1;
	state->debug_thread_handle = CreateThread(
		NULL,           // default security attributes
		0,              // default stack size
		(LPTHREAD_START_ROUTINE)debugging_loop, // thread function
		args,           // thread argument
		0,              // default creation flags
		NULL            // record the thread handle
	);
	if (!state->debug_thread_handle)
		return 1;

	if (take_semaphore(state->process_creation_semaphore)) {
		//Run it twice, so even in the race condition where the debug thread starts the child process between
		destroy_target_process(state); //when we try to kill the child process and when we kill the debug thread,
		destroy_target_process(state); //the process still gets killed
		return 1;
	}

	if (!state->child_handle) { //This will only be true if the debug thread failed to create the target process
		destroy_target_process(state); //Thus, we should make sure to kill the debug thread
		return 1;
	}
	return 0;
}

////////////////////////////////////////////////////////////////
// Instrumentation methods /////////////////////////////////////
////////////////////////////////////////////////////////////////

/**
 * This function allocates and initializes a new instrumentation specific state object based on the given options.
 * @param options - a JSON string that contains the instrumentation specific string of options
 * @param state - an instrumentation specific JSON string previously returned from none_get_state that should be loaded
 * @return - An instrumentation specific state object on success or NULL on failure
 */
void * none_create(char * options, char * state)
{
	none_state_t * none_state;
	none_state = malloc(sizeof(none_state_t));
	if (!none_state)
		return NULL;
	memset(none_state, 0, sizeof(none_state_t));

	none_state->process_creation_semaphore = create_semaphore(0, 1);
	if (!none_state->process_creation_semaphore) {
		none_cleanup(none_state);
		return NULL;
	}

	if (state && none_set_state(none_state, state))
	{
		none_cleanup(none_state);
		return NULL;
	}
	return none_state;
}

/**
 * This function cleans up all resources with the passed in instrumentation state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the none_create function
 * This state object should not be referenced after this function returns.
 */
void none_cleanup(void * instrumentation_state)
{
	none_state_t * state = (none_state_t *)instrumentation_state;
	destroy_target_process(state);
	destroy_semaphore(state->process_creation_semaphore);
	free(state);
}

/**
 * This function merges the coverage information from two instrumentation states.  This will always fail for the
 * none instrumentation, since it does not record instrumentation data.
 * @param instrumentation_state - an instrumentation specific state object previously created by the none_create function
 * @param other_instrumentation_state - an instrumentation specific state object previously created by the none_create function
 * @return - An instrumentation specific state object that contains the combination of both of the passed in instrumentation states
 * on success, or NULL on failure
 */
void * none_merge(void * instrumentation_state, void * other_instrumentation_state)
{
	return NULL; //No instrumentation data, so we can't ever merge
}

/**
 * This function returns the state information holding the previous execution path info.  The returned value can later be passed to
 * none_create or none_set_state to load the state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the none_create function
 * @return - A JSON string that holds the instrumentation specific state object information on success, or NULL on failure
 */
char * none_get_state(void * instrumentation_state)
{
	none_state_t * state = (none_state_t *)instrumentation_state;
	json_t *state_obj, *temp;
	char * ret;

	state_obj = json_object();
	ADD_INT(temp, state->last_status, state_obj, "last_status");
	ret = json_dumps(state_obj, 0);
	json_decref(state_obj);
	return ret;
}

/**
 * This function frees an instrumentation state previously obtained via none_get_state.
 * @param state - the instrumentation state to free
 */
void none_free_state(char * state)
{
	free(state);
}

/**
 * This function sets the instrumentation state to the passed in state previously obtained via none_get_state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the none_create function
 * @param state - an instrumentation state previously obtained via none_get_state
 * @return - 0 on success, non-zero on failure.
 */
int none_set_state(void * instrumentation_state, char * state)
{
	none_state_t * current_state = (none_state_t *)instrumentation_state;
	int result, temp_int;
	if (!state)
		return 1;

	//If a child process is running when the state is being set
	destroy_target_process(current_state);//kill it so we don't orphan it

	GET_INT(temp_int, state, current_state->last_status, "last_status", result);
	current_state->finished_last_run = 1;

	return 0; //No state to set, so just return success
}

/**
 * This function enables the instrumentation and runs the fuzzed process.  If the process needs to be restarted, it will be.
 * @param instrumentation_state - an instrumentation specific state object previously created by the none_create function
 * @process - a pointer to return a handle to the process that instrumentation was enabled on
 * @cmd_line - the command line of the fuzzed process to enable instrumentation on
 * @input - a buffer to the input that should be sent to the fuzzed process on stdin
 * @input_length - the length of the input parameter
 * returns 0 on success, -1 on failure
 */
int none_enable(void * instrumentation_state, HANDLE * process, char * cmd_line, char * input, size_t input_length)
{
	none_state_t * state = (none_state_t *)instrumentation_state;
	if(state->child_handle)
		destroy_target_process(state);
	if (create_target_process(state, cmd_line, input, input_length))
		return -1;
	*process = state->child_handle;
	return 0;
}

/**
 * This function determines whether the process being instrumented has taken a new path.  The none instrumentation does
 * not track the fuzzed process's path, so it is unable to determine if the process took a new path.  It will however be
 * able to determine if the process exitted normally, hung, or crashed.
 * @param instrumentation_state - an instrumentation specific state object previously created by the none_create function
 * @param process_status - pointer that will be filled with a value representing whether the fuzzed process crashed or hung, or neither
 * @return - 0 when a new path wasn't detected (as it always won't be with the none instrumentation), or -1 on failure.
 */
int none_is_new_path(void * instrumentation_state, int * process_status)
{
	none_state_t * state = (none_state_t *)instrumentation_state;
	if (!state->finished_last_run) {
		destroy_target_process(state);
		state->finished_last_run = 1;
	}
	if (state->last_status < 0)
		return -1;
	if(state->last_child_hung)
		*process_status = FUZZ_HANG;
	else
		*process_status = state->last_status;
	return 0; //We don't gather instrumentation data, so we can't ever tell if we hit a new path.
}

/**
* This function returns help text for this instrumentation.  This help text will describe the instrumentation and any options
* that can be passed to none_create.
* @return - a newly allocated string containing the help text.
*/
char * none_help(void)
{
	return strdup(
		"none - No instrumentation (using debugging to detect crashes)\n"
		"Options:\n"
		"\ttimeout               The number of milliseconds to wait for the target process to finish\n"
	);
}
