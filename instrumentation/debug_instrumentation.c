#define _CRT_RAND_S
#include <windows.h>
#include <stdlib.h>
#include <ntstatus.h>

#include "instrumentation.h"
#include "debug_instrumentation.h"

#include <utils.h>
#include <jansson_helper.h>

/**
 * This function creates the target process and debugs it.  This function runs in
 * a separate thread, releasing the process_creation_semaphore once it has created
 * the target process.  This function then runs the debug loop on the target, setting
 * state->last_status when the process crashes, hangs, or exits normally.
 * @param args - A thread_arguments_t object with the thread's arguments in it
 * @return - zero on success, non-zero on failure
*/
static int debugging_thread(debug_state_t * state)
{
	DEBUG_EVENT de;
	DWORD cont, child_pid;

	while (1)
	{
		//Wait for the main thread to tell us to go
		take_semaphore(state->fuzz_round_semaphore);

		//Create the child process, mark it as running, and let the main thread know we're done
		if (start_process_and_write_to_stdin_flags(state->thread_args.cmd_line, state->thread_args.stdin_input,
				state->thread_args.stdin_length, &state->child_handle, DEBUG_ONLY_THIS_PROCESS)) {
			release_semaphore(state->process_creation_semaphore);
			state->child_handle = NULL;
			ERROR_MSG("Failed to create process with command line: %s\n", state->thread_args.cmd_line);
			return 1;
		}
		state->process_running = 1;

		//Let the main thread know we've created the process
		release_semaphore(state->process_creation_semaphore);

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
					// Not all exceptions are real crashes - we ignore breakpoints being hit and
					// exceptions that are encountered multiple times
					if (!de.u.Exception.dwFirstChance || // if the debugger has not encountered this exception before
						(de.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT &&
						 de.u.Exception.ExceptionRecord.ExceptionCode != STATUS_WX86_BREAKPOINT)) {
						state->last_status = FUZZ_CRASH;
						cont = DBG_EXCEPTION_NOT_HANDLED;
						state->process_running = 0;

						//Once we know the result, kill the process to speed things up
						TerminateProcess(state->child_handle, 0);
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
				release_semaphore(state->results_ready_semaphore);
				return -1;
			}

			memset(&de, 0, sizeof(DEBUG_EVENT));
		}

		//Let the main thread know we've finished looking at the current fuzzed process' debug events
		release_semaphore(state->results_ready_semaphore);
	}

	return 0;
}

/**
 * This function terminates the fuzzed process.
 * @param state - The debug_state_t object containing this instrumentation's state
 */
static void destroy_target_process(debug_state_t * state) {
	if (state->child_handle) {
		state->last_child_hung = is_process_alive(state->child_handle);
		//If the process hung, then make sure the debug thread finishes its debug loop
		if(state->last_child_hung)//otherwise we'll be waiting for it forever
			state->process_running = 0;

		TerminateProcess(state->child_handle, 0);
		CloseHandle(state->child_handle);
		state->child_handle = NULL;

		//Wait for the debug thread to be done with the child.  We need to wait
		//here, since we don't want the results_ready_semaphore to becoming stale
		//because the debug instrumentation user did not read the results of a previous
		//fuzzed process
		take_semaphore(state->results_ready_semaphore);
	}
}

/**
 * This function starts the fuzzed process
 * @param state - The debug_state_t object containing this instrumentation's state
 * @param cmd_line - the command line of the fuzzed process to start
 * @param stdin_input - the input to pass to the fuzzed process's stdin
 * @param stdin_length - the length of the stdin_input parameter
 * @return - zero on success, non-zero on failure.
 */
static int create_target_process(debug_state_t * state, char* cmd_line, char * stdin_input, size_t stdin_length) {

	//Reset the state for this fuzz process
	state->finished_last_run = 0;
	state->last_child_hung = 0;
	state->last_status = -1;

	//Tell the debug thread to start a new process
	state->thread_args.cmd_line = cmd_line;
	state->thread_args.stdin_input = stdin_input;
	state->thread_args.stdin_length = stdin_length;
	release_semaphore(state->fuzz_round_semaphore);

	//Wait for the debug thread to finish creating the new process
	if (take_semaphore(state->process_creation_semaphore) || !state->child_handle)
		return 1;
	return 0;
}

/**
 * This function ends the fuzzed process (if it wasn't previously ended).
 * @param state - The debug_state_t object containing this instrumentation's state
 * @return - returns 0 on success or -1 on error
 */
static int finish_fuzz_round(debug_state_t * state) {
	if (!state->finished_last_run) {
		destroy_target_process(state);
		state->finished_last_run = 1;
	}
	if (state->last_status < 0)
		return -1;

	if(state->last_child_hung)
		state->last_status = FUZZ_HANG;
	// else leave it as whatever it was

	return 0;
}

////////////////////////////////////////////////////////////////
// Instrumentation methods /////////////////////////////////////
////////////////////////////////////////////////////////////////

/**
 * This function allocates and initializes a new instrumentation specific state object based on the given options.
 * @param options - a JSON string that contains the instrumentation specific string of options
 * @param state - an instrumentation specific JSON string previously returned from debug_get_state that should be loaded
 * @return - An instrumentation specific state object on success or NULL on failure
 */
void * debug_create(char * options, char * state)
{
	debug_state_t * debug_state;
	debug_state = malloc(sizeof(debug_state_t));
	if (!debug_state)
		return NULL;
	memset(debug_state, 0, sizeof(debug_state_t));

	debug_state->fuzz_round_semaphore = create_semaphore(0, 1);
	debug_state->process_creation_semaphore = create_semaphore(0, 1);
	debug_state->results_ready_semaphore = create_semaphore(0, 1);
	if (!debug_state->fuzz_round_semaphore || !debug_state->process_creation_semaphore || !debug_state->results_ready_semaphore) {
		debug_cleanup(debug_state);
		return NULL;
	}

	if (state && debug_set_state(debug_state, state))
	{
		debug_cleanup(debug_state);
		return NULL;
	}

	debug_state->debug_thread_handle = CreateThread(
		NULL,           // default security attributes
		0,              // default stack size
		(LPTHREAD_START_ROUTINE)debugging_thread, // thread function
		debug_state,     // thread argument
		0,              // default creation flags
		NULL            // record the thread handle
	);
	if (!debug_state->debug_thread_handle) {
		debug_cleanup(debug_state);
		return NULL;
	}

	return debug_state;
}

/**
 * This function cleans up all resources with the passed in instrumentation state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the debug_create function
 * This state object should not be referenced after this function returns.
 */
void debug_cleanup(void * instrumentation_state)
{
	debug_state_t * state = (debug_state_t *)instrumentation_state;

	destroy_target_process(state);
	if (state->debug_thread_handle) {
		TerminateThread(state->debug_thread_handle, 0);
		CloseHandle(state->debug_thread_handle);
		state->debug_thread_handle = NULL;
	}

	if(state->fuzz_round_semaphore)
		destroy_semaphore(state->fuzz_round_semaphore);
	if (state->process_creation_semaphore)
		destroy_semaphore(state->process_creation_semaphore);
	if (state->results_ready_semaphore)
		destroy_semaphore(state->results_ready_semaphore);
	free(state);
}

/**
 * This function merges the coverage information from two instrumentation states.  This will always fail for the
 * debug instrumentation, since it does not record instrumentation data.
 * @param instrumentation_state - an instrumentation specific state object previously created by the debug_create function
 * @param other_instrumentation_state - an instrumentation specific state object previously created by the debug_create function
 * @return - An instrumentation specific state object that contains the combination of both of the passed in instrumentation states
 * on success, or NULL on failure
 */
void * debug_merge(void * instrumentation_state, void * other_instrumentation_state)
{
	return NULL; //No instrumentation data, so we can't ever merge
}

/**
 * This function returns the state information holding the previous execution path info.  The returned value can later be passed to
 * debug_create or debug_set_state to load the state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the debug_create function
 * @return - A JSON string that holds the instrumentation specific state object information on success, or NULL on failure
 */
char * debug_get_state(void * instrumentation_state)
{
	debug_state_t * state = (debug_state_t *)instrumentation_state;
	json_t *state_obj, *temp;
	char * ret;

	state_obj = json_object();
	ADD_INT(temp, state->last_status, state_obj, "last_status");
	ret = json_dumps(state_obj, 0);
	json_decref(state_obj);
	return ret;
}

/**
 * This function frees an instrumentation state previously obtained via debug_get_state.
 * @param state - the instrumentation state to free
 */
void debug_free_state(char * state)
{
	free(state);
}

/**
 * This function sets the instrumentation state to the passed in state previously obtained via debug_get_state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the debug_create function
 * @param state - an instrumentation state previously obtained via debug_get_state
 * @return - 0 on success, non-zero on failure.
 */
int debug_set_state(void * instrumentation_state, char * state)
{
	debug_state_t * current_state = (debug_state_t *)instrumentation_state;
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
 * @param instrumentation_state - an instrumentation specific state object previously created by the debug_create function
 * @process - a pointer to return a handle to the process that instrumentation was enabled on
 * @cmd_line - the command line of the fuzzed process to enable instrumentation on
 * @input - a buffer to the input that should be sent to the fuzzed process on stdin
 * @input_length - the length of the input parameter
 * returns 0 on success, -1 on failure
 */
int debug_enable(void * instrumentation_state, HANDLE * process, char * cmd_line, char * input, size_t input_length)
{
	debug_state_t * state = (debug_state_t *)instrumentation_state;
	if(state->child_handle)
		destroy_target_process(state);
	if (create_target_process(state, cmd_line, input, input_length))
		return -1;
	*process = state->child_handle;
	return 0;
}

/**
 * This function determines whether the process being instrumented has taken a new path.  The debug instrumentation does
 * not track the fuzzed process's path, so it is unable to determine if the process took a new path.  It will however be
 * able to determine if the process exitted normally, hung, or crashed.
 * @param instrumentation_state - an instrumentation specific state object previously created by the debug_create function
 * @return - 0 when a new path wasn't detected (as it always won't be with the debug instrumentation), or -1 on failure.
 */
int debug_is_new_path(void * instrumentation_state)
{
	return 0; //We don't gather instrumentation data, so we can't ever tell if we hit a new path.
}

/**
 * This function will return the result of the fuzz job. It should be called
 * after the process has finished processing the tested input.
 * @param instrumentation_state - an instrumentation specific structure previously created by the create() function
 * @return - either FUZZ_NONE, FUZZ_HANG, FUZZ_CRASH, or -1 on error.
 */
int debug_get_fuzz_result(void * instrumentation_state)
{
	debug_state_t * state = (debug_state_t *)instrumentation_state;
	finish_fuzz_round(state);
	return state->last_status;
}

/**
* This function returns help text for this instrumentation.  This help text will describe the instrumentation and any options
* that can be passed to debug_create.
* @return - a newly allocated string containing the help text.
*/
char * debug_help(void)
{
	return strdup(
		"debug - Windows debug thread \"instrumentation\", only detects crashes\n"
		"Options:\n"
		"\tNone\n"
		"\n"
	);
}
