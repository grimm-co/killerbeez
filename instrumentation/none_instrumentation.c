#ifdef _WIN32
#define _CRT_RAND_S
#include <Windows.h>
#else
#include <sys/types.h> // pid_t
#include <string.h> // strdup
#include <unistd.h> // fork 
#include <wordexp.h>
#include <sys/types.h> // kill
#include <signal.h>    // kill
#include <sys/wait.h>  // waitpid
#endif
#include <stdlib.h>

#include "instrumentation.h"
#include "none_instrumentation.h"

#include <utils.h>
#include <jansson_helper.h>

#ifdef _WIN32
/**
 * This function creates the target process and debugs it.  This function runs in
 * a separate thread, releasing the process_creation_semaphore once it has created
 * the target process.  This function then runs the debug loop on the target, setting
 * state->last_status when the process crashes, hangs, or exits normally.
 * @param args - A thread_arguments_t object with the thread's arguments in it
 * @return - zero on success, non-zero on failure
*/
static int debugging_thread(none_state_t * state)
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
					if (!de.u.Exception.dwFirstChance || de.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT) {
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
#endif

/**
 * This function terminates the fuzzed process.
 * @param state - The none_state_t object containing this instrumentation's state
 */
static void destroy_target_process(none_state_t * state) {
	if (state->child_handle) {
		state->last_child_hung = is_process_alive(state->child_handle);
		//If the process hung, then make sure the debug thread finishes its debug loop
		if(state->last_child_hung)//otherwise we'll be waiting for it forever
			state->process_running = 0;

		#ifdef _WIN32
		TerminateProcess(state->child_handle, 0);
		CloseHandle(state->child_handle);
		state->child_handle = NULL;

		//Wait for the debug thread to be done with the child.  We need to wait
		//here, since we don't want the results_ready_semaphore to becoming stale
		//because the none instrumentation user did not read the results of a previous
		//fuzzed process
		take_semaphore(state->results_ready_semaphore);
		#else
		kill(state->child_handle, SIGKILL);
		state->child_handle = NULL; // TODO: windows can set handles to NULL. what is equivalent for PIDs?
		#endif
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

	//Reset the state for this fuzz process
	state->finished_last_run = 0;
	state->last_child_hung = 0;
	state->last_status = -1;

	// update cmd args
	state->thread_args.cmd_line = cmd_line;
	state->thread_args.stdin_input = stdin_input;
	state->thread_args.stdin_length = stdin_length;

	#ifdef _WIN32
	//Tell the debug thread to start a new process
	release_semaphore(state->fuzz_round_semaphore);

	//Wait for the debug thread to finish creating the new process
	if (take_semaphore(state->process_creation_semaphore) || !state->child_handle)
		return 1;

	#else
	// create the process
	// naive approach of fork/execve for now; TODO: rip afl's forkserver

	if (!cmd_line) return 0; // TODO: why is this NULL on the first iteration?

	pid_t pid = fork();

	state->process_running = 1;
	state->last_status = FUZZ_HANG;
	
	wordexp_t w;

	// TODO: may want flags eg no expand
	wordexp(cmd_line, &w, 0);

	if (pid == 0) // child
	{
		// TODO: jeffball says that you can pass in "environ" as the env
		// TODO: execv expects argv to be null-terminated. i am unsure if wordv is.
		execv(w.we_wordv[0], w.we_wordv);
	} else { // parent
		state->child_handle = pid;
	}
	
	#endif
	
	return 0;
}

/**
 * This function ends the fuzzed process (if it wasn't previously ended).
 * @param state - The none_state_t object containing this instrumentation's state
 * @return - returns 0 on success or -1 on error
 */
static int finish_fuzz_round(none_state_t * state) {
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

	#ifdef _WIN32
	none_state->fuzz_round_semaphore = create_semaphore(0, 1);
	none_state->process_creation_semaphore = create_semaphore(0, 1);
	none_state->results_ready_semaphore = create_semaphore(0, 1);
	if (!none_state->fuzz_round_semaphore || !none_state->process_creation_semaphore || !none_state->results_ready_semaphore) {
		none_cleanup(none_state);
		return NULL;
	}

	// TODO: can this be moved up out of the ifdef, so we don't need to repeat it below in the linux portion?
	if (state && none_set_state(none_state, state))
	{
		none_cleanup(none_state);
		return NULL;
	}

	none_state->debug_thread_handle = CreateThread(
		NULL,           // default security attributes
		0,              // default stack size
		(LPTHREAD_START_ROUTINE)debugging_thread, // thread function
		none_state,     // thread argument
		0,              // default creation flags
		NULL            // record the thread handle
	);
	if (!none_state->debug_thread_handle) {
		none_cleanup(none_state);
		return NULL;
	}
	#else
	// set state if one was passed in
	// set_state might fail, so check for that
	if (state && none_set_state(none_state, state))
	{
		none_cleanup(none_state);
		return NULL;
	}

	// create the child process
	if ( create_target_process( none_state, none_state->thread_args.cmd_line,
			none_state->thread_args.stdin_input, none_state->thread_args.stdin_length ) )
		return NULL;

	#endif
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

	#ifdef _WIN32
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
	#endif
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
#ifdef _WIN32
int none_enable(void * instrumentation_state, HANDLE * process, char * cmd_line, char * input, size_t input_length)
#else
int none_enable(void * instrumentation_state, pid_t * process, char * cmd_line, char * input, size_t input_length)
#endif
{
	none_state_t * state = (none_state_t *)instrumentation_state;
	if(state->child_handle)
		destroy_target_process(state);
	if (create_target_process(state, cmd_line, input, input_length))
		return -1;
	*process = state->child_handle;
	return 0;
}

#ifndef _WIN32

/**
 * Not used in Windows.
 * sets state->last_status when the process crashes, hangs, or exits normally.
*/

/**
 * Checks if the target process is done fuzzing the inputs yet.
 * @param state - The _state_t object containing this instrumentation's state
 * @return - zero if the process is still running, non-zero if the process is done.
 */
int none_is_process_done(void * instrumentation_state)
{
	none_state_t * state = (none_state_t *)instrumentation_state;
	int status[1];

	pid_t result = waitpid(state->child_handle, status, 0);

	// ^the third arg should probably be WNOHANG, so that we don't block here,
	// but rather inside the driver, which calls this in generic_wait_for_process_completion
	// and should handling timing out on its own.

	// however, doing so means that we never get a pid back from waitpid.
	// (we never hit the else branch below)

	// one possibility, but i think it is not the case:
	// 		this means that the waitpid in utils.c:is_process_alive might get to it first.
	// the reason i suspect not is because we never hit the error message for result == -1 below.

	if (result == 0) {         // child is still running
		return 0;
	} else if (result == -1) { // error eg waitpid was already called, no children

		ERROR_MSG("is_process_done failed");

	} else {                   // result is a pid, so the child is dead
		// check if it exited normally or crashed
		if (WIFEXITED(*status)) { // 1 if exited normally
			state->process_running = 0;
			state->finished_last_run = 1;
			state->last_status = FUZZ_NONE;
			state->last_child_hung = 0;
		} else { // nonzero exit code
			state->process_running = 0;
			state->finished_last_run = 1;
			state->last_status = FUZZ_CRASH;
			state->last_child_hung = 0;
		}
		return 1;
	}

	/*
	int process_running;
	// int finished_last_run;
	int last_status; // not the last status code
	int last_child_hung;
	*/
}
#endif

/**
 * This function determines whether the process being instrumented has taken a new path.  The none instrumentation does
 * not track the fuzzed process's path, so it is unable to determine if the process took a new path.  It will however be
 * able to determine if the process exitted normally, hung, or crashed.
 * @param instrumentation_state - an instrumentation specific state object previously created by the none_create function
 * @return - 0 when a new path wasn't detected (as it always won't be with the none instrumentation), or -1 on failure.
 */
int none_is_new_path(void * instrumentation_state)
{
	return 0; //We don't gather instrumentation data, so we can't ever tell if we hit a new path.
}

/**
 * This function will return the result of the fuzz job. It should be called
 * after the process has finished processing the tested input.
 * @param instrumentation_state - an instrumentation specific structure previously created by the create() function
 * @return - either FUZZ_NONE, FUZZ_HANG, FUZZ_CRASH, or -1 on error.
 */
int none_get_fuzz_result(void * instrumentation_state)
{
	none_state_t * state = (none_state_t *)instrumentation_state;
	finish_fuzz_round(state);
	return state->last_status;
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
		"\tNone\n"
		"\n"
	);
}
