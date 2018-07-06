#pragma once
#include <utils.h>

#ifdef _WIN32
#include <Windows.h> // HANDLE (winnt.h might work instead)
#else
#include <sys/types.h> // pid_t
#endif

void * debug_create(char * options, char * state);
void debug_cleanup(void * instrumentation_state);
void * debug_merge(void * instrumentation_state, void * other_instrumentation_state);
char * debug_get_state(void * instrumentation_state);
void debug_free_state(char * state);
int debug_set_state(void * instrumentation_state, char * state);

#ifdef _WIN32
int debug_enable(void * instrumentation_state, HANDLE * process, char * cmd_line, char * input, size_t input_length);
#else
int debug_enable(void * instrumentation_state, pid_t * process, char * cmd_line, char * input, size_t input_length);
#endif

int debug_is_new_path(void * instrumentation_state);
int debug_get_fuzz_result(void * instrumentation_state);
char * debug_help(void);

typedef struct
{
	char * cmd_line; //the command line of the target process to start
	char * stdin_input; //input to the STDIN of the target process
	size_t stdin_length; //the length of the input to write stdin
} thread_args_t;

struct debug_state
{
	#ifdef _WIN32
	HANDLE child_handle;
	HANDLE debug_thread_handle;
	#else
	pid_t child_handle;
	#endif
	int process_running;

	//This semaphore is used to make the debug thread wait until the main
	//thread wants it to start a new process and begin debugging it.
	semaphore_t fuzz_round_semaphore;

	//This semaphore is used by the main thread to wait until the debug
	//thread has created the fuzzed process.
	semaphore_t process_creation_semaphore;

	//This semaphore is used by the main thread to wait until the debug
	//thread has finished debugging the fuzzed process and the results can
	//now be viewed (in last_status).
	semaphore_t results_ready_semaphore;

	int finished_last_run;
	int last_status;
	int last_child_hung;

	//This struct is used to pass arguments to the debugging thread.  It
	//should only be accessed while in the create_thread_process function,
	//as they will point to memory that is out of scope afterwards.  The
	//strings in the thread_args should not be freed.
	thread_args_t thread_args;
};
typedef struct debug_state debug_state_t;
