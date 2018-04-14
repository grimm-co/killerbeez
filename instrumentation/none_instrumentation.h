#pragma once
#include <utils.h>

void * none_create(char * options, char * state);
void none_cleanup(void * instrumentation_state);
void * none_merge(void * instrumentation_state, void * other_instrumentation_state);
char * none_get_state(void * instrumentation_state);
void none_free_state(char * state);
int none_set_state(void * instrumentation_state, char * state);
int none_enable(void * instrumentation_state, HANDLE * process, char * cmd_line, char * input, size_t input_length);
int none_is_new_path(void * instrumentation_state, int * process_status);
char * none_help(void);

struct none_state
{
	//Options
	int timeout;

	HANDLE child_handle;
	HANDLE debug_thread_handle;
	int process_running;
	semaphore_t process_creation_semaphore;

	int finished_last_run;
	int last_status;
};
typedef struct none_state none_state_t;
