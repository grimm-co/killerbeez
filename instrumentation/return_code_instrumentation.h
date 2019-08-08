#pragma once
#include "forkserver_internal.h"

void * return_code_create(char * options, char * state);
void return_code_cleanup(void * instrumentation_state);
void * return_code_merge(void * instrumentation_state, void * other_instrumentation_state);
char * return_code_get_state(void * instrumentation_state);
void return_code_free_state(char * state);
int return_code_set_state(void * instrumentation_state, char * state);
int return_code_enable(void * instrumentation_state, pid_t * process, char * cmd_line, char * input, size_t input_length);
int return_code_is_new_path(void * instrumentation_state);
int return_code_get_fuzz_result(void * instrumentation_state);
int return_code_is_process_done(void * instrumentation_state);
int return_code_help(char ** help_str);

struct return_code_state
{
	int fork_server_setup;
	int use_fork_server;
	forkserver_t fs;

	pid_t child_pid;

	int enable_called;
	int last_status;
	int process_reaped; // used to prevent further calls to get_process_status if the process has been reaped
};
typedef struct return_code_state return_code_state_t;
