#pragma once

#include <Windows.h>

#include "winafl_types.h"
#include "winafl_config.h"

void * dynamorio_create(char * options, char * state);
void dynamorio_cleanup(void * instrumentation_state);
void * dynamorio_merge(void * instrumentation_state, void * other_instrumentation_state);
char * dynamorio_get_state(void * instrumentation_state);
void dynamorio_free_state(char * state);
int dynamorio_set_state(void * instrumentation_state, char * state);
int dynamorio_enable(void * instrumentation_state, HANDLE * process, char * cmd_line, char * input, size_t input_length);
int dynamorio_is_new_path(void * instrumentation_state);
int dynamorio_get_module_info(void * instrumentation_state, int index, int * is_new, char ** module_name, char ** info, int * size);
instrumentation_edges_t * dynamorio_get_edges(void * instrumentation_state, int index);
int dynamorio_is_process_done(void * instrumentation_state);
int dynamorio_get_fuzz_result(void * instrumentation_state);
char * dynamorio_help(void);

void dynamorio_print_state(void * instrumentation_state);

#define FOREACH_MODULE(x, state)  for(x = state->modules; x; x = x->next)

struct target_module
{
	int index;
	HANDLE shm_handle;              /* Handle of the SHM region         */
	u8 * trace_bits;                /* SHM with instrumentation bitmap  */
	u8  virgin_bits[MAP_SIZE];      /* Regions yet untouched by fuzzing */
	u32 last_shm_hash;              /* The most recent hash of the SHM region */
	int last_path_was_new;
	u8 * ignore_bytes;

	instrumentation_edges_t * edges_memory; /* SHM with list of edges */
	
	struct target_module * next;
};
typedef struct target_module target_module_t;


struct dynamorio_state
{
	//Options
	char * default_dynamorio_dir;
	char * dynamorio_dir;
	char * default_winafl_dir;
	char * winafl_dir;
	char * target_path;
	char * dump_map_dir;
	char * ignore_bytes_dir;
	char * ignore_bytes_file;
	int per_module_coverage;
	int fuzz_iterations_max;
	char * client_params;
	int timeout;
	int edges;

	HANDLE child_handle;             /* Handle to the child process      */
	s32 child_pid;                   /* PID of the fuzzed program        */
	HANDLE pipe_handle;              /* Handle of the comms named pipe   */
	HANDLE shm_handle;               /* Handle of the SHM region         */

	char ** module_names;
	size_t num_modules;
	target_module_t * modules;

	char * pidfile;                 /* pid file name */
	char * pipe_name;               /* name of the pipe to communicate with Dynamorio */
	int fuzz_iterations_current;

	u8  virgin_bits[MAP_SIZE];      /* Regions yet untouched by fuzzing */

	char *fuzzer_id;                /* The fuzzer ID or a randomized
								       seed allowing multiple instances */
	u8 * trace_bits;                /* SHM with instrumentation bitmap  */
	u8 * ignore_bytes;
	u32 last_shm_hash;              /* The most recent hash of the SHM region */
	int last_path_was_new;
	int last_process_status;
	int analyzed_last_round;

	instrumentation_edges_t * edges_memory; /* SHM with list of edges  */
};
typedef struct dynamorio_state dynamorio_state_t;
