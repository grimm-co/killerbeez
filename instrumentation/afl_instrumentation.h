#include <stdio.h>     // fprintf
#include <signal.h>    // for pid_t
#include <stdint.h>    // uint*_t
#include <string.h>  // for memset, strdup
#include <sys/wait.h>  // for waitpid

#include "forkserver_internal.h"

#include "../afl_progs/config.h"
#include "../afl_progs/alloc-inl.h"

struct afl_state {
	int shm_id;
	char *qemu_path;
	char *target_path;
	pid_t child_pid;
	forkserver_t fs;
	int process_finished;
	int last_fuzz_result;
	int fuzz_results_set;  // have we set the fuzz results?
	int last_status;  // the last input did what? (CRASH, HANG, NONE, etc.)
	int last_is_new_path;  // did the last input hit a new code path?
	int use_fork_server;
	int fork_server_setup;
	int persistence_max_cnt;
	int qemu_mode;
	int deferred_startup;
	int loaded_state;
	uint8_t virgin_bits[MAP_SIZE];  // Regions yet untouched by fuzzing
	uint8_t virgin_tmout[MAP_SIZE]; // Bits we haven't seen in tmouts
	uint8_t virgin_crash[MAP_SIZE]; // Bits we haven't seen in crashes
	uint8_t *trace_bits;            // SHM with instrumentation bitmap
};
typedef struct afl_state afl_state_t;

void * afl_create(char *options, char *state);
void afl_cleanup(void *instrumentation_state);
char * afl_get_state(void *instrumentation_state);
void afl_free_state(char *state);
int afl_set_state(void *instrumentation_state, char *state);
void * afl_merge(void *instrumentation_state, void *other_instrumentation_state);
int afl_enable(void *instrumentation_state, pid_t *process, char *cmd_line,
		char *input, size_t input_length);
int afl_is_new_path(void *instrumentation_state);
int afl_get_fuzz_result(void *instrumentation_state);
int afl_is_process_done(void *instrumentation_state);
int afl_help(char **help_str);

static afl_state_t * setup_options(char *options);
static void destroy_target_process(afl_state_t * state, int force);
static int create_target_process(afl_state_t * state, char* cmd_line,
			char * input, size_t input_length);
int setup_shm(void *instrumentation_state);
static void remove_shm();
#ifdef __x86_64__
static void simplify_trace(uint64_t* mem);
#else
static void simplify_trace(uint32_t* mem);
#endif /* ^__x86_64__ */
static inline uint8_t has_new_bits(uint8_t* virgin_map, uint8_t *trace_bits);
static int finish_fuzz_round(afl_state_t *state);
