#pragma once

#include "forkserver.h"

void * linux_ipt_create(char * options, char * state);
void linux_ipt_cleanup(void * instrumentation_state);
void * linux_ipt_merge(void * instrumentation_state, void * other_instrumentation_state);
char * linux_ipt_get_state(void * instrumentation_state);
void linux_ipt_free_state(char * state);
int linux_ipt_set_state(void * instrumentation_state, char * state);
int linux_ipt_enable(void * instrumentation_state, pid_t * process, char * cmd_line, char * input, size_t input_length);
int linux_ipt_is_new_path(void * instrumentation_state);
int linux_ipt_is_process_done(void * instrumentation_state);
int linux_ipt_get_fuzz_result(void * instrumentation_state);
char * linux_ipt_help(void);

#define PERF_MMAP_SIZE 1024*1024

struct linux_ipt_state
{
  int num_address_ranges;
  int fork_server_setup;
  int intel_pt_type;

  int perf_fd;
  struct perf_event_mmap_page * pem;
  void * perf_mmap_aux_buf;

  pid_t child_pid;
  forkserver_t fs;
  int last_status;
  int process_finished;
  int last_fuzz_result;
  int fuzz_results_set;
};
typedef struct linux_ipt_state linux_ipt_state_t;
