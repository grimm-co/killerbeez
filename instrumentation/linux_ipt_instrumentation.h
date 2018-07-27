#pragma once

#include "forkserver_internal.h"
#include "uthash.h"
#include "xxhash.h"

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
int linux_ipt_help(char ** help_str);

struct ipt_hashtable_key {
  uint64_t tip;
  uint64_t tnt;
};

struct ipt_hashtable_entry {
    struct ipt_hashtable_key id;
    UT_hash_handle hh;
};

struct ipt_hash_state
{
  uint64_t tnt_bits;
  uint64_t num_bits;
  uint64_t total_num_bits;
  XXH64_state_t * tnt;
  XXH64_state_t * tip;
};

struct linux_ipt_state
{
  int persistence_max_cnt;
  int ipt_mmap_size;

  char ** coverage_libraries;
  uint64_t * library_starts;
  uint64_t * library_ends;
  uint32_t * library_hashes;
  size_t num_coverage_libraries;

  char * target_path;
  uint64_t target_start;
  uint64_t target_end;

  int num_address_ranges;
  int fork_server_setup;
  int intel_pt_type;

  int perf_fd;
  struct perf_event_mmap_page * pem;
  void * perf_aux_buf;
  char * reorder_buffer;
  uint64_t last_ip;
  char * filter;

  struct ipt_hash_state ipt_hashes;
  struct ipt_hashtable_entry * head;

  pid_t child_pid;
  forkserver_t fs;
  int last_status;
  int process_finished;
  int last_fuzz_result;
  int fuzz_results_set;
  int last_is_new_path;
};
typedef struct linux_ipt_state linux_ipt_state_t;
