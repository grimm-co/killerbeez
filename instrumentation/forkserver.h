#pragma once

int killerbeez_loop(void);
#define KILLERBEEZ_LOOP() killerbeez_loop()

#define PERSIST_MAX_VAR "PERSISTENCE_MAX_CNT"

//Designated file descriptors for read/write to the forkserver
//and target process
#define FUZZER_TO_FORKSRV   198
#define FORKSRV_TO_FUZZER   199
#define MAX_FORKSRV_FD      200

//Commands that the fuzzer can send to the forkserver, or the forkserver
//sends to the target
#define EXIT       0
#define FORK       1
#define RUN        2
#define FORK_RUN   3
#define GET_STATUS 4

#define FORKSERVER_ERROR -1
#define FORKSERVER_NO_RESULTS_READY -2

struct forkserver {
  int fuzzer_to_forksrv;
  int forksrv_to_fuzzer;
  int target_stdin;
  int sent_get_status;
  int last_status;
};
typedef struct forkserver forkserver_t;

void fork_server_init(forkserver_t * fs, char * target_path, char ** argv, int use_forkserver_library,
  int persistence_max_cnt, int needs_stdin_fd);
int fork_server_exit(forkserver_t * fs);
int fork_server_fork(forkserver_t * fs);
int fork_server_fork_run(forkserver_t * fs);
int fork_server_run(forkserver_t * fs);
int fork_server_get_status(forkserver_t * fs, int wait);
int fork_server_get_pending_status(forkserver_t * fs, int wait);

