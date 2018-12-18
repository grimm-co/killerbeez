#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "forkserver_internal.h"

static void forkserver_persistence_init(void);

//////////////////////////////////////////////////////////////
//Fork Server ////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

//The fork server design was inspired by the LLVM mode of AFL. It however,
//has been modified significantly to suit our purposes.  The LLVM mode of
//AFL is available at:
//https://github.com/mirrorer/afl/blob/master/llvm_mode/afl-llvm-rt.o.c#L95

void __forkserver_init(void)
{
  int response = 0x41414141;
  char command;
  int child_pid = -1;
  int target_pipe[2];

  // Phone home and tell the parent that we're OK. If parent isn't there,
  // assume we're not running in forkserver mode and just execute program.
  if(write(FORKSRV_TO_FUZZER, &response, sizeof(int)) != sizeof(int))
    return;

  if(getenv(PERSIST_MAX_VAR)) {
    forkserver_persistence_init();
    return;
  }

  if(pipe(target_pipe))
    _exit(1);

  while (1) {

    // Wait for parent by reading from the pipe. Exit if read fails.
    if(read(FUZZER_TO_FORKSRV, &command, sizeof(command)) != sizeof(command))
      _exit(1);

    switch(command) {

      case EXIT:
        _exit(0);
        break;

      case FORK:
      case FORK_RUN:

        child_pid = fork();
        if(child_pid < 0)
          _exit(1);

        //In child process: close fds, resume execution.
        if(!child_pid) {
          close(FUZZER_TO_FORKSRV);
          close(FORKSRV_TO_FUZZER);
          close(target_pipe[1]);

          //If we're just forking, wait for the forkserver to tell us to go
          if(command == FORK && read(target_pipe[0], &response, sizeof(int)) != sizeof(int))
            _exit(1);

          close(target_pipe[0]);
          return;
        }
        response = child_pid;

        break;

      case RUN:
        //Make sure the target process has started
        if(child_pid == -1) {
          response = FORKSERVER_ERROR;
          break;
        }
        //Tell the target process to go
        response = 0;
        if(write(target_pipe[1], &response, sizeof(int)) != sizeof(int))
          _exit(1);
        break;

      case GET_STATUS:
        if(waitpid(child_pid, &response, 0) < 0)
          _exit(1);
        break;
    }

    if(write(FORKSRV_TO_FUZZER, &response, sizeof(int)) != sizeof(int))
      _exit(1);
  }
}

//////////////////////////////////////////////////////////////
//Persistence Mode ///////////////////////////////////////////
//////////////////////////////////////////////////////////////

static int max_cnt = 0;
static int cycle_cnt = 0;
static int forkserver_cycle_cnt = 0;

static void forkserver_persistence_init(void)
{
  int response = 0x41414141;
  char command;
  int child_pid = -1;

  //Get the maximum number of persistent executions
  max_cnt = atoi(getenv(PERSIST_MAX_VAR));
  if(!max_cnt)
    _exit(1);

  while (1) {

    // Wait for parent by reading from the pipe. Exit if read fails.
    if(read(FUZZER_TO_FORKSRV, &command, sizeof(command)) != sizeof(command))
      _exit(1);

    switch(command) {

      case EXIT:

        if(child_pid != -1)
          kill(child_pid, SIGKILL);
        _exit(0);
        break;

      case FORK:
      case FORK_RUN:

        if(child_pid == -1 || forkserver_cycle_cnt == max_cnt) {

          if(child_pid != -1 && forkserver_cycle_cnt == max_cnt) {
            //if we've hit the maximum cycle count, continue the child, so it may exit
            //and clean up.  We do this now, rather than in GET_STATUS commands, to ensure that
            //the exit portion of the target process does not get traced.
            kill(child_pid, SIGCONT);
            if(waitpid(child_pid, &response, 0) < 0)
              _exit(1);
            forkserver_cycle_cnt = 0;
          }

          child_pid = fork();
          if(child_pid < 0)
            _exit(1);

          //In child process: close fds, resume execution.
          if(!child_pid) {
            close(FUZZER_TO_FORKSRV);
            close(FORKSRV_TO_FUZZER);
            return;
          }

          if(waitpid(child_pid, &response, WUNTRACED) < 0 || !WIFSTOPPED(response)) {
            //Failed to start the child, kill it and report failure
            kill(child_pid, SIGKILL);
            child_pid = -1;
          }
        }
        response = child_pid;

        if(command != FORK_RUN && response != -1) //If the command is FORK_RUN, fall into the RUN case
          break;

      case RUN:
        //Tell the target process to go
        if(child_pid == -1) {
          response = FORKSERVER_ERROR;
          break;
        }
        kill(child_pid, SIGCONT);
        forkserver_cycle_cnt++;
        if(command != FORK_RUN) //Don't overwrite the FORK case's response
          response = 0;
        break;

      case GET_STATUS:

        if(waitpid(child_pid, &response, WUNTRACED) < 0)
          _exit(1);

        if(WIFEXITED(response) || WIFSIGNALED(response)) { //The process ended, either
          child_pid = -1; //by hitting the max_cnt count and exiting, or by crashing
          forkserver_cycle_cnt = 0;
        }
        else if(WIFSTOPPED(response)) //If we hit a SIGSTOP, then the child didn't
          response = 0;               //die, just return 0 to the parent

        break;
    }

    if(write(FORKSRV_TO_FUZZER, &response, sizeof(response)) != sizeof(response))
      _exit(1);
  }
}

int __killerbeez_loop(void) {
  raise(SIGSTOP);
  return cycle_cnt++ != max_cnt;
}

