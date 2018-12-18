/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is the rewrite of afl-as.h's main_payload.

*/

/*
	This file has been modified from the original AFL version to incorporate into
	Killerbeez.  Specifically, the fork server has been modified to match the
  Killerbeez fork server protocol.
 */

#include "../config.h"
#include "../types.h"

#include "../../instrumentation/forkserver_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>

/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 0
#endif /* ^USE_TRACE_PC */


/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

u8  __afl_area_initial[MAP_SIZE];
u8* __afl_area_ptr = __afl_area_initial;

__thread u32 __afl_prev_loc;


/* Running in persistent mode? */

static u8 is_persistent;


/* SHM setup. */

static void __afl_map_shm(void) {

  u8 *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */
    if (__afl_area_ptr == (void *)-1) _exit(1);

  }

}


/* Fork server logic. */

static void __afl_start_forkserver_persistence(void);

static int max_cnt = 0;
static int forkserver_cycle_cnt = 0;
static int cycle_cnt = 0;

static void __afl_start_forkserver(void) {

  static int response = 0x41414141;
  char command;
  s32 child_pid;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */
  if(write(FORKSRV_TO_FUZZER, &response, sizeof(int)) != sizeof(int))
    return;

  if(getenv(PERSIST_MAX_VAR)) {
    __afl_start_forkserver_persistence();
    return;
  }

  while (1) {
    // Wait for parent by reading from the pipe. Exit if read fails.
    if(read(FUZZER_TO_FORKSRV, &command, sizeof(command)) != sizeof(command))
      _exit(1);

    switch(command) {

      case EXIT:
      case RUN: //LLVM doesn't do the single RUN/FORK commands
      case FORK: //but instead only implements FORK_RUN
        _exit(0);
        break;

      case FORK_RUN:
        child_pid = fork();
        if(child_pid < 0)
          _exit(1);

        //In child process: close fds, resume execution.
        if(!child_pid) {
          close(FUZZER_TO_FORKSRV);
          close(FORKSRV_TO_FUZZER);

          //Reset the afl bitmap to a clean state
          memset(__afl_area_ptr, 0, MAP_SIZE);
          __afl_prev_loc = 0;
          return;
        }

        response = child_pid;
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

static void __afl_start_forkserver_persistence(void) {

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

      case FORK:
      case RUN:
      case EXIT:

        if(child_pid != -1)
          kill(child_pid, SIGKILL);
        _exit(0);
        break;

      case FORK_RUN:

        if(child_pid == -1 || forkserver_cycle_cnt == max_cnt) {
          //If we need to (re)start the persistent child, do so

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
        } else {
          //Otherwise, just tell it to continue
          kill(child_pid, SIGCONT);
        }

        //Tell the target process to go
        response = child_pid;
        if(child_pid == -1) {
          response = FORKSERVER_ERROR;
          break;
        }

        forkserver_cycle_cnt++;
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

/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(void) {
  static u8  first_pass = 1;

  if (first_pass) {

    if (is_persistent) {
      memset(__afl_area_ptr, 0, MAP_SIZE);
      __afl_prev_loc = 0;
    }

    cycle_cnt  = 0;
    first_pass = 0;
    return 1;
  }

  if (is_persistent) {

    if(++cycle_cnt != max_cnt) {
      raise(SIGSTOP);
      memset(__afl_area_ptr, 0, MAP_SIZE);
      __afl_prev_loc = 0;
      return 1;

    } else {

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */
      __afl_area_ptr = __afl_area_initial;
    }
  }

  return 0;
}


/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static u8 init_done;

  if (!init_done) {

    __afl_map_shm();
    __afl_start_forkserver();
    init_done = 1;

  }

}


/* Proper initialization routine. */

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {

  is_persistent = !!getenv(PERSIST_MAX_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}


/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  __afl_area_ptr[*guard]++;
}


/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {

  u32 inst_ratio = 100;
  u8* x;

  if (start == stop || *start) return;

  x = getenv("AFL_INST_RATIO");
  if (x) inst_ratio = atoi(x);

  if (!inst_ratio || inst_ratio > 100) {
    fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
    abort();
  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  *(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
    else *start = 0;

    start++;

  }

}
