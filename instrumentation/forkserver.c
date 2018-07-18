#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "forkserver.h"

//Whether we should hook __libc_start_main or not.  This is a default option
//that should work for most Linux programs
#define USE_LIBC_START_MAIN 1

//If we're not hooking __libc_start_main, this defines the function to hook
#define CUSTOM_FUNCTION_NAME custom_function_to_hook

//If we're not hooking __libc_start_main, this defines whether we should run
//before or after the function that we are hooking
#define RUN_BEFORE_CUSTOM_FUNCTION 0

//////////////////////////////////////////////////////////////
//Function Prototypes and Globals ////////////////////////////
//////////////////////////////////////////////////////////////

void forkserver_init(void);
void * fake_main(void * a0, void * a1, void * a2, void * a3, void * a4, void * a5, void * a6, void * a7);

//Whether or not we've already started the forkserver
static int init_done = 0;

//For now, just leave this as 0, in the future we will implement persistent mode
static int is_persistent = 0;

//////////////////////////////////////////////////////////////
//Function Hooking ///////////////////////////////////////////
//////////////////////////////////////////////////////////////

#ifdef __APPLE__ 
//On APPLE, we need the definition of the function we're hooking, so we include the library
#include <stdio.h>

#define FUNCTION CUSTOM_FUNCTION_NAME
#define NEW_FUNCTION new_##FUNCTION
#define DYLD_INTERPOSE(_replacment,_replacee) \
__attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };
#else

#if USE_LIBC_START_MAIN
#define FUNCTION __libc_start_main
#else
#define FUNCTION CUSTOM_FUNCTION_NAME
#endif

#define NEW_FUNCTION FUNCTION

#endif

//Convert FUNCTION into "FUNCTION" so we can use it to call dlsym
#define STRINGIFY_INNER(s) (#s)
#define STRINGIFY(name) STRINGIFY_INNER(name)
#define FUNCTION_NAME STRINGIFY(FUNCTION)


typedef void * (*orig_function_type)(void *, void *, void *, void *, void *, void *, void *, void *);

static orig_function_type orig_func = NULL;
#if USE_LIBC_START_MAIN
static orig_function_type orig_main = NULL;
#endif

void * NEW_FUNCTION(void * a0, void * a1, void * a2, void * a3, void * a4, void * a5, void * a6, void * a7)
{
	void * ret;

	if(orig_func == NULL)
		orig_func = (orig_function_type)dlsym(RTLD_NEXT, FUNCTION_NAME);

#if USE_LIBC_START_MAIN //we're hooking __libc_start_main

	orig_main = a0;
	ret = orig_func((void *)fake_main, a1, a2, a3, a4, a5, a6, a7);

#else //We're hooking a custom function

#if RUN_BEFORE_CUSTOM_FUNCTION //If we want to run before the hooked function
	if(!init_done) forkserver_init();
#endif

	ret = orig_func(a0, a1, a2, a3, a4, a5, a6, a7);

#if !RUN_BEFORE_CUSTOM_FUNCTION //If we want to run after the hooked function
	if(!init_done) forkserver_init();
#endif

#endif

	return ret;
}

void * fake_main(void * a0, void * a1, void * a2, void * a3, void * a4, void * a5, void * a6, void * a7)
{
	forkserver_init();
	return orig_main(a0, a1, a2, a3, a4, a5, a6, a7);
}

#ifdef __APPLE__
DYLD_INTERPOSE(NEW_FUNCTION, FUNCTION)
#endif

//////////////////////////////////////////////////////////////
//Fork Server ////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

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

   The code in this section has been modified from the original to suit the
   purposes of this project.
*/


void forkserver_init(void)
{
  int tmp = 0;
  int child_pid;
  int child_stopped = 0;

  // Phone home and tell the parent that we're OK. If parent isn't there,
  // assume we're not running in forkserver mode and just execute program.
  if (write(FORKSRV_TO_FUZZER, &tmp, 4) != 4) return;

  while (1) {

    int was_killed;
    int status;

    // Wait for parent by reading from the pipe. Abort if read fails.
    if (read(FUZZER_TO_FORKSRV, &was_killed, 4) != 4)
			_exit(1);

    // If we stopped the child in persistent mode, but there was a race
    // condition and afl-fuzz already issued SIGKILL, write off the old
    // process.
    if (child_stopped && was_killed) {
      child_stopped = 0;
      if(waitpid(child_pid, &status, 0) < 0)
				_exit(1);
    }

    if (!child_stopped) {

      // Once woken up, create a clone of our process.
      child_pid = fork();
      if (child_pid < 0)
				_exit(1);

      // In child process: close fds, resume execution.
      if (!child_pid) {
        close(FUZZER_TO_FORKSRV);
        close(FORKSRV_TO_FUZZER);
        return;
      }

    } else {

      // Special handling for persistent mode: if the child is alive but
      // currently stopped, simply restart it with SIGCONT.
      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    // In parent process: write PID to pipe, then wait for child.
    if (write(FORKSRV_TO_FUZZER, &child_pid, 4) != 4)
			_exit(1);

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    // In persistent mode, the child stops itself with SIGSTOP to indicate
    // a successful run. In this case, we want to wake it up without forking
    // again.
    if (WIFSTOPPED(status)) child_stopped = 1;

    // Relay wait status to pipe, then loop back.
    if (write(FORKSRV_TO_FUZZER, &status, 4) != 4) _exit(1);

  }

	init_done = 1;

}

