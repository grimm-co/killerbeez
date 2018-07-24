#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
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

static void forkserver_init(void);
static void forkserver_persistence_init(void);
static void * fake_main(void * a0, void * a1, void * a2, void * a3, void * a4, void * a5, void * a6, void * a7);

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

  //The fork server design was inspired by the LLVM mode of AFL. It however,
  //has been modified significantly to suit our purposes.  The LLVM mode of
  //AFL is available at:
  //https://github.com/mirrorer/afl/blob/master/llvm_mode/afl-llvm-rt.o.c#L95

static void forkserver_init(void)
{
  int response = 0x41414141;
  char command;
  int child_pid;
  int target_pipe[2];

  //Ensure children don't try to also run the forkserver
  init_done = 1;

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

static long max_cnt = 0;
static long cycle_cnt = 0;

static void forkserver_persistence_init(void)
{
  int response = 0x41414141;
  char command, target_command;
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

        kill(child_pid, SIGKILL);
        _exit(0);
        break;

      case FORK:
      case FORK_RUN:

        if(child_pid == -1) {

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
        kill(child_pid, SIGCONT);
        if(command != FORK_RUN) //Don't overwrite the FORK case's response
          response = 0;
        break;

      case GET_STATUS:

        if(waitpid(child_pid, &response, WUNTRACED) < 0)
          _exit(1);

        if(WIFEXITED(response) || WIFSIGNALED(response)) //The process ended, either
          child_pid = -1; //by hitting the max_cnt count and exiting, or by crashing
        else if(WIFSTOPPED(response)) //If we hit a SIGSTOP, then the child didn't
          response = 0;               //die, just return 0 to the parent

        break;
    }

    if(write(FORKSRV_TO_FUZZER, &response, sizeof(response)) != sizeof(response))
      _exit(1);
  }
}

int killerbeez_loop(void) {

  cycle_cnt++;
  if(cycle_cnt == max_cnt)
    return 0;

  raise(SIGSTOP);
  return 1;
}

