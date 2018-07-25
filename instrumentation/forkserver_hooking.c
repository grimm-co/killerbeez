#define _GNU_SOURCE
#include <dlfcn.h>

#include "forkserver.h"
#include "forkserver_config.h"

#if !DISABLE_HOOKING

//////////////////////////////////////////////////////////////
//Types, Function Prototypes, and Globals ////////////////////
//////////////////////////////////////////////////////////////

//In order to allow for the hooking of functions, regardless of their arguments, we define the hook
//function as having a ton of void * arguments.  This allows us to pass these arguments on (regardless
//of whether they actually exist or not).
typedef void * (*orig_function_type)(void *, void *, void *, void *, void *, void *, void *, void *);

//Whether or not we've already started the forkserver
static int init_done = 0;

//A pointer to the original function that we hooked
static orig_function_type orig_func = 0;

//////////////////////////////////////////////////////////////
//Function Hooking ///////////////////////////////////////////
//////////////////////////////////////////////////////////////

#ifdef __APPLE__

//Define a fake prototype here, otherwise it will complain when it's used.
void CUSTOM_FUNCTION_NAME(void);

#define FUNCTION CUSTOM_FUNCTION_NAME
#define NEW_FUNCTION new_##FUNCTION
#define DYLD_INTERPOSE(_replacment,_replacee) \
  __attribute__((used)) static struct{ const void* replacment; const void* replacee; } _interpose_##_replacee \
__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacment, (const void*)(unsigned long)&_replacee };

#else //LINUX

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

#if USE_LIBC_START_MAIN
static orig_function_type orig_main = 0;

void * fake_main(void * a0, void * a1, void * a2, void * a3, void * a4, void * a5, void * a6, void * a7)
{
  __forkserver_init();
  return orig_main(a0, a1, a2, a3, a4, a5, a6, a7);
}
#endif

void * NEW_FUNCTION(void * a0, void * a1, void * a2, void * a3, void * a4, void * a5, void * a6, void * a7)
{
  void * ret;

  if(orig_func == 0)
    orig_func = (orig_function_type)dlsym(RTLD_NEXT, FUNCTION_NAME);

#if USE_LIBC_START_MAIN //we're hooking __libc_start_main

  orig_main = a0;
  ret = orig_func((void *)fake_main, a1, a2, a3, a4, a5, a6, a7);

#else //We're hooking a custom function

#if RUN_BEFORE_CUSTOM_FUNCTION //If we want to run before the hooked function
  if(!init_done) {
    __forkserver_init();
    init_done = 1;
  }
#endif

  ret = orig_func(a0, a1, a2, a3, a4, a5, a6, a7);

#if !RUN_BEFORE_CUSTOM_FUNCTION //If we want to run after the hooked function
  if(!init_done) {
    __forkserver_init();
    init_done = 1;
  }
#endif

#endif

  return ret;
}

#ifdef __APPLE__
DYLD_INTERPOSE(NEW_FUNCTION, FUNCTION)
#endif

#endif //!DISABLE_HOOKING
