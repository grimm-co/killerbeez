// Linux-only Intel PT instrumentation.

#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#include "instrumentation.h"
#include "linux_ipt_instrumentation.h"

#include <utils.h>
#include <jansson_helper.h>

////////////////////////////////////////////////////////////////
// Private methods /////////////////////////////////////////////
////////////////////////////////////////////////////////////////

/**
 * This function terminates the fuzzed process.
 * @param state - The linux_ipt_state_t object containing this instrumentation's state
 */
static int destroy_target_process(linux_ipt_state_t * state)
{
  kill(state->child_pid, SIGKILL);
  return fork_server_get_status(&state->fds, 1);
}

/**
 * This function starts the fuzzed process
 * @param state - The linux_ipt_state_t object containing this instrumentation's state
 * @param cmd_line - the command line of the fuzzed process to start
 * @param stdin_input - the input to pass to the fuzzed process's stdin
 * @param stdin_length - the length of the stdin_input parameter
 * @return - zero on success, non-zero on failure.
 */
static int create_target_process(linux_ipt_state_t * state, char* cmd_line, char * stdin_input, size_t stdin_length)
{
  char * target_path;
  char ** argv;
  int pid;

  if(!state->fork_server_setup) {
    if(split_command_line(cmd_line, &target_path, &argv))
      return -1;
    fork_server_init(&state->fds, target_path, argv, 1, stdin_length != 0);
    state->fork_server_setup = 1;
  }

  pid = fork_server_fork(&state->fds);
  if(pid < 0)
    return -1;

  //Take care of the stdin input, write over the file, then truncate it accordingly
  lseek(state->fds.target_stdin, 0, SEEK_SET);
  if(stdin_input != NULL && stdin_length != 0) {
    if(write(state->fds.target_stdin, stdin_input, stdin_length) != stdin_length)
      FATAL_MSG("Short write to target's stdin file");
  }
  if (ftruncate(state->fds.target_stdin, stdin_length))
    FATAL_MSG("ftruncate() failed");
  lseek(state->fds.target_stdin, 0, SEEK_SET);

  state->child_pid = pid;
  return 0;
}

static int get_file_int(char * filename)
{
  int ret;
  char * buffer;

  ret = read_file(filename, &buffer);
  if(ret > 0 && buffer != NULL)
    ret = atoi(buffer);
  else
    ret = -1;
  free(buffer);
  return ret;
}

static int get_ipt_system_info(linux_ipt_state_t * state)
{
  int ret;

  if(access("/sys/devices/intel_pt/", F_OK)) {
    INFO_MSG("Intel PT not supported (/sys/devices/intel_pt/ does not exist)");
    return 1;
  }

  //For the moment, we'll only support Intel PT with address filtering
  ret = get_file_int("/sys/devices/intel_pt/caps/ip_filtering");
  if(ret <= 0) {
    INFO_MSG("Intel PT address filtering not supported");
    return -1;
  }

  ret = get_file_int("/sys/devices/intel_pt/caps/num_address_ranges");
  if(ret <= 0) {
    INFO_MSG("Intel PT address filtering not supported");
    return -1;
  }
  state->num_address_ranges = ret;

  return 0;
}

////////////////////////////////////////////////////////////////
// Instrumentation methods /////////////////////////////////////
////////////////////////////////////////////////////////////////

/**
 * This function allocates and initializes a new instrumentation specific state object based on the given options.
 * @param options - a JSON string that contains the instrumentation specific string of options
 * @param state - an instrumentation specific JSON string previously returned from linux_ipt_get_state that should be loaded
 * @return - An instrumentation specific state object on success or NULL on failure
 */
void * linux_ipt_create(char * options, char * state)
{
  // Allocate and initialize linux_ipt state object.
  linux_ipt_state_t * linux_ipt_state;
  linux_ipt_state = malloc(sizeof(linux_ipt_state_t));
  if (!linux_ipt_state)
    return NULL;
  memset(linux_ipt_state, 0, sizeof(linux_ipt_state_t));

  if(get_ipt_system_info(linux_ipt_state)) {
    linux_ipt_cleanup(linux_ipt_state);
    return NULL;
  }

  if (state && linux_ipt_set_state(linux_ipt_state, state))
  {
    linux_ipt_cleanup(linux_ipt_state);
    return NULL;
  }

  return linux_ipt_state;
}

/**
 * This function cleans up all resources with the passed in instrumentation state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the linux_ipt_create function
 * This state object should not be referenced after this function returns.
 */
void linux_ipt_cleanup(void * instrumentation_state)
{
  linux_ipt_state_t * state = (linux_ipt_state_t *)instrumentation_state;

  destroy_target_process(state);

  free(state);
}

/**
 * This function merges the coverage information from two instrumentation states.  This will always fail for the
 * linux_ipt instrumentation, since it does not record instrumentation data.
 * @param instrumentation_state - an instrumentation specific state object previously created by the linux_ipt_create function
 * @param other_instrumentation_state - an instrumentation specific state object previously created by the linux_ipt_create function
 * @return - An instrumentation specific state object that contains the combination of both of the passed in instrumentation states
 * on success, or NULL on failure
 */
void * linux_ipt_merge(void * instrumentation_state, void * other_instrumentation_state)
{
  return NULL; //TODO
}

/**
 * This function returns the state information holding the previous execution path info.  The returned value can later be passed to
 * linux_ipt_create or linux_ipt_set_state to load the state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the linux_ipt_create function
 * @return - A JSON string that holds the instrumentation specific state object information on success, or NULL on failure
 */
char * linux_ipt_get_state(void * instrumentation_state)
{
  linux_ipt_state_t * state = (linux_ipt_state_t *)instrumentation_state;
  json_t *state_obj, *temp;
  char * ret;

  state_obj = json_object();
  ret = json_dumps(state_obj, 0);
  json_decref(state_obj);
  return ret;
}

/**
 * This function frees an instrumentation state previously obtained via linux_ipt_get_state.
 * @param state - the instrumentation state to free
 */
void linux_ipt_free_state(char * state)
{
  free(state);
}

/**
 * This function sets the instrumentation state to the passed in state previously obtained via linux_ipt_get_state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the linux_ipt_create function
 * @param state - an instrumentation state previously obtained via linux_ipt_get_state
 * @return - 0 on success, non-zero on failure.
 */
int linux_ipt_set_state(void * instrumentation_state, char * state)
{
  linux_ipt_state_t * current_state = (linux_ipt_state_t *)instrumentation_state;
  int result, temp_int;
  if (!state)
    return 1;

  //If a child process is running when the state is being set
  destroy_target_process(current_state); //kill it so we don't orphan it

  return 0; //No state to set, so just return success
}

/**
 * This function enables the instrumentation and runs the fuzzed process.  If the process needs to be restarted, it will be.
 * @param instrumentation_state - an instrumentation specific state object previously created by the linux_ipt_create function
 * @process - a pointer to return a handle to the process that instrumentation was enabled on
 * @cmd_line - the command line of the fuzzed process to enable instrumentation on
 * @input - a buffer to the input that should be sent to the fuzzed process on stdin
 * @input_length - the length of the input parameter
 * returns 0 on success, -1 on failure
 */
int linux_ipt_enable(void * instrumentation_state, pid_t * process, char * cmd_line, char * input, size_t input_length)
{
  linux_ipt_state_t * state = (linux_ipt_state_t *)instrumentation_state;
  if(state->child_pid)
    destroy_target_process(state);
  if (create_target_process(state, cmd_line, input, input_length))
    return -1;
  *process = state->child_pid;
  return 0;
}

/**
 * This function determines whether the process being instrumented has taken a new path.  The linux_ipt instrumentation does
 * not track the fuzzed process's path, so it is unable to determine if the process took a new path.
 * @param instrumentation_state - an instrumentation specific state object previously created by the linux_ipt_create function
 * @return - 0 when a new path wasn't detected (as it always won't be with the linux_ipt instrumentation), or -1 on failure.
 */
int linux_ipt_is_new_path(void * instrumentation_state)
{
  return 0; //TODO
}

/**
 * This function will return the result of the fuzz job. It should be called
 * after the process has finished processing the tested input, which should always be the case
 * with the linux_ipt instrumentation, since test_next_input should always wait for the process to finish.
 * @param instrumentation_state - an instrumentation specific structure previously created by the create() function
 * @return - either FUZZ_NONE, FUZZ_HANG, FUZZ_CRASH, or -1 on error.
 */
int linux_ipt_get_fuzz_result(void * instrumentation_state)
{
  linux_ipt_state_t * state = (linux_ipt_state_t *)instrumentation_state;
  int status;

  status = destroy_target_process(state);
  return -1;
}

/**
 * This function returns help text for this instrumentation.  This help text will describe the instrumentation and any options
 * that can be passed to linux_ipt_create.
 * @return - a newly allocated string containing the help text.
 */
char * linux_ipt_help(void)
{
  return strdup(
      "ipt - Linux IPT instrumentation\n"
      "Options:\n"
      "\tNone\n"
      "\n"
      );
}

