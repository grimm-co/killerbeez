#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "instrumentation.h"
#include "forkserver.h"
#include "utils.h"

#define STRINGIFY_INTERNAL(x) #x
#define STRINGIFY(x) STRINGIFY_INTERNAL(x)
#define MSAN_ERROR 86

//Save a fd to the /dev/null, so we don't have to keep opening/closing it
static int dev_null_fd =  -1;

//TODO Used to detect if a child timed out
static int child_timed_out = 0;

//TODO implement memory limiting
static int mem_limit = 0;

//TODO customize the execution timeout
static int exec_tmout = 1000;

//TODO asan detection
static int uses_asan = 0;

static char * find_fork_server_library(char * buffer, size_t buffer_len)
{
#ifdef __APPLE__
  char * library_name = "libforkserver.dylib";
#else
  char * library_name = "libforkserver.so";
#endif

  char * directory = filename_relative_to_binary_dir(".");
  snprintf(buffer, buffer_len, "%s/%s", directory, library_name);
  if (access(buffer, R_OK))
    FATAL_MSG("Failed to find the %s in %s.", library_name, directory);
}

void fork_server_init(fds_t * fds, char * target_path, char ** argv, int use_forkserver_library, int needs_stdin_fd)
{
  static struct itimerval it;
  int st_pipe[2], ctl_pipe[2];
  int rlen, status, forksrv_pid;
  char fork_server_library_path[MAX_PATH];
  char stdin_filename[100];

  if(dev_null_fd < 0) {
    dev_null_fd = open("/dev/null", O_RDWR);
    if (dev_null_fd < 0)
      FATAL_MSG("Unable to open /dev/null");
  }

  if(needs_stdin_fd) {
    strncpy(stdin_filename, "/tmp/fuzzfileXXXXXX", sizeof(stdin_filename));
    fds->target_stdin = mkstemp(stdin_filename);
    if(fds->target_stdin < 0)
      FATAL_MSG("Couldn't make temp file\n");
  }
  else
    fds->target_stdin = -1;

  DEBUG_MSG("Spinning up the fork server...");

  if(pipe(st_pipe) || pipe(ctl_pipe))
    FATAL_MSG("pipe() failed");

  forksrv_pid = fork();
  if(forksrv_pid < 0)
    FATAL_MSG("fork() failed");

  //In the child process
  if (!forksrv_pid) {

    struct rlimit r;

    // Umpf. On OpenBSD, the default fd limit for root users is set to
    // soft 128. Let's try to fix that...
    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < MAX_FORKSRV_FD) {

      r.rlim_cur = MAX_FORKSRV_FD;
      setrlimit(RLIMIT_NOFILE, &r); // Ignore errors

    }

    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); // Ignore errors

#else

      // This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
      // according to reliable sources, RLIMIT_DATA covers anonymous
      // maps - so we should be getting good protection against OOM bugs.
      setrlimit(RLIMIT_DATA, &r); // Ignore errors

#endif // ^RLIMIT_AS


    }

    // Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
    // before the dump is complete.

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); // Ignore errors

    // Isolate the process and configure standard descriptors.
    setsid();
    
    if(needs_stdin_fd) {
      dup2(fds->target_stdin, 0);
      close(fds->target_stdin);
    }
    else
      dup2(dev_null_fd, 0);
    //dup2(dev_null_fd, 1);
    //dup2(dev_null_fd, 2);

    // Set up control and status pipes, close the unneeded original fds.
    if (dup2(ctl_pipe[0], FUZZER_TO_FORKSRV) < 0)
      FATAL_MSG("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_TO_FUZZER) < 0)
      FATAL_MSG("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(dev_null_fd);

    // Preload the forkserver library
    if(use_forkserver_library) {
      find_fork_server_library(fork_server_library_path, sizeof(fork_server_library_path));
      setenv("LD_PRELOAD", fork_server_library_path, 1);
    }

    // This should improve performance a bit, since it stops the linker from
    // doing extra work post-fork().
    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

    // Set sane defaults for ASAN if nothing else specified.
    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "symbolize=0:"
                           "allocator_may_return_null=1", 0);

    // MSAN is tricky, because it doesn't support abort_on_error=1 at this
    // point. So, we do this in a very hacky way.
    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "symbolize=0:"
                           "abort_on_error=1:"
                           "allocator_may_return_null=1:"
                           "msan_track_origins=0", 0);

    execv(target_path, argv);
    exit(1);
  }

  // Close the unneeded endpoints.
  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fds->fuzzer_to_forksrv = ctl_pipe[1];
  fds->forksrv_to_fuzzer = st_pipe[0];

  // Wait for the fork server to come up, but don't wait too long.
  it.it_value.tv_sec = (exec_tmout / 1000);
  it.it_value.tv_usec = (exec_tmout % 1000) * 1000;
  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(st_pipe[0], &status, sizeof(status));

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;
  setitimer(ITIMER_REAL, &it, NULL);

  // If we have a four-byte "hello" message from the server, we're all set.
  // Otherwise, try to figure out what went wrong.
  if (rlen == 4) {
    DEBUG_MSG("All right - fork server is up.");
    return;
  }

  if (child_timed_out)
    FATAL_MSG("Timeout while initializing fork server");

  if (waitpid(forksrv_pid, &status, 0) <= 0)
    FATAL_MSG("waitpid() failed");

  if (WIFSIGNALED(status)) {

    if (mem_limit && mem_limit < 500 && uses_asan) {

      ERROR_MSG(
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you have a\n"
           "    restrictive memory limit configured, this is expected");

    } else if (!mem_limit) {

      ERROR_MSG(
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, try running without the forkserver.\n\n"

#endif // __APPLE__

           "    - Less likely, there is a horrible bug in the fuzzer.");

    } else {

      ERROR_MSG(
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The current memory limit (%s) is too restrictive, causing the\n"
           "      target to hit an OOM condition in the dynamic linker. Try bumping up\n"
           "      the limit with the -m setting in the command line. A simple way confirm\n"
           "      this diagnosis would be:\n\n"

#ifdef RLIMIT_AS
           "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
           "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif // ^RLIMIT_AS

           "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
           "      estimate the required amount of virtual memory for the binary.\n\n"

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      targets. To fix this, try running without the forkserver.\n\n"

#endif // __APPLE__

           "    - Less likely, there is a horrible bug in the fuzzer.",
           mem_limit << 20, mem_limit - 1);

    }

    FATAL_MSG("Fork server crashed with signal %d", WTERMSIG(status));

  }

  if (mem_limit && mem_limit < 500 && uses_asan) {

    ERROR_MSG(
           "Hmm, looks like the target binary terminated before we could complete a\n"
           "    handshake with the injected code. Since it seems to be built with ASAN and\n"
           "    you have a restrictive memory limit configured, this is expected.");

  } else if (!mem_limit) {

    ERROR_MSG(
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. Perhaps there is a horrible bug in the\n"
         "    fuzzer.");

  } else {

    ERROR_MSG(
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. There are a few probable explanations:\n\n"

         "    - The current memory limit (%s) is too restrictive, causing an OOM\n"
         "      fault in the dynamic linker. This can be fixed with the -m option. A\n"
         "      simple way to confirm the diagnosis may be:\n\n"

#ifdef RLIMIT_AS
         "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
         "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif // ^RLIMIT_AS

         "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
         "      estimate the required amount of virtual memory for the binary.\n\n"

         "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
         "      fail.",
         mem_limit << 20, mem_limit - 1);

  }

  FATAL_MSG("Fork server handshake failed");
}

static int send_command(fds_t * fds, char command)
{
  if (write(fds->fuzzer_to_forksrv, &command, sizeof(command)) != sizeof(command))
    return FORKSERVER_ERROR;
  return 0;
}

static int read_response(fds_t * fds)
{
  int response;
  if (read(fds->forksrv_to_fuzzer, &response, sizeof(response)) != sizeof(response))
    return FORKSERVER_ERROR;
  return response;
}

int fork_server_exit(fds_t * fds)
{
  return send_command(fds, EXIT);
}

int fork_server_fork(fds_t * fds)
{
  if(send_command(fds, FORK))
    return FORKSERVER_ERROR;
  return read_response(fds); //Wait for the target pid
}

int fork_server_run(fds_t * fds)
{
  return send_command(fds, RUN);
}

int fork_server_get_pending_status(fds_t * fds, int wait)
{
  unsigned long bytes_available = 0;
  int err;

  if(wait)
    return read_response(fds); //Wait for the target's exit status
  else {
    err = ioctl(fds->forksrv_to_fuzzer, FIONREAD, &bytes_available);
    printf("%d GOT %lu from ioctl\n", err, bytes_available);
    if(!err && bytes_available == sizeof(int))
      return read_response(fds); //Wait for the target's exit status
  }
  return FORKSERVER_NO_RESULTS_READY;
}

int fork_server_get_status(fds_t * fds, int wait)
{
  if(send_command(fds, GET_STATUS))
    return FORKSERVER_ERROR;
  return fork_server_get_pending_status(fds, wait);
}

