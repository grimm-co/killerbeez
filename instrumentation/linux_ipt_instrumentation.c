// Linux-only Intel PT instrumentation.
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "instrumentation.h"
#include "linux_ipt_instrumentation.h"
#include "forkserver.h"
#include "uthash.h"
#include "xxhash.h"

#include <utils.h>
#include <jansson_helper.h>

////////////////////////////////////////////////////////////////
// IPT Packet Analyzer /////////////////////////////////////////
////////////////////////////////////////////////////////////////

//Uncomment this define to make the IPT parser print each packet
//#define IPT_DEBUG

#ifdef IPT_DEBUG
#define IPT_DEBUG_MSG DEBUG_MSG
#else
#define IPT_DEBUG_MSG
#endif

#define BYTES_LEFT(num)    ((end - p) >= (num))
#define BIT_TEST(num, bit) ((num) & (1 << (bit)))

static uint64_t get_ip_val(unsigned char **pp, unsigned char *end, int len, uint64_t *last_ip)
{
  unsigned char *p = *pp;
  uint64_t v = *last_ip;
  int i;
  unsigned shift = 0;

  if (len == 0) {
    *last_ip = 0;
    return 0; // out of context
  }
  if (len < 4) {
    if (!BYTES_LEFT(len)) {
      *last_ip = 0;
      WARNING_MSG("Got error in get_ip_val: Not enough bytes for decoding IP (have %lu, need %lu)", end-p, len);
      return 0;
    }
    for (i = 0; i < len; i++, shift += 16, p += 2) {
      uint64_t b = *(uint16_t *)p;
      v = (v & ~(0xffffULL << shift)) | (b << shift);
    }
    v = ((int64_t)(v << (64 - 48))) >> (64 - 48); // sign extension
  } else {
    WARNING_MSG("Got error in get_ip_val!");
    return 0;
  }
  *pp = p;
  *last_ip = v;
  return v;
}

static void finish_tnt_hash(struct ipt_hash_state * ipt_hashes)
{
	if(ipt_hashes->num_bits != 0) {
		if(XXH64_update(ipt_hashes->tnt, &ipt_hashes->tnt_bits, sizeof(uint64_t)) == XXH_ERROR)
			WARNING_MSG("Updating the TNT hash failed!"); //Should never happen
	}
}

static void add_tnt_to_hash(struct ipt_hash_state * ipt_hashes, unsigned char * tnt_bits, int num_bits)
{
	uint64_t i;
#ifdef IPT_DEBUG
  char bit_string[64];

  for(i = 0; i < num_bits; i++)
    bit_string[i] = BIT_TEST(tnt_bits[i / 8], i % 8) ? 'T' : 'N';
  bit_string[num_bits] = 0;

  IPT_DEBUG_MSG("TNT bits %d: %s", num_bits, bit_string);
#endif

	for(i = 0; i < num_bits; i++) {
		ipt_hashes->tnt_bits |= (BIT_TEST(tnt_bits[i / 8], i % 8) << ipt_hashes->num_bits);
		ipt_hashes->num_bits++;
		if(ipt_hashes->num_bits == sizeof(ipt_hashes->tnt_bits)) {
			if(XXH64_update(ipt_hashes->tnt, &ipt_hashes->tnt_bits, sizeof(uint64_t)) == XXH_ERROR)
				WARNING_MSG("Updating the TNT hash failed!"); //Should never happen
			ipt_hashes->tnt_bits = 0;
			ipt_hashes->num_bits = 0;
		}
	}
}

static void add_tip_to_hash(struct ipt_hash_state * ipt_hashes, uint64_t tip)
{
  IPT_DEBUG_MSG("TIP %lx", tip);
  if(XXH64_update(ipt_hashes->tip, &tip, sizeof(uint64_t)) == XXH_ERROR)
    WARNING_MSG("Updating the TIP hash failed!"); //Should never happen
}

static int get_tnt_num_bits(unsigned char * packet, int max_bits)
{
  int num_bits;
  for(num_bits = max_bits; num_bits >= 0; num_bits--) { //Find the stop bit
    if(BIT_TEST(packet[num_bits / 8], num_bits % 8))
      break;
  }
  return num_bits;
}

static int analyze_ipt(linux_ipt_state_t * state)
{
  unsigned char * p, * start, * end, * psb_pos;
  struct ipt_hashtable_entry * hashes, * match = NULL;
  uint64_t ip_address, last_ip = 0;

  const unsigned char psb[0x10] = {
    0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
    0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82
  };

	//Reset the IPT hashes struct
	state->ipt_hashes.tnt_bits = 0;
	state->ipt_hashes.num_bits = 0;
  if(XXH64_reset(state->ipt_hashes.tnt, 0) == XXH_ERROR ||
    XXH64_reset(state->ipt_hashes.tip, 0) == XXH_ERROR)
    return -1;

  hashes = malloc(sizeof(struct ipt_hashtable_entry));
  if(!hashes)
    return -1;

  start = (char *)state->perf_aux_buf + state->pem->aux_tail;
  p = (char *)state->perf_aux_buf + state->pem->aux_tail;
  end = (char *)state->perf_aux_buf + state->pem->aux_head;

#ifdef IPT_DEBUG
  write_buffer_to_file("/tmp/ipt_dump", start, end-start);
#endif

  while(p < end) {

    psb_pos = memmem(p, end - p, psb, sizeof(psb));
    if(!psb_pos) {
      DEBUG_MSG("Couldn't find PSB packet");
      break;
    }
    IPT_DEBUG_MSG("Skipping %d bytes", psb_pos - p);
    p = psb_pos + sizeof(psb);

    while(p < end)
    {
      IPT_DEBUG_MSG("%04x: %02x %02x %02x %02x %02x %02x %02x %02x", p - start,
        (unsigned char)p[0], (unsigned char)p[1], (unsigned char)p[2], (unsigned char)p[3],
        (unsigned char)p[4], (unsigned char)p[5], (unsigned char)p[6], (unsigned char)p[7]);

      if (p[0] == 2 && BYTES_LEFT(2)) {
        if (p[1] == 0xa3 && BYTES_LEFT(8)) { // Long TNT
          IPT_DEBUG_MSG("Long TNT");
          add_tnt_to_hash(&state->ipt_hashes, p+2, get_tnt_num_bits(p+2, 47));
          p += 8;
          continue;
        }
        if (p[1] == 0x43 && BYTES_LEFT(8)) { // PIP
          IPT_DEBUG_MSG("PIP");
          p += 8;
          continue;
        }
        if (p[1] == 3 && BYTES_LEFT(4)) { // CBR
          IPT_DEBUG_MSG("CBR");
          p += 4;
          continue;
        }
        if (p[1] == 0x83) { //TRACESTOP
          IPT_DEBUG_MSG("TRACESTOP");
          p += 2;
          continue;
        }
        if (p[1] == 0xf3 && BYTES_LEFT(8)) { // OVF
          p += 8;
          WARNING_MSG("IPT received overflow packet");
          continue;
        }
        if (p[1] == 0x82 && BYTES_LEFT(16) && !memcmp(p, psb, 16)) { // PSB
          IPT_DEBUG_MSG("PSB");
          p += 16;
          continue;
        }
        if (p[1] == 0x23) { // PSBEND
          IPT_DEBUG_MSG("PSBEND");
          p += 2;
          continue;
        }
        if (p[1] == 0xc3 && BYTES_LEFT(11) && p[2] == 0x88) { //MNT
          IPT_DEBUG_MSG("MNT");
          p += 10;
          continue;
        }
        if (p[1] == 0x73 && BYTES_LEFT(7)) { //TMA
          IPT_DEBUG_MSG("TMA");
          p += 7;
          continue;
        }
        if (p[1] == 0xc8 && BYTES_LEFT(7)) { //VMCS
          IPT_DEBUG_MSG("VMCS");
          p += 7;
          continue;
        }
      }

      if(!(p[0] & 1)) {
        if (p[0] == 0) { // PAD
          IPT_DEBUG_MSG("PAD");
          p++;
          continue;
        }

        // Short TNT
        char tnt_bits = p[0] >> 1;
        add_tnt_to_hash(&state->ipt_hashes, &tnt_bits, get_tnt_num_bits(&tnt_bits, 6));
        IPT_DEBUG_MSG("SHORT TNT");
        p++;
        continue;
      }

#define TIP_TYPE_TIP     0xd
#define TIP_TYPE_TIP_PGE 0x11
#define TIP_TYPE_TIP_PGD 0x1
#define TIP_TYPE_FUP     0x1d

      char tip_type = p[0] & 0x1f;
      if(tip_type == TIP_TYPE_TIP || tip_type == TIP_TYPE_TIP_PGE
          || tip_type == TIP_TYPE_TIP_PGD || tip_type == TIP_TYPE_FUP) {

        int ipl = *p >> 5;
        ip_address = get_ip_val(&p, end, ipl, &last_ip);
        if(tip_type != TIP_TYPE_TIP || (tip_type == TIP_TYPE_TIP && ip_address)) {
          IPT_DEBUG_MSG("TIP/PGE/PGD/FUP");
          if(tip_type == TIP_TYPE_TIP) {
            add_tip_to_hash(&state->ipt_hashes, ip_address);
          }

          p++;
          continue;
        }
      }

      if (p[0] == 0x99 && BYTES_LEFT(2)) { // MODE
        if ((p[1] >> 5) == 1) {
          IPT_DEBUG_MSG("MODE 1");
          p += 2;
          continue;
        } else if ((p[1] >> 5) == 0) {
          IPT_DEBUG_MSG("MODE 2");
          p += 2;
          continue;
        }
      }

      if (p[0] == 0x19 && BYTES_LEFT(8)) { // TSC
        IPT_DEBUG_MSG("TSC");
        p+=8;
        continue;
      }
      if (p[0] == 0x59 && BYTES_LEFT(2)) { // MTC
        IPT_DEBUG_MSG("MTC");
        p += 2;
        continue;
      }
      if ((p[0] & 3) == 3) { // CYC
        IPT_DEBUG_MSG("CYC");
        if ((p[0] & 4) && BYTES_LEFT(1)) {
          do {
            p++;
          } while ((p[0] & 1) && BYTES_LEFT(1));
        }
        p++;
        continue;
      }

      WARNING_MSG("Hit unknown packet type at offset 0x%lx", p - start);
      break;
    }
  }

  //Create a hashtable entry to lookup/add
  finish_tnt_hash(&state->ipt_hashes);
  memset(hashes, 0, sizeof(struct ipt_hashtable_entry));
  hashes->id.tip = XXH64_digest(state->ipt_hashes.tip);
  hashes->id.tnt = XXH64_digest(state->ipt_hashes.tnt);
  DEBUG_MSG("Got TIP hash 0x%llx and TNT hash 0x%llx", hashes->id.tip, hashes->id.tnt);

  //Look for our hashes in the hashtable, and add them if they're not already in it
  HASH_FIND(hh, state->head, &hashes->id, sizeof(struct ipt_hashtable_key), match);
  if(!match)
    HASH_ADD(hh, state->head, id, sizeof(struct ipt_hashtable_key), hashes);
  else
    free(hashes);
  return match == NULL;
}

////////////////////////////////////////////////////////////////
// Private methods /////////////////////////////////////////////
////////////////////////////////////////////////////////////////

static void cleanup_ipt(linux_ipt_state_t * state)
{
  if(state->perf_aux_buf && state->perf_aux_buf != MAP_FAILED)
    munmap(state->perf_aux_buf, state->pem->aux_size);
  state->perf_aux_buf = NULL;
  if(state->pem && state->pem != MAP_FAILED)
    munmap(state->pem, PERF_MMAP_SIZE + getpagesize());
  state->pem = NULL;
  if(state->perf_fd >= 0)
    close(state->perf_fd);
  state->perf_fd = -1;
}

/**
 * This function terminates the fuzzed process.
 * @param state - The linux_ipt_state_t object containing this instrumentation's state
 */
static void destroy_target_process(linux_ipt_state_t * state)
{
  if(state->child_pid) {
    kill(state->child_pid, SIGKILL);
    state->child_pid = 0;
    state->last_status = fork_server_get_status(&state->fs, 1);
  }
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
  char ** argv;
  int i, pid;

  if(!state->fork_server_setup) {
    if(split_command_line(cmd_line, &state->target_path, &argv))
      return -1;
    fork_server_init(&state->fs, state->target_path, argv, 1, stdin_length != 0);
    state->fork_server_setup = 1;
    for(i = 0; argv[i]; i++)
      free(argv[i]);
    free(argv);
  }

  cleanup_ipt(state);
  pid = fork_server_fork(&state->fs);
  if(pid < 0)
    return -1;

  //Take care of the stdin input, write over the file, then truncate it accordingly
  lseek(state->fs.target_stdin, 0, SEEK_SET);
  if(stdin_input != NULL && stdin_length != 0) {
    if(write(state->fs.target_stdin, stdin_input, stdin_length) != stdin_length)
      FATAL_MSG("Short write to target's stdin file");
  }
  if(ftruncate(state->fs.target_stdin, stdin_length))
    FATAL_MSG("ftruncate() failed");
  lseek(state->fs.target_stdin, 0, SEEK_SET);

  state->child_pid = pid;
  return 0;
}

static int get_file_int(char * filename)
{
  int ret, fd;
  char buffer[100];

  fd = open(filename, O_RDONLY);
  if(fd < 0)
    return -1;

  memset(buffer, 0, sizeof(buffer));
  ret = read(fd, buffer, sizeof(buffer));
  if(ret > 0)
    ret = atoi(buffer);
  else
    ret = -1;
  close(fd);
  return ret;
}

static int get_ipt_system_info(linux_ipt_state_t * state)
{
  int ret;

  if(access("/sys/devices/intel_pt/", F_OK)) {
    INFO_MSG("Intel PT not supported (/sys/devices/intel_pt/ does not exist)");
    return 1;
  }

  ret = get_file_int("/sys/devices/intel_pt/type");
  if(ret <= 0) {
    INFO_MSG("Intel PT not supported");
    return -1;
  }
  state->intel_pt_type = ret;

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

//There's no syscall definition in libc for perf_event_open, so we'll define our own
static long perf_event_open(struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
  return syscall(__NR_perf_event_open, hw_event, (uintptr_t)pid, (uintptr_t)cpu, (uintptr_t)group_fd, (uintptr_t)flags);
}

static int setup_ipt(linux_ipt_state_t * state, pid_t pid)
{
  struct perf_event_attr pe;
  char filter[256];
  struct stat statbuf;
  size_t size;

  memset(&pe, 0, sizeof(struct perf_event_attr));
  pe.size = sizeof(struct perf_event_attr);
  pe.config = (1U << 11); // Disable RET compression, makes parsing easier
  pe.disabled = 0;
  pe.enable_on_exec = 0;
  pe.exclude_hv = 1;
  pe.exclude_kernel = 1;
  pe.type = state->intel_pt_type;

  state->perf_fd = perf_event_open(&pe, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
  if(state->perf_fd < 0) {
    ERROR_MSG("perf_event_open failed!");
    return 1;
  }

  if(!state->target_path_filter_size) {
    if(stat(state->target_path, &statbuf)) {
      ERROR_MSG("Couldn't get size of target executable (%s)", state->target_path);
      return 1;
    }
    state->target_path_filter_size = statbuf.st_size;
    if(state->target_path_filter_size != size % 0x1000)
      state->target_path_filter_size = (((size + 0x1000) / 0x1000) * 0x1000);
  }

  //See https://elixir.bootlin.com/linux/v4.17.8/source/kernel/events/core.c#L8806 for the filter format
  //start is autodetected by the kernel
  snprintf(filter, sizeof(filter), "filter 0/%ld@%s", state->target_path_filter_size, state->target_path);
  IPT_DEBUG_MSG("Using filter: %s", filter);
  if(ioctl(state->perf_fd, PERF_EVENT_IOC_SET_FILTER, filter)) {
    ERROR_MSG("perf filter failed! (errno %d: %s)", errno, strerror(errno));
    return 1;
  }

  state->pem = mmap(NULL, PERF_MMAP_SIZE + getpagesize(), PROT_READ|PROT_WRITE, MAP_SHARED, state->perf_fd, 0);
  if(state->pem == MAP_FAILED) {
    ERROR_MSG("Perf mmap failed\n");
    return 1;
  }

  state->pem->aux_offset = state->pem->data_offset + state->pem->data_size;
  state->pem->aux_size = PERF_MMAP_SIZE;
  state->perf_aux_buf = mmap(NULL, state->pem->aux_size, PROT_READ, MAP_SHARED, state->perf_fd, state->pem->aux_offset);
  if(state->perf_aux_buf == MAP_FAILED) {
    ERROR_MSG("Perf mmap failed\n");
    return 1;
  }
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
  if(!linux_ipt_state)
    return NULL;
  memset(linux_ipt_state, 0, sizeof(linux_ipt_state_t));

  if(get_ipt_system_info(linux_ipt_state)) {
    linux_ipt_cleanup(linux_ipt_state);
    return NULL;
  }

  linux_ipt_state->ipt_hashes.tip = XXH64_createState();
  linux_ipt_state->ipt_hashes.tnt = XXH64_createState();
  if(!linux_ipt_state->ipt_hashes.tip || !linux_ipt_state->ipt_hashes.tnt) {
    linux_ipt_cleanup(linux_ipt_state);
    return NULL;
  }

  if(state && linux_ipt_set_state(linux_ipt_state, state))
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
  fork_server_exit(&state->fs);

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
  if(!state)
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

  if(create_target_process(state, cmd_line, input, input_length))
    return -1;
  state->process_finished = 0;
  state->fuzz_results_set = 0;

  if(setup_ipt(state, state->child_pid))
    return -1;

  if(fork_server_run(&state->fs))
    return -1;

  *process = state->child_pid;
  return 0;
}

int linux_ipt_is_new_path(void * instrumentation_state)
{
  linux_ipt_state_t * state = (linux_ipt_state_t *)instrumentation_state;

  //If we haven't cleaned up the IPT state, then it must not have been
  if(state->perf_fd >= 0) { //analyzed.  Analyze it now and cleanup the IPT state
    state->last_is_new_path = analyze_ipt(state);
    cleanup_ipt(state);
  }
  return state->last_is_new_path;
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

  if(!state->fuzz_results_set) {
    //if it's still alive, it's a hang
    if(!linux_ipt_is_process_done(state)) {
      destroy_target_process(state);
      state->last_fuzz_result = FUZZ_HANG;
      return state->last_fuzz_result;
    }
    //If it died from a signal (and it wasn't SIGKILL, that we send), it's a crash
    else if(WIFSIGNALED(state->last_status) && WTERMSIG(state->last_status) != SIGKILL)
      state->last_fuzz_result = FUZZ_CRASH;
    //Otherwise, just set FUZZ_NONE
    else
      state->last_fuzz_result = FUZZ_NONE;
    state->fuzz_results_set = 1;
  }

  return state->last_fuzz_result;
}

/**
 * Checks if the target process is done fuzzing the inputs yet.  If it has finished, it will have
 * written last_status, the result of the fuzz job.
 *
 * @param state - The dynamorio_state_t object containing this instrumentation's state
 * @return - 0 if the process is not done testing the fuzzed input, non-zero if the process is done.
 */
int linux_ipt_is_process_done(void * instrumentation_state)
{
  int status;
  linux_ipt_state_t * state = (linux_ipt_state_t *)instrumentation_state;

  if(state->process_finished)
    return 1;

  status = fork_server_get_status(&state->fs, 0);
  //it's still alive or an error occurred and we can't tell
  if(status < 0 || status == FORKSERVER_NO_RESULTS_READY)
    return 0;
  state->last_status = status;
  state->process_finished = 1;
  return 1;
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

