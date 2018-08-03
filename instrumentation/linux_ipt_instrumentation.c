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
#include "forkserver_internal.h"
#include "uthash.h"
#include "xxhash.h"

#include <utils.h>
#include <jansson_helper.h>

////////////////////////////////////////////////////////////////
// IPT Packet Analyzer /////////////////////////////////////////
////////////////////////////////////////////////////////////////

//Uncomment this #define to make the IPT parser print each packet and parser details
//#define IPT_DEBUG

#ifdef IPT_DEBUG
//Prints each IPT packet and the packet bytes
#define IPT_DEBUG_MSG_PACKET(...) DEBUG_MSG(__VA_ARGS__)
//Prints status messages about the parser
#define IPT_DEBUG_MSG(...)        DEBUG_MSG(__VA_ARGS__)
#else
#define IPT_DEBUG_MSG_PACKET(...)
#define IPT_DEBUG_MSG(...)
#endif

#define BYTES_LEFT(num)    ((end - p) >= (num))
#define BIT_TEST(num, bit) ((num) & (1 << (bit)))

/**
 * This function sign extends a number
 * @param num - the number to sign extend
 * @param sign_bit - which bit in num is the value's current sign bit
 * @return - the sign extended number
 */
static uint64_t sign_extend(uint64_t num, uint8_t sign_bit)
{
  uint64_t mask = ~0ULL << sign_bit;
  return num & (1ULL << (sign_bit - 1)) ? num | mask : num & ~mask;
}

/**
 * This function parsers an IPT TIP/FUP packet and obtains the IP address that it refers to
 * @param outp - The position of the TIP/FUP packet bytes in the IPT packet buffer.  This pointer will
 * be updated to point after the parsed TIP/FUP packet.
 * @param end - The end of the IPT packet buffer.  Used to ensure, we don't read past the end
 * @param last_ip - The IP address that was in the most recent TIP/FUP packet. This value will be
 * updated with the IP address from the parsed packet.
 * @return - the IP address from the TIP/FUP packet.
 */
static uint64_t handle_ip_packet(unsigned char ** outp, unsigned char *end, uint64_t *last_ip)
{
  unsigned char *p = *outp;
  uint64_t new_ip;
  int num_bytes;
  uint64_t new_bytes;

  int ip_bytes = p[0] >> 5;

  if (ip_bytes == 0) //IP is out of context
    return 0;
  else if(ip_bytes == 1) { //Bottom 32 bits, last_ip top 48
    num_bytes = 2;
    new_bytes = *((uint64_t *)(p+1)) & 0xFFFFULL;
    new_ip = (*last_ip & (0xFFFFFFFFFFFFULL << 16)) | new_bytes;
  } else if(ip_bytes == 2) { //Bottom 32 bits, last_ip top 32
    num_bytes = 4;
    new_bytes = *((uint64_t *)(p+1)) & 0xFFFFFFFFULL;
    new_ip = (*last_ip & (0xFFFFFFFFULL << 32)) | new_bytes;
  } else if(ip_bytes == 3) { //Bottom 48 bits, sign extended
    num_bytes = 6;
    new_bytes = *((uint64_t *)(p+1)) & 0xFFFFFFFFFFFFULL;
    new_ip = sign_extend(new_bytes, 48);
  } else if(ip_bytes == 4) { //Bottom 48 bits, last_ip top 16
    num_bytes = 6;
    new_bytes = *((uint64_t *)(p+1)) & 0xFFFFFFFFFFFFULL;
    new_ip = (*last_ip & (0xFFFFULL << 48)) | new_bytes;
  } else if(ip_bytes == 6) { //All 64 bits
    num_bytes = 8;
    new_ip = *((uint64_t *)(p+1));
  } else {
    WARNING_MSG("Got unknown IP packet (IPBytes=%d)", ip_bytes);
    return 0;
  }

  if (!BYTES_LEFT(num_bytes)) {
    WARNING_MSG("Got error in handle_ip_packet: Not enough bytes for decoding IP (have %lu, need %lu)", end-p, ip_bytes);
    return 0;
  }

  *outp = p + num_bytes;
  *last_ip = new_ip;
  return new_ip;
}

/**
 * This function adds any remaining TNT packet bits to the TNT hash being recorded
 * @param ipt_hashes - A pointer to the hash structure with the TNT hash to update
 */
static void finish_tnt_hash(struct ipt_hash_state * ipt_hashes)
{
  if(ipt_hashes->num_bits != 0) {
    if(XXH64_update(ipt_hashes->tnt, &ipt_hashes->tnt_bits, sizeof(uint64_t)) == XXH_ERROR)
      WARNING_MSG("Updating the TNT hash failed!"); //Should never happen
  }
  //Add in the total number of bits, so we can differentiate between a packet with TNN and a packet with TN
  if(XXH64_update(ipt_hashes->tnt, &ipt_hashes->total_num_bits, sizeof(uint64_t)) == XXH_ERROR)
    WARNING_MSG("Updating the TNT hash failed!"); //Should never happen
}

/**
 * This function adds TNT packet bits to the TNT hash being recorded
 * @param ipt_hashes - A pointer to the hash structure with the TNT hash to update
 * @param tnt_bits - the TNT bits to add to the hash
 * @param num_bits - the number of bits in the tnt_bits parameter
 */
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
  ipt_hashes->total_num_bits += num_bits;
}

/**
 * This function adds a TIP packet's IP address to the TIP hash being recorded
 * @param state - The linux_ipt_state_t object containing this instrumentation's state
 * @param tip - the IP address to add to the TIP hash
 */
static void add_tip_to_hash(linux_ipt_state_t * state, uint64_t tip)
{
  uint64_t adjusted_address = tip;
  int i;
  long index = -1;

  IPT_DEBUG_MSG("TIP %lx", tip);

  //Adjust the reported address to remove ASLR
  if(state->num_coverage_libraries) {
    for(i = 0; i < state->num_coverage_libraries; i++) {
      if(state->library_starts[i] <= tip && tip < state->library_ends[i]) {
        index = i;
        break;
      }
    }

    //Normalize the address, then mix in the hash of the library to ensure there are not collisions
    //when two separate libraries report a TIP at the same offset
    if(index != -1)
      adjusted_address = (tip - state->library_starts[i]) | (((uint64_t)state->library_hashes[i]) << 32);
  } else if(state->target_start <= tip && tip < state->target_end) //if the address is in the target executable
    adjusted_address = tip - state->target_start; //normalize the address with the target's start address

  if(XXH64_update(state->ipt_hashes.tip, &adjusted_address, sizeof(uint64_t)) == XXH_ERROR)
    WARNING_MSG("Updating the TIP hash failed!"); //Should never happen
}

/**
 * This function determines how many bits are in a TNT packet
 * @param packet - A pointer to the IPT packet buffer
 * @param max - the maximum possible bits that could be in a packet
 */
static int get_tnt_num_bits(unsigned char * packet, int max_bits)
{
  int num_bits;
  for(num_bits = max_bits; num_bits >= 0; num_bits--) { //Find the stop bit
    if(BIT_TEST(packet[num_bits / 8], num_bits % 8))
      break;
  }
  return num_bits;
}

/**
 * This function parses the IPT packet buffer to determine if the execution trace was new or not.  If it was, the
 * execution trace's hash is added to the hashtable to ensure we do not mark it as new again.
 * @param state - The linux_ipt_state_t object containing this instrumentation's state
 * @param return - -1 on error, 0 if the IPT packets in the IPT packet buffer don't describe a unique run, or 1 if they do
 */
static int analyze_ipt(linux_ipt_state_t * state)
{
  unsigned char * p, * start, * end, * psb_pos;
  struct ipt_hashtable_entry * hashes, * match = NULL;
  uint64_t ip_address;
  size_t num_bytes_at_end;
  int unknown_packet_hit = 0;

  const unsigned char psb[0x10] = {
    0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
    0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82
  };

  //Disable IPT while we're analyzing it
  ioctl(state->perf_fd, PERF_EVENT_IOC_DISABLE, 0);

  //Perform a quick sanity check to ensure the IPT trace data is sane
  if (state->pem->aux_head == state->pem->aux_tail) {
    WARNING_MSG("No IPT trace data was recorded, something is likely wrong.");
    return -1;
  } else if (state->persistence_max_cnt == 0 && state->pem->aux_head < state->pem->aux_tail) {
    WARNING_MSG("The IPT trace data has overflown. Use the ipt_mmap_size option to increase the size.");
    return -1;
  }

  //Reset the IPT hashes struct
  state->ipt_hashes.tnt_bits = 0;
  state->ipt_hashes.num_bits = 0;
  state->ipt_hashes.total_num_bits = 0;
  if(XXH64_reset(state->ipt_hashes.tnt, 0) == XXH_ERROR ||
      XXH64_reset(state->ipt_hashes.tip, 0) == XXH_ERROR)
    return -1;

  hashes = malloc(sizeof(struct ipt_hashtable_entry));
  if(!hashes)
    return -1;

  //Reorder the buffer if it wrapped around to make parsing easier
  if(state->pem->aux_head < state->pem->aux_tail) {
    state->reorder_buffer = malloc(state->ipt_mmap_size);
    num_bytes_at_end = state->pem->aux_size - state->pem->aux_tail;
    memcpy(state->reorder_buffer, state->perf_aux_buf + state->pem->aux_tail, num_bytes_at_end);
    memcpy(state->reorder_buffer + num_bytes_at_end, state->perf_aux_buf, state->pem->aux_head);

    start = state->reorder_buffer;
    end = state->reorder_buffer + num_bytes_at_end + state->pem->aux_head;
  } else {
    start = (char *)state->perf_aux_buf + state->pem->aux_tail;
    end = (char *)state->perf_aux_buf + state->pem->aux_head;
  }
  p = start;

#ifdef IPT_DEBUG
  write_buffer_to_file("/tmp/ipt_dump", start, end-start);
#endif

  //Rather than use Intel's libipt, we instead parse the buffer ourselves to ensure we can do so
  //quickly.  As we only need the TIP/TNT packets, this parser attempts to parse as little else
  //as possible.  Further, we only record hashes of the TIP/TNT packets, as full decoding of the
  //IPT packets to match them to the basic blocks transitions is far too slow.
  while(p < end) {

    if(unknown_packet_hit) {
      psb_pos = memmem(p, end - p, psb, sizeof(psb));
      if(!psb_pos) {
        DEBUG_MSG("Couldn't find PSB packet");
        break;
      }
      if(psb_pos - p != 0)
        IPT_DEBUG_MSG("Skipping %d bytes", psb_pos - p);
      p = psb_pos + sizeof(psb);
      state->last_ip = 0;
      unknown_packet_hit = 0;
    }

    while(p < end)
    {
      IPT_DEBUG_MSG_PACKET("%04x: %02x %02x %02x %02x %02x %02x %02x %02x", p - start,
          (unsigned char)p[0], (unsigned char)p[1], (unsigned char)p[2], (unsigned char)p[3],
          (unsigned char)p[4], (unsigned char)p[5], (unsigned char)p[6], (unsigned char)p[7]);

      if (p[0] == 2 && BYTES_LEFT(2)) {
        if (p[1] == 0xa3 && BYTES_LEFT(8)) { // Long TNT
          IPT_DEBUG_MSG_PACKET("Long TNT");
          add_tnt_to_hash(&state->ipt_hashes, p+2, get_tnt_num_bits(p+2, 47));
          p += 8;
          continue;
        }
        if (p[1] == 0x43 && BYTES_LEFT(8)) { // PIP
          IPT_DEBUG_MSG_PACKET("PIP");
          p += 8;
          continue;
        }
        if (p[1] == 3 && BYTES_LEFT(4)) { // CBR
          IPT_DEBUG_MSG_PACKET("CBR");
          p += 4;
          continue;
        }
        if (p[1] == 0x83) { //TRACESTOP
          IPT_DEBUG_MSG_PACKET("TRACESTOP");
          p += 2;
          continue;
        }
        if (p[1] == 0xf3 && BYTES_LEFT(8)) { // OVF
          p += 8;
          WARNING_MSG("IPT received overflow packet");
          continue;
        }
        if (p[1] == 0x82 && BYTES_LEFT(16) && !memcmp(p, psb, 16)) { // PSB
          IPT_DEBUG_MSG_PACKET("PSB");
          p += 16;
          state->last_ip = 0;
          continue;
        }
        if (p[1] == 0x23) { // PSBEND
          IPT_DEBUG_MSG_PACKET("PSBEND");
          p += 2;
          continue;
        }
        if (p[1] == 0xc3 && BYTES_LEFT(11) && p[2] == 0x88) { //MNT
          IPT_DEBUG_MSG_PACKET("MNT");
          p += 10;
          continue;
        }
        if (p[1] == 0x73 && BYTES_LEFT(7)) { //TMA
          IPT_DEBUG_MSG_PACKET("TMA");
          p += 7;
          continue;
        }
        if (p[1] == 0xc8 && BYTES_LEFT(7)) { //VMCS
          IPT_DEBUG_MSG_PACKET("VMCS");
          p += 7;
          continue;
        }
      }

      if(!(p[0] & 1)) {
        if (p[0] == 0) { // PAD
          IPT_DEBUG_MSG_PACKET("PAD");
          p++;
          continue;
        }

        // Short TNT
        char tnt_bits = p[0] >> 1;
        add_tnt_to_hash(&state->ipt_hashes, &tnt_bits, get_tnt_num_bits(&tnt_bits, 6));
        IPT_DEBUG_MSG_PACKET("SHORT TNT");
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
        ip_address = handle_ip_packet(&p, end, &state->last_ip);
        IPT_DEBUG_MSG_PACKET("TIP/PGE/PGD/FUP");
        if(tip_type == TIP_TYPE_TIP)
          add_tip_to_hash(state, ip_address);
        p++;
        continue;
      }

      if (p[0] == 0x99 && BYTES_LEFT(2)) { // MODE
        IPT_DEBUG_MSG_PACKET("MODE");
        p += 2;
        continue;
      }

      if (p[0] == 0x19 && BYTES_LEFT(8)) { // TSC
        IPT_DEBUG_MSG_PACKET("TSC");
        p+=8;
        continue;
      }
      if (p[0] == 0x59 && BYTES_LEFT(2)) { // MTC
        IPT_DEBUG_MSG_PACKET("MTC");
        p += 2;
        continue;
      }
      if ((p[0] & 3) == 3) { // CYC
        IPT_DEBUG_MSG_PACKET("CYC");
        if ((p[0] & 4) && BYTES_LEFT(1)) {
          do {
            p++;
          } while ((p[0] & 1) && BYTES_LEFT(1));
        }
        p++;
        continue;
      }

      WARNING_MSG("Hit unknown packet type at offset 0x%lx", p - start);
      unknown_packet_hit = 1;
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

/**
 * This function wraps the perf_event_open syscall, which does not have one in libc
 */
static long perf_event_open(struct perf_event_attr* hw_event, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
  return syscall(__NR_perf_event_open, hw_event, (uintptr_t)pid, (uintptr_t)cpu, (uintptr_t)group_fd, (uintptr_t)flags);
}

/**
 * This function cleans up the IPT related file descriptor and memory mappings
 * @param state - The linux_ipt_state_t object containing this instrumentation's state
 */
static void cleanup_ipt(linux_ipt_state_t * state)
{
  if(state->perf_aux_buf && state->perf_aux_buf != MAP_FAILED && state->pem && state->pem != MAP_FAILED) {
    munmap(state->perf_aux_buf, state->pem->aux_size);
    state->perf_aux_buf = NULL;
    munmap(state->pem, state->ipt_mmap_size + getpagesize());
    state->pem = NULL;
  }
  if(state->perf_fd >= 0)
    close(state->perf_fd);
  state->perf_fd = -1;
}

/**
 * This function determines the size used in an IPT filter for the specified filename.
 * @param filename - the filename determine the IPT filter size for
 * @return - the size that should be specified in an IPT filter for the given filename
 */
static size_t get_file_filter_size(char * filename)
{
  struct stat statbuf;
  size_t pagesize = getpagesize();
  size_t ret;

  if(stat(filename, &statbuf))
    FATAL_MSG("Couldn't get size of \"%s\"", filename);

  ret = statbuf.st_size;
  if(ret % pagesize != 0)
    ret = (((ret + pagesize) / pagesize) * pagesize);
  return ret;
}

/**
 * This function creates an IPT filter for the the coverage libraries specified in a linux_ipt_state
 * @param state - The linux_ipt_state_t object containing this instrumentation's state
 * @return - an IPT filter that can be passed to the Linux perf subsystem, which will instruction IPT to only
 * generate IPT packets for the regions defined in the linux_ipt_state.
 */
static char * create_ipt_filter(linux_ipt_state_t * state)
{
  char item_filter[1000], filter[4096];
  size_t i;

  //See https://elixir.bootlin.com/linux/v4.17.8/source/kernel/events/core.c#L8806 for the filter format
  //start is autodetected by the kernel
  memset(filter, 0, sizeof(filter));
  if(state->num_coverage_libraries) {
    for(i = 0; i < state->num_coverage_libraries; i++) {
      snprintf(item_filter, sizeof(item_filter), "filter 0/%ld@%s%s", get_file_filter_size(state->coverage_libraries[i]),
        state->coverage_libraries[i], i != state->num_coverage_libraries - 1 ? "\n" : "");
      strncat(filter, item_filter, sizeof(filter) - (strlen(filter) + 1));
    }
  } else
    snprintf(filter, sizeof(filter), "filter 0/%ld@%s", get_file_filter_size(state->target_path), state->target_path);

  IPT_DEBUG_MSG("Using filter: %s", filter);
  return strdup(filter);
}

/**
 * This function sets up IPT tracing for the specified process
 * @param state - The linux_ipt_state_t object containing this instrumentation's state
 * @param pid - The process ID of the process to trace
 * @return - 0 on success, non-zero on failure
 */
static int setup_ipt(linux_ipt_state_t * state, pid_t pid)
{
  struct perf_event_attr pe;

  state->last_ip = 0;

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
    ERROR_MSG("Could not open the perf event file system (perf_event_open failed with errno %d (%s))", errno, strerror(errno));
    ERROR_MSG("Try adjusting the perf system permissions with: echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid");
    return 1;
  }

  if(!state->filter)
    state->filter = create_ipt_filter(state);
  if(ioctl(state->perf_fd, PERF_EVENT_IOC_SET_FILTER, state->filter)) {
    ERROR_MSG("perf filter failed! (errno %d: %s)", errno, strerror(errno));
    return 1;
  }

  state->pem = mmap(NULL, state->ipt_mmap_size + getpagesize(), PROT_READ|PROT_WRITE, MAP_SHARED, state->perf_fd, 0);
  if(state->pem == MAP_FAILED) {
    ERROR_MSG("Perf mmap failed (ipt_mmap_size=%d)\n", state->ipt_mmap_size);
    return 1;
  }

  state->pem->aux_offset = state->pem->data_offset + state->pem->data_size;
  state->pem->aux_size = state->ipt_mmap_size;
  state->perf_aux_buf = mmap(NULL, state->pem->aux_size, PROT_READ, MAP_SHARED, state->perf_fd, state->pem->aux_offset);
  if(state->perf_aux_buf == MAP_FAILED) {
    ERROR_MSG("Perf AUX mmap failed (ipt_mmap_size=%d)\n", state->ipt_mmap_size);
    return 1;
  }
  return 0;
}

/**
 * This function records the address information for the traced libraries or executable
 * inside of the fork server (which will have the same addresses as all target processes).
 * @param state - The linux_ipt_state_t object containing this instrumentation's state
 */
static void record_fork_server_address_info(linux_ipt_state_t * state)
{
  char filename[64], line[1024+MAX_PATH], map_filename[MAX_PATH], last_filename[MAX_PATH];
  FILE * fp;
  uint64_t start, end;
  int count, index, file_len;
  size_t i;
  char * file_buffer;
  XXH32_state_t * hash;

  //Allocate the library start/end arrays
  if(state->num_coverage_libraries) {
    state->library_starts = calloc(state->num_coverage_libraries, sizeof(uint64_t));
    state->library_ends = calloc(state->num_coverage_libraries, sizeof(uint64_t));
    state->library_hashes = calloc(state->num_coverage_libraries, sizeof(uint32_t));
    if(!state->library_starts || !state->library_ends || !state->library_hashes)
      FATAL_MSG("Failed allocating memory for library address ranges and hashes");
  }

  //Open /proc/$pid/maps
  snprintf(filename, sizeof(filename), "/proc/%d/maps", state->fs.pid);
  fp = fopen(filename, "r");
  if(!fp)
    FATAL_MSG("Failed to open the fork server's maps file (%s)", filename);

  //Parse the maps file line by line, looking for the libraries or main executable
  while (fgets(line, sizeof(line), fp) != NULL)
  {
    memset(map_filename, 0, sizeof(map_filename));
    count = sscanf(line, "%16lx-%16lx %*4s %*8s %*s %*d %1024s\n", &start, &end, map_filename);
    if(count != 3)
      continue;
    if(state->num_coverage_libraries) {
      for(i = 0; i < state->num_coverage_libraries; i++) {
        if(strcmp(map_filename, state->coverage_libraries[i]) == 0) {
          if(state->library_starts[i] == 0)
            state->library_starts[i] = start;
          state->library_ends[i] = end;
        }
      }

    } else if(strcmp(map_filename, state->target_path) == 0) {
      if(state->target_start == 0)
        state->target_start = start;
      state->target_end = end;
    }
  }
  fclose(fp);

  //Give a warning if we weren't able to find a library's or the main executable's start/end address
  if(state->num_coverage_libraries) {
    for(i = 0; i < state->num_coverage_libraries; i++) {
      if(!state->library_starts[i] || !state->library_ends[i]) {
        WARNING_MSG("Could not determine the address of the %s library in memory.  The generated hashes will be specific to "
          "this run if ASLR is enabled.", state->coverage_libraries[i]);
        state->library_starts[i] = state->library_ends[i] = 0;
      } else {
        //Read the library
        file_len = read_file(state->coverage_libraries[i], &file_buffer);
        if(file_len < 0)
          FATAL_MSG("Couldn't open the library %s to calculate its hash", state->coverage_libraries[i]);

        //Calculate the library's hash
        hash = XXH32_createState();
        if(XXH32_reset(hash, 0) == XXH_ERROR ||
            XXH32_update(hash, file_buffer, file_len) == XXH_ERROR)
          FATAL_MSG("Failed calculating hash of library %s", state->coverage_libraries[i]); //Should never happen
        state->library_hashes[i] = XXH32_digest(hash);

        //Deallocate the hash and file contents
        XXH32_freeState(hash);
        free(file_buffer);
      }
    }

  } else if(!state->target_start || !state->target_end) {
    WARNING_MSG("Could not determine the address of the target executable in memory.  The generated hashes will be specific to "
      "this run if ASLR is enabled and the executable is PIE.");
    state->target_start = state->target_end = 0;
  }
}

/**
 * This function terminates the fuzzed process.
 * @param state - The linux_ipt_state_t object containing this instrumentation's state
 */
static void destroy_target_process(linux_ipt_state_t * state)
{
  if(state->child_pid) {
    if(!state->persistence_max_cnt) {
      kill(state->child_pid, SIGKILL);
      state->child_pid = 0;
    }
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
    fork_server_init(&state->fs, state->target_path, argv, 1, state->persistence_max_cnt, stdin_length != 0);
    record_fork_server_address_info(state);
    state->fork_server_setup = 1;
    for(i = 0; argv[i]; i++)
      free(argv[i]);
    free(argv);
  }

  pid = fork_server_fork(&state->fs);
  if(pid < 0)
    return -1;

  if(pid != state->child_pid) {
    //New target process, cleanup the old IPT state and set it up for the new target
    state->child_pid = pid;
    cleanup_ipt(state);
    if(setup_ipt(state, state->child_pid))
      return -1;
  } else {
    //Persistence mode with the same target process being used, adjust the ring buffers and reenable IPT
    __sync_synchronize(); //smp_mb()
    __atomic_store_n(&state->pem->aux_tail, state->pem->aux_head, __ATOMIC_SEQ_CST);
    ioctl(state->perf_fd, PERF_EVENT_IOC_ENABLE, 0);
  }

  //Take care of the stdin input, write over the file, then truncate it accordingly
  lseek(state->fs.target_stdin, 0, SEEK_SET);
  if(stdin_input != NULL && stdin_length != 0) {
    if(write(state->fs.target_stdin, stdin_input, stdin_length) != stdin_length)
      FATAL_MSG("Short write to target's stdin file");
  }
  if(ftruncate(state->fs.target_stdin, stdin_length))
    FATAL_MSG("ftruncate() failed");
  lseek(state->fs.target_stdin, 0, SEEK_SET);
  return 0;
}

/**
 * This function reads a number from the given file
 * @param filename - the path to the file to read a number from.
 * @return - The number that was in the specified file, or -1 on error
 */
static int get_file_int(char * filename)
{
  int ret, fd;
  char buffer[16];

  fd = open(filename, O_RDONLY);
  if(fd < 0)
    return -1;

  memset(buffer, 0, sizeof(buffer));
  ret = read(fd, buffer, sizeof(buffer)-1);
  if(ret > 0)
    ret = atoi(buffer);
  else
    ret = -1;
  close(fd);
  return ret;
}

/**
 * This function reads the Intel PT state of the current processor from the sys filesystem
 * @param state - The linux_ipt_state_t object containing this instrumentation's state
 * @return - 0 on success, non-zero if IPT or IP address filtering are not supported
 */
static int get_ipt_system_info(linux_ipt_state_t * state)
{
  int ret;

  if(access("/sys/devices/intel_pt/", F_OK)) {
    INFO_MSG("Intel PT not supported (/sys/devices/intel_pt/ does not exist)");
    return -1;
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
  if(ret < state->num_coverage_libraries) {
    INFO_MSG("Too many coverage libraries specified. Intel PT address filtering on "
      "this system only supports %d, but %d were specified.", ret, state->num_coverage_libraries);
    return -1;
  }
  state->num_address_ranges = ret;

  return 0;
}

////////////////////////////////////////////////////////////////
// Instrumentation methods /////////////////////////////////////
////////////////////////////////////////////////////////////////

/**
 * This function creates a linux_ipt_state_t object based on the given options.
 * @param options - A JSON string of the options to set in the new linux_ipt_state_t. See the
 * help function for more information on the specific options available.
 * @return the linux_ipt_state_t generated from the options in the JSON options string, or NULL on failure
 */
static linux_ipt_state_t * setup_options(char * options)
{
  linux_ipt_state_t * state;
  size_t i;
  size_t pagesize = getpagesize();

  state = malloc(sizeof(linux_ipt_state_t));
  if(!state)
    return NULL;
  memset(state, 0, sizeof(linux_ipt_state_t));

  //Setup defaults
  state->ipt_mmap_size = 1024*1024; //1MB

  //Parse the options
  if(options) {
    PARSE_OPTION_INT(state, options, persistence_max_cnt, "persistence_max_cnt", linux_ipt_cleanup);
    PARSE_OPTION_INT(state, options, ipt_mmap_size, "ipt_mmap_size", linux_ipt_cleanup);
    PARSE_OPTION_ARRAY(state, options, coverage_libraries, num_coverage_libraries, "coverage_libraries", linux_ipt_cleanup);
  }

  for(i = 0; i < state->num_coverage_libraries; i++) {
    if(!file_exists(state->coverage_libraries[i])) {
      ERROR_MSG("Could not access the specified coverage library \"%s\" does not exist", state->coverage_libraries[i]);
      linux_ipt_cleanup(state);
      return NULL;
    }
  }

  //Fix up the IPT mmap size if it's not page aligned
  if(state->ipt_mmap_size % pagesize != 0)
    state->ipt_mmap_size = (((state->ipt_mmap_size + pagesize) / pagesize) * pagesize);

  //If we're in persistence mode, allocate the reorder buffer
  if(state->persistence_max_cnt) {
    state->reorder_buffer = malloc(state->ipt_mmap_size);
    if(!state->reorder_buffer) {
      linux_ipt_cleanup(state);
      return NULL;
    }
  }

  return state;
}

/**
 * This function allocates and initializes a new instrumentation specific state object based on the given options.
 * @param options - a JSON string that contains the instrumentation specific string of options
 * @param state - an instrumentation specific JSON string previously returned from linux_ipt_get_state that should be loaded
 * @return - An instrumentation specific state object on success or NULL on failure
 */
void * linux_ipt_create(char * options, char * state)
{
  linux_ipt_state_t * linux_ipt_state = setup_options(options);
  if(!linux_ipt_state)
    return NULL;

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

  if(state && linux_ipt_set_state(linux_ipt_state, state)) {
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
  struct ipt_hashtable_entry * hash, * tmp;
  size_t i;
  linux_ipt_state_t * state = (linux_ipt_state_t *)instrumentation_state;

  //Kill any remaining target processes
  destroy_target_process(state);

  //Cleanup the fork server
  if(state->fork_server_setup) {
    fork_server_exit(&state->fs);
    state->fork_server_setup = 0;
  }

  //Cleanup our xxhashes
  if(state->ipt_hashes.tnt != NULL)
    XXH64_freeState(state->ipt_hashes.tip);
  if(state->ipt_hashes.tnt != NULL)
    XXH64_freeState(state->ipt_hashes.tnt);

  //Cleanup the perf IPT fd and mmaps
  cleanup_ipt(state);

  //Cleanup the hashtable entries
  HASH_ITER(hh, state->head, hash, tmp) {
    HASH_DEL(state->head, hash);
    free(hash);
  }

  for(i = 0; i < state->num_coverage_libraries; i++)
    free(state->coverage_libraries[i]);
  free(state->library_starts);
  free(state->library_ends);
  free(state->library_hashes);
  free(state->coverage_libraries);
  free(state->reorder_buffer);
  free(state->filter);
  free(state->target_path);
  free(state);
}

/**
 * This function merges the coverage information from two instrumentation states.
 * @param instrumentation_state - an instrumentation specific state object previously created by the linux_ipt_create function
 * @param other_instrumentation_state - an instrumentation specific state object previously created by the linux_ipt_create function
 * @return - An instrumentation specific state object that contains the combination of both of the passed in instrumentation states
 * on success, or NULL on failure
 */
void * linux_ipt_merge(void * instrumentation_state, void * other_instrumentation_state)
{
  linux_ipt_state_t * merged;
  struct ipt_hashtable_entry * entry = NULL, * hash = NULL, * tmp = NULL, * match = NULL;
  linux_ipt_state_t * first = (linux_ipt_state_t *)instrumentation_state;
  linux_ipt_state_t * second = (linux_ipt_state_t *)other_instrumentation_state;

  merged = linux_ipt_create(NULL, NULL);
  if (!merged)
    return NULL;

  //Add the first state's entries
  HASH_ITER(hh, first->head, hash, tmp)
  {
    entry = malloc(sizeof(struct ipt_hashtable_entry));
    memset(entry, 0, sizeof(entry));
    entry->id.tip = hash->id.tip;
    entry->id.tnt = hash->id.tnt;
    HASH_ADD(hh, merged->head, id, sizeof(struct ipt_hashtable_key), entry);
  }

  //Add the second state's entries
  HASH_ITER(hh, second->head, hash, tmp)
  {
    entry = malloc(sizeof(struct ipt_hashtable_entry));
    memset(entry, 0, sizeof(entry));
    entry->id.tip = hash->id.tip;
    entry->id.tnt = hash->id.tnt;
    HASH_FIND(hh, merged->head, &entry->id, sizeof(struct ipt_hashtable_key), match);
    if(!match)
      HASH_ADD(hh, merged->head, id, sizeof(struct ipt_hashtable_key), entry);
  }

  return merged;
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
  json_t *state_obj, *hash_obj, *hash_list, *temp;
  struct ipt_hashtable_entry * hash = NULL, * tmp = NULL;
  char * ret;

  state_obj = json_object();
  if (!state_obj)
    return NULL;

  ADD_INT(temp, state->last_status, state_obj, "last_status");
  ADD_INT(temp, state->process_finished, state_obj, "process_finished");
  ADD_INT(temp, state->last_fuzz_result, state_obj, "last_fuzz_result");
  ADD_INT(temp, state->fuzz_results_set, state_obj, "fuzz_results_set");
  ADD_INT(temp, state->last_is_new_path, state_obj, "last_is_new_path");

  hash_list = json_array();
  if (!hash_list)
    return NULL;
  HASH_ITER(hh, state->head, hash, tmp)
  {
    hash_obj = json_mem((const char *)&hash->id, sizeof(struct ipt_hashtable_key));
    if (!hash_obj)
      return NULL;
    json_array_append_new(hash_list, hash_obj);
  }
  json_object_set_new(state_obj, "hash_list", hash_list);

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
  struct ipt_hashtable_entry * entry = NULL, * hash = NULL, * tmp = NULL, * match = NULL;
  json_t * hash_obj;
  int result, temp_int;
  size_t length;

  if(!state)
    return 1;

  //If a child process is running when the state is being set
  destroy_target_process(current_state); //kill it so we don't orphan it

  //Free any existing hashes already in the hashtable
  HASH_ITER(hh, current_state->head, hash, tmp) {
    HASH_DEL(current_state->head, hash);
    free(hash);
  }

  GET_INT(temp_int, state, current_state->last_status, "last_status", result);
  GET_INT(temp_int, state, current_state->process_finished, "process_finished", result);
  GET_INT(temp_int, state, current_state->last_fuzz_result, "last_fuzz_result", result);
  GET_INT(temp_int, state, current_state->fuzz_results_set, "fuzz_results_set", result);
  GET_INT(temp_int, state, current_state->last_is_new_path, "last_is_new_path", result);

  FOREACH_OBJECT_JSON_ARRAY_ITEM_BEGIN(state, hash_list, "hash_list", hash_obj, result)

    length = json_mem_length(hash_obj);
    if(length != sizeof(struct ipt_hashtable_key))
      return 1;

    entry = malloc(sizeof(struct ipt_hashtable_entry));
    if(!entry)
      return 1;

    memset(entry, 0, sizeof(entry));
    memcpy(&entry->id, json_mem_value(hash_obj), sizeof(struct ipt_hashtable_key));
    HASH_FIND(hh, current_state->head, &entry->id, sizeof(struct ipt_hashtable_key), match);
    if(!match)
      HASH_ADD(hh, current_state->head, id, sizeof(struct ipt_hashtable_key), entry);

  FOREACH_OBJECT_JSON_ARRAY_ITEM_END(hash_list)

  return 0; //No state to set, so just return success
}

/**
 * This function enables the instrumentation and runs the fuzzed process.
 * @param instrumentation_state - an instrumentation specific state object previously created by the linux_ipt_create function
 * @process - a pointer to return a handle to the process that the instrumentation was enabled on
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

  if(fork_server_run(&state->fs))
    return -1;

  *process = state->child_pid;
  return 0;
}

static int finish_fuzz_round(linux_ipt_state_t * state)
{
  if(!state->fuzz_results_set) {
    //if it's still alive, it's a hang
    if(!linux_ipt_is_process_done(state)) {
      destroy_target_process(state);
      state->last_fuzz_result = FUZZ_HANG;
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
 * This function determines whether the process being instrumented has taken a new path.  Calling this function will stop the
 * process if it is not yet finished.
 * @param instrumentation_state - an instrumentation specific state object previously created by the linux_ipt_create function
 * @return - 1 if the previously setup process (via the enable function) took a new path, 0 if it did not, or -1 on failure.
 */
int linux_ipt_is_new_path(void * instrumentation_state)
{
  linux_ipt_state_t * state = (linux_ipt_state_t *)instrumentation_state;

  //Ensure that the process has finished parsing the input (or stop it if it's not)
  finish_fuzz_round(state);

  //If we haven't cleaned up the IPT state, then it must not have been
  if(state->perf_fd >= 0) //analyzed.  Analyze it now and cleanup the IPT state
    state->last_is_new_path = analyze_ipt(state);

  return state->last_is_new_path;
}

/**
 * This function will return the result of the fuzz job. It should be called
 * after the process has finished processing the tested input.
 * @param instrumentation_state - an instrumentation specific structure previously created by the linux_ipt_create function
 * @return - either FUZZ_NONE, FUZZ_HANG, FUZZ_CRASH, or -1 on error.
 */
int linux_ipt_get_fuzz_result(void * instrumentation_state)
{
  return finish_fuzz_round((linux_ipt_state_t *)instrumentation_state);
}

/**
 * Checks if the target process is done fuzzing the inputs yet.
 * @param state - The linux_ipt_state_t object containing this instrumentation's state
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
 * This function returns help text for the Linux IPT instrumentation.
 * @param help_str - A pointer that will be updated to point to the new help string.
 * @return 0 on success and -1 on failure
 */
int linux_ipt_help(char ** help_str)
{
  *help_str = strdup(
"ipt - Linux IPT instrumentation\n"
"Options:\n"
"  persistence_max_cnt  The number of executions to run in one process while\n"
"                         fuzzing in persistence mode\n"
"  ipt_mmap_size        The amount of memory to use for the IPT trace data\n"
"                         buffer\n"
"  coverage_libraries   An array of library or executable filenames that IPT\n"
"                         should record trace information.  By default, only\n"
"                         the executable is traced.\n"
"\n"
  );
  if (*help_str == NULL)
    return -1;
  return 0;
}

