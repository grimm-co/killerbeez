#include <stdio.h>     // fprintf
#include <signal.h>    // for pid_t
#include <stdint.h>    // uint*_t
#include <string.h>  // for memset, strdup
#include <sys/wait.h>  // for waitpid

#include "forkserver_internal.h"

/**** BEGIN DEFINES TAKEN FROM AFL (APLv2 LICENSE) ****/
// Use the standard 16-bit map size from AFL
#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)
/* Environment variable used to pass SHM ID to the called program. */
#define SHM_ENV_VAR         "__AFL_SHM_ID"

#define ALLOC_OFF_HEAD  8
#define ALLOC_OFF_TOTAL (ALLOC_OFF_HEAD + 1)

/* Maximum allocator request size (keep well under INT_MAX): */
#define MAX_ALLOC           0x40000000

/* Magic tokens used to mark used / freed chunks. */
#define ALLOC_MAGIC_C1  0xFF00FF00 /* Used head (dword)  */
#define ALLOC_MAGIC_F   0xFE00FE00 /* Freed head (dword) */
#define ALLOC_MAGIC_C2  0xF0       /* Used tail (byte)   */
/* Positions of guard tokens in relation to the user-visible pointer. */
#define ALLOC_C1(_ptr)  (((uint32_t*)(_ptr))[-2])
#define ALLOC_S(_ptr)   (((uint32_t*)(_ptr))[-1])
#define ALLOC_C2(_ptr)  (((unsigned char*)(_ptr))[ALLOC_S(_ptr)])

/* Just print stuff to the appropriate stream. */
#ifdef MESSAGES_TO_STDOUT
#  define SAYF(x...)    printf(x)
#else
#  define SAYF(x...)    fprintf(stderr, x)
#endif /* ^MESSAGES_TO_STDOUT */

#define ABORT(x...) do { \
    SAYF("\n[-] PROGRAM ABORT : " x); \
    SAYF("\n    Stop location : " "%s(), %s:%u\n\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    abort(); \
  } while (0)

#define ALLOC_CHECK_SIZE(_s) do { \
    if ((_s) > MAX_ALLOC) \
      ABORT("Bad alloc request: %u bytes", (_s)); \
  } while (0)

#define ALLOC_CHECK_RESULT(_r, _s) do { \
    if (!(_r)) \
      ABORT("Out of memory: can't allocate %u bytes", (_s)); \
  } while (0)

static inline void* DFL_ck_alloc_nozero(uint32_t size) {
  void* ret;
  if (!size) return NULL;
  ALLOC_CHECK_SIZE(size);
  ret = malloc(size + ALLOC_OFF_TOTAL);
  ALLOC_CHECK_RESULT(ret, size);
  ret += ALLOC_OFF_HEAD;
  ALLOC_C1(ret) = ALLOC_MAGIC_C1;
  ALLOC_S(ret)  = size;
  ALLOC_C2(ret) = ALLOC_MAGIC_C2;
  return ret;
}
#define ck_alloc_nozero   DFL_ck_alloc_nozero

/* Allocate a buffer, returning zeroed memory. */
static inline void* DFL_ck_alloc(uint32_t size) {
  void* mem;
  if (!size) return NULL;
  mem = DFL_ck_alloc_nozero(size);
  return memset(mem, 0, size);
}
#define ck_alloc          DFL_ck_alloc

#define alloc_printf(_str...) ({ \
    uint8_t* _tmp; \
    int32_t _len = snprintf(NULL, 0, _str); \
    if (_len < 0) FATAL_MSG("Whoa, snprintf() fails?!"); \
    _tmp = ck_alloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })

#define CHECK_PTR(_p) do { \
    if (_p) { \
      if (ALLOC_C1(_p) ^ ALLOC_MAGIC_C1) {\
        if (ALLOC_C1(_p) == ALLOC_MAGIC_F) \
          ABORT("Use after free."); \
        else ABORT("Corrupted head alloc canary."); \
      } \
      if (ALLOC_C2(_p) ^ ALLOC_MAGIC_C2) \
        ABORT("Corrupted tail alloc canary."); \
    } \
  } while (0)

static inline void DFL_ck_free(void* mem) {
  if(!mem) return;
  CHECK_PTR(mem);
#ifdef DEBUG_BUILD
  /* Catch pointer issues sooner. */
  memset(mem, 0xFF, ALLOC_S(mem));
#endif /* DEBUG_BUILD */
  ALLOC_C1(mem) = ALLOC_MAGIC_F;
  free(mem - ALLOC_OFF_HEAD);
}

#define ck_free           DFL_ck_free

#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */
static const uint8_t simplify_lookup[256] = {
  [0]         = 1,
  [1 ... 255] = 128
};

/**** END DEFINES TAKEN FROM AFL (APLv2 LICENSE) ****/


struct afl_state {
	char *target_path;
	pid_t child_pid;
	forkserver_t fs;
	int process_finished;
	int last_fuzz_result;
	int fuzz_results_set;  // have we set the fuzz results?
	int last_status;  // the last input did what? (CRASH, HANG, NONE, etc.)
	int last_is_new_path;  // did the last input hit a new code path?
	int use_fork_server;
	int fork_server_setup;
	int persistence_max_cnt;
	uint8_t *input_bitmap;
	uint8_t virgin_bits[MAP_SIZE];  // Regions yet untouched by fuzzing
	uint8_t virgin_tmout[MAP_SIZE]; // Bits we haven't seen in tmouts
	uint8_t virgin_crash[MAP_SIZE]; // Bits we haven't seen in crashes
	uint8_t *trace_bits;            // SHM with instrumentation bitmap
};
typedef struct afl_state afl_state_t;

void * afl_create(char *options, char *state);
void afl_cleanup(void *instrumentation_state);
char * afl_get_state(void *instrumentation_state);
void afl_free_state(char *state);
int afl_set_state(void *instrumentation_state, char *state);
void * afl_merge(void *instrumentation_state, void *other_instrumentation_state);
int afl_enable(void *instrumentation_state, pid_t *process, char *cmd_line,
		char *input, size_t input_length);
int afl_is_new_path(void *instrumentation_state);
int afl_get_fuzz_result(void *instrumentation_state);
int afl_is_process_done(void *instrumentation_state);
int afl_help(char **help_str);

static afl_state_t * setup_options(char *options);
static void destroy_target_process(afl_state_t * state);
static int create_target_process(afl_state_t * state, char* cmd_line,
			char * input, size_t input_length);
int setup_shm(void *instrumentation_state);
static void remove_shm();
#ifdef __x86_64__
static void simplify_trace(uint64_t* mem);
#else
static void simplify_trace(uint32_t* mem);
#endif /* ^__x86_64__ */
static inline uint8_t has_new_bits(uint8_t* virgin_map, uint8_t *trace_bits);
static int finish_fuzz_round(afl_state_t *state);
