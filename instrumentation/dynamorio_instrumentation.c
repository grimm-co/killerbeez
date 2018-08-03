#define _CRT_RAND_S
#include <windows.h>
#include <Shlwapi.h>
#include <io.h>
#include <stdlib.h> 

#include "instrumentation.h"
#include "dynamorio_instrumentation.h"

#include <utils.h>
#include <jansson_helper.h>

//AFL headers
#include "winafl_config.h"
#include "winafl_hash.h"
#include "winafl_types.h"
#include "winafl_alloc_inl.h"

//#define DEBUG_TRACE_BITS

static BOOL connect_to_pipe(HANDLE pipe, char * pipe_name, DWORD timeout);
static HANDLE create_pipe(char * pipe_name, DWORD timeout);
static void cleanup_pipe(HANDLE * pipe);
static int has_new_coverage_per_module(dynamorio_state_t * state);
static int has_new_coverage(u8 * trace_bits, u8 * virgin_bits, u8 * ignore_bytes, u32 * last_shm_hash, char * dump_map_dir);

////////////////////////////////////////////////////////////////
// SHM Memory Analysis and Misc Functions //////////////////////
////////////////////////////////////////////////////////////////

/*
   The code in this section (SHM Memory Analysis and Misc Functions) was taken
   from WinAFL and falls under the following license:

   Original AFL code written by Michal Zalewski <lcamtuf@google.com>

   Windows fork written and maintained by Ivan Fratric <ifratric@google.com>

   Copyright 2016 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   The code in this section has been modified from the original to suit the
   purposes of this project.

*/


/**
 * Allocates a string and formats it based on the passed arguments.
 * @param format_string - the printf-style format string to format the allocated string with
 * @return - the newly allocated string, that should be freed with ck_free, containing the
 * formatted text.
 */
char *alloc_printf(const char *format_string, ...) {
	va_list argptr;
	char* _tmp;
	s32 _len;

	va_start(argptr, format_string);
	_len = vsnprintf(NULL, 0, format_string, argptr);
	if (_len < 0) FATAL_MSG("Whoa, snprintf() fails?!");
	_tmp = (char *)ck_alloc(_len + 1);
	vsnprintf(_tmp, _len + 1, format_string, argptr);
	va_end(argptr);
	return _tmp;
}

#define FFL(_b) (0xffULL << ((_b) << 3))
#define FF(_b)  (0xff << ((_b) << 3))

/**
 * Check if the current execution path brings anything new to the table.
 * Update virgin bits to reflect the finds. Returns 1 if the only change is
 * the hit-count for a particular tuple; 2 if there are new tuples seen.
 * Updates the map, so subsequent calls will always return 0.
 * 
 * This function is called after every exec() on a fairly large buffer, so
 * it needs to be fast. We do this in 32-bit and 64-bit flavors.
 *
 * @param trace_bits - the bitmap representing the edges hit in the last run
 * @param virgin_map - the bitmap representing the edges that have been hit so far
 * @return - 1 if the only change is hit-count, 2 if there are new edges, 0 otherwise
 */
static inline u8 has_new_bits(u8*trace_bits, u8* virgin_map) {

#ifdef __x86_64__

	u64* current = (u64*)trace_bits;
	u64* virgin = (u64*)virgin_map;

	u32  i = (MAP_SIZE >> 3);

#else

	u32* current = (u32*)trace_bits;
	u32* virgin = (u32*)virgin_map;

	u32  i = (MAP_SIZE >> 2);

#endif /* ^__x86_64__ */

	u8   ret = 0;

	while (i--) {

#ifdef __x86_64__

		u64 cur = *current;
		u64 vir = *virgin;

#else

		u32 cur = *current;
		u32 vir = *virgin;

#endif /* ^__x86_64__ */

		/* Optimize for *current == ~*virgin, since this will almost always be the
		case. */

		if (cur & vir) {

			if (ret < 2) {

				/* This trace did not have any new bytes yet; see if there's any
				current[] byte that is non-zero when virgin[] is 0xff. */

#ifdef __x86_64__

				if (((cur & FFL(0)) && (vir & FFL(0)) == FFL(0)) ||
					((cur & FFL(1)) && (vir & FFL(1)) == FFL(1)) ||
					((cur & FFL(2)) && (vir & FFL(2)) == FFL(2)) ||
					((cur & FFL(3)) && (vir & FFL(3)) == FFL(3)) ||
					((cur & FFL(4)) && (vir & FFL(4)) == FFL(4)) ||
					((cur & FFL(5)) && (vir & FFL(5)) == FFL(5)) ||
					((cur & FFL(6)) && (vir & FFL(6)) == FFL(6)) ||
					((cur & FFL(7)) && (vir & FFL(7)) == FFL(7))) ret = 2;
				else ret = 1;

#else

				if (((cur & FF(0)) && (vir & FF(0)) == FF(0)) ||
					((cur & FF(1)) && (vir & FF(1)) == FF(1)) ||
					((cur & FF(2)) && (vir & FF(2)) == FF(2)) ||
					((cur & FF(3)) && (vir & FF(3)) == FF(3))) ret = 2;
				else ret = 1;

#endif /* ^__x86_64__ */

			}

			*virgin = vir & ~cur;

		}

		current++;
		virgin++;

	}

	return ret;

}

#ifdef DEBUG_TRACE_BITS
static int first_run = 1;
#endif
/**
 * Check if the current execution path brings anything new to the table.
 * Update virgin bits to reflect the finds. Returns 1 if the only change is
 * the hit-count for a particular tuple; 2 if there are new tuples seen.
 * Updates the map, so subsequent calls will always return 0.
 *
 * This function is called after every exec() on a fairly large buffer, so
 * it needs to be fast. We do this in 32-bit and 64-bit flavors.
 *
 * This function is identical to has_new_bits, but takes an ignore_bytes bitmap
 * that lists bits that should be ignored when determining if a new edge has been found
 *
 * @param trace_bits - the bitmap representing the edges hit in the last run
 * @param virgin_map - the bitmap representing the edges that have been hit so far
 * @param ignore_bytes - a bitmap representing the edges that should be ignored when reporting
 * new edges
 * @return - 1 if the only change is hit-count, 2 if there are new edges, 0 otherwise
 */
static inline u8 has_new_bits_with_ignore(u8*trace_bits, u8* virgin_map, u8* ignore_bytes) {

	u8 ret = 0;
	u32  i = 0;

	u8 trace, virgin, ignore;
	while (i < MAP_SIZE) {
		trace = *trace_bits;
		virgin = *virgin_map;
		ignore = *ignore_bytes;

		/* Optimize for *current == ~*virgin, since this will almost always be the
		case. */
		if (!ignore && (trace & virgin)) {
			if (ret < 2) {
				/* This trace did not have any new bytes yet; see if there's any
				current[] byte that is non-zero when virgin[] is 0xff. */
				if (trace & FFL(0) && (virgin & FFL(0)) == FFL(0))
					ret = 2;
				else
					ret = 1;
			}
#ifdef DEBUG_TRACE_BITS
			if (!first_run && (trace & FFL(0) && (virgin & FFL(0)) == FFL(0)))
				printf("diff byte %d\n", i);
#endif

			*virgin_map = virgin & ~trace;
		}

		trace_bits++;
		virgin_map++;
		ignore_bytes++;
		i++;
	}
#ifdef DEBUG_TRACE_BITS
	first_run = 0;
#endif
	return ret;

}

#define AREP4(_sym)   (_sym), (_sym), (_sym), (_sym)
#define AREP8(_sym)   AREP4(_sym), AREP4(_sym)
#define AREP16(_sym)  AREP8(_sym), AREP8(_sym)
#define AREP32(_sym)  AREP16(_sym), AREP16(_sym)
#define AREP64(_sym)  AREP32(_sym), AREP32(_sym)
#define AREP128(_sym) AREP64(_sym), AREP64(_sym)

static u8 count_class_lookup[256] = {

	/* 0 - 3:       4 */ 0, 1, 2, 4,
	/* 4 - 7:      +4 */ AREP4(8),
	/* 8 - 15:     +8 */ AREP8(16),
	/* 16 - 31:   +16 */ AREP16(32),
	/* 32 - 127:  +96 */ AREP64(64), AREP32(64),
	/* 128+:     +128 */ AREP128(128)

};

#ifdef __x86_64__

/**
 * Destructively classify execution counts in a trace. This is used as a
 * preprocessing step for any newly acquired traces. Called on every exec,
 * must be fast.
 * @param mem - the bitmap which defines the edges that have been hit by a trace
 */
static inline void classify_counts(u64* mem) {

	u32 i = MAP_SIZE >> 3;

	while (i--) {

		/* Optimize for sparse bitmaps. */

		if (*mem) {

			u8* mem8 = (u8*)mem;

			mem8[0] = count_class_lookup[mem8[0]];
			mem8[1] = count_class_lookup[mem8[1]];
			mem8[2] = count_class_lookup[mem8[2]];
			mem8[3] = count_class_lookup[mem8[3]];
			mem8[4] = count_class_lookup[mem8[4]];
			mem8[5] = count_class_lookup[mem8[5]];
			mem8[6] = count_class_lookup[mem8[6]];
			mem8[7] = count_class_lookup[mem8[7]];

		}

		mem++;

	}

}

#else

/**
* Destructively classify execution counts in a trace. This is used as a
* preprocessing step for any newly acquired traces. Called on every exec,
* must be fast.
* @param mem - the bitmap which defines the edges that have been hit by a trace
*/
static inline void classify_counts(u32* mem) {

	u32 i = MAP_SIZE >> 2;

	while (i--) {

		/* Optimize for sparse bitmaps. */

		if (*mem) {

			u8* mem8 = (u8*)mem;

			mem8[0] = count_class_lookup[mem8[0]];
			mem8[1] = count_class_lookup[mem8[1]];
			mem8[2] = count_class_lookup[mem8[2]];
			mem8[3] = count_class_lookup[mem8[3]];

		}

		mem++;

	}

}

#endif /* ^__x86_64__ */

/**
 * This function merges the bitmap in src into the bitmap in dest
 * @param dest - the bitmap that will be combined with the src bitmap.
 * @param src - the bitmap that will be added to the dest bitmap
 */
void merge_bitmaps(u8 * dest, const u8 * src)
{
	size_t i;
	for (i = 0; i < MAP_SIZE; i++)
		dest[i] &= src[i];
}

////////////////////////////////////////////////////////////////
// Process and SHM Management //////////////////////////////////
////////////////////////////////////////////////////////////////

/**
 * This function cleans up the shared memory.
 * @param trace_bits - a pointer to the mapped shared memory region
 * @param shm_handle - a Windows handle to the shared memory region
 */
static void remove_shm(u8 * trace_bits, HANDLE shm_handle)
{
	if (trace_bits)
		UnmapViewOfFile(trace_bits);
	if (shm_handle)
		CloseHandle(shm_handle);
}

/**
 * This function creates and maps a shared memory region.
 * @param fuzzer_id - the id associated with this shared memory region
 * @param index - the index of the target module that this shared memory region will be associated with.
 * If this shared memory region isn't associated with a target module, -1 should be passed in.
 * @param out_trace_bits - A pointer to a pointer of memory that will be assigned to a mapped view of
 * the shared memory region
 * @param for_edges - whether the shm region is for the full edge recording or not
 * @return - a Windows handle to the shared memory region on success, or NULL on failure
 */
static HANDLE setup_shm_region(char * fuzzer_id, int index, u8 ** out_trace_bits, int for_edges)
{
	char* shm_str;
	HANDLE shm_handle;
	DWORD size;

	if (for_edges)
		size = EDGES_SHM_SIZE;
	else
		size = MAP_SIZE;

	if (index < 0)
		shm_str = (char *)alloc_printf("afl_shm_%s", fuzzer_id);
	else
		shm_str = (char *)alloc_printf("afl_shm_%s_%d", fuzzer_id, index);
	DEBUG_MSG("Setting up shm region: %s", shm_str);

	shm_handle = CreateFileMapping(
		INVALID_HANDLE_VALUE,    // use paging file
		NULL,                    // default security
		PAGE_READWRITE,          // read/write access
		0,                       // maximum object size (high-order DWORD)
		size,                    // maximum object size (low-order DWORD)
		shm_str);                // name of mapping object
	ck_free(shm_str);

	if (shm_handle == NULL) {
		if (GetLastError() != ERROR_ALREADY_EXISTS)
			FATAL_MSG("CreateFileMapping failed");
		return NULL;
	}

	*out_trace_bits = (u8 *)MapViewOfFile(
		shm_handle,          // handle to map object
		FILE_MAP_ALL_ACCESS, // read/write permission
		0,
		0,
		size
	);
	if (!*out_trace_bits)
		FATAL_MSG("MapViewOfFile() failed");
	
	return shm_handle;
}

/**
 * This function generates a fuzzer_id for use with mapping of shared memory regions and assigns
 * the fuzzer_id to state->fuzzer_id (first freeing the previous state->fuzzer_id if set).
 * @param state - The dynamorio_state_t object containing this instrumentation's state
 */
void generate_fuzzer_id(dynamorio_state_t * state)
{
	unsigned int seeds[2];

	if (state->fuzzer_id != NULL) {
		ck_free(state->fuzzer_id);
		state->fuzzer_id = NULL;
	}

	rand_s(&seeds[0]);
	rand_s(&seeds[1]);
	state->fuzzer_id = (char *)alloc_printf("%I32x%I32x", seeds[0], seeds[1]);
}

/**
 * This function configures shared memory and virgin_bits.
 * @param state - The dynamorio_state_t object containing this instrumentation's state
 * @param reset_virgin_bits - Whether the virgin bits (that define which edges have already been 
 * seen), should be reset
 */
static void setup_shm_and_pick_fuzzer_id(dynamorio_state_t * state, int reset_virgin_bits) {

	u8 attempts = 0;
	target_module_t * target_module;

	if (state->per_module_coverage)
	{
		//First pick a fuzzer id by trying to create the first shm region
		target_module = state->modules;
		while (attempts < 5 && !target_module->shm_handle) {
			attempts++;
			generate_fuzzer_id(state);
			if(state->edges)
				target_module->shm_handle = setup_shm_region(state->fuzzer_id, target_module->index, (u8**)&target_module->edges_memory, 1);
			else
				target_module->shm_handle = setup_shm_region(state->fuzzer_id, target_module->index, &target_module->trace_bits, 0);
		}
		if (!target_module->shm_handle) {
			PFATAL("Couldn't create shm region for %s module\n", state->module_names[target_module->index]);
		}
		if(reset_virgin_bits)
			memset(target_module->virgin_bits, 0xFF, MAP_SIZE);
		if (state->edges)
			memset(target_module->edges_memory, 0, EDGES_SHM_SIZE);

		//Next create the rest of them with that fuzzer id
		target_module = target_module->next;
		while (target_module)
		{
			if (state->edges)
				target_module->shm_handle = setup_shm_region(state->fuzzer_id, target_module->index, (u8**)&target_module->edges_memory, 1);
			else
				target_module->shm_handle = setup_shm_region(state->fuzzer_id, target_module->index, &target_module->trace_bits, 0);
			if (!target_module->shm_handle)
				FATAL_MSG("Couldn't create shm region for %s module", state->module_names[target_module->index]);

			if (reset_virgin_bits)
				memset(target_module->virgin_bits, 0xFF, MAP_SIZE);
			if (state->edges)
				memset(target_module->edges_memory, 0, EDGES_SHM_SIZE);

			target_module = target_module->next;
		}
	}
	else
	{
		while (attempts < 5 && !state->shm_handle) {
			attempts++;
			generate_fuzzer_id(state);
			if (state->edges)
				state->shm_handle = setup_shm_region(state->fuzzer_id, -1, (u8**)&state->edges_memory, 1);
			else
				state->shm_handle = setup_shm_region(state->fuzzer_id, -1, &state->trace_bits, 0);
		}
		if (!state->shm_handle) {
			FATAL_MSG("Couldn't create shm region");
		}

		if (reset_virgin_bits)
			memset(state->virgin_bits, 0xFF, MAP_SIZE);
		if (state->edges)
			memset(state->edges_memory, 0, EDGES_SHM_SIZE);
	}
}

/**
 * This function kills a process with the specified exit code 
 * @param dwProcessId - the process id of the process to kill
 * @param uExitCode - the exit code that the specified process should be killed with
 * @return - a BOOL describing whether the process was successfully terminated (TRUE) or not (FALSE)
 */
BOOL TerminateProcessByPid(DWORD dwProcessId, UINT uExitCode)
{
	DWORD dwDesiredAccess = PROCESS_TERMINATE;
	BOOL  bInheritHandle = FALSE;
	HANDLE hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
	if (hProcess == NULL)
		return FALSE;

	BOOL result = TerminateProcess(hProcess, uExitCode);

	CloseHandle(hProcess);

	return result;
}

/**
 * This function wraps the creation of a pipe
 * @param pipe_name - The name of the pipe to create
 * @param timeout - The maximum time to wait for the pipe to be created
 * @return - A handle to the created pipe
 */
static HANDLE create_pipe(char * pipe_name, DWORD timeout)
{
	HANDLE pipe;

	pipe = CreateNamedPipe(
		pipe_name,                // pipe name
		PIPE_ACCESS_DUPLEX |      // read/write access
		FILE_FLAG_OVERLAPPED,     // asynchronous (so we can time out)
		0,
		1,                        // max. instances
		512,                      // output buffer size
		512,                      // input buffer size
		timeout,                  // client time-out
		NULL);                    // default security attribute

	if (pipe == INVALID_HANDLE_VALUE)
		FATAL_MSG("CreateNamedPipe failed for pipe %s, GLE=%d.", pipe_name, GetLastError());
	return pipe;
}

/**
 * This function connects to a pipe.
 * @param pipe - A handle to the pipe to connect to
 * @param pipe_name - The name of the pipe to connect to.  Only used in help messages, if creation fails.
 * @param timeout - The maximum time to wait for the client to connect to the pipe
 * @return - TRUE if the connection succeeds, FALSE otherwise
 */
static BOOL connect_to_pipe(HANDLE pipe, char * pipe_name, DWORD timeout)
{
	BOOL success = FALSE;
	OVERLAPPED overlap = { 0 };
	overlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (ConnectNamedPipe(pipe, &overlap)) {
		// Overlapped ConnectNamedPipe is expected to always return 0
		ERROR_MSG("ConnectNamedPipe failed for the pipe %s, GLE=%d.", pipe_name, GetLastError());
		return FALSE;
	}
	switch (GetLastError()) {
	case ERROR_PIPE_CONNECTED:
		success = TRUE;
		break;
	case ERROR_IO_PENDING:
		if (WaitForSingleObject(overlap.hEvent, timeout) == WAIT_OBJECT_0) {
			// Pipe is connected
			DWORD ignored_bytestransferred;
			success = GetOverlappedResult(pipe, &overlap, &ignored_bytestransferred, FALSE);
			break;
		}
		else
		{
			// Timed out or failed
			CancelIo(pipe);
		}
	}

	if (!success) {
		ERROR_MSG("Did not receive connection from DynamoRIO child process on pipe %s, GLE=%d.", pipe_name, GetLastError());
		ERROR_MSG("Try increasing the instrumentation timeout option (currently set to %lu).", timeout);
	}

	CloseHandle(overlap.hEvent);

	return success;
}

/**
* This function cleans up a pipe.
* @param pipe - A handle to the pipe to clean up
*/
static void cleanup_pipe(HANDLE * pipe)
{
	if (*pipe) {
		DisconnectNamedPipe(*pipe);
		CloseHandle(*pipe);
		*pipe = NULL;
	}
}

/**
 * This function terminates the fuzzed process (running in drrun.exe).
 * @param state - The dynamorio_state_t object containing this instrumentation's state
 * @param wait_exit - The maximum number of milliseconds to wait when trying to wait for fuzzed process.
 */
static void destroy_target_process(dynamorio_state_t * state, int wait_exit) {
	//TODO this seems like it'll be really slow.  Optimize it if possible

	char kill_cmd[512];
	HANDLE kill_handle;

	if (state->child_handle) {

		//nudge the child process
		if (WaitForSingleObject(state->child_handle, wait_exit) == WAIT_TIMEOUT) {

			//Try to nudge the process first
			snprintf(kill_cmd, sizeof(kill_cmd) - 1, "%s\\drconfig.exe -nudge_pid %d 0 1", state->dynamorio_dir, state->child_pid);
			if (start_process_and_write_to_stdin(kill_cmd, NULL, 0, &kill_handle))
				FATAL_MSG("Could not nudge process with drconfig");
			CloseHandle(kill_handle);

			//wait until the child process exits
			if (WaitForSingleObject(state->child_handle, state->timeout) == WAIT_TIMEOUT) {

				//It didn't exit, so kill drrun
				if (!TerminateProcess(state->child_handle, 9))
					FATAL_MSG("Could not stop fuzzed program (pid %d) with TerminateProcess (GLE=%d)", state->child_pid, GetLastError());

				//Clean up the target process as well
				TerminateProcessByPid(state->child_pid, 9);
			}
		}
		CloseHandle(state->child_handle);
		state->child_handle = NULL;
	}

	cleanup_pipe(&state->pipe_handle);
}

/**
 * This function starts the fuzzed process inside of DynamoRIO
 * @param state - The dynamorio_state_t object containing this instrumentation's state
 * @param cmd_line - the command line of the fuzzed process to start
 * @param stdin_input - the input to pass to the fuzzed process's stdin
 * @param stdin_length - the length of the stdin_input parameter
 */
static void create_target_process(dynamorio_state_t * state, char* cmd_line, char * stdin_input, size_t stdin_length) {
	char* dr_cmd;
	FILE *fp;
	size_t pidsize;
	char buffer[MAX_PATH];

	state->pipe_handle = create_pipe(state->pipe_name, state->timeout);

	//Create the child process
	dr_cmd = alloc_printf(
		"%s\\drrun.exe -pidfile %s -no_follow_children -c \"%s\\winafl.dll\" %s -fuzzer_id %s -- %s",
		state->dynamorio_dir, state->pidfile, state->winafl_dir, state->client_params, state->fuzzer_id, cmd_line);
	if (start_process_and_write_to_stdin(dr_cmd, stdin_input, stdin_length, &state->child_handle))
		FATAL_MSG("Child process died when started with command line: %s", dr_cmd);

	if (!connect_to_pipe(state->pipe_handle, state->pipe_name, state->timeout)) //Connect to the comms pipe
	{
		if (get_process_status(state->child_handle) == 0) // process is not alive
			FATAL_MSG("Child process died when started with command line: %s", dr_cmd);
		else
			FATAL_MSG("Error communicating with child process with command line: %s", dr_cmd);
	}

	ck_free(dr_cmd);

	//by the time pipe has connected the pidfile must have been created
	fp = fopen(state->pidfile, "rb");
	if (!fp)
		FATAL_MSG("Error opening pidfile %s", state->pidfile);
	pidsize = fread(buffer, 1, sizeof(buffer)-1, fp);
	buffer[pidsize] = 0;
	fclose(fp);
	remove(state->pidfile);
	state->child_pid = atoi(buffer);

	//Reset the fuzz iteration count
	state->fuzz_iterations_current = 0;
}

/**
 * This function ends the fuzzed process (if it wasn't previously ended), cleans
 * up the pipe, and calculates the whether a new path was taken.
 * @param state - The dynamorio_state_t object containing this instrumentation's state
 * @return - returns -1 on error, -2 when in edge mode, or the results of
 * has_new_coverage/has_new_coverage_per_module functions
 */
static int finish_fuzz_round(dynamorio_state_t * state) {
	DWORD num_bytes_available;
	char result;
	DWORD num_read;
	int ret;

	if (state->analyzed_last_round)
		return state->last_path_was_new;

	//Determine if the last process hung or not.  If there's nothing in the pipe, then it obviously hung.
	if (!PeekNamedPipe(state->pipe_handle, NULL, 0, NULL, &num_bytes_available, NULL))
		return -1;

	if (!num_bytes_available)
	{
		destroy_target_process(state, 0);
		state->last_process_status = FUZZ_HANG;
	}
	else
	{
		//Read the result from the child
		ReadFile(state->pipe_handle, &result, 1, &num_read, NULL);

		//See if we should restart the client
		state->fuzz_iterations_current++;
		if (state->fuzz_iterations_current == state->fuzz_iterations_max) {
			destroy_target_process(state, state->timeout);
		}

		//Record the process status
		if (num_read == 1 && result == 'K') //Normal
		{
			state->last_process_status = FUZZ_NONE;
		}
		else //The process hung or crashed, restart it
		{
			destroy_target_process(state, 0);
			if (num_read == 1 && result == 'C') //Crash
				state->last_process_status = FUZZ_CRASH;
			else //unknown char or couldn't read, Hang
				state->last_process_status = FUZZ_HANG;
		}
	}

	//Now check to see if the instrumentation found a new path
	if (state->edges)
		ret = -2;
	else if (state->per_module_coverage)
		ret = has_new_coverage_per_module(state);
	else
		ret = has_new_coverage(state->trace_bits, state->virgin_bits, state->ignore_bytes, &state->last_shm_hash, state->dump_map_dir);
	state->last_path_was_new = ret;
	state->analyzed_last_round = 1;
	return ret;
}

/**
 * Checks if the target process is done fuzzing the inputs yet.  If it has finished, it will have
 * written the results to the dynamorio instrumentation's pipe.

 * @param state - The dynamorio_state_t object containing this instrumentation's state
 * @return - 0 if the process has not done testing the fuzzed input, 1 if the process is done, -1 on error.
 */
int dynamorio_is_process_done(void * instrumentation_state)
{
	dynamorio_state_t * state = (dynamorio_state_t *)instrumentation_state;
	DWORD num_bytes_available;

	if (!state->enable_called)
		return -1;

	if (!PeekNamedPipe(state->pipe_handle, NULL, 0, NULL, &num_bytes_available, NULL))
		return -1;

	return num_bytes_available != 0;
}

////////////////////////////////////////////////////////////////
// Instrumentation methods /////////////////////////////////////
////////////////////////////////////////////////////////////////

/**
 * This function loads the ignore_bytes (the bytes in the edges bitmap that should be ignored
 * when checking which edges are new).
 * @param state - The dynamorio_state_t object containing this instrumentation's state
 */
static void load_ignore_bytes(dynamorio_state_t * state)
{
	char filename[4096];
	int size;
	target_module_t * target_module;

	if (!state->per_module_coverage && state->ignore_bytes_file)
	{
		size = read_file(state->ignore_bytes_file, (char **)&state->ignore_bytes);
		if (size < 0)
			FATAL_MSG("Could not open ignore bytes file %s", state->ignore_bytes_file);
		else if (size != MAP_SIZE)
			FATAL_MSG("Incorrect size of ignore bytes file %s", state->ignore_bytes_file);
	}
	else if(state->per_module_coverage && state->ignore_bytes_dir)
	{
		FOREACH_MODULE(target_module, state)
		{
			snprintf(filename, sizeof(filename), "%s\\%s.dat", state->ignore_bytes_dir, state->module_names[target_module->index]);
			size = read_file(filename, (char **)&target_module->ignore_bytes);
			if (size >= 0 && size != MAP_SIZE) //ignore missing ignore bytes files
				FATAL_MSG("Incorrect size of ignore bytes file %s", filename);
			else if (size >= 0)
				DEBUG_MSG("Loaded ignore bytes file %s for modules %s", filename, state->module_names[target_module->index]);
		}
	}
}

/**
 * This function generates the arguments that will be passed to the winafl.dll DynamoRIO tool.
 * @param state - The dynamorio_state_t object containing this instrumentation's state
 */
static void generate_client_params(dynamorio_state_t * state)
{
	char * temp;
	size_t size, i;

	//Format client params
	size = 10 * 4096;
	temp = (char *)malloc(size);
	if (!temp)
		FATAL_MSG("Couldn't get memory for client_params");
	snprintf(temp, size - 1, "%s -fuzz_iterations %d", state->client_params ? state->client_params : "", state->fuzz_iterations_max);
	if (state->num_modules)
	{
		char line[1024];
		char * modules_filename = get_temp_filename(".txt");
		FILE * fp = fopen(modules_filename, "wb");
		if (!fp)
			FATAL_MSG("Couldn't open modules file '%s'", modules_filename);
		for (i = 0; i < state->num_modules; i++)
		{
			snprintf(line, sizeof(line), "%s\n", state->module_names[i]);
			fwrite(line, 1, strlen(line), fp);
		}
		fclose(fp);
		snprintf(temp, size - 1, "%s -coverage_module_file %s", temp, modules_filename);
		free(modules_filename);
	}
	if (state->per_module_coverage)
		snprintf(temp, size - 1, "%s -per_module_coverage", temp);
	
	if (state->edges)
		snprintf(temp, size - 1, "%s -verbose_edges", temp);

	if (state->client_params)
		free(state->client_params);
	state->client_params = temp;
}

/**
* This function adds the string \bin32\ or \bin64\ to the end of the provided
* dynamorio base path. The architecture is chosen to match the binary in
* target_path, or the fuzzer if target_path is NULL.
* @param base_path - char * containing the base dynamorio directory
* @param target_path - char * containing the path to the binary being fuzzed,
* or NULL if that option has not been provided to the fuzzer
* @return - A newly allocated char * pointing to the path with the architecture
* suffix added
*/
static char * add_architecture_to_path(char * base_path, char * target_path) {
	char * temp;
	DWORD binary_type;

	temp = (char *)malloc(MAX_PATH + 1);
	if (!temp)
		FATAL_MSG("Couldn't get memory for dynamorio_dir");
	memset(temp, 0, MAX_PATH + 1);

	if (target_path)
	{
		if (GetBinaryTypeA(target_path, &binary_type))
		{
			//Pick the path based on the target file's architecture
			if (binary_type == SCS_32BIT_BINARY)
				snprintf(temp, MAX_PATH - 1, "%s\\bin32\\", base_path);
			else if (binary_type == SCS_64BIT_BINARY)
				snprintf(temp, MAX_PATH - 1, "%s\\bin64\\", base_path);

			//Assign the default path
			if (binary_type == SCS_32BIT_BINARY || binary_type == SCS_64BIT_BINARY)
				return temp;
		}
	}

	//Couldn't get the architecture from the target path
	//so just guess the dynamorio path that matches the current architecture
#ifdef _M_X64
	snprintf(temp, MAX_PATH - 1, "%s\\bin64\\", base_path);
#else
	snprintf(temp, MAX_PATH - 1, "%s\\bin32\\", base_path);
#endif
	return temp;
}

/**
 * This function populates the default_dynamorio_dir field of the state. It
 * searches the folders containing the fuzzer to find a dynamorio directory in
 * one of a few likely locations.
 * @param state - a pointer to the state to modify
 * @param target_path - char * containing the path to the binary being fuzzed,
 * or NULL if that option has not been provided to the fuzzer
 */
static void pick_default_dynamorio_dir(dynamorio_state_t * state, char * target_path)
{
	char * path;
	size_t pathlen;

	if (state->default_dynamorio_dir)
		free(state->default_dynamorio_dir);
	state->default_dynamorio_dir = NULL;

	//Try to autodetect the dynamorio directory
	// Usual location for binary distribution
	path = filename_relative_to_binary_dir("..\\dynamorio\\bin32\\drrun.exe");
	if (!path)
	{  // Usual location for 32-bit developer environment
		path = filename_relative_to_binary_dir("..\\..\\..\\dynamorio\\bin32\\drrun.exe");
	}
	if (!path)
	{  // Usual location for 64-bit developer environment
		path = filename_relative_to_binary_dir("..\\..\\..\\..\\dynamorio\\bin64\\drrun.exe");
	}
	if (!path)
		return;

	pathlen = strlen(path);
	path[pathlen - 16] = '\0'; // Remove "\\binXX\\drrun.exe"
	state->default_dynamorio_dir = add_architecture_to_path(path, target_path);
	free(path);
}

/**
 * This function copies a dynamorio_state_t object, or allocates a new one with the default parameters.
 * @param original - The dynamorio_state_t object that should be copied.  If this parameter is NULL,
 * a new dynamorio_state_t is allocated with the default options.
 * @return - the newly allocated dynamorio_state_t object.
 */
static dynamorio_state_t * copy_state(dynamorio_state_t * original)
{
	size_t i;
	dynamorio_state_t * ret = (dynamorio_state_t *)malloc(sizeof(dynamorio_state_t));
	target_module_t * target_module, *ret_target_module, *new_target_module;
	if (!ret)
		return NULL;
	memset(ret, 0, sizeof(dynamorio_state_t));

	if (!original)
	{ //No original passed in, just make the default one
		pick_default_dynamorio_dir(ret, NULL);
		ret->default_winafl_dir = filename_relative_to_binary_dir(".");
		ret->fuzz_iterations_max = 1;
		ret->timeout = 1000; //1 second
		ret->edges = 0;
		ret->analyzed_last_round = 1;
		return ret;
	}
	
	//Copy all the relevant options
	ret->default_dynamorio_dir = strdup(original->default_dynamorio_dir);
	if (original->dynamorio_dir) ret->dynamorio_dir = strdup(original->dynamorio_dir);
	ret->winafl_dir = strdup(original->winafl_dir);
	if (original->target_path) ret->target_path = strdup(original->target_path);
	if (original->dump_map_dir) ret->dump_map_dir = strdup(original->dump_map_dir);
	if (original->ignore_bytes_dir) ret->ignore_bytes_dir = strdup(original->ignore_bytes_dir);
	if (original->ignore_bytes_file) ret->ignore_bytes_file = strdup(original->ignore_bytes_file);
	ret->per_module_coverage = original->per_module_coverage;
	ret->fuzz_iterations_max = original->fuzz_iterations_max;
	if (original->client_params) ret->client_params = strdup(original->client_params);
	ret->timeout = original->timeout;
	ret->fuzz_iterations_current = original->fuzz_iterations_current;
	ret->edges = original->edges;

	if (original->per_module_coverage)
	{
		ret->num_modules = original->num_modules;
		ret->module_names = (char **)malloc(ret->num_modules * sizeof(char *));
		for (i = 0; i < ret->num_modules; i++)
			ret->module_names[i] = strdup(original->module_names[i]);

		ret_target_module = NULL;
		FOREACH_MODULE(target_module, original)
		{
			new_target_module = (target_module_t *)malloc(sizeof(target_module_t));
			memset(new_target_module, 0, sizeof(target_module_t));
			new_target_module->index = target_module->index;
			memcpy(new_target_module->virgin_bits, original->virgin_bits, MAP_SIZE);
			new_target_module->last_shm_hash = target_module->last_shm_hash;
			new_target_module->last_path_was_new = target_module->last_path_was_new;
			if (target_module->ignore_bytes)
			{
				new_target_module->ignore_bytes = (u8 *)malloc(MAP_SIZE);
				memcpy(new_target_module->ignore_bytes, target_module->ignore_bytes, MAP_SIZE);
			}

			//Add the new module to the linked list of modules
			if (ret_target_module)
				ret->modules = new_target_module;
			else
				ret_target_module->next = new_target_module;
			ret_target_module = new_target_module;
		}
	}
	else
	{
		memcpy(ret->virgin_bits, original->virgin_bits, MAP_SIZE);
		ret->last_shm_hash = original->last_shm_hash;
		ret->last_path_was_new = original->last_path_was_new;
	}

	return ret;
}

/**
 * This function creates a dynamorio_state_t object based on the given options.
 * @param options - A JSON string of the options to set in the new dynamorio_state_t. See the
 * help function for more information on the specific options available.
 * @return the dynamorio_state_t generated from the options in the JSON options string, or NULL on failure
 */
static dynamorio_state_t * setup_options(char * options)
{
	dynamorio_state_t * state;
	size_t i, length;
	target_module_t * target_module;
	char * temp;
	char buffer[MAX_PATH];

	state = copy_state(NULL);
	if (!state)
		return NULL;

	//Parse the options
	PARSE_OPTION_STRING(state, options, dynamorio_dir, "dynamorio_dir", dynamorio_cleanup);
	PARSE_OPTION_STRING(state, options, winafl_dir, "winafl_dir", dynamorio_cleanup);
	PARSE_OPTION_STRING(state, options, target_path, "target_path", dynamorio_cleanup);
	PARSE_OPTION_STRING(state, options, dump_map_dir, "dump_map_dir", dynamorio_cleanup);
	PARSE_OPTION_STRING(state, options, ignore_bytes_dir, "ignore_bytes_dir", dynamorio_cleanup);
	PARSE_OPTION_STRING(state, options, ignore_bytes_file, "ignore_bytes_file", dynamorio_cleanup);
	PARSE_OPTION_STRING(state, options, client_params, "client_params", dynamorio_cleanup);
	PARSE_OPTION_INT(state, options, fuzz_iterations_max, "fuzz_iterations", dynamorio_cleanup);
	PARSE_OPTION_INT(state, options, per_module_coverage, "per_module_coverage", dynamorio_cleanup);
	PARSE_OPTION_INT(state, options, timeout, "timeout", dynamorio_cleanup);
	PARSE_OPTION_ARRAY(state, options, module_names, num_modules, "coverage_modules", dynamorio_cleanup);
	PARSE_OPTION_INT(state, options, edges, "edges", dynamorio_cleanup);

	if (!state->num_modules && state->target_path) { //if the user didn't specify a module, we'll pick the executable itself by default
		state->num_modules = 1;
		state->module_names = malloc(sizeof(char *));
		length = strlen(state->target_path) + 1;
		state->module_names[0] = malloc(length);
		strncpy(state->module_names[0], PathFindFileName(state->target_path), length);
		INFO_MSG("No Coverage Module selected, choosing the target executable \"%s\" by default.", state->module_names[0]);
	}

	if (!state->num_modules)
		FATAL_MSG("No Coverage Module selected, please specify one with the coverage_modules option.");

	if (state->target_path)
	{
		pick_default_dynamorio_dir(state, state->target_path);
	}

	if (state->dynamorio_dir) //if the user specified a dynamorio directory, use that. Otherwise use the default one
	{
		temp = state->dynamorio_dir;
		state->dynamorio_dir = add_architecture_to_path(temp, state->target_path);
		free(temp);
	}
	else
	{
		if (state->default_dynamorio_dir)
			state->dynamorio_dir = strdup(state->default_dynamorio_dir);
		else
			FATAL_MSG("Dynamorio was not found in the default location, and dynamorio_dir was not specified.");
	}

	if (!state->winafl_dir) { //if the user didn't specify a winafl directory, try to automatically determine one
		state->winafl_dir = add_architecture_to_path(state->default_winafl_dir, state->target_path);
	}

	//Verify winafl.dll exists
	snprintf(buffer, sizeof(buffer) - 1, "%s\\winafl.dll", state->winafl_dir);
	if (access(buffer, 0))
		FATAL_MSG("Failed to find the winafl.dll in %s. Use the winafl_dir option to modify the directory to look for winafl.dll, and ensure that you have matching bitness (bin32 vs 64) between winafl.dll and the fuzz target.", state->winafl_dir);

	//printf("Modules (%zu):\n", state->num_modules);
	for (i = 0; i < state->num_modules; i++)
	{
		//printf("%d: %s\n", i, state->module_names[i]);
		target_module = (target_module_t *)malloc(sizeof(target_module_t));
		memset(target_module, 0, sizeof(target_module_t));
		target_module->index = i;
		target_module->next = state->modules;
		state->modules = target_module;
	}
	//printf("\n");

	generate_client_params(state);
	load_ignore_bytes(state);
	return state;
}

/**
 * This function allocates and initializes a new instrumentation specific state object based on the given options.
 * @param options - a JSON string that contains the instrumentation specific string of options
 * @param state - an instrumentation specific JSON string previously returned from dynamorio_get_state that should be loaded
 * @return - An instrumentation specific state object on success or NULL on failure
 */
void * dynamorio_create(char * options, char * state)
{
	dynamorio_state_t * dynamorio_state;

	dynamorio_state = setup_options(options);
	if (!dynamorio_state)
		return NULL;

	if (state && dynamorio_set_state(dynamorio_state, state))
	{
		dynamorio_cleanup(dynamorio_state);
		return NULL;
	}

	return dynamorio_state;
}

/**
 * This function cleans up all resources with the passed in instrumentation state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the dynamorio_create function
 * This state object should not be referenced after this function returns.
 */
void dynamorio_cleanup(void * instrumentation_state)
{
	target_module_t * target_module, *next;

	dynamorio_state_t * state = (dynamorio_state_t *)instrumentation_state;
	destroy_target_process(state, 0);
	remove_shm(state->trace_bits, state->shm_handle);

	for (target_module = state->modules; target_module; )
	{
		next = target_module->next;
		remove_shm(target_module->trace_bits, target_module->shm_handle);
		free(state->ignore_bytes);
		free(state->module_names[target_module->index]);
		free(target_module);
		target_module = next;
	}

	if (state->pidfile) ck_free(state->pidfile);
	if (state->pipe_name) ck_free(state->pipe_name);
	if (state->fuzzer_id) ck_free(state->fuzzer_id);
	free(state->default_dynamorio_dir);
	free(state->dynamorio_dir);
	free(state->default_winafl_dir);
	free(state->winafl_dir);
	free(state->target_path);
	free(state->dump_map_dir);
	free(state->client_params);
	free(state->ignore_bytes_dir);
	free(state->ignore_bytes_file);
	free(state->module_names);
	free(state->ignore_bytes);
	free(state);
}

/**
 * This function merges the coverage information from two instrumentation states.
 * @param instrumentation_state - an instrumentation specific state object previously created by the dynamorio_create function
 * @param other_instrumentation_state - an instrumentation specific state object previously created by the dynamorio_create function
 * @return - An instrumentation specific state object that contains the combination of both of the passed in instrumentation states
 * on success, or NULL on failure
 */
void * dynamorio_merge(void * instrumentation_state, void * other_instrumentation_state)
{
	target_module_t * ret_module, * new_module;
	size_t i, j;
	int found;
	dynamorio_state_t * ret;
	dynamorio_state_t * first = (dynamorio_state_t *)instrumentation_state;
	dynamorio_state_t * second = (dynamorio_state_t *)other_instrumentation_state;

	//Check that the instrumenation states are similar enough
	if (first->per_module_coverage != second->per_module_coverage
		|| first->num_modules != second->num_modules)
		return NULL;

	for (i = 0; i < first->num_modules; i++)
	{
		found = 0;
		for (j = 0; j < first->num_modules; j++)
		{
			if (!strcmp(first->module_names[i], second->module_names[j]))
				found = 1;
		}
		if (!found)
			return NULL;
	}

	ret = copy_state(first);
	if (!ret)
		return NULL;

	if (ret->per_module_coverage)
	{
		FOREACH_MODULE(ret_module, ret)
		{
			FOREACH_MODULE(new_module, second)
			{
				if (!strcmp(ret->module_names[ret_module->index], second->module_names[new_module->index]))
				{
					merge_bitmaps(ret_module->virgin_bits, new_module->virgin_bits);
					//We don't really need to track these, they're not relevant for merged instrumentations
					ret_module->last_path_was_new = ret_module->last_shm_hash = 0;
				}
			}
		}
	}
	else
	{
		merge_bitmaps(ret->virgin_bits, second->virgin_bits);
		ret->last_path_was_new = ret->last_shm_hash = 0;
	}
	return ret;
}

/**
 * This function returns the state information holding the previous execution path info.  The returned value can later be passed to
 * dynamorio_create or dynamorio_set_state to load the state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the dynamorio_create function
 * @return - A JSON string that holds the instrumentation specific state object information on success, or NULL on failure
 */
char * dynamorio_get_state(void * instrumentation_state)
{
	dynamorio_state_t * state = (dynamorio_state_t *)instrumentation_state;
	json_t *state_obj, *module_obj, *temp, *module_list;
	target_module_t * target_module;
	char * ret;

	state_obj = json_object();
	if (!state_obj)
		return NULL;

	ADD_INT(temp, state->last_process_status, state_obj, "last_process_status");
	
	if (!state->per_module_coverage)
	{
		ADD_MEM(temp, (const char *)state->virgin_bits, MAP_SIZE, state_obj, "virgin_bits");
		ADD_INT(temp, state->last_shm_hash, state_obj, "last_shm_hash");
		ADD_INT(temp, state->last_path_was_new, state_obj, "last_path_was_new");
	}
	else
	{
		module_list = json_array();
		if (!module_list)
			return NULL;
		FOREACH_MODULE(target_module, state)
		{
			module_obj = json_object();
			if (!module_obj)
				return NULL;
			ADD_STRING(temp, state->module_names[target_module->index], module_obj, "name");
			ADD_MEM(temp, (const char *)target_module->virgin_bits, MAP_SIZE, module_obj, "virgin_bits");
			ADD_INT(temp, target_module->last_shm_hash, module_obj, "last_shm_hash");
			ADD_INT(temp, target_module->last_path_was_new, module_obj, "last_path_was_new");
			json_array_append_new(module_list, module_obj);
		}
		json_object_set_new(state_obj, "modules", module_list);
	}

	ret = json_dumps(state_obj, 0);
	json_decref(state_obj);
	return ret;

}

/**
 * This function frees an instrumentation state previously obtained via dynamorio_get_state.
 * @param state - the instrumentation state to free
 */
void dynamorio_free_state(char * state)
{
	free(state);
}

#define get_item(arg1, dest, temp, func, name, ret) \
	temp = func(arg1, name, &ret);                  \
	if (ret <= 0)                                   \
		return 1;                                   \
	dest = temp;

#define get_virgin_bits(arg1, dest, temp, func, ret)   \
	temp = func(arg1, "virgin_bits", &ret);            \
	if (ret <= 0)                                      \
		return 1;                                      \
	memcpy(dest, temp, MAP_SIZE);                      \
    free(temp);

/**
 * This function sets the instrumentation state to the passed in state previously obtained via dynamorio_get_state.
 * @param instrumentation_state - an instrumentation specific state object previously created by the dynamorio_create function
 * @param state - an instrumentation state previously obtained via dynamorio_get_state
 * @return - 0 on success, non-zero on failure.
 */
int dynamorio_set_state(void * instrumentation_state, char * state)
{
	int result, inner_result, tempint, found;
	char * tempstr;
	json_t * module_obj;
	target_module_t * target_module;
	dynamorio_state_t * dynamorio_state = (dynamorio_state_t *)instrumentation_state;

	if (!state)
		return 1;

	//If a child process is running when the state is being set
	destroy_target_process(dynamorio_state, 0);//kill it so we don't orphan it

	get_item(state, dynamorio_state->last_process_status, tempint, get_int_options, "last_process_status", result);
	dynamorio_state->analyzed_last_round = 1;

	if (!dynamorio_state->per_module_coverage)
	{
		get_item(state, dynamorio_state->last_shm_hash, tempint, get_int_options, "last_shm_hash", result);
		get_item(state, dynamorio_state->last_path_was_new, tempint, get_int_options, "last_path_was_new", result);
		get_virgin_bits(state, dynamorio_state->virgin_bits, tempstr, get_mem_options, result);
	}
	else
	{
		FOREACH_OBJECT_JSON_ARRAY_ITEM_BEGIN(state, modules, "modules", module_obj, result)

			tempstr = get_string_options_from_json(module_obj, "name", &inner_result);
			if (inner_result <= 0)
				return 1;
			found = 0;

			FOREACH_MODULE(target_module, dynamorio_state)
			{
				if (!strcmp(dynamorio_state->module_names[target_module->index], tempstr))
				{
					get_item(module_obj, target_module->last_shm_hash, tempint, get_int_options_from_json, "last_shm_hash", inner_result);
					get_item(module_obj, target_module->last_path_was_new, tempint, get_int_options_from_json, "last_path_was_new", inner_result);
					get_virgin_bits(module_obj, target_module->virgin_bits, tempstr, get_mem_options_from_json, inner_result);
					found = 1;
				}
			}
			free(tempstr);
			if (!found)
				return 1;
		FOREACH_OBJECT_JSON_ARRAY_ITEM_END(modules);

		if (result < 0)
			return 1;
	}

	return 0;
}

/**
 * This function enables the instrumentation and runs the fuzzed process.  If the process needs to be restarted, it will be.
 * @param instrumentation_state - an instrumentation specific state object previously created by the dynamorio_create function
 * @process - a pointer to return a handle to the process that instrumentation was enabled on
 * @cmd_line - the command line of the fuzzed process to enable instrumentation on
 * @input - a buffer to the input that should be sent to the fuzzed process on stdin
 * @input_length - the length of the input parameter
 * returns 0 on success, -1 on failure
 */
int dynamorio_enable(void * instrumentation_state, HANDLE * process, char * cmd_line, char * input, size_t input_length)
{
	dynamorio_state_t * state = (dynamorio_state_t *)instrumentation_state;
	DWORD num_written;
	target_module_t * target_module;

	if (!state->fuzzer_id)
	{
		setup_shm_and_pick_fuzzer_id(state, 1);
		state->pipe_name = (char *)alloc_printf("\\\\.\\pipe\\afl_pipe_%s", state->fuzzer_id);
		state->pidfile = alloc_printf("childpid_%s.txt", state->fuzzer_id);
	}

	if (!state->child_handle   //if we haven't started the child yet
		|| get_process_status(state->child_handle) == 0 //or the child died
		|| input_length != 0) //or the fuzzer wants to send input on stdin (which doesn't work with persistence mode)
	{
		if (state->child_handle)
			destroy_target_process(state, 0);
		create_target_process(state, cmd_line, input, input_length);
	}
	else //the child is alive and we haven't cleaned up from last round
		finish_fuzz_round(state);

	*process = state->child_handle;

	//Blank the map state
	if (state->per_module_coverage)
	{
		FOREACH_MODULE(target_module, state)
			memset(state->edges ? (void *)target_module->edges_memory : target_module->trace_bits, 0, state->edges ? EDGES_SHM_SIZE : MAP_SIZE);
	}
	else
		memset(state->edges ? (void *)state->edges_memory : state->trace_bits, 0, state->edges ? EDGES_SHM_SIZE : MAP_SIZE);

	//Tell the child instrumentation to go
	WriteFile(state->pipe_handle, "F", 1, &num_written, NULL);
	state->analyzed_last_round = 0;
	state->enable_called = 1;

	return 0;
}

/**
 * This function determines if the last run had new coverage.
 * @param trace_bits - the edge bitmap of the most recent run
 * @parma virgin_bits - the edge bitmap of all edges previously seen
 * @param ignore_bytes - the edge bitmap of which bytes in the edge bitmap should be ignored
 * @param last_shm_hash - a pointer to a hash of the last run's trace_bits region.  This pointer will be
 * updated with the current run's trace_bits' hash.
 * @param dump_map_dir - This optional parameter will cause the trace_bits bitmap to be dumped to the directory
 * specified by this parameter.
 * @return - returns 1 if new edge was found or an edge's hit count changed, or 0 otherwise
 */
static int has_new_coverage(u8 * trace_bits, u8 * virgin_bits, u8 * ignore_bytes, u32 * last_shm_hash, char * dump_map_dir)
{
	u8 hnb;
	u32 hash, temp;

#ifdef __x86_64__
	classify_counts((u64*)trace_bits);
#else
	classify_counts((u32*)trace_bits);
#endif // ^__x86_64__

	//A quick check of the last hash we saw to see if this output took the same path
	//Used to speed up the memory compare
	if (ignore_bytes)
	{
		hash = hash32_with_ignore(trace_bits, ignore_bytes, MAP_SIZE, HASH_CONST);
		temp = hash32(trace_bits, MAP_SIZE, HASH_CONST); //TODO REMOVE
	}
	else
		temp = hash = hash32(trace_bits, MAP_SIZE, HASH_CONST);

	DEBUG_MSG("Dynamorio Instrumentation got hash %08x temp %08x (last hash %08x)", hash, temp, *last_shm_hash);
	if (hash == *last_shm_hash)
		return 0;

	if (dump_map_dir)
	{	//Write out the hash bitmap for debugging purposes
		char buffer[MAX_PATH];
		snprintf(buffer, sizeof(buffer) - 1, "%s\\%08x", dump_map_dir, hash);
		write_buffer_to_file(buffer, (char *)trace_bits, MAP_SIZE);
	}

	//We had a new path (or hash collision), record it to the virgin bits
	*last_shm_hash = hash;
	if (ignore_bytes)
		hnb = has_new_bits_with_ignore(trace_bits, virgin_bits, ignore_bytes);
	else
		hnb = has_new_bits(trace_bits, virgin_bits);
	DEBUG_MSG("has_new_bits = %hhu", hnb);
	return hnb != 0;
}


/**
 * This function determines if which of the target_modules being tracked have new edges hit from the most recent run.
 * This function should only be called when per_module_coverage is enabled.
 * @param state - a dynamorio_state_t object previously created by the dynamorio_create function
 * @return - returns 1 if new edge was found or an edge's hit count changed, or 0 otherwise
 */
static int has_new_coverage_per_module(dynamorio_state_t * state)
{
	target_module_t * target_module;
	int isnew, ret = 0;
	u32 last_hash;

	FOREACH_MODULE(target_module, state)
	{
		last_hash = target_module->last_shm_hash;
		isnew = has_new_coverage(target_module->trace_bits, target_module->virgin_bits, target_module->ignore_bytes, &target_module->last_shm_hash, state->dump_map_dir);
		ret |= isnew;
		target_module->last_path_was_new = isnew;
		if (isnew)
			DEBUG_MSG("Module %s has new bits (hash %08x, last hash %08x)", state->module_names[target_module->index], target_module->last_shm_hash, last_hash);
	}
	return ret != 0;
}

/**
 * This function determines whether the process being instrumented has taken a new path.  It should be
 * called after the process has finished processing the tested input.
 * @param instrumentation_state - an instrumentation specific state object previously created by the dynamorio_create function
 * @return - 1 if the previously setup process (via the enable function) took a new path, 0 if it did not, or -1 on failure.
 */
int dynamorio_is_new_path(void * instrumentation_state)
{
	dynamorio_state_t * state = (dynamorio_state_t *)instrumentation_state;
	if (!state->enable_called)
		return -1;
	return finish_fuzz_round(state);
}

/**
 * This function will return the result of the fuzz job. It should be called
 * after the process has finished processing the tested input.
 * @param instrumentation_state - an instrumentation specific structure previously created by the create() function
 * @return - either FUZZ_NONE, FUZZ_HANG, or FUZZ_CRASH, or -1 on error.
 */
int dynamorio_get_fuzz_result(void * instrumentation_state)
{
	dynamorio_state_t * state = (dynamorio_state_t *)instrumentation_state;
	if (!state->enable_called)
		return -1;
	if (finish_fuzz_round(state) < 0)
		return -1;
	return state->last_process_status;
}

/**
 * This function returns information about each of the modules that the instrumentation is tracing.
 * @param instrumentation_state - an instrumentation specific state object previously created by the dynamorio_create function
 * @param index - an index into the module list for the module that information should be retrieved about.  The return value
 * will indicate if a module exists for this index.  Indices start at 0 and increase from there.
 * @param is_new - This parameter returns whether or not the last run of the instrumentation returned a new path for the module
 * with the specified index.  In order for the information returned in this parameter to be accurate, the is_new_path method should
 * be called first.  This parameter is optional and can be set to NULL.
 * @param module_name - This parameter returns the filename of the module at the specified index.  This parameter is optional and can
 * be set to NULL.  The value returned in this parameter should not be freed by the caller.
 * @param info - This parameter returns the an AFL style bitmap of the edges associated with the module at the specified index.  This
 * parameter is optional and can be set to NULL.  The value returned in this parameter should not be freed by the caller
 * @param size - This parameter returns the size of the AFL style bitmap of edges returned in the info parameter.  This parameter is
 * optional and can be set to NULL.
 * @return - 0 if the module with the specified index is found, non-zero on error or if the module is not found
 */
int dynamorio_get_module_info(void * instrumentation_state, int index, int * is_new, char ** module_name, char ** info, int * size)
{
	dynamorio_state_t * state = (dynamorio_state_t *)instrumentation_state;
	target_module_t * target_module;

	if (info || is_new) {
		if (!state->enable_called)
			return -1;
		if (finish_fuzz_round(state) < 0)
			return -1;
	}

	FOREACH_MODULE(target_module, state)
	{
		if (target_module->index == index)
		{
			if(is_new)
				*is_new = target_module->last_path_was_new;
			if(module_name)
				*module_name = state->module_names[index];
			if (info) {
				if (state->edges) //If they asked for edges, we don't have the trace info
					*info = NULL;
				else
					*info = (char *)target_module->trace_bits;
			}
			if(size)
				*size = MAP_SIZE;
			return 0;
		}
	}
	return 1;
}

/*
 * This function gets a list of the edges hit during the instrumented programs most recent run
 * @param instrumentation_state - an instrumentation specific state object previously created by the dynamorio_create function
 * @param index - The index of the module to retrieve the edges for.  This parameter is only needed if the per_module_coverage
 * option is enabled.
 * @return - a list of the edges hit during the instrumented programs most recent run, or NULL on error
 */
instrumentation_edges_t * dynamorio_get_edges(void * instrumentation_state, int index)
{
	dynamorio_state_t * state = (dynamorio_state_t *)instrumentation_state;
	target_module_t * target_module;

	if (!state->enable_called)
		return -1;

	if (!state->edges) //If they didn't ask for edges ahead of time, we don't have them
		return NULL;

	if (finish_fuzz_round(state) == -1)
		return NULL;

	if (!state->per_module_coverage)
		return state->edges_memory;

	FOREACH_MODULE(target_module, state)
	{
		if (target_module->index == index)
			return target_module->edges_memory;
	}

	return NULL;
}

/**
 * This function returns help text for this instrumentation.  This help text will describe the instrumentation and any options
 * that can be passed to dynamorio_create.
 * @param help_str - A pointer that will be updated to point to the new help string.
 * @return 0 on success and -1 on failure
 */
int dynamorio_help(char ** help_str)
{
	*help_str = strdup(
"dynamorio - DynamoRIO instrumentation (based heavily on winafl)\n"
"Options:\n"
"  dynamorio_dir         Set the directory with DynamoRIO binaries in it\n"
"  winafl_dir            Set the directory with winafl.dll in it\n"
"  target_path           The path to the target program to fuzz\n"
"  dump_map_dir          Set the directory to dump the instrumentation bitmap\n"
"                          to, for debugging purposes\n"
"  ignore_bytes_dir      Set the directory to load ignore bit files from when\n"
"                          per_module_coverage is set (of the form\n"
"                          $ignore_bits_dir\\$dll_name.dll.dat).\n"
"  ignore_bytes_file     Set the file to load ignore bit files from when\n"
"                          per_module_coverage is not set.\n"
"  timeout               The number of milliseconds to wait when communicating\n"
"                          with the instrumentation in the target process\n"
"  client_params         Parameters to pass to the winafl.dll DynamoRIO tool\n"
"                          (Do not specify per_module_coverage,\n"
"                          fuzz_iterations, or coverage_modules here)\n"
"  fuzz_iterations       Maximum number of iterations for the target function\n"
"                          to run before restarting the target process\n"
"  coverage_modules      An array of modules that should be instrumented to\n"
"                          record coverage information\n"
"  per_module_coverage   Whether coverage should be tracked in one bitmap (0),\n"
"                          or in a separate bitmap for each module (1)\n"
"\n"
	);
	if (*help_str == NULL)
		return -1;
	return 0;
}

/**
 * This function will log information about the given instrumentation state to the logger.  It's mostly useful for debugging.
 * @param instrumentation_state - an instrumentation specific state object previously created by the dynamorio_create function
 */
void dynamorio_print_state(void * instrumentation_state)
{
	dynamorio_state_t * state = (dynamorio_state_t *)instrumentation_state;
	target_module_t * target_module;

	if (!state->per_module_coverage)
		INFO_MSG("DynamoRIO State: last_hash %08x (hash %08x) last_path_as_new %d", state->last_shm_hash,
			hash32(state->virgin_bits, MAP_SIZE, HASH_CONST), state->last_path_was_new);
	else
	{
		INFO_MSG("DynamoRIO State:");
		FOREACH_MODULE(target_module, state)
		{
			INFO_MSG("module %s: last_hash %08x (hash %08x) last_path_as_new %d", state->module_names[target_module->index],
				target_module->last_shm_hash, hash32(target_module->virgin_bits, MAP_SIZE, HASH_CONST), target_module->last_path_was_new);
		}
	}
}




