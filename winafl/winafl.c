/*
   WinAFL - DynamoRIO client (instrumentation) code
   ------------------------------------------------

   Written and maintained by Ivan Fratric <ifratric@google.com>

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

   This file has been modified from the original to suit the purposes of this
   project.
*/

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dr_api.h>
#include <drmgr.h>
#include <drx.h>
#include <drreg.h>
#include <drwrap.h>
#include <drsyms.h>
#include <drtable.h>
#include <hashtable.h>

#include "modules.h"
#include "utils.h"
#include <winafl_config.h>


#define NOTIFY(level, fmt, ...) do {          \
    if (verbose >= (level))                   \
        dr_fprintf(STDERR, fmt, __VA_ARGS__); \
} while (0)

//////////////////////////////////////////////////////////////////////////////////////
// Enums and Struct Definitions //////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////

#define UNKNOWN_MODULE_ID USHRT_MAX
#define OPTION_MAX_LENGTH MAXIMUM_PATH

#define COVERAGE_BB 0
#define COVERAGE_EDGE 1

#define NUM_THREAD_MODULE_CACHE 8

typedef struct _target_module_t {
	char module_name[MAXIMUM_PATH];
	int index;
	struct _target_module_t *next;
	unsigned char *afl_area;
} target_module_t;

typedef struct _winafl_option_t {
	/* Use nudge to notify the process for termination so that
	 * event_exit will be called.
	 */
	bool verbose_edges;
	bool nudge_kills;
	bool debug_mode;
	bool write_log;
	int coverage_kind;
	char logdir[MAXIMUM_PATH];
	target_module_t *target_modules;
	char fuzz_module[MAXIMUM_PATH];
	char fuzz_method[MAXIMUM_PATH];
	char pipe_name[MAXIMUM_PATH];
	char shm_name[MAXIMUM_PATH];
	unsigned long fuzz_offset;
	int fuzz_iterations;
	void **func_args;
	int num_fuz_args;
	drwrap_callconv_t callconv;
	bool thread_coverage;
	bool per_module_coverage;
} winafl_option_t;

typedef struct _winafl_data_t {
	module_entry_t *cache[NUM_THREAD_MODULE_CACHE];
	file_t  log;
	bool instrumentation_enabled;
	bool exception_hit;

	//Because we instrument the code once, and multiple threads
	//all access that code.  We point the instrumented code at this area
	//for threads we don't care to record the coverage info for (when
	//thread_coverage is on).
	unsigned char *fake_afl_area;

	//The real coverage info area (when per-module coverage is off)
	unsigned char *afl_area;
} winafl_data_t;

typedef struct _debug_data_t {
	int pre_hanlder_called;
	int post_handler_called;
} debug_data_t;

typedef struct _fuzz_target_t {
	reg_t xsp;            /* stack level at entry to the fuzz target */
	app_pc func_pc;
	int iteration;
} fuzz_target_t;

enum {
	NUDGE_TERMINATE_PROCESS = 1,
	NUDGE_DONE_PROCESSING_INPUT = 2,
};

//////////////////////////////////////////////////////////////////////////////////////
// Global Variables //////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////

static uint verbose;

static winafl_option_t options;

static winafl_data_t winafl_data;

static int winafl_tls_field;

static fuzz_target_t fuzz_target;

static debug_data_t debug_data;

static module_table_t *module_table;
static client_id_t client_id;

static volatile bool go_native;

static HANDLE pipe = NULL;

//////////////////////////////////////////////////////////////////////////////////////
// Function Prototypes ///////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////

static void event_exit(void);
static void event_thread_exit(void *drcontext);

static void setup_shm_and_tls_regions_for_coverage(void *drcontext);
static void read_start_fuzz_command();

//////////////////////////////////////////////////////////////////////////////////////
// Function Definitions //////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////

/**
 * This function calculates the number of modules in a linked list of modules.
 * @param target_module - a linked list of modules
 * @return - the number of modules in the specified linked list
 */
static int get_target_modules_length(target_module_t * target_module)
{
	int count = 0;
	while (target_module)
	{
		count++;
		target_module = target_module->next;
	}
	return count;
}

/**
 * This function is the registered nudge handler.  It will handle DynamoRIO's nudges.
 * @param drcontext - a pointer to the input program's machine context.  This parameter should not be
 * inspected or modified, and should only be used to be passed to the DynamoRIO API routines.
 * @param argument - The argument that the nudging process gave
 */
static void event_nudge(void *drcontext, uint64 argument)
{
	int nudge_arg = (int)argument;
	int exit_arg = (int)(argument >> 32);
	char buffer[200];

	if (nudge_arg == NUDGE_TERMINATE_PROCESS) {
		static int nudge_term_count;
		/* handle multiple from both NtTerminateProcess and NtTerminateJobObject */
		uint count = dr_atomic_add32_return_sum(&nudge_term_count, 1);
		if (count == 1) {
			dr_exit_process(exit_arg);
		}
	}
	else if (nudge_arg == NUDGE_DONE_PROCESSING_INPUT)
	{

	}
	else
	{
		snprintf(buffer, sizeof(buffer), "Unknown nudge argument: %d", nudge_arg);
		DR_ASSERT_MSG(false, buffer);
	}
}

/**
 * This function cleans up the winafl instrumentation prior to the process being killed
 * @param pid - the pid of the process about to be killed
 * @param exit_code - The exit code of the process about to be killed
 * @return - whether to skip the termination action by the application: i.e., true indicates
 * to skip it (the usual case) and false indicates to continue with the application action
 */
static bool event_soft_kill(process_id_t pid, int exit_code)
{
	/* we pass [exit_code, NUDGE_TERMINATE_PROCESS] to target process */
	dr_config_status_t res;
	res = dr_nudge_client_ex(pid, client_id,
		NUDGE_TERMINATE_PROCESS | (uint64)exit_code << 32,
		0);
	if (res == DR_SUCCESS) {
		/* skip syscall since target will terminate itself */
		return true;
	}
	/* else failed b/c target not under DR control or maybe some other
	 * error: let syscall go through
	 */
	return false;
}


/**
 * This function writes the afl bitmap of edges to the log file
 */
static void dump_winafl_data()
{
	dr_write_file(winafl_data.log, winafl_data.afl_area, MAP_SIZE);
}

/**
 * This function is the registered exception handler.  It will handle exceptions passed to it by DynamoRIO,
 * whenever the instrumented application throws an exception.
 * @param drcontext - a pointer to the input program's machine context.  This parameter should not be
 * inspected or modified, and should only be used to be passed to the DynamoRIO API routines.
 * @param excpt - A DynamoRIO exceptions struct that contains details of the exception was generated.
 * @return - whether the exception should be passed on to the client
 */
static bool onexception(void *drcontext, dr_exception_t *excpt) {
	DWORD num_written;
	DWORD exception_code = excpt->record->ExceptionCode;

	if (options.debug_mode || options.write_log)
		dr_fprintf(winafl_data.log, "Exception caught: %x\n", exception_code);

	if ((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
		(exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
		(exception_code == EXCEPTION_PRIV_INSTRUCTION) ||
		(exception_code == STATUS_HEAP_CORRUPTION) ||
		(exception_code == EXCEPTION_STACK_OVERFLOW)) {
		if (options.debug_mode) {
			dr_fprintf(winafl_data.log, "crashed\n");
		}
		else {
			winafl_data.exception_hit = true;
			WriteFile(pipe, "C", 1, &num_written, NULL);
		}
		dr_exit_process(1);
	}
	return true;
}

/**
 * This function is the callback for a new thread being created by the instrumented application.
 * @param drcontext - a pointer to the input program's machine context.  This parameter should not be
 * inspected or modified, and should only be used to be passed to the DynamoRIO API routines.
 */
static void event_thread_init(void *drcontext)
{
	void **thread_data;
	int i, num_modules, size;

	//Calculate size of tls data
	num_modules = get_target_modules_length(options.target_modules);
	size = (num_modules + 1) * sizeof(void *);

	//Allocate tls data
	thread_data = (void **)dr_thread_alloc(drcontext, size);
	memset(thread_data, 0, size);

	if (options.thread_coverage) {
		if (options.per_module_coverage)
		{
			for (i = 0; i < num_modules; i++)
				thread_data[i + 1] = winafl_data.fake_afl_area;
		}
		else
			thread_data[1] = winafl_data.fake_afl_area;
	}
	drmgr_set_tls_field(drcontext, winafl_tls_field, thread_data);

	//If we haven't set a target module, then just enable instrumentation now
	if (!options.fuzz_module[0]) {
		if (!winafl_data.instrumentation_enabled) {
			winafl_data.instrumentation_enabled = true;
			read_start_fuzz_command();
		}
		setup_shm_and_tls_regions_for_coverage(drcontext);
	}
}

/**
 * This function is the callback for a thread exiting in the instrumented application.
 * @param drcontext - a pointer to the input program's machine context.  This parameter should not be
 * inspected or modified, and should only be used to be passed to the DynamoRIO API routines.
 */
static void event_thread_exit(void *drcontext)
{
	int num_modules, size;
	void *data;

	//Calculate size of tls data
	num_modules = get_target_modules_length(options.target_modules);
	size = (num_modules + 1) * sizeof(void *);

	//Free tls data
	data = drmgr_get_tls_field(drcontext, winafl_tls_field);
	dr_thread_free(drcontext, data, size);
}

/**
 * This function looks up a module in the target module linked list by the module name
 * @param module_name - the module to find in the target module linked list
 * @return - A pointer to the target_module_t struct describing the requested module, or NULL if the
 * module was not found
 */
static target_module_t * find_target_module(const char * module_name)
{
	target_module_t * target_module = options.target_modules;
	while (target_module) {
		if (_stricmp(module_name, target_module->module_name) == 0)
			return target_module;
		target_module = target_module->next;
	}
	return NULL;
}

/**
 * This function adds a module to the linked list of target modules.
 * @param the name of the module to add
 */
static void add_target_module(const char * name)
{
	target_module_t *target_modules;

	target_modules = options.target_modules;
	options.target_modules = (target_module_t *)dr_global_alloc(sizeof(target_module_t));
	options.target_modules->index = get_target_modules_length(target_modules);
	options.target_modules->next = target_modules;
	strncpy(options.target_modules->module_name, name, BUFFER_SIZE_ELEMENTS(options.target_modules->module_name));
}

/**
 * This function is a callback for DynamoRIO's instrumentation insertion phase.  Depending on the module of the
 * passed in instruction, it will instrument the application's code to track the hit count for each
 * basic block.
 * @param drcontext - a pointer to the input program's machine context.  This parameter should not be
 * inspected or modified, and should only be used to be passed to the DynamoRIO API routines.
 * @param tag - tag is a unique identifier for the basic block fragment
 * @param bb - tag is a unique identifier for the basic block fragment
 * @param inst - The current instruction being instrumented
 * @param for_trace - for_trace indicates whether this callback is for a new basic block (false) or for adding a
 * basic block to a trace being created (true). The client has the opportunity to either include the same modifications
 * made to the standalone basic block, or to use different modifications, for the code in the trace.
 * @param translating - whether this callback is for basic block creation (false) or is for address translation (true).
 * @param user_data - User data passed from the previous DynamoRIO instrumentation phase, currently unused
 * @return - emit flags that control the behavior of basic blocks and traces when emitted into the code cache
 */
static dr_emit_flags_t instrument_bb_coverage(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
	bool for_trace, bool translating, void *user_data)
{
	app_pc start_pc;
	module_entry_t *mod_entry;
	const char *module_name;
	uint offset;
	target_module_t *target_module;
	unsigned char *afl_map;

	if (!drmgr_is_first_instr(drcontext, inst))
		return DR_EMIT_DEFAULT;

	//Find the module
	start_pc = dr_fragment_app_pc(tag);
	mod_entry = module_table_lookup(winafl_data.cache, NUM_THREAD_MODULE_CACHE, module_table, start_pc);
	if (mod_entry == NULL || mod_entry->data == NULL)
		return DR_EMIT_DEFAULT;

	//Find the module in our list of target modules
	module_name = dr_module_preferred_name(mod_entry->data);
	target_module = find_target_module(module_name);
	if (!target_module)
		return DR_EMIT_DEFAULT;

	offset = (uint)(start_pc - mod_entry->data->start);
	if (options.write_log)
		dr_fprintf(winafl_data.log, "Instrumenting module %s for bb coverage at offset %lx\n", module_name, offset);
	offset &= MAP_SIZE - 1;

	drreg_reserve_aflags(drcontext, bb, inst);

	if (options.thread_coverage) {
		reg_id_t reg;
		opnd_t opnd1, opnd2;
		instr_t *new_instr;

		drreg_reserve_register(drcontext, bb, inst, NULL, &reg);

		drmgr_insert_read_tls_field(drcontext, winafl_tls_field, bb, inst, reg);

		opnd1 = opnd_create_reg(reg);
		if (options.per_module_coverage)
			opnd2 = OPND_CREATE_MEMPTR(reg, (target_module->index + 1) * sizeof(void *));
		else
			opnd2 = OPND_CREATE_MEMPTR(reg, sizeof(void *));
		new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(bb, inst, new_instr);

		opnd1 = OPND_CREATE_MEM8(reg, offset);
		new_instr = INSTR_CREATE_inc(drcontext, opnd1);
		instrlist_meta_preinsert(bb, inst, new_instr);

		drreg_unreserve_register(drcontext, bb, inst, reg);
	}
	else {
		afl_map = winafl_data.afl_area;
		if (options.per_module_coverage)
			afl_map = target_module->afl_area;

		instrlist_meta_preinsert(bb, inst,
			INSTR_CREATE_inc(drcontext, OPND_CREATE_ABSMEM
			(&(afl_map[offset]), OPSZ_1)));
	}

	drreg_unreserve_aflags(drcontext, bb, inst);

	return DR_EMIT_DEFAULT;
}

/**
 * This function is a callback for DynamoRIO's instrumentation insertion phase.  Depending on the module of the
 * passed in instruction, it will instrument the application's code to track the hit count for each
 * basic block edge.
 * @param drcontext - a pointer to the input program's machine context.  This parameter should not be
 * inspected or modified, and should only be used to be passed to the DynamoRIO API routines.
 * @param tag - tag is a unique identifier for the basic block fragment
 * @param bb - tag is a unique identifier for the basic block fragment
 * @param inst - The current instruction being instrumented
 * @param for_trace - for_trace indicates whether this callback is for a new basic block (false) or for adding a
 * basic block to a trace being created (true). The client has the opportunity to either include the same modifications
 * made to the standalone basic block, or to use different modifications, for the code in the trace.
 * @param translating - whether this callback is for basic block creation (false) or is for address translation (true).
 * @param user_data - User data passed from the previous DynamoRIO instrumentation phase, currently unused
 * @return - emit flags that control the behavior of basic blocks and traces when emitted into the code cache
 */
static dr_emit_flags_t instrument_edge_coverage(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
	bool for_trace, bool translating, void *user_data)
{
	static bool debug_information_output = false;
	app_pc start_pc;
	module_entry_t *mod_entry;
	reg_id_t reg, reg2, reg3;
	opnd_t opnd1, opnd2;
	instr_t *new_instr;
	const char *module_name;
	uint offset;
	target_module_t *target_module;

	if (!drmgr_is_first_instr(drcontext, inst))
		return DR_EMIT_DEFAULT;

	//Find the module
	start_pc = dr_fragment_app_pc(tag);
	mod_entry = module_table_lookup(winafl_data.cache, NUM_THREAD_MODULE_CACHE, module_table, start_pc);
	if (mod_entry == NULL || mod_entry->data == NULL)
		return DR_EMIT_DEFAULT;

	//Find the module in our list of target modules
	module_name = dr_module_preferred_name(mod_entry->data);
	target_module = find_target_module(module_name);
	if (!target_module)
		return DR_EMIT_DEFAULT;

	offset = (uint)(start_pc - mod_entry->data->start);
	if (options.write_log)
		dr_fprintf(winafl_data.log, "Instrumenting module %s for edge coverage at offset %lx\n", module_name, offset);
	offset &= MAP_SIZE - 1;

	drreg_reserve_aflags(drcontext, bb, inst);
	drreg_reserve_register(drcontext, bb, inst, NULL, &reg);
	drreg_reserve_register(drcontext, bb, inst, NULL, &reg2);
	drreg_reserve_register(drcontext, bb, inst, NULL, &reg3);

	//reg2 stores AFL area, reg 3 stores previous offset

	//load the pointer to previous offset in reg3
	drmgr_insert_read_tls_field(drcontext, winafl_tls_field, bb, inst, reg3);

	//load address of shm into reg2
	if (options.thread_coverage) {
		opnd1 = opnd_create_reg(reg2);
		if (options.per_module_coverage)
			opnd2 = OPND_CREATE_MEMPTR(reg3, (target_module->index + 1) * sizeof(void *));
		else
			opnd2 = OPND_CREATE_MEMPTR(reg3, sizeof(void *));
		new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(bb, inst, new_instr);
	}
	else {
		opnd1 = opnd_create_reg(reg2);
		if(options.per_module_coverage)
			opnd2 = OPND_CREATE_INTPTR((uint64)target_module->afl_area);
		else
			opnd2 = OPND_CREATE_INTPTR((uint64)winafl_data.afl_area);
		new_instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
		instrlist_meta_preinsert(bb, inst, new_instr);
	}

	//load previous offset into register
	opnd1 = opnd_create_reg(reg);
	opnd2 = OPND_CREATE_MEMPTR(reg3, 0);
	new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
	instrlist_meta_preinsert(bb, inst, new_instr);

	//xor register with the new offset
	opnd1 = opnd_create_reg(reg);
	opnd2 = OPND_CREATE_INT32(offset);
	new_instr = INSTR_CREATE_xor(drcontext, opnd1, opnd2);
	instrlist_meta_preinsert(bb, inst, new_instr);

	//increase the counter at reg (offset ^ previous) + reg2 (afl area)
	opnd1 = opnd_create_base_disp(reg2, reg, 1, 0, OPSZ_1);
	new_instr = INSTR_CREATE_inc(drcontext, opnd1);
	instrlist_meta_preinsert(bb, inst, new_instr);

	//store the new previous offset value
	offset = (offset >> 1) & (MAP_SIZE - 1);
	opnd1 = OPND_CREATE_MEMPTR(reg3, 0);
	opnd2 = OPND_CREATE_INT32(offset);
	new_instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
	instrlist_meta_preinsert(bb, inst, new_instr);

	drreg_unreserve_register(drcontext, bb, inst, reg3);
	drreg_unreserve_register(drcontext, bb, inst, reg2);
	drreg_unreserve_register(drcontext, bb, inst, reg);
	drreg_unreserve_aflags(drcontext, bb, inst);

	return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
instrument_verbose_edge_coverage(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
	bool for_trace, bool translating, void *user_data)
{
	static bool debug_information_output = false;
	app_pc start_pc;
	module_entry_t *mod_entry;
	reg_id_t index_register, shm_reg, tls_reg, previous_reg;
	opnd_t opnd1, opnd2;
	instr_t *new_instr;
	const char *module_name;
	uint offset;
	target_module_t *target_module;
	
	if (!drmgr_is_first_instr(drcontext, inst))
		return DR_EMIT_DEFAULT;

	//Find the module
	start_pc = dr_fragment_app_pc(tag);
	mod_entry = module_table_lookup(winafl_data.cache, NUM_THREAD_MODULE_CACHE, module_table, start_pc);
	if (mod_entry == NULL || mod_entry->data == NULL)
		return DR_EMIT_DEFAULT;

	//Find the module in our list of target modules
	module_name = dr_module_preferred_name(mod_entry->data);
	target_module = find_target_module(module_name);
	if (!target_module)
		return DR_EMIT_DEFAULT;

	offset = (uint)(start_pc - mod_entry->data->start);
	if(options.write_log)
		dr_fprintf(winafl_data.log, "Instrumenting module %s for verbose edge recording at offset %lx\n", module_name, offset);

	drreg_reserve_aflags(drcontext, bb, inst);
	drreg_reserve_register(drcontext, bb, inst, NULL, &index_register); //used to hold the offset to the current index in the from/to array
	drreg_reserve_register(drcontext, bb, inst, NULL, &previous_reg); //used to hold the previous basic block's offset
	drreg_reserve_register(drcontext, bb, inst, NULL, &shm_reg); //used to hold the pointer to the shm region
	drreg_reserve_register(drcontext, bb, inst, NULL, &tls_reg); //used to hold the pointer to the tls structure

	//shm_reg stores AFL area, previous_reg stores previous offset

	//the thread local area when in non-per module coverage mode is of the form:
	//  void * previous_block_address;
	//  void * shm pointer;
	//
	//the thread local area when in per module coverage mode is of the form:
	//  void * previous_block_address;
	//  void * shm pointer for first target module;
	//  void * shm pointer for second target module;
	//  ...
	//
	//And the shm area is of the form (depending on whether we're compiled to 32/64-bit):
	//  uint32_t/uint64_t num_items
	//  void * from1
	//  void * to1
	//  void * from2
	//  void * to2
	//  ...

	//load the address of the thread local storage in tls_reg
	drmgr_insert_read_tls_field(drcontext, winafl_tls_field, bb, inst, tls_reg);

	//Get the address of the shm region into shm_reg
	opnd1 = opnd_create_reg(shm_reg);
	if (options.per_module_coverage)
		opnd2 = OPND_CREATE_MEMPTR(tls_reg, (target_module->index + 1) * sizeof(void *));
	else
		opnd2 = OPND_CREATE_MEMPTR(tls_reg, sizeof(void *));
	new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
	instrlist_meta_preinsert(bb, inst, new_instr);

	//load index to write to into a register and increment it atomically
	
	//First we set index_register to 1
	opnd1 = opnd_create_reg(index_register);
	opnd2 = OPND_CREATE_INTPTR(1);
	new_instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
	instrlist_meta_preinsert(bb, inst, new_instr);
	
	//Then we use xadd with a lock to atomically read the index and increment it
	opnd1 = OPND_CREATE_MEMPTR(shm_reg, 0);
	opnd2 = opnd_create_reg(index_register);
	new_instr = LOCK(INSTR_CREATE_xadd(drcontext, opnd1, opnd2));
	instrlist_meta_preinsert(bb, inst, new_instr);
	
	//load previous offset into register
	opnd1 = opnd_create_reg(previous_reg);
	opnd2 = OPND_CREATE_MEMPTR(tls_reg, 0);
	new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
	instrlist_meta_preinsert(bb, inst, new_instr);
	
	//times the index register by 2
	opnd1 = opnd_create_reg(index_register);
	opnd2 = OPND_CREATE_INT8(1);
	new_instr = INSTR_CREATE_shl(drcontext, opnd1, opnd2);
	instrlist_meta_preinsert(bb, inst, new_instr);

	//Now index_register contains the offset in the array to write to and previous_reg contains the previous basic block's offset
	//Let's write the previous basic basic block's edge to the array
#ifdef _M_X64
	opnd1 = opnd_create_base_disp(shm_reg, index_register, 8, 8, OPSZ_8);
#else
	opnd1 = opnd_create_base_disp(shm_reg, index_register, 4, 4, OPSZ_4);
#endif
	opnd2 = opnd_create_reg(previous_reg);
	new_instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
	instrlist_meta_preinsert(bb, inst, new_instr);

	//Now let's write the current basic block's offset to the array
#ifdef _M_X64
	opnd1 = opnd_create_base_disp(shm_reg, index_register, 8, 0x10, OPSZ_8);
	opnd2 = OPND_CREATE_INT64(offset);
#else
	opnd1 = opnd_create_base_disp(shm_reg, index_register, 4, 8, OPSZ_4);
	opnd2 = OPND_CREATE_INT32(offset);
#endif
	new_instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
	instrlist_meta_preinsert(bb, inst, new_instr);

	//store the current basic block's offset to the previous slot
	opnd1 = OPND_CREATE_MEMPTR(tls_reg, 0);
#ifdef _M_X64
	opnd2 = OPND_CREATE_INT64(offset);
#else
	opnd2 = OPND_CREATE_INT32(offset);
#endif
	new_instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
	instrlist_meta_preinsert(bb, inst, new_instr);
	
	drreg_unreserve_register(drcontext, bb, inst, tls_reg);
	drreg_unreserve_register(drcontext, bb, inst, shm_reg);
	drreg_unreserve_register(drcontext, bb, inst, previous_reg);
	drreg_unreserve_register(drcontext, bb, inst, index_register);
	drreg_unreserve_aflags(drcontext, bb, inst);

	return DR_EMIT_DEFAULT;
}

/**
 * This function is called prior to the application's function being fuzzed.  It records the application's state
 * (rsp and rip values), so that post_fuzz_handler can snap the application state back and continue fuzzing
 * without restarting the process.  It also initializes the afl_area edges bitmap that will be used by the
 * basic block instrumentations.
 * @param wrapcxt - An opaque pointer to the DynamoRIO context that this function is called in.  Should only
 * be passed to the DynamoRIO API routines.
 * @param user_data - User data field that can be assigned and passed on to the post_fuzz_handler. Currently unused.
 */
static void pre_fuzz_handler(void *wrapcxt, INOUT void **user_data)
{
	int i;
	void *drcontext;

	if (options.debug_mode || options.write_log)
		dr_fprintf(winafl_data.log, "pre_fuzz_handler started\n");

	app_pc target_to_fuzz = drwrap_get_func(wrapcxt);
	dr_mcontext_t *mc = drwrap_get_mcontext_ex(wrapcxt, DR_MC_ALL);
	drcontext = drwrap_get_drcontext(wrapcxt);

	//Save the PC and stack
	fuzz_target.xsp = mc->xsp;
	fuzz_target.func_pc = target_to_fuzz;

	//save or restore arguments
	if (fuzz_target.iteration == 0) {
		for (i = 0; i < options.num_fuz_args; i++) {
			options.func_args[i] = drwrap_get_arg(wrapcxt, i);
		}
	}
	else {
		for (i = 0; i < options.num_fuz_args; i++) {
			drwrap_set_arg(wrapcxt, i, options.func_args[i]);
		}
	}

	//Wait for the fuzzer to tell us to start
	read_start_fuzz_command();

	//Setup the SHM and TLS regions before we start tracking coverage
	setup_shm_and_tls_regions_for_coverage(drcontext);

	if (options.debug_mode || options.write_log)
		dr_fprintf(winafl_data.log, "pre_fuzz_handler finished\n");
}

static void read_start_fuzz_command()
{
	char command = 0;
	DWORD num_read;
	char buffer[256];

	//Wait for orders from the fuzzer
	if (!options.debug_mode) {
		DR_ASSERT_MSG(ReadFile(pipe, &command, 1, &num_read, NULL), "Failed to read from comms pipe");
		dr_fprintf(winafl_data.log, "Got %c from pipe\n", command);

		if (command != 'F') {
			if (command == 'Q') {
				dr_exit_process(0);
			}
			else if (command != 0) {
				memset(buffer, 0, sizeof(buffer));
				snprintf(buffer, sizeof(buffer) - 1, "unrecognized command received over pipe: %02x (%c)", command, command);
				DR_ASSERT_MSG(false, buffer);
			}
		}
	}
	else {
		debug_data.pre_hanlder_called++;
	}
}

static void setup_shm_and_tls_regions_for_coverage(void *drcontext)
{
	target_module_t * cur;

	if (options.write_log)
		dr_fprintf(winafl_data.log, "Initializing shm area\n");

	//Zeroize the shm memory area
	if (options.per_module_coverage)
	{
		for (cur = options.target_modules; cur; cur = cur->next)
		{
			if (cur->afl_area)
				memset(cur->afl_area, 0, options.verbose_edges ? EDGES_SHM_SIZE : MAP_SIZE);
		}
	}
	else if (winafl_data.afl_area)
		memset(winafl_data.afl_area, 0, options.verbose_edges ? EDGES_SHM_SIZE : MAP_SIZE);

	if(options.write_log)
		dr_fprintf(winafl_data.log, "initializing thread local data\n");

	//If needed fill in the thread local storage
	if (options.coverage_kind == COVERAGE_EDGE || options.thread_coverage || options.verbose_edges) {
		void **thread_data = (void **)drmgr_get_tls_field(drcontext, winafl_tls_field);
		thread_data[0] = 0; //previous basic block offset
		if (options.per_module_coverage)
		{
			for (cur = options.target_modules; cur; cur = cur->next)
				thread_data[cur->index + 1] = cur->afl_area;
		}
		else
			thread_data[1] = winafl_data.afl_area;
	}
}

/**
 * This function is called after to the application's function being fuzzed.  It snaps the application state back
 * and continue fuzzing without restarting the process. However, if the fuzz_iterations count has been hit, the process
 * will be ended.
 * @param wrapcxt - An opaque pointer to the DynamoRIO context that this function is called in.  Should only
 * be passed to the DynamoRIO API routines.
 * @param user_data - User data from the post_fuzz_handler. Currently unused.
 */
static void post_fuzz_handler(void *wrapcxt, void *user_data)
{
	DWORD num_written;
	DWORD num_bytes = 0;
	dr_mcontext_t *mc;

	if(options.debug_mode || options.write_log)
		dr_fprintf(winafl_data.log, "post_fuzz_handler started\n");

	if (!options.debug_mode) {
		WriteFile(pipe, "K", 1, &num_written, NULL);
	} else {
		debug_data.post_handler_called++;
	}

	fuzz_target.iteration++;
	if (fuzz_target.iteration == options.fuzz_iterations) {
		if (options.debug_mode || options.write_log)
			dr_fprintf(winafl_data.log, "Exiting due to iteration count (iteration %d max %d)", fuzz_target.iteration, options.fuzz_iterations);
		dr_exit_process(0);
	}

	mc = drwrap_get_mcontext(wrapcxt);
	mc->xsp = fuzz_target.xsp;
	mc->pc = fuzz_target.func_pc;

	drwrap_redirect_execution(wrapcxt);

	if (options.debug_mode || options.write_log)
		dr_fprintf(winafl_data.log , "post_fuzz_handler finished\n");
}

/**
 * This function is prior to the CreateFileW Windows API function to help determine what
 * files are being opened by the target application.
 * @param wrapcxt - An opaque pointer to the DynamoRIO context that this function is called in.  Should only
 * be passed to the DynamoRIO API routines.
 * @param user_data - User data pointer. Currently unused.
 */
static void createfilew_interceptor(void *wrapcxt, INOUT void **user_data)
{
	wchar_t *filenamew = (wchar_t *)drwrap_get_arg(wrapcxt, 0);

	if (options.debug_mode || options.write_log)
		dr_fprintf(winafl_data.log, "In OpenFileW, reading %ls\n", filenamew);
}

/**
 * This function is prior to the CreateFileA Windows API function to help determine what
 * files are being opened by the target application.
 * @param wrapcxt - An opaque pointer to the DynamoRIO context that this function is called in.  Should only
 * be passed to the DynamoRIO API routines.
 * @param user_data - User data pointer. Currently unused.
 */
static void createfilea_interceptor(void *wrapcxt, INOUT void **user_data)
{
	char *filename = (char *)drwrap_get_arg(wrapcxt, 0);

	if (options.debug_mode || options.write_log)
		dr_fprintf(winafl_data.log, "In OpenFileA, reading %s\n", filename);
}

static void
verfierstopmessage_interceptor_pre(void *wrapctx, INOUT void **user_data)
{
	EXCEPTION_RECORD exception_record = { 0 };
	dr_exception_t dr_exception = { 0 };
	dr_exception.record = &exception_record;
	exception_record.ExceptionCode = STATUS_HEAP_CORRUPTION;

	onexception(NULL, &dr_exception);
}


/**
 * This function is a callback for when a module is unloaded.  We remove it from the module_table so
 * we don't try to instrument it anymore.
 * @param drcontext - a pointer to the input program's machine context.  This parameter should not be
 * inspected or modified, and should only be used to be passed to the DynamoRIO API routines.
 * @param info - a module_data_t structure describing the module that was unloaded
 */
static void event_module_unload(void *drcontext, const module_data_t *info)
{
	module_table_unload(module_table, info);
}

/**
* This function is a callback for when a module is loaded.  We remove it from the module_table so
* we don't try to instrument it anymore.
* @param drcontext - a pointer to the input program's machine context.  This parameter should not be
* inspected or modified, and should only be used to be passed to the DynamoRIO API routines.
* @param info - a module_data_t structure describing the module that was unloaded
* @param loaded - whether the module is fully initialized by the loader or in the process of being loaded
*/
static void event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
	const char *module_name = info->names.exe_name;
	app_pc to_wrap = 0;

	if (module_name == NULL) {
		// In case exe_name is not defined, we will fall back on the preferred name.
		module_name = dr_module_preferred_name(info);
	}

	if (options.debug_mode)
		dr_fprintf(winafl_data.log, "Module loaded, %s\n", module_name);

	if (options.fuzz_module[0]) {
		if (strcmp(module_name, options.fuzz_module) == 0) {
			if (options.fuzz_offset) {
				to_wrap = info->start + options.fuzz_offset;
			}
			else {
				//first try exported symbols
				to_wrap = (app_pc)dr_get_proc_address(info->handle, options.fuzz_method);
				if (!to_wrap) {
					//if that fails, try with the symbol access library
					drsym_init(0);
					drsym_lookup_symbol(info->full_path, options.fuzz_method, (size_t *)(&to_wrap), 0);
					drsym_exit();
					DR_ASSERT_MSG(to_wrap, "Can't find specified method in fuzz_module");
					to_wrap += (size_t)info->start;
				}
			}
			drwrap_wrap_ex(to_wrap, pre_fuzz_handler, post_fuzz_handler, NULL, options.callconv);
		}

		if (options.debug_mode && (_stricmp(module_name, "KERNEL32.dll") == 0)) {
			to_wrap = (app_pc)dr_get_proc_address(info->handle, "CreateFileW");
			drwrap_wrap(to_wrap, createfilew_interceptor, NULL);
			to_wrap = (app_pc)dr_get_proc_address(info->handle, "CreateFileA");
			drwrap_wrap(to_wrap, createfilea_interceptor, NULL);
		}
	}

	if (_stricmp(module_name, "verifier.dll") == 0) {
		to_wrap = (app_pc)dr_get_proc_address(info->handle, "VerifierStopMessage");
		drwrap_wrap(to_wrap, verfierstopmessage_interceptor_pre, NULL);
	}

	module_table_load(module_table, info);
}

/**
 * This function is called prior to the application exiting.  It cleans up the DynamoRIO releated resources.
 */
static void event_exit(void)
{
	DWORD num_written;
	if (options.debug_mode) {
		if (debug_data.pre_hanlder_called == 0) {
			dr_fprintf(winafl_data.log, "WARNING: Target function was never called. Incorrect target_offset?\n");
		}
		else if (debug_data.post_handler_called == 0) {
			dr_fprintf(winafl_data.log, "WARNING: Post-fuzz handler was never reached. Did the target function return normally?\n");
		}
		else {
			dr_fprintf(winafl_data.log, "Everything appears to be running normally.\n");
		}

		dr_fprintf(winafl_data.log, "Coverage map follows:\n");
		dump_winafl_data();
		dr_close_file(winafl_data.log);
	}

	if (!options.fuzz_module[0] && !winafl_data.exception_hit) {
		//if we're not using the pre/post fuzz handler functions, we should let the fuzzer know we didn't crash
		WriteFile(pipe, "K", 1, &num_written, NULL);
	}

	/* destroy module table */
	module_table_destroy(module_table);

	drx_exit();
	drmgr_exit();
}

/**
 * This function is called at the time DynamoRIO is started.  It initializes the AFL bitmaps and sets up the instrumentation.
 */
static void event_init(void)
{
	char buffer[MAXIMUM_PATH];

	if (options.debug_mode || options.write_log) {
		debug_data.pre_hanlder_called = 0;
		debug_data.post_handler_called = 0;

		winafl_data.log =
			drx_open_unique_appid_file(options.logdir, dr_get_process_id(),
				"afl", "proc.log",
				DR_FILE_ALLOW_LARGE,
				buffer, BUFFER_SIZE_ELEMENTS(buffer));
		if (winafl_data.log != INVALID_FILE) {
			dr_log(NULL, LOG_ALL, 1, "winafl: log file is %s\n", buffer);
			NOTIFY(1, "<created log file %s>\n", buffer);
		}
	}

	module_table = module_table_create();

	memset(winafl_data.cache, 0, sizeof(winafl_data.cache));
	if (options.per_module_coverage)
	{
		target_module_t * target_module;
		for (target_module = options.target_modules; target_module; target_module = target_module->next)
		{
			DR_ASSERT_MSG(target_module->afl_area != NULL, "afl_area not properly setup");
			memset(target_module->afl_area, 0, options.verbose_edges  ? EDGES_SHM_SIZE : MAP_SIZE);
		}
	}
	else
	{
		DR_ASSERT_MSG(winafl_data.afl_area != NULL, "afl_area not properly setup");
		memset(winafl_data.afl_area, 0, options.verbose_edges ? EDGES_SHM_SIZE : MAP_SIZE);
	}

	fuzz_target.iteration = 0;
}

/**
 * This function sets up a pipe to communicate to the main fuzzing process.
 * @param pipe_name - the name of the pipe to setup
 * @param access - the type of access required to the pipe
 * @return - a HANDLE to the pipe that was setup
 */
static HANDLE setup_pipe(const char * pipe_name, DWORD access)
{
	char buffer[512];
	HANDLE pipe_handle;

	pipe_handle = CreateFile(
		pipe_name,      // pipe name
		access,
		0,              // no sharing
		NULL,           // default security attributes
		OPEN_EXISTING,  // opens existing pipe
		0,              // default attributes
		NULL);          // no template file

	if (pipe_handle == INVALID_HANDLE_VALUE)
	{
		snprintf(buffer, sizeof(buffer) - 1, "Error connecting to pipe '%s'", pipe_name);
		buffer[sizeof(buffer) - 1] = 0;
		DR_ASSERT_MSG(false, buffer);
	}
	return pipe_handle;
}

/**
 * Sets up the pipe used for communication to the main fuzzing process
 */
static void setup_comms_pipe()
{
	pipe = setup_pipe(options.pipe_name, GENERIC_READ | GENERIC_WRITE);
}

/**
 * This function maps a shared memory region and returns a pointer it
 * @param name - the name of the shared memory region to map
 * @param for_edges - whether the shm region is for the full edge recording or not
 * @return - a pointer to the shared memory region
 */
static unsigned char * get_shmem_region(char * name, int for_edges)
{
	HANDLE map_file;
	char buffer[512];
	char * ret;
	DWORD size;

	if (for_edges)
		size = EDGES_SHM_SIZE;
	else
		size = MAP_SIZE;

	map_file = OpenFileMapping(
		FILE_MAP_ALL_ACCESS,   // read/write access
		FALSE,                 // do not inherit the name
		name);                 // name of mapping object

	if (map_file == NULL)
	{
		snprintf(buffer, sizeof(buffer) - 1, "OpenFileMapping Failed for shm_name %s (GLE=%d)",
			name, GetLastError());
		DR_ASSERT_MSG(false, buffer);
	}

	ret = (unsigned char *)MapViewOfFile(map_file, // handle to map object
		FILE_MAP_ALL_ACCESS,  // read/write permission
		0,
		0,
		size);

	if (ret == NULL)
	{
		snprintf(buffer, sizeof(buffer) - 1, "MapViewOfFile Failed for shm_name %s (GLE=%d)",
			name, GetLastError());
		DR_ASSERT_MSG(false, buffer);
	}
	return ret;
}

/**
 * Sets up the shared memory regions for all of the target modules being tracked.
 */
static void setup_per_module_shmem() {
	target_module_t * cur;
	char name[512];

	DR_ASSERT_MSG(options.per_module_coverage, "setup_per_module_shmem should only be called when options.per_module_coverage is true");
	for (cur = options.target_modules; cur; cur = cur->next)
	{
		memset(name, 0, sizeof(name));
		snprintf(name, sizeof(name) - 1, "%s_%d", options.shm_name, cur->index);
		cur->afl_area = get_shmem_region(name, options.verbose_edges);
	}
}

/**
* Sets up the shared memory region when not tracking per module coverage.
 */
static void
setup_shmem() {
	DR_ASSERT_MSG(!options.per_module_coverage, "setup_shmem should only be called when options.per_module_coverage is false");
	winafl_data.afl_area = get_shmem_region(options.shm_name, options.verbose_edges);
}

/**
 * Opens the module file and adds the modules listed in it to the target_module linked list
 */
static void read_module_file(const char * filename)
{
	FILE *fp;
	char line[1024];

	fp = fopen(filename, "rb");
	USAGE_CHECK(fp, "Couldn't open module file");

	while (fgets(line, sizeof(line), fp))
	{
		if (line[strlen(line) - 1] == '\n')
			line[strlen(line) - 1] = 0;
		if (line[strlen(line) - 1] == '\r')
			line[strlen(line) - 1] = 0;
		add_target_module(line);
	}

	fclose(fp);
}

/**
 * Parses the command line arguments passed to DynamoRIO and sets up the global options struct
 * @param id - The client_id assigned by DynamoRIO to this instrance
 * @param argc - the number of arguments in the argv parameter
 * @param argv - the command line arguments passed to DynamoRIO
 */
static void options_init(client_id_t id, int argc, const char *argv[])
{
	int i;
	const char *token;
	char buffer[512];
	/* default values */
	options.nudge_kills = true;
	options.verbose_edges = false;
	options.debug_mode = false;
	options.write_log = false;
	options.thread_coverage = true;
	options.per_module_coverage = false;
	options.coverage_kind = COVERAGE_EDGE;
	options.target_modules = NULL;
	options.fuzz_module[0] = 0;
	options.fuzz_method[0] = 0;
	options.fuzz_offset = 0;
	options.fuzz_iterations = 1;
	options.func_args = NULL;
	options.num_fuz_args = 0;
	options.callconv = DRWRAP_CALLCONV_DEFAULT;
	dr_snprintf(options.logdir, BUFFER_SIZE_ELEMENTS(options.logdir), ".");

	strcpy(options.pipe_name, "\\\\.\\pipe\\afl_pipe_default");
	strcpy(options.shm_name, "afl_shm_default");

	for (i = 1/*skip client*/; i < argc; i++) {
		token = argv[i];
		if (strcmp(token, "-no_nudge_kills") == 0)
			options.nudge_kills = false;
		else if (strcmp(token, "-verbose_edges") == 0)
		{
			options.verbose_edges = true;
			options.coverage_kind = COVERAGE_EDGE;
			options.thread_coverage = true;
		}
		else if (strcmp(token, "-nudge_kills") == 0)
			options.nudge_kills = true;
		else if (strcmp(token, "-no_thread_coverage") == 0)
			options.thread_coverage = false;
		else if (strcmp(token, "-per_module_coverage") == 0)
			options.per_module_coverage = true;
		else if (strcmp(token, "-debug") == 0)
			options.debug_mode = true;
		else if (strcmp(token, "-write_log") == 0)
			options.write_log = true;
		else if (strcmp(token, "-logdir") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing logdir path");
			strncpy(options.logdir, argv[++i], BUFFER_SIZE_ELEMENTS(options.logdir));
		}
		else if (strcmp(token, "-fuzzer_id") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing fuzzer id");
			strcpy(options.pipe_name, "\\\\.\\pipe\\afl_pipe_");
			strcat(options.pipe_name, argv[i + 1]);
			strcpy(options.shm_name, "afl_shm_");
			strcat(options.shm_name, argv[i + 1]);
			i++;
		}
		else if (strcmp(token, "-covtype") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing coverage type");
			token = argv[++i];
			if (strcmp(token, "bb") == 0) options.coverage_kind = COVERAGE_BB;
			else if (strcmp(token, "edge") == 0) options.coverage_kind = COVERAGE_EDGE;
			else USAGE_CHECK(false, "invalid coverage type");
		}
		else if (strcmp(token, "-coverage_module") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing module");
			add_target_module(argv[++i]);
		}
		else if (strcmp(token, "-coverage_module_file") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing module file");
			read_module_file(argv[++i]);
		}
		else if (strcmp(token, "-target_module") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing module");
			strncpy(options.fuzz_module, argv[++i], BUFFER_SIZE_ELEMENTS(options.fuzz_module));
		}
		else if (strcmp(token, "-target_method") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing method");
			strncpy(options.fuzz_method, argv[++i], BUFFER_SIZE_ELEMENTS(options.fuzz_method));
		}
		else if (strcmp(token, "-fuzz_iterations") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing number of iterations");
			options.fuzz_iterations = atoi(argv[++i]);
		}
		else if (strcmp(token, "-nargs") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing number of arguments");
			options.num_fuz_args = atoi(argv[++i]);
		}
		else if (strcmp(token, "-target_offset") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing offset");
			options.fuzz_offset = strtoul(argv[++i], NULL, 0);
		}
		else if (strcmp(token, "-verbose") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing -verbose number");
			token = argv[++i];
			if (dr_sscanf(token, "%u", &verbose) != 1) {
				USAGE_CHECK(false, "invalid -verbose number");
			}
		}
		else if (strcmp(token, "-call_convention") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing calling convention");
			++i;
			if (strcmp(argv[i], "stdcall") == 0)
				options.callconv = DRWRAP_CALLCONV_CDECL;
			else if (strcmp(argv[i], "fastcall") == 0)
				options.callconv = DRWRAP_CALLCONV_FASTCALL;
			else if (strcmp(argv[i], "thiscall") == 0)
				options.callconv = DRWRAP_CALLCONV_THISCALL;
			else if (strcmp(argv[i], "ms64") == 0)
				options.callconv = DRWRAP_CALLCONV_MICROSOFT_X64;
			else
				NOTIFY(0, "Unknown calling convention, using default value instead.\n");
		}
		else {
			NOTIFY(0, "UNRECOGNIZED OPTION: \"%s\"\n", token);
			memset(buffer, 0, sizeof(buffer));
			snprintf(buffer, sizeof(buffer) - 1, "Invalid option: %s", token);
			USAGE_CHECK(false, buffer);
		}
	}

	if (options.verbose_edges && (options.coverage_kind != COVERAGE_EDGE || options.thread_coverage != true)) {
		USAGE_CHECK(false, "If verbose_edges is specified, then the coverage kind must be edge and thread coverage must be on");
	}

	if (options.fuzz_module[0] && (options.fuzz_offset == 0) && (options.fuzz_method[0] == 0)) {
		USAGE_CHECK(false, "If fuzz_module is specified, then either fuzz_method or fuzz_offset must be as well");
	}

	if (options.num_fuz_args) {
		options.func_args = (void **)dr_global_alloc(options.num_fuz_args * sizeof(void *));
	}

	if (strlen(options.fuzz_module) == 0 && strlen(options.fuzz_method) == 0 && options.fuzz_offset == 0
		&& options.fuzz_iterations != 1) {
		USAGE_CHECK(false, "If fuzz_module is specified, then either fuzz_method or fuzz_offset must be as well");
	}
}

/**
 * The main entrypoint from DynamoRIO
 * @param id - The client_id assigned by DynamoRIO to this instrance
 * @param argc - the number of command line arguments in the argv parameter
 * @param argv - the command line arguments passed to DynamoRIO
 */
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
	target_module_t * cur;
	drreg_options_t ops = { sizeof(ops), 2 /*max slots needed: aflags*/, false };
	size_t size;

	dr_set_client_name("WinAFL", "");

	drmgr_init();
	drx_init();
	drreg_init(&ops);
	drwrap_init();

	options_init(id, argc, argv);

	dr_register_exit_event(event_exit);

	drmgr_register_exception_event(onexception);

	if (options.verbose_edges) {
		drmgr_register_bb_instrumentation_event(NULL, instrument_verbose_edge_coverage, NULL);
	}
	else  if (options.coverage_kind == COVERAGE_BB) {
		drmgr_register_bb_instrumentation_event(NULL, instrument_bb_coverage, NULL);
	}
	else if (options.coverage_kind == COVERAGE_EDGE) {
		drmgr_register_bb_instrumentation_event(NULL, instrument_edge_coverage, NULL);
	}

	drmgr_register_module_load_event(event_module_load);
	drmgr_register_module_unload_event(event_module_unload);
	dr_register_nudge_event(event_nudge, id);

	client_id = id;

	if (options.nudge_kills)
		drx_register_soft_kills(event_soft_kill);

	winafl_data.instrumentation_enabled = false;
	winafl_data.exception_hit = false;

	if (options.thread_coverage || options.coverage_kind == COVERAGE_EDGE) {
		size = MAP_SIZE;
		if (options.verbose_edges)
			size = EDGES_SHM_SIZE;
		winafl_data.fake_afl_area = (unsigned char *)dr_global_alloc(size);
		memset(winafl_data.fake_afl_area, 0, size);
	}

	//Allocate the afl area
	if (!options.debug_mode) {
		setup_comms_pipe();
		if (options.per_module_coverage)
			setup_per_module_shmem();
		else
			setup_shmem();
	}
	else
	{
		if (options.per_module_coverage)
		{
			for (cur = options.target_modules; cur; cur = cur->next)
				cur->afl_area = (unsigned char *)dr_global_alloc(MAP_SIZE);
		}
		else
			winafl_data.afl_area = (unsigned char *)dr_global_alloc(MAP_SIZE);
	}

	if (options.coverage_kind == COVERAGE_EDGE || options.thread_coverage) {
		winafl_tls_field = drmgr_register_tls_field();
		if (winafl_tls_field == -1) {
			DR_ASSERT_MSG(false, "error reserving TLS field");
		}
		drmgr_register_thread_init_event(event_thread_init);
		drmgr_register_thread_exit_event(event_thread_exit);
	}

	event_init();

	if(options.write_log)
		dr_fprintf(winafl_data.log, "Done with dr_client_main\n");
}
