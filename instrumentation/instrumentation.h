#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <Windows.h>

#ifdef INSTRUMENTATION_EXPORTS
#define INSTRUMENTATION_API __declspec(dllexport)
#elif defined(INSTRUMENTATION_NO_IMPORT)
#define INSTRUMENTATION_API
#else
#define INSTRUMENTATION_API __declspec(dllimport)
#endif

#define FUZZ_NONE  0
#define FUZZ_HANG  1
#define FUZZ_CRASH 2

struct instrumentation_edge
{
#ifdef _M_X64
	uint64_t from;
	uint64_t to;
#else
	uint32_t from;
	uint32_t to;
#endif
};
typedef struct instrumentation_edge instrumentation_edge_t;

struct instrumentation_edges
{
#ifdef _M_X64
	uint64_t num_edges;
#else
	uint32_t num_edges;
#endif
	instrumentation_edge_t edges[1];
};
typedef struct instrumentation_edges instrumentation_edges_t;

struct instrumentation
{
	void *(*create)(char * options, char * state);
	void(*cleanup)(void * instrumentation_state);
	void *(*merge)(void * instrumentation_state, void * other_instrumentation_state);

	char * (*get_state)(void * instrumentation_state);
	void(*free_state)(char * state);
	int(*set_state)(void * instrumentation_state, char * state);

	int(*enable)(void * instrumentation_state, HANDLE * process, char * cmd_line, char * input, size_t input_length);
	int(*is_new_path)(void * instrumentation_state, int * process_status);

	//Optional
	int (*get_module_info)(void * instrumentation_state, int index, int * is_new, char ** module_name, char ** info, int * size);
	instrumentation_edges_t * (*get_edges)(void * instrumentation_state, int index);
	void(*wait_for_target_completion)(void * instrumentation_state, int timeout);
};
typedef struct instrumentation instrumentation_t;
