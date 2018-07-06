#pragma once
#include "driver.h"

#include <instrumentation.h>

#ifdef __cplusplus
#define FUNC_PREFIX extern "C"
#else
#define FUNC_PREFIX
#endif

FUNC_PREFIX void * wmp_create(char * options, instrumentation_t * instrumentation, void * instrumentation_state,
	mutator_t * mutator, void * mutator_state);
FUNC_PREFIX void wmp_cleanup(void * driver_state);
FUNC_PREFIX int wmp_test_input(void * driver_state, char * buffer, size_t length);
FUNC_PREFIX int wmp_test_next_input(void * driver_state);
FUNC_PREFIX char * wmp_get_last_input(void * driver_state, int * length);
FUNC_PREFIX char * wmp_help(void);

struct wmp_state
{
	//Options
	char * path;          //The path to wmplayer.exe
	char * extension;     //The file extension of the input files to wmplayer.exe
	int timeout;          //Maximum number of seconds to allow wmplayer.exe to run
	char * test_filename; //The filename that we're going to write our test input to
	double input_ratio;   //the ratio of the maximum input size

	//The handle to the wmplayer.exe instance
	HANDLE process;

	//command line of the fuzzed process
	char * cmd_line;

	//time wmplayer.exe started
	time_t start_time;

	//The instrumentation module
	instrumentation_t * instrumentation;

	//The instrumentation's state
	void * instrumentation_state;

	mutator_t * mutator;
	void * mutator_state;
	char * mutate_buffer;
	size_t mutate_buffer_length;
	int mutate_last_size;

	int fuzz_result;
};
typedef struct wmp_state wmp_state_t;
