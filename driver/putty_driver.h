#pragma once
#include "driver.h"
#include "instrumentation.h"
#include <global_types.h>

void * putty_create(char * options, instrumentation_t * instrumentation, void * instrumentation_state,
	mutator_t * mutator, void * mutator_state);
void putty_cleanup(void * driver_state);
int putty_test_input(void * driver_state, char * buffer, size_t length);
int putty_test_next_input(void * driver_state);
char * putty_get_last_input(void * driver_state, int * length);
char * putty_help(void);

struct putty_state
{
	//Options
	char * path;            //The path to the fuzzed executable
	char * arguments;       //Arguments to give the binary
	int timeout;            //Maximum number of seconds to allow the executable to run
	char * ip;       //The IP address to send the fuzzed data to
	int lport;        //The port to send the fuzzed data to
	double input_ratio;     //the ratio of the maximum input size
	int * sleeps;           //How many milliseconds to sleep between inputs
	int sleeps_count;       //The number of items in the sleeps array

	//The handle to the fuzzed process instance
	HANDLE process;

	//command line of the fuzzed process
	char * cmd_line;

	//The instrumentation module
	instrumentation_t * instrumentation;

	//The instrumentation's state
	void * instrumentation_state;

	mutator_t * mutator;
	void * mutator_state;

	int num_inputs;
	char ** mutate_buffers;
	size_t * mutate_buffer_lengths;
	int * mutate_last_sizes;
};
typedef struct putty_state putty_state_t;
