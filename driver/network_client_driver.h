#pragma once
#include "driver.h"
#include "instrumentation.h"
#include <global_types.h>

#ifndef _WIN32 // Linux
#include <sys/types.h> // pid_t
#endif

void * network_client_create(char * options, instrumentation_t * instrumentation, void * instrumentation_state,
	mutator_t * mutator, void * mutator_state);
void network_client_cleanup(void * driver_state);
int network_client_test_input(void * driver_state, char * buffer, size_t length);
int network_client_test_next_input(void * driver_state);
char * network_client_get_last_input(void * driver_state, int * length);
int network_client_help(char ** help_str);

struct network_client_state
{
	//Options
	char * path;            //The path to the fuzzed executable
	char * arguments;       //Arguments to give the binary
	int timeout;            //Maximum number of seconds to allow the executable to run
	char * target_ip;       //The IP address to send the fuzzed data to
	int lport;        //The port to send the fuzzed data to
	double input_ratio;     //the ratio of the maximum input size
	int * sleeps;           //How many milliseconds to sleep between inputs
	int sleeps_count;       //The number of items in the sleeps array

	//The handle to the fuzzed process instance
	#ifdef _WIN32
	HANDLE process;
	#else
	pid_t process;
	#endif

	//command line of the fuzzed process
	char * cmd_line;

	//The instrumentation module
	instrumentation_t * instrumentation;

	//The instrumentation's state
	void * instrumentation_state;

	mutator_t * mutator;
	void * mutator_state;

	// it'd be nice if this could be size_t, but mutator function
	// get_input_info requires ints.
	int num_inputs;
	char ** mutate_buffers;
	size_t * mutate_buffer_lengths;
	size_t * mutate_last_sizes;
};
typedef struct network_client_state network_client_state_t;
