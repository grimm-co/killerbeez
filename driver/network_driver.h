#pragma once
#include "driver.h"
#include "instrumentation.h"
#include <global_types.h>

void * network_create(char * options, instrumentation_t * instrumentation, void * instrumentation_state,
	mutator_t * mutator, void * mutator_state);
void network_cleanup(void * driver_state);
int network_test_input(void * driver_state, char * buffer, size_t length);
int network_test_next_input(void * driver_state);
char * network_get_last_input(void * driver_state, int * length);
int network_help(char ** help_str);

struct network_state
{
	//Options
	char * path;            //The path to the fuzzed executable
	char * arguments;       //Arguments to give the binary
	int timeout;            //Maximum number of seconds to allow the executable to run
	char * target_ip;       //The IP address to send the fuzzed data to
	int target_port;        //The port to send the fuzzed data to
	int target_udp;         //Is the network driver hitting a udp port (1) or tcp port (0)
	int skip_network_check; //Don't wait for the target_port to be listening
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
typedef struct network_state network_state_t;
