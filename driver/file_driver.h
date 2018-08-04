#pragma once
#include "driver.h"
#include <instrumentation.h>

void * file_create(char * options, instrumentation_t * instrumentation, void * instrumentation_state,
	mutator_t * mutator, void * mutator_state);
void file_cleanup(void * driver_state);
int file_test_input(void * driver_state, char * buffer, size_t length);
int file_test_next_input(void * driver_state);
char * file_get_last_input(void * driver_state, int * length);
int file_help(char ** help_str);

struct file_state
{
	//Options
	char * path;          //The path to the fuzzed executable
	char * arguments;     //Arguments to give the binary
	char * extension;     //The file extension of the input files to the fuzzed process
	int timeout;          //Maximum number of seconds to allow the executable to run
	char * test_filename; //The filename that we're going to write our test input to
	double input_ratio;   //the ratio of the maximum input size

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
	char * mutate_buffer;
	size_t mutate_buffer_length;
	int mutate_last_size;
};
typedef struct file_state file_state_t;
