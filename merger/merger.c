//This program merges multiple sets of instrumentation data into one
//instrumentation state.  The resulting instrumentation state will include the
//tracked coverage from all of the input instrumentation states. This allows
//multiple instances of the fuzzer to share instrumentation data, and ignore
//paths that the other fuzzer found.

#include <instrumentation.h>
#include <instrumentation_factory.h>
#include <utils.h>

#include <stdio.h>
#include <stdlib.h>


/**
* This function prints out the usage information for the merger and the available instrumentations.
* @param program_name - the name of the program currently being run (for use in the outputted message)
*/
void usage(char * program_name)
{
	char * help_text;
	printf(
		"Usage: %s instrumentation_name [-i instrumentation_options] output_file input_file [input_file ...]\n"
		"\n"
		"Options:\n"
		"\t -i instrumentation_options   Set the options for the instrumentation\n"
		"\t output_file                  Set the file containing that the combined instrumentation state should dump to\n"
		"\t input_file                   Set the file containing that the instrumentation state should load from\n"
		"\n",
		program_name
	);

#define PRINT_HELP(x, y) \
	x = y;               \
	if(x) {              \
		puts(x);         \
		free(x);         \
	}

	PRINT_HELP(help_text, instrumentation_help());
	exit(1);
}


int main(int argc, char ** argv)
{
	instrumentation_t * instrumentation;
	int instrumentation_length, argv_index;
	char *instrumentation_options = NULL, *instrumentation_state_string = NULL, *instrumentation_state_dump_file = NULL;
	void * instrumentation_state = NULL, *new_instrumentation_state = NULL, *merged_instrumentation_state = NULL;

	if (argc < 3)
		usage(argv[0]);

	if (setup_logging(NULL))
	{
		printf("Failed setting up logging, exitting\n");
		return 1;
	}

	instrumentation = instrumentation_factory(argv[1]);
	if (!instrumentation)
		FATAL_MSG("Unknown instrumentation (%s)", argv[1]);

	if (strcmp("-i", argv[2]))
	{
		argv_index = 3;
		instrumentation_state_dump_file = argv[2];
	}
	else
	{
		instrumentation_options = argv[3];
		argv_index = 5;
		instrumentation_state_dump_file = argv[4];
	}


	for (; argv_index < argc; argv_index++)
	{
		//Load the instrumentation state from disk
		instrumentation_length = read_file(argv[argv_index], &instrumentation_state_string);
		if (instrumentation_length <= 0)
			FATAL_MSG("Could not read instrumentation file or empty instrumentation file: %s", argv[argv_index]);
		new_instrumentation_state = instrumentation->create(instrumentation_options, instrumentation_state_string);
		if (!instrumentation)
			FATAL_MSG("Bad options/state for instrumentation file %s", argv[argv_index]);
		free(instrumentation_state_string);

		if (!instrumentation_state)
			instrumentation_state = new_instrumentation_state;
		else
		{
			merged_instrumentation_state = instrumentation->merge(instrumentation_state, new_instrumentation_state);
			instrumentation->cleanup(instrumentation_state);
			instrumentation->cleanup(new_instrumentation_state);
			instrumentation_state = merged_instrumentation_state;
		}
	}

	instrumentation_state_string = instrumentation->get_state(instrumentation_state);
	if (instrumentation_state_string)
	{
		write_buffer_to_file(instrumentation_state_dump_file, instrumentation_state_string, strlen(instrumentation_state_string));
		instrumentation->free_state(instrumentation_state_string);
	}
	else
		WARNING_MSG("Couldn't dump instrumentation state to file %s", instrumentation_state_dump_file);

	//Cleanup the objects and exit
	instrumentation->cleanup(instrumentation_state);
	free(instrumentation);
	return 0;
}
