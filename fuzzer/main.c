#include <global_types.h>
#include <driver.h>
#include <driver_factory.h>
#include <mutator_factory.h>
#include <instrumentation.h>
#include <instrumentation_factory.h>
#include <utils.h>

#ifdef _WIN32
#include <io.h>
#include <Shlwapi.h>
#define F_OK 00     // for checking if a file is open/writable
#define W_OK 02
#include "XGetopt.h"
#else
#include <libgen.h>     // dirname
#include <unistd.h>     // access, F_OK, W_OK, getopt
#include <sys/stat.h>   // mkdir
#include <errno.h>      // output directory creation
#endif

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/**
 * This function prints out the usage information for the fuzzer and each of the individual components
 * @param program_name - the name of the program currently being run (for use in the outputted message)
 * @param mutator_directory - the directory to look for mutators in, when printing out the mutator help information
 */
void usage(char * program_name, char * mutator_directory)
{
	printf(
"\n"
"Usage: %s\n"
"         driver_name instrumentation_name mutator_name [options]\n"
"\n"
"Options:\n"
"  -d driver_options              JSON filename with options for the driver\n"
"  -hd                            Get help text about drivers\n"
"  -hi                            Get help text about instrumentation\n"
"  -hl                            Get help text about logging\n"
"  -hm                            Get help text about mutators\n"
"  -i instrumentation_options     JSON filename with options for the instrumentation\n"
"  -j instrumentation_state_file  Set the file containing that the\n"
"                                   instrumentation state should dump to\n"
"  -k instrumentation_state_file  Set the file containing that the\n"
"                                   instrumentation state should load from\n"
"  -l logging_options             JSON filename with options for logging\n"
"  -m mutator_options             JSON filename with options for the mutator\n"
"  -n num_iterations              Limit the number of iterations to run\n"
"                                   (optional, infinite by default)\n"
"  -o output_directory            The directory to write files which cause a\n"
"                                   crash or hang\n"
"  -p mutator_directory           The directory to look for mutator DLLs in\n"
"                                   (must be specified to view help for\n"
"                                   specific mutators)\n"
"  -r mutator_state               Set the state that the mutator should load\n"
"  -s seed                        The seed file to use\n"
"  -t mutator_state_file          Set the file containing that the mutator\n"
"                                   state should dump to\n"
"  -u mutator_state_file          Set the file containing that the mutator\n"
"                                   state should load from\n"
"\n\n",
		program_name
	);

	exit(1);
}

//The global module state objects
static driver_t * driver = NULL;
static mutator_t * mutator = NULL;
static void * mutator_state = NULL;
static instrumentation_t * instrumentation = NULL;
static void * instrumentation_state = NULL;

static void cleanup_modules(void)
{
	if(driver)
		driver->cleanup(driver->state);
	if(instrumentation && instrumentation_state)
		instrumentation->cleanup(instrumentation_state);
	if(mutator && mutator_state)
		mutator->cleanup(mutator_state);
	free(driver);
	free(instrumentation);
	free(mutator);
}

static void sigint_handler(int sig)
{
	CRITICAL_MSG("CTRL-c detected, exiting\n");
	cleanup_modules();
	exit(0);
}

#define NUM_ITERATIONS_INFINITE -1

#define PRINT_HELP(x) \
		puts(x);      \
		free(x);

int main(int argc, char ** argv)
{
	char *driver_name, *driver_options = NULL,
		*mutator_name, *mutator_options = NULL, *mutator_saved_state = NULL,
		*mutation_state_dump_file = NULL, *mutation_state_load_file = NULL,
		*mutate_buffer = NULL, *mutator_directory = NULL, *mutator_directory_cli = NULL,
		*logging_options = NULL,
		*seed_file = NULL, *seed_buffer = NULL,
		*instrumentation_name = NULL, *instrumentation_options = NULL, 
		*instrumentation_state_string = NULL, *instrumentation_state_load_file = NULL,
		*instrumentation_state_dump_file = NULL;
	int seed_length = 0, mutate_length = 0, instrumentation_length = 0, mutator_state_length;
	time_t fuzz_begin_time;
	int i = 0, iteration = 0, fuzz_result = FUZZ_NONE, new_path = 0;
	char filename[MAX_PATH];
	char filehash[256];
	char c;
	char * directory;

	//Default options
	int num_iterations = NUM_ITERATIONS_INFINITE; //default to infinite
	char * output_directory = "output";

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Mutator Setup /////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	if (!mutator_directory)
	{
		char * mutator_repo_dir = getenv("KILLERBEEZ_MUTATORS");
		//If the environment variable KILLERBEEZ_MUTATORS is set, try to autodetect the directory based on the repo build path
		if (mutator_repo_dir) 
		{
			mutator_directory = (char *)malloc(MAX_PATH + 1);
			if (!mutator_directory)
			{
				printf("Couldn't get memory for default mutator_directory");
				return 1;
			}
			memset(mutator_directory, 0, MAX_PATH + 1);
#ifdef _WIN32

#if defined(_M_X64) || defined(__x86_64__)
#ifdef _DEBUG
			snprintf(mutator_directory, MAX_PATH, "%s\\..\\build\\x64\\Debug\\mutators\\", mutator_repo_dir);
#else
			snprintf(mutator_directory, MAX_PATH, "%s\\..\\build\\x64\\Release\\mutators\\", mutator_repo_dir);
#endif
#else
#ifdef _DEBUG
			snprintf(mutator_directory, MAX_PATH, "%s\\..\\build\\X86\\Debug\\mutators\\", mutator_repo_dir);
#else
			snprintf(mutator_directory, MAX_PATH, "%s\\..\\build\\X86\\Release\\mutators\\", mutator_repo_dir);
#endif
#endif

#else
			snprintf(mutator_directory, MAX_PATH, "%s/../build/mutators/", mutator_repo_dir);
#endif
		}
		else
		{
#ifdef _WIN32
			mutator_directory = filename_relative_to_binary_dir("..\\mutators\\");
#else // LINUX and APPLE
			mutator_directory = filename_relative_to_binary_dir("../mutators");
#endif
		}
	}
	
	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Parse Arguments ///////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////
	while ((c = getopt(argc, argv, "d:h:i:j:k:l:m:n:o:p:r:s:t:u:")) != -1)
	{
		switch (c)
		{
			case 'd':
				read_file(optarg, &driver_options);
				break;
			case 'h':
				if (optarg == NULL) {
					usage(argv[0], mutator_directory);
				} else if (strcmp(optarg, "l") == 0) {
					PRINT_HELP(logging_help());
				} else if (strcmp(optarg, "d") == 0) {
					PRINT_HELP(driver_help());
				} else if (strcmp(optarg, "i") == 0) {
					PRINT_HELP(instrumentation_help());
				} else if (strcmp(optarg, "m") == 0) {
					PRINT_HELP(mutator_help(mutator_directory));
				}
				exit(1);
			case 'i':
				read_file(optarg, &instrumentation_options);
				break;
			case 'j':
				instrumentation_state_dump_file = optarg;
				break;
			case 'k':
				instrumentation_state_load_file = optarg;
				break;
			case 'l':
				read_file(optarg, &logging_options);
				break;
			case 'm':
				read_file(optarg, &mutator_options);
				break;
			case 'n':
				num_iterations = atoi(optarg);
				break;
			case 'o':
				output_directory = optarg;
				break;
			case 'p':
				mutator_directory_cli = optarg;
				break;
			case 'r':
				mutator_saved_state = optarg;
				break;
			case 's':
				seed_file = optarg;
				break;
			case 't':
				mutation_state_dump_file = optarg;
				break;
			case 'u':
				mutation_state_load_file = optarg;
				break;
		}
	}

	// Make sure we have enough positional arguments
	if (argc-optind < 3)
	{
		usage(argv[0], mutator_directory);
	}
	driver_name = argv[optind];
	instrumentation_name = argv[optind+1];
	mutator_name = argv[optind+2];

	if (setup_logging(logging_options))
	{
		printf("Failed setting up logging, exiting\n");
		return 1;
	}

	signal(SIGINT, sigint_handler);

	//Check number of iterations for valid number of rounds
	if (num_iterations != NUM_ITERATIONS_INFINITE && num_iterations <= 0)
		FATAL_MSG("Invalid number of iterations %d", num_iterations);

	if (mutator_directory_cli) 
	{ 
		free(mutator_directory);
		mutator_directory = strdup(mutator_directory_cli); 
		mutator_directory_cli = NULL;
	}
	if (!mutator_directory)
		FATAL_MSG("Mutator directory was not found in default location. You may need to pass the -md flag.");

	if (instrumentation_state_dump_file) {
		strncpy(filename, instrumentation_state_dump_file, sizeof(filename));

		#ifdef _WIN32
		PathRemoveFileSpec(filename);
		#else
		dirname(filename);
		#endif

		if (access(filename, W_OK))
			FATAL_MSG("The provided instrumentation_state_dump_file filename (%s) is not writeable", instrumentation_state_dump_file);
	}
	if (mutation_state_dump_file) {
		strncpy(filename, mutation_state_dump_file, sizeof(filename));

		#ifdef _WIN32
		PathRemoveFileSpec(filename);
		#else
		dirname(filename);
		#endif

		if (access(filename, W_OK))
			FATAL_MSG("The provided mutation_state_dump_file filename (%s) is not writeable", mutation_state_dump_file);
	}

#ifdef _WIN32
	#define create_output_directory(name)                                                \
		snprintf(filename, sizeof(filename), "%s" name, output_directory);               \
		if(!CreateDirectory(filename, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) { \
			FATAL_MSG("Unable to create directory %s", filename);                        \
		}
#else
	#define create_output_directory(name)                                                \
		snprintf(filename, sizeof(filename), "%s" name, output_directory);               \
		if (mkdir(filename, 0775) == -1) {                                               \
			if (errno != EEXIST)                                                         \
				FATAL_MSG("Unable to create directory %s", filename);                    \
		} // otherwise, it already exists and we don't need to do anything
#endif

	//Setup the output directory
	create_output_directory("");			// creates ./output
	create_output_directory("/crashes");	// creates ./output/crashes and so on
	create_output_directory("/hangs");
	create_output_directory("/new_paths");

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Ojbect Setup //////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	//Load the instrumentation state from disk (if specified, and create the instrumentation
	if (instrumentation_state_load_file)
	{
		instrumentation_length = read_file(instrumentation_state_load_file, &instrumentation_state_string);
		if (instrumentation_length <= 0)
			FATAL_MSG("Could not read instrumentation file or empty instrumentation file: %s", instrumentation_state_load_file);
	}

	// NULL means instrumentation failed to initialize.
	instrumentation = instrumentation_factory(instrumentation_name);
	if (!instrumentation)
	{
		free(instrumentation_state_string);
		FATAL_MSG("Unknown instrumentation '%s'", instrumentation_name);
	}

	instrumentation_state = instrumentation->create(instrumentation_options, instrumentation_state_string);
	if (!instrumentation_state)
	{
		free(instrumentation_state_string);
		FATAL_MSG("Bad options/state for instrumentation %s", instrumentation_name);
	}

	free(instrumentation_state_string);

	//Load the seed buffer from a file
	if (seed_file)
	{
		seed_length = read_file(seed_file, &seed_buffer);
		if (seed_length <= 0)
			FATAL_MSG("Could not read seed file or empty seed file: %s", seed_file);
	}

	if (!seed_buffer)
		FATAL_MSG("No seed file or seed id specified.");

	if (mutation_state_load_file)
	{
		free(mutator_saved_state);
		mutator_state_length = read_file(mutation_state_load_file, &mutator_saved_state);
		if (mutator_state_length <= 0)
			FATAL_MSG("Could not read mutator saved state from file: %s", mutation_state_load_file);
	}

	//Create the mutator
	mutator = mutator_factory_directory(mutator_directory, mutator_name);
	if (!mutator)
		FATAL_MSG("Unknown mutator (%s)", mutator_name);
	free(mutator_directory);
	mutator_state = mutator->create(mutator_options, mutator_saved_state, seed_buffer, seed_length);
	if (!mutator_state)
		FATAL_MSG("Bad mutator options or saved state for mutator %s", mutator_name);
	free(mutator_saved_state);
	free(seed_buffer);

	//Create the driver
	driver = driver_all_factory(driver_name, driver_options, instrumentation, instrumentation_state, mutator, mutator_state);
	if (!driver)
	{
		FATAL_MSG("Unknown driver '%s' or bad options: \n\n\tdriver options: %s\n\n"\
			"\tmutator options: %s\n\n\tPass %s -hd for help.\n", driver_name,
			driver_options, mutator_options, argv[0]);
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Main Fuzz Loop ////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	fuzz_begin_time = time(NULL);

	//Copy the input, mutate it, and run the fuzzed program
	for (iteration = 0; num_iterations == NUM_ITERATIONS_INFINITE || iteration < num_iterations; iteration++)
	{
		DEBUG_MSG("Fuzzing the %d iteration", iteration);

		fuzz_result = driver->test_next_input(driver->state);

		if (fuzz_result < 0)
		{
			if(fuzz_result == -2)
				WARNING_MSG("The mutator has run out of mutations to test after %d iterations", iteration);
			else
				ERROR_MSG("The driver failed to test the target program, fuzz_result was %d",fuzz_result);
			break;
		}

		new_path = instrumentation->is_new_path(instrumentation_state);
		if (new_path < 0)
		{
			ERROR_MSG("The instrumentation failed to determine the fuzzed process's fuzz_result");
			break;
		}

		directory = NULL;
		if (fuzz_result == FUZZ_CRASH) {
			directory = "crashes";
			CRITICAL_MSG("Found %s", directory);
		} else if (fuzz_result == FUZZ_HANG) {
			directory = "hangs";
			ERROR_MSG("Found %s", directory);
		} else if (new_path > 0) {
			directory = "new_paths";
			INFO_MSG("Found %s", directory);
		}

		if (directory != NULL) {
			mutate_buffer = driver->get_last_input(driver->state, &mutate_length);
			if (!mutate_buffer) {
				ERROR_MSG("Unable to dump mutate buffer\n");
			} else {
				if (output_directory) {
					md5((uint8_t *)mutate_buffer, mutate_length, filehash, sizeof(filehash));
					snprintf(filename, MAX_PATH, "%s/%s/%s", output_directory, directory, filehash);
					if (!file_exists(filename)) //If the file already exists, there's no reason to write it again
						write_buffer_to_file(filename, mutate_buffer, mutate_length);
				}
				free(mutate_buffer);
			}
		}
	}

	INFO_MSG("Ran %ld iterations in %lld seconds", iteration, time(NULL) - fuzz_begin_time);

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Cleanup ///////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	if (instrumentation_state_dump_file)
	{
		instrumentation_state_string = instrumentation->get_state(instrumentation_state);
		if (instrumentation_state_string)
		{
			write_buffer_to_file(instrumentation_state_dump_file, instrumentation_state_string, strlen(instrumentation_state_string));
			instrumentation->free_state(instrumentation_state_string);
		}
		else
			WARNING_MSG("Couldn't dump instrumentation state to file %s", instrumentation_state_dump_file);
	}
	if (mutation_state_dump_file)
	{
		mutator_saved_state = mutator->get_state(mutator_state);
		if (mutator_saved_state)
		{
			write_buffer_to_file(mutation_state_dump_file, mutator_saved_state, strlen(mutator_saved_state));
			mutator->free_state(mutator_saved_state);
		}
		else
			WARNING_MSG("Couldn't dump mutator state to file %s", mutation_state_dump_file);
	}

	//Cleanup everything and exit
	cleanup_modules();
	return 0;
}
