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
#else
#include <libgen.h>     // dirname
#include <unistd.h>     // access, F_OK, W_OK
#include <sys/stat.h>   // mkdir
#include <sys/types.h>
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
"  -d driver_options                 Set the options for the driver\n"
"  -i instrumentation_options        Set the options for the instrumentation\n"
"  -isd instrumentation_state_file   Set the file containing that the\n"
"                                      instrumentation state should dump to\n"
"  -isf instrumentation_state_file   Set the file containing that the\n"
"                                      instrumentation state should load from\n"
"  -l logging_options                Set the options for logging\n"
"  -n num_iterations                 Limit the number of iterations to run\n"
"                                      (optional, infinite by default)\n"
"  -m mutator_options                Set the options for the mutator\n"
"  -md mutator_directory             The directory to look for mutator DLLs in\n"
"                                      (must be specified to view help for\n"
"                                      specific mutators)\n"
"  -ms mutator_state                 Set the state that the mutator should load\n"
"  -msd mutator_state_file           Set the file containing that the mutator\n"
"                                      state should dump to\n"
"  -msf mutator_state_file           Set the file containing that the mutator\n"
"                                      state should load from\n"
"  -o output_directory               The directory to write files which cause a\n"
"                                      crash or hang\n"
"  -sf seed_file                     The seed file to use\n"
"\n\n"
"\n -h <l[ogging], d[river], i[nstrumentation], m[utators]> for more help.\n\n",
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

int main(int argc, char ** argv)
{
	char *driver_name, *driver_options = NULL,
		*mutator_name, *mutator_options = NULL, *mutator_saved_state = NULL, *mutation_state_dump_file = NULL, *mutation_state_load_file = NULL,
		*mutate_buffer = NULL, *mutator_directory = NULL, *mutator_directory_cli = NULL,
		*logging_options = NULL,
		*seed_file = NULL, *seed_buffer = NULL,
		*instrumentation_name = NULL, *instrumentation_options = NULL, 
		*instrumentation_state_string = NULL, *instrumentation_state_load_file = NULL,
		*instrumentation_state_dump_file = NULL;
	int seed_length = 0, mutate_length = 0, instrumentation_length = 0, mutator_state_length;
	time_t fuzz_begin_time;
	int iteration = 0, fuzz_result = FUZZ_NONE, new_path = 0;
	char filename[MAX_PATH];
	char filehash[256];
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

#define PRINT_HELP(x) \
		puts(x);      \
		free(x);         

	// if "fuzzer.exe -h something"
	if ( argc > 2 && !strcmp("-h", argv[1]) ) 
	{
		puts("");
		if (!strcmp("logging", argv[2]) || !strcmp("l", argv[2])) {
			PRINT_HELP(logging_help());
		} else if (!strcmp("driver", argv[2]) || !strcmp("d", argv[2])) {
			PRINT_HELP(driver_help());
		} else if (!strcmp("instrumentation", argv[2]) || !strcmp("i", argv[2])) {
			PRINT_HELP(instrumentation_help());
		} else if (!strcmp("mutators", argv[2]) || !strcmp("m", argv[2])) {
			PRINT_HELP(mutator_help(mutator_directory));
		} else {
			printf("Unknown help option \"%s\". Expected <l[ogging], d[river], i[nstrumentation], m[utators]>.\n\n",argv[2]);
		}
		
		exit(1);
	}

	if (argc < 4)
	{
		usage(argv[0], mutator_directory);
	}

	driver_name = argv[1];
	instrumentation_name = argv[2];
	mutator_name = argv[3];

	//Now parse the rest of the args now that we have a valid mutator dir setup
	for (int i = 4; i < argc; i++)
	{
		IF_ARG_OPTION("-d", driver_options)
		ELSE_IF_ARG_OPTION("-i", instrumentation_options)
		ELSE_IF_ARG_OPTION("-isd", instrumentation_state_dump_file)
		ELSE_IF_ARG_OPTION("-isf", instrumentation_state_load_file)
		ELSE_IF_ARGINT_OPTION("-n", num_iterations)
		ELSE_IF_ARG_OPTION("-m", mutator_options)
		ELSE_IF_ARG_OPTION("-md", mutator_directory_cli)
		ELSE_IF_ARG_OPTION("-l", logging_options)
		ELSE_IF_ARG_OPTION("-ms", mutator_saved_state)
		ELSE_IF_ARG_OPTION("-msd", mutation_state_dump_file)
		ELSE_IF_ARG_OPTION("-msf", mutation_state_load_file)
		ELSE_IF_ARG_OPTION("-o", output_directory)
		ELSE_IF_ARG_OPTION("-sf", seed_file)
	    else
		{
			if (strcmp("-h", argv[i]))
				printf("Unknown argument: %s\n", argv[i]);
			usage(argv[0], mutator_directory);
		}
	}

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
			"\tmutator options: %s\n\n\tPass %s -h driver for help.\n", driver_name,
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
		if (fuzz_result == FUZZ_CRASH)
			directory = "crashes";
		else if (fuzz_result == FUZZ_HANG)
			directory = "hangs";
		else if (new_path > 0)
			directory = "new_paths";

		if (directory != NULL)
		{
			CRITICAL_MSG("Found %s", directory);

			mutate_buffer = driver->get_last_input(driver->state, &mutate_length);
			if (!mutate_buffer)
				ERROR_MSG("Unable to dump mutate buffer\n");
			else
			{
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
