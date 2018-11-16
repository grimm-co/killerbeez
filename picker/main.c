//This program helps the user decide which libraries should be instrumented
//while fuzzing.  This is accomplished by running the target program and
//recording coverage information on each of the loaded libraries. It then
//analyzes the coverage information for each library to determine which
//libraries the coverage information varies based on the input file.  These
//libraries are most likely the ones that process the input file, and thus the
//most likely targets for fuzzing.

#include <driver.h>
#include <driver_factory.h>
#include <instrumentation.h>
#include <instrumentation_factory.h>
#include <utils.h>

#include <stdio.h>
#include <stdlib.h>


/**
* This function prints out the usage information for the fuzzer and each of the individual components.
* @param program_name - the name of the program currently being run (for use in the outputted message)
*/
void usage(char * program_name)
{
	char * help_text;
	printf(
		"Usage: %s driver_name instrumentation_name seed_directory [options]\n"
		"\n"
		"Options:\n"
		"\t -d driver_options             Set the options for the driver\n"
		"\t -i instrumentation_options    Set the options for the instrumentation\n"
		"\t -ib ignore_bytes_dir          The directory to write the list of bytes in the instrumentation to ignore\n"
		"\t -l logging_options            Set the options for logging\n"
		"\t -n num_iterations             The number of iterations to run per file [default 10 per file]\n"
		"\n",
		program_name
	);

#define PRINT_HELP(x, y) \
	x = y;               \
	if(x) {              \
		puts(x);         \
		free(x);         \
	}

	PRINT_HELP(help_text, driver_help());
	PRINT_HELP(help_text, instrumentation_help());
	exit(1);
}


int main(int argc, char ** argv)
{
	driver_t * driver;
	instrumentation_t * instrumentation;
	char *driver_name, *driver_options = NULL,
		*seed_directory = NULL, *seed_buffer = NULL, * module_name = NULL, *logging_options = NULL,
		*instrumentation_name = NULL, *instrumentation_options = NULL, *ignore_bytes_dir = NULL;
	void * instrumentation_state = NULL;
	int seed_length = 0, file_count, module_index, new_path, cur_index;
	int iteration = 0;
	WIN32_FIND_DATA fdFile;
	HANDLE file_handle;
	char filename[4096];
	char ** module_names = NULL, ** filenames = NULL;
	char * module_infos = NULL;
	int * module_results = NULL;
	char * info, * ignore_bytes;
	int num_modules = 0, num_files = 0, info_size, module_info_size = -1, i;

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Parse Arguments ///////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	//Default options
	int num_iterations = 10;

	if (argc < 4)
	{
		usage(argv[0]);
	}

	driver_name = argv[1];
	instrumentation_name = argv[2];
	seed_directory = argv[3];
	for (int i = 4; i < argc; i++)
	{
		IF_ARG_OPTION("-d", driver_options)
		ELSE_IF_ARG_OPTION("-i", instrumentation_options)
		ELSE_IF_ARG_OPTION("-ib", ignore_bytes_dir)
		ELSE_IF_ARG_OPTION("-l", logging_options)
		ELSE_IF_ARGINT_OPTION("-n", num_iterations)
		else
		{
			if (strcmp("-h", argv[i]))
				printf("Unknown argument: %s\n", argv[i]);
			usage(argv[0]);
		}
	}

	if (setup_logging(logging_options))
	{
		printf("Failed setting up logging, exitting\n");
		return 1;
	}

	if (num_iterations < 2)
		FATAL_MSG("Bad iteration number (%d).  Must have a iteration count greater than 1.", num_iterations);

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Ojbect Setup //////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	instrumentation = instrumentation_factory(instrumentation_name);
	if (!instrumentation)
		FATAL_MSG("Unknown instrumentation '%s'", instrumentation_name);
	instrumentation_state = instrumentation->create(instrumentation_options, NULL);
	if (!instrumentation_state)
		FATAL_MSG("Bad options/state for instrumentation %s", instrumentation_name);
	if (!instrumentation->get_module_info)
		FATAL_MSG("Instrumentation '%s' does not support per module coverage", instrumentation_name);

	//Create the driver
	driver = driver_instrumentation_factory(driver_name, driver_options, instrumentation, instrumentation_state);
	if (!driver)
		FATAL_MSG("Unknown driver '%s' or bad options: %s", driver_name, driver_options);

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Get the list of files to test /////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////
	
	memset(filename, 0, sizeof(filename));
	snprintf(filename, sizeof(filename) - 1, "%s\\*", seed_directory);
	file_count = 0;

	int success = 1;
	for (file_handle = FindFirstFile(filename, &fdFile);
		file_handle != INVALID_HANDLE_VALUE && success;
		success = FindNextFile(file_handle, &fdFile))
	{
		//Skip directories
		if (fdFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			continue;

		//Read the seed file
		memset(filename, 0, sizeof(filename));
		snprintf(filename, sizeof(filename) - 1, "%s\\%s", seed_directory, fdFile.cFileName);
		seed_length = read_file(filename, &seed_buffer);
		if (seed_length <= 0) //Couldn't read file, or empty file
			continue;
		free(seed_buffer);

		num_files++;
		filenames = (char **)realloc(filenames, num_files * sizeof(char *));
		filenames[num_files - 1] = strdup(filename);
	}
	FindClose(file_handle);

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Main Test Loop ////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

#define INITIAL_STATE 0
#define PATH_SET 1
#define NEW_PATH_ON_SAME_FILE 2
#define NEW_PATH_ON_DIFF_FILE 3
	char * module_results_descriptions[] = {
		"no paths set", //INITIAL_STATE
		"a single path for all files", //PATH_SET
		"multiple paths for the same file", //NEW_PATH_ON_SAME_FILE
		"one path for each file" //NEW_PATH_ON_DIFF_FILE
	};

	for(file_count = 0; file_count < num_files; file_count++)
	{
		//Read the seed file
		seed_length = read_file(filenames[file_count], &seed_buffer);
		if (seed_length <= 0) //Couldn't read file, or empty file
			continue;

		INFO_MSG("Testing file '%s'", filenames[file_count]);
		for (iteration = 0; iteration < num_iterations; iteration++)
		{
			driver->test_input(driver->state, seed_buffer, seed_length);

			module_index = 0;
			while (!instrumentation->get_module_info(instrumentation_state, module_index, &new_path, &module_name, &info, &info_size))
			{
				cur_index = module_index;
				module_index++;

				if (module_info_size == -1)
					module_info_size = info_size;
				if (info_size != module_info_size)
					FATAL_MSG("Module instrumentation data varies per size, not supported (yet)");
				if (!info)
					FATAL_MSG("Instrumentation data unavailable from the %s instrumentation.\n", instrumentation_name);

				if (num_modules < module_index)
				{
					//module_infos is a dynamically allocated array that holds all of the instrumentation data for each of the
					//instrumented modules.  While it is declared/used as a char *, it can be thought of as a 4-dimension array:
					//char module_infos[NUM_MODULES_TRACED][NUM_FILES_TRACED][NUM_ITERATIONS_PER_FILE][MODULE_INFO_SIZE];

					module_names = (char **)realloc(module_names, module_index * sizeof(char *));
					module_names[cur_index] = module_name;
					module_results = (int *)realloc(module_results, module_index * sizeof(int *));
					module_results[cur_index] = INITIAL_STATE;
					module_infos = (char *)realloc(module_infos, module_index * num_files * num_iterations * module_info_size);
					num_modules = module_index;
				}

				int pos = ((cur_index * num_files * num_iterations) + (file_count * num_iterations) + iteration) * module_info_size;
				memcpy(module_infos + pos, info, module_info_size);

				//Logic:
				//If it's the first time we've run this module, mark that we've set the path
				//If it's the first iteration that we've tried a new file and we found a new path, it has
				//  at least one new path per file. So until we determine that it can take multiple
				//  paths for the same file, mark it as having one path per file.
				//Otherwise, we've found a new path, then it must be a new path for the same file.  Mark it as
				//	such.  After we've decided that, there is no coming back from that state.
				if (module_results[cur_index] == INITIAL_STATE)
					module_results[cur_index] = PATH_SET;
				else if (new_path && iteration == 0 && module_results[cur_index] != NEW_PATH_ON_SAME_FILE)
					module_results[cur_index] = NEW_PATH_ON_DIFF_FILE;
				else if (new_path)
					module_results[cur_index] = NEW_PATH_ON_SAME_FILE;
			}
		}
		free(seed_buffer);
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Compare the runs and calculate ignore bytes ///////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	//In the next portion, we have the variables:
	//module_index     = the module index (since you can use the picker on many different modules at once).
	//num_files        = the number of files being tested
	//num_iterations   = the number of times each file was traced
	//file_count       = the iterator over the files for a specific module
	//iteration        = the iterator over the individual traces for a specific file
	//module_info_size = the size of the instrumentation data from the traced module (a constant value, that doesn't change per file/module/iteration)
	//cur_pos          = an index into module_infos to the instrumentation data for the $iteration trace of the $file_count file
	//prev_pos         = an index into module_infos to the instrumentation data for the ($iteration-1) trace of the $file_count file



	ignore_bytes = (char *)malloc(module_info_size);
	for (module_index = 0; module_index < num_modules; module_index++)
	{
		if (module_results[module_index] != NEW_PATH_ON_SAME_FILE)
			continue;

		memset(ignore_bytes, 0xff, module_info_size);
		int total_ignore_count = 0;
		for (file_count = 0; file_count < num_files; file_count++)
		{
			for (iteration = 1; iteration < num_iterations; iteration++)
			{
				int ignore_count = 0;

				//The calculations for cur_pos and prev_pos are done as such:
				//index * num_files * num_iterations = skip over the modules we've already checked
				//file_count * num_iterations = skip over the files we've already checked for this module
				//iteration = skip to the iteration that we're currently checking (prev_pos uses iteration - 1, since it's jumping to the previous iteration's instrumentation data)
				//and then it's all multiplied by the module_info_size since each one of the instrumentation data records that we're skipping is that many bytes large
				int prev_pos = ((module_index * num_files * num_iterations) + (file_count * num_iterations) + iteration - 1) * module_info_size;
				int cur_pos = ((module_index * num_files * num_iterations) + (file_count * num_iterations) + iteration) * module_info_size;

				for (i = 0; i < module_info_size; i++)
				{
					if (module_infos[prev_pos + i] != module_infos[cur_pos + i])
					{
						if (!ignore_bytes[i])
							total_ignore_count++;
						ignore_bytes[i] = 0x00;
						ignore_count++;
					}
				}
				DEBUG_MSG("Module %s File %s iteration (%d/%d) ignore count %d total ignore count %d", module_names[module_index], filenames[file_count], iteration - 1, iteration, ignore_count, total_ignore_count);
			}
		}

		if (ignore_bytes_dir)
		{
			memset(filename, 0, sizeof(filename));
			snprintf(filename, sizeof(filename) - 1, "%s\\%s.dat", ignore_bytes_dir, module_names[module_index]);

/*
			//Swap the byte ordering here, so we don't have to in the hashing function later
#if defined(_M_X64) || defined(__x86_64__)
			for (i = 0; i < sizeof(ignore_bytes); i += sizeof(u64))
				*((u64 *)&ignore_bytes[i]) = _byteswap_uint64(*((u64 *)&ignore_bytes[i]));
#else
			for (i = 0; i < sizeof(ignore_bytes); i += sizeof(u32))
				*((u32 *)&ignore_bytes[i]) = SWAP32(*((u32 *)&ignore_bytes[i]));
#endif
*/

			write_buffer_to_file(filename, ignore_bytes, module_info_size);
		}
	}
	free(ignore_bytes);

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Print the results /////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	CRITICAL_MSG("Results:");
	for (module_index = 0; module_index < num_modules; module_index++)
		CRITICAL_MSG("Module %s had %s", module_names[module_index], module_results_descriptions[module_results[module_index]]);

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Cleanup ///////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////
	
	//free the generated info
	free(module_results);
	free(module_names);
	free(module_infos);
	for (file_count = 0; file_count < num_files; file_count++)
		free(filenames[file_count]);
	free(filenames);

	//Cleanup the objects and exit
	driver->cleanup(driver->state);
	instrumentation->cleanup(instrumentation_state);
	free(driver);
	free(instrumentation);
	return 0;
}
