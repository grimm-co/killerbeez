#include "mutator_tester.h"

#include <global_types.h>
#include <jansson.h>
#include <jansson_helper.h>
#include <mutator_factory.h>
#include <utils.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#endif

//The list of test functions
static test_info_t test_info[NUM_TESTS] =
{
	{ test_all,    "Run all tests!" }, //test_all MUST be the first entry in the test_info array
	{ test_mutate, "Test the mutate() function, this will print each iteration of mutation" },
	{ test_state,  "Test the get_state() and set_state() functions." },
	{ test_thread_mutate, "Test the thread safe mutate function. Only non-repeating mutators will pass this test" },
	{ test_run_forever, "Test the mutate() function by mutating the given buffer endlessly." },
	{ test_mutate_parts, "Test the mutate_input_part() function." },
	{ test_mutate_once, "Call the mutate() function once and print the output" },
};

static test_function test_all_tests[] =
{
	test_mutate,
	test_state,
	test_thread_mutate,
	test_mutate_parts,
	test_mutate_once
};

/** This function sets up the mutator for testing. This test program is designed
 * To aid in the debugging of a mutator DLL. The dll is loaded like it would be in the 
 * full blown fuzzer and a series of tests are run against it to find common errors.
 * @return - if the process fails, it will return 1, if a test fails, the error code 
 * returned will be its test number + 100. For example if test 1 fails main will return 101
 * 0 is returned on success!
 */
int main(int argc, char *argv[])
{
	//Args
	char *test_type_to_convert = NULL, *mutator_path = NULL, *mutator_options = NULL, *seed_file = NULL; //args
	char *seed_buffer = NULL;
	char *test_string = NULL;
	char *help = NULL;
	int ret;
	unsigned long test_num;
	size_t seed_length;
	mutator_t * mutator;
	void * mutator_state;

	if (argc == 3 && !strcmp(argv[1], "help"))
	{
		help = mutator_help(argv[2]);
		if(help)
			puts(help);
		free(help);
		return 0;
	}
	else if (argc < 3)
	{
		print_usage(argv[0]);
		return 0;
	}

	test_type_to_convert = argv[1];
	mutator_path = argv[2];
	if(argc > 3)
		mutator_options = argv[3];

	srand(time(NULL));

	//Convert the test type to int
	test_num = strtoul(test_type_to_convert, &test_string, 10);
	if (test_string == test_type_to_convert || test_num >= NUM_TESTS || *test_string != '\0') { //Check for empty str, and overflow
		printf("Invalid test number!");
		return 1;
	}

	if (argc < 5) {
		seed_length = 8;
		seed_buffer = (char *)malloc(seed_length);
		memset(seed_buffer, 0, seed_length);
	}
	else
	{
		//Load the seed buffer from a file
		seed_file = argv[4];
		seed_length = read_file(seed_file, &seed_buffer);
		if (seed_length <= 0)
		{
			printf("Could not read seed file or empty seed file: %s\n", seed_file);
			return 1;
		}
	}

	//Load the DLL
	mutator = mutator_factory(mutator_path);
	if (mutator == NULL) {
		printf("Load mutator returned a NULL pointer\n");
		return 1;
	}
	//Setup the mutator
	mutator_state = setup_mutator(mutator, mutator_options, seed_buffer, seed_length);
	if (!mutator_state) {
		printf("setup_mutator() failed\n");
		return 1;
	}

	//Everything is setup, now do the tests.
	ret = test_info[test_num].func(mutator, mutator_state, mutator_options, seed_buffer, seed_length);
	if (ret)
		ret = 100 + test_num;

	mutator->cleanup(mutator_state);
	free(mutator);
	free(seed_buffer);
	return ret;
}

/**
 * This function initinalizes the mutator. It calls its create function to setup 
 * the mutators state struct, and returns it. This struct is required for all other
 * mutator spicific function calls.
 * 
 * @param mutator - a mutator_t struct with the API function pointers for the mutator to setup
 * @param mutator_options - a JSON string that contains the mutator options
 * @param seed_buffer - The data buffer used to seed the mutator
 * @param seed_length - The length of the seed_buffer in bytes
 * @return mutator_state - the state struct for a spicific mutator
 */
void * setup_mutator(mutator_t * mutator, char * mutator_options, char * seed_buffer, size_t seed_length)
{
	void * mutator_state;

	mutator_state = mutator->create(mutator_options, NULL, seed_buffer, seed_length);
	if (!mutator_state)
	{
		printf("Bad mutator options or saved state\n");
		return NULL;
	}
	return mutator_state;
}

/**
 * This function prints the usage statment for the program.
 *
 * @param argv - The array of command line arguments
 * @return none
 */
void print_usage(char *executable_name)
{
	int i;
	printf("\nUsage:\n");
	printf("\n%s help \"/path/to/mutator/directory\"\n", executable_name);
	printf("\tPrint mutator help.\n");
	printf("\n%s test_type \"/path/to/mutator.dll\" [\"JSON Mutator Options String\" [path/to/input/data]]\n", executable_name);
	printf("\tRun a mutator test. Valid Test Types:\n");
	for (i = 0; i < NUM_TESTS; i++)
		printf("\t\t %d - %s\n", i, test_info[i].usage_info);
}

/**
 * This function runs all other tests in the test_info struct.
 *
 * @param mutator - the mutator struct representing the mutator to be tested, returned by load_mutator
 * @param mutator_state - the state struct for the mutator being tested.  Currently unused for this test.
 * @param mutator_options - a JSON string that contains the mutator options
 * @param seed_buffer - The data buffer used to seed the mutator
 * @param seed_length - The length of the seed_buffer in bytes
 * @return int - the results of the tests. 0 for success and nonzero for fail
 */
int test_all(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length) {
	int test_num, ret = 0;
	void * single_test_mutator_state;

	for (test_num = 0; test_num < sizeof(test_all_tests)/sizeof(test_all_tests[0]) && !ret; test_num++)
	{
		single_test_mutator_state = setup_mutator(mutator, mutator_options, seed_buffer, seed_length);
		if (!single_test_mutator_state) {
			printf("setup_mutator() failed\n");
			return 1;
		}

		printf("+---------+\n");
		printf("| TEST %2d |\n", test_num);
		printf("+---------+\n\n");

		ret = test_all_tests[test_num](mutator, single_test_mutator_state, mutator_options, seed_buffer, seed_length);
		mutator->cleanup(single_test_mutator_state);
	}
	return ret;
}

/**
 * This function tests several testcases around the mutators mutate() function.
 * This allows the user to see if the data is being mutated in the expected manner.
 * It also ensures that each iteration of mutation is being tracked appropriately.
 * 
 * @param mutator - the mutator struct representing the mutator to be tested, returned by load_mutator
 * @param mutator_state - the state struct for the mutator being tested, This state should
 * be at the starting state for the mutator (iteration 0)
 * @param mutator_options - a JSON string that contains the mutator options
 * @param seed_buffer - The data buffer used to seed the mutator
 * @param seed_length - The length of the seed_buffer in bytes
 * @return int - the results of the tests. 0 for success and 1 for fail
 */
int test_mutate(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length) {

	int total_iterations, mut_iter, i, limit;
	char * mutate_buffer = (char *)malloc(2 * seed_length);
	int ret;

	total_iterations = mutator->get_total_iteration_count(mutator_state);
	printf("The mutator reported %d required iterations.\n\n", total_iterations);
	printf("=== Original Data ===\n");
	print_hex(seed_buffer, seed_length);
	printf("\n\n\n");

	limit = total_iterations;
	if (total_iterations == -1)
		limit = 64;

	for (i = 0; i <= limit; i++) {
		printf("=== Iteration %d ===\n", i);
		mut_iter = mutator->get_current_iteration(mutator_state);
		if (i != mut_iter) {
			printf("ERROR: The mutator reports that it is on iteration %d but the real iteration is %d\n", mut_iter, i);
			return 1;
		}
		ret = mutator->mutate(mutator_state, mutate_buffer, 2 * seed_length);
		printf("mutated buffer, %3d bytes:\n", ret);
		if (ret != -1 && ret != 0) {
			print_hex(mutate_buffer, ret);
		}
		printf("\n\n");

		if (ret == 0 && i == total_iterations) {
			printf("The mutator reported that everything has been mutated on iteration %d of %d\n", i, total_iterations);
			break;
		} else if (ret == 0 && total_iterations == -1) { //undeterminable number of outputs, it's not really a bug
			printf("The mutator reported that everything has been mutated on iteration %d\n", i);
			break;
		} else if (ret == -1) {
			printf("ERROR: the mutator reported an error!\n");
			return 1;
		} else if (i == limit && total_iterations != -1) {
			printf("ERROR: The expected number of mutations were performed (%d), but the mutator did not return 0\n", total_iterations);
		}
	}

	if (total_iterations != -1 && ret != 0)
	{
		for (i = 1; i < 100 && ret != 0; i++)
			ret = mutator->mutate(mutator_state, mutate_buffer, 2 * seed_length);

		if (ret == 0 && total_iterations != -1)
			printf("ERROR: it took %d extra iterations for the mutator to return 0", i-1);
		else
			printf("ERROR: the mutator did not return 0 even after %d extra iterations", i-1);
		return 1;
	}

	return 0;
}

/**
 * This function tests several testcases around the mutators get_state() and set_state functions.
 * This allows the user to check if the state of a mutator is being correctly saved and restored.
 *
 * @param mutator - the mutator struct returned by load_mutator
 * @param mutator_state - the state struct for a spicific mutator
 * @param mutator_options - a JSON string that contains the mutator options
 * @param seed_buffer - The data buffer used to seed the mutator
 * @param seed_length - The length of the seed_buffer in bytes
 * @return int - the results of the tests. 0 for success and 1 for fail
 */
int test_state(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length) {

	size_t total_iterations, i;
	char * mutate_buffer = (char *)malloc(2 * seed_length);
	char * new_mutate_buffer = (char *)malloc(2 * seed_length);
	char * old_saved_state_buffer;
	char * new_saved_state_buffer;
	json_t * old_JSON_state;
	json_t * new_JSON_state;
	int ret, old_iter, new_iter, old_mutate_length, new_mutate_length;
	void * new_mutator_state;

	if (!mutate_buffer || !new_mutate_buffer)
	{
		printf("Malloc failed\n");
		free(mutate_buffer);
		free(new_mutate_buffer);
		return 1;
	}

	total_iterations = mutator->get_total_iteration_count(mutator_state);
	if (total_iterations == -1) {
		total_iterations = 64;
	}
	printf("Mutating the data %zi times\n", total_iterations / 2 );
	for (i = 0; i <= total_iterations / 2; i++) {
		ret = mutator->mutate(mutator_state, mutate_buffer, 2 * seed_length);
		if (ret <= 0) {
			if (ret < 0)
				printf("ERROR: The mutate() function returned an error or finished pre-maturely. Run test 1 for more info\n");
			else
				printf("Mutator finished mutations early\n");
			break;
		}
	}
	printf("Mutation stopped on iteration %zi\n", i);
	printf("Saving the mutators state...\n");
	old_saved_state_buffer = (char *)mutator->get_state(mutator_state);
	printf("Here is the OLD JSON string:\n%s\n", old_saved_state_buffer);

	//Setup a new mutator to restore the state into
	new_mutator_state = setup_mutator(mutator, mutator_options, seed_buffer, seed_length);
	if (!new_mutator_state) {
		printf("setup_mutator() failed\n");
		free(mutate_buffer);
		free(new_mutate_buffer);
		mutator->free_state(old_saved_state_buffer);
		return 1;
	}

	//set the state from the old -> new
	printf("Restoring the mutators state...\n");
	ret = mutator->set_state(new_mutator_state, old_saved_state_buffer);
	if (ret) {
		printf("set_state() returned error code %i\n", ret);
	}
	new_saved_state_buffer = (char *)mutator->get_state(new_mutator_state);
	printf("Here is the NEW JSON string:\n%s\n", new_saved_state_buffer);

	//Compare JSON states to see if they were saved and restored correctly
	old_JSON_state = json_string(old_saved_state_buffer);
	mutator->free_state(old_saved_state_buffer);
	if (old_JSON_state == NULL) {
		printf("Failed to convert old JSON string to JSON object\n");
		free(mutate_buffer);
		free(new_mutate_buffer);
		mutator->free_state(new_saved_state_buffer);
		mutator->cleanup(new_mutator_state);
		return 1;
	}
	new_JSON_state = json_string(new_saved_state_buffer);
	mutator->free_state(new_saved_state_buffer);
	if (new_JSON_state == NULL) {
		printf("Failed to convert new JSON string to JSON object\n");
		json_decref(old_JSON_state);
		free(mutate_buffer);
		free(new_mutate_buffer);
		mutator->cleanup(new_mutator_state);
		return 1;
	}
	if (!json_equal(old_JSON_state, new_JSON_state)) {
		printf("The mutator failed to restore state properly\n");
		json_decref(old_JSON_state);
		json_decref(new_JSON_state);
		free(mutate_buffer);
		free(new_mutate_buffer);
		mutator->cleanup(new_mutator_state);
		return 1;
	}
	json_decref(old_JSON_state);
	json_decref(new_JSON_state);
	printf("The saved states are equal, this is expected\n");

	//Get the iteration count and call mutate once, just to make sure that they work
	old_iter = mutator->get_current_iteration(mutator_state);
	new_iter = mutator->get_current_iteration(new_mutator_state);

	old_mutate_length = mutator->mutate(mutator_state, mutate_buffer, 2 * seed_length);
	new_mutate_length = mutator->mutate(new_mutator_state, new_mutate_buffer, 2 * seed_length);

	if (old_iter == new_iter
		&& old_mutate_length == new_mutate_length && old_mutate_length >= 0
		&& !memcmp(mutate_buffer, new_mutate_buffer, old_mutate_length)) {
		printf("Success! The mutator has restored its state\n");
		ret = 0;
	} else {
		printf("The mutator failed to mutate properly after restoring the state\n"
			"Original mutator iteration count %d New mutator iteration count %d\n"
			"Original mutator output length %d new mutator output length %d\n", old_iter, new_iter, old_mutate_length, new_mutate_length);
		printf("old (%d bytes): ", old_mutate_length);
		if(old_mutate_length > 0)
			print_hex(mutate_buffer, old_mutate_length);
		printf("\nnew (%d bytes): ", new_mutate_length);
		if(new_mutate_length > 0)
			print_hex(new_mutate_buffer, new_mutate_length);
		printf("\n");
		ret = 1;
	}

	free(mutate_buffer);
	free(new_mutate_buffer);
	mutator->cleanup(new_mutator_state);
	return ret;
}

#define RACER_IS_THREAD_SAFE
#define NUM_RACER_THREADS 10
#define NUM_RACER_SAVED_BUFFERS 256
#define NUM_RACER_ROUNDS 50

static int racer_buffers_count;
static int racer_saved_buffer_lengths[NUM_RACER_SAVED_BUFFERS];
static char * racer_saved_buffers[NUM_RACER_SAVED_BUFFERS];
static char * racer_seed_buffer;
static size_t racer_seed_length;
static mutator_t * racer_mutator;

#ifdef _WIN32
DWORD WINAPI mutate_racer(LPVOID mutator_state)
#else
void * mutate_racer(void * mutator_state)
#endif
{
	int index = 0;
	size_t mutate_buffer_length = 2 * racer_seed_length;

	while (index < NUM_RACER_SAVED_BUFFERS)
	{
#ifdef _WIN32
		index = InterlockedIncrement(&racer_buffers_count) - 1;
#else
		index = __sync_fetch_and_add(&racer_buffers_count, 1) - 1;
#endif
		if (index >= NUM_RACER_SAVED_BUFFERS)
			break;
		racer_saved_buffers[index] = malloc(mutate_buffer_length);
		memcpy(racer_saved_buffers[index], racer_seed_buffer, racer_seed_length);
#ifdef RACER_IS_THREAD_SAFE
		racer_saved_buffer_lengths[index] = racer_mutator->mutate_extended(mutator_state, racer_saved_buffers[index], mutate_buffer_length, MUTATE_THREAD_SAFE);
#else
		racer_saved_buffer_lengths[index] = racer_mutator->mutate(mutator_state, racer_saved_buffers[index], mutate_buffer_length);
#endif
		if (racer_saved_buffer_lengths[index] <= 0)
			break;
	}

#ifdef _WIN32
	return index;
#else
	return NULL;
#endif
}

/**
 * This function tests the thread safe mutate function.
 *
 * @param mutator - the mutator struct returned by load_mutator
 * @param mutator_state - the state struct for a spicific mutator
 * @param mutator_options - a JSON string that contains the mutator options
 * @param seed_buffer - The data buffer used to seed the mutator
 * @param seed_length - The length of the seed_buffer in bytes
 * @return int - the results of the tests. 0 for success and 1 for fail
 */
int test_thread_mutate(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length) {
	int round, i, j, found_duplicate = 0;

	racer_seed_buffer = seed_buffer;
	racer_seed_length = seed_length;
	racer_mutator = mutator;

	for (round = 0; !found_duplicate && round < NUM_RACER_ROUNDS; round++)
	{
		memset(racer_saved_buffers, 0, sizeof(racer_saved_buffers));
		memset(racer_saved_buffer_lengths, 0, sizeof(racer_saved_buffer_lengths));
		racer_buffers_count = 0;

		mutator_state = setup_mutator(mutator, mutator_options, seed_buffer, seed_length);
		if (!mutator_state) {
			printf("setup_mutator() failed\n");
			return 1;
		}

		//Run the racer threads
#ifdef _WIN32
		HANDLE threads[NUM_RACER_THREADS];
		for(i = 0; i < NUM_RACER_THREADS; i++)
			threads[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mutate_racer, mutator_state, 0, NULL);
		WaitForMultipleObjects(NUM_RACER_THREADS, threads, TRUE, INFINITE);
		for (i = 0; i < NUM_RACER_THREADS; i++)
			CloseHandle(threads[i]);
#else
		pthread_t threads[NUM_RACER_THREADS];
		for(i = 0; i < NUM_RACER_THREADS; i++)
			pthread_create(&threads[i], NULL, mutate_racer, mutator_state);
		for (i = 0; i < NUM_RACER_THREADS; i++)
			pthread_join(threads[i], NULL);
#endif

		for (i = 0; !found_duplicate && i < NUM_RACER_SAVED_BUFFERS; i++)
		{
			if (racer_saved_buffer_lengths[i] <= 0 || racer_saved_buffers[i] == NULL)
				continue;

			for (j = i + 1; !found_duplicate && j < NUM_RACER_SAVED_BUFFERS; j++)
			{
				if (racer_saved_buffer_lengths[j] <= 0 || racer_saved_buffers[j] == NULL)
					continue;

				if (racer_saved_buffer_lengths[i] == racer_saved_buffer_lengths[j] && !memcmp(racer_saved_buffers[i], racer_saved_buffers[j], racer_saved_buffer_lengths[i]))
				{
					printf("Found duplicate in round %d: %d and %d\n", round, i, j);
					print_hex(racer_saved_buffers[i], racer_saved_buffer_lengths[i]);
					printf("\n");
					print_hex(racer_saved_buffers[j], racer_saved_buffer_lengths[j]);
					printf("\n\n");
					found_duplicate = 1;
				}
			}
		}

		for (i = 0; i < NUM_RACER_SAVED_BUFFERS; i++)
			free(racer_saved_buffers[i]);
		mutator->cleanup(mutator_state);
	}

	return found_duplicate;
}

/**
* This function tests the provided mutator by mutating a buffer endlessly
*
* @param mutator - a mutator_t struct to test
* @param mutator_state - the state struct for a spicific mutator
* @param mutator_options - a JSON string that contains the mutator options
* @param seed_buffer - The data buffer used to seed the mutator
* @param seed_length - The length of the seed_buffer in bytes
* @return int - the results of the tests. 0 for success and 1 for fail
*/
int test_run_forever(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length) {
	size_t i;
	int ret;
	char * mutate_buffer = (char *)malloc(2 * seed_length);

	if (!mutate_buffer)
	{
		printf("Malloc failed\n");
		return 1;
	}

	ret = 1;
	for (i = 0; ret != 0 && ret != -1; i++) {
		ret = mutator->mutate(mutator_state, mutate_buffer, 2 * seed_length);
		if (ret == -1) {
			printf("%4lu: The mutate() function returned an error.\n", i);
		} else if(ret == 0) {
			printf("%4lu: The mutate() function returned 0 (i.e. there are no more mutations).\n", i);
		} else if(ret > 0) {
			printf("%4lu: ", i);
			print_hex(mutate_buffer, ret);
			printf("\n");
		}
	}

	free(mutate_buffer);
	return ret;
}

int test_mutate_parts(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length) {
	size_t * input_sizes;
	int i, j, num_bytes, num_inputs, total_iteration_count;
	char * mutate_buffer;

	mutate_buffer = (char *)malloc(2 * seed_length);
	if (!mutate_buffer) {
		printf("Malloc failed\n");
		return 1;
	}

	total_iteration_count = mutator->get_total_iteration_count(mutator_state);
	mutator->get_input_info(mutator_state, &num_inputs, &input_sizes);
	printf("mutator started with %d inputs and has %d iterations total\n", num_inputs, total_iteration_count);
	for (i = 0; i < num_inputs; i++)
		printf("Input %d was %lu bytes\n", i, input_sizes[i]);
	free(input_sizes);

	for (i = 0; i < 10; i++)
	{
		num_bytes = 1;
		for (j = 0; j < num_inputs && num_bytes > 0; j++) {
			num_bytes = mutator->mutate_extended(mutator_state, mutate_buffer, 2 * seed_length, MUTATE_MULTIPLE_INPUTS | j);
			if (num_bytes > 0) {
				printf("%4d %4d: ", i, j);
				print_hex(mutate_buffer, num_bytes);
				printf("\n");
			}
		}
	}
	free(mutate_buffer);
	return 0;
}

int test_mutate_once(mutator_t * mutator, void * mutator_state, char * mutator_options, char * seed_buffer, size_t seed_length) {
	size_t max_length = 5 * 1024 * 1024; //Allow for very large mutations
	char * mutate_buffer;
	int mutate_length;

	mutate_buffer = (char *)malloc(max_length);
	memset(mutate_buffer, 0, max_length);

	mutate_length = mutator->mutate(mutator_state, mutate_buffer, max_length);
	if(mutate_length < 0)
		return -1;
	write(1, mutate_buffer, mutate_length);
	free(mutate_buffer);
	return 0;
}

