#include "radamsa_mutator.h"

#include <jansson.h>
#include <jansson_helper.h>
#include <utils.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <process.h>
#include <strsafe.h>
#include <tchar.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

typedef struct radamsa_state
{
	char * input;

	size_t input_length;

	//The iteration number
	int iteration;

	//Whether we have been able to connect to radamsa yet or not
	int radamsa_up;

	//The seed for radamsa
	int seed;

	//The path to the radamsa binary
	char * path;

	//The port to bind radamsa to
	int port;

	//The number of times we've connected to radamsa's port.  This is different from iteration
	//since sometimes radamsa doesn't return input, and we have to call radamsa again.  Thus,
	//we need to keep track of radamsa's iteration count, so that we can later fast forward
	//if asked to load a previous mutator state.
	int radamsa_iteration;

	//The handle/pid of the radamsa instance
#ifdef _WIN32
	HANDLE process;
#else
	int process;
#endif

	//A mutex used when doing thread safe mutations
	mutex_t mutate_mutex;
} radamsa_state_t;

static void cleanup_process(radamsa_state_t * state);
static int start_process(radamsa_state_t * state);

mutator_t radamsa_mutator = {
	FUNCNAME(create),
	FUNCNAME(cleanup),
	FUNCNAME(mutate),
	FUNCNAME(mutate_extended),
	FUNCNAME(get_state),
	radamsa_free_state,
	FUNCNAME(set_state),
	FUNCNAME(get_current_iteration),
	radamsa_get_total_iteration_count,
	FUNCNAME(get_input_info),
	FUNCNAME(set_input),
	FUNCNAME(help)
};

#ifndef ALL_MUTATORS_IN_ONE
RADAMSA_MUTATOR_API void init(mutator_t * m)
{
	memcpy(m, &radamsa_mutator, sizeof(mutator_t));
}
#endif

#ifdef _WIN32
#define PATH_SEP "\\"
#define RADAMSA_BIN_NAME "radamsa.exe"
#define DEVELOP_PREFIX "..\\..\\..\\..\\" //CMake puts things at root/build/(Win32/x64)/(Debug/Release)/killerbeez/
#else
#define PATH_SEP "/"
#define RADAMSA_BIN_NAME "radamsa"
#define DEVELOP_PREFIX "../../" //CMake puts things at root/build/killerbeez/
#endif

RADAMSA_MUTATOR_API radamsa_state_t * setup_options(char * options)
{
	radamsa_state_t * state;
	state = (radamsa_state_t *)malloc(sizeof(radamsa_state_t));
	if (!state)
		return NULL;
	memset(state, 0, sizeof(radamsa_state_t));

	srand(time(NULL));
	//Setup defaults
	state->port = 10000 + (rand() % 50000);
	state->seed = rand();
	state->mutate_mutex = create_mutex();
	if (!state->mutate_mutex) {
		free(state);
		return NULL;
	}

	if (options && strlen(options)) {
		PARSE_OPTION_STRING(state, options, path, "path", FUNCNAME(cleanup));
		PARSE_OPTION_INT(state, options, seed, "seed", FUNCNAME(cleanup));
		PARSE_OPTION_INT(state, options, port, "port", FUNCNAME(cleanup));
		PARSE_OPTION_INT(state, options, radamsa_iteration, "radamsa_iteration", FUNCNAME(cleanup));
	}

	if (!state->path) {
		// Usual location for binary distribution
		char *default_path = filename_relative_to_binary_dir(".." PATH_SEP "radamsa" PATH_SEP "bin" PATH_SEP RADAMSA_BIN_NAME);
		if (!default_path)
		{  // Usual location for 32-bit developer environment
			default_path = filename_relative_to_binary_dir(DEVELOP_PREFIX "radamsa" PATH_SEP "bin" PATH_SEP RADAMSA_BIN_NAME);
		}
		if (!default_path)
		{
			FUNCNAME(cleanup)(state);
			return NULL;
		}
		state->path = default_path;
	}

	return state;
}

RADAMSA_MUTATOR_API void * FUNCNAME(create)(char * options, char * state, char * input, size_t input_length)
{
	radamsa_state_t * new_state;

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData))
		return NULL;
#endif

	new_state = setup_options(options);
	if (!new_state)
		return NULL;

	new_state->input = (char *)malloc(input_length);
	if (!new_state->input || !input_length)
	{
		FUNCNAME(cleanup)(new_state);
		return NULL;
	}
	memcpy(new_state->input, input, input_length);
	new_state->input_length = input_length;

	if (FUNCNAME(set_state)(new_state, state))
	{
		FUNCNAME(cleanup)(new_state);
		return NULL;
	}
	return new_state;
}

RADAMSA_MUTATOR_API void FUNCNAME(cleanup)(void * mutator_state)
{
	radamsa_state_t * state = (radamsa_state_t *)mutator_state;
	cleanup_process(state);
	destroy_mutex(state->mutate_mutex);
	free(state->input);
	free(state->path);
	free(state);
}

static int mutate_inner(radamsa_state_t * state, char * buffer, size_t buffer_length)
{
	struct sockaddr_in addr;
	int attempts, result, total_read = 0;
#ifdef _WIN32
	SOCKET sock;
#else
	int sock;
#endif

	//Create a socket for us to connect to the radamsa daemon
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
	if (sock == INVALID_SOCKET)
#else
	if (sock < 0)
#endif
		return -1;

	//connect to the radamsa daemon.  Sometimes it takes a bit to startup and bind to the port, so if we just
	//started radamsa, we'll try multiple times with a little sleep in between if it fails.
	for(attempts = 0; attempts == 0 || (attempts < 5 && !state->radamsa_up); attempts++) {
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		addr.sin_port = htons(state->port);
#ifdef _WIN32
		result = connect(sock, (SOCKADDR *)&addr, sizeof(addr));
		if (result != SOCKET_ERROR)
			break;
		Sleep(250);
#else
		result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
		if (result >= 0)
			break;
		sleep(1);
#endif
	}
	if(attempts >= 5)
		return -1;
	state->radamsa_up = 1;
	state->radamsa_iteration++;

	//Read radamsa's response
	result = 1;
	while (total_read < (int)buffer_length && result > 0)
	{
		result = recv(sock, buffer + total_read, buffer_length - total_read, 0);
		if (result > 0)
			total_read += result;
		else if (result < 0) //Error, then break
			total_read = -1;
	}

#ifdef _WIN32
	closesocket(sock);
#else
	close(sock);
#endif

	if (total_read == 0) //In some non-error cases, radamsa just returns 0 bytes
	{ //Since we don't want to do this, just call the mutator again
		total_read = mutate_inner(state, buffer, buffer_length);
	}

	return total_read;
}

/**
 * This function will mutate the input given in the create function and return it in the buffer argument.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param buffer - a buffer that the mutated input will be written to
 * @param buffer_length - the size of the passed in buffer argument.  It must be at least as large as
 * the original input buffer.
 * @return - the length of the mutated data, 0 when the mutator is out of mutations, or -1 on error
 */
RADAMSA_MUTATOR_API int FUNCNAME(mutate)(void * mutator_state, char * buffer, size_t buffer_length)
{
	radamsa_state_t * state = (radamsa_state_t *)mutator_state;
	state->iteration++;
	return mutate_inner(state, buffer, buffer_length);
}

/**
 * This function will mutate the input given in the create function and return it in the buffer argument.
 * This function also accepts a set of flags which instruct it how to mutate the input.  See global_types.h
 * for the list of available flags.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param buffer - a buffer that the mutated input will be written to
 * @param buffer_length - the size of the passed in buffer argument.  It must be at least as large as
 * the original input buffer.
 * @param flags - A set of mutate flags that modify how this mutator mutates the input.
 * @return - the length of the mutated data, 0 when the mutator is out of mutations, or -1 on error
 */
RADAMSA_MUTATOR_API int FUNCNAME(mutate_extended)(void * mutator_state, char * buffer, size_t buffer_length, uint64_t flags)
{
	SINGLE_INPUT_MUTATE_EXTENDED(radamsa_state_t, state->mutate_mutex);
}

RADAMSA_MUTATOR_API char * FUNCNAME(get_state)(void * mutator_state)
{
	radamsa_state_t * state = (radamsa_state_t *)mutator_state;
	json_t *state_obj, *temp;
	char * ret;

	state_obj = json_object();
	if (!state_obj)
		return NULL;
	ADD_INT(temp, state->iteration, state_obj, "iteration");
	ADD_INT(temp, state->radamsa_iteration, state_obj, "radamsa_iteration");
	ADD_INT(temp, state->seed, state_obj, "seed");
	ret = json_dumps(state_obj, 0);
	json_decref(state_obj);
	return ret;
}

RADAMSA_MUTATOR_API int FUNCNAME(set_state)(void * mutator_state, char * state)
{
	radamsa_state_t * current_state = (radamsa_state_t *)mutator_state;
	int result, temp;

	if (state) {
		GET_INT(temp, state, current_state->iteration, "iteration", result);
		GET_INT(temp, state, current_state->radamsa_iteration, "radamsa_iteration", result);
		GET_INT(temp, state, current_state->seed, "seed", result);
	}
	cleanup_process(current_state);
	return start_process(current_state);
}

RADAMSA_MUTATOR_API int FUNCNAME(get_current_iteration)(void * mutator_state)
{
	GENERIC_MUTATOR_GET_ITERATION(radamsa_state_t);
}

/**
 * Obtains information about the inputs that were given to the mutator when it was created
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param num_inputs - a pointer to an integer used to return the number of inputs given to this mutator
 * when it was created.  This parameter is optional and can be NULL, if this information is not needed
 * @param input_sizes - a pointer to a size_t array used to return the sizes of the inputs given to this
 * mutator when it was created. This parameter is optional and can be NULL, if this information is not needed.
 */
RADAMSA_MUTATOR_API void FUNCNAME(get_input_info)(void * mutator_state, int * num_inputs, size_t **input_sizes)
{
	SINGLE_INPUT_GET_INFO(radamsa_state_t);
}

/**
* This function will set the input(saved in the mutators state) to something new.
* This can be used to reinitialize a mutator with new data, without reallocating the entire state struct.
* @param mutator_state - a mutator specific structure previously created by the create function.
* @param new_input - The new input used to produce new mutated inputs later when the mutate function is called
* @param input_length - the size in bytes of the input buffer.
* @return 0 on success and -1 on failure
*/
RADAMSA_MUTATOR_API int FUNCNAME(set_input)(void * mutator_state, char * new_input, size_t input_length)
{
	radamsa_state_t * state = (radamsa_state_t *)mutator_state;
	if (state->input) {
		free(state->input);
		state->input = NULL;
	}
	state->input = (char *)malloc(input_length);
	if (!state->input) {
		return -1;
	}
	state->input_length = input_length;
	memcpy(state->input, new_input, input_length);
	FUNCNAME(set_state)(mutator_state, NULL); //give the new input to radamsa.exe
	return 0;
}

/**
* This function sets a help message for the mutator. This is useful
* if the mutator takes a JSON options string in the create() function.
* @param help_str - A pointer that will be updated to point to the new help string.
* @return 0 on success and -1 on failure
*/
RADAMSA_MUTATOR_API int FUNCNAME(help)(char** help_str)
{
	GENERIC_MUTATOR_HELP(
"radamsa - Radamsa mutator (Starts and calls radamsa to mutate input)\n"
"Options:\n"
"  path                  The path to radamsa.exe\n"
"  port                  The port to tell radamsa to bind to when starting up\n"
"  radamsa_iteration     The number of iterations to seek forward in the\n"
"                          radamsa output\n"
"  seed                  The random seed to use when mutating\n"
"\n"
	);
}

static void cleanup_process(radamsa_state_t * state)
{
	if (state->process)
	{
#ifdef _WIN32
		TerminateProcess(state->process, 9);
		CloseHandle(state->process);
		state->process = NULL;
#else
		int status;
		kill(state->process, 9);
		wait(&status);
		state->process = 0;
#endif
	}
	state->radamsa_up = 0;
}

static int start_process(radamsa_state_t * state)
{
	char cmd_line[256];
	snprintf(cmd_line, sizeof(cmd_line), "%s -o :%d -n inf -s %d ", state->path, state->port, state->seed);
	if (state->radamsa_iteration != 0)
		snprintf(cmd_line, sizeof(cmd_line), "%s -S %d ", cmd_line, state->radamsa_iteration + 1); //radamsa counts from 1
	return start_process_and_write_to_stdin(cmd_line, state->input, state->input_length, &state->process);
}
