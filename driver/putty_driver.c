#include "putty_driver.h"

#include <utils.h>
#include <jansson_helper.h>
#include <instrumentation.h>
#include "driver.h"

//c headers
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

//Windows API
#include <Shlwapi.h>
#include <iphlpapi.h>
#include <process.h>

/**
 * This function creates a putty_state_t object based on the given options.
 * @param options - A JSON string of the options to set in the new putty_state_t. See the
 * help function for more information on the specific options available.
 * @return - the putty_state_t generated from the options in the JSON options string, or NULL on failure
 */
static putty_state_t * setup_options(char * options)
{
	putty_state_t * state;
	size_t cmd_length;

	state = (putty_state_t *)malloc(sizeof(putty_state_t));
	if (!state)
		return NULL;
	memset(state, 0, sizeof(putty_state_t));

	//Setup defaults
	state->timeout = 2;
	state->input_ratio = 2.0;
	state->lport = 9999;
	state->ip = strdup("127.0.0.1");

	//Parse the options
	PARSE_OPTION_STRING(state, options, path, "path", putty_cleanup);
	PARSE_OPTION_STRING(state, options, arguments, "arguments", putty_cleanup);
	PARSE_OPTION_INT(state, options, timeout, "timeout", putty_cleanup);
	PARSE_OPTION_INT(state, options, lport, "port", putty_cleanup);
	PARSE_OPTION_STRING(state, options, ip, "ip", putty_cleanup);
	PARSE_OPTION_DOUBLE(state, options, input_ratio, "ratio", putty_cleanup);
	PARSE_OPTION_INT_ARRAY(state, options, sleeps, sleeps_count, "sleeps", putty_cleanup);
	
	cmd_length = (state->path ? strlen(state->path) : 0) + (state->arguments ? strlen(state->arguments) : 0) + 4;
	state->cmd_line = (char *)malloc(cmd_length);
	memset(state->cmd_line, 0, cmd_length);

	if (!state->path || !state->cmd_line || !file_exists(state->path)
		|| !state->ip || !state->lport || state->input_ratio <= 0)
	{
		putty_cleanup(state);
		return NULL;
	}
	//Build the cmd line
	snprintf(state->cmd_line, cmd_length, "\"%s\" %s", state->path, state->arguments ? state->arguments : "");

	return state;
}

/**
 * This function allocates and initializes a new driver specific state object based on the given options.
 * @param options - a JSON string that contains the driver specific string of options
 * @param instrumentation - a pointer to an instrumentation instance that the driver will use
 * to instrument the requested program.  This instrumentation instance should already be initialized.
 * @param instrumentation_state - a pointer to the instrumentation state for the passed in instrumentation
 * @return - a driver specific state object on success or NULL on failure
 */
void * putty_create(char * options, instrumentation_t * instrumentation, void * instrumentation_state,
	mutator_t * mutator, void * mutator_state)
{
	WSADATA wsaData;
	putty_state_t * state;
	size_t i;

	//Make sure we either have both a mutator and state
	if (!options || !strlen(options) || (mutator && !mutator_state) || (!mutator && mutator_state))
	{ //or neither
		FATAL_MSG("ERROR: Missing driver options");
		return NULL;
	}
	//Startup because we gonna use the winsock DLL
	if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
		ERROR_MSG("WSAStartup Failed");
		return NULL;
	}

	state = setup_options(options);
	if (!state)
		return NULL;
	if (mutator)
	{
		mutator->get_input_info(mutator_state, &state->num_inputs, &state->mutate_buffer_lengths);
		
		//size of sleeps array and inputs must be equal
		if (state->sleeps && state->num_inputs != state->sleeps_count)
		{
			putty_cleanup(state);
			return NULL;
		}

		//Setup the mutate buffers
		//allocate space for the array of mutate buffers
		state->mutate_buffers = malloc(sizeof(char *) * state->num_inputs);
		if (!state->mutate_buffers)
		{
			putty_cleanup(state);
			return NULL;
		}
		memset(state->mutate_buffers, 0, sizeof(char *) * state->num_inputs);

		//Allocate space for the array containing the sizes the mutate buffers
		state->mutate_last_sizes = malloc(sizeof(size_t) * state->num_inputs);
		if (!state->mutate_last_sizes)
		{
			putty_cleanup(state);
			return NULL;
		}
		
		//populate the array of mutate buffers
		for (i = 0; i < state->num_inputs; i++)
		{
			if (setup_mutate_buffer(state->input_ratio, state->mutate_buffer_lengths[i], &state->mutate_buffers[i],
				&state->mutate_buffer_lengths[i]))
			{
				putty_cleanup(state);
				return NULL;
			}
			state->mutate_last_sizes[i] = -1;
		}

		state->mutator = mutator;
		state->mutator_state = mutator_state;
	}

	state->instrumentation = instrumentation;
	state->instrumentation_state = instrumentation_state;
	return state;
}

/**
 * This function cleans up the fuzzed process, if it's not being managed
 * by the instrumentation module instead.
 * @param state - the putty_state_t object that represents the current state of the driver
 */
static void cleanup_process(putty_state_t * state)
{
	//If we have a process running and no instrumentation, kill it.
	//If we have an instrumentation, then the instrumentation will kill the process
	if (state->process && !state->instrumentation)
	{
		TerminateProcess(state->process, 9);
		CloseHandle(state->process);
		state->process = NULL;
	}
}

/**
 * This function cleans up all resources with the passed in driver state.
 * @param driver_state - a driver specific state object previously created by the putty_create function
 * This state object should not be referenced after this function returns.
 */
void putty_cleanup(void * driver_state)
{
	putty_state_t * state = (putty_state_t *)driver_state;
	int i;

	//stop the fuzzed process
	cleanup_process(state);

	//Cleanup mutator stuff
	for (i = 0; state->mutate_buffers && i < state->num_inputs; i++)
		free(state->mutate_buffers[i]);
	free(state->mutate_buffers);
	free(state->mutate_buffer_lengths);
	free(state->mutate_last_sizes);

	//Clean up driver specific options
	free(state->path);
	free(state->arguments);
	free(state->ip);
	free(state->cmd_line);
	free(state->sleeps);

	//Clean up the struct holding it all
	free(state);
}

/**
* This function sends the provided buffer on the already connected TCP socket
* @param sock - a pointer to a connected TCP SOCKET to send the buffer on
* @param buffer - the buffer to send
* @param length - the length of the buffer parameter
* @return - non-zero on error, zero on success
*/
static int send_tcp_input(SOCKET * sock, char * buffer, size_t length)
{
	int result;
	size_t total_read = 0;

	result = 1;
	while (total_read < length && result > 0)
	{
		result = send(*sock, buffer + total_read, length - total_read, 0);
		if (result > 0)
			total_read += result;
		else if (result < 0) //Error, then break
			total_read = -1;
		if (result == SOCKET_ERROR)
			ERROR_MSG("send() failed with error: %d", WSAGetLastError());
	}

	return total_read != length;
}

/**
 * This function creates a socket and waits for a client to connect.
 * @param state - the putty_state_t object that represents the current state of the driver
 * @param sock - a pointer to a SOCKET used to return the created socket
 * @return - non-zero on error, zero on success
 */
static int start_listener(putty_state_t * state, SOCKET * sock)
{
	struct sockaddr_in addr;
	int iResult = 0;
	*sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (*sock == INVALID_SOCKET)
	{
		ERROR_MSG("socket function failed with error: %ld", WSAGetLastError());
		return 1;
	}
	//Create socket (TCP Only right now)
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(state->ip);
	addr.sin_port = htons(state->lport);
	//Now bind to the socket
	iResult = bind(*sock, (SOCKADDR *)& addr, sizeof(addr));
	if (iResult == SOCKET_ERROR)
	{
		ERROR_MSG("Socket failed to bind, error: %d", WSAGetLastError());
		iResult = closesocket(*sock);
		if (iResult == SOCKET_ERROR)
			ERROR_MSG("closesocket function failed with error %d", WSAGetLastError());
		return 1;
	}
	//Now put the socket into LISTEN state
	if (listen(*sock, SOMAXCONN) == SOCKET_ERROR)
	{
		ERROR_MSG("listen function failed with error: %d", WSAGetLastError());
		return 1;
	}

	return 0;
}

/**
 * This function will run the fuzzed program and test it with the given inputs. This function
 * blocks until the program has finished processing the input.
 * @param state - the putty_state_t object that represents the current state of the driver
 * @param inputs - an array of inputs to send to the program
 * @param lengths - an array of lengths for the buffers in the inputs parameter
 * @param inputs_count - the number of buffers in the inputs parameter
 * @return - 0 on success or -1 on failure
 */
static int putty_run(putty_state_t * state, char ** inputs, size_t * lengths, size_t inputs_count)
{
	SOCKET serverSock;
	SOCKET clientSock;
	size_t i;
	int listening = 0;

	//Start the server socket so the client can connect below:
	if (start_listener(state, &serverSock))
	{
		return FUZZ_ERROR;
	}

	//Have the instrumentation start the new process, since it needs to do so in a custom environment
	state->instrumentation->enable(state->instrumentation_state, &state->process, state->cmd_line, NULL, 0);

	//Now accept the client connection
	clientSock = accept(serverSock, NULL, NULL);
	if (clientSock == INVALID_SOCKET)
	{
		FATAL_MSG("accept() failed with error: %d\n", WSAGetLastError());
		return FUZZ_ERROR;
	}
	closesocket(serverSock);

	for (i = 0; i < inputs_count; i++)
	{
		if (state->sleeps && state->sleeps[i] != 0)
			Sleep(state->sleeps[i]);
		if (send_tcp_input(&clientSock, inputs[i], lengths[i]))
		{
			return FUZZ_ERROR;
		}
	}
	closesocket(clientSock);
	
	//Wait for it to be done
	return generic_wait_for_process_completion(state->process, state->timeout, 
		state->instrumentation, state->instrumentation_state);
}

/**
 * This function will run the fuzzed program and test it with the given input.
 * This function blocks until the program has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the
 * 		putty_create function
 * @param input - the input that should be tested
 * @param length - the length of the input parameter
 * @return - FUZZ_NONE, FUZZ_HANG, FUZZ_CRASH on success or FUZZ_ERROR on failure
 */
int putty_test_input(void * driver_state, char * input, size_t length)
{
	putty_state_t * state = (putty_state_t *)driver_state;
	char ** inputs;
	size_t * input_lengths;
	size_t i, inputs_count;
	int ret = FUZZ_ERROR;

	if (decode_mem_array(input, &inputs, &input_lengths, &inputs_count) == 0)
	{
		if (inputs_count)
			ret = putty_run(state, inputs, input_lengths, inputs_count);
		
		//clean up time
		for (i = 0; i < inputs_count; i++)
			free(inputs[i]);

		free(inputs);
		free(input_lengths);
	}
	return ret;
}

/**
 * This function will run the fuzzed program with the output of the mutator given during driver
 * creation.  This function blocks until the program has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the putty_create function
 * @return - 0 on success, -1 on error, or -2 if the mutator has finished generating inputs
 */
int putty_test_next_input(void * driver_state)
{
	putty_state_t * state = (putty_state_t *)driver_state;
	int i;

	if (!state->mutator)
		return FUZZ_ERROR;

	memset(state->mutate_last_sizes, 0, sizeof(int) * state->num_inputs);
	for (i = 0; i < state->num_inputs; i++)
	{
		state->mutate_last_sizes[i] = state->mutator->mutate_extended(state->mutator_state,
			state->mutate_buffers[i], state->mutate_buffer_lengths[i], MUTATE_MULTIPLE_INPUTS | i);
		if (state->mutate_last_sizes[i] < 0)
			return FUZZ_ERROR;
		if (state->mutate_last_sizes[i] == 0)
			return -2;
	}
	return putty_run(state, state->mutate_buffers, state->mutate_last_sizes, state->num_inputs);
}

/**
 * When this driver is using a mutator given to it during driver creation, this function retrieves
 * the last input that was tested with the putty_test_next_input function.
 * @param driver_state - a driver specific structure previously created by the putty_create function
 * @param length - a pointer to an integer used to return the length of the input that was last tested.
 * @return - NULL on error or if the driver doesn't have a mutator, or a buffer containing the last input
 * that was tested by the driver with the putty_test_next_input function.  This buffer should be freed
 * by the caller.
 */
char * putty_get_last_input(void * driver_state, int * length)
{
	putty_state_t * state = (putty_state_t *)driver_state;
	int i;

	if (!state->mutate_buffers)
		return NULL;
	for (i = 0; i < state->num_inputs; i++)
	{
		if (state->mutate_last_sizes[i] <= 0)
			return NULL;
	}
	return encode_mem_array(state->mutate_buffers, 
		state->mutate_last_sizes, state->num_inputs, length);
}

/**
 * This function returns help text for this driver.  This help text will describe the driver and any options
 * that can be passed to putty_create.
 * @return - a newly allocated string containing the help text.
 */
char * putty_help(void)
{

	return strdup(
		"putty - putty driver (This driver acts as a server and forces the putty client\n"
		"to connect to be fuzzed)\n"
		"Required Options:\n"
		"\tpath					 The path to plink.exe"
		"\targuments             Arguments to pass to the target process\n"
		"Optional Options:\n"
		"\ttimeout               The maximum number of seconds to wait\n"
		"\t                      for the target process to finish\n"
		"\tratio                 The ratio of mutation buffer size to\n"
		"\t                      input size when given a mutator\n"
		"\tip                    The target IP to connect to\n"
		"\tport                  The target port to connect to\n"
		"\tratio                 The ratio of mutation buffer size to input\n"
		"\t                      size when given a mutator\n"
		"\tsleeps                An array of milliseconds to wait between each\n"
		"\t       				 input being sent to the target program\n"
		"\n"
	);
}
