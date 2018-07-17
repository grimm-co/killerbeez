#include "network_driver.h"

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
 * This function creates a network_state_t object based on the given options.
 * @param options - A JSON string of the options to set in the new network_state_t. See the
 * help function for more information on the specific options available.
 * @return - the network_state_t generated from the options in the JSON options string, or NULL on failure
 */
static network_state_t * setup_options(char * options)
{
	network_state_t * state;
	size_t cmd_length;

	state = (network_state_t *)malloc(sizeof(network_state_t));
	if (!state)
		return NULL;
	memset(state, 0, sizeof(network_state_t));

	//Setup defaults
	state->timeout = 2;
	state->input_ratio = 2.0;

	//Parse the options
	PARSE_OPTION_STRING(state, options, path, "path", network_cleanup);
	PARSE_OPTION_STRING(state, options, arguments, "arguments", network_cleanup);
	PARSE_OPTION_INT(state, options, timeout, "timeout", network_cleanup);
	PARSE_OPTION_INT(state, options, target_port, "port", network_cleanup);
	PARSE_OPTION_STRING(state, options, target_ip, "ip", network_cleanup);
	PARSE_OPTION_INT(state, options, target_udp, "udp", network_cleanup);
	PARSE_OPTION_INT(state, options, skip_network_check, "skip_network_check", network_cleanup);
	PARSE_OPTION_DOUBLE(state, options, input_ratio, "ratio", network_cleanup);
	PARSE_OPTION_INT_ARRAY(state, options, sleeps, sleeps_count, "sleeps", network_cleanup);

	cmd_length = (state->path ? strlen(state->path) : 0) + (state->arguments ? strlen(state->arguments) : 0) + 2;
	state->cmd_line = (char *)malloc(cmd_length);

	if (!state->path || !state->cmd_line || !file_exists(state->path) || !state->target_ip || !state->target_port || state->input_ratio <= 0)
	{
		network_cleanup(state);
		return NULL;
	}

	snprintf(state->cmd_line, cmd_length, "%s %s", state->path, state->arguments ? state->arguments : "");

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
void * network_create(char * options, instrumentation_t * instrumentation, void * instrumentation_state,
	mutator_t * mutator, void * mutator_state)
{
	WSADATA wsaData;
	network_state_t * state;
	int i;

	//This driver requires at least the path to the program to run. Make sure we either have both a mutator and state
	if (!options || !strlen(options) || (mutator && !mutator_state) || (!mutator && mutator_state)) //or neither
		return NULL;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
		ERROR_MSG("WSAStartup Failed\n");
		return NULL;
	}
	
	state = setup_options(options);
	if (!state)
		return NULL;

	if (mutator)
	{
		mutator->get_input_info(mutator_state, &state->num_inputs, &state->mutate_buffer_lengths);
		if (state->sleeps && state->num_inputs != state->sleeps_count)
		{
			network_cleanup(state);
			return NULL;
		}

		state->mutate_buffers = malloc(sizeof(char *) * state->num_inputs);
		if (!state->mutate_buffers) {
			network_cleanup(state);
			return NULL;
		}

		//Setup the mutate buffers
		state->mutate_buffers = malloc(sizeof(char *) * state->num_inputs);
		state->mutate_last_sizes = malloc(sizeof(int) * state->num_inputs);
		memset(state->mutate_buffers, 0, sizeof(char *) * state->num_inputs);
		for (i = 0; i < state->num_inputs; i++)
		{
			if(setup_mutate_buffer(state->input_ratio, state->mutate_buffer_lengths[i], &state->mutate_buffers[i],
				&state->mutate_buffer_lengths[i]))
			{
				network_cleanup(state);
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
 * @param state - the network_state_t object that represents the current state of the driver
 */
static void cleanup_process(network_state_t * state)
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
 * @param driver_state - a driver specific state object previously created by the network_create function
 * This state object should not be referenced after this function returns.
 */
void network_cleanup(void * driver_state)
{
	network_state_t * state = (network_state_t *)driver_state;
	int i;

	cleanup_process(state);
	for(i = 0; state->mutate_buffers && i < state->num_inputs; i++)
		free(state->mutate_buffers[i]);
	free(state->mutate_buffers);
	free(state->mutate_buffer_lengths);
	free(state->mutate_last_sizes);
	
	free(state->path);
	free(state->arguments);
	free(state->cmd_line);
	free(state->target_ip);
	free(state->sleeps);
	free(state);
}

/**
 * This function creates a socket and (when using TCP) connects it to the fuzzed program.
 * @param state - the network_state_t object that represents the current state of the driver
 * @param sock - a pointer to a SOCKET used to return the created socket
 * @return - non-zero on error, zero on success
 */
static int connect_to_target(network_state_t * state, SOCKET * sock)
{
	struct sockaddr_in addr;

	if(state->target_udp)
		*sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	else
		*sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (*sock == INVALID_SOCKET)
		return 1;

	if (!state->target_udp)
	{
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr(state->target_ip);
		addr.sin_port = htons(state->target_port);
		if (connect(*sock, (const struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
			closesocket(*sock);
			return 1;
		}
	}

	return 0;
}

/**
 * This function sends the provided buffer on the arleady connected TCP socket
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
	}

	return total_read != length;
}

/**
 * This function sends the provided buffer on the UDP socket
 * @param state - the network_state_t object that represents the current state of the driver
 * @param sock - a pointer to a UDP SOCKET to send the buffer on
 * @param buffer - the buffer to send
 * @param length - the length of the buffer parameter
 * @return - non-zero on error, zero on success
 */
static int send_udp_input(network_state_t * state, SOCKET * sock, char * buffer, size_t length)
{
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(state->target_ip);
	addr.sin_port = htons(state->target_port);
	if (sendto(*sock, buffer, length, 0, (const struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
		return 1;
	return 0;
}

/**
 * This function determines if there is a program listening on the specified port on the local computer
 * @param port - the port number to check
 * @param udp - whether the specified port is udp (1) or tcp (0)
 * @return - 1 if the port is listening, 0 if the port is not listening, or -1 on error
 */
static int is_port_listening(int port, int udp)
{
	MIB_TCPTABLE * tcp_table;
	MIB_UDPTABLE * udp_table;
	DWORD i, size = 0;

	if (udp) {
		if (GetUdpTable(NULL, &size, TRUE) != ERROR_INSUFFICIENT_BUFFER)
			return -1;
		udp_table = malloc(size);
		if (!udp_table)
			return -1;
		if (GetUdpTable(udp_table, &size, TRUE) != NO_ERROR) {
			free(udp_table);
			return -1;
		}
		for (i = 0; i < udp_table->dwNumEntries; i++) {
			if (udp_table->table[i].dwLocalPort == htons(port))
			{
				free(udp_table);
				return 1;
			}
		}
		free(udp_table);

	} else {
		if (GetTcpTable(NULL, &size, TRUE) != ERROR_INSUFFICIENT_BUFFER)
			return -1;
		tcp_table = malloc(size);
		if (!tcp_table)
			return -1;
		if (GetTcpTable(tcp_table, &size, TRUE) != NO_ERROR) {
			free(tcp_table);
			return -1;
		}
		for (i = 0; i < tcp_table->dwNumEntries; i++) {
			if (tcp_table->table[i].dwState == MIB_TCP_STATE_LISTEN && tcp_table->table[i].dwLocalPort == htons(port))
			{
				free(tcp_table);
				return 1;
			}
		}
		free(tcp_table);
	}
	return 0;
}

/**
 * This function will run the fuzzed program and test it with the given inputs. This function
 * blocks until the program has finished processing the input.
 * @param state - the network_state_t object that represents the current state of the driver
 * @param inputs - an array of inputs to send to the program
 * @param lengths - an array of lengths for the buffers in the inputs parameter
 * @param inputs_count - the number of buffers in the inputs parameter
 * @return - 0 on success or -1 on failure
 */
static int network_run(network_state_t * state, char ** inputs, size_t * lengths, size_t inputs_count)
{
	SOCKET sock;
	size_t i;
	int listening = 0;

	//Start the process and give it our input
	if (state->instrumentation)
	{
		//Have the instrumentation start the new process, since it needs to do so in a custom environment
		state->instrumentation->enable(state->instrumentation_state, &state->process, state->cmd_line, NULL, 0);
	}
	else
	{
		//kill any previous processes so they release the file we're gonna write to
		cleanup_process(state);

		//Start the new process
		if (start_process_and_write_to_stdin(state->cmd_line, NULL, 0, &state->process))
		{
			cleanup_process(state);
			return -1;
		}
	}

	//Wait for the port to be listening
	while (!state->skip_network_check && listening == 0) {
		listening = is_port_listening(state->target_port, state->target_udp);
		if(listening == 0)
			Sleep(5);
	}
	if(listening < 0)
		return -1;

	if (connect_to_target(state, &sock)) // opens socket
		return -1;
	for (i = 0; i < inputs_count; i++)
	{
		if (state->sleeps && state->sleeps[i] != 0)
			Sleep(state->sleeps[i]);
		if (state->target_udp && send_udp_input(state, &sock, inputs[i], lengths[i])
			|| (!state->target_udp && send_tcp_input(&sock, inputs[i], lengths[i])))
		{
			closesocket(sock);
			return -1;
		}
	}
	closesocket(sock);

	//Wait for it to be done
	generic_wait_for_process_completion(&state->fuzz_result, state->process, state->timeout, state->instrumentation, state->instrumentation_state);

	return driver_get_fuzz_result(&state->fuzz_result, state->instrumentation, state->instrumentation_state);
}

/**
 * This function will run the fuzzed program and test it with the given input. This function
 * blocks until the program has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the network_create function
 * @param input - the input that should be tested
 * @param length - the length of the input parameter
 * @return - FUZZ_CRASH, FUZZ_HANG, or FUZZ_NONE on success or -1 on failure
 */
int network_test_input(void * driver_state, char * input, size_t length)
{
	network_state_t * state = (network_state_t *)driver_state;
	char ** inputs;
	size_t * input_lengths;
	size_t i, inputs_count;

	if (decode_mem_array(input, &inputs, &input_lengths, &inputs_count))
		return -1;
	if (inputs_count)
	{
		if (network_run(state, inputs, input_lengths, inputs_count) == -1)
		{
			network_test_input_cleanup(inputs, inputs_count, input_lengths);
			return -1;
		}
	}
	network_test_input_cleanup(inputs, inputs_count, input_lengths);

	return driver_get_fuzz_result(&state->fuzz_result, state->instrumentation, state->instrumentation_state);
}

static void network_test_input_cleanup(char ** inputs, size_t inputs_count, size_t * input_lengths)
{
	for (i = 0; i < inputs_count; i++)
		free(inputs[i]);
	free(inputs);
	free(input_lengths);
}

/**
 * This function will run the fuzzed program with the output of the mutator given during driver
 * creation.  This function blocks until the program has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the network_create function
 * @return - FUZZ_CRASH, FUZZ_HANG, or FUZZ_NONE on success, -1 on error, -2 if the mutator has finished generating inputs
 */
int network_test_next_input(void * driver_state)
{
	network_state_t * state = (network_state_t *)driver_state;
	int i;

	if (!state->mutator)
		return -1;
	
	memset(state->mutate_last_sizes, 0, sizeof(int) * state->num_inputs);
	for (i = 0; i < state->num_inputs; i++)
	{
		state->mutate_last_sizes[i] = state->mutator->mutate_extended(state->mutator_state,
			state->mutate_buffers[i], state->mutate_buffer_lengths[i], MUTATE_MULTIPLE_INPUTS | i);
		if (state->mutate_last_sizes[i] < 0)
			return -1;
		else if (state->mutate_last_sizes[i] == 0)
			return -2;
	}

	if(network_run(state, state->mutate_buffers, state->mutate_last_sizes, state->num_inputs) == -1)
		return -1;

	return driver_get_fuzz_result(&state->fuzz_result, state->instrumentation, state->instrumentation_state);
}

/**
 * When this driver is using a mutator given to it during driver creation, this function retrieves
 * the last input that was tested with the network_test_next_input function.
 * @param driver_state - a driver specific structure previously created by the network_create function
 * @param length - a pointer to an integer used to return the length of the input that was last tested.
 * @return - NULL on error or if the driver doesn't have a mutator, or a buffer containing the last input
 * that was tested by the driver with the network_test_next_input function.  This buffer should be freed
 * by the caller.
 */
char * network_get_last_input(void * driver_state, int * length)
{
	network_state_t * state = (network_state_t *)driver_state;
	int i;

	if (!state->mutate_buffers)
		return NULL;
	for (i = 0; i < state->num_inputs; i++)
	{
		if (state->mutate_last_sizes[i] <= 0)
			return NULL;
	}
	return encode_mem_array(state->mutate_buffers, state->mutate_last_sizes, state->num_inputs, length);
}

/**
 * This function returns help text for this driver.  This help text will describe the driver and any options
 * that can be passed to network_create.
 * @return - a newly allocated string containing the help text.
 */
char * network_help(void)
{
	return strdup(
		"network - network driver (Sends mutated input over the network to the target process)\n"
		"Required Options:\n"
		"\tip                    The target IP to connect to\n"
		"\tpath                  The path to the target process\n"
		"\tport                  The target port to connect to\n"
		"Optional Options:\n"
		"\targuments             Arguments to pass to the target process\n"
		"\ttimeout               The maximum number of seconds to wait for the target process to finish\n"
		"\tratio                 The ratio of mutation buffer size to input size when given a mutator\n"
		"\tskip_network_check    Whether or not to wait for the specified port to be listening on the localhost\n"
		"\t                      prior to connecting to the target program\n"
		"\tsleeps                An array of milliseconds to wait between each input being sent to the target program\n"
		"\tudp                   Whether the fuzzed input should be sent to the target program on UDP (1) or TCP (0)\n"
		"\n"
	);
}
