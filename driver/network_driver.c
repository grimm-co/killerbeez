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
 * This function cleans up all resources with the passed in driver state.
 * @param driver_state - a driver specific state object previously created by the network_create function
 * This state object should not be referenced after this function returns.
 */
void network_cleanup(void * driver_state)
{
	network_state_t * state = (network_state_t *)driver_state;
	int i;

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
 * @return - FUZZ_ result on success or FUZZ_ERROR on failure
 */
static int network_run(network_state_t * state, char ** inputs, size_t * lengths, size_t inputs_count)
{
	SOCKET sock;
	size_t i;
	int listening = 0;

	//Start the process and give it our input
	if(state->instrumentation->enable(state->instrumentation_state, &state->process, state->cmd_line, NULL, 0))
		return FUZZ_ERROR;

	//Wait for the port to be listening
	while (!state->skip_network_check && listening == 0) {
		listening = is_port_listening(state->target_port, state->target_udp);
		if(listening == 0)
			Sleep(5);
	}
	if(listening < 0)
		return FUZZ_ERROR;

	if (connect_to_target(state, &sock)) // opens socket
		return FUZZ_ERROR;
	for (i = 0; i < inputs_count; i++)
	{
		if (state->sleeps && state->sleeps[i] != 0)
			Sleep(state->sleeps[i]);
		if (state->target_udp && send_udp_input(state, &sock, inputs[i], lengths[i])
			|| (!state->target_udp && send_tcp_input(&sock, inputs[i], lengths[i])))
		{
			closesocket(sock);
			return FUZZ_ERROR;
		}
	}
	closesocket(sock);

	//Wait for it to be done and return FUZZ_ result
	return generic_wait_for_process_completion(state->process, state->timeout,
		state->instrumentation, state->instrumentation_state);
}

static void network_test_input_cleanup(char ** inputs, size_t inputs_count, size_t * input_lengths)
{
	for (size_t i = 0; i < inputs_count; i++)
		free(inputs[i]);
	free(inputs);
	free(input_lengths);
}

/**
 * This function will run the fuzzed program and test it with the given input. This function
 * blocks until the program has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the network_create function
 * @param input - the input that should be tested
 * @param length - the length of the input parameter
 * @return - FUZZ_ result on success or FUZZ_ERROR on failure
 */
int network_test_input(void * driver_state, char * input, size_t length)
{
	network_state_t * state = (network_state_t *)driver_state;
	char ** inputs;
	size_t * input_lengths;
	size_t inputs_count;
	int network_run_result = FUZZ_ERROR;

	if (decode_mem_array(input, &inputs, &input_lengths, &inputs_count))
		return FUZZ_ERROR;
	if (inputs_count)
	{
		network_run_result = network_run(state, inputs, input_lengths, inputs_count);
		if (network_run_result == FUZZ_ERROR)
		{
			network_test_input_cleanup(inputs, inputs_count, input_lengths);
			return FUZZ_ERROR;
		}
	}
	network_test_input_cleanup(inputs, inputs_count, input_lengths);

	return network_run_result;
}


/**
 * This function will run the fuzzed program with the output of the mutator given during driver
 * creation.  This function blocks until the program has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the network_create function
 * @return - FUZZ_ result on success, FUZZ_ERROR on error, -2 if the mutator has finished generating inputs
 */
int network_test_next_input(void * driver_state)
{
	network_state_t * state = (network_state_t *)driver_state;
	int i;
	int network_run_result = FUZZ_ERROR;

	if (!state->mutator)
		return FUZZ_ERROR;
	
	memset(state->mutate_last_sizes, 0, sizeof(int) * state->num_inputs);
	for (i = 0; i < state->num_inputs; i++)
	{
		state->mutate_last_sizes[i] = state->mutator->mutate_extended(state->mutator_state,
			state->mutate_buffers[i], state->mutate_buffer_lengths[i], MUTATE_MULTIPLE_INPUTS | i);
		if (state->mutate_last_sizes[i] < 0)
			return FUZZ_ERROR;
		else if (state->mutate_last_sizes[i] == 0)
			return -2;
	}

	network_run_result = network_run(state, state->mutate_buffers, state->mutate_last_sizes, state->num_inputs);

	return network_run_result;
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
 * @param help_str - A pointer that will be updated to point to the new help string.
 * @return 0 on success and -1 on failure
 */
int network_help(char ** help_str)
{
	*help_str = strdup(
"network - Sends mutated input over the network to the target process\n"
"Required Options:\n"
"  ip                    The target IP to connect to\n"
"  path                  The path to the target process\n"
"  port                  The target port to connect to\n"
"Optional Options:\n"
"  arguments             Arguments to pass to the target process\n"
"  timeout               The maximum number of seconds to wait for the target\n"
"                          process to finish\n"
"  ratio                 The ratio of mutation buffer size to input size when\n"
"                          given a mutator\n"
"  skip_network_check    Whether or not to wait for the specified port to be\n"
"                          listening on the localhost prior to connecting to\n"
"                          the target program\n"
"  sleeps                An array of milliseconds to wait between each input\n"
"                          being sent to the target program\n"
"  udp                   Whether the fuzzed input should be sent to the target\n"
"                          program on UDP (1) or TCP (0)\n"
"\n"
	);
	if (*help_str == NULL)
		return -1;
	return 0;
}
