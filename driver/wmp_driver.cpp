#include "wmp_driver.h"

#include <jansson_helper.h>
#include <utils.h>
#include <instrumentation.h>
#include "driver.h"

//c headers
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

//Windows API
#include <process.h>
#include <Mmdeviceapi.h>
#include <mmdeviceapi.h>
#include <endpointvolume.h>

static int is_playing_sound();

/**
 * This function creates a wmp_state_t object based on the given options.
 * @param options - A JSON string of the options to set in the new wmp_state_t. See the
 * help function for more information on the specific options available.
 * @return - the wmp_state_t generated from the options in the JSON options string, or NULL on failure
 */
static wmp_state_t * setup_options(char * options)
{
	wmp_state_t * state;
	size_t cmd_length;

	state = (wmp_state_t *)malloc(sizeof(wmp_state_t));
	if (!state)
		return NULL;
	memset(state, 0, sizeof(wmp_state_t));


	//Setup defaults
	state->extension = strdup(".aac"); //strdup'd so we can uniformly free it later
	state->path = strdup("C:\\Program Files (x86)\\Windows Media Player\\wmplayer.exe"); //strdup'd so we can uniformly free it later
	state->timeout = 2;
	state->input_ratio = 2.0;

	if (options && strlen(options))
	{
		PARSE_OPTION_STRING(state, options, path, "path", wmp_cleanup);
		PARSE_OPTION_STRING(state, options, extension, "extension", wmp_cleanup);
		PARSE_OPTION_INT(state, options, timeout, "timeout", wmp_cleanup);
		PARSE_OPTION_DOUBLE(state, options, input_ratio, "ratio", wmp_cleanup);
	}

	//Create a test filename to write the fuzz file to
	state->test_filename = get_temp_filename(state->extension);

	cmd_length = strlen(state->path) + strlen(state->test_filename) + 10;
	state->cmd_line = (char *)malloc(cmd_length);
	if (!state->cmd_line) {
		wmp_cleanup(state);
		return NULL;
	}
	snprintf(state->cmd_line, cmd_length, "\"%s\" /play %s", state->path, state->test_filename);

	return state;
}

/**
 * This function allocates and initializes a new driver specific state object based on the given options.
 * @param options - a JSON string that contains the driver specific string of options
 * @param instrumentation - a pointer to an instrumentation instance that the driver will use
 * to instrument the requested program.  This instrumentation instance should already be initialized.
 * @param instrumentation_state - a pointer to the instrumentation state for the passed in instrumentation
 * @return - A driver specific state object on success or NULL on failure
 */
void * wmp_create(char * options, instrumentation_t * instrumentation, void * instrumentation_state,
	mutator_t * mutator, void * mutator_state)
{
	wmp_state_t * state;
	int num_inputs;
	size_t *input_sizes;

	state = setup_options(options);
	if (!state)
		return NULL;

	//We need to call this before we make WINAPI calls to get the audio device below
	CoInitialize(NULL);

	if (mutator)
	{
		mutator->get_input_info(mutator_state, &num_inputs, &input_sizes);
		if (num_inputs != 1
			|| setup_mutate_buffer(state->input_ratio, input_sizes[0], &state->mutate_buffer, &state->mutate_buffer_length))
		{
			free(input_sizes);
			wmp_cleanup(state);
			return NULL;
		}
		free(input_sizes);
	}

	state->mutator = mutator;
	state->mutator_state = mutator_state;
	state->mutate_last_size = -1;
	state->instrumentation = instrumentation;
	state->instrumentation_state = instrumentation_state;
	return state;
}

/**
 * This function cleans up all resources with the passed in driver state.
 * @param driver_state - a driver specific state object previously created by the wmp_create function
 * This state object should not be referenced after this function returns.
 */
void wmp_cleanup(void * driver_state)
{
	wmp_state_t * state = (wmp_state_t *)driver_state;

	free(state->mutate_buffer);

	free(state->path);
	free(state->extension);
	free(state->cmd_line);
	if (state->test_filename)
	{
		unlink(state->test_filename);
		free(state->test_filename);
	}
	free(state);
}

/**
 * This function will run wmplayer.exe and test it with the given input. This function
 * blocks until the wmplayer.exe has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the wmp_create function
 * @param input - the input that should be tested
 * @param length - the length of the input parameter
 * @return - FUZZ_ result on success or FUZZ_ERROR on failure
 */
int wmp_test_input(void * driver_state, char * input, size_t length)
{
	wmp_state_t * state = (wmp_state_t *)driver_state;

	//Write the input to disk
	write_buffer_to_file(state->test_filename, input, length);

	//Start the process and give it our input
	if(state->instrumentation->enable(state->instrumentation_state, &state->process, state->cmd_line, NULL, 0))
		return FUZZ_ERROR;

	time_t start_time = time(NULL);
	int tmp_result = FUZZ_ERROR;

	// This is reimplementing the loop in generic_wait_for_process
	// completion, because we want to do an additional check:
	// `is_playing_sound`, which can end early.
	//
	// We assume that if WMP is playing sound, it has successfully
	// processed input, which means that we won't get a crash.
	while (1)
	{
		tmp_result = state->instrumentation->is_process_done(state->instrumentation_state);

		if (tmp_result == 1) // process is done, it crashed or exited cleanly
		{
			// so fetch the result from the instrumentation
			return state->instrumentation->get_fuzz_result(state->instrumentation_state);
		}
		else if (tmp_result == -1)
		{
			return FUZZ_ERROR;
		} // else it's still running, so do our other checks

		// WMP is playing sound, so we don't expect a crash and can end
		// this fuzz round.
		if (is_playing_sound())
			return FUZZ_NONE;
		
		if (time(NULL) - start_time > state->timeout)
			return FUZZ_HANG;
		
		Sleep(50);
	}

	// We should never get here, because we should take one of the return
	// statements in the above loop.
	return FUZZ_ERROR;
}

/**
 * This function will run the fuzzed program with the output of the mutator given during driver
 * creation.  This function blocks until the program has finished processing the input.
 * @param driver_state - a driver specific structure previously created by the wmp_create function
 * @return - FUZZ_ result on success, FUZZ_ERROR on error, -2 if the mutator has finished generating inputs
 */
int wmp_test_next_input(void * driver_state)
{
	wmp_state_t * state = (wmp_state_t *)driver_state;
	return generic_test_next_input(state, state->mutator, state->mutator_state, state->mutate_buffer,
		state->mutate_buffer_length, wmp_test_input, &state->mutate_last_size);
}

/**
 * When this driver is using a mutator given to it during driver creation, this function retrieves
 * the last input that was tested with the wmp_test_next_input function.
 * @param driver_state - a driver specific structure previously created by the wmp_create function
 * @param length - a pointer to an integer used to return the length of the input that was last tested.
 * @return - NULL on error or if the driver doesn't have a mutator, or a buffer containing the last input
 * that was tested by the driver with the wmp_test_next_input function.  This buffer should be freed
 * by the caller.
 */
char * wmp_get_last_input(void * driver_state, int * length)
{
	wmp_state_t * state = (wmp_state_t *)driver_state;
	if (!state->mutator || state->mutate_last_size <= 0)
		return NULL;
	*length = state->mutate_last_size;
	return (char *)memdup(state->mutate_buffer, state->mutate_last_size);
}

#define EXIT_ON_ERROR(hres)  \
              if (FAILED(hres)) { goto done; }
#define SAFE_RELEASE(punk)  \
              if ((punk) != NULL)  \
                { (punk)->Release(); (punk) = NULL; }

/**
 * This function determines if any sound is currently being played out the speakers.  This is used to
 * determine if the wmplayer.exe process has finished parsing the fuzzed file and now trying to play it.
 * @return - 1 if sound is being played, 0 if sound is not being played, and -1 if an error occurs.
 */
static int is_playing_sound()
{
	HRESULT hr = S_OK;
	IMMDeviceEnumerator *pEnumerator = NULL;
	IMMDevice *pDevice = NULL;
	IAudioMeterInformation *pMeterInfo = NULL;
	HWND hPeakMeter = NULL;
	float peak = 0;
	int ret = -1;

	hr = CoCreateInstance(
		__uuidof(MMDeviceEnumerator), NULL,
		CLSCTX_ALL, __uuidof(IMMDeviceEnumerator),
		(void**)&pEnumerator);
	EXIT_ON_ERROR(hr);

	hr = pEnumerator->GetDefaultAudioEndpoint(eRender, eConsole, &pDevice);
	EXIT_ON_ERROR(hr);

	hr = pDevice->Activate(__uuidof(IAudioMeterInformation), CLSCTX_ALL, NULL, (void**)&pMeterInfo);
	EXIT_ON_ERROR(hr);

	hr = pMeterInfo->GetPeakValue(&peak);
	EXIT_ON_ERROR(hr);
	ret = peak > 0;

done:
	SAFE_RELEASE(pEnumerator);
	SAFE_RELEASE(pDevice);
	SAFE_RELEASE(pMeterInfo)
	return ret;
}

/**
 * This function returns help text for this driver.  This help text will describe the driver and any options
 * that can be passed to wmp_create.
 * @param help_str - A pointer that will be updated to point to the new help string.
 * @return 0 on success and -1 on failure
 */
int wmp_help(char ** help_str)
{
	*help_str = strdup(
"wmp - Windows Media Player driver (Fuzzes wmplayer.exe)\n"
"Optional Arguments:\n"
"  extension             The file extension of the input files to\n"
"                          wmplayer.exe\n"
"  path                  The path to the wmplayer.exe\n"
"  ratio                 The ratio of mutation buffer size to input size\n"
"                          when given a mutator\n"
"  timeout               The maximum number of seconds to wait for the\n"
"                          target process to finish\n"
"\n"
	);
	if (*help_str == NULL)
		return -1;
	return 0;
}

