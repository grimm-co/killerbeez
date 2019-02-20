#include "multipart_mutator.h"
#include <mutators.h>

#ifdef _WIN32
#include <Shlwapi.h>
#else
#include <libgen.h>
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <utils.h>
#include <mutator_factory.h>
#include <jansson.h>
#include <jansson_helper.h>

typedef struct
{
	char ** mutator_names;
	char * mutator_directory;

	mutator_t ** mutators;
	void ** mutator_states;
	size_t mutator_count;
} multipart_state_t;

///////////////////////////////////////////////////////////////////////////////////////////
// Helper functions ///////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////

static int get_json_items(char * json_text, char * attribute_name, char *** output_array, int *all_use_same)
{
	json_error_t error;
	json_t * root, *json_array, *item;
	char ** dumped_array = NULL;
	int i, num_items;

	*output_array = NULL;
	*all_use_same = 0;

	if (!json_text)
		return 0;

	root = json_loads(json_text, 0, &error);
	if (!root)
		return -1;

	if (attribute_name) {
		json_array = json_object_get(root, attribute_name);
		if (!json_array) { //Couldn't find the attribute
			json_decref(root);
			return 0;
		}
	}
	else
		json_array = root;

	//if options isn't an array, then we want all the mutators to use the same options
	if(!json_is_array(json_array)) {
		dumped_array = malloc(sizeof(char *));
		dumped_array[0] = json_dumps(json_array, 0);
		*output_array = dumped_array;
		*all_use_same = 1;;
		json_decref(root);
		return 1;
	}

	//options is an empty array
	num_items = json_array_size(json_array);
	if (!num_items) {
		json_decref(root);
		return 0;
	}

	dumped_array = calloc(num_items, sizeof(char *));
	for (i = 0; i < num_items; i++)
	{
		item = json_array_get(json_array, i);
		if (!json_is_null(item))
			dumped_array[i] = json_dumps(item, 0);
	}

	json_decref(root);
	*output_array = dumped_array;
	return num_items;
}

static void free_mutator_arrays(char ** inputs, size_t * input_lengths, size_t inputs_count,
	char ** options, size_t num_options, char ** states, size_t num_states)
{
	size_t i;
	for (i = 0; i < inputs_count; i++)
		free(inputs[i]);
	for (i = 0; i < num_options; i++)
		free(options[i]);
	for (i = 0; i < num_states; i++)
		free(states[i]);
	free(inputs);
	free(options);
	free(states);
	free(input_lengths);
}

static int setup_mutators(multipart_state_t * multipart_state, char * mutator_options, char * mutator_states, char * mutator_inputs)
{
	size_t inputs_count, i;
	char **inputs = NULL, **options = NULL, **states = NULL, *option, *state;
	int num_options, num_states, all_use_same_options, all_use_same_states;
	size_t * input_lengths;

	if (decode_mem_array(mutator_inputs, &inputs, &input_lengths, &inputs_count))
		return 1;

	if (!inputs_count) { //No inputs were found
		free_mutator_arrays(inputs, input_lengths, inputs_count, NULL, 0, NULL, 0);
		return 1;
	}

	num_options = get_json_items(mutator_options, "options", &options, &all_use_same_options);
	num_states = get_json_items(mutator_states, NULL, &states, &all_use_same_states);

	if (inputs_count != multipart_state->mutator_count
		|| (num_options != 0 && !all_use_same_options && num_options != inputs_count)
		|| (num_states != 0 && !all_use_same_states && num_states != inputs_count))
	{
		free_mutator_arrays(inputs, input_lengths, inputs_count, options, num_options, states, num_states);
		return 1;
	}

	multipart_state->mutators = calloc(inputs_count, sizeof(mutator_t *));
	multipart_state->mutator_states = calloc(inputs_count, sizeof(void *));
	if(!multipart_state->mutators || !multipart_state->mutator_states) {
		free(multipart_state->mutators);
		free(multipart_state->mutator_states);
		multipart_state->mutators = NULL;
		multipart_state->mutator_states = NULL;
		free_mutator_arrays(inputs, input_lengths, inputs_count, options, num_options, states, num_states);
		return 1;
	}

	for (i = 0; i < inputs_count; i++)
	{
		//Create the mutator and get its state
		multipart_state->mutators[i] = mutator_factory_directory(multipart_state->mutator_directory, multipart_state->mutator_names[i]);
		if (multipart_state->mutators[i]) {
			option = NULL;
			if (all_use_same_options)
				option = options[0];
			else if(num_options != 0)
				option = options[i];
			state = NULL;
			if (all_use_same_states)
				state = states[0];
			else if (num_states != 0)
				state = states[i];

			multipart_state->mutator_states[i] = multipart_state->mutators[i]->create(option, state, inputs[i], input_lengths[i]);
		}

		if (!multipart_state->mutator_states[i] || !multipart_state->mutators[i])
		{
			printf("Unknown mutator %s, bad mutator options, or bad saved state for mutator %lu\n", multipart_state->mutator_names[i], i);
			free(multipart_state->mutators[i]); //free the one that failed, if it did
			multipart_state->mutators[i] = NULL;
			free_mutator_arrays(inputs, input_lengths, inputs_count, options, num_options, states, num_states);
			return 1;
		}
	}

	free_mutator_arrays(inputs, input_lengths, inputs_count, options, num_options, states, num_states);
	return 0;
}

///////////////////////////////////////////////////////////////////////////////////////////
// Mutator Functions //////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////

mutator_t multipart_mutator = {
	FUNCNAME(create),
	FUNCNAME(cleanup),
	FUNCNAME(mutate),
	FUNCNAME(mutate_extended),
	FUNCNAME(get_state),
	multipart_free_state,
	FUNCNAME(set_state),
	FUNCNAME(get_current_iteration),
	FUNCNAME(get_total_iteration_count),
	FUNCNAME(get_input_info),
	FUNCNAME(set_input),
	FUNCNAME(help)
};

/**
 * This function fills in m with all of the function pointers for this mutator.
 * @param m - a pointer to a mutator_t structure
 * @return none
 */
#ifndef ALL_MUTATORS_IN_ONE
MULTIPART_MUTATOR_API void init(mutator_t * m)
{
	memcpy(m, &multipart_mutator, sizeof(mutator_t));
}
#endif

/**
 * This function tries to determine the location of the currently executing library
 * to use as the default mutator directory.
 * @return either a string with the directory that contains the currently executing
 * library path, or NULL if it can't be determined.
 */
static char * get_default_mutator_directory()
{
#ifdef _WIN32
	HANDLE handle;
	char filename[MAX_PATH];

	//Find the path of the current library
	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
		GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCSTR)&get_default_mutator_directory,
		(HMODULE *)&handle))
	{
		//Trim the filename off, and look for other mutators in the same directory
		memset(filename, 0, sizeof(filename));
		GetModuleFileName(handle, filename, sizeof(filename));
		PathRemoveFileSpec(filename);
		return strdup(filename);
	}
#else //!_WIN32
	FILE * fp;
	int notdone = 1, found = 0;
	char path[256];
	char * buffer = NULL;
	size_t length = 0;

#ifdef __APPLE__
	//Run vmmap on our process and locate this mutator's library on disk
	char command[64];
	snprintf(command, sizeof(command), "vmmap %d", getpid());
	fp = popen(command, "r");
#else
	//Parse /proc/self/maps to try to locate this mutator's library on disk
	fp = fopen("/proc/self/maps", "r");
#endif
	if(fp) {
		while(notdone > 0 && !found)
		{
			notdone = getline(&buffer, &length, fp);
			if(notdone > 0) {
				memset(path, 0, sizeof(path));
#ifdef __APPLE__
				if(strncmp(buffer, "__TEXT", 6)) //if the line didn't start with __TEXT
					continue; //then skip it
				notdone = sscanf(buffer, "%*s %*x-%*x [ %*s %*s %*s %*s %*s %*s %255s\n", path);
#else
				notdone = sscanf(buffer, "%*x-%*x %*c%*c%*c%*c %*x %*x:%*x %*u %255s\n", path);
#endif
				if(strstr(path, MUTATOR_NAME "_mutator")) {
					found = 1;
				}
			}
		}
		free(buffer);
		fclose(fp);
		if(found)
			return strdup(dirname(path));
	}
#endif
	return NULL; //Couldn't figure out a reasonable default, search the normal library paths instead
}

static multipart_state_t * setup_options(char * options, char * input, size_t input_length)
{
	multipart_state_t * state;

	if (!options || !strlen(options)) //The multipart needs options
		return NULL; //so error out if they weren't provided

	state = (multipart_state_t *)malloc(sizeof(multipart_state_t));
	if (!state)
		return NULL;
	memset(state, 0, sizeof(multipart_state_t));

	PARSE_OPTION_STRING(state, options, mutator_directory, "mutator_directory", FUNCNAME(cleanup));
	PARSE_OPTION_ARRAY(state, options, mutator_names, mutator_count, "mutators", FUNCNAME(cleanup));

	if(!state->mutator_directory)
		state->mutator_directory = get_default_mutator_directory();

	if (state->mutator_count == 0) {
		FUNCNAME(cleanup)(state);
		return NULL;
	}

	return state;
}

/**
 * This function will allocate and initialize the mutator state used in the other Mutator API
 * functions.
 * @param options - a json string that contains the mutator specific string of options.
 * @param state - Optionally, used to load a previously dumped state (with the get_state()
 * function), that defines the current iteration of the mutator.
 * @param input - the input used to produce new mutated inputs later when the mutate function is called
 * This parameter must be a string containing a JSON array of JSON mem items of the individual inputs
 * @param input_length - the size of the input buffer
 * @return a mutator specific structure or NULL on failure.
 */
MULTIPART_MUTATOR_API void * FUNCNAME(create)(char * options, char * state, char * input, size_t input_length)
{
	multipart_state_t * new_state;
	new_state = setup_options(options, input, input_length);
	if (!new_state)
		return NULL;

	if (setup_mutators(new_state, options, state, input)) {
		FUNCNAME(cleanup)(new_state);
		return NULL;
	}

	return new_state;
}

/**
 * This function will release any resources that the mutator has open
 * and free the mutator state structure.
 * @param mutator_state - a mutator specific structure previously created by
 * the create function.  This structure will be freed and should not be referenced afterwards.
 */
MULTIPART_MUTATOR_API void FUNCNAME(cleanup)(void * mutator_state)
{
	multipart_state_t * state = (multipart_state_t *)mutator_state;
	size_t i;

	for (i = 0; i < state->mutator_count; i++)
	{
		free(state->mutator_names[i]);
		if (state->mutators && state->mutators[i])
		{
			state->mutators[i]->cleanup(state->mutator_states[i]);
			free(state->mutators[i]);
		}
	}

	free(state->mutator_directory);
	free(state->mutators);
	free(state->mutator_states);
	free(state);
}

/**
 * The multipart mutator does not implement the mutate function, and thus this function always
 * returns an error (-1).
 * @return - -1 to indicate an error
 */
MULTIPART_MUTATOR_API int FUNCNAME(mutate)(void * mutator_state, char * buffer, size_t buffer_length)
{
	return -1;
}

/**
 * This function will mutate the input given in the create function and return it in the buffer argument.
 * This function also accepts a set of flags which instruct it how to mutate the input.  See global_types.h
 * for the list of available flags.  The multipart mutator does not support mutating all of the inputs given
 * during create at once, so the MUTATE_MULTIPLE_INPUTS flag must be set.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param buffer - a buffer that the mutated input will be written to
 * @param buffer_length - the size of the passed in buffer argument.  It must be at least as large as
 * the original input buffer.
 * @param flags - A set of mutate flags that modify how this mutator mutates the input.
 * @return - the length of the mutated data, 0 when the mutator is out of mutations, or -1 on error
 */
MULTIPART_MUTATOR_API int FUNCNAME(mutate_extended)(void * mutator_state, char * buffer, size_t buffer_length, uint64_t flags)
{
	multipart_state_t * state = (multipart_state_t *)mutator_state;
	unsigned short input_part = flags & MUTATE_MULTIPLE_INPUTS_MASK;
	uint64_t inner_flags;
	if (!(flags & MUTATE_MULTIPLE_INPUTS) || input_part < 0 || input_part >= state->mutator_count)
		return -1;

	inner_flags = flags & ~(MUTATE_MULTIPLE_INPUTS | MUTATE_MULTIPLE_INPUTS_MASK);
	return state->mutators[input_part]->mutate_extended(state->mutator_states[input_part], buffer, buffer_length, inner_flags);
}

/**
 * This function will return the state of the mutator.  The returned value can be used to restart the
 * mutator at a later time, by passing it to the create or set_state function.  It is the caller's
 * responsibility to free the memory allocated here by calling the free_state function.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @return - a buffer that defines the current state of the mutator.
 */
MULTIPART_MUTATOR_API char * FUNCNAME(get_state)(void * mutator_state)
{
	multipart_state_t * state = (multipart_state_t *)mutator_state;
	json_t *states_array, *temp;
	json_error_t error;
	char * ret, *single_state;
	size_t i;

	states_array = json_array();
	for (i = 0; i < state->mutator_count; i++)
	{
		single_state = state->mutators[i]->get_state(state->mutator_states[i]);
		temp = json_loads(single_state, 0, &error);
		state->mutators[i]->free_state(single_state);
		json_array_append_new(states_array, temp);
	}

	ret = json_dumps(states_array, 0);
	json_decref(states_array);
	return ret;
}

/**
 * This function will set the current state of the mutator.
 * This can be used to restart a mutator once from a previous run.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param state - a previously dumped state buffer obtained by the get_state function.
 * @return 0 on success or non-zero on failure
 */
MULTIPART_MUTATOR_API int FUNCNAME(set_state)(void * mutator_state, char * state)
{
	multipart_state_t * current_state = (multipart_state_t *)mutator_state;
	json_t *states_array, *temp;
	json_error_t error;
	char *single_state;
	size_t i;

	if (!state)
		return 1;
	states_array = json_loads(state, 0, &error);
	if (!states_array || !json_is_array(states_array) || json_array_size(states_array) != current_state->mutator_count)
	{
		if(states_array)
			json_decref(states_array);
		return 1;
	}

	for (i = 0; i < current_state->mutator_count; i++)
	{
		temp = json_array_get(states_array, i);
		single_state = json_dumps(temp, 0);
		current_state->mutators[i]->set_state(current_state->mutator_states[i], single_state);
		free(single_state);
	}

	json_decref(states_array);
	return 0;
}

/**
 * This function will return the current iteration count of the mutator, i.e.
 * how many mutations have been generated with it.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @return value - the number of previously generated mutations
 */
MULTIPART_MUTATOR_API int FUNCNAME(get_current_iteration)(void * mutator_state)
{
	multipart_state_t * state = (multipart_state_t *)mutator_state;
	int lowest = -1, temp;
	size_t i;
	for (i = 0; i < state->mutator_count; i++) {
		temp = state->mutators[i]->get_current_iteration(state->mutator_states[i]);
		if (lowest == -1 || lowest > temp)
			lowest = temp;
	}
	return lowest;
}

/**
 * Returns the total number of mutations possible with this mutator and the current options.
 * For the multipart mutator, it will determine the number of mutations possible from all of
 * the mutators and return the lowest value
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @return the number of possible mutations with this mutator, or -1 if infinite or the number
 * cannot be determined.
 */
MULTIPART_MUTATOR_API int FUNCNAME(get_total_iteration_count)(void * mutator_state)
{
	multipart_state_t * state = (multipart_state_t *)mutator_state;
	int lowest = -1, temp;
	size_t i;
	for (i = 0; i < state->mutator_count; i++) {
		temp = state->mutators[i]->get_total_iteration_count(state->mutator_states[i]);
		if (lowest == -1 || (temp != -1 && lowest > temp))
			lowest = temp;
	}
	return lowest;
}

/**
 * Obtains information about the inputs that were given to the mutator when it was created
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param num_inputs - a pointer to an integer used to return the number of inputs given to this mutator
 * when it was created.  This parameter is optional and can be NULL, if this information is not needed
 * @param input_sizes - a pointer to a size_t array used to return the sizes of the inputs given to this
 * mutator when it was created. This parameter is optional and can be NULL, if this information is not needed.
 */
MULTIPART_MUTATOR_API void FUNCNAME(get_input_info)(void * mutator_state, int * num_inputs, size_t **input_sizes)
{
	multipart_state_t * state = (multipart_state_t *)mutator_state;
	size_t i;
	size_t * sizes;
	if (num_inputs)
		*num_inputs = state->mutator_count;
	if (input_sizes) {
		*input_sizes = malloc(sizeof(size_t) * state->mutator_count);
		for (i = 0; i < state->mutator_count; i++)
		{
			state->mutators[i]->get_input_info(state->mutator_states[i], NULL, &sizes);
			(*input_sizes)[i] = sizes[0];
			free(sizes);
		}
	}
}

/**
 * This function will set the mutator's input to something new.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param new_input - The new input used to produce new mutated inputs later when the mutate function is called
 * @param input_length - the size in bytes of the input buffer.
 * @return 0 on success and -1 on failure
 */
MULTIPART_MUTATOR_API int FUNCNAME(set_input)(void * mutator_state, char * new_input, size_t input_length)
{
	multipart_state_t * state = (multipart_state_t *)mutator_state;
	size_t inputs_count, i;
	char **inputs = NULL;
	size_t * input_lengths;
	int ret = 0;

	if (decode_mem_array(new_input, &inputs, &input_lengths, &inputs_count))
		return -1;
	if (inputs_count != state->mutator_count) {
		free_mutator_arrays(inputs, input_lengths, inputs_count, NULL, 0, NULL, 0);
		return -1;
	}

	for (i = 0; ret == 0 && i < state->mutator_count; i++)
		ret = state->mutators[i]->set_input(state->mutator_states[i], inputs[i], input_lengths[i]);
	free_mutator_arrays(inputs, input_lengths, inputs_count, NULL, 0, NULL, 0);
	return ret;
}

/**
 * This function sets a help message for the mutator.
 * @param help_str - A pointer that will be updated to point to the new help string.
 * @return 0 on success and -1 on failure
 */
MULTIPART_MUTATOR_API int FUNCNAME(help)(char **help_str)
{
	GENERIC_MUTATOR_HELP(
"multipart - a mutator to manage multiple mutators\n"
"Required Options:\n"
"  mutators              An array of mutator names or library filenames that\n"
"                          the multipart mutator should use to mutate the input.\n"
"Optional Options:\n"
"  mutator_directory     The directory to look for other mutator libraries in\n"
"  options               An array of mutator options to pass to each mutator used\n"
"\n"
	);
}
