#include "driver_factory.h"

#include "file_driver.h"
#include "stdin_driver.h"
#include "network_server_driver.h"
#include "network_client_driver.h"
#ifdef _WIN32
#include "wmp_driver.h"
#endif

#include <instrumentation.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define FACTORY_ERROR()  { free(ret); return NULL; }

/**
 * This function obtains a driver_t object by calling the driver specified by driver_type's create method.
 * @param driver_type - the name of the driver that should be created.
 * @param options - a JSON string that contains the driver specific string of options
 * @return - a driver_t object of the specified type on success or NULL on failure
 */
DRIVER_API driver_t * driver_factory(char * driver_type, char * options)
{
	return driver_all_factory(driver_type, options, NULL, NULL, NULL, NULL);
}

/**
 * This function obtains a driver_t object by calling the driver specified by driver_type's create method.
 * @param driver_type - the name of the driver that should be created.
 * @param options - a JSON string that contains the driver specific string of options
 * @param instrumentation - optionally, a pointer to an instrumentation instance that the driver will use
 * to instrument the requested program.  This instrumentation instance should already be initialized.
 * @param instrumentation_state - a pointer to the instrumentation state for the passed in instrumentation
 * @return - a driver_t object of the specified type on success or NULL on failure
 */
DRIVER_API driver_t * driver_instrumentation_factory(char * driver_type, char * options, instrumentation_t * instrumentation, 
	void * instrumentation_state)
{
	return driver_all_factory(driver_type, options, instrumentation, instrumentation_state, NULL, NULL);
}

/**
 * This function obtains a driver_t object by calling the driver specified by driver_type's create method.
 * @param driver_type - the name of the driver that should be created.
 * @param options - a JSON string that contains the driver specific string of options
 * @param mutator - optionally, a pointer to a mutator instance that the driver will use
 * to obtain input when fuzzing the requested program.  This mutator instance should already be initialized.
 * @param mutator_state - a pointer to the mutator state for the passed in mutator
 * @return - a driver_t object of the specified type on success or NULL on failure
 */
DRIVER_API driver_t * driver_mutator_factory(char * driver_type, char * options, mutator_t * mutator, void * mutator_state)
{
	return driver_all_factory(driver_type, options, NULL, NULL, mutator, mutator_state);
}

/**
 * This function obtains a driver_t object by calling the driver specified by driver_type's create method.
 * @param driver_type - the name of the driver that should be created.
 * @param options - a JSON string that contains the driver specific string of options
 * @param instrumentation - optionally, a pointer to an instrumentation instance that the driver will use
 * to instrument the requested program.  This instrumentation instance should already be initialized.
 * @param instrumentation_state - a pointer to the instrumentation state for the passed in instrumentation
 * @param mutator - optionally, a pointer to a mutator instance that the driver will use
 * to obtain input when fuzzing the requested program.  This mutator instance should already be initialized.
 * @param mutator_state - a pointer to the mutator state for the passed in mutator
 * @return - a driver_t object of the specified type on success or NULL on failure
 */
DRIVER_API driver_t * driver_all_factory(char * driver_type, char * options, instrumentation_t * instrumentation, void * instrumentation_state,
	mutator_t * mutator, void * mutator_state)
{
	driver_t * ret = (driver_t *)malloc(sizeof(driver_t));
	if (!strcmp(driver_type, "file"))
	{
		ret->state = file_create(options, instrumentation, instrumentation_state, mutator, mutator_state);
		if (!ret->state)
			FACTORY_ERROR();
		ret->cleanup = file_cleanup;
		ret->test_input = file_test_input;
		ret->test_next_input = file_test_next_input;
		ret->get_last_input = file_get_last_input;
	}
	else if (!strcmp(driver_type, "stdin"))
	{
		ret->state = stdin_create(options, instrumentation, instrumentation_state, mutator, mutator_state);
		if (!ret->state)
			FACTORY_ERROR();
		ret->cleanup = stdin_cleanup;
		ret->test_input = stdin_test_input;
		ret->test_next_input = stdin_test_next_input;
		ret->get_last_input = stdin_get_last_input;
	}
	else if (!strcmp(driver_type, "network_server"))
	{
		ret->state = network_server_create(options, instrumentation, instrumentation_state, mutator, mutator_state);
		if (!ret->state)
			FACTORY_ERROR();
		ret->cleanup = network_server_cleanup;
		ret->test_input = network_server_test_input;
		ret->test_next_input = network_server_test_next_input;
		ret->get_last_input = network_server_get_last_input;
	}
	else if (!strcmp(driver_type, "network_client"))
	{
		ret->state = network_client_create(options, instrumentation, instrumentation_state, mutator, mutator_state);
		if (!ret->state) {
			puts("Factory Error");
			FACTORY_ERROR();
			}
		ret->cleanup = network_client_cleanup;
		ret->test_input = network_client_test_input;
		ret->test_next_input = network_client_test_next_input;
		ret->get_last_input = network_client_get_last_input;
	}
	#ifdef _WIN32
	else if (!strcmp(driver_type, "wmp"))
	{
		ret->state = wmp_create(options, instrumentation, instrumentation_state, mutator, mutator_state);
		if (!ret->state)
			FACTORY_ERROR();
		ret->cleanup = wmp_cleanup;
		ret->test_input = wmp_test_input;
		ret->test_next_input = wmp_test_next_input;
		ret->get_last_input = wmp_get_last_input;
	}
	#endif
	else
		FACTORY_ERROR();
	return ret;
}

#define APPEND_HELP(text, new_text, func)                               \
  if(!func(&new_text)) {                                                \
    text = (char *)realloc(text, strlen(text) + strlen(new_text) + 1);  \
    strcat(text, new_text);                                             \
    free(new_text);                                                     \
  }

/**
 * This function returns help text for all available drivers.  This help text will describe the drivers and any options
 * that can be passed to their create functions.
 * @return - a newly allocated string containing the help text.
 */
DRIVER_API char * driver_help(void)
{
	char * text, *new_text;
	text = strdup("Driver Options:\n\n");
	APPEND_HELP(text, new_text, file_help);
	APPEND_HELP(text, new_text, stdin_help);
	APPEND_HELP(text, new_text, network_server_help);
	APPEND_HELP(text, new_text, network_client_help);
	#ifdef _WIN32
	APPEND_HELP(text, new_text, wmp_help);
	#endif
	return text;
}

