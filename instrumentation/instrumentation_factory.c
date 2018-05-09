#include "instrumentation_factory.h"
#include "dynamorio_instrumentation.h"
#include "none_instrumentation.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define FACTORY_ERROR()  { free(ret); return NULL; }

/**
* This function obtains a instrumentation_t object by calling the instrumentation specified by instrumentation_type's create method.
* @param instrumentation_type - the name of the instrumentation that should be created.  Currently known instrumentation types are: dynamorio.
* @param options - a JSON string that contains the instrumentation specific string of options
* @return - a instrumentation_t object of the specified type on success or NULL on failure
*/
instrumentation_t * instrumentation_factory(char * instrumentation_type)
{
	instrumentation_t * ret = (instrumentation_t *)malloc(sizeof(instrumentation_t));
	memset(ret, 0, sizeof(instrumentation_t));
	if (!strcmp(instrumentation_type, "none"))
	{
		ret->create = none_create;
		ret->cleanup = none_cleanup;
		ret->merge = none_merge;
		ret->get_state = none_get_state;
		ret->free_state = none_free_state;
		ret->set_state = none_set_state;
		ret->enable = none_enable;
		ret->is_new_path = none_is_new_path;
	}
	else if (!strcmp(instrumentation_type, "dynamorio"))
	{
		ret->create = dynamorio_create;
		ret->cleanup = dynamorio_cleanup;
		ret->merge = dynamorio_merge;
		ret->get_state = dynamorio_get_state;
		ret->free_state = dynamorio_free_state;
		ret->set_state = dynamorio_set_state;
		ret->enable = dynamorio_enable;
		ret->is_new_path = dynamorio_is_new_path;
		ret->get_module_info = dynamorio_get_module_info;
		ret->get_edges = dynamorio_get_edges;
		ret->wait_for_target_completion = dynamorio_wait_for_target_completion;
	}
	else
		FACTORY_ERROR();
	return ret;
}

#define APPEND_HELP(text, new_text, func)                                \
	new_text = func();                                                   \
	text = (char *)realloc(text, strlen(text) + strlen(new_text) + 1);   \
	strcat(text, new_text);                                              \
	free(new_text);

/**
* This function returns help text for all available instrumentations.  This help text will describe the instrumentations and any options
* that can be passed to their create functions.
* @return - a newly allocated string containing the help text.
*/
char * instrumentation_help(void)
{
	char * text, *new_text;
	text = strdup("Instrumentation Options:\n\n");
	APPEND_HELP(text, new_text, none_help);
	APPEND_HELP(text, new_text, dynamorio_help);
	return text;
}