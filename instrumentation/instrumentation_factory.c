#include "instrumentation_factory.h"
#ifdef _WIN32
#include "debug_instrumentation.h"
#include "dynamorio_instrumentation.h"
#else
#include "return_code_instrumentation.h"
#if !__APPLE__ // Linux
#include "linux_ipt_instrumentation.h"
#endif
#endif

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
	#ifdef _WIN32
	if (!strcmp(instrumentation_type, "debug"))
	{
		ret->create = debug_create;
		ret->cleanup = debug_cleanup;
		ret->merge = debug_merge;
		ret->get_state = debug_get_state;
		ret->free_state = debug_free_state;
		ret->set_state = debug_set_state;
		ret->enable = debug_enable;
		ret->is_new_path = debug_is_new_path;
		ret->get_fuzz_result = debug_get_fuzz_result;
		ret->is_process_done = debug_is_process_done;
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
		ret->is_process_done = dynamorio_is_process_done;
		ret->get_fuzz_result = dynamorio_get_fuzz_result;
	}
	#else
	if (!strcmp(instrumentation_type, "return_code"))
	{
		ret->create = return_code_create;
		ret->cleanup = return_code_cleanup;
		ret->merge = return_code_merge;
		ret->get_state = return_code_get_state;
		ret->free_state = return_code_free_state;
		ret->set_state = return_code_set_state;
		ret->enable = return_code_enable;
		ret->is_new_path = return_code_is_new_path;
		ret->get_fuzz_result = return_code_get_fuzz_result;
		ret->is_process_done = return_code_is_process_done;
	}
	#if !__APPLE__ // Linux
	else if (!strcmp(instrumentation_type, "ipt"))
	{
		ret->create = linux_ipt_create;
		ret->cleanup = linux_ipt_cleanup;
		ret->merge = linux_ipt_merge;
		ret->get_state = linux_ipt_get_state;
		ret->free_state = linux_ipt_free_state;
		ret->set_state = linux_ipt_set_state;
		ret->enable = linux_ipt_enable;
		ret->is_new_path = linux_ipt_is_new_path;
		ret->get_fuzz_result = linux_ipt_get_fuzz_result;
		ret->is_process_done = linux_ipt_is_process_done;
	}
	#endif
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
* This function returns help text for all available instrumentations.  This help text will describe the instrumentations and any options
* that can be passed to their create functions.
* @return - a newly allocated string containing the help text.
*/
char * instrumentation_help(void)
{
	char * text, *new_text;
	text = strdup("Instrumentation Options:\n\n");
	#ifdef _WIN32
	APPEND_HELP(text, new_text, debug_help);
	APPEND_HELP(text, new_text, dynamorio_help);
	#else
	APPEND_HELP(text, new_text, return_code_help);
	#if !__APPLE__ // Linux
	APPEND_HELP(text, new_text, linux_ipt_help);
	#endif
	#endif
	return text;
}
