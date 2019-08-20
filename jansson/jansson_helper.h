#pragma once

#include "jansson.h"

#ifdef __cplusplus
extern "C" {
#endif

// Some macros to make parsing options easier

#define PARSE_OPTION_INT_TEMP(state, options, name, name_literal, fail_func, temp_name)  \
	int result_##temp_name = 0;                                                          \
	int tempi_##temp_name = get_int_options(options, name_literal, &result_##temp_name); \
	if (result_##temp_name < 0)                                                          \
	{                                                                                    \
		fail_func(state);                                                                \
		return NULL;                                                                     \
	}                                                                                    \
	else if (result_##temp_name > 0)                                                     \
	{                                                                                    \
		state->name = tempi_##temp_name;                                                 \
	}

#define PARSE_OPTION_INT(state, options, name, name_literal, fail_func)                  \
	PARSE_OPTION_INT_TEMP(state, options, name, name_literal, fail_func, name)

#define PARSE_OPTION_UINT64T_TEMP(state, options, name, name_literal, fail_func, temp_name)       \
	int result_##temp_name = 0;                                                                   \
	uint64_t tempi_##temp_name = get_uint64t_options(options, name_literal, &result_##temp_name); \
	if (result_##temp_name < 0)                                                                   \
	{                                                                                             \
		fail_func(state);                                                                         \
		return NULL;                                                                              \
	}                                                                                             \
	else if (result_##temp_name > 0)                                                              \
	{                                                                                             \
		state->name = tempi_##temp_name;                                                          \
	}

#define PARSE_OPTION_UINT64T(state, options, name, name_literal, fail_func)                       \
	PARSE_OPTION_UINT64T_TEMP(state, options, name, name_literal, fail_func, name)

#define PARSE_OPTION_DOUBLE_TEMP(state, options, name, name_literal, fail_func, temp_name)     \
	int result_##temp_name = 0;                                                                \
	double tempi_##temp_name = get_double_options(options, name_literal, &result_##temp_name); \
	if (result_##temp_name < 0)                                                                \
	{                                                                                          \
		fail_func(state);                                                                      \
		return NULL;                                                                           \
	}                                                                                          \
	else if (result_##temp_name > 0)                                                           \
	{                                                                                          \
		state->name = tempi_##temp_name;                                                       \
	}

#define PARSE_OPTION_DOUBLE(state, options, name, name_literal, fail_func)                     \
	PARSE_OPTION_DOUBLE_TEMP(state, options, name, name_literal, fail_func, name)

#define PARSE_OPTION_STRING_TEMP(state, options, name, name_literal, fail_func, temp_name)     \
	int result_##temp_name = 0;                                                                \
	char * temps_##temp_name = get_string_options(options, name_literal, &result_##temp_name); \
	if (result_##temp_name < 0)                                                                \
	{                                                                                          \
		fail_func(state);                                                                      \
		return NULL;                                                                           \
	}                                                                                          \
	else if (result_##temp_name > 0)                                                           \
	{                                                                                          \
		if(state->name)                                                                        \
			free(state->name);                                                                 \
		state->name = temps_##temp_name;                                                       \
	}

#define PARSE_OPTION_STRING(state, options, name, name_literal, fail_func)                     \
	PARSE_OPTION_STRING_TEMP(state, options, name, name_literal, fail_func, name)

#define PARSE_OPTION_ARRAY_TEMP(state, options, name, count, name_literal, fail_func, temp_name)                   \
	int result_##temp_name = 0;                                                                                    \
	size_t count_##temp_name = 0;                                                                                  \
	char ** temps_##temp_name = get_array_options(options, name_literal, &count_##temp_name, &result_##temp_name); \
	if (result_##temp_name < 0)                                                                                    \
	{                                                                                                              \
		fail_func(state);                                                                                          \
		return NULL;                                                                                               \
	}                                                                                                              \
	else if (result_##temp_name > 0)                                                                               \
	{                                                                                                              \
		if(state->name)                                                                                            \
			free(state->name);                                                                                     \
		state->name = temps_##temp_name;                                                                           \
		state->count = count_##temp_name;                                                                          \
	}                            

#define PARSE_OPTION_ARRAY(state, options, name, count, name_literal, fail_func)                                   \
	PARSE_OPTION_ARRAY_TEMP(state, options, name, count, name_literal, fail_func, name)

#define PARSE_OPTION_INT_ARRAY_TEMP(state, options, name, count, name_literal, fail_func, temp_name)                 \
	int result_##temp_name = 0;                                                                                      \
	size_t count_##temp_name = 0;                                                                                    \
	int * temps_##temp_name = get_int_array_options(options, name_literal, &count_##temp_name, &result_##temp_name); \
	if (result_##temp_name < 0)                                                                                      \
	{                                                                                                                \
		fail_func(state);                                                                                            \
		return NULL;                                                                                                 \
	}                                                                                                                \
	else if (result_##temp_name > 0)                                                                                 \
	{                                                                                                                \
		if(state->name)                                                                                              \
			free(state->name);                                                                                       \
		state->name = temps_##temp_name;                                                                             \
		state->count = count_##temp_name;                                                                            \
	}

#define PARSE_OPTION_INT_ARRAY(state, options, name, count, name_literal, fail_func)                                 \
	PARSE_OPTION_INT_ARRAY_TEMP(state, options, name, count, name_literal, fail_func, name)


// Some macros to make iterating json arrays easier

#define FOREACH_OBJECT_JSON_ARRAY_ITEM_BEGIN(state, name, name_str, item, result)                    \
    do {                                                                                             \
		json_t * root##name, *option_array##name;                                                    \
		size_t i##name;                                                                              \
																									 \
		result = -1;                                                                                 \
		root##name = get_root_option_json_object(state);                                             \
		if (root##name)                                                                              \
		{                                                                                            \
			option_array##name = json_object_get(root##name, name_str);                              \
			if (!option_array##name || !json_is_array(option_array##name))                           \
				json_decref(root##name);                                                             \
			else                                                                                     \
			{                                                                                        \
				result = 1;                                                                          \
				for (i##name = 0; i##name < json_array_size(option_array##name); i##name++)          \
				{                                                                                    \
					item = json_array_get(option_array##name, i##name);

#define FOREACH_OBJECT_JSON_ARRAY_ITEM_END(name)                                                     \
				}                                                                                    \
			}                                                                                        \
			json_decref(root##name);                                                                 \
		}                                                                                            \
	} while (0);

//If you want to end the macro early, such that the code won't hit the end of the loop, use this to
//free the root object.
#define FOREACH_OBJECT_JSON_ARRAY_ITEM_FREE(name)                                                    \
	json_decref(root##name);

// Some macros to make generating objects easier

#define ADD_ITEM1(temp, arg1, dest, func, name)       \
	temp = func(arg1);                                \
    if(!temp) return NULL;                            \
	json_object_set_new(dest, name, temp);

#define ADD_ITEM2(temp, arg1, arg2, dest, func, name) \
	temp = func(arg1, arg2);                          \
    if(!temp) return NULL;                            \
	json_object_set_new(dest, name, temp);

#define ADD_STRING(temp, arg1, dest, name)        ADD_ITEM1(temp, arg1, dest, json_string, name)
#define ADD_INT(temp, arg1, dest, name)           ADD_ITEM1(temp, arg1, dest, json_integer, name)
#define ADD_UINT64T                               ADD_INT //Internally they both use json_integer
#define ADD_MEM(temp, arg1, arg2, dest, name)     ADD_ITEM2(temp, arg1, arg2, dest, json_mem, name)
#define ADD_DOUBLE(temp, arg1, dest, name)        ADD_ITEM1(temp, arg1, dest, json_real, name)

#define GET_ITEM(arg1, dest, temp, func, name, ret) \
    temp = func(arg1, name, &ret);                  \
    if (ret <= 0)                                   \
        return 1;                                   \
    dest = temp;

#define GET_STRING(temp, arg1, dest, name, ret)   GET_ITEM(arg1, dest, temp, get_string_options, name, ret)
#define GET_INT(temp, arg1, dest, name, ret)      GET_ITEM(arg1, dest, temp, get_int_options, name, ret)
#define GET_UINT64T(temp, arg1, dest, name, ret)  GET_ITEM(arg1, dest, temp, get_uint64t_options, name, ret)
#define GET_MEM(temp, arg1, dest, name, ret)      GET_ITEM(arg1, dest, temp, get_mem_options, name, ret)
#define GET_DOUBLE(temp, arg1, dest, name, ret)   GET_ITEM(arg1, dest, temp, get_double_options, name, ret)

JANSSON_API char * get_string_options(const char * options, const char * option_name, int * result);
JANSSON_API char * get_string_options_from_json(json_t * root, const char * option_name, int * result);

JANSSON_API char * get_mem_options(const char * options, const char * option_name, int * result);
JANSSON_API char * get_mem_options_from_json(json_t * root, const char * option_name, int * result);

JANSSON_API int get_int_options(const char * options, const char * option_name, int * result);
JANSSON_API int get_int_options_from_json(json_t * root, const char * option_name, int * result);

JANSSON_API uint64_t get_uint64t_options(const char * options, const char * option_name, int * result);
JANSSON_API uint64_t get_uint64t_options_from_json(json_t * root, const char * option_name, int * result);

JANSSON_API double get_double_options(const char * json_string, const char * option_name, int * result);
JANSSON_API double get_double_options_from_json(json_t * root, const char * option_name, int * result);

JANSSON_API char ** get_array_options(const char * options, const char * option_name, size_t * count, int * result);
JANSSON_API int * get_int_array_options(const char * json_string, const char * option_name, size_t * count, int * result);

JANSSON_API json_t * get_root_option_json_object(const char * options);

JANSSON_API char * add_string_option_to_json(const char * root_options, const char * new_option_name, const char * new_value);
JANSSON_API char * add_int_option_to_json(const char * root_options, const char * new_option_name, int new_value);

JANSSON_API int decode_mem_array(const char *json_string, char *** items, size_t ** item_lengths, size_t * items_count);
JANSSON_API char * encode_mem_array(char ** items, size_t * item_lengths, size_t items_count, int * output_length);

#ifdef __cplusplus
}
#endif
