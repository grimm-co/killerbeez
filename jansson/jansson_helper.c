#include "jansson.h"
#include "jansson_helper.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * This function parses the given JSON string and converts it into a json_t object
 * @param json_string - a JSON character buffer that should be converted into a json_t
 * @return - a json_t object on success, or NULL on failure
 */
json_t * get_root_option_json_object(const char * json_string)
{
	json_t * root;
	json_error_t error;

	root = json_loads(json_string, 0, &error);
	if (!root)
	{
		fprintf(stderr, "json error in options: on line %d: %s\n", error.line, error.text);
		return NULL;
	}

	if (!json_is_object(root))
	{
		fprintf(stderr, "json error in options: root is not an object\n");
		json_decref(root);
		return NULL;
	}

	return root;
}

/**
 * Gets a string attribute value from a json_t object
 * @param root - the json_t object to get the attribute from
 * @param option_name - the name of the attribute to get
 * @param result - a pointer to an integer to return the results of trying to get
 * the attribute value.  The value 0 is returned if the attribute isn't found, -1
 * if the attribute is found but not a string, and 1 if the attribute is found and
 * a string.
 * @param should_free - whether or not to free the root json_t parameter after finding
 * the attribute
 * @return - the string value of the specified attribute on success, or NULL if the attribute
 * wasn't found or the wrong type. The return value should be freed by the caller.
 */
static char * get_string_options_inner(json_t * root, const char * option_name, int * result, int should_free)
{
	json_t *option_item;
	char * option_value;

	option_item = json_object_get(root, option_name);
	if (!option_item)
	{
		if (should_free)
			json_decref(root);
		*result = 0;
		return NULL;
	}

	if (!json_is_string(option_item))
	{
		*result = -1;
		fprintf(stderr, "error: option item %s is expected to be a string\n", option_name);
		if (should_free)
			json_decref(root);
		return NULL;
	}

	option_value = strdup(json_string_value(option_item));
	*result = 1;
	if (should_free)
		json_decref(root);
	return option_value;
}

/**
 * Gets a string attribute value from a JSON string
 * @param json_string - the JSON string to parse and obtain the attribute value from
 * @param option_name - the name of the attribute to get
 * @param result - a pointer to an integer to return the results of trying to get
 * the attribute value.  The value 0 is returned if the attribute isn't found, -1
 * if the attribute is found but not a string, and 1 if the attribute is found and
 * a string.
 * @return - the string value of the specified attribute on success, or NULL if the json
 * couldn't be parsed, the attribute wasn't found, or the attribute was the wrong type.
 * The return value should be freed by the caller.
 */
char * get_string_options(const char * json_string, const char * option_name, int * result)
{
	json_t * root;

	*result = -1;
	root = get_root_option_json_object(json_string);
	if (!root)
		return NULL;
	return get_string_options_inner(root, option_name, result, 1);
}


/**
 * Gets a string attribute value from a JSON string
 * @param root - the json_t object to get the attribute from
 * @param option_name - the name of the attribute to get
 * @param result - a pointer to an integer to return the results of trying to get
 * the attribute value.  The value 0 is returned if the attribute isn't found, -1
 * if the attribute is found but not a string, and 1 if the attribute is found and
 * a string.
 * @return - the string value of the specified attribute on success, or NULL if the
 * attribute wasn't found or the wrong type. The return value should be freed by the caller.
 */
char * get_string_options_from_json(json_t * root, const char * option_name, int * result)
{
	return get_string_options_inner(root, option_name, result, 0);
}

/**
 * Gets a mem attribute value from a json_t object
 * @param root - the json_t object to get the attribute from
 * @param option_name - the name of the attribute to get
 * @param result - a pointer to an integer to return the results of trying to get
 * the attribute value.  The value 0 is returned if the attribute isn't found, -1
 * if the attribute is found but not a mem, and 1 if the attribute is found and
 * a mem.
 * @param should_free - whether or not to free the root json_t parameter after finding
 * the attribute
 * @return - the mem value of the specified attribute on success, or NULL if the attribute
 * wasn't found or the wrong type.  The return value should be freed by the caller.
 */
static char * get_mem_options_inner(json_t * root, const char * option_name, int * result, int should_free)
{
	json_t *option_item;
	char * option_value;
	size_t length;

	option_item = json_object_get(root, option_name);
	if (!option_item)
	{
		if (should_free)
			json_decref(root);
		*result = 0;
		return NULL;
	}

	if (!json_is_mem(option_item))
	{
		*result = -1;
		fprintf(stderr, "error: option item %s is expected to be a mem\n", option_name);
		if (should_free)
			json_decref(root);
		return NULL;
	}

	length = json_mem_length(option_item);
	option_value = malloc(length);
	memcpy(option_value, json_mem_value(option_item), length);
	*result = 1;
	if (should_free)
		json_decref(root);
	return option_value;
}

/**
 * Gets a mem attribute value from a JSON string
 * @param json_string - the JSON string to parse and obtain the attribute value from
 * @param option_name - the name of the attribute to get
 * @param result - a pointer to an integer to return the results of trying to get
 * the attribute value.  The value 0 is returned if the attribute isn't found, -1
 * if the attribute is found but not a mem, and 1 if the attribute is found and
 * a mem.
 * @return - the mem value of the specified attribute on success, or NULL if the json
 * couldn't be parsed, the attribute wasn't found, or the attribute was the wrong type.
 * The return value should be freed by the caller.
 */
char * get_mem_options(const char * json_string, const char * option_name, int * result)
{
	json_t * root;

	*result = -1;
	root = get_root_option_json_object(json_string);
	if (!root)
		return NULL;
	return get_mem_options_inner(root, option_name, result, 1);
}

/**
 * Gets a mem attribute value from a json_t object
 * @param root - the json_t object to get the attribute from
 * @param option_name - the name of the attribute to get
 * @param result - a pointer to an integer to return the results of trying to get
 * the attribute value.  The value 0 is returned if the attribute isn't found, -1
 * if the attribute is found but not a mem, and 1 if the attribute is found and
 * a mem.
 * @return - the mem value of the specified attribute on success, or NULL if the attribute
 * wasn't found or the wrong type. The return value should be freed by the caller.
 */
char * get_mem_options_from_json(json_t * root, const char * option_name, int * result)
{
	return get_mem_options_inner(root, option_name, result, 0);
}

/**
 * Gets an integer attribute value from a json_t object
 * @param root - the json_t object to get the attribute from
 * @param option_name - the name of the attribute to get
 * @param result - a pointer to an integer to return the results of trying to get
 * the attribute value.  The value 0 is returned if the attribute isn't found, -1
 * if the attribute is found but not an integer, and 1 if the attribute is found and
 * an integer.
 * @param should_free - whether or not to free the root json_t parameter after finding
 * the attribute
 * @return - the integer value of the specified attribute on success, or -1 if the attribute
 * wasn't found or the wrong type.  Check the value of the result parameter to differentiate
 * between the attribute value of -1 or failure to get the value.
 */
static long long get_int_options_inner(json_t * root, const char * option_name, int * result, int should_free)
{
	json_t *option_item;
	long long option_value;

	option_item = json_object_get(root, option_name);
	if (!option_item)
	{
		if (should_free)
			json_decref(root);
		*result = 0;
		return -1;
	}

	if (!json_is_integer(option_item))
	{
		*result = -1;
		fprintf(stderr, "error: option item %s is expected to be an integer\n", option_name);
		if (should_free)
			json_decref(root);
		return -1;
	}

	option_value = json_integer_value(option_item);
	*result = 1;
	if (should_free)
		json_decref(root);
	return option_value;
}

/**
 * Gets an integer attribute value from a JSON string
 * @param json_string - the JSON string to parse and obtain the attribute value from
 * @param option_name - the name of the attribute to get
 * @param result - a pointer to an integer to return the results of trying to get
 * the attribute value.  The value 0 is returned if the attribute isn't found, -1
 * if the attribute is found but not an integer, and 1 if the attribute is found and
 * an integer.
 * @return - the integer value of the specified attribute on success, or -1 if the json
 * couldn't be parsed, the attribute wasn't found, or the attribute was the wrong type.
 * Check the value of the result parameter to differentiate between the attribute value
 * of -1 or failure to get the value.
 */
int get_int_options(const char * json_string, const char * option_name, int * result)
{
	json_t * root;

	*result = -1;
	root = get_root_option_json_object(json_string);
	if (!root)
		return -1;
	return (int)get_int_options_inner(root, option_name, result, 1);
}

/**
* Gets an integer attribute value from a json_t object
* @param root - the json_t object to get the attribute from
* @param option_name - the name of the attribute to get
* @param result - a pointer to an integer to return the results of trying to get
* the attribute value.  The value 0 is returned if the attribute isn't found, -1
* if the attribute is found but not an integer, and 1 if the attribute is found and
* an integer.
* @return - the integer value of the specified attribute on success, or -1 if the attribute
* wasn't found or the wrong type.  Check the value of the result parameter to differentiate
* between the attribute value of -1 or failure to get the value.
*/
int get_int_options_from_json(json_t * root, const char * option_name, int * result)
{
	return (int)get_int_options_inner(root, option_name, result, 0);
}

/**
* Gets a uint64_t attribute value from a JSON string
* @param json_string - the JSON string to parse and obtain the attribute value from
* @param option_name - the name of the attribute to get
* @param result - a pointer to an integer to return the results of trying to get
* the attribute value.  The value 0 is returned if the attribute isn't found, -1
* if the attribute is found but not an integer, and 1 if the attribute is found and
* an integer.
* @return - the uint64_t value of the specified attribute on success, or -1 if the json
* couldn't be parsed, the attribute wasn't found, or the attribute was the wrong type.
* Check the value of the result parameter to differentiate between the attribute value
* of -1 or failure to get the value.s
*/
uint64_t get_uint64t_options(const char * json_string, const char * option_name, int * result)
{
	json_t * root;

	*result = -1;
	root = get_root_option_json_object(json_string);
	if (!root)
		return -1;
	return (uint64_t)get_int_options_inner(root, option_name, result, 1);
}

/**
* Gets a uint64_t attribute value from a json_t object
* @param root - the json_t object to get the attribute from
* @param option_name - the name of the attribute to get
* @param result - a pointer to an integer to return the results of trying to get
* the attribute value.  The value 0 is returned if the attribute isn't found, -1
* if the attribute is found but not an integer, and 1 if the attribute is found and
* an integer.
* @return - the uint64_t value of the specified attribute on success, or -1 if the attribute
* wasn't found or the wrong type.  Check the value of the result parameter to differentiate
* between the attribute value of -1 or failure to get the value.
*/
uint64_t get_uint64t_options_from_json(json_t * root, const char * option_name, int * result)
{
	return (uint64_t)get_int_options_inner(root, option_name, result, 0);
}

/**
 * Gets a double attribute value from a json_t object
 * @param root - the json_t object to get the attribute from
 * @param option_name - the name of the attribute to get
 * @param result - a pointer to an integer to return the results of trying to get
 * the attribute value.  The value 0 is returned if the attribute isn't found, -1
 * if the attribute is found but not a number, and 1 if the attribute is found and
 * a number.
 * @param should_free - whether or not to free the root json_t parameter after finding
 * the attribute
 * @return - the double value of the specified attribute on success, or -1 if the attribute
 * wasn't found or the wrong type.  Check the value of the result parameter to differentiate
 * between the attribute value of -1 or failure to get the value.
 */
static double get_double_options_inner(json_t * root, const char * option_name, int * result, int should_free)
{
	json_t *option_item;
	double option_value;

	option_item = json_object_get(root, option_name);
	if (!option_item)
	{
		if (should_free)
			json_decref(root);
		*result = 0;
		return -1;
	}

	if (!json_is_real(option_item))
	{
		*result = -1;
		fprintf(stderr, "error: option item %s is expected to be a real\n", option_name);
		if (should_free)
			json_decref(root);
		return -1;
	}

	option_value = json_real_value(option_item);
	*result = 1;
	if (should_free)
		json_decref(root);
	return option_value;
}

/**
 * Gets an double attribute value from a JSON string
 * @param json_string - the JSON string to parse and obtain the attribute value from
 * @param option_name - the name of the attribute to get
 * @param result - a pointer to an integer to return the results of trying to get
 * the attribute value.  The value 0 is returned if the attribute isn't found, -1
 * if the attribute is found but not an integer, and 1 if the attribute is found and
 * an double.
 * @return - the double value of the specified attribute on success, or -1 if the json
 * couldn't be parsed, the attribute wasn't found, or the attribute was the wrong type.
 * Check the value of the result parameter to differentiate between the attribute value
 * of -1 or failure to get the value.
 */
double get_double_options(const char * json_string, const char * option_name, int * result)
{
	json_t * root;

	*result = -1;
	root = get_root_option_json_object(json_string);
	if (!root)
		return -1;
	return get_double_options_inner(root, option_name, result, 1);
}

/**
 * Gets an double attribute value from a json_t object
 * @param root - the json_t object to get the attribute from
 * @param option_name - the name of the attribute to get
 * @param result - a pointer to an integer to return the results of trying to get
 * the attribute value.  The value 0 is returned if the attribute isn't found, -1
 * if the attribute is found but not an integer, and 1 if the attribute is found and
 * an double.
 * @return - the double value of the specified attribute on success, or -1 if the attribute
 * wasn't found or the wrong type.  Check the value of the result parameter to differentiate
 * between the attribute value of -1 or failure to get the value.
 */
double get_double_options_from_json(json_t * root, const char * option_name, int * result)
{
	return get_double_options_inner(root, option_name, result, 0);
}

static int get_array_options_inner(const char * json_string, const char * option_name, size_t * count, char *** string_array, int ** int_array, int is_string_array)
{
	json_t * root, *option_array, *option_item;
	char ** option_strings;
	int * option_ints;
	size_t i;

	root = get_root_option_json_object(json_string);
	if (!root)
		return -1;

	option_array = json_object_get(root, option_name);
	if (!option_array)
	{
		json_decref(root);
		return 0;
	}

	if (!json_is_array(option_array))
	{
		fprintf(stderr, "error: option item %s is expected to be a array\n", option_name);
		json_decref(root);
		return -1;
	}

	*count = json_array_size(option_array);
	if(is_string_array)
		option_strings = malloc(*count * sizeof(char *));
	else
		option_ints = malloc(*count * sizeof(int));
	if ((is_string_array && !option_strings) || (!is_string_array && !option_ints))
	{
		fprintf(stderr, "error: couldn't allocate array for option %s (%zu items)\n", option_name, *count);
		json_decref(root);
		return -1;
	}
	for (i = 0; i < *count; i++)
	{
		option_item = json_array_get(option_array, i);
		if ((is_string_array && !json_is_string(option_item)) || (!is_string_array && !json_is_integer(option_item)))
		{
			fprintf(stderr, "error: option %zu in array %s is expected to be a %s\n", i, option_name, is_string_array ? "string" : "integer");
			json_decref(root);
			free(option_strings);
			return -1;
		}
		if(is_string_array)
			option_strings[i] = strdup(json_string_value(option_item));
		else
			option_ints[i] = json_integer_value(option_item);
	}

	if (is_string_array)
		*string_array = option_strings;
	else
		*int_array = option_ints;

	json_decref(root);
	return 1;
}


/**
 * Gets a string array attribute value from a JSON string
 * @param json_string - the JSON string to parse and obtain the attribute value from
 * @param option_name - the name of the attribute to get
 * @param count - a pointer to a size_t object used to return the number of items found
 * in the array attribute value
 * @param result - a pointer to an integer to return the results of trying to get
 * the attribute value.  The value 0 is returned if the attribute isn't found; -1
 * if the attribute is found but not an array, contains elements that aren't strings, or
 * on allocation failures; and 1 if the attribute is found and a string array.
 * @return - the string array of the specified attribute on success, or NULL if the
 * attribute wasn't found or the wrong type.  The returned array and all of its elements should
 * be freed by the caller.
 */
char ** get_array_options(const char * json_string, const char * option_name, size_t * count, int * result)
{
	char **option_strings = NULL;
	*result = get_array_options_inner(json_string, option_name, count, &option_strings, NULL, 1);
	return option_strings;
}

/**
 * Gets an integer array attribute value from a JSON string
 * @param json_string - the JSON string to parse and obtain the attribute value from
 * @param option_name - the name of the attribute to get
 * @param count - a pointer to a size_t object used to return the number of items found
 * in the array attribute value
 * @param result - a pointer to an integer to return the results of trying to get
 * the attribute value.  The value 0 is returned if the attribute isn't found; -1
 * if the attribute is found but not an array, contains elements that aren't integers, or
 * on allocation failures; and 1 if the attribute is found and an integer array.
 * @return - the integer array of the specified attribute on success, or NULL if the
 * attribute wasn't found or the wrong type.  The returned array should be freed by
 * the caller.
 */
int * get_int_array_options(const char * json_string, const char * option_name, size_t * count, int * result)
{
	int *option_ints = NULL;
	*result = get_array_options_inner(json_string, option_name, count, NULL, &option_ints, 0);
	return option_ints;
}

/**
 * Adds a new attribute to an existing json string.
 * @param root_options - the JSON string to parse and add an attribute to
 * @param new_option_name - the name of the attribute to create
 * @param new_value_string - If specified, the new attribute has the type string
 * and is given the value of this parameter.
 * @param new_value_int - If new_value_string is NULL, the new attribute has the
 * type int and the value specified in this parameter.
 * @return - NULL on error, or the json string passed in the root_options parameter
 * with the added attribute as requested
 */
static char * add_option_to_json(const char * root_options, const char * new_option_name, const char * new_value_string, int new_value_int)
{
	json_t * root, *temp;
	char * ret;

	root = get_root_option_json_object(root_options);
	if (!root)
		return NULL;

	//Add the new item
	if (new_value_string) {
		ADD_STRING(temp, new_value_string, root, new_option_name);
	} else {
		ADD_INT(temp, new_value_int, root, new_option_name);
	}

	ret = json_dumps(root, 0);
	json_decref(root);
	return ret;
}

/**
 * Adds a new string attribute to an existing json string.
 * @param root_options - the JSON string to parse and add an attribute to
 * @param new_option_name - the name of the attribute to create
 * @param new_value - the new attribute's value
 * @return - NULL on error, or the json string passed in the root_options parameter
 * with the added attribute as requested
 */
char * add_string_option_to_json(const char * root_options, const char * new_option_name, const char * new_value)
{
	if (!new_value)
		return NULL;
	return add_option_to_json(root_options, new_option_name, new_value, 0);
}

/**
 * Adds a new integer attribute to an existing json string.
 * @param root_options - the JSON string to parse and add an attribute to
 * @param new_option_name - the name of the attribute to create
 * @param new_value - the new attribute's value
 * @return - NULL on error, or the json string passed in the root_options parameter
 * with the added attribute as requested
 */
char * add_int_option_to_json(const char * root_options, const char * new_option_name, int new_value)
{
	return add_option_to_json(root_options, new_option_name, NULL, new_value);
}

/**
 * Gets an array of buffers out of a JSON string containing an array of
 * JSON mem items
 * @param json_string - the JSON string to parse and get the array items from
 * @param items - a pointer to an array of buffers.  This will be used to return
 * the array of items.
 * @param item_lengths - a pointer to a size_t array that will be used to return the
 * lengths of each item returned in the items parameter
 * @param items_count - a size_t pointer that will be used to return the number of items
 * returned in the items parameter
 * @return - non-zero on failure, 0 on success
 */
int decode_mem_array(const char *json_string, char *** items, size_t ** item_lengths, size_t * items_count)
{
	json_t * items_jsons, *item_json;
	json_error_t error;
	size_t count, i, j;
	char ** items_array;
	size_t * items_lengths_array;

	items_jsons = json_loads(json_string, 0, &error);
	if (!items_jsons)
		return 1;

	if (!json_is_array(items_jsons)) {
		json_decref(items_jsons);
		return 1;
	}

	count = json_array_size(items_jsons);
	if (!count) {
		json_decref(items_jsons);
		*items = NULL;
		*item_lengths = NULL;
		*items_count = 0;
		return 0;
	}

	items_array = malloc(sizeof(char *) * count);
	items_lengths_array = malloc(sizeof(size_t) * count);
	if (!items_array || !items_lengths_array) {
		free(items_array);
		free(items_lengths_array);
		json_decref(items_jsons);
		return 1;
	}
	memset(items_array, 0, sizeof(char *) * count);

	for (i = 0; i < count; i++)
	{
		item_json = json_array_get(items_jsons, i);
		if (json_is_mem(item_json))
		{
			items_lengths_array[i] = json_mem_length(item_json);
			items_array[i] = malloc(items_lengths_array[i]);
			if (items_array[i])
				memcpy(items_array[i], json_mem_value(item_json), items_lengths_array[i]);
		}

		if (!items_array[i])
		{
			for (j = 0; j < i; j++)
				free(items_array[j]);
			free(items_array);
			free(items_lengths_array);
			json_decref(items_jsons);
			return 1;
		}
	}

	*items = items_array;
	*item_lengths = items_lengths_array;
	*items_count = count;
	return 0;
}

/**
 * Transforms an array of buffers into a JSON string containing the array
 * @param items - an array of buffers that will be put into the returned JSON string
 * @param item_lengths - an array of integers that list the lengths of the buffers
 * in the items parameter
 * @param items_count - the number of items in the items and item_lengths parameters
 * @param output_length = the length of the returned JSON string
 * @return - a JSON string containing an array of mem items encoding the buffers on success, or NULL on failure
 */
char * encode_mem_array(char ** items, size_t * item_lengths, size_t items_count, int * output_length)
{
	json_t *items_obj, *item_obj;
	size_t i;
	char * ret;

	items_obj = json_array();
	if (!items_obj)
		return NULL;
	for (i = 0; i < items_count; i++)
	{
		item_obj = json_mem(items[i], item_lengths[i]);
		if (!item_obj) {
			json_decref(items_obj);
			return NULL;
		}
		json_array_append_new(items_obj, item_obj);
	}
	ret = json_dumps(items_obj, 0);
	*output_length = strlen(ret);
	json_decref(items_obj);
	return ret;
}
