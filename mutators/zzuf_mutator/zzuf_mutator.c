#include "zzuf_mutator.h"
#include <mutators.h>

#include <utils.h>
#include <jansson_helper.h>
#include <global_types.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Fuzzing mode
enum fuzzing_mode {
  FUZZING_XOR = 0, FUZZING_SET, FUZZING_UNSET, FUZZING_UNKNOWN
};

// We arbitrarily split files into 1024-byte chunks. Each chunk has an
// associated seed that can be computed from the zzuf seed, the chunk
// index and the fuzziness density. This allows us to predictably fuzz
// any part of the file without reading the whole file.
#define CHUNKBYTES 1024

// The default fuzzing ratio is, arbitrarily, 0.4%.  The minimal fuzzing
// ratio is 0.000000001% (less than one bit changed on a whole DVD).
#define DEFAULT_RATIO 0.004
#define MIN_RATIO 0.00000000001
#define MAX_RATIO 5.0

struct zzuf_state
{
  char * input;
  size_t input_length;

  //Option strings
  char * protect_string;
  char * refuse_string;
  char * range_string;
  char * mode_string;

  //Parsed Options
  enum fuzzing_mode mode;     // Fuzzing mode (xor, set, unset)
  int seed;          // Random number generator seed
  double ratio;
  unsigned char protect[256]; // Per-value byte protection
  unsigned char refuse[256];  // Per-value byte exclusion
  int64_t *ranges;            // Per-offset byte protection

  //Protects the fields below, i.e. the iteration count, data array, and random state
  mutex_t mutate_mutex;

  int iteration;
  unsigned long ctx;
  int current_chunk;
  uint8_t data[CHUNKBYTES];
};
typedef struct zzuf_state zzuf_state_t;

mutator_t zzuf_mutator = {
  FUNCNAME(create),
  FUNCNAME(cleanup),
  FUNCNAME(mutate),
  FUNCNAME(mutate_extended),
  FUNCNAME(get_state),
  zzuf_free_state,
  FUNCNAME(set_state),
  FUNCNAME(get_current_iteration),
  zzuf_get_total_iteration_count,
  FUNCNAME(get_input_info),
  FUNCNAME(set_input),
  FUNCNAME(help)
};

////////////////////////////////////////////////////////////////////////////////////////////
//// zzuf mutator methods //////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

/*
 * The code in this section was taken from the zzuf project (available at
 * https://github.com/samhocevar/zzuf) and is licensed under the below
 * terms.  It has been modified from the original version to suit the
 * purposes of this project.
 *
 * zzuf - general purpose fuzzer
 *
 * Copyright © 2002—2015 Sam Hocevar <sam@hocevar.net>
 *
 * This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What the Fuck You Want
 * to Public License, Version 2, as published by the WTFPL Task Force.
 * See http://www.wtfpl.net/ for more details.
 */

#define MAGIC1 0x33ea84f7
#define MAGIC2 0x783bc31f
#define MAGIC3 0x9b5da2fb

void zzuf_srand(zzuf_state_t * state, uint32_t seed)
{
  state->ctx = (seed ^ 0x12345678);
}

uint32_t zzuf_rand(zzuf_state_t * state, uint32_t max)
{
  /* Could be better, but do we care? */
  long hi = state->ctx / 12773L;
  long lo = state->ctx % 12773L;
  long x = 16807L * lo - 2836L * hi;
  if (x <= 0)
    x += 0x7fffffffL;
  return (state->ctx = x) % (unsigned long)max;
}

/* This function converts a string containing a list of ranges in the format
 * understood by cut(1) such as "1-5,8,10-" into a C array for lookup. It is
 * the caller's duty to call free() on the returned value */
int64_t *_zz_allocrange(char const *list)
{
  char const *parser;
  int64_t *ranges;
  unsigned int i, chunks;

  /* Count commas */
  for (parser = list, chunks = 1; *parser; ++parser)
    if (*parser == ',')
      chunks++;

  ranges = malloc((chunks + 1) * 2 * sizeof(int64_t));

  /* Fill ranges list */
  for (parser = list, i = 0; i < chunks; ++i)
  {
    char const *comma = strchr(parser, ',');
    char const *dash = strchr(parser, '-');

    ranges[i * 2] = (dash == parser) ? 0 : atoi(parser);
    if (dash && (dash + 1 == comma || dash[1] == '\0'))
      ranges[i * 2 + 1] = ranges[i * 2]; /* special case */
    else if (dash && (!comma || dash < comma))
      ranges[i * 2 + 1] = atoi(dash + 1) + 1;
    else
      ranges[i * 2 + 1] = ranges[i * 2] + 1;
    parser = comma + 1;
  }
  ranges[i * 2] = ranges[i * 2 + 1] = 0;

  return ranges;
}

int _zz_isinrange(int64_t value, int64_t const *ranges)
{
  int64_t const *r;

  if (!ranges)
    return 1;

  for (r = ranges; r[1]; r += 2)
    if (value >= r[0] && (r[0] == r[1] || value < r[1]))
      return 1;

  return 0;
}

static void add_char_range(unsigned char *table, char const *list)
{
  static char const hex[] = "0123456789abcdef0123456789ABCDEF";
  char const *tmp;
  int a, b;

  memset(table, 0, 256 * sizeof(unsigned char));

  for (tmp = list, a = b = -1; *tmp; ++tmp)
  {
    int ch;

    if (*tmp == '\\' && tmp[1] == '\0')
      ch = '\\';
    else if (*tmp == '\\')
    {
      tmp++;
      if (*tmp == 'n')
        ch = '\n';
      else if (*tmp == 'r')
        ch = '\r';
      else if (*tmp == 't')
        ch = '\t';
      else if (tmp[0] >= '0' && tmp[0] <= '7' && tmp[1] >= '0'
          && tmp[1] <= '7' && tmp[2] >= '0' && tmp[2] <= '7')
      {
        ch = tmp[2] - '0';
        ch |= (int)(tmp[1] - '0') << 3;
        ch |= (int)(tmp[0] - '0') << 6;
        tmp += 2;
      }
      else if ((*tmp == 'x' || *tmp == 'X')
          && tmp[1] && strchr(hex, tmp[1])
          && tmp[2] && strchr(hex, tmp[2]))
      {
        ch = ((int)(strchr(hex, tmp[1]) - hex) & 0xf) << 4;
        ch |= (int)(strchr(hex, tmp[2]) - hex) & 0xf;
        tmp += 2;
      }
      else
        ch = (unsigned char)*tmp; /* XXX: OK for \\, but what else? */
    }
    else
      ch = (unsigned char)*tmp;

    if (a != -1 && b == '-' && a <= ch)
    {
      while (a <= ch)
        table[a++] = 1;
      a = b = -1;
    }
    else
    {
      if (a != -1)
        table[a] = 1;
      a = b;
      b = ch;
    }
  }

  if (a != -1)
    table[a] = 1;
  if (b != -1)
    table[b] = 1;
}

static enum fuzzing_mode _zz_fuzzing(char const *mode)
{
  if (!strcmp(mode, "xor"))
    return FUZZING_XOR;
  else if (!strcmp(mode, "set"))
    return FUZZING_SET;
  else if (!strcmp(mode, "unset"))
    return FUZZING_UNSET;
  return FUZZING_UNKNOWN;
}

void _zz_fuzz(zzuf_state_t * state, char * buf, int64_t len)
{
  uint32_t chunkseed;
  int64_t i, j, start, stop;
  unsigned char byte, fuzzbyte;
  int todo;
  unsigned int idx;
  uint8_t bit;

  for (i = 0; i < (len + CHUNKBYTES - 1) / CHUNKBYTES; ++i)
  {
    /* Cache bitmask array */
    if (state->current_chunk != (int)i)
    {
      chunkseed = (uint32_t)i;
      chunkseed ^= MAGIC2;
      chunkseed += (uint32_t)(state->ratio * MAGIC1);
      chunkseed ^= (state->seed + state->iteration); //Increment the zzuf seed each mutation
      chunkseed += (uint32_t)(i * MAGIC3);

      zzuf_srand(state, chunkseed);

      memset(state->data, 0, CHUNKBYTES);

      /* Add some random dithering to handle ratio < 1.0/CHUNKBYTES */
      todo = (int)((state->ratio * (8 * CHUNKBYTES) * 1000000.0 + zzuf_rand(state, 1000000)) / 1000000.0);
      while (todo--)
      {
        idx = zzuf_rand(state, CHUNKBYTES);
        bit = (1 << zzuf_rand(state, 8));
        state->data[idx] ^= bit;
      }

      state->current_chunk = i;
    }

    // Apply our bitmask array to the buffer
    start = (i * CHUNKBYTES > 0) ? i * CHUNKBYTES : 0;
    stop = ((i + 1) * CHUNKBYTES < len) ? (i + 1) * CHUNKBYTES : len;

    for (j = start; j < stop; ++j)
    {
      if (state->ranges && !_zz_isinrange(j, state->ranges))
        continue; // Not in one of the ranges, skip byte

      byte = (uint8_t)buf[j];

      if(state->protect[byte])
        continue;

      fuzzbyte = state->data[j % CHUNKBYTES];
      if(!fuzzbyte)
        continue;

      switch (state->mode)
      {
        case FUZZING_XOR:
          byte ^= fuzzbyte;
          break;
        case FUZZING_SET:
          byte |= fuzzbyte;
          break;
        case FUZZING_UNSET:
          byte &= ~fuzzbyte;
          break;
      }

      if(state->refuse[byte])
        continue;

      buf[j] = (uint8_t)byte;
    }
  }
}

////////////////////////////////////////////////////////////////////////////////////////////
//// API methods ///////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

#ifndef ALL_MUTATORS_IN_ONE

/**
 * This function fills in the supplied mutator_t with all of the function
 * pointers for this mutator.
 * @param m - a pointer to a mutator_t structure
 */
ZZUF_MUTATOR_API void init(mutator_t * m)
{
  memcpy(m, &zzuf_mutator, sizeof(mutator_t));
}

#endif

/**
 * This function sets up the refuse, protect, and range tables from the associated strings in a
 * state.  Additionally, the fuzzing mode is set from the mode string.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 */
static void setup_state_from_strings(zzuf_state_t * state)
{
  if(state->refuse_string)
    add_char_range(state->refuse, state->refuse_string);
  if(state->protect_string)
    add_char_range(state->protect, state->protect_string);
  if(state->range_string)
    state->ranges = _zz_allocrange(state->range_string);
  if(state->mode_string)
    state->mode = _zz_fuzzing(state->mode_string);
}

/**
 * This function frees the memory associated with the protect, refuse, mode, and range strings. Also
 * the range table is freed.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 */
static void free_ranges(zzuf_state_t * state)
{
  free(state->protect_string);
  state->protect_string = NULL;
  free(state->refuse_string);
  state->refuse_string = NULL;
  free(state->range_string);
  state->range_string = NULL;
  free(state->mode_string);
  state->mode_string = NULL;
  free(state->ranges);
  state->ranges = NULL;
}

/**
 * This function creates and initializes a zzuf_state_t object based on the passed in JSON options.
 * @return the newly created zzuf_state_t object or NULL on failure
 */
static zzuf_state_t * setup_options(char * options)
{
  zzuf_state_t * state;
  size_t i;
  state = (zzuf_state_t *)malloc(sizeof(zzuf_state_t));
  if (!state)
    return NULL;
  memset(state, 0, sizeof(zzuf_state_t));

  state->current_chunk = -1;
  state->mutate_mutex = create_mutex();
  if (!state->mutate_mutex) {
    free(state);
    return NULL;
  }

  //Setup defaults
  state->seed = rand();
  state->mode = FUZZING_XOR;
  state->ratio = DEFAULT_RATIO;

  if (!options || !strlen(options))
    return state;

  PARSE_OPTION_STRING(state, options, mode_string, "mode", FUNCNAME(cleanup));
  PARSE_OPTION_DOUBLE(state, options, ratio, "ratio", FUNCNAME(cleanup));
  PARSE_OPTION_STRING(state, options, range_string, "range", FUNCNAME(cleanup));
  PARSE_OPTION_STRING(state, options, refuse_string, "refuse", FUNCNAME(cleanup));
  PARSE_OPTION_INT(state, options, seed, "seed", FUNCNAME(cleanup));
  PARSE_OPTION_STRING(state, options, protect_string, "protect", FUNCNAME(cleanup));

  state->ratio = state->ratio < MIN_RATIO ? MIN_RATIO : state->ratio > MAX_RATIO ? MAX_RATIO : state->ratio;
  setup_state_from_strings(state);
  if(state->mode == FUZZING_UNKNOWN) {
    FUNCNAME(cleanup)(state);
    return NULL;
  }
  return state;
}

/**
 * This function will allocate and initialize the mutator state. The mutator state should be
 * freed by calling the cleanup function.
 * @param options - a json string that contains the zzuf specific options.
 * @param state - optionally, a previously dumped state (with the get_state() function) to load
 * @param input - The input that this mutator will later be mutating
 * @param input_length - the size of the input parameter
 * @return a mutator specific structure or NULL on failure. The returned value should
 * not be used for anything other than passing to the various Mutator API functions.
 */
ZZUF_MUTATOR_API void * FUNCNAME(create)(char * options, char * state, char * input, size_t input_length)
{
  zzuf_state_t * zzuf_state = setup_options(options);
  if (!zzuf_state)
    return NULL;

  zzuf_state->input = (char *)malloc(input_length);
  if (!zzuf_state->input || !input_length)
  {
    FUNCNAME(cleanup)(zzuf_state);
    return NULL;
  }
  memcpy(zzuf_state->input, input, input_length);
  zzuf_state->input_length = input_length;
  if (state && FUNCNAME(set_state)(zzuf_state, state)) {
    FUNCNAME(cleanup)(zzuf_state);
    return NULL;
  }
  return zzuf_state;
}

/**
 * This function will release any resources that the mutator has open
 * and free the mutator state structure.
 * @param mutator_state - a mutator specific structure previously created by
 * the create function. This structure will be freed and should not be referenced afterwards.
 */
ZZUF_MUTATOR_API void FUNCNAME(cleanup)(void * mutator_state)
{
  size_t i;
  zzuf_state_t * state = (zzuf_state_t *)mutator_state;

  destroy_mutex(state->mutate_mutex);
  free_ranges(state);
  free(state->input);
  free(state);
}

/**
 * This function will mutate the input given in the create function and return it in the buffer argument.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param buffer - a buffer that the mutated input will be written to
 * @param buffer_length - the size of the passed in buffer argument
 * @return - the length of the mutated data, 0 when the mutator is out of mutations, or -1 on error
 */
ZZUF_MUTATOR_API int FUNCNAME(mutate)(void * mutator_state, char * buffer, size_t buffer_length)
{
  zzuf_state_t * state = (zzuf_state_t *)mutator_state;
  size_t mutated_buffer_length;
  //Can't mutate an empty buffer
  if (buffer_length == 0)
    return -1;

  mutated_buffer_length = buffer_length > state->input_length ? state->input_length : buffer_length;
  memcpy(buffer, state->input, mutated_buffer_length);
  _zz_fuzz(state, buffer, mutated_buffer_length);
  state->iteration++;
  return (int)mutated_buffer_length;
}

/**
 * This function will mutate the input given in the create function and return it in the buffer argument.
 * This function also accepts a set of flags which instruct it how to mutate the input. See global_types.h
 * for the list of available flags.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param buffer - a buffer that the mutated input will be written to
 * @param buffer_length - the size of the passed in buffer argument.
 * @param flags - A set of mutate flags that modify how this mutator mutates the input.
 * @return - the length of the mutated data, 0 when the mutator is out of mutations, or -1 on error
 */
ZZUF_MUTATOR_API int FUNCNAME(mutate_extended)(void * mutator_state, char * buffer, size_t buffer_length, uint64_t flags)
{
  SINGLE_INPUT_MUTATE_EXTENDED(zzuf_state_t, state->mutate_mutex);
}

/**
 * This function will return the state of the mutator. The returned value can be used to restart the
 * mutator at a later time, by passing it to the create or set_state function. It is the caller's
 * responsibility to free the memory allocated here by calling the free_state function.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @return - a buffer that defines the current state of the mutator. This will be a mutator specific JSON string.
 */
ZZUF_MUTATOR_API char * FUNCNAME(get_state)(void * mutator_state)
{
  zzuf_state_t * state = (zzuf_state_t *)mutator_state;
  json_t *obj, *temp;
  char * ret;

  obj = json_object();
  ADD_INT(temp, state->iteration, obj, "iteration");
  ADD_INT(temp, state->seed, obj, "seed");
  ADD_INT(temp, state->mode, obj, "mode");
  ADD_DOUBLE(temp, state->ratio, obj, "ratio");
  ADD_STRING(temp, state->protect_string, obj, "protect");
  ADD_STRING(temp, state->refuse_string, obj, "refuse");
  ADD_STRING(temp, state->range_string, obj, "range");
  ret = json_dumps(obj, 0);
  json_decref(obj);
  return ret;
}

/**
 * This function will set the current state of the mutator.
 * This can be used to restart a mutator once from a previous run.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param state - a previously dumped state buffer obtained by the get_state function.
 * @return 0 on success or non-zero on failure
 */
ZZUF_MUTATOR_API int FUNCNAME(set_state)(void * mutator_state, char * state)
{
  zzuf_state_t * zzuf_state = (zzuf_state_t *)mutator_state;
  int result, temp_int;
  double temp_double;
  char * temp_str;

  if (!state)
    return 1;

  free_ranges(zzuf_state);
  zzuf_state->current_chunk = -1;

  GET_INT(temp_int, state, zzuf_state->iteration, "iteration", result);
  GET_INT(temp_int, state, zzuf_state->seed, "seed", result);
  GET_INT(temp_int, state, zzuf_state->mode, "mode", result);
  GET_DOUBLE(temp_double, state, zzuf_state->ratio, "ratio", result);
  GET_STRING(temp_str, state, zzuf_state->protect_string, "protect", result);
  GET_STRING(temp_str, state, zzuf_state->refuse_string, "refuse", result);
  GET_STRING(temp_str, state, zzuf_state->range_string, "range", result);
  setup_state_from_strings(zzuf_state);

  return 0;
}

/**
 * This function will return the current iteration count of the mutator, i.e.
 * how many mutations have been generated with it.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @return value - the number of previously generated mutations
 */
ZZUF_MUTATOR_API int FUNCNAME(get_current_iteration)(void * mutator_state)
{
  GENERIC_MUTATOR_GET_ITERATION(zzuf_state_t);
}

/**
 * Obtains information about the inputs that were given to the mutator when it was created
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param num_inputs - a pointer to an integer used to return the number of inputs given to this mutator
 * when it was created. This parameter is optional and can be NULL, if this information is not needed
 * @param input_sizes - a pointer to a size_t array used to return the sizes of the inputs given to this
 * mutator when it was created. This parameter is optional and can be NULL, if this information is not needed.
 */
ZZUF_MUTATOR_API void FUNCNAME(get_input_info)(void * mutator_state, int * num_inputs, size_t **input_sizes)
{
  SINGLE_INPUT_GET_INFO(zzuf_state_t);
}

/**
 * This function will set the input(saved in the mutators state) to something new.
 * This can be used to reinitialize a mutator with new data, without reallocating the entire state struct.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param new_input - The new input used to produce new mutated inputs later when the mutate function is called
 * @param input_length - the size in bytes of the input buffer.
 * @return 0 on success and -1 on failure
 */
ZZUF_MUTATOR_API int FUNCNAME(set_input)(void * mutator_state, char * new_input, size_t input_length)
{
  GENERIC_MUTATOR_SET_INPUT(zzuf_state_t);
}

/**
 * This function sets a help message for the mutator.
 * @param help_str - A pointer that will be updated to point to the new help string.
 * @return 0 on success and -1 on failure
 */
ZZUF_MUTATOR_API int FUNCNAME(help)(char ** help_str)
{
  GENERIC_MUTATOR_HELP(
      "zzuf - zzuf-based mutator\n"
      "Options:\n"
      "\tmode                  fuzzing mode to use: xor, set, or unset\n"
      "\tprotect               protect bytes and characters in <list>\n"
      "\trange                 only fuzz bytes at offsets within <ranges>\n"
      "\tratio                 bit fuzzing ratio\n"
      "\trefuse                refuse bytes and characters in <list>\n"
      "\tseed                  random seed\n"
      "\n"
      );
}
