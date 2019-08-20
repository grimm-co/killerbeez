#include "honggfuzz_mutator.h"
#include <mutators.h>

#include <utils.h>
#include <jansson.h>
#include <jansson_helper.h>
#include <global_types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
	char* s;
	size_t len;
} string_t;

struct honggfuzz_state
{
	int mutations_per_run;
	char * dictionary_file;
	uint64_t dictionary_count;
	string_t ** dictq;

	char * input;
	size_t input_length;

	//Protects the fields below, i.e. the iteration count, mutate buffer information, and random state
	mutex_t mutate_mutex;

	int iteration;
	uint8_t * mutated_buffer;
	uint64_t mutated_buffer_length;
	uint64_t max_mutated_buffer_length;
	uint64_t random_state[2];
};
typedef struct honggfuzz_state honggfuzz_state_t;

mutator_t honggfuzz_mutator = {
	FUNCNAME(create),
	FUNCNAME(cleanup),
	FUNCNAME(mutate),
	FUNCNAME(mutate_extended),
	FUNCNAME(get_state),
	honggfuzz_free_state,
	FUNCNAME(set_state),
	FUNCNAME(get_current_iteration),
	honggfuzz_get_total_iteration_count,
	FUNCNAME(get_input_info),
	FUNCNAME(set_input),
	FUNCNAME(help)
};

////////////////////////////////////////////////////////////////////////////////////////////
//// Honggfuzz mutator methods /////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

/*
 * The code in this section (Honggfuzz mutator methods) was taken
 * from honggfuzz and falls under the following license:
 *
 * honggfuzz - run->dynamicFilefer mangling routines
 * -----------------------------------------
 *
 * Author:
 * Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2015 by Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * The code in this section has been modified from the original to suit the
 * purposes of this project.
 */

//The following functions are taken from honggfuzz, see:
//https://github.com/google/honggfuzz/blob/master/mangle.c
//https://github.com/google/honggfuzz/blob/master/libcommon/util.c

/*
 * xoroshiro128plus by David Blackman and Sebastiano Vigna
 */
static inline uint64_t util_RotL(const uint64_t x, int k)
{
	return (x << k) | (x >> (64 - k));
}

static inline uint64_t util_InternalRnd64(honggfuzz_state_t * state) {
	const uint64_t s0 = state->random_state[0];
	uint64_t s1 = state->random_state[1];
	const uint64_t result = s0 + s1;
	s1 ^= s0;
	state->random_state[0] = util_RotL(s0, 55) ^ s1 ^ (s1 << 14);
	state->random_state[1] = util_RotL(s1, 36);
	return result;
}

uint64_t util_rnd64(honggfuzz_state_t * state) {
	return util_InternalRnd64(state);
}

uint64_t util_rndGet(honggfuzz_state_t * state, uint64_t min, uint64_t max) {
	assert(min <= max);
	if (max == UINT64_MAX) {
		return util_rnd64(state);
	}

	return ((util_rnd64(state) % (max - min + 1)) + min);
}

void util_rndBuf(honggfuzz_state_t * state, uint8_t* buf, uint64_t sz) {
	if (sz == 0) {
		return;
	}
	for (uint64_t i = 0; i < sz; i++) {
		buf[i] = (uint8_t)util_InternalRnd64(state);
	}
}

static inline void mangle_Overwrite(honggfuzz_state_t * state, const uint8_t* src, uint64_t off, uint64_t sz) {
	uint64_t maxToCopy = state->mutated_buffer_length - off;
	if (sz > maxToCopy) {
		sz = maxToCopy;
	}

	memmove(&state->mutated_buffer[off], src, (size_t)sz);
}

static inline void mangle_Move(honggfuzz_state_t * state, uint64_t off_from, uint64_t off_to, uint64_t len) {
	if (off_from >= state->mutated_buffer_length) {
		return;
	}
	if (off_to >= state->mutated_buffer_length) {
		return;
	}

	int64_t len_from = (int64_t)state->mutated_buffer_length - off_from - 1;
	int64_t len_to = (int64_t)state->mutated_buffer_length - off_to - 1;

	if ((int64_t)len > len_from) {
		len = len_from;
	}
	if ((int64_t)len > len_to) {
		len = len_to;
	}

	memmove(&state->mutated_buffer[off_to], &state->mutated_buffer[off_from], (size_t)len);
}

static void mangle_Inflate(honggfuzz_state_t * state, uint64_t off, uint64_t len) {
	if (state->mutated_buffer_length >= state->max_mutated_buffer_length) {
		return;
	}
	if (len > (state->max_mutated_buffer_length - state->mutated_buffer_length)) {
		len = state->max_mutated_buffer_length - state->mutated_buffer_length;
	}

	state->mutated_buffer_length += len;
	mangle_Move(state, off, off + len, state->mutated_buffer_length);
}

static void mangle_MemMove(honggfuzz_state_t * state) {
	uint64_t off_from = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	uint64_t off_to = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	uint64_t len = util_rndGet(state, 0, state->mutated_buffer_length);

	mangle_Move(state, off_from, off_to, len);
}

static void mangle_Byte(honggfuzz_state_t * state) {
	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	state->mutated_buffer[off] = (uint8_t)util_rnd64(state);
}

static void mangle_Bytes(honggfuzz_state_t * state) {
	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	uint32_t val = (uint32_t)util_rnd64(state);

	/* Overwrite with random 2,3,4-byte values */
	uint64_t toCopy = util_rndGet(state, 2, 4);
	mangle_Overwrite(state, (uint8_t*)&val, off, toCopy);
}

static void mangle_Bit(honggfuzz_state_t * state) {
	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	state->mutated_buffer[off] ^= (uint8_t)(1U << util_rndGet(state, 0, 7));
}

static void mangle_DictionaryInsert(honggfuzz_state_t * state) {
	if (state->dictionary_count == 0) {
		mangle_Bit(state);
		return;
	}

	uint64_t choice = util_rndGet(state, 0, state->dictionary_count - 1);
	string_t* str = state->dictq[choice];
	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	mangle_Inflate(state, off, str->len);
	mangle_Move(state, off, off + str->len, str->len);
	mangle_Overwrite(state, (uint8_t*)str->s, off, str->len);
}

static void mangle_Dictionary(honggfuzz_state_t * state) {
	if (state->dictionary_count == 0) {
		mangle_Bit(state);
		return;
	}

	uint64_t choice = util_rndGet(state, 0, state->dictionary_count - 1);
	string_t* str = state->dictq[choice];
	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	mangle_Overwrite(state, (uint8_t*)str->s, off, str->len);
}

static void mangle_Magic(honggfuzz_state_t * state) {
	struct magic_values
	{
		//ugh.  Visual studio insists on strings being null terminated
		uint8_t val[9];//so we need to use 9 bytes instead of 8 for the value
		uint64_t size;
	};
	static const struct magic_values mangleMagicVals[] = {
		// 1B - No endianness
		{ "\x00\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x01\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x02\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x03\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x04\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x05\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x06\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x07\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x08\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x09\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x0A\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x0B\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x0C\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x0D\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x0E\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x0F\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x10\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x20\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x40\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x7E\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x7F\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x80\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\x81\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\xC0\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\xFE\x00\x00\x00\x00\x00\x00\x00", 1 },
		{ "\xFF\x00\x00\x00\x00\x00\x00\x00", 1 },
		// 2B - NE
		{ "\x00\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x01\x01\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x80\x80\x00\x00\x00\x00\x00\x00", 2 },
		{ "\xFF\xFF\x00\x00\x00\x00\x00\x00", 2 },
		// 2B - BE
		{ "\x00\x01\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x02\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x03\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x04\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x05\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x06\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x07\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x08\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x09\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x0A\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x0B\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x0C\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x0D\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x0E\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x0F\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x10\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x20\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x40\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x7E\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x7F\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x80\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x81\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\xC0\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\xFE\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\xFF\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x7E\xFF\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x7F\xFF\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x80\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x80\x01\x00\x00\x00\x00\x00\x00", 2 },
		{ "\xFF\xFE\x00\x00\x00\x00\x00\x00", 2 },
		// 2B - LE
		{ "\x00\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x01\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x02\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x03\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x04\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x05\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x06\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x07\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x08\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x09\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x0A\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x0B\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x0C\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x0D\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x0E\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x0F\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x10\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x20\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x40\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x7E\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x7F\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x80\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x81\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\xC0\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\xFE\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\xFF\x00\x00\x00\x00\x00\x00\x00", 2 },
		{ "\xFF\x7E\x00\x00\x00\x00\x00\x00", 2 },
		{ "\xFF\x7F\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x00\x80\x00\x00\x00\x00\x00\x00", 2 },
		{ "\x01\x80\x00\x00\x00\x00\x00\x00", 2 },
		{ "\xFE\xFF\x00\x00\x00\x00\x00\x00", 2 },
		// 4B - NE
		{ "\x00\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x01\x01\x01\x01\x00\x00\x00\x00", 4 },
		{ "\x80\x80\x80\x80\x00\x00\x00\x00", 4 },
		{ "\xFF\xFF\xFF\xFF\x00\x00\x00\x00", 4 },
		// 4B - BE
		{ "\x00\x00\x00\x01\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x02\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x03\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x04\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x05\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x06\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x07\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x08\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x09\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x0A\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x0B\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x0C\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x0D\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x0E\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x0F\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x10\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x20\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x40\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x7E\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x7F\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x80\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x81\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\xC0\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\xFE\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\xFF\x00\x00\x00\x00", 4 },
		{ "\x7E\xFF\xFF\xFF\x00\x00\x00\x00", 4 },
		{ "\x7F\xFF\xFF\xFF\x00\x00\x00\x00", 4 },
		{ "\x80\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x80\x00\x00\x01\x00\x00\x00\x00", 4 },
		{ "\xFF\xFF\xFF\xFE\x00\x00\x00\x00", 4 },
		// 4B - LE
		{ "\x00\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x01\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x02\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x03\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x04\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x05\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x06\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x07\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x08\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x09\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x0A\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x0B\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x0C\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x0D\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x0E\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x0F\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x10\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x20\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x40\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x7E\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x7F\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x80\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\x81\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\xC0\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\xFE\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\xFF\x00\x00\x00\x00\x00\x00\x00", 4 },
		{ "\xFF\xFF\xFF\x7E\x00\x00\x00\x00", 4 },
		{ "\xFF\xFF\xFF\x7F\x00\x00\x00\x00", 4 },
		{ "\x00\x00\x00\x80\x00\x00\x00\x00", 4 },
		{ "\x01\x00\x00\x80\x00\x00\x00\x00", 4 },
		{ "\xFE\xFF\xFF\xFF\x00\x00\x00\x00", 4 },
		// 8B - NE
		{ "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x01\x01\x01\x01\x01\x01\x01\x01", 8 },
		{ "\x80\x80\x80\x80\x80\x80\x80\x80", 8 },
		{ "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8 },
		// 8B - BE
		{ "\x00\x00\x00\x00\x00\x00\x00\x01", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x02", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x03", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x04", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x05", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x06", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x07", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x08", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x09", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x0A", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x0B", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x0C", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x0D", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x0E", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x0F", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x10", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x20", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x40", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x7E", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x7F", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x80", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x81", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\xC0", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\xFE", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\xFF", 8 },
		{ "\x7E\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8 },
		{ "\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8 },
		{ "\x80\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x80\x00\x00\x00\x00\x00\x00\x01", 8 },
		{ "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE", 8 },
		// 8B - LE
		{ "\x00\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x01\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x02\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x03\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x04\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x05\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x06\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x07\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x08\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x09\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x0A\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x0B\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x0C\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x0D\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x0E\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x0F\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x10\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x20\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x40\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x7E\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x7F\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x80\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\x81\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\xC0\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\xFE\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\xFF\x00\x00\x00\x00\x00\x00\x00", 8 },
		{ "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7E", 8 },
		{ "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x7F", 8 },
		{ "\x00\x00\x00\x00\x00\x00\x00\x80", 8 },
		{ "\x01\x00\x00\x00\x00\x00\x00\x80", 8 },
		{ "\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8 },
	};

	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	uint64_t choice = util_rndGet(state, 0, ARRAY_SIZE(mangleMagicVals) - 1);
	mangle_Overwrite(state, mangleMagicVals[choice].val, off, mangleMagicVals[choice].size);
}

static void mangle_MemSet(honggfuzz_state_t * state) {
	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	uint64_t sz = util_rndGet(state, 1, state->mutated_buffer_length - off);
	int val = (int)util_rndGet(state, 0, UINT8_MAX);

	memset(&state->mutated_buffer[off], val, (size_t)sz);
}

static void mangle_Random(honggfuzz_state_t * state) {
	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	uint64_t len = util_rndGet(state, 1, state->mutated_buffer_length - off);
	util_rndBuf(state, &state->mutated_buffer[off], len);
}

static void mangle_AddSub(honggfuzz_state_t * state) {
	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);

	/* 1,2,4,8 */
	uint64_t varLen = 1ULL << util_rndGet(state, 0, 3);
	if ((state->mutated_buffer_length - off) < varLen) {
		varLen = 1;
	}

	int delta = (int)util_rndGet(state, 0, 8192);
	delta -= 4096;

	assert(varLen == 1 || varLen == 2 || varLen == 4 || varLen == 8);
	switch (varLen) {
		case 1: {
			state->mutated_buffer[off] += delta;
			break;
		}
		case 2: {
			int16_t val;
			memcpy(&val, &state->mutated_buffer[off], sizeof(val));
			if (util_rnd64(state) & 0x1) {
				val += delta;
			}
			else {
				/* Foreign endianess */
				val = SWAP16(val);
				val += delta;
				val = SWAP16(val);
			}
			mangle_Overwrite(state, (uint8_t*)&val, off, varLen);
			break;
		}
		case 4: {
			int32_t val;
			memcpy(&val, &state->mutated_buffer[off], sizeof(val));
			if (util_rnd64(state) & 0x1) {
				val += delta;
			}
			else {
				/* Foreign endianess */
				val = SWAP32(val);
				val += delta;
				val = SWAP32(val);
			}
			mangle_Overwrite(state, (uint8_t*)&val, off, varLen);
			break;
		}
		case 8: {
			int64_t val;
			memcpy(&val, &state->mutated_buffer[off], sizeof(val));
			if (util_rnd64(state) & 0x1) {
				val += delta;
			}
			else {
				/* Foreign endianess */
				val = SWAP64(val);
				val += delta;
				val = SWAP64(val);
			}
			mangle_Overwrite(state, (uint8_t*)&val, off, varLen);
			break;
		}
	}
}

static void mangle_IncByte(honggfuzz_state_t * state) {
	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	state->mutated_buffer[off] += (uint8_t)1UL;
}

static void mangle_DecByte(honggfuzz_state_t * state) {
	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	state->mutated_buffer[off] -= (uint8_t)1UL;
}

static void mangle_NegByte(honggfuzz_state_t * state) {
	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	state->mutated_buffer[off] = ~(state->mutated_buffer[off]);
}

static void mangle_CloneByte(honggfuzz_state_t * state) {
	uint64_t off1 = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	uint64_t off2 = util_rndGet(state, 0, state->mutated_buffer_length - 1);

	uint8_t tmp = state->mutated_buffer[off1];
	state->mutated_buffer[off1] = state->mutated_buffer[off2];
	state->mutated_buffer[off2] = tmp;
}

static void mangle_Resize(honggfuzz_state_t * state) {
	state->mutated_buffer_length = util_rndGet(state, 1, state->max_mutated_buffer_length);
}

static void mangle_Expand(honggfuzz_state_t * state) {
	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	uint64_t len = util_rndGet(state, 1, state->mutated_buffer_length - off);

	mangle_Inflate(state, off, len);
	mangle_Move(state, off, off + len, state->mutated_buffer_length);
}

static void mangle_Shrink(honggfuzz_state_t * state) {
	if (state->mutated_buffer_length <= 1U) {
		return;
	}

	uint64_t len = util_rndGet(state, 1, state->mutated_buffer_length - 1);
	uint64_t off = util_rndGet(state, 0, len);

	state->mutated_buffer_length -= len;
	mangle_Move(state, off + len, off, state->mutated_buffer_length);
}

static void mangle_InsertRnd(honggfuzz_state_t * state) {
	uint64_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);
	uint64_t len = util_rndGet(state, 1, state->mutated_buffer_length - off);

	mangle_Inflate(state, off, len);
	mangle_Move(state, off, off + len, state->mutated_buffer_length);
	util_rndBuf(state, &state->mutated_buffer[off], len);
}

static void mangle_ASCIIVal(honggfuzz_state_t * state) {
	char buf[32];
	snprintf(buf, sizeof(buf), "%" PRId64, (int64_t)util_rnd64(state));
	size_t off = util_rndGet(state, 0, state->mutated_buffer_length - 1);

	mangle_Overwrite(state, (uint8_t*)buf, off, strlen(buf));
}

static void mangle_mangleContent(honggfuzz_state_t* state) {
	if (state->mutations_per_run == 0U) {
		return;
	}

	/* Minimum support file size for mangling is 1 */
	if (state->mutated_buffer_length == 0UL) {
		state->mutated_buffer_length = 1UL;
		state->mutated_buffer[0] = '\0';
	}

	static void(*const mangleFuncs[])(honggfuzz_state_t * state) = {
		mangle_Resize,
		mangle_Byte,
		mangle_Bit,
		mangle_Bytes,
		mangle_Magic,
		mangle_IncByte,
		mangle_DecByte,
		mangle_NegByte,
		mangle_AddSub,
		mangle_Dictionary,
		mangle_DictionaryInsert,
		mangle_MemMove,
		mangle_MemSet,
		mangle_Random,
		mangle_CloneByte,
		mangle_Expand,
		mangle_Shrink,
		mangle_InsertRnd,
		mangle_ASCIIVal,
	};

	uint64_t changesCnt = util_rndGet(state, 1, state->mutations_per_run);
	for (uint64_t x = 0; x < changesCnt; x++) {
		uint64_t choice = util_rndGet(state, 0, ARRAY_SIZE(mangleFuncs) - 1);
		mangleFuncs[choice](state);
	}
}

static size_t util_decodeCString(char* s) {
	size_t o = 0;
	for (size_t i = 0; s[i] != '\0' && s[i] != '"'; i++, o++) {
		switch (s[i]) {
		case '\\': {
			i++;
			if (!s[i]) {
				continue;
			}
			switch (s[i]) {
			case 'a':
				s[o] = '\a';
				break;
			case 'r':
				s[o] = '\r';
				break;
			case 'n':
				s[o] = '\n';
				break;
			case 't':
				s[o] = '\t';
				break;
			case '0':
				s[o] = '\0';
				break;
			case 'x': {
				if (s[i + 1] && s[i + 2]) {
					char hex[] = { s[i + 1], s[i + 2], 0 };
					s[o] = (char) strtoul(hex, NULL, 16);
					i += 2;
				}
				else {
					s[o] = s[i];
				}
				break;
			}
			default:
				s[o] = s[i];
				break;
			}
			break;
		}
		default: {
			s[o] = s[i];
			break;
		}
		}
	}
	s[o] = '\0';
	return o;
}

static int input_parseDictionary(honggfuzz_state_t * state) {
	char * contents;
	char lineptr[2100];
	int start, pos = 0, length, ret = 0;
	size_t len;

	length = read_file(state->dictionary_file, &contents);
	if (length < 0) {
		printf("Couldn't open '%s'", state->dictionary_file);
		return 1;
	}

	for (;;) {
		//Find the end of the line
		len = 0;
		memset(lineptr, 0, sizeof(lineptr));
		for (start = pos; pos < length; pos++)
		{
			if (contents[pos] == '\n')
			{
				len = pos - start;
				memcpy(lineptr, &contents[start], len);
				pos++;
				break;
			}
		}

		if (len == 0) {
			if(start == pos) //end of the file with no left over content
				break;

			len = pos - start;
			memcpy(lineptr, &contents[start], len);
		}

		//Remove the \r\n
		if (len > 1 && lineptr[len - 1] == '\n') {
			lineptr[len - 1] = '\0';
			len--;
		}
		if (len > 1 && lineptr[len - 1] == '\r') {
			lineptr[len - 1] = '\0';
			len--;
		}

		//if the line is empty, skip it
		if (lineptr[0] == '#' || lineptr[0] == '\r' || lineptr[0] == '\n' || lineptr[0] == '\0') {
			continue;
		}

		//Parse the dictionary line
		char bufn[1025];
		char bufv[1025];
		if (sscanf(lineptr, "\"%1024s", bufv) != 1 &&
			sscanf(lineptr, "%1024[^=]=\"%1024s", bufn, bufv) != 2) {
			printf("Incorrect dictionary entry: '%s'.\n", lineptr);
			ret = 1;
			break;
		}

		char* s = strdup(bufv);
		string_t* str = (string_t*)malloc(sizeof(string_t));
		str->len = util_decodeCString(s);
		str->s = s;

		state->dictq = (string_t **)realloc(state->dictq, (state->dictionary_count + 1) * sizeof(string_t));
		state->dictq[state->dictionary_count] = str;
		state->dictionary_count++;
	}

	return ret;
}

////////////////////////////////////////////////////////////////////////////////////////////
//// API methods ///////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////

#ifndef ALL_MUTATORS_IN_ONE

/**
 * This function filled in the supplied mutator_t with all of the function
 * pointers for this mutator.
 * @param m - a pointer to a mutator_t structure
 * @return none
 */
HONGGFUZZ_MUTATOR_API void init(mutator_t * m)
{
	memcpy(m, &honggfuzz_mutator, sizeof(mutator_t));
}

#endif

/**
 * This function creates and initializes a honggfuzz_state_t object based on the passed in JSON options.
 * @return the newly created honggfuzz_state_t object or NULL on failure
 */
static honggfuzz_state_t * setup_options(char * options)
{
	honggfuzz_state_t * state;
	state = (honggfuzz_state_t *)malloc(sizeof(honggfuzz_state_t));
	if (!state)
		return NULL;
	memset(state, 0, sizeof(honggfuzz_state_t));

	//Setup defaults
	state->mutations_per_run = 6;
	state->random_state[0] = (((uint64_t)rand()) << 32) | rand();
	state->random_state[1] = (((uint64_t)rand()) << 32) | rand();
	state->mutate_mutex = create_mutex();
	if (!state->mutate_mutex) {
		free(state);
		return NULL;
	}

	if (!options || !strlen(options))
		return state;

	PARSE_OPTION_INT(state, options, mutations_per_run, "mutations_per_run", FUNCNAME(cleanup));
	PARSE_OPTION_UINT64T_TEMP(state, options, random_state[0], "random_state0", FUNCNAME(cleanup), temp1);
	PARSE_OPTION_UINT64T_TEMP(state, options, random_state[1], "random_state1", FUNCNAME(cleanup), temp2);
	PARSE_OPTION_STRING(state, options, dictionary_file, "dictionary", FUNCNAME(cleanup));

	if (state->dictionary_file && input_parseDictionary(state))
	{
		FUNCNAME(cleanup)(state);
		return NULL;
	}

	return state;
}

/**
 * This function will allocate and initialize the mutator state.  The mutator state should be
 * freed by calling the cleanup function.
 * @param options - a json string that contains the honggfuzz specific  options.
 * @param state - optionally, a previously dumped state (with the get_state() function) to load
 * @param input - The input that this mutator will later be mutating
 * @param input_length - the size of the input parameter
 * @return a mutator specific structure or NULL on failure.  The returned value should
 * not be used for anything other than passing to the various Mutator API functions.
 */
HONGGFUZZ_MUTATOR_API void * FUNCNAME(create)(char * options, char * state, char * input, size_t input_length)
{
	honggfuzz_state_t * honggfuzz_state = setup_options(options);
	if (!honggfuzz_state)
		return NULL;

	honggfuzz_state->input = (char *)malloc(input_length);
	if (!honggfuzz_state->input || !input_length)
	{
		FUNCNAME(cleanup)(honggfuzz_state);
		return NULL;
	}
	memcpy(honggfuzz_state->input, input, input_length);
	honggfuzz_state->input_length = input_length;
	if (state && FUNCNAME(set_state)(honggfuzz_state, state)) {
		FUNCNAME(cleanup)(honggfuzz_state);
		return NULL;
	}
	return honggfuzz_state;
}

/**
 * This function clears out the dictionary related information inside a honggfuzz_state object
 * @param honggfuzz_state - a previously created honggfuzz specific state structure
 */
static void clear_dictionary(honggfuzz_state_t * honggfuzz_state)
{
	uint64_t i;
	for (i = 0; i < honggfuzz_state->dictionary_count; i++)
	{
		free(honggfuzz_state->dictq[i]->s);
		free(honggfuzz_state->dictq[i]);
	}
	free(honggfuzz_state->dictionary_file);
	free(honggfuzz_state->dictq);

	honggfuzz_state->dictq = NULL;
	honggfuzz_state->dictionary_count = 0;
	honggfuzz_state->dictionary_file = NULL;
}

/**
 * This function will release any resources that the mutator has open
 * and free the mutator state structure.
 * @param mutator_state - a mutator specific structure previously created by
 * the create function.  This structure will be freed and should not be referenced afterwards.
 */
HONGGFUZZ_MUTATOR_API void FUNCNAME(cleanup)(void * mutator_state)
{
	honggfuzz_state_t * honggfuzz_state = (honggfuzz_state_t *)mutator_state;
	clear_dictionary(honggfuzz_state);
	destroy_mutex(honggfuzz_state->mutate_mutex);
	free(honggfuzz_state->input);
	honggfuzz_state->input = NULL;
	free(honggfuzz_state);
}

/**
 * This function will mutate the input given in the create function and return it in the buffer argument.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param buffer - a buffer that the mutated input will be written to
 * @param buffer_length - the size of the passed in buffer argument
 * @return - the length of the mutated data, 0 when the mutator is out of mutations, or -1 on error
 */
HONGGFUZZ_MUTATOR_API int FUNCNAME(mutate)(void * mutator_state, char * buffer, size_t buffer_length)
{
	honggfuzz_state_t * honggfuzz_state = (honggfuzz_state_t *)mutator_state;
	//Can't mutate an empty buffer
	if (buffer_length == 0)
		return -1;

	//Setup the mutated buffer
	honggfuzz_state->mutated_buffer = (uint8_t *)buffer;
	honggfuzz_state->mutated_buffer_length = MIN(buffer_length, honggfuzz_state->input_length);
	memcpy(honggfuzz_state->mutated_buffer, honggfuzz_state->input, (size_t)honggfuzz_state->mutated_buffer_length);
	honggfuzz_state->max_mutated_buffer_length = buffer_length;

	//Now mutate the buffer
	honggfuzz_state->iteration++;
	mangle_mangleContent(honggfuzz_state);
	return (int)honggfuzz_state->mutated_buffer_length;
}

/**
 * This function will mutate the input given in the create function and return it in the buffer argument.
 * This function also accepts a set of flags which instruct it how to mutate the input.  See global_types.h
 * for the list of available flags.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param buffer - a buffer that the mutated input will be written to
 * @param buffer_length - the size of the passed in buffer argument.  It must be at least as large as
 * the original input buffer.
 * @param flags - A set of mutate flags that modify how this mutator mutates the input.
 * @return - the length of the mutated data, 0 when the mutator is out of mutations, or -1 on error
 */
HONGGFUZZ_MUTATOR_API int FUNCNAME(mutate_extended)(void * mutator_state, char * buffer, size_t buffer_length, uint64_t flags)
{
  SINGLE_INPUT_MUTATE_EXTENDED(honggfuzz_state_t, state->mutate_mutex);
}

/**
 * This function will return the state of the mutator.  The returned value can be used to restart the
 * mutator at a later time, by passing it to the create or set_state function.  It is the caller's
 * responsibility to free the memory allocated here by calling the free_state function.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @return - a buffer that defines the current state of the mutator.  This will be a mutator specific JSON string.
 */
HONGGFUZZ_MUTATOR_API char * FUNCNAME(get_state)(void * mutator_state)
{
	honggfuzz_state_t * honggfuzz_state = (honggfuzz_state_t *)mutator_state;
	json_t *obj, *temp, *dictionary_file, *dictionary_list, *dictionary_obj;
	uint64_t i;
	char * ret;

	obj = json_object();
	ADD_INT(temp, honggfuzz_state->iteration, obj, "iteration");
	ADD_UINT64T(temp, honggfuzz_state->random_state[0], obj, "random_state0");
	ADD_UINT64T(temp, honggfuzz_state->random_state[1], obj, "random_state1");
	if (honggfuzz_state->dictionary_file)
	{
		dictionary_file = json_string(honggfuzz_state->dictionary_file);
		if(!dictionary_file)
			return NULL;
		json_object_set_new(obj, "dictionary_file", dictionary_file);

		//Add the dictionary list to the json object
		dictionary_list = json_array();
		if (!dictionary_list)
			return NULL;
		for (i = 0; i < honggfuzz_state->dictionary_count; i++)
		{
			dictionary_obj = json_object();
			if (!dictionary_obj)
				return NULL;
			ADD_MEM(temp, honggfuzz_state->dictq[i]->s, honggfuzz_state->dictq[i]->len, dictionary_obj, "s");
			ADD_UINT64T(temp, honggfuzz_state->dictq[i]->len, dictionary_obj, "len");
			json_array_append_new(dictionary_list, dictionary_obj);
		}
		json_object_set_new(obj, "dictionary", dictionary_list);
	}

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
HONGGFUZZ_MUTATOR_API int FUNCNAME(set_state)(void * mutator_state, char * state)
{
	honggfuzz_state_t * honggfuzz_state = (honggfuzz_state_t *)mutator_state;
	int result, inner_result, temp_int;
	uint64_t temp_uint64t;
	char * temp_str;
	json_t * dictionary_obj;
	string_t * dictionary_item;

	if (!state)
		return 1;

	GET_INT(temp_int, state, honggfuzz_state->iteration, "iteration", result);
	GET_UINT64T(temp_uint64t, state, honggfuzz_state->random_state[0], "random_state0", result);
	GET_UINT64T(temp_uint64t, state, honggfuzz_state->random_state[1], "random_state1", result);

	clear_dictionary(honggfuzz_state);
	temp_str = get_string_options(state, "dictionary_file", &result);
	if (result > 0)
	{
		honggfuzz_state->dictionary_file = temp_str;
		FOREACH_OBJECT_JSON_ARRAY_ITEM_BEGIN(state, dictionary, "dictionary", dictionary_obj, result)

			//Create the new dictionary item
			dictionary_item = (string_t *)malloc(sizeof(string_t));
			GET_ITEM(dictionary_obj, dictionary_item->s, temp_str, get_mem_options_from_json, "s", inner_result);
			GET_ITEM(dictionary_obj, dictionary_item->len, temp_int, get_int_options_from_json, "len", inner_result);

			//Add the dictionary item to the dictionary linked list
			honggfuzz_state->dictq = (string_t **)realloc(honggfuzz_state->dictq, (honggfuzz_state->dictionary_count + 1) * sizeof(string_t));
			honggfuzz_state->dictq[honggfuzz_state->dictionary_count] = dictionary_item;
			honggfuzz_state->dictionary_count++;

		FOREACH_OBJECT_JSON_ARRAY_ITEM_END(dictionary);

		if (result < 0)
			return 1;
	}

	return 0;
}

/**
 * This function will return the current iteration count of the mutator, i.e.
 * how many mutations have been generated with it.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @return value - the number of previously generated mutations
 */
HONGGFUZZ_MUTATOR_API int FUNCNAME(get_current_iteration)(void * mutator_state)
{
	GENERIC_MUTATOR_GET_ITERATION(honggfuzz_state_t);
}

/**
 * Obtains information about the inputs that were given to the mutator when it was created
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param num_inputs - a pointer to an integer used to return the number of inputs given to this mutator
 * when it was created.  This parameter is optional and can be NULL, if this information is not needed
 * @param input_sizes - a pointer to a size_t array used to return the sizes of the inputs given to this
 * mutator when it was created. This parameter is optional and can be NULL, if this information is not needed.
 */
HONGGFUZZ_MUTATOR_API void FUNCNAME(get_input_info)(void * mutator_state, int * num_inputs, size_t **input_sizes)
{
	SINGLE_INPUT_GET_INFO(honggfuzz_state_t);
}

/**
 * This function will set the input(saved in the mutators state) to something new.
 * This can be used to reinitialize a mutator with new data, without reallocating the entire state struct.
 * @param mutator_state - a mutator specific structure previously created by the create function.
 * @param new_input - The new input used to produce new mutated inputs later when the mutate function is called
 * @param input_length - the size in bytes of the input buffer.
 * @return 0 on success and -1 on failure
 */
HONGGFUZZ_MUTATOR_API int FUNCNAME(set_input)(void * mutator_state, char * new_input, size_t input_length)
{
	GENERIC_MUTATOR_SET_INPUT(honggfuzz_state_t);
}

/**
 * This function sets a help message for the mutator.
 * @param help_str - A pointer that will be updated to point to the new help string.
 * @return 0 on success and -1 on failure
 */
HONGGFUZZ_MUTATOR_API int FUNCNAME(help)(char ** help_str)
{
	GENERIC_MUTATOR_HELP(
"honggfuzz - honggfuzz-based mutator\n"
"Options:\n"
"  dictionary_file       A file containing dictionary words to use while\n"
"                          mangling input\n"
"  mutations_per_run     The number of different mangle functions to apply per\n"
"                          single round of mutating the input\n"
"  random_state0         The first half of the seed to honggfuzz's random\n"
"                          number generator\n"
"  random_state1         The second half of the seed to honggfuzz's random\n"
"                          number generator\n"
"\n"
	);
}
