#pragma once
#include "driver.h"
#include <instrumentation.h>
#include <global_types.h>

DRIVER_API driver_t * driver_factory(char * driver_type, char * options);
DRIVER_API driver_t * driver_instrumentation_factory(char * driver_type, char * options, instrumentation_t * instrumentation,
	void * instrumentation_state);
DRIVER_API driver_t * driver_mutator_factory(char * driver_type, char * options, mutator_t * mutator, void * mutator_state);
DRIVER_API driver_t * driver_all_factory(char * driver_type, char * options, instrumentation_t * instrumentation, void * instrumentation_state,
	mutator_t * mutator, void * mutator_state);
DRIVER_API char * driver_help(void);
