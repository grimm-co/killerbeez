#pragma once

#include "instrumentation.h"

INSTRUMENTATION_API instrumentation_t * instrumentation_factory(char * instrumentation_type);
INSTRUMENTATION_API char * instrumentation_help(void);