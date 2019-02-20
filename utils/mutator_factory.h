#pragma once
#include <global_types.h>
#include <utils.h>

UTILS_API mutator_t * mutator_factory(char * mutator_filename);
UTILS_API mutator_t * mutator_factory_directory(char * mutator_directory, char * mutator_type);
UTILS_API char * mutator_help(char * mutator_directory);
