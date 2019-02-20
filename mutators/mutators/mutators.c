#include "mutators.h"

#include <stdint.h>
#include <stdlib.h>

MUTATORS_API void default_free_state(char * state)
{
	free(state);
}

MUTATORS_API int return_unknown_or_infinite_total_iterations(void * mutator_state)
{
	return -1; //infinite
}
