cmake_minimum_required (VERSION 2.8.8)
project (interesting_value_mutator)

include_directories (${PROJECT_SOURCE_DIR}/../mutators/)

set(INTERESTING_VALUE_SRC ${PROJECT_SOURCE_DIR}/interesting_value_mutator.c)
source_group("Library Sources" FILES ${INTERESTING_VALUE_SRC})

add_library(interesting_value_mutator SHARED ${INTERESTING_VALUE_SRC}
  $<TARGET_OBJECTS:mutators_object> $<TARGET_OBJECTS:jansson_object>)
target_link_libraries(interesting_value_mutator utils)
target_compile_definitions(interesting_value_mutator PUBLIC INTERESTING_VALUE_MUTATOR_EXPORTS)
target_compile_definitions(interesting_value_mutator PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(interesting_value_mutator PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(interesting_value_mutator PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(interesting_value_mutator Shlwapi)
endif (WIN32)
