cmake_minimum_required (VERSION 2.8.8)
project (arithmetic_mutator)

include_directories (${PROJECT_SOURCE_DIR}/../mutators/)

set(ARITHMETIC_SRC ${PROJECT_SOURCE_DIR}/arithmetic_mutator.c)
source_group("Library Sources" FILES ${ARITHMETIC_SRC})

add_library(arithmetic_mutator SHARED ${ARITHMETIC_SRC}
  $<TARGET_OBJECTS:mutators_object> $<TARGET_OBJECTS:jansson_object>)
target_compile_definitions(arithmetic_mutator PUBLIC ARITHMETIC_MUTATOR_EXPORTS)
target_compile_definitions(arithmetic_mutator PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(arithmetic_mutator PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(arithmetic_mutator PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(arithmetic_mutator Shlwapi)
endif (WIN32)
