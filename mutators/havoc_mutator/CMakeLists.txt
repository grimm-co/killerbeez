cmake_minimum_required (VERSION 2.8.8)
project (havoc_mutator)

include_directories (${PROJECT_SOURCE_DIR}/../mutators/)

set(HAVOC_SRC ${PROJECT_SOURCE_DIR}/havoc_mutator.c)
source_group("Library Sources" FILES ${HAVOC_SRC})

add_library(havoc_mutator SHARED ${HAVOC_SRC}
  $<TARGET_OBJECTS:mutators_object> $<TARGET_OBJECTS:jansson_object>)
target_link_libraries(havoc_mutator utils)
target_compile_definitions(havoc_mutator PUBLIC HAVOC_MUTATOR_EXPORTS)
target_compile_definitions(havoc_mutator PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(havoc_mutator PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(havoc_mutator PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(havoc_mutator Shlwapi)
endif (WIN32)
