cmake_minimum_required (VERSION 2.8.8)
project (ni_mutator)

include_directories (${PROJECT_SOURCE_DIR}/../mutators/)

set(NI_SRC ${PROJECT_SOURCE_DIR}/ni_mutator.c)
source_group("Library Sources" FILES ${NI_SRC})

add_library(ni_mutator SHARED ${NI_SRC}
  $<TARGET_OBJECTS:mutators_object> $<TARGET_OBJECTS:jansson_object>)
target_link_libraries(ni_mutator utils)
target_compile_definitions(ni_mutator PUBLIC NI_MUTATOR_EXPORTS)
target_compile_definitions(ni_mutator PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(ni_mutator PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(ni_mutator PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(ni_mutator Shlwapi)
endif (WIN32)
