cmake_minimum_required (VERSION 2.8.8)
project (afl_mutator)

include_directories (${PROJECT_SOURCE_DIR}/../mutators/)

set(AFL_SRC ${PROJECT_SOURCE_DIR}/afl_mutator.c)
source_group("Library Sources" FILES ${AFL_SRC})

add_library(afl_mutator SHARED ${AFL_SRC}
  $<TARGET_OBJECTS:mutators_object> $<TARGET_OBJECTS:jansson_object>)
target_compile_definitions(afl_mutator PUBLIC AFL_MUTATOR_EXPORTS)
target_compile_definitions(afl_mutator PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(afl_mutator PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(afl_mutator PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(afl_mutator Shlwapi)
endif (WIN32)
