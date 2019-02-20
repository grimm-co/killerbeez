cmake_minimum_required (VERSION 2.8.8)
project (nop_mutator)

include_directories (${PROJECT_SOURCE_DIR}/../mutators/)

set(NOP_SRC ${PROJECT_SOURCE_DIR}/nop_mutator.c)
source_group("Library Sources" FILES ${NOP_SRC})

add_library(nop_mutator SHARED ${NOP_SRC}
  $<TARGET_OBJECTS:mutators_object> $<TARGET_OBJECTS:jansson_object>)
target_compile_definitions(nop_mutator PUBLIC NOP_MUTATOR_EXPORTS)
target_compile_definitions(nop_mutator PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(nop_mutator PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(nop_mutator PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(nop_mutator Shlwapi)
endif (WIN32)
