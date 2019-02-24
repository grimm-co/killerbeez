cmake_minimum_required (VERSION 2.8.8)
project (bit_flip_mutator)

include_directories (${PROJECT_SOURCE_DIR}/../mutators/)

set(BIT_FLIP_SRC ${PROJECT_SOURCE_DIR}/bit_flip_mutator.c)
source_group("Library Sources" FILES ${BIT_FLIP_SRC})

add_library(bit_flip_mutator SHARED ${BIT_FLIP_SRC}
  $<TARGET_OBJECTS:mutators_object> $<TARGET_OBJECTS:jansson_object>)
target_link_libraries(bit_flip_mutator utils)
target_compile_definitions(bit_flip_mutator PUBLIC BF_MUTATOR_EXPORTS)
target_compile_definitions(bit_flip_mutator PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(bit_flip_mutator PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(bit_flip_mutator PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(bit_flip_mutator Shlwapi)
endif (WIN32)
