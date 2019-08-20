cmake_minimum_required (VERSION 2.8.8)
project (dictionary_mutator)

include_directories (${PROJECT_SOURCE_DIR}/../mutators/)

set(DICTIONARY_SRC ${PROJECT_SOURCE_DIR}/dictionary_mutator.c)
source_group("Library Sources" FILES ${DICTIONARY_SRC})

add_library(dictionary_mutator SHARED ${DICTIONARY_SRC}
  $<TARGET_OBJECTS:mutators_object> $<TARGET_OBJECTS:jansson_object>)
target_link_libraries(dictionary_mutator utils)
target_compile_definitions(dictionary_mutator PUBLIC DICTIONARY_MUTATOR_EXPORTS)
target_compile_definitions(dictionary_mutator PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(dictionary_mutator PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(dictionary_mutator PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(dictionary_mutator Shlwapi)
endif (WIN32)
