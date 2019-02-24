cmake_minimum_required (VERSION 2.8.8)
project (splice_mutator)

include_directories (${PROJECT_SOURCE_DIR}/../mutators/)

set(SPLICE_SRC ${PROJECT_SOURCE_DIR}/splice_mutator.c)
source_group("Library Sources" FILES ${SPLICE_SRC})

add_library(splice_mutator SHARED ${SPLICE_SRC}
  $<TARGET_OBJECTS:mutators_object> $<TARGET_OBJECTS:jansson_object>)
target_link_libraries(splice_mutator utils)
target_compile_definitions(splice_mutator PUBLIC SPLICE_MUTATOR_EXPORTS)
target_compile_definitions(splice_mutator PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(splice_mutator PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(splice_mutator PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(splice_mutator Shlwapi)
endif (WIN32)
