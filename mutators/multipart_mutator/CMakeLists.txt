cmake_minimum_required (VERSION 2.8.8)
project (multipart_mutator)

include_directories (${PROJECT_SOURCE_DIR}/../mutators/)

set(MULTIPART_SRC ${PROJECT_SOURCE_DIR}/multipart_mutator.c)
source_group("Library Sources" FILES ${MULTIPART_SRC})

add_library(multipart_mutator SHARED ${MULTIPART_SRC}
  $<TARGET_OBJECTS:mutators_object> $<TARGET_OBJECTS:jansson_object>)
target_compile_definitions(multipart_mutator PUBLIC MULTIPART_MUTATOR_EXPORTS)
target_compile_definitions(multipart_mutator PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(multipart_mutator PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(multipart_mutator PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(multipart_mutator Shlwapi)
endif (WIN32)
