cmake_minimum_required (VERSION 2.8.8)
project (zzuf_mutator)

include_directories (${PROJECT_SOURCE_DIR}/../mutators/)

set(ZZUF_SRC ${PROJECT_SOURCE_DIR}/zzuf_mutator.c)
source_group("Library Sources" FILES ${ZZUF_SRC})

add_library(zzuf_mutator SHARED ${ZZUF_SRC}
  $<TARGET_OBJECTS:mutators_object> $<TARGET_OBJECTS:jansson_object>)
target_link_libraries(zzuf_mutator utils)
target_compile_definitions(zzuf_mutator PUBLIC ZZUF_MUTATOR_EXPORTS)
target_compile_definitions(zzuf_mutator PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(zzuf_mutator PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(zzuf_mutator PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(zzuf_mutator Shlwapi)
endif (WIN32)
