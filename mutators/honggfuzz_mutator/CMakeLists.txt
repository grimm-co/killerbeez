cmake_minimum_required (VERSION 2.8.8)
project (honggfuzz_mutator)

include_directories (${PROJECT_SOURCE_DIR}/../mutators/)

set(HONGGFUZZ_SRC ${PROJECT_SOURCE_DIR}/honggfuzz_mutator.c)
source_group("Library Sources" FILES ${HONGGFUZZ_SRC})

add_library(honggfuzz_mutator SHARED ${HONGGFUZZ_SRC}
  $<TARGET_OBJECTS:mutators_object> $<TARGET_OBJECTS:jansson_object>)
target_compile_definitions(honggfuzz_mutator PUBLIC HONGGFUZZ_MUTATOR_EXPORTS)
target_compile_definitions(honggfuzz_mutator PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(honggfuzz_mutator PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(honggfuzz_mutator PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(honggfuzz_mutator Shlwapi)
endif (WIN32)
