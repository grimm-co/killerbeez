cmake_minimum_required (VERSION 2.8.8)
project (radamsa_mutator)

include_directories (${PROJECT_SOURCE_DIR}/../mutators/)

set(RADAMSA_SRC ${PROJECT_SOURCE_DIR}/radamsa_mutator.c)
source_group("Library Sources" FILES ${RADAMSA_SRC})

add_library(radamsa_mutator SHARED ${RADAMSA_SRC}
  $<TARGET_OBJECTS:mutators_object> $<TARGET_OBJECTS:jansson_object>)
target_link_libraries(radamsa_mutator utils)
target_compile_definitions(radamsa_mutator PUBLIC RADAMSA_MUTATOR_EXPORTS)
target_compile_definitions(radamsa_mutator PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(radamsa_mutator PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(radamsa_mutator PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(radamsa_mutator Shlwapi)
  target_link_libraries(radamsa_mutator ws2_32)
endif (WIN32)
