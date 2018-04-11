cmake_minimum_required (VERSION 2.8.8)
project (merger)

include_directories (${CMAKE_SOURCE_DIR}/instrumentation/)

set(MERGER_SRC ${PROJECT_SOURCE_DIR}/merger.c)
source_group("Executable Sources" FILES ${MERGER_SRC})
add_executable(merger ${MERGER_SRC} $<TARGET_OBJECTS:instrumentation>)
target_compile_definitions(merger PUBLIC INSTRUMENTATION_NO_IMPORT)

target_link_libraries(merger utils)
target_link_libraries(merger jansson)
if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(merger Shlwapi)
endif (WIN32)
