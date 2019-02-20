cmake_minimum_required (VERSION 2.8.8)
project (fuzzer)

include_directories (${CMAKE_SOURCE_DIR}/driver/)
include_directories (${CMAKE_SOURCE_DIR}/instrumentation/)
include_directories (${CMAKE_SOURCE_DIR}/mutator/)

set(FUZZER_SRC ${PROJECT_SOURCE_DIR}/main.c)
source_group("Executable Sources" FILES ${FUZZER_SRC})

add_executable(fuzzer ${FUZZER_SRC} $<TARGET_OBJECTS:driver>
	$<TARGET_OBJECTS:instrumentation>)

target_compile_definitions(fuzzer PUBLIC DRIVER_NO_IMPORT)
target_compile_definitions(fuzzer PUBLIC INSTRUMENTATION_NO_IMPORT)
target_compile_definitions(fuzzer PUBLIC MUTATOR_NO_IMPORT)

target_link_libraries(fuzzer)
target_link_libraries(fuzzer jansson)
if (WIN32)
  target_link_libraries(fuzzer Shlwapi)  # utils needs Shlwapi
  target_link_libraries(fuzzer ws2_32)   # network driver needs ws2_32
  target_link_libraries(fuzzer iphlpapi) # network driver needs iphlpapi
endif (WIN32)
