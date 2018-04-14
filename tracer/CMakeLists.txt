cmake_minimum_required (VERSION 2.8.8)
project (tracer)

include_directories (${CMAKE_SOURCE_DIR}/driver/)
include_directories (${CMAKE_SOURCE_DIR}/instrumentation/)

set(TRACER_SRC ${PROJECT_SOURCE_DIR}/main.c)
source_group("Executable Sources" FILES ${TRACER_SRC})
add_executable(tracer ${TRACER_SRC} $<TARGET_OBJECTS:driver>
	$<TARGET_OBJECTS:instrumentation>)
target_compile_definitions(tracer PUBLIC INSTRUMENTATION_NO_IMPORT)
target_compile_definitions(tracer PUBLIC DRIVER_NO_IMPORT)

target_link_libraries(tracer utils)
target_link_libraries(tracer jansson)
if (WIN32)
  target_link_libraries(tracer Shlwapi)  # utils needs Shlwapi
  target_link_libraries(tracer ws2_32)   # driver needs ws2_32
  target_link_libraries(tracer iphlpapi) # network driver needs iphlpapi
endif (WIN32)
