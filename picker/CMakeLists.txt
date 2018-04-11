cmake_minimum_required (VERSION 2.8.8)
project (picker)

include_directories (${CMAKE_SOURCE_DIR}/driver/)
include_directories (${CMAKE_SOURCE_DIR}/instrumentation/)

set(PICKER_SRC ${PROJECT_SOURCE_DIR}/main.c)
source_group("Executable Sources" FILES ${PICKER_SRC})
add_executable(picker ${PICKER_SRC} $<TARGET_OBJECTS:driver>
	$<TARGET_OBJECTS:instrumentation>)
target_compile_definitions(picker PUBLIC INSTRUMENTATION_NO_IMPORT)
target_compile_definitions(picker PUBLIC DRIVER_NO_IMPORT)

target_link_libraries(picker utils)
target_link_libraries(picker jansson)
if (WIN32)
  target_link_libraries(picker Shlwapi)  # utils needs Shlwapi
  target_link_libraries(picker ws2_32)   # driver needs ws2_32
  target_link_libraries(picker iphlpapi) # network driver needs iphlpapi
endif (WIN32)