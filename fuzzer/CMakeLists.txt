cmake_minimum_required (VERSION 2.8.8)
project (fuzzer)

include_directories (${CMAKE_SOURCE_DIR}/driver/)
include_directories (${CMAKE_SOURCE_DIR}/instrumentation/)
include_directories (${CMAKE_SOURCE_DIR}/mutator/)
include_directories (${CMAKE_SOURCE_DIR}/utils/)

add_library(utils ${CMAKE_SOURCE_DIR}/utils/utils.c ${CMAKE_SOURCE_DIR}/utils/mutator_factory.c)
# Utils requires -ldl (on UNIX) and -lpthread
if (UNIX)
  target_link_libraries(utils dl)
endif (UNIX)
find_package(Threads REQUIRED)
if(THREADS_HAVE_PTHREAD_ARG)
  set_property(TARGET utils PROPERTY COMPILE_OPTIONS "-pthread")
  set_property(TARGET utils PROPERTY INTERFACE_COMPILE_OPTIONS "-pthread")
endif()
if(CMAKE_THREAD_LIBS_INIT)
  target_link_libraries(utils "${CMAKE_THREAD_LIBS_INIT}")
endif()

set(FUZZER_SRC ${PROJECT_SOURCE_DIR}/main.c)
source_group("Executable Sources" FILES ${FUZZER_SRC})

add_executable(fuzzer ${FUZZER_SRC} $<TARGET_OBJECTS:driver>
	$<TARGET_OBJECTS:instrumentation>)

target_compile_definitions(fuzzer PUBLIC DRIVER_NO_IMPORT)
target_compile_definitions(fuzzer PUBLIC INSTRUMENTATION_NO_IMPORT)
target_compile_definitions(fuzzer PUBLIC MUTATOR_NO_IMPORT)

if (UNIX)
  target_link_libraries(fuzzer dl)
endif (UNIX)
target_link_libraries(fuzzer utils)
target_link_libraries(fuzzer jansson)
if (WIN32)
  target_link_libraries(fuzzer Shlwapi)  # utils needs Shlwapi
  target_link_libraries(fuzzer ws2_32)   # network driver needs ws2_32
  target_link_libraries(fuzzer iphlpapi) # network driver needs iphlpapi
endif (WIN32)
