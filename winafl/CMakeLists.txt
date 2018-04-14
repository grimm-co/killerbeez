cmake_minimum_required (VERSION 2.8.8)
project (winafl)
include_directories (${PROJECT_SOURCE_DIR}/)

# Generate the strings for the correct version of DynamoRIO
if( CMAKE_SIZEOF_VOID_P EQUAL 8 ) # 64-bit
	set(DYNAMORIO_LIB_FOLDER_NAME "lib64")
else( CMAKE_SIZEOF_VOID_P EQUAL 8 ) # 32-bit
	set(DYNAMORIO_LIB_FOLDER_NAME "lib32")
endif (CMAKE_SIZEOF_VOID_P EQUAL 8)

# Set debug/release version of DynamoRIO.  Pick release if not specified
if( "${CMAKE_CONFIGURATION_TYPES}" STREQUAL "" )
set(DYNAMORIO_FOLDER_NAME "release")
else( "${CMAKE_CONFIGURATION_TYPES}" STREQUAL "" )
string(TOLOWER "${CMAKE_CONFIGURATION_TYPES}" DYNAMORIO_FOLDER_NAME) # debug/release
endif( "${CMAKE_CONFIGURATION_TYPES}" STREQUAL "" )

# Find DynamoRIO
find_library(DYNAMORIO_LIBRARY dynamorio HINTS ${CMAKE_SOURCE_DIR}/../dynamorio/${DYNAMORIO_LIB_FOLDER_NAME}/${DYNAMORIO_FOLDER_NAME})
if(NOT DYNAMORIO_LIBRARY)
  message(FATAL_ERROR "Could not find DynamoRIO")
endif()
get_filename_component(DYNAMORIO_LIB_PATH ${DYNAMORIO_LIBRARY} DIRECTORY)

# Add DynamoRIO directories to the include and library paths
include_directories (
	${DYNAMORIO_LIB_PATH}/../../include/
	${DYNAMORIO_LIB_PATH}/../../ext/include/
)
link_directories(
	${DYNAMORIO_LIB_PATH}/
	${DYNAMORIO_LIB_PATH}/../
	${DYNAMORIO_LIB_PATH}/../../ext/${DYNAMORIO_LIB_FOLDER_NAME}/${DYNAMORIO_FOLDER_NAME}
)

# Make sure the winafl.dll gets put in the bin32/bin64 directory
if (CMAKE_SIZEOF_VOID_P EQUAL 8) # 64-bit
SET( WINAFL_DIR "bin64" )
else (CMAKE_SIZEOF_VOID_P EQUAL 8) # 32-bit
SET( WINAFL_DIR "bin32" )
endif (CMAKE_SIZEOF_VOID_P EQUAL 8)
SET( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${WINAFL_DIR}/ )
SET( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${WINAFL_DIR}/ )
SET( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/${WINAFL_DIR}/ )

# Include the instrumentation headers
include_directories (
	${PROJECT_SOURCE_DIR}/../instrumentation/
)

# Create the winafl project
SET(WINAFL_SRC
	${PROJECT_SOURCE_DIR}/modules.c
	${PROJECT_SOURCE_DIR}/winafl.c
)
source_group("Library Sources" FILES ${WINAFL_SRC})

add_library(winafl SHARED ${WINAFL_SRC})

if (WIN32)
	target_compile_definitions(winafl PUBLIC WINDOWS)
	set(LINK_FLAGS ${LINK_FLAGS} "/NODEFAULTLIB:library")
elseif (APPLE)
	target_compile_definitions(winafl PUBLIC MACOS)
else (WIN32)
	target_compile_definitions(winafl PUBLIC LINUX)
endif (WIN32)

if( CMAKE_SIZEOF_VOID_P EQUAL 8 ) # 64-bit
	target_compile_definitions(winafl PUBLIC X86_64)
else( CMAKE_SIZEOF_VOID_P EQUAL 8 ) # 32-bit
	target_compile_definitions(winafl PUBLIC X86_32)
endif (CMAKE_SIZEOF_VOID_P EQUAL 8)

target_link_libraries(winafl drx.lib)
target_link_libraries(winafl drcontainers.lib)
target_link_libraries(winafl drreg.lib)
target_link_libraries(winafl drwrap.lib)
target_link_libraries(winafl drsyms.lib)
target_link_libraries(winafl drmgr.lib)
target_link_libraries(winafl drcontainers.lib)
target_link_libraries(winafl ntdll_imports.lib)
target_link_libraries(winafl dynamorio.lib)
