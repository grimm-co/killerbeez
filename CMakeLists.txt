cmake_minimum_required (VERSION 2.8.8)
project (killerbeez)

SET ( BUILD_DIRECTORY ${CMAKE_SOURCE_DIR}/../build )

if (WIN32)
	# windows/visual studio build convention eg build/X86/Debug
	SET( WINDOWS_BUILD_PATH ${BUILD_DIRECTORY}/${CMAKE_C_COMPILER_ARCHITECTURE_ID}/${CMAKE_BUILD_TYPE} )
	SET( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${WINDOWS_BUILD_PATH}/killerbeez/ )
	SET( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${WINDOWS_BUILD_PATH}/killerbeez/ )
	SET( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${WINDOWS_BUILD_PATH}/killerbeez/ )
	LINK_DIRECTORIES(${WINDOWS_BUILD_PATH}/killerbeez/) # give linker path to utils
	add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_DEPRECATION_DISABLE -D_CRT_NONSTDC_NO_DEPRECATE)
else (WIN32)
	SET( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIRECTORY}/killerbeez/ )
	SET( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${BUILD_DIRECTORY}/killerbeez/ )
	SET( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${BUILD_DIRECTORY}/killerbeez/ )
	LINK_DIRECTORIES(${BUILD_DIRECTORY}/killerbeez/) # give linker path to utils
endif (WIN32)

# add headers for utils from utils source folder/repo
include_directories (${CMAKE_SOURCE_DIR}/../killerbeez-utils/jansson/)
include_directories (${CMAKE_SOURCE_DIR}/../killerbeez-utils/utils/)

add_subdirectory(${CMAKE_SOURCE_DIR}/../killerbeez-mutators/ ${CMAKE_BINARY_DIR}/../killerbeez-mutators/)

add_subdirectory(driver)
add_subdirectory(fuzzer)
add_subdirectory(instrumentation)
add_subdirectory(merger)
add_subdirectory(picker)
add_subdirectory(tracer)
add_subdirectory(winafl)
