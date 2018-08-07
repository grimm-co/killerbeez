cmake_minimum_required (VERSION 2.8.8)
project (killerbeez)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -D_DEBUG")	# for _DEBUG ifdefs in utils.h

if (UNIX)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wfatal-errors") # quit after first error
endif (UNIX)

if (APPLE)
	set(CMAKE_MACOSX_RPATH 1) # https://github.com/liballeg/allegro5/issues/532#issuecomment-170338164
endif (APPLE)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Debug) 	# for gcc -g
	message("WARNING: Building with debug options; performance will be impacted. Try cmake -DCMAKE_BUILD_TYPE=Release ../killerbeez")
endif()

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

# compile mutators, which will compile utils
add_subdirectory(${CMAKE_SOURCE_DIR}/../killerbeez-mutators/ ${CMAKE_BINARY_DIR}/killerbeez-mutators/)

add_subdirectory(corpus) # test programs
add_subdirectory(fuzzer) # instantiates & coordinates other parts
add_subdirectory(driver) # starts program, feeds input, determines when program is done
add_subdirectory(instrumentation) # inserts instructions to program to tell whether an input makes the binary take a new path

if (WIN32)
add_subdirectory(merger) # merges instrumentation data between fuzzer nodes
add_subdirectory(picker) # picks which libraries of a target program are being used, and worth fuzzing
add_subdirectory(tracer) # runs through program and records basic block edges
add_subdirectory(winafl) # parts ripped from winafl for dynamorio
endif (WIN32)
