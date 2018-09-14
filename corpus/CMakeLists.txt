cmake_minimum_required (VERSION 2.8.8)
project (corpus)

# All of the Windows test programs have precompiled versions, as the DynamoRIO
# instrumentation needs exact offsets into the program to know where to hook.
# As such, we've included precompiled versions with and listed the offsets,
# rather than having the user compile them.
if (UNIX)
	SET( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIRECTORY}/killerbeez/corpus/ )
	SET( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${BUILD_DIRECTORY}/killerbeez/corpus/ )
	SET( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${BUILD_DIRECTORY}/killerbeez/corpus/ )

	if (NOT APPLE)
		add_subdirectory(persist)
	endif (NOT APPLE)
	add_subdirectory(hang)
	add_subdirectory(libtest)
	add_subdirectory(test)
	add_subdirectory(network)

endif ()
