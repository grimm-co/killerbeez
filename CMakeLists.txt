cmake_minimum_required (VERSION 2.8.8)
project (killerbeez)
include(ExternalProject)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -D_DEBUG")	# for _DEBUG ifdefs in utils.h
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (UNIX)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wfatal-errors") # quit after first error
endif (UNIX)

if (APPLE)
	set(CMAKE_MACOSX_RPATH 1) # https://github.com/liballeg/allegro5/issues/532#issuecomment-170338164
endif (APPLE)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Debug) 	# for gcc -g
	message("WARNING: Building with debug options; performance will be impacted. Try cmake -DCMAKE_BUILD_TYPE=Release ..")
endif()


if (WIN32)
	# windows/visual studio build convention eg build/X86/Debug
	SET ( BUILD_DIRECTORY ${CMAKE_SOURCE_DIR}/build/${CMAKE_C_COMPILER_ARCHITECTURE_ID}/${CMAKE_BUILD_TYPE} )
	add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_DEPRECATION_DISABLE -D_CRT_NONSTDC_NO_DEPRECATE)
else (WIN32)
	SET ( BUILD_DIRECTORY ${CMAKE_BINARY_DIR} )
endif (WIN32)

SET( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${BUILD_DIRECTORY}/killerbeez/ )
SET( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${BUILD_DIRECTORY}/killerbeez/ )
SET( CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${BUILD_DIRECTORY}/killerbeez/ )

# Make linux builds relocatable
SET(CMAKE_BUILD_WITH_INSTALL_RPATH 1)
SET(CMAKE_INSTALL_RPATH "$ORIGIN")

# add headers for utils from utils source folder/repo
include_directories (jansson/)
include_directories (utils/)

# IWYU. Pass -DNO_IWYU=1 to disable, -DNO_IWYU= to re-enable (or regenerate cache)
if (UNIX AND NOT NO_IWYU)
	find_program(iwyu_path NAMES include-what-you-use iwyu)
	if(NOT iwyu_path)
		# can be installed with sudo apt install iwyu -y
		message(STATUS "Could not find include-what-you-use, continuing without it")
	else()
		message(STATUS "Found include-what-you-use, displaying its suggestions")
		set(CMAKE_C_INCLUDE_WHAT_YOU_USE ${iwyu_path})
		set(CMAKE_CXX_INCLUDE_WHAT_YOU_USE ${iwyu_path})
	endif()
else()
	message(STATUS "include-what-you-use disabled")
endif()

add_subdirectory(jansson/)

# The general mutator library with the common functionality
add_subdirectory(mutators)

add_subdirectory(corpus) # test programs
add_subdirectory(fuzzer) # instantiates & coordinates other parts
add_subdirectory(driver) # starts program, feeds input, determines when program is done
add_subdirectory(instrumentation) # inserts instructions to program to tell whether an input makes the binary take a new path
add_subdirectory(merger) # merges instrumentation data between fuzzer nodes
add_subdirectory(tracer) # runs through program and records basic block edges

if (WIN32)
add_subdirectory(picker) # picks which libraries of a target program are being used, and worth fuzzing
add_subdirectory(winafl) # parts ripped from winafl for dynamorio
endif (WIN32)

### RELEASE ZIP CONFIG ###
# Choose what to install into the release zip
install(DIRECTORY ${BUILD_DIRECTORY}/killerbeez DESTINATION . USE_SOURCE_PERMISSIONS)
install(DIRECTORY ${BUILD_DIRECTORY}/mutators DESTINATION . USE_SOURCE_PERMISSIONS)

### BOINC wrapper ###
# If on Windows, include prebuilt BOINC wrapper
if (WIN32)
  SET(BOINC_WRAPPER C:/killerbeez/wrapper_26014_windows_x86_64.exe)
endif ()
# If on Linux, we can build our own BOINC wrapper
if (UNIX AND (NOT APPLE))
  SET(BOINC_WRAPPER ${CMAKE_SOURCE_DIR}/server/boinc/samples/wrapper/wrapper)
  ExternalProject_Add(boinc-wrapper
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/server/boinc
    DOWNLOAD_COMMAND cd <SOURCE_DIR> && git submodule update --init .
    BUILD_IN_SOURCE true
    CONFIGURE_COMMAND ./_autosetup
    COMMAND ./configure --disable-server --disable-client --disable-manager --enable-boinczip
    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
    COMMAND ${CMAKE_MAKE_PROGRAM} -C samples/wrapper
    INSTALL_COMMAND ""
  )
endif ()
install(PROGRAMS ${BOINC_WRAPPER} DESTINATION server/skel)

### radamsa ###
set(RADAMSA_URL https://gitlab.com/akihe/radamsa.git)
ExternalProject_Add(radamsa
  GIT_REPOSITORY ${RADAMSA_URL}
  BUILD_IN_SOURCE true
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
  INSTALL_COMMAND ""
  EXCLUDE_FROM_ALL true
)
ExternalProject_Get_Property(radamsa SOURCE_DIR)
install(DIRECTORY ${SOURCE_DIR}/bin DESTINATION radamsa USE_SOURCE_PERMISSIONS)
install(FILES ${SOURCE_DIR}/LICENCE DESTINATION radamsa)

# Set up CPack to generate the release zip
SET(CPACK_GENERATOR "ZIP")
# TODO: might want some kind of versioning or architecture in this name
SET(CPACK_PACKAGE_FILE_NAME "killerbeez-${CMAKE_SYSTEM_NAME}")
SET(CPACK_SOURCE_GENERATOR "ZIP")
SET(CPACK_SOURCE_IGNORE_FILES "/build/;/server/boinc/")
SET(CPACK_SOURCE_INSTALLED_DIRECTORIES "${CMAKE_SOURCE_DIR};killerbeez")
include (CPack)

# Special `release` target to ensure boinc-wrapper is built before package
add_custom_target(release
  ${CMAKE_MAKE_PROGRAM} package)
if (UNIX)
  if (APPLE)
    # macOS can't build the boinc wrapper right now, maybe we can patch
    # things up in the future to make this possible, but for now we're
    # just not building it.
    add_dependencies(release radamsa)
  else ()
    add_dependencies(release radamsa boinc-wrapper)
  endif ()
endif ()
