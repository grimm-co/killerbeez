cmake_minimum_required (VERSION 2.8.8)
project (mutators)

set(MUTATORS_SRC
	${PROJECT_SOURCE_DIR}/mutators.c
	${PROJECT_SOURCE_DIR}/afl_helpers.c
)
source_group("Library Sources" FILES ${MUTATORS_SRC})

add_library(mutators SHARED ${MUTATORS_SRC} $<TARGET_OBJECTS:jansson_object>)
target_compile_definitions(mutators PUBLIC MUTATORS_EXPORTS)
target_compile_definitions(mutators PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(mutators PUBLIC JANSSON_NO_IMPORT)
if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(mutators Shlwapi)
endif (WIN32)

add_library(mutators_object OBJECT ${MUTATORS_SRC})
if (NOT WIN32)
  set_target_properties(mutators_object PROPERTIES COMPILE_FLAGS "-fPIC")
endif (NOT WIN32)
target_compile_definitions(mutators_object PUBLIC MUTATORS_NO_IMPORT)
target_compile_definitions(mutators_object PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(mutators_object PUBLIC JANSSON_NO_IMPORT)

add_library(mutators_static STATIC ${MUTATORS_SRC})
target_compile_definitions(mutators_static PUBLIC MUTATORS_NO_IMPORT)
target_link_libraries(mutators_static utils_static)
target_link_libraries(mutators_static jansson_static)
