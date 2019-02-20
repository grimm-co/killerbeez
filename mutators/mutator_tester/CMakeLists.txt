cmake_minimum_required (VERSION 2.8.8)
project (mutator_tester)

set(MUTATOR_TESTER_SRC ${PROJECT_SOURCE_DIR}/mutator_tester.c)
source_group("Executable Sources" FILES ${MUTATOR_TESTER_SRC})
add_executable(mutator_tester ${MUTATOR_TESTER_SRC} $<TARGET_OBJECTS:jansson_object>)
target_compile_definitions(mutator_tester PUBLIC UTILS_NO_IMPORT)
target_compile_definitions(mutator_tester PUBLIC JANSSON_NO_IMPORT)

if (WIN32) # utils.dll needs Shlwapi
  target_link_libraries(mutator_tester Shlwapi)
else (WIN32)
  target_link_libraries(mutator_tester dl)
  target_link_libraries(mutator_tester pthread)
endif (WIN32)
