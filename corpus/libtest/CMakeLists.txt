cmake_minimum_required (VERSION 2.8.8)
project (libtest)

add_executable(libtest      ${PROJECT_SOURCE_DIR}/test.c)
add_executable(libtest_pie  ${PROJECT_SOURCE_DIR}/test.c)
add_library(lib1test SHARED ${PROJECT_SOURCE_DIR}/lib1.c)
add_library(lib2test SHARED ${PROJECT_SOURCE_DIR}/lib2.c)

set_target_properties(libtest PROPERTIES LINK_FLAGS "-no-pie")

target_link_libraries(libtest     lib1test lib2test)
target_link_libraries(libtest_pie lib1test lib2test)
