cmake_minimum_required (VERSION 2.8.8)
project (persist)

set(PERSIST_SRC ${PROJECT_SOURCE_DIR}/test.c)

add_executable(nopersist       ${PERSIST_SRC})
add_executable(persist         ${PERSIST_SRC})
add_executable(persist_hang    ${PERSIST_SRC})
add_executable(deferred        ${PERSIST_SRC})
add_executable(deferred_nohook ${PERSIST_SRC})

target_compile_definitions(persist         PUBLIC PERSIST)
target_compile_definitions(persist_hang    PUBLIC PERSIST PUBLIC HANG)
target_compile_definitions(deferred        PUBLIC SLOW_STARTUP)
target_compile_definitions(deferred_nohook PUBLIC SLOW_STARTUP PUBLIC DEFERRED_NOHOOK)

target_link_libraries(persist         forkserver)
target_link_libraries(persist_hang    forkserver)
target_link_libraries(deferred        forkserver)
target_link_libraries(deferred_nohook forkserver)

include_directories(${PROJECT_SOURCE_DIR}/../../instrumentation/)
