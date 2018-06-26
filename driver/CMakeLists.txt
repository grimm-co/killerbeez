cmake_minimum_required (VERSION 2.8.8)
project (driver)

include_directories (${CMAKE_SOURCE_DIR}/instrumentation/)

SET(DRIVER_SRC
    ${PROJECT_SOURCE_DIR}/driver.c
    ${PROJECT_SOURCE_DIR}/driver_factory.c
    ${PROJECT_SOURCE_DIR}/file_driver.c
)

if (WIN32) # TODO: this should be removed when the others are implemented in linux
    list(APPEND DRIVER_SRC
        ${PROJECT_SOURCE_DIR}/network_driver.c
        ${PROJECT_SOURCE_DIR}/stdin_driver.c
        ${PROJECT_SOURCE_DIR}/wmp_driver.cpp
    )
endif(WIN32)

source_group("Library Sources" FILES ${DRIVER_SRC})

add_library(driver OBJECT ${DRIVER_SRC})
target_compile_definitions(driver PUBLIC DRIVER_NO_IMPORT)
