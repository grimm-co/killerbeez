cmake_minimum_required (VERSION 2.8.8)
project (driver)

include_directories (${PROJECT_SOURCE_DIR}/)
include_directories (${CMAKE_SOURCE_DIR}/instrumentation/)

SET(DRIVER_SRC
	${PROJECT_SOURCE_DIR}/driver.c
	${PROJECT_SOURCE_DIR}/driver_factory.c
	${PROJECT_SOURCE_DIR}/file_driver.c
	${PROJECT_SOURCE_DIR}/network_driver.c
	${PROJECT_SOURCE_DIR}/stdin_driver.c
	${PROJECT_SOURCE_DIR}/wmp_driver.cpp
	${PROJECT_SOURCE_DIR}/putty_driver.c
)
source_group("Library Sources" FILES ${DRIVER_SRC})

add_library(driver OBJECT ${DRIVER_SRC})
target_compile_definitions(driver PUBLIC DRIVER_NO_IMPORT)
