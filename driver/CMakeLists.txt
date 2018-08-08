cmake_minimum_required (VERSION 2.8.8)
project (driver)

SET(DRIVER_SRC
	${PROJECT_SOURCE_DIR}/driver.c
	${PROJECT_SOURCE_DIR}/driver_factory.c
	${PROJECT_SOURCE_DIR}/file_driver.c
	${PROJECT_SOURCE_DIR}/stdin_driver.c
	${PROJECT_SOURCE_DIR}/network_server_driver.c
	${PROJECT_SOURCE_DIR}/network_client_driver.c
)

if (WIN32)
	set(DRIVER_SRC
		${DRIVER_SRC}
		${PROJECT_SOURCE_DIR}/wmp_driver.cpp
	)
endif(WIN32)

source_group("Library Sources" FILES ${DRIVER_SRC})

add_library(driver OBJECT ${DRIVER_SRC})
target_compile_definitions(driver PUBLIC DRIVER_NO_IMPORT)
target_include_directories(driver PUBLIC ${PROJECT_SOURCE_DIR}/../instrumentation/)

