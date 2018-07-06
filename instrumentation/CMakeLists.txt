cmake_minimum_required (VERSION 2.8.8)
project (instrumentation)

set(INSTRUMENTATION_SRC
	${PROJECT_SOURCE_DIR}/dynamorio_instrumentation.c
	${PROJECT_SOURCE_DIR}/instrumentation.c
	${PROJECT_SOURCE_DIR}/instrumentation_factory.c
	${PROJECT_SOURCE_DIR}/none_instrumentation.c
)
source_group("Library Sources" FILES ${INSTRUMENTATION_SRC})

add_library(instrumentation OBJECT ${INSTRUMENTATION_SRC})
target_compile_definitions(instrumentation PUBLIC INSTRUMENTATION_NO_IMPORT)
