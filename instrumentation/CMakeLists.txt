cmake_minimum_required (VERSION 2.8.8)
project (instrumentation)

set(INSTRUMENTATION_SRC
	${PROJECT_SOURCE_DIR}/instrumentation.c
	${PROJECT_SOURCE_DIR}/instrumentation_factory.c
)

if (WIN32)
	set(INSTRUMENTATION_SRC
		${INSTRUMENTATION_SRC}
		${PROJECT_SOURCE_DIR}/debug_instrumentation.c
		${PROJECT_SOURCE_DIR}/dynamorio_instrumentation.c
	)
endif (WIN32)

source_group("Library Sources" FILES ${INSTRUMENTATION_SRC})

add_library(instrumentation OBJECT ${INSTRUMENTATION_SRC})
target_compile_definitions(instrumentation PUBLIC INSTRUMENTATION_NO_IMPORT)
