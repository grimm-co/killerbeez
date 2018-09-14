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
else ()
	set(INSTRUMENTATION_SRC
		${INSTRUMENTATION_SRC}
		${PROJECT_SOURCE_DIR}/return_code_instrumentation.c
	)

	if (NOT APPLE)
		set(INSTRUMENTATION_SRC
			${INSTRUMENTATION_SRC}
			${PROJECT_SOURCE_DIR}/linux_ipt_instrumentation.c
		)

		set(FORKSERVER_SRC
			${PROJECT_SOURCE_DIR}/forkserver.c
			${PROJECT_SOURCE_DIR}/forkserver_hooking.c
		)

		add_library(forkserver SHARED ${FORKSERVER_SRC})
		target_link_libraries(forkserver dl)
	endif ()
endif ()

source_group("Library Sources" FILES ${INSTRUMENTATION_SRC})

add_library(instrumentation OBJECT ${INSTRUMENTATION_SRC})
target_compile_definitions(instrumentation PUBLIC INSTRUMENTATION_NO_IMPORT)
