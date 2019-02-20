cmake_minimum_required (VERSION 2.8.8)
project (jansson)

include_directories (${PROJECT_SOURCE_DIR}/)
SET(JANSSON_SRC
	${PROJECT_SOURCE_DIR}/dump.c
	${PROJECT_SOURCE_DIR}/error.c
	${PROJECT_SOURCE_DIR}/hashtable.c
	${PROJECT_SOURCE_DIR}/hashtable_seed.c
	${PROJECT_SOURCE_DIR}/jansson_helper.c
	${PROJECT_SOURCE_DIR}/load.c
	${PROJECT_SOURCE_DIR}/memory.c
	${PROJECT_SOURCE_DIR}/pack_unpack.c
	${PROJECT_SOURCE_DIR}/strbuffer.c
	${PROJECT_SOURCE_DIR}/strconv.c
	${PROJECT_SOURCE_DIR}/utf.c
	${PROJECT_SOURCE_DIR}/value.c
)
source_group("Library Sources" FILES ${JANSSON_SRC})

add_library(jansson SHARED ${JANSSON_SRC})
target_compile_definitions(jansson PUBLIC JANSSON_EXPORTS)

add_library(jansson_object OBJECT ${JANSSON_SRC})
if (NOT WIN32)
  set_target_properties(jansson_object PROPERTIES COMPILE_FLAGS "-fPIC")
endif (NOT WIN32)
target_compile_definitions(jansson_object PUBLIC JANSSON_NO_IMPORT)

add_library(jansson_static STATIC ${JANSSON_SRC})
target_compile_definitions(jansson_static PUBLIC JANSSON_NO_IMPORT)
