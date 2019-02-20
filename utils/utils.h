#pragma once

#ifdef _WIN32
#include <Windows.h>
#else
#include <pthread.h>
#include <semaphore.h>
#include <dlfcn.h>
#ifdef __APPLE__
#include <sys/syslimits.h>
#else
#include <linux/limits.h>
#endif
#endif

#include <stdint.h>
#include <stdlib.h>

#ifdef _WIN32
#if defined(UTILS_EXPORTS)
#define UTILS_API __declspec(dllexport)
#elif defined(UTILS_NO_IMPORT)
#define UTILS_API
#elif defined(__cplusplus)
#define UTILS_API extern "C" __declspec(dllimport)
#else
#define UTILS_API __declspec(dllimport)
#endif
#else //_WIN32
#define UTILS_API
#endif

#ifndef MAX_PATH
#define MAX_PATH PATH_MAX
#endif

#define FUZZ_ERROR -1
#define FUZZ_NONE  0
#define FUZZ_RUNNING 1
#define FUZZ_CRASH 2
#define FUZZ_HANG  3

#ifdef _WIN32
typedef HANDLE mutex_t;
typedef HANDLE semaphore_t;
#else
typedef pthread_mutex_t * mutex_t;
typedef sem_t * semaphore_t;
#endif

#ifdef _WIN32
UTILS_API int start_process_and_write_to_stdin(char * cmd_line, char * input, size_t input_length, HANDLE * process_out);
UTILS_API int start_process_and_write_to_stdin_flags(char * cmd_line, char * input, size_t input_length, HANDLE * process_out, DWORD creation_flags);
UTILS_API int start_process_and_write_to_stdin_and_save_pipes_timeout(char * cmd_line, char * input, size_t input_length, HANDLE * process_out, HANDLE * pipe_rd_ptr, HANDLE * pipe_wr_ptr, DWORD timeout_ms);
UTILS_API int WriteToPipe(HANDLE process, HANDLE pipe_wr, HANDLE pipe_rd, char * input, size_t input_length, DWORD timeout_ms);
UTILS_API int FlushPipe(HANDLE pipe_rd);
UTILS_API wchar_t * convert_char_array_to_wchar(char * string, wchar_t * out_buffer);
UTILS_API char * convert_wchar_array_to_char(wchar_t * string, char * out_buffer);
UTILS_API int get_process_status(HANDLE process);
#else
UTILS_API int get_process_status(pid_t process);
#endif

UTILS_API char * get_temp_filename(char * suffix);
UTILS_API int file_exists(char * path);
UTILS_API int write_buffer_to_file(char * filename, char * buffer, size_t length);
UTILS_API char * filename_relative_to_binary_dir(char * relative_path);
UTILS_API int read_file(char * filename, char **buffer);
UTILS_API void print_hex(char * data, size_t size);
UTILS_API void md5(uint8_t *initial_msg, size_t initial_len, char * output, size_t output_size);
UTILS_API void * memdup(void * src, size_t length);

UTILS_API mutex_t create_mutex(void);
UTILS_API int take_mutex(mutex_t mutex);
UTILS_API int release_mutex(mutex_t mutex);
UTILS_API void destroy_mutex(mutex_t mutex);
UTILS_API semaphore_t create_semaphore(int initial, int max);
UTILS_API int take_semaphore(semaphore_t semaphore);
UTILS_API int release_semaphore(semaphore_t semaphore);
UTILS_API void destroy_semaphore(semaphore_t semaphore);

#ifndef _WIN32
UTILS_API int split_command_line(char * cmd_line, char ** executable, char ***argv);
UTILS_API int start_process_and_write_to_stdin(char * cmd_line, char * input, size_t input_length, pid_t * process_out);
#endif

//Logging
enum LOG_LEVEL {
	DEBUG,
	INFO,
	WARNING,
	ERROR_LEVEL, //ERROR is already taken
	CRITICAL,
	FATAL,
	MAX_LOG_LEVEL,
};

#if defined(_DEBUG)
#define DEBUG_MSG(msg, ...) log_msg(DEBUG, msg, ##__VA_ARGS__)
#else
#define DEBUG_MSG(msg, ...)
#endif

#define INFO_MSG(msg, ...) log_msg(INFO, msg, ##__VA_ARGS__)
#define WARNING_MSG(msg, ...) log_msg(WARNING, msg, ##__VA_ARGS__)
#define ERROR_MSG(msg, ...) log_msg(ERROR_LEVEL, msg, ##__VA_ARGS__)
#define CRITICAL_MSG(msg, ...) log_msg(CRITICAL, msg, ##__VA_ARGS__)
#define FATAL_MSG(msg, ...) log_msg(FATAL, msg, ##__VA_ARGS__)

UTILS_API char * logging_help(void);
UTILS_API int setup_logging(const char * log_options);
UTILS_API int log_msg(enum LOG_LEVEL level, const char * msg, ...);

//Argument parser helpers

#define IF_ARG_OPTION(x, y)           \
if(!strcmp(argv[i], x) && i+1 < argc) \
{                                     \
	y = argv[i + 1];                  \
	i++;                              \
}
#define IF_ARGINT_OPTION(x, y)        \
if(!strcmp(argv[i], x) && i+1 < argc) \
{                                     \
	y = atoi(argv[i + 1]);            \
	i++;                              \
}
#define IF_ARGDOUBLE_OPTION(x, y)     \
if(!strcmp(argv[i], x) && i+1 < argc) \
{                                     \
	y = atof(argv[i + 1]);            \
	i++;                              \
}
#define IF_ARG_SET_TRUE(x, y)         \
if(!strcmp(argv[i], x))               \
{                                     \
	y = 1;                            \
}

#define ELSE_IF_ARG_OPTION(x, y)       else IF_ARG_OPTION(x,y)
#define ELSE_IF_ARGINT_OPTION(x, y)    else IF_ARGINT_OPTION(x,y)
#define ELSE_IF_ARGDOUBLE_OPTION(x, y) else IF_ARGDOUBLE_OPTION(x,y)
#define ELSE_IF_ARG_SET_TRUE(x, y)     else IF_ARG_SET_TRUE(x,y)

/**
 * Get the number of items in an array
 */
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*x))
