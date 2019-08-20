#include "utils.h"

#include <jansson_helper.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#include <io.h>
#include <process.h>
#include <tchar.h>
#include <strsafe.h>
#include <Shlwapi.h>
#include <windows.h>

#define F_OK 0
#else

#ifdef __APPLE__
#include <mach-o/dyld.h> // _NSGetExecutablePath
#endif

#include <errno.h>
#include <libgen.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wordexp.h>
#endif

#ifdef _WIN32
static int CreateChildProcess(char * cmd_line, HANDLE read_pipe, HANDLE * process_out, DWORD creation_flags);

/**
* This function converts a char * to a wchar *
* @param - The char * string that should be converted to a wchar * string
* @param - A wchar * buffer that the converted string should be placed into.  If NULL,
* this function will allocate a wchar * buffer to place the converted string into.
* @return - A pointer to the converted string
*/
UTILS_API wchar_t * convert_char_array_to_wchar(char * string, wchar_t * out_buffer)
{
	size_t size = (strlen(string) + 1) * sizeof(wchar_t);
	size_t converted_length = 0;

	if (!out_buffer)
	{
		out_buffer = (wchar_t *)malloc(size);
		if (!out_buffer)
			return NULL;
	}

	mbstowcs_s(&converted_length, out_buffer, strlen(string) + 1, string, size);
	return out_buffer;
}

/**
* This function converts a wchar * to a char *
* @param - The wchar * string that should be converted to a char * string
* @param - A char * buffer that the converted string should be placed into.  If NULL,
* this function will allocate a char * buffer to place the converted string into.
* @return - A pointer to the converted string
*/
UTILS_API char * convert_wchar_array_to_char(wchar_t * string, char * out_buffer)
{
	size_t size = (wcslen(string) + 1) * 2;
	size_t converted_length = 0;

	if (!out_buffer)
	{
		out_buffer = (char *)malloc(size);
		if (!out_buffer)
			return NULL;
	}

	wcstombs_s(&converted_length, out_buffer, size, string, size-1);
	return out_buffer;
}


#define CLOSE_PIPES() \
	if(pipe_rd) CloseHandle(pipe_rd); \
	if(pipe_wr) CloseHandle(pipe_wr);

#define MAX_CMD_LEN 10*4096
#define MAX_STANDARD_IN_PIPE_SIZE 8*1024 *1024 //8MB

static int start_process_and_write_to_stdin_inner(char * cmd_line, char * input, size_t input_length, HANDLE * process_out, HANDLE * pipe_rd_ptr, HANDLE * pipe_wr_ptr, DWORD timeout_ms, DWORD creation_flags)
{
	SECURITY_ATTRIBUTES saAttr;
	int ret;
	HANDLE pipe_rd, pipe_wr;

	//Mark the process as not started in case we error out
	*process_out = NULL;
	if (strlen(cmd_line) > MAX_CMD_LEN)
		return 1;

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Create a pipe for the child process's STDIN.
	if (!CreatePipe(&pipe_rd, &pipe_wr, &saAttr, min(input_length, MAX_STANDARD_IN_PIPE_SIZE)))
		return 1;

	// Ensure the write handle to the pipe for STDIN is not inherited.
	if (!SetHandleInformation(pipe_wr, HANDLE_FLAG_INHERIT, 0))
	{
		CLOSE_PIPES();
		return 1;
	}

	// Create the child process.
	if (CreateChildProcess(cmd_line, pipe_rd, process_out, creation_flags))
	{
		CLOSE_PIPES();
		return 1;
	}

	//Write the input buffer
	ret = 0;
	if (input && input_length > 0)
	{
		if (WriteToPipe(*process_out, pipe_wr, pipe_rd, input, input_length, timeout_ms))
			ret = 1;
	}

	//Either save the pipes, or close them so we don't leak resources
	if (pipe_rd_ptr)
		*pipe_rd_ptr = pipe_rd;
	else
		CloseHandle(pipe_rd);
	if (pipe_wr_ptr)
		*pipe_wr_ptr = pipe_wr;
	else
		CloseHandle(pipe_wr);
	return ret;
}

/**
  * This function starts a process and writes to the stdin of the process.
  * @param cmd_line - The command line of the new process to start
  * @param input - a buffer that should be pasesd to the newly created process's stdin
  * @param input_length - The length of the input parameter
  * @param process_out - a pointer to a HANDLE that will be filled in with a handle to the newly created process
  * @param pipe_rd_ptr - a pointer to a HANDLE that will be filled in with the read end of the stdin pipe for the new process.
  * If pipe_rd_ptr is NULL, the read end of the stdin pipe will be closed instead.
  * @param pipe_wr_ptr - a pointer to a HANDLE that will be filled in with the write end of the stdin pipe for the new process.
  * If pipe_wr_ptr is NULL, the write end of the stdin pipe will be closed instead.
  * @param timeout_ms - The maximum number of milliseconds to wait when writing to the newly created process's stdin pipe.
  * @return - zero on success, non-zero on failure
  */
UTILS_API int start_process_and_write_to_stdin_and_save_pipes_timeout(char * cmd_line, char * input, size_t input_length, HANDLE * process_out, HANDLE * pipe_rd_ptr, HANDLE * pipe_wr_ptr, DWORD timeout_ms)
{
	return start_process_and_write_to_stdin_inner(cmd_line, input, input_length, process_out, pipe_rd_ptr, pipe_wr_ptr, timeout_ms, 0);
}

/**
  * This function starts a process and writes to the stdin of the process.
  * @param cmd_line - The command line of the new process to start
  * @param input - a buffer that should be pasesd to the newly created process's stdin
  * @param input_length - The length of the input parameter
  * @param process_out - a pointer to a HANDLE that will be filled in with a handle to the newly created process
  * @return - zero on success, non-zero on failure
  */
UTILS_API int start_process_and_write_to_stdin(char * cmd_line, char * input, size_t input_length, HANDLE * process_out)
{
	return start_process_and_write_to_stdin_inner(cmd_line, input, input_length, process_out, NULL, NULL, 0, 0);
}

/**
  * This function starts a process and writes to the stdin of the process.
  * @param cmd_line - The command line of the new process to start
  * @param input - a buffer that should be pasesd to the newly created process's stdin
  * @param input_length - The length of the input parameter
  * @param process_out - a pointer to a HANDLE that will be filled in with a handle to the newly created process
  * @param creation_flags - The creation flags that should be passed to the CreateProcess Windows API
  * @return - zero on success, non-zero on failure
  */
UTILS_API int start_process_and_write_to_stdin_flags(char * cmd_line, char * input, size_t input_length, HANDLE * process_out, DWORD creation_flags)
{
	return start_process_and_write_to_stdin_inner(cmd_line, input, input_length, process_out, NULL, NULL, 0, creation_flags);
}


/**
  * This function starts a new process
  * @param cmd_line - The command line for the process to create
  * @param read_pipe - A handle to the read end of a pipe that should be assigned to the newly created process's stdin
  * @param process_out - A pointer toa HANDLE that will be filled in with a handle to the newly created process
  * @param creation_flags - The creation flags that should be passed to the CreateProcess Windows API
  * @return - zero on success, non-zero on failure
  */
static int CreateChildProcess(char * cmd_line, HANDLE read_pipe, HANDLE * process_out, DWORD creation_flags)
{
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;

	// Set up members of the PROCESS_INFORMATION structure.

	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));


	// Set up members of the STARTUPINFO structure.
	// This structure specifies the STDIN and STDOUT handles for redirection.

	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdInput = read_pipe;
	siStartInfo.hStdError = NULL;
	siStartInfo.hStdOutput = NULL;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
	siStartInfo.wShowWindow = 1;

	// Create the child process.
	bSuccess = CreateProcess(NULL,
		cmd_line,      // command line
		NULL,          // process security attributes
		NULL,          // primary thread security attributes
		TRUE,          // handles are inherited
		creation_flags,// creation flags
		NULL,          // use parent's environment
		NULL,          // use parent's current directory
		&siStartInfo,  // STARTUPINFO pointer
		&piProcInfo);  // receives PROCESS_INFORMATION

	// If an error occurs, exit the application.
	if (!bSuccess)
		return 1;

	CloseHandle(piProcInfo.hThread); //We don't need the thread handle
	*process_out = piProcInfo.hProcess;
	return 0;
}

#define MAX_WRITE_SIZE 8*1024*1024 //8MB

#define GET_FILETIME_DIFF_IN_MILLISECONDS(x,y,z) \
	ULARGE_INTEGER temp1##x##y, temp2##x##y; \
	temp1##x##y.LowPart = x.dwLowDateTime; temp1##x##y.HighPart = x.dwHighDateTime; \
	temp2##x##y.LowPart = y.dwLowDateTime; temp2##x##y.HighPart = y.dwHighDateTime; \
	z = (temp1##x##y.QuadPart - temp2##x##y.QuadPart) / 10000;

/**
 * Writes the given input buffer the a pipe, checking to make sure the other process hasn't died
 * and that there is room on the pipe to write.
 * @param process - The process that holds the read end of the pipe.
 * @param pipe_wr - The write end of the pipe that will be written to.
 * @param pipe_rd - The read end of the pipe being written to
 * @param input - a buffer to write to the the pipe_wr parameter
 * @param input_length - The length of the input parameter
 * @param timeout_ms - The maximum number of milliseconds to wait when writing to the pipe
 * @return - 0 on success (all bytes written to the pipe), 1 on failure
 */
UTILS_API int WriteToPipe(HANDLE process, HANDLE pipe_wr, HANDLE pipe_rd, char * input, size_t input_length, DWORD timeout_ms)
{
	DWORD dwWritten, out_size, total_in_pipe, timediff;
	size_t total_written = 0, write_size;
	BOOL bSuccess = FALSE;
	FILETIME start_time, time;

	GetSystemTimeAsFileTime(&start_time);
	while (total_written < input_length && get_process_status(process))
	{
		if (!GetNamedPipeInfo(pipe_wr, NULL, &out_size, NULL, NULL))
			break;
		if (!PeekNamedPipe(pipe_rd, NULL, 0, NULL, &total_in_pipe, NULL))
			break;
		write_size = min(min(input_length - total_written, MAX_WRITE_SIZE), out_size - total_in_pipe);
		if (write_size == 0) //There's no room to write to the pipe
		{
			GetSystemTimeAsFileTime(&time);
			GET_FILETIME_DIFF_IN_MILLISECONDS(time, start_time, timediff);
			if (timeout_ms && timediff > timeout_ms)
				return 1;
			dwWritten = WaitForSingleObject(pipe_wr, timeout_ms);
		}
		else
		{
			bSuccess = WriteFile(pipe_wr, input + total_written, write_size, &dwWritten, NULL);
			if (!bSuccess) break;
			total_written += dwWritten;
		}
	}
	return total_written != input_length;
}

/**
 * Flushes any input waiting on the given pipe
 * @param pipe_rd - a handle to the pipe that should be flushed
 * @return - 0 on success, non-zero on failure
 */
UTILS_API int FlushPipe(HANDLE pipe_rd)
{
	DWORD total_in_pipe, num_read;
	int failed;
	char * temp;

	if (!PeekNamedPipe(pipe_rd, NULL, 0, NULL, &total_in_pipe, NULL))
		return 1;
	if (!total_in_pipe)
		return 0;

	temp = (char *)malloc(total_in_pipe);
	failed = ReadFile(pipe_rd, temp, total_in_pipe, &num_read, NULL) != TRUE;
	free(temp);
	if (num_read != total_in_pipe)
		failed = 1;
	return failed;
}

#endif //_WIN32

/**
 * This function checks if a process is still alive
 * @param - a HANDLE to the process to check
 * @return - FUZZ_RUNNING (1) if the process is alive, FUZZ_NONE (0) if it is not, FUZZ_ERROR (-1) on failure
 */
#ifdef _WIN32
UTILS_API int get_process_status(HANDLE process)
{
	DWORD exitCode;
	if (GetExitCodeProcess(process, &exitCode) == 0)
		return FUZZ_ERROR;
	return exitCode == STILL_ACTIVE;
}
#else
/**
 * This function checks if a CHILD process is still alive
 * @return - FUZZ_CRASH (2) if the process exited by crash, FUZZ_RUNNING (1) if
 * the process is alive, FUZZ_NONE (0) if it exited cleanly, FUZZ_ERROR (-1) on
 * failure
 *
 * NOTE: This should only be called once after a process has terminated.
 *
 */
UTILS_API int get_process_status(pid_t pid)
{

	// We can't use kill here, because it'll return "alive" if the process is
	// in a zombie state (ie, unreaped).  So, we have to reap here.

	int status;
	pid_t result;

	// WNOHANG result: 0 means it exists and is alive, pid means it has exited,
	// -1 means error
	result = waitpid(pid, &status, WNOHANG);

	if(result == 0) {
		return FUZZ_RUNNING;
	} else if (result > 0) {
		if(WIFEXITED(status))
			return FUZZ_NONE; // it exited normally
		if(WIFSIGNALED(status))
			return FUZZ_CRASH; // it crashed
	}
	// either waitpid failed, or the process is not running, did not exit
	// normally, and was not signaled, in either case we don't know what
	// went wrong
	return FUZZ_ERROR;
}
#endif

/**
 * Generates a temporary filename
 * @param suffix - Optionally, a suffix to append to the generated temporary filename.  If NULL,
 * no file extension will be added.
 * @return - NULL on failure, or a newly allocated character buffer holding the temporary filename.
 * The caller should free the returned buffer
 */
UTILS_API char * get_temp_filename(char * suffix)
{
#ifdef _WIN32
	char temp_dir[MAX_PATH];
	char temp_filename[MAX_PATH];
	char * ret;
	size_t suffix_length = 0;

	//Get the temp filename
	// eg C:\Users\<name>\AppData\Local\Temp\ 
	if (GetTempPath(MAX_PATH, temp_dir) == 0)
		return NULL;
	// eg C:\Users\<name>\AppData\Local\Temp\fuzD828.tmp
	GetTempFileName(temp_dir, "fuzzfile", 0, temp_filename);

	//Add the suffix and convert it to a useable format
	if (suffix)
		suffix_length = strlen(suffix);

	ret = (char *)malloc(MAX_PATH + suffix_length);
	if (!ret)
		return NULL;

	memset(ret, 0, MAX_PATH + suffix_length);
	strncpy(ret, temp_filename, MAX_PATH);
	unlink(ret); //Cleanup the file without the extension that GetTempFileName generated
	if(suffix)
		strncat(ret, suffix, MAX_PATH + suffix_length);
	// eg C:\Users\<name>\AppData\Local\Temp\fuzFEAD.tmp.txt

#else
	// on macOS we can use $TMPDIR. ubuntu doesn't seem to have one, stackoverflow recommends
	// /tmp. /dev/shm might be a better option, because it's a tmpfs (doesn't write to disk)
	// but i suspect it's less portable to other *nixes.
	char temp_filename[] = "/tmp/fuzzfileXXXXXX"; // X's required for mktemp
	char * ret;
	size_t suffix_length = 0;

	// mktemp is unsafe, but i'm not sure what the threat model is.
	// for ours, it might be sufficient.
	// alternatively, we can mkstemp, but that will also create a file
	// (as is happening in the windows version of the code) and requires deletion.
	// that's probably as simple as an unlink(), but it's almost certainly slower.
	mktemp(temp_filename);

	if (suffix)
		suffix_length = strlen(suffix);

	ret = (char *)malloc(MAX_PATH + suffix_length);
	if (!ret)
		return NULL;

	memset(ret, 0, MAX_PATH + suffix_length);
	strncpy(ret, temp_filename, MAX_PATH);
	if(suffix)
		strncat(ret, suffix, MAX_PATH + suffix_length);

#endif

	return ret;
}

/**
 * Determines whether a file exists or not
 * @param path - The path of the file to check for existence
 * @return - 1 if the file exists, 0 otherwise
 */
UTILS_API int file_exists(char * path)
{
	return !access(path,F_OK);
}

/**
 * This function writes a buffer to the specified file.
 * @param filename - The filename to write the buffer to
 * @param buffer - The buffer to write
 * @param length - THe length of the buffer parameter
 * @param return - 0 on success, non-zero otherwise
 */
UTILS_API int write_buffer_to_file(char * filename, char * buffer, size_t length)
{
	int num_written;
	size_t total = 0;
	FILE * fp = NULL;
	int error = EACCES;

#ifdef _WIN32
	//On Windows, we need to do this in a loop, since we may
	//need to wait for a process to stop holding this file
	while (!fp && error == EACCES)
	{
		fp = fopen(filename, "wb+");
		error = errno;
	}
#else
	fp = fopen(filename, "wb+");
#endif
	if (!fp)
		return -1;

	while (total < length)
	{
		num_written = fwrite(buffer + total, 1, length - total, fp);
		if (num_written < 0 && errno != EAGAIN && errno != EINTR)
			break;
		else if (num_written > 0)
			total += num_written;
	}
	fclose(fp);
	return total != length;
}

/**
* This function takes a relative path representing a location relative to the
* running binary (note: NOT the working directory) and returns the
* corresponding absolute path, if that path exists in the filesystem.
*
* @param relative_path - a char * pointing to the path relative to the executable
* @return - NULL on error or nonexistent path, or a char * pointing to a
* newly-allocated buffer containing the absolute path. The caller should free the
* returned buffer
*/
UTILS_API char * filename_relative_to_binary_dir(char * relative_path) {
	char exedir[2*MAX_PATH], temppath[MAX_PATH];
	int len;

// write full path into exedir
#ifdef _WIN32
	if (!GetModuleFileName(NULL, exedir, 2*MAX_PATH)) {
		return NULL;
	}
	PathRemoveFileSpec(exedir);  // Cut off file name
	len = snprintf(temppath, MAX_PATH, "%s\\%s", exedir, relative_path);
#elif __APPLE__
	unsigned int bufsize = sizeof(exedir) + 1;
	if (_NSGetExecutablePath(exedir, &bufsize) != 0)
		return NULL;
	realpath(exedir, temppath);
	dirname_r(temppath, temppath); // Cut off file name
	len = snprintf(temppath, MAX_PATH, "%s/%s", temppath, relative_path);
#else
	if ((len = readlink("/proc/self/exe", exedir, MAX_PATH)) < 0)
		return NULL;

	exedir[len] = 0; //readlink doesn't null terminate
	dirname(exedir); // Cut off file name
	len = snprintf(temppath, MAX_PATH, "%s/%s", exedir, relative_path);
#endif

	if (len == MAX_PATH) {
		return NULL;
	}

	if (!file_exists(temppath)) {
		return NULL;
	}
	return strdup(temppath);
}

/**
 * Calculates the MD5 hash of a buffer and return the value as a hexstring.
 * Taken from https://gist.github.com/creationix/4710780
 * @param buffer - The buffer to calculate the md5 hash on
 * @param buffer_length - the length of the buffer parameter
 * @param output - a buffer to record the md5 hash to.
 * @param output_size - the length of the output parameter
 */
void md5(uint8_t *buffer, size_t buffer_length, char * output, size_t output_size) {

	// leftrotate function definition
	#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))


	// These vars will contain the hash
	uint32_t h0, h1, h2, h3;

	// Message (to prepare)
	uint8_t *msg = NULL;

	// Note: All variables are unsigned 32 bit and wrap modulo 2^32 when calculating

	// r specifies the per-round shift amounts

	uint32_t r[] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

	// Use binary integer part of the sines of integers (in radians) as constants// Initialize variables:
	uint32_t k[] = {
		0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
		0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
		0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
		0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
		0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
		0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
		0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
		0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
		0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
		0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
		0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
		0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
		0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
		0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
		0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
		0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

	h0 = 0x67452301;
	h1 = 0xefcdab89;
	h2 = 0x98badcfe;
	h3 = 0x10325476;

	// Pre-processing: adding a single 1 bit
	//append "1" bit to message
	/* Notice: the input bytes are considered as bits strings,
	where the first bit is the most significant bit of the byte.[37] */

	// Pre-processing: padding with zeros
	//append "0" bit until message length in bit = 448 (mod 512)
	//append length mod (2 pow 64) to message

	int new_len;
	for (new_len = buffer_length * 8 + 1; new_len % 512 != 448; new_len++);
	new_len /= 8;

	msg = (uint8_t *)calloc(new_len + 64, 1); // also appends "0" bits
                                              // (we alloc also 64 extra bytes...)
	memcpy(msg, buffer, buffer_length);
	msg[buffer_length] = 128; // write the "1" bit

	uint32_t bits_len = 8 * buffer_length; // note, we append the len
	memcpy(msg + new_len, &bits_len, 4); // in bits at the end of the buffer

	// Process the message in successive 512-bit chunks:
	int offset;
	for (offset = 0; offset<new_len; offset += (512 / 8)) {

		// break chunk into sixteen 32-bit words w[j], 0 = j = 15
		uint32_t *w = (uint32_t *)(msg + offset);

		// Initialize hash value for this chunk:
		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;

		uint32_t i;
		for (i = 0; i<64; i++) {

			uint32_t f, g;

			if (i < 16) {
				f = (b & c) | ((~b) & d);
				g = i;
			}
			else if (i < 32) {
				f = (d & b) | ((~d) & c);
				g = (5 * i + 1) % 16;
			}
			else if (i < 48) {
				f = b ^ c ^ d;
				g = (3 * i + 5) % 16;
			}
			else {
				f = c ^ (b | (~d));
				g = (7 * i) % 16;
			}

			uint32_t temp = d;
			d = c;
			c = b;
			b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
			a = temp;
		}

		// Add this chunk's hash to result so far:
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;

	}
	free(msg);

	//Copy the hash to the output buffer
	uint8_t *p0 = (uint8_t *)&h0, *p1 = (uint8_t *)&h1, *p2 = (uint8_t *)&h2, *p3 = (uint8_t *)&h3;
	snprintf(output, output_size, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
		p0[0], p0[1], p0[2], p0[3], p1[0], p1[1], p1[2], p1[3],
		p2[0], p2[1], p2[2], p2[3], p3[0], p3[1], p3[2], p3[3]
	);
}

static struct logging_info {
	int initialized;
	int level;
	FILE * log_file;

	int stdout_on:1;
	int file_on:1;
} logging = { .initialized = 0, .level = INFO, .log_file = NULL, .stdout_on = 1, .file_on = 1, };

const char * log_level_names[] = {
	"DEBUG",
	"INFO",
	"WARNING",
	"ERROR",
	"CRITICAL",
	"FATAL"
};

/**
 * Returns a string describing the options for the logging subsystem
 */
UTILS_API char * logging_help(void)
{
	return strdup(
"Logging Options:\n"
"  file                  Enable/disable file logging (default enabled)\n"
"  filename              Set the filename of the logging file\n"
"                          (default killerbeez.log)\n"
"  level                 Set the log level (0-4), higher is less verbose, lower\n"
"                          is more verbose (default 1)\n"
"  stdout                Enable/disable logging to stdout (default enabled)\n"
	);
}

#define GET_OPTIONAL_ARG(temp, options, dest, name, ret, func) \
	temp = func(options, name, &ret);                          \
	if (ret < 0)                                               \
		return 1;                                              \
	if (ret > 0)                                               \
		dest = temp;

/**
  * This function takes a JSON string of logging options and sets up the desired
  * logging state.
  *
  * @param log_options - a JSON string of logging options.  For the default options,
  * NULL can be provided
  * @return - zero on success, non-zero on error
  */
UTILS_API int setup_logging(const char * log_options)
{
	int temp_int, result;
	char * temp_str, * filename = NULL;

	if (logging.initialized)
		return 0;
	
	if (log_options) {
		GET_OPTIONAL_ARG(temp_int, log_options, logging.level, "level", result, get_int_options);
		GET_OPTIONAL_ARG(temp_int, log_options, logging.stdout_on, "stdout", result, get_int_options);
		GET_OPTIONAL_ARG(temp_int, log_options, logging.file_on, "file", result, get_int_options);
		GET_OPTIONAL_ARG(temp_str, log_options, filename, "filename", result, get_string_options);
	}

	if (logging.file_on) {
		if (!filename)
			filename = strdup("killerbeez.log");

		logging.log_file = fopen(filename, "a+");
		if (!logging.log_file) {
#ifdef _WIN32
			printf("[LOGGING] ERROR: Failed to open file %s. GetLastError %d", filename, GetLastError());
#else
			printf("[LOGGING] ERROR: Failed to open file %s. errno %d", filename, errno);
#endif
			return 1;
		}
		free(filename);
	}

	logging.initialized = 1;
	INFO_MSG("Logging Started");
	return 0;
}

/**
  * This function takes a log level, a printf style format string, and printf style
  * arguments and outputs the message to any of the configured loggers.  Prior to
  * calling this function, logging must be initialized via the setup_logging
  * function prior to any calls to log_msg.  If the specified level is FATAL or
  * above, log_msg will exit(1) immediately after logging the specified message.
  *
  * @param level - the log level of the message to log
  * @param msg - a printf style format string to log
  * @param ... - printf style arguments to log
  * @return - zero on success, non-zero on error
  */
UTILS_API int log_msg(enum LOG_LEVEL level, const char * msg, ...)
{
	va_list args, temp_args;
	struct tm new_time;
	time_t aclock;
	char time_buf[64];

	if (!logging.initialized)
		return 1;
	if (level < logging.level)
		return 0;

	time(&aclock);
#ifdef _WIN32
	localtime_s(&new_time, &aclock);
	if (asctime_s(time_buf, sizeof(time_buf), &new_time))
#else
	localtime_r(&aclock, &new_time);
	if (!asctime_r(&new_time, time_buf))
#endif
	{ //If we couldn't get the time, NULL out time_buf, so we don't print garbage
		strncpy(time_buf, "TIME FAILURE", sizeof(time_buf));
	}
	else //asctime appends a newline to the end of the buffer,
		time_buf[strlen(time_buf) - 1] = 0; //remove it

	va_start(args, msg);
	if (logging.stdout_on) {
		va_copy(temp_args, args);
		fprintf(stdout, "%s - %-8s - ", time_buf, log_level_names[level]);
		vprintf(msg, temp_args);
		fwrite("\n", 1, 1, stdout);
		fflush(stdout);
		va_end(temp_args);
	}
	if (logging.file_on) {
		va_copy(temp_args, args);
		fprintf(logging.log_file, "%s - %-8s - ", time_buf, log_level_names[level]);
		vfprintf(logging.log_file, msg, temp_args);
		fwrite("\n", 1, 1, logging.log_file);
		fflush(logging.log_file);
		va_end(temp_args);
	}
	va_end(args);

	//If the message is FATAL, we should die after logging
	if (level >= FATAL)
		exit(1);

	return 0;
}

/**
 * Reads a file from disk
 * @param filename - The filename of the file to read
 * @param buffer - A pointer to a character buffer that will be assigned a newly allocated
 * buffer to hold the file contents.  The caller should free this buffer.
 * @return - -1 on failure, otherwise the number of bytes read from the file
 */
UTILS_API int read_file(char * filename, char **buffer)
{
	FILE *fp;
	long fsize, total = 0, num_read;

	*buffer = NULL;

	fp = fopen(filename, "rb");
	if (!fp)
		return -1;

	//Get the size
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	*buffer = (char *)malloc(fsize + 1);
	if (!*buffer)
	{
		fclose(fp);
		return -1;
	}

	(*buffer)[fsize] = 0; //NULL terminate in case the caller wants to use it as a string
	while (total < fsize)
	{
		num_read = fread(*buffer + total, 1, fsize, fp);
		total += num_read;
	}

	fclose(fp);

	return fsize;
}

/**
 * This function prints a data buffer in hex
 * @param data - a char * data buffer
 * @param size - the size of the data buffer
 * @return none
 */
UTILS_API void print_hex(char * data, size_t size) {
	unsigned char *p = (unsigned char *)data;
	for (size_t i = 0; i<size; i++) {
		if ((i % 16 == 0) && i)
			printf("\n");
		printf("%02x", p[i]);
	}
}

/**
 * Allocates a new region of memory and copies the specified buffer onto it
 * @param src - a pointer to the region of memory to copy
 * @param length - the length of the region of memory to copy
 * @return a newly created region of memory with the specified contents on success, or NULL on failure
 */
UTILS_API void * memdup(void * src, size_t length)
{
	void * dest = malloc(length);
	if (dest)
		memcpy(dest, src, length);
	return dest;
}

/**
 * Creates a mutex
 * @return - the created mutex on success, NULL on failure
 */
UTILS_API mutex_t create_mutex(void)
{
#ifdef _WIN32
	return CreateMutex(NULL, FALSE, NULL);
#else
	pthread_mutex_t * mutex = malloc(sizeof(pthread_mutex_t));
	if (mutex)
		pthread_mutex_init(mutex, NULL);
	return mutex;
#endif
}

/**
 * Takes a mutex
 * @param mutex - the mutex to take
 * @return - zero on success, nonzero on failure
 */
UTILS_API int take_mutex(mutex_t mutex)
{
#ifdef _WIN32
	return WaitForSingleObject(mutex, INFINITE) == WAIT_FAILED;
#else
	return pthread_mutex_lock(mutex);
#endif
}

/**
 * Releases a mutex
 * @param mutex - the mutex to release
 * @return - zero on success, nonzero on failure
 */
UTILS_API int release_mutex(mutex_t mutex)
{
#ifdef _WIN32
	return ReleaseMutex(mutex) == 0;
#else
	return pthread_mutex_unlock(mutex);
#endif
}

/**
 * Cleans up the resources asscoiated with a mutex
 * @param mutex - the mutex to clean up
 */
UTILS_API void destroy_mutex(mutex_t mutex)
{
	if (mutex) {
#ifdef _WIN32
		CloseHandle(mutex);
#else
		pthread_mutex_destroy(mutex);
		free(mutex);
#endif
	}
}

/**
 * Creates a semaphore with the specified initial value and max value (max value
 * only used on Windows)
 * @param initial - the initial value of the semaphore
 * @param max - the max value of the semaphore (only used on Windows)
 * @return - the created semaphore on success, NULL on failure
 */
UTILS_API semaphore_t create_semaphore(int initial, int max)
{
#ifdef _WIN32
	return CreateSemaphore(NULL, initial, max, NULL);
#else
	sem_t * semaphore = malloc(sizeof(sem_t));
	if (semaphore && sem_init(semaphore, 0, initial)) {
		free(semaphore);
		semaphore = NULL;
	}
	return semaphore;
#endif
}

/**
 * Takes a semaphore
 * @param semaphore - the semaphore to take
 * @return - zero on success, nonzero on failure
 */
UTILS_API int take_semaphore(semaphore_t semaphore)
{
#ifdef _WIN32
	return WaitForSingleObject(semaphore, INFINITE) == WAIT_FAILED;
#else
	//Loop and wait to actually take it, in case we get stopped by a signal
	int taken = 0;
	while (!taken) {
		if (!sem_wait(semaphore))
			taken = 1;
		else if (errno != EINTR) //got a signal rather than took the semaphore
			break;
	}
	return taken == 0;
#endif
}

/**
 * Releases a semaphore
 * @param semaphore - the semaphore to release
 * @return - zero on success, nonzero on failure
 */
UTILS_API int release_semaphore(semaphore_t semaphore)
{
#ifdef _WIN32
	return ReleaseSemaphore(semaphore, 1, NULL) == 0;
#else
	return sem_post(semaphore);
#endif
}

/**
 * Cleans up the resources asscoiated with a semaphore
 * @param semaphore - the semaphore to clean up
 */
UTILS_API void destroy_semaphore(semaphore_t semaphore)
{
	if (semaphore) {
#ifdef _WIN32
		CloseHandle(semaphore);
#else
		sem_destroy(semaphore);
		free(semaphore);
#endif
	}
}

#ifndef _WIN32

/**
 * This function takes a command line and splits it into the executable filename and
 * the argv-array style arguments.
 * @param cmd_line - the command line to split
 * @param executable - A pointer that will be assigned the filename of the executable
 * in the command line.  The assigned pointer should be freed by the caller.
 * @param argv - A pointer that will be assigned the address of an argv style arguments
 * array.  This array and each item in it should be freed by the caller.
 * @return - 0 on success, non-zero on failure
 */
UTILS_API int split_command_line(char * cmd_line, char ** executable, char ***argv)
{
	wordexp_t wordexp_result;
	size_t i, j;
	char * target_executable, **target_argv;

	// Expand the command line into the program and arguments
	if(wordexp(cmd_line, &wordexp_result, 0)) {
		wordfree(&wordexp_result);
		return -1;
	}

	target_executable = strdup(wordexp_result.we_wordv[0]);
	target_argv = malloc(sizeof(char *) * (wordexp_result.we_wordc+1));
	if(!target_executable || !target_argv) {
		free(target_executable);
		free(target_argv);
		wordfree (&wordexp_result);
		return -1;
	}

	for(i = 0; i < wordexp_result.we_wordc; i++) {
		target_argv[i] = strdup(wordexp_result.we_wordv[i]);
		if(!target_argv[i]) {
			free(target_executable);
			for(j = 0; j < i; j++)
				free(target_argv[j]);
			free(target_argv);
			wordfree (&wordexp_result);
			return -1;
		}
	}
	target_argv[wordexp_result.we_wordc] = NULL;

	wordfree (&wordexp_result);
	*executable = target_executable;
	*argv = target_argv;
	return 0;
}

/**
 * This function starts a process and writes to the stdin of the process.
 * @param cmd_line - The command line of the new process to start.  The command line must start with the
 * path of the executable to start.
 * @param input - a buffer that should be pasesd to the newly created process's stdin
 * @param input_length - The length of the input parameter
 * @param process_out - a pointer to a pid_t that will be filled in with a handle to the newly created process
 * @return - zero on success, non-zero on failure
 */
UTILS_API int start_process_and_write_to_stdin(char * cmd_line, char * input, size_t input_length, pid_t * process_out)
{
	int pipes[2];
	int status, i;
	pid_t child_pid;
	ssize_t result;
	size_t total_written = 0;
	char * executable, **argv;

	if(split_command_line(cmd_line, &executable, &argv))
		return 1;

	if(pipe(pipes))
		return 1;

	child_pid = fork();
	if(child_pid < 0)
		return 1;
	else if(child_pid == 0) { //Child

		// Open a file descriptor to /dev/null. I don't believe this needs to be closed.
		int dev_null = open("/dev/null", O_WRONLY);
		if (dev_null == -1 )
			FATAL_MSG("Couldn't open /dev/null for child process.");

		close(pipes[1]); // close the in side of the pipe for the child
		// connect read side of pipe to child's stdin, closing the in side of the pipe for the child
		dup2(pipes[0], STDIN_FILENO);
		close(pipes[0]); // close fd attached to out side of pipe

		// redirect child's stdout/stderr to devnull
		dup2(dev_null, STDOUT_FILENO);
		dup2(dev_null, STDERR_FILENO);

		// fd 1/2 now point to /dev/null, so it stays open.
		close(dev_null);

		execv(executable, argv);
		exit(EXIT_FAILURE);
	} // back to parent code

	close(pipes[0]);

	// Write the fuzz input to the child, from the parent.
	while (total_written < input_length)
	{
		result = write(pipes[1], input + total_written, input_length - total_written);
		if (result > 0)
			total_written += result;
		else if (result < 0 && errno != EAGAIN) //Error, then break
			break;
	}

	close(pipes[1]);

	// If the child stopped accepting input (write failed)
	if(total_written != input_length)
	{
		kill(child_pid, 9);
		wait(&status);
		return 1;
	}

	free(executable);
	for(i = 0; argv[i]; i++)
		free(argv[i]);
	free(argv);

	*process_out = child_pid;
	return 0;
}

#endif //!_WIN32
