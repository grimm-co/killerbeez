#include "mutator_factory.h"
#include "utils.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <dirent.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/types.h>
#endif

/**
 * Looks in a directory and retrieves a list of filenames of library files in that directory
 * @param directory - the directory to look for the library files in
 * @param num_libraries - a pointer to an int in which to return the number of library files found
 * @return - a pointer to a list of library files on success, or NULL if no library files were found
 */
static char ** get_mutator_library_filenames(char * directory, int * num_libraries)
{
	int num_files = 0;
	char ** mutator_dlls = NULL;
	char filename[MAX_PATH] ;

#ifdef _WIN32
	HANDLE file_handle;
	WIN32_FIND_DATA fdFile;
	BOOL success;

	memset(filename, 0, sizeof(filename));
	snprintf(filename, sizeof(filename) - 1, "%s\\*.dll", directory);

	success = 1;
	for (file_handle = FindFirstFile(filename, &fdFile);
		file_handle != INVALID_HANDLE_VALUE && success;
		success = FindNextFile(file_handle, &fdFile))
	{
		//Skip directories
		if (fdFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			continue;

		//Read the seed file
		memset(filename, 0, sizeof(filename));
		snprintf(filename, sizeof(filename) - 1, "%s\\%s", directory, fdFile.cFileName);

		num_files++;
		mutator_dlls = (char **)realloc(mutator_dlls, num_files * sizeof(char *));
		mutator_dlls[num_files - 1] = strdup(filename);
	}
	FindClose(file_handle);
#else

#ifdef __APPLE__
	char * extension = "dylib";
#else
	char * extension = "so";
#endif
	struct dirent *dp;
	DIR *dfd;
	struct stat stbuf;

	if ((dfd = opendir(directory)) != NULL)
	{
		while ((dp = readdir(dfd)) != NULL)
		{
			snprintf(filename, sizeof(filename), "%s/%s", directory, dp->d_name);
			if(stat(filename, &stbuf ) == -1)
				continue;

			if ((stbuf.st_mode & S_IFMT) == S_IFDIR)
				continue; // Skip directories

			if (!strncmp(&filename[strlen(filename)-strlen(extension)], extension, strlen(extension))) {
				num_files++;
				mutator_dlls = (char **)realloc(mutator_dlls, num_files * sizeof(char *));
				mutator_dlls[num_files - 1] = strdup(filename);
			}
		}
	}
	closedir(dfd);

#endif

	*num_libraries = num_files;
	return mutator_dlls;
}

UTILS_API mutator_t * mutator_factory(char * mutator_filename)
{
	void(*init_ptr)(mutator_t *);
	mutator_t * ret;

#ifdef _WIN32
	HINSTANCE handle = LoadLibrary(mutator_filename);
#else
	void * 	handle = dlopen(mutator_filename, RTLD_LAZY);
#endif
	if (!handle) //Couldn't load the requested mutator library
		return NULL;

#ifdef _WIN32
	init_ptr = (void(*)(mutator_t *))GetProcAddress(handle, "init");
#else
	init_ptr = (void(*)(mutator_t *))dlsym(handle, "init");
#endif
	if (!init_ptr) { //The library didn't have our init function
#ifdef _WIN32
		FreeLibrary(handle);
#else
		dlclose(handle);
#endif
		return NULL;
	}

	//Call the mutator's init function to initailize the mutators struct
	ret = (mutator_t *)malloc(sizeof(mutator_t));
	init_ptr(ret);
	return ret;
}

static void generate_mutator_filename(char * mutator_directory, char * mutator_type, int include_mutator, char * output_filename, size_t output_filename_length)
{
#ifdef _WIN32
	char * extension = "dll", *prefix = "";
#elif defined(__APPLE__)
	char * extension = "dylib", *prefix = "lib";
#else
	char * extension = "so", *prefix = "lib";
#endif

	memset(output_filename, 0, output_filename_length);
	if(mutator_directory) {
		if (include_mutator)
			snprintf(output_filename, output_filename_length, "%s/%s%s_mutator.%s", mutator_directory, prefix, mutator_type, extension);
		else
			snprintf(output_filename, output_filename_length, "%s/%s%s.%s", mutator_directory, prefix, mutator_type, extension);
	} else {
		if (include_mutator)
			snprintf(output_filename, output_filename_length, "%s%s_mutator.%s", prefix, mutator_type, extension);
		else
			snprintf(output_filename, output_filename_length, "%s%s.%s", prefix, mutator_type, extension);
	}
}

/**
 * This function obtains a mutator_t object by calling the mutator specified by mutator's init method.
 * @param mutator_directory - the directory to load the mutator library file from.
 * @param mutator_type - the name of the mutator that should be created.
 * @return - a instrumentation_t object of the specified type on success or NULL on failure
 */
UTILS_API mutator_t * mutator_factory_directory(char * mutator_directory, char * mutator_type)
{
	char filename[MAX_PATH];
	mutator_t * ret;

	generate_mutator_filename(mutator_directory, mutator_type, 0, filename, sizeof(filename));
	ret = mutator_factory(filename);
	if (!ret) {
		generate_mutator_filename(mutator_directory, mutator_type, 1, filename, sizeof(filename));
		ret = mutator_factory(filename);
	}
	return ret;
}

/**
 * This function returns help text for all the mutators found in the specified mutator directory.  This help text will
 * describe the mutators and any options that can be passed to their create functions.
 * @param mutator_directory - The directory to look for mutator libraries in
 * @return - a newly allocated string containing the help text.
 */
UTILS_API char * mutator_help(char * mutator_directory)
{
#ifdef _WIN32
	HINSTANCE handle;
#else
	void * handle;
#endif
	int num_libraries = 0, i;
	char ** mutator_libraries;
	int(*help_ptr)(char **);
	char * text = NULL, * new_text = NULL;

	mutator_libraries = get_mutator_library_filenames(mutator_directory, &num_libraries);
	if (!num_libraries)
	{
		printf("ERROR: Could not find any mutators.  Please ensure that the directory %s contains the mutator library files", mutator_directory);
		return NULL;
	}

	text = strdup("\nMutator Options:\n\n");
	for (i = 0; i < num_libraries; i++)
	{
#ifdef _WIN32
		handle = LoadLibrary(mutator_libraries[i]);
#else
		handle = dlopen(mutator_libraries[i], RTLD_LAZY);
#endif
		if (!handle) //if we couldn't load the library, just continue
			continue;
#ifdef _WIN32
		help_ptr = (int(*)(char **))GetProcAddress(handle, "help");
#else
		help_ptr = (int(*)(char **))dlsym(handle, "help");
#endif
		if (help_ptr) {//The library has a help function
			if (!help_ptr(&new_text)) //Call help() and check for failure
			{
				text = (char *)realloc(text, strlen(text) + strlen(new_text) + 1);
				strcat(text, new_text);
				free(new_text);
			}
		}
#ifdef _WIN32
		FreeLibrary(handle);
#else
		dlclose(handle);
#endif
		handle = NULL;
	}
	text = (char *)realloc(text, strlen(text) + 2);
	strcat(text, "\n");
	free(mutator_libraries);
	return text;
}
