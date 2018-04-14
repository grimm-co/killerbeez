#include <driver.h>
#include <driver_factory.h>
#include <instrumentation.h>
#include <instrumentation_factory.h>
#include <jansson_helper.h>
#include <utils.h>

#include <stdio.h>
#include <stdlib.h>

void usage(char * program_name)
{
	char * help_text;
	printf(
		"Usage: %s driver_name instrumentation_name input_file output_file [options]\n"
		"\n"
		"Required:\n"
		"\t driver_name                   The driver framework used to run the target program\n"
		"\t instrumentation_name          The instrumenation framework to use to determine the path a program took\n"
		"\t input_file                    The input to the target program\n"
		"\t output_file                   Write the edges to the given file.  The given path will be used as a prefix when recording multiple modules\n"
		"Options:\n"
		"\t -b                            When writing the edges to a file, write them in binary (rather than human readable text)\n"
		"\t -d driver_options             Set the options for the driver\n"
		"\t -i instrumentation_options    Set the options for the instrumentation\n"
		"\t -l logging_options            Set the options for logging\n"
		"\t -n num_iterations             The number of iterations to run [5 per file].  Edges which are only in one run will be excluded\n"
		"\t -p                            Record the edges for each module independently\n"
		"\n",
		program_name
	);

#define PRINT_HELP(x, y) \
	x = y;               \
	if(x) {              \
		puts(x);         \
		free(x);         \
	}

	PRINT_HELP(help_text, logging_help());
	PRINT_HELP(help_text, driver_help());
	PRINT_HELP(help_text, instrumentation_help());
	exit(1);
}

struct edge_counts
{
	instrumentation_edge_t edge;
	int count;
};

void record_edges(instrumentation_edges_t * edges, struct edge_counts ** all_runs, int * all_runs_num_edges)
{
	int this_run_num_edges;
	instrumentation_edge_t *this_run;
	int i, j, found;

	this_run = NULL;
	this_run_num_edges = 0;

	for (i = 0; i < edges->num_edges; i++)
	{
		//First check for the edge in this run
		found = 0;
		for (j = 0; j < this_run_num_edges; j++)
		{
			if (this_run[j].to == edges->edges[i].to && this_run[j].from == edges->edges[i].from)
			{
				found = 1;
				break;
			}
		}
		if (found) //If we've already recorded this one, just skip it
			continue;

		//If we haven't recorded this edge for this run before, add it to the this_run list
		this_run_num_edges++;
		this_run = (instrumentation_edge_t *)realloc(this_run, this_run_num_edges * sizeof(instrumentation_edge_t));
		this_run[this_run_num_edges - 1].to = edges->edges[i].to;
		this_run[this_run_num_edges - 1].from = edges->edges[i].from;

		//Now check to see if it's been recorded already in other runs
		for (j = 0; j < *all_runs_num_edges; j++)
		{
			if ((*all_runs)[j].edge.to == edges->edges[i].to && (*all_runs)[j].edge.from == edges->edges[i].from)
			{
				(*all_runs)[j].count++;
				found = 1;
				break;
			}
		}

		//If we haven't found this edge before, add it to the all_runs list
		if (!found)
		{
			*all_runs_num_edges = *all_runs_num_edges + 1;
			*all_runs = (struct edge_counts *)realloc(*all_runs, *all_runs_num_edges * sizeof(struct edge_counts));
			(*all_runs)[*all_runs_num_edges - 1].edge.to = edges->edges[i].to;
			(*all_runs)[*all_runs_num_edges - 1].edge.from = edges->edges[i].from;
			(*all_runs)[*all_runs_num_edges - 1].count = 1;
		}
	}
	free(this_run);
}

#define MAX_MODULES 512

int main(int argc, char ** argv)
{
	driver_t * driver;
	instrumentation_t * instrumentation;
	char *driver_name, *driver_options = NULL,
		*input_filename = NULL, *seed_buffer = NULL, *output_file = NULL,
		*instrumentation_name = NULL, *instrumentation_options = NULL,
		*logging_options = NULL;
	void * instrumentation_state = NULL;
	int seed_length, iteration;
	instrumentation_edges_t * edges;
	instrumentation_edge_t *deterministic_edges;
	struct edge_counts * all_runs[MAX_MODULES];
	int all_runs_num_edges[MAX_MODULES];
	int i, j, deterministic_edges_num_edges, num_modules = 0;
	char * module_name = NULL;
	char * module_names[MAX_MODULES];
	char filename_buffer[MAX_PATH];
	FILE * fp;

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Parse Arguments ///////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	//Default options
	int num_iterations = 5;
	int binary_mode = 0;
	int per_module_edges = 0;

	if (argc < 5)
	{
		usage(argv[0]);
	}

	driver_name = argv[1];
	instrumentation_name = argv[2];
	input_filename = argv[3];
	output_file = argv[4];
	for (int i = 5; i < argc; i++)
	{
		IF_ARG_SET_TRUE("-b", binary_mode)
		ELSE_IF_ARG_OPTION("-d", driver_options)
		ELSE_IF_ARG_OPTION("-i", instrumentation_options)
		ELSE_IF_ARG_OPTION("-l", logging_options)
		ELSE_IF_ARGINT_OPTION("-n", num_iterations)
		ELSE_IF_ARG_SET_TRUE("-p", per_module_edges)
		else
		{
			if (strcmp("-h", argv[i]))
				printf("Unknown argument: %s\n", argv[i]);
			usage(argv[0]);
		}
	}

	if (setup_logging(logging_options))
	{
		printf("Failed setting up logging, exiting\n");
		return 1;
	}

	if (num_iterations < 1)
		FATAL_MSG("Bad iteration number (%d).  Must have a iteration count 1 or greater.", num_iterations);

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Ojbect Setup //////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	instrumentation = instrumentation_factory(instrumentation_name);
	if (!instrumentation)
		FATAL_MSG("Unknown instrumentation '%s'", instrumentation_name);
	if (!instrumentation->get_edges)
		FATAL_MSG("Instrumentation '%s' does not support the ability to get a list of edges", instrumentation_name);

	if (instrumentation_options)
		instrumentation_options = add_int_option_to_json(instrumentation_options, "edges", 1);
	else
		instrumentation_options = "{\"edges\": 1}";

	instrumentation_state = instrumentation->create(instrumentation_options, NULL);
	if (!instrumentation_state)
		FATAL_MSG("Bad options/state for instrumentation %s", instrumentation_name);

	driver = driver_instrumentation_factory(driver_name, driver_options, instrumentation, instrumentation_state);
	if (!driver)
		FATAL_MSG("Unknown driver '%s' or bad options: %s", driver_name, driver_options ? driver_options : "none");

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Main Test Loop ////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	//Read the seed file
	seed_length = read_file(input_filename, &seed_buffer);
	if (seed_length <= 0) //Couldn't read file, or empty file
		FATAL_MSG("Unable to open the input file \"%s\"", input_filename);

	memset(&all_runs, 0, sizeof(all_runs));
	memset(&all_runs_num_edges, 0, sizeof(all_runs_num_edges));
	memset(&module_names, 0, sizeof(module_names));
	if (!per_module_edges)
	{
		num_modules = 1;
	}
	else
	{
		while (!instrumentation->get_module_info(instrumentation_state, num_modules, NULL, &module_name, NULL, NULL))
		{
			if (num_modules >= MAX_MODULES)
				FATAL_MSG("Too many modules specified, %d specified, %d maximum", num_modules, MAX_MODULES);
			module_names[num_modules] = module_name;
			num_modules++;
		}
	}

	for (iteration = 0; iteration < num_iterations; iteration++)
	{
		driver->test_input(driver->state, seed_buffer, seed_length);
		for (i = 0; i < num_modules; i++)
		{
			edges = instrumentation->get_edges(instrumentation_state, i);
			if (!edges)
				FATAL_MSG("Instrumentation failed to get the program edges from the tested process.");
			record_edges(edges, &all_runs[i], &all_runs_num_edges[i]);
		}
	}
	free(seed_buffer);

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Reduce the list of edges to just the ones in every run, and store it //////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	for (i = 0; i < num_modules; i++)
	{
		deterministic_edges = NULL;
		deterministic_edges_num_edges = 0;
		for (j = 0; j < all_runs_num_edges[i]; j++)
		{
			if (all_runs[i][j].count == num_iterations) //if the edge was found in all the iterations
			{
				deterministic_edges_num_edges++;
				deterministic_edges = (instrumentation_edge_t *)realloc(deterministic_edges, deterministic_edges_num_edges * sizeof(instrumentation_edge_t));
				deterministic_edges[deterministic_edges_num_edges - 1].to = all_runs[i][j].edge.to;
				deterministic_edges[deterministic_edges_num_edges - 1].from = all_runs[i][j].edge.from;
			}
		}

		if (!module_names[i])
			snprintf(filename_buffer, sizeof(filename_buffer) - 1, "%s", output_file);
		else
			snprintf(filename_buffer, sizeof(filename_buffer) - 1, "%s_%s.%s", output_file, module_names[i], binary_mode ? "dat" : "txt");

		fp = fopen(filename_buffer, "wb+");
		if (fp == NULL)
			FATAL_MSG("Couldn't open the file %s to write the edges to for %s", filename_buffer, module_names[i] ? module_names[i] : "the program");

		for (j = 0; j < deterministic_edges_num_edges; j++)
		{
			if (binary_mode)
				fwrite(&deterministic_edges[j], sizeof(instrumentation_edge_t), 1, fp);
			else
				fprintf(fp, "%016x:%016x\n", deterministic_edges[j].from, deterministic_edges[j].to);
		}
		fclose(fp);

		free(deterministic_edges);
	}

	//////////////////////////////////////////////////////////////////////////////////////////////////////
	// Cleanup ///////////////////////////////////////////////////////////////////////////////////////////
	//////////////////////////////////////////////////////////////////////////////////////////////////////

	//Cleanup the objects and exit
	driver->cleanup(driver->state);
	instrumentation->cleanup(instrumentation_state);
	free(driver);
	free(instrumentation);
	return 0;
}
