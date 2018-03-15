struct instrumentation
{
  void *(*create)(char * options, char * state);
  void(*cleanup)(void * instrumentation_state);
  void *(*merge)(void * instrumentation_state,
    void * other_instrumentation_state);
  char * (*get_state)(void * instrumentation_state);
  void(*free_state)(char * state);
  int(*set_state)(void * instrumentation_state, char * state);
  int(*enable)(void * instrumentation_state, HANDLE * process,
  char * cmd_line, char * input, size_t input_length);
  int(*is_new_path)(void * instrumentation_state, int * process_status);

  //Optional
  int (*get_module_info)(void * instrumentation_state, int index,
    int * is_new, char ** module_name, char ** info, int * size);
  instrumentation_edges_t * (*get_edges)(void * instrumentation_state,
    int index);
};
typedef struct instrumentation instrumentation_t;
