typedef struct mutator
{
  void * (*create)(char * options, char * state, char * input,
    size_t input_length);
  void(*cleanup)(void * mutator_state);

  int(*mutate)(void * mutator_state, char * buffer,
    size_t buffer_length);
  int(*mutate_extended)(void * mutator_state, char * buffer,
    size_t buffer_length, uint64_t flags);

  char * (*get_state)(void * mutator_state);
  void(*free_state)(char * state);
  int(*set_state)(void * mutator_state, char * state);

  int(*get_current_iteration)(void * mutator_state);
  int(*get_total_iteration_count)(void * mutator_state);
  void(*get_input_info)(void * mutator_state, int * num_inputs,
    size_t **input_sizes);

  int(*set_input)(void * mutator_state, char * new_input,
    size_t input_length);
  int(*help)(char **help_str);
} mutator_t;
