struct driver
{
  void (*cleanup)(void * driver_state);
  int (*test_input)(void * driver_state, char * buffer, size_t length);
  int(*test_next_input)(void * driver_state);
  void *(*get_last_input)(void * driver_state, int * length);
  void * state;
};
typedef struct driver driver_t;
