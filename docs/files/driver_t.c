struct driver
{
  void (*cleanup)(void * driver_state);
  int (*test_input)(void * driver_state, char * buffer, size_t length);
  void * state;
};
typedef struct driver driver_t;
