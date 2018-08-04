struct instrumentation_edge
{
#ifdef _M_X64
  uint64_t from;
  uint64_t to;
#else
  uint32_t from;
  uint32_t to;
#endif
};
typedef struct instrumentation_edge instrumentation_edge_t;
