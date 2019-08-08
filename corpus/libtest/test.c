#include "libs.h"
#include <string.h>
#include <unistd.h>

int main()
{
  char buffer[4];
  memset(buffer, 0, 4);
  read(0, buffer, sizeof(buffer));

  test_func1(buffer);
  test_func2(buffer);
  return 0;
}
