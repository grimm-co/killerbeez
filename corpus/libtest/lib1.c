#include <stdio.h>

int test_func1(char * buffer)
{
  char * nil = NULL;

  if (buffer[0] == 'A')
  {
    if (buffer[1] == 'B')
    {
      if (buffer[2] == 'C')
      {
        if (buffer[3] == 'D')
        {
          *nil = 0;
        }
        else
        {
          puts("lib1 Wrong 3");
        }
      }
      else
      {
        puts("lib1 Wrong 2");
      }
    }
    else
    {
      puts("lib1 Wrong 1");
    }
  }
  else
  {
    puts("lib1 Wrong 0");
  }

  return 0;
}

