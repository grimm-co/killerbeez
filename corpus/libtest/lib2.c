#include <stdio.h>

int test_func2(char * buffer)
{
  char * nil = NULL;

  if (buffer[0] == 'E')
  {
    if (buffer[1] == 'F')
    {
      if (buffer[2] == 'G')
      {
        if (buffer[3] == 'H')
        {
          *nil = 0;
        }
        else
        {
          puts("lib2 Wrong 3");
        }
      }
      else
      {
        puts("lib2 Wrong 2");
      }
    }
    else
    {
      puts("lib2 Wrong 1");
    }
  }
  else
  {
    puts("lib2 Wrong 0");
  }

  return 0;
}

