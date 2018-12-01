#include <string.h>
#include <stdio.h>
#include <unistd.h>

int test_func()
{
  char buffer[4];
  char * nil = NULL;
  memset(buffer, 0, 4);
  read(0, buffer, sizeof(buffer));

  if (buffer[0] == 'A')
  {
    if (buffer[1] == 'B')
    {
      if (buffer[2] == 'C')
      {
        if (buffer[3] == 'D')
        {
#ifdef HANG
					while(1) {}
#endif
          *nil = 'E';
        }
        else
        {
          puts("Wrong 3");
        }
      }
      else
      {
        puts("Wrong 2");
      }
    }
    else
    {
      puts("Wrong 1");
    }
  }
  else
  {
    puts("Wrong 0");
  }

  return 0;
}


int main()
{
#ifdef SLOW_STARTUP
  sleep(5);
#endif

#ifdef DEFERRED
  __AFL_INIT();
#endif

#ifdef PERSIST
  while(__AFL_LOOP()) {
#endif

    test_func();

#ifdef PERSIST
  }
#endif

  return 0;
}
