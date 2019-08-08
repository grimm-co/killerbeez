#include <string.h>
#include <stdio.h>
#include <unistd.h>

#if defined(PERSIST) || defined(DEFERRED_NOHOOK)
#include <forkserver.h>
#endif

int test_func()
{
  char buffer[4];
  char * nil = NULL;
  FILE * fp = stdin;
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

#ifdef DEFERRED_NOHOOK
  KILLERBEEZ_INIT();
#endif

#ifdef PERSIST
  while(KILLERBEEZ_LOOP()) {
#endif

#ifdef HANG
    while(1);
#endif

    test_func();
#ifdef PERSIST
  }
#endif

  return 0;
}
