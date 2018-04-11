#include <string.h>
#include <stdio.h>

int main(int argc, char ** argv)
{
	char buffer[4];
	char * nil = NULL;
	FILE * fp = stdin;

	if (argc > 1)
	{
		fp = fopen(argv[1], "rb+");
		if (!fp)
		{
			puts("Couldn't open file\n");
			return 1;
		}
	}

	memset(buffer, 0, 4);
	fread(buffer, 1, 4, fp);
	fclose(fp);

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

	//puts("Sleeping now");
	//Sleep(1000 * 100);
	//while (1) {}

    return 0;
}
