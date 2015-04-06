#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <map>
#include <string>

using namespace std;

void sequ_cpy(char *dst, char *src, int num)
{
	int len = 0;
	
	strcpy(dst, src);
	len = strlen(dst);
	while(num - len > 0)
	{
		dst[len] = ' ';
		len++;
	}
	dst[len] = '\0';
}

int main(int argc, char *argv[])
{
	char line[1024];
	FILE *fprd, *fpwr;	
	
	fpwr = fopen("dst.txt", "w");
	if (!fprd)
	{
		printf("open dst.txt error\n");
		return 0;
	}
	
	map <string, int> list;
	int index = 0;
	while (++index < argc)
	{
		char call_name[64];
		fprd = fopen(argv[index], "r");
		if (!fprd)
		{
			printf("open %s error\n", argv[index]);
			fclose(fpwr);
			return -1;
		}
		
		while((fgets(line, 1024, fprd)) != NULL)
		{
			memset(call_name, 0, sizeof(call_name));		
			sscanf(line, "#define __NR_%[a-zA-Z0-9_]", call_name);
			list[call_name] = 1;
			memset(line, 0, sizeof(line));
		}
		fclose(fprd);
	}
	
	map <string, int>::iterator it;
	for(it = list.begin(); it != list.end();it++)
	{		
		memset(line, 0, sizeof(line));
		sprintf(line, "\"%s\":", (*it).first.c_str());
		sequ_cpy(line, line, 32);
		sprintf(&line[32], "C.__NR_%s,\r\n", (*it).first.c_str());
		
		//printf("%s\n", line);
	    fwrite(line, 1, strlen(line), fpwr);
	}
    fclose(fpwr);
	return 0;
	
	
	
	
	
	return 0;
}