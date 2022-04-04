#include <stdio.h>
#include <unistd.h>

int main(){
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 1, 0);
	char str[100];
	printf("%p", &str);
	gets(str);
	return 0;
}