#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable(){
	char buffer[8];
	gets(buffer);
}

void getshell(){
	system("/bin/sh");
}

int main(){
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stderr, 0, 2, 0);
	setvbuf(stdin, 0, 2, 0);
	printf("Have you heard of stack overflow?");
	vulnerable();
	printf("It seems that you know nothing about it.");
	return 0;
}
