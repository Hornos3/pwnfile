#include <stdio.h>

int main(){
	char buf[40];
	fgets(buf, 40, stdin);
	for(int i=0; i<5; i++){
		for(int j=0; j<8; j++){
			printf("%02x ", buf[i*8+j] & 0xff);
		}
		printf("\n");
	}
}