#include <stdio.h>
#include <stdlib.h>

int main(){
	srand(0x41414141);
	for(int i=0; i<50; i++){
		printf("%d,", rand() % 6 + 1);
	}
	return 0;
}