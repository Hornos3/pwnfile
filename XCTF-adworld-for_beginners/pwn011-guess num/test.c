#include <stdio.h>
#include <stdlib.h>

int main(){
	srand(0xffffffff);
	for(int i=0; i<10; i++){
		printf("%d,", rand() % 6 + 1);
	}
	printf("\n");
}
// 4, 5, 5, 4, 3, 1, 5, 4, 3, 3