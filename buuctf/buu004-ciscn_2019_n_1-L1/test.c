#include <stdio.h>

int main(){
	float a = 11.28125;
	printf("%x", *((int*)&a));
}