#include <stdio.h>

void save(char* a, char* b){printf("123456");}
void takeaway(char* a){printf("654321");}
void stealkey(){printf("abcdef");}
void fakekey(long long a){printf("fedcba");}
void run(){printf("888888");}

int B4ckDo0r(){
	save("colin", "colin");
	save("colin", "colin");
	save("colin", "colin");
	save("colin", "colin");
	save("colin", "colin");
	save("colin", "colin");
	save("colin", "colin");
	
	save("\x00", "colin");
	stealkey();
	fakekey(-0x1090F2);
	run();
	return 0;
}
