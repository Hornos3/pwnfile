//
// Created by root on 23-4-14.
//
#include <sys/syscall.h>

char tip_string[] = "Successfully called patched scanf\n";

int patch_scanf(const char* a, char* b){
    int ret = 0;
    asm(
            "mov rdi, 0\n"
            "mov rsi, %1\n"
            "mov rdx, 80\n"
            "mov rax, 0\n"
            "syscall\n"
            "mov %0, eax\n"
            "mov rdi, 1\n"
            "mov rsi, %2\n"
            "mov rdx, 35\n"
            "mov rax, 1\n"
            "syscall\n"
            :"=r"(ret)
            :"r"(b), "r"(tip_string)
            :"rdi", "rsi", "rdx", "rax"
            );
    return ret;
}