//
// Created by root on 23-4-15.
//
void myprintf(const char* x, char* y){
    asm(
        "mov rdi, 0\n"
        "mov rsi, %0\n"
        "mov rdx, 80\n"
        "mov rax, 0\n"
        "syscall\n"
        :
        :"r"(y)
        :"rdi", "rsi", "rdx", "rax"
        );
}