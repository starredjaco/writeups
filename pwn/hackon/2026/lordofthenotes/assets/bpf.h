#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <errno.h>

static int bpf(int cmd, union bpf_attr *attr, unsigned int size);
static int bpf_create_ringbuf_map(size_t ringbuf_sz);
static int bpf_create_array_map(uint32_t key_size, uint64_t value_size, uint32_t max_entr);
static int bpf_update_map(int map_fd, uint64_t key, void* value, uint64_t flags);
static int bpf_lookup_map(int map_fd, uint64_t key, void* outval);
static int bpf_prog_trigger(int prog_fd, char *data, size_t datalen);
static int bpf_prog_load(struct bpf_insn insns[], uint64_t insn_cnt);

#define VERIFIER_LOG_SIZE 0x100000

static int bpf(int cmd, union bpf_attr *attr, unsigned int size){
    return syscall(__NR_bpf, cmd, attr, size);
}

static int bpf_create_ringbuf_map(size_t ringbuf_sz){
    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_RINGBUF,
        .max_entries = ringbuf_sz
    };

    int map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));

    if (map_fd < 0){ perror("[-] Error creating map"); exit(1);}

    return map_fd;
}


static int bpf_create_array_map(uint32_t key_size, uint64_t value_size, uint32_t max_entr){

    union bpf_attr attr = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = key_size,
        .value_size = value_size,
        .max_entries = max_entr
    };


    int map_fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));

    if (map_fd < 0){ perror("[-] Error creating map"); exit(1);}

    return map_fd;
}

static int bpf_update_map(int map_fd, uint64_t key, void* value, uint64_t flags){
    
    int ret = -1;

    uint64_t kv = key;

    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t)&kv,
        .value = (uint64_t)value,
        .flags = flags
    };

    ret = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));

    return ret;

}

static int bpf_lookup_map(int map_fd, uint64_t key, void* outval){
    int ret = -1;

    union bpf_attr attr = {
        .map_fd = map_fd,
        .key = (uint64_t)&key,
        .value = (uint64_t)outval
    };

    ret = bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
    return ret;
}

static int bpf_prog_trigger(int prog_fd, char *data, size_t datalen){
    int socks[2] = {0};

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) != 0){
        perror("[-] socketpair failed");
        goto done;
    }

    if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(int)) != 0 ){
        perror("[-] setsockopt failed");
        goto done;
    }

    printf("[!] Triggering prog_fd %d with payload size %ld\n", prog_fd, datalen);

    if(write(socks[1], data, datalen) != datalen){
        perror("write");
    }

    usleep(5000);

done:

}

static int bpf_prog_load(struct bpf_insn insns[], uint64_t insn_cnt){

    char verifier_log_buff[VERIFIER_LOG_SIZE] = {0};

    int ret = -1;
    int prog_fd = -1;

    union bpf_attr attr = 
    {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = insn_cnt,
        .insns = (uint64_t)insns,
        .license = (uint64_t)"",
        .log_level = 2,
        .log_size = VERIFIER_LOG_SIZE,
        .log_buf = (uint64_t)verifier_log_buff
    };

    prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));

    if (prog_fd < 0){
        printf("[-] Program failed! Verifier log: %s\n", verifier_log_buff);
        printf("[-] Errno: %s\n", strerror(errno));
    } else {
        printf("[!] Loaded BPF bytecode on FD: %d\n", prog_fd);
    }

    //puts(verifier_log_buff);

    return prog_fd;
}