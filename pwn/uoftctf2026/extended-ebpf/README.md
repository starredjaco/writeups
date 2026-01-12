# extended eBPF

## TL; DR

Take advantage of a vulnerable eBPF verifier patch to abuse a vulnerability in the LSH implementation to create a confusion register and leverage an OOB read/write to LPE with ALU sanitation disabled

## Challenge Description

This challenge was part of UofTCTF 2026.

> I extended the eBPF because its cool.

- Category: **pwn**

## Exploitation
### Initial setup
We are given a list of common files in kernel exploitation challenges:

```console
root@ubuntu:/home/lkt/Desktop/ctf/uoftctf/eebpf# ls -l
total 19740
-rw-r--r-- 1 root root  7480320 ene  4 08:58 bzImage
-rw-r--r-- 1 root root      798 ene  4 08:54 chall.patch
-rw-r--r-- 1 root root      547 dic 31 03:10 Dockerfile
-rw-r--r-- 1 root root  2665855 dic 31 03:10 initramfs.cpio.gz
-rwxr-xr-x 1 root root      267 dic 31 03:17 start-qemu.sh
```

As always, we will interact with the kernel by creating a C solver. In this case we are not going to exploit a vulnerable kernel module, as we can see there is `chall.patch`:

```c
diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 24ae8f33e5d7..e5641845ecc0 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -13030,7 +13030,7 @@ static int retrieve_ptr_limit(const struct bpf_reg_state *ptr_reg,
 static bool can_skip_alu_sanitation(const struct bpf_verifier_env *env,
 				    const struct bpf_insn *insn)
 {
-	return env->bypass_spec_v1 || BPF_SRC(insn->code) == BPF_K;
+	return true;
 }
 
 static int update_alu_sanitation_state(struct bpf_insn_aux_data *aux,
@@ -14108,7 +14108,7 @@ static bool is_safe_to_compute_dst_reg_range(struct bpf_insn *insn,
 	case BPF_LSH:
 	case BPF_RSH:
 	case BPF_ARSH:
-		return (src_is_const && src_reg->umax_value < insn_bitness);
+		return (src_reg->umax_value < insn_bitness);
 	default:
 		return false;
 	}
```

This patch implements 2 major modifications in the implementation of the Linux eBPF verifier. I will refer now (and later on) to [this blog](https://chomp.ie/Blog+Posts/Kernel+Pwning+with+eBPF+-+a+Love+Story) by chompie, that is the one I used to learn throughout the CTF about eBPF internals.

### Absolute basics of eBPF

#### Intro and security measures
eBPF provides a way of creating and executing kernel level applications from userland as a non-privileged user. As you would think this can be dangerous, and that is the reason why eBPF implements a lot of security measures around its functionality. The verifier will analyze the program, creating a control flow graph and monitorizing the content of the registers. This will be a **static** analysis, meaning he doesn't really know the content of each register, this is the important part. It will keep track of the contents by creating specific ranges: 

From [Kernel Pwning with eBPF - a Love Story](https://chomp.ie/Blog+Posts/Kernel+Pwning+with+eBPF+-+a+Love+Story):
- ``umin_value``, ``umax_value`` store the min/max value of the register when interpreted as an unsigned (64 bit) integer
- ``smin_value``, ``smax_value`` store the min/max value of the register when interpreted as a signed (64 bit) integer.
- ``u32_min_value``, ``u32_max_value`` store the min/max value of the register when interpreted as an unsigned (32 bit) integer.
- ``s32_min_value``, ``s32_max_value`` store the min/max value of the register when interpreted as a signed (32 bit) integer.
- ...

There are two types of registers **pointer** register and **scalar** register, the first one is the one that holds pointers and the verifier will have flags to mark them to its type, making sure we don't execute a memory access instruction with a scalar register. The scalar registers are the ones who hold constant numbers. The verifier will make sure the arithmetic operations (ADD, SUB, MUL, AND, OR, etc.) are safe:

- **Pointer + Pointer**: Blocked.
- **Pointer + Scalar** : Checks if the result is inside the `map_size` bounds (we will talk about this later).
- **Scalar + Scalar** : Allowed.

Keep in mind that when doing this checks the verifier **does not know** the actual contents of the registers, so for example if we execute an instruction `BPF_BPF_JMP_IMM(BPF_JGE, BPF_REG_1, 0, 20) (jump 20 instructions forward if r1 > 2)`, and the branch is not taken, the state will be updated to a new range, thinking that r1 is now ``(0, 1)`` (in the unsigned ranges). This is done to prevent OOB accesses, there are more rules but for now this is what we need to understand.

After passing this checks, there is another security measure called **ALU Sanitation**, this will patch the actual eBPF bytecode being executed to check if the state of the verifier matches with the actual state in runtime.

#### Interacting with userland
eBPF implements a data type called `bpf_map`, by creating a map you can pass values to your eBPF bytecode and it can get accessed by the kernel safely. The map has a fixed size, and that is the max bounds check the verifier is doing `map_size`. There are a lot of map types, but the most relevant for this challenge are `BPF_MAP_TYPE_ARRAY` and `BPF_MAP_TYPE_ARRAY_OF_MAPS`. The first one is a standard array, we will create a map with this type setting a `key_size`, for example 4 bytes as an integer for the index of the array, and `value_size`. As well as the `max_entries` of the structure. Every operation on the map will be executed by the syscall `bpf`, that will accept as the first parameter a specific `cmd` such as `BPF_MAP_UPDATE_ELEM` to update the array, `BPF_MAP_LOOKUP_ELEM`, to read from it, etc.

I will not dive too much into eBPF internals in this writeup, you can get more information about it in the blog I mentioned before, [this one](https://www.zerodayinitiative.com/blog/2020/4/8/cve-2020-8835-linux-kernel-privilege-escalation-via-improper-ebpf-program-verification), or in the [official documentation](https://docs.ebpf.io/).

### Back to the challenge

Analyzing the patch we see that ALU Sanitation is **completely disabled** so that takes out a big security measure. The other modification is a bit more complex, it is modifying the implementation of the left, right and signed right shifts.

The full function being modified is :

```c
static bool is_safe_to_compute_dst_reg_range(struct bpf_insn *insn,
					     const struct bpf_reg_state *src_reg)
{
	bool src_is_const = false;
	u64 insn_bitness = (BPF_CLASS(insn->code) == BPF_ALU64) ? 64 : 32;

	if (insn_bitness == 32) {
		if (tnum_subreg_is_const(src_reg->var_off)
		    && src_reg->s32_min_value == src_reg->s32_max_value
		    && src_reg->u32_min_value == src_reg->u32_max_value)
			src_is_const = true;
	} else {
		if (tnum_is_const(src_reg->var_off)
		    && src_reg->smin_value == src_reg->smax_value
		    && src_reg->umin_value == src_reg->umax_value)
			src_is_const = true;
	}

	switch (BPF_OP(insn->code)) {
	case BPF_ADD:
	case BPF_SUB:
	case BPF_NEG:
	case BPF_AND:
	case BPF_XOR:
	case BPF_OR:
	case BPF_MUL:
		return true;

	/* Shift operators range is only computable if shift dimension operand
	 * is a constant. Shifts greater than 31 or 63 are undefined. This
	 * includes shifts by a negative number.
	 */
	case BPF_LSH:
	case BPF_RSH:
	case BPF_ARSH:
		return (src_is_const && src_reg->umax_value < insn_bitness);
	default:
		return false;
	}
}
```

It sets `src_is_const` if the value of the register being shifted is _constant_, this means, its minimum range is equal to its maximum range. Only if the value is constant it will execute the shift, this check is really important because in the actual LSH implementation we can see that it will use the `umin_value` to do the shifting:

```c
static void scalar_min_max_lsh(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
...
	dst_reg->var_off = tnum_lshift(dst_reg->var_off, umin_val);
...
}
```

In our patch, the line `return (src_is_const && src_reg->umax_value < insn_bitness);` is changed to `return (src_reg->umax_value < insn_bitness);`, removing completely the constant value check. This creates a big vulnerability in the eBPF verifier, because this means that the shift will be **always** executed with the minimum value, even when there is a different maximum value. So if we somehow create a situation where ``R1 = 1`` and the verifier thinks ``R1 = (0, 1)`` he will execute the left shift with 0, but in reality the shift will be executed with 1. `R1 << 0 (in the verifier)` vs `R1 << 1 (runtime)`.

### Exploitation

I will not explain here all the eBPF setup in C, but we created some helper functions that using the `bpf` syscall can interact with the maps (create, update and lookup). Also, there is a [bpf.h](assets/bpf.h) file where we have all this functions, along with the actual eBPF bytecode instruction definitions. I took these from [here](https://github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490/blob/main/include/bpf_defs.h).

The first thing we will do is create a map and update it to set its first value to `1`, this will be our shift value. Because we load it from the map, the verifier does not know its real value, so he sets a range (umin, umax).

```c
/* int create_map(int map_type, uint32_t key_size, uint64_t value_size, uint32_t max_entr, int inner_map_fd) */
int map_fd = create_map(BPF_MAP_TYPE_ARRAY, 0x4, 0x8, 0x3, 0); /* uint64_t map_array[3] */
uint64_t shift = 1;
update_map(map_fd, 0, &shift, BPF_ANY); /* map_array[0] = shift */
```

Then in our bytecode we will retrieve this value, and using a JMP instruction, we will set the verifier's state to `SHIFT = (0, 1)`

```c
BPF_JMP_IMM(BPF_JGE, SHIFT, 2, 19) /* if (SHIFT > 2); pc += 19; 
```

Because the branch is not taken (because `SHIFT = 1`), the verifier will now update the range to (0, 1), because those are the unsigned values below 2. Now we just have to execute the left shift with a register that holds 1.

```c
...
BPF_MOV64_IMM(VULN, 1),
BPF_ALU64_REG(BPF_LSH, VULN, SHIFT), // 1 << (0, 1)
BPF_ALU64_IMM(BPF_SUB, VULN, 1),
...

```

**What the verifier thinks happened**:

I.      VULN = 1
II.     1 << 0 = 1
III.    1 - 1 = 0

        VULN == 0
**What happens in runtime**:

I.      VULN = 1
II.     1 << 1 = 2
III     1 - 1 = 0

        VULN == 1

This is critical, because now we can do **pointer+scalar** MUL operations bypassing every verifier restriction. If we now multiply  `0x1337 * VULN`, the verifier will think the result is 0 and that is safe to add to a pointer, but in reality we will be adding 0x1337 into it.