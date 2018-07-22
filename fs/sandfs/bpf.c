#ifdef CONFIG_SANDFS

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/bpf_perf_event.h>

#include "sandfs.h"

int sandfs_request_bpf_op(void *priv, struct sandfs_args *args)
{
	int ret = -ENOSYS;
	struct bpf_prog *accel_prog;

	if (!priv)
		return ret;

	accel_prog = READ_ONCE(priv);
	if (accel_prog) {
		/* run program */
		rcu_read_lock(); 
		ret = BPF_PROG_RUN(accel_prog, args);
		rcu_read_unlock();
	}

	return ret;
}

void sandfs_clear_bpf_ops(struct super_block *sb)
{
	struct bpf_prog *old_prog;

	BUG_ON(!sb || !SANDFS_SB(sb) || !SANDFS_SB(sb)->priv);

	printk(KERN_INFO "Clearing XDP operations\n");

	old_prog = xchg(&SANDFS_SB(sb)->priv, NULL);
	if (old_prog)
		bpf_prog_put(old_prog);

	printk(KERN_INFO "Cleared SANDFS ops\n");
}

int sandfs_set_bpf_ops(struct super_block *sb, int fd)
{
	struct bpf_prog *prog = NULL;
	struct bpf_prog *old_prog;
	struct sandfs_sb_info *sbi;

	BUG_ON(!sb);

	if (fd <= 0) {
		printk(KERN_ERR "Failed to setup sandfs bpf ops. "
			"Invalid prog_fd %d!\n", fd);
		return -EINVAL;
	}

	sbi = SANDFS_SB(sb);
	if (!sbi) {
		printk(KERN_ERR "Failed to setup sandfs bpf ops. "
			"NULL sb info!\n");
		return -EINVAL;
	}

	printk(KERN_INFO "Setting SANDFS bpf ops\n");

	prog = bpf_prog_get_type(fd, BPF_PROG_TYPE_SANDFS);
	if (IS_ERR(prog))
		return -1;

	old_prog = xchg(&sbi->priv, prog);
	if (old_prog)
		bpf_prog_put(old_prog);

	printk(KERN_INFO "SANDFS bpf program updated\n");
	return 0;
}

static u64 bpf_get_current_task1(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)
{
	return (long) current;
}

static const struct bpf_func_proto bpf_get_current_task_proto = {
	.func		= bpf_get_current_task1,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
};

BPF_CALL_3(bpf_probe_read_str1, void *, dst, u32, size,
       const void *, unsafe_ptr)
{
    int ret;

    /*
     * The strncpy_from_unsafe() call will likely not fill the entire
     * buffer, but that's okay in this circumstance as we're probing
     * arbitrary memory anyway similar to bpf_probe_read() and might
     * as well probe the stack. Thus, memory is explicitly cleared
     * only in error case, so that improper users ignoring return
     * code altogether don't copy garbage; otherwise length of string
     * is returned that can be used for bpf_perf_event_output() et al.
     */
    ret = strncpy_from_unsafe(dst, unsafe_ptr, size);
    if (unlikely(ret < 0))
        memset(dst, 0, size);

    return ret;
}

static const struct bpf_func_proto bpf_probe_read_str_proto = {
    .func       = bpf_probe_read_str1,
    .gpl_only   = true,
    .ret_type   = RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_RAW_STACK,
    .arg2_type  = ARG_CONST_STACK_SIZE,
    .arg3_type  = ARG_ANYTHING,
};

BPF_CALL_3(bpf_probe_read1, void *, dst, u32, size, const void *, unsafe_ptr)
{
	int ret;

	ret = probe_kernel_read(dst, unsafe_ptr, size);
	if (unlikely(ret < 0))
		memset(dst, 0, size);

	return ret;
}

static const struct bpf_func_proto bpf_probe_read_proto = {
	.func		= bpf_probe_read1,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type  = ARG_PTR_TO_RAW_STACK,
    .arg2_type  = ARG_CONST_STACK_SIZE,
	.arg3_type	= ARG_ANYTHING,
};

static __always_inline u64
__bpf_perf_event_output(struct pt_regs *regs, struct bpf_map *map,
			u64 flags, struct perf_raw_record *raw)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	unsigned int cpu = smp_processor_id();
	u64 index = flags & BPF_F_INDEX_MASK;
	struct perf_sample_data sample_data;
	struct bpf_event_entry *ee;
	struct perf_event *event;

	if (index == BPF_F_CURRENT_CPU)
		index = cpu;
	if (unlikely(index >= array->map.max_entries))
		return -E2BIG;

	ee = READ_ONCE(array->ptrs[index]);
	if (!ee)
		return -ENOENT;

	event = ee->event;
	if (unlikely(event->attr.type != PERF_TYPE_SOFTWARE ||
		     event->attr.config != PERF_COUNT_SW_BPF_OUTPUT))
		return -EINVAL;

	if (unlikely(event->oncpu != cpu))
		return -EOPNOTSUPP;

	perf_sample_data_init(&sample_data, 0, 0);
	sample_data.raw = raw;
	perf_event_output(event, &sample_data, regs);
	return 0;
}

BPF_CALL_5(bpf_perf_event_output1, struct pt_regs *, unused_regs/*FIXME*/, struct bpf_map *, map,
	   u64, flags, void *, data, u64, size)
{
	struct pt_regs regs = {0};

	struct perf_raw_record raw = {
		.frag = {
			.size = size,
			.data = data,
		},
	};

	if (unlikely(flags & ~(BPF_F_INDEX_MASK)))
		return -EINVAL;

	return __bpf_perf_event_output(&regs, map, flags, &raw);
}

static const struct bpf_func_proto bpf_perf_event_output_proto = {
	.func		= bpf_perf_event_output1,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type  = ARG_PTR_TO_STACK,
    .arg5_type  = ARG_CONST_STACK_SIZE,
};

BPF_CALL_4(bpf_sandfs_read_args, void *, p, u32, type, void *, dst, u32, size)
{
	int ret = -EINVAL;
	const void *inptr = NULL;
	struct sandfs_args *args = (struct sandfs_args *)p;
	unsigned num_args = args->num_args;

	if (type == OPCODE && size == sizeof(uint32_t))
		inptr = (void *)&args->op;

	else if (type == NUM_ARGS && size == sizeof(uint32_t))
		inptr = (void *)&args->num_args;

	// param 0
	else if (type == PARAM_0_SIZE && size == sizeof(uint32_t) &&
			num_args >= 1 && num_args <= MAX_NUM_ARGS) {
		inptr = &args->args[0].size;
	}

	else if (type == PARAM_0_VALUE && num_args >= 1 &&
			num_args <= MAX_NUM_ARGS) {
		ret = -E2BIG;
		if (size >= args->args[0].size) {
			size = args->args[0].size;
			inptr = args->args[0].value;
		}
	}

	// param 1
	else if (type == PARAM_1_SIZE && size == sizeof(uint32_t) &&
			num_args >= 2 && num_args <= MAX_NUM_ARGS) {
		inptr = &args->args[1].size;
	}

	else if (type == PARAM_1_VALUE && num_args >= 2 &&
			num_args <= MAX_NUM_ARGS) {
		ret = -E2BIG;
		if (size >= args->args[1].size) {
			size = args->args[1].size;
			inptr = args->args[1].value;
		}
	}

	// param 2
	else if (type == PARAM_2_SIZE && size == sizeof(uint32_t) &&
			num_args >= 3 && num_args <= MAX_NUM_ARGS)
		inptr = &args->args[2].size;

	else if (type == PARAM_2_VALUE && num_args >= 3 &&
			num_args <= MAX_NUM_ARGS) {
		ret = -E2BIG;
		if (size >= args->args[2].size) {
			size = args->args[2].size;
			inptr = args->args[2].value;
		}
	}

	// param 3
	else if (type == PARAM_3_SIZE && size == sizeof(uint32_t) &&
			num_args == MAX_NUM_ARGS)
		inptr = &args->args[3].size;

	else if (type == PARAM_3_VALUE && num_args == MAX_NUM_ARGS) {
		ret = -E2BIG;
		if (size >= args->args[3].size) {
			size = args->args[3].size;
			inptr = args->args[3].value;
		}
	}

	if (!inptr) {
		printk(KERN_ERR "Invalid input to sandfs_read_args"
			"type: %d num_args: %d size: %d\n",
			type, num_args, size);
		return ret;
	}

	ret = probe_kernel_read(dst, inptr, size);
	if (unlikely(ret < 0))
		memset(dst, 0, size);

	return ret;
}

static const struct bpf_func_proto bpf_sandfs_read_args_proto = {
	.func		= bpf_sandfs_read_args,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING, //ARG_CONST_SIZE_OR_ZERO,
	.arg3_type  = ARG_PTR_TO_RAW_STACK,
    .arg4_type  = ARG_CONST_STACK_SIZE,
};

BPF_CALL_4(bpf_sandfs_write_args, void *, p, u32, type, const void *,
		src, u32, size)
{
	int ret = -EINVAL;
	void *outptr = NULL;
	struct sandfs_args *args = (struct sandfs_args *)p;
	unsigned numargs = args->num_args;

	if (type == PARAM_0_VALUE && numargs >= 1 &&
		numargs <= MAX_NUM_ARGS && size == args->args[0].size)
		outptr = args->args[0].value;

	else if (type == PARAM_1_VALUE && numargs >= 2 &&
			numargs <= MAX_NUM_ARGS && size == args->args[1].size)
		outptr = args->args[1].value;

	else if (type == PARAM_2_VALUE && numargs >= 3 &&
			numargs <= MAX_NUM_ARGS && size == args->args[2].size)
		outptr = args->args[2].value;

	else if (type == PARAM_3_VALUE && numargs == MAX_NUM_ARGS &&
			size == args->args[1].size)
		outptr = args->args[3].value;

	if (!outptr) {
		printk(KERN_ERR "Invalid input to sandfs_write_args type: %d "
				"num_args: %d size: %d\n", type, numargs, size);
		return ret;
	}

	ret = probe_kernel_write(outptr, src, size);
	if (unlikely(ret < 0))
		memset(outptr, 0, size);

	return ret;
}

static const struct bpf_func_proto bpf_sandfs_write_args_proto = {
	.func		= bpf_sandfs_write_args,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING, //ARG_CONST_SIZE_OR_ZERO,
	.arg3_type  = ARG_PTR_TO_STACK,
    .arg4_type  = ARG_CONST_STACK_SIZE,
};

static
const struct bpf_func_proto *sandfs_prog_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_probe_read:
		return &bpf_probe_read_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_get_current_task:
		return &bpf_get_current_task_proto;
	case BPF_FUNC_get_current_uid_gid:
		return &bpf_get_current_uid_gid_proto;
	case BPF_FUNC_get_current_comm:
		return &bpf_get_current_comm_proto;
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	case BPF_FUNC_get_smp_processor_id:
		return &bpf_get_smp_processor_id_proto;
	case BPF_FUNC_get_prandom_u32:
		return &bpf_get_prandom_u32_proto;
	case BPF_FUNC_perf_event_output:
		return &bpf_perf_event_output_proto;
	case BPF_FUNC_probe_read_str:
		return &bpf_probe_read_str_proto;
	// SANDFS related
	case BPF_FUNC_sandfs_read_args:
		return &bpf_sandfs_read_args_proto;
	case BPF_FUNC_sandfs_write_args:
		return &bpf_sandfs_write_args_proto;
	default:
		return NULL;
	}
}

/* bpf+sandfs programs can access fields of 'struct pt_regs' */
static bool sandfs_prog_is_valid_access(int off, int size, enum bpf_access_type type,
					enum bpf_reg_type *reg_type)
{
	if (off < 0 || off >= sizeof(struct sandfs_args))
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;
	/*
	 * Assertion for 32 bit to make sure last 8 byte access
	 * (BPF_DW) to the last 4 byte member is disallowed.
	 */
	if (off + size > sizeof(struct sandfs_args))
		return false;

	return true;
}

static const struct bpf_verifier_ops sandfs_prog_ops = {
	.get_func_proto  = sandfs_prog_func_proto,
	.is_valid_access = sandfs_prog_is_valid_access,
};

static struct bpf_prog_type_list sandfs_tl __ro_after_init = {
	.ops	= &sandfs_prog_ops,
	.type	= BPF_PROG_TYPE_SANDFS,
};

int __init sandfs_register_bpf_prog_ops(void)
{
	bpf_register_prog_type(&sandfs_tl);
	printk(KERN_INFO "Registered SANDFS operations\n");
	return 0;
}
#endif
