#ifndef _LINUX_SANDFS_H
#define _LINUX_SANDFS_H

#define MAX_NUM_ARGS 4

typedef enum {
	SANDFS_LOOKUP,
	SANDFS_OPEN,
	SANDFS_CLOSE,
	SANDFS_READ,
	SANDFS_WRITE,
} sandfs_op_t;

typedef enum {
	OPCODE = 0,
	NUM_ARGS,
	PARAM_0_SIZE,
	PARAM_0_VALUE,
	PARAM_1_SIZE,
	PARAM_1_VALUE,
	PARAM_2_SIZE,
	PARAM_2_VALUE,
	PARAM_3_SIZE,
	PARAM_3_VALUE,
} sandfs_arg_t;

struct sandfs_arg {
	uint32_t size;
	void *value;
};

struct sandfs_args {
	sandfs_arg_t op;
	uint32_t num_args;
	struct sandfs_arg args[MAX_NUM_ARGS];
};

#endif /* _LINUX_SANDFS_H */
