/*
 * Copyright (c) 1998-2017 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2017 Stony Brook University
 * Copyright (c) 2003-2017 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "sandfs.h"

/*
 * returns: -ERRNO if error (returned to user)
 *          0: tell VFS to invalidate dentry
 *          1: dentry is valid
 */
static int sandfs_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct path lower_path;
	struct dentry *lower_dentry;
	int err = 1;

	struct sandfs_args args;
    const char *path;
    void *path_buf;
	
	if (flags & LOOKUP_RCU)
		return -ECHILD;

	path_buf = vmalloc(PATH_MAX);
	if (IS_ERR(path_buf)) {
		pr_err("[%s:%d] Failed to alloc memory for file path\n",
			__func__, __LINE__);
		return -ENOMEM;
	}

	sandfs_get_lower_path(dentry, &lower_path);

	path = d_path(&lower_path, (char *)path_buf, PATH_MAX);
	if (!path) {
		pr_err("[%s,%d] Failed to get path\n", __func__, __LINE__);
		err = -EIO;
		goto out;
	}

	args.args[0].size = strlen(path);
	args.args[0].value = (void *)path;

	args.num_args = 1;
	args.op = SANDFS_LOOKUP;
	err = sandfs_request_bpf_op(SANDFS_SB(d_inode(dentry)->i_sb)->priv, &args);
	if (err < 0)
		goto out;

	lower_dentry = lower_path.dentry;
	if (!(lower_dentry->d_flags & DCACHE_OP_REVALIDATE))
		goto out;

	err = lower_dentry->d_op->d_revalidate(lower_dentry, flags);
out:
	sandfs_put_lower_path(dentry, &lower_path);
	vfree(path_buf);
	return err;
}

static void sandfs_d_release(struct dentry *dentry)
{
	/* release and reset the lower paths */
	sandfs_put_reset_lower_path(dentry);
	sandfs_free_dentry_private_data(dentry);
	return;
}

const struct dentry_operations sandfs_dops = {
	.d_revalidate	= sandfs_d_revalidate,
	.d_release	= sandfs_d_release,
};
