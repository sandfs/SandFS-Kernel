/*
 * Copyright (c) 2018-2019 Ashish Bijlani
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
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/string.h>

typedef enum sandfs_tokens {
	SANDFS_OPT_PROG,
	SANDFS_OPT_ERR
} sandfs_tokens;

typedef struct sandfs_options {
	int prog_fd;
	int err;
} sandfs_options;

struct sandfs_mount_data {
	void *dev_name;
	char *prog_fd;
};

static const match_table_t tokens = {
	{SANDFS_OPT_PROG, "fd=%d"},
	{SANDFS_OPT_ERR, NULL}
};

struct sandfs_options* sandfs_parse_options(char *options)
{
	char *p;
	int token;
	int fd;
	struct sandfs_options *opts;
	substring_t args[MAX_OPT_ARGS];

	opts = kmalloc(sizeof(sandfs_options), GFP_KERNEL);
	if (!opts) {
		printk("No Memory \n");
		return NULL;	
	}
	
	opts->err = 0;
	opts->prog_fd = -1;

	if (!options) {
        opts->err = -EINVAL;
        goto out;
	}

    while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;
            
		token = match_token(p, tokens, args);
		switch (token) {
		case SANDFS_OPT_PROG: 
			if (match_int(&args[0], &fd))
				return 0;
			opts->prog_fd = fd;
			opts->err=0;		
			printk(KERN_ERR "Sandfs: option fd:%d\n", fd);
			break;
		case SANDFS_OPT_ERR:
		default:
			opts->err=-EINVAL;
			printk(KERN_ERR "Sandfs: unrecognized option\n");
			break;
		}
	}

out:
	return opts;	
}

/*
 * There is no need to lock the sandfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int sandfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	struct sandfs_mount_data *data = (struct sandfs_mount_data *)raw_data;
	char *dev_name = data->dev_name;
	struct sandfs_options *opts = NULL;
	struct inode *inode;

	if (!dev_name) {
		printk(KERN_ERR
		       "sandfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	printk(KERN_ERR "Sandfs: request to mount on %s with prog_fd=%s\n",
			dev_name, data->prog_fd ? data->prog_fd : "<null>");

	opts = sandfs_parse_options(data->prog_fd);
	if (!opts) {
		err = -ENOMEM;
		goto out;
	}

	if (opts->prog_fd == -1) {
		printk(KERN_ERR "Error in parsing prog_fd=%d\n",
			opts->prog_fd);
		goto out;
	}

	printk(KERN_ERR "Sandfs prog_fd=%d\n", opts->prog_fd);

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"sandfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct sandfs_sb_info), GFP_KERNEL);
	if (!SANDFS_SB(sb)) {
		printk(KERN_CRIT "sandfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}

	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	sandfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &sandfs_sops;
	sb->s_xattr = sandfs_xattr_handlers;

	sb->s_export_op = &sandfs_export_ops; /* adding NFS support */

	sb->s_magic = SANDFS_SUPER_MAGIC;
    sb->s_stack_depth = lower_path.dentry->d_sb->s_stack_depth + 1;

    err = -EINVAL;
    if (sb->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
        pr_err("SandFS: maximum fs stacking depth exceeded\n");
        goto out_free;
    }

	/* get a new inode and allocate our root dentry */
	inode = sandfs_iget(sb, d_inode(lower_path.dentry));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &sandfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = sandfs_new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	sandfs_set_lower_path(sb->s_root, &lower_path);

	if (sandfs_set_bpf_ops(sb, opts->prog_fd))
		printk(KERN_ERR "Failed to setup BPF ops\n");

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "sandfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(SANDFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
}

struct dentry *sandfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	struct sandfs_mount_data data;
	data.dev_name = (void *) dev_name;
	data.prog_fd = (char *)raw_data;
	return mount_nodev(fs_type, flags, (void *)&data,
			   sandfs_read_super);
}

static struct file_system_type sandfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= SANDFS_NAME,
	.mount		= sandfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= FS_USERNS_MOUNT, /* allow unpriv mounts */
};
MODULE_ALIAS_FS(SANDFS_NAME);

static int __init init_sandfs_fs(void)
{
	int err;

	pr_info("Registering sandfs " SANDFS_VERSION "\n");

	err = sandfs_init_inode_cache();
	if (err)
		goto out;
	err = sandfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&sandfs_fs_type);
	if (err)
		goto out;
	err = sandfs_register_bpf_prog_ops();

out:
	if (err) {
		sandfs_destroy_inode_cache();
		sandfs_destroy_dentry_cache();
	}

	return err;
}

static void __exit exit_sandfs_fs(void)
{
	sandfs_destroy_inode_cache();
	sandfs_destroy_dentry_cache();
	unregister_filesystem(&sandfs_fs_type);
	pr_info("Completed sandfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Sandfs " SANDFS_VERSION
		   " (http://sandfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_sandfs_fs);
module_exit(exit_sandfs_fs);
