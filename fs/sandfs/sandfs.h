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

#ifndef _SANDFS_H_
#define _SANDFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/xattr.h>
#include <linux/exportfs.h>
#include <linux/vmalloc.h>
#include <linux/sandfs.h>

/* the file system name */
#define SANDFS_NAME "sandfs"

/* sandfs root inode number */
#define SANDFS_ROOT_INO     1

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

//#define DEBUG

#ifdef DEBUG
#define DBG(fmt, ...) printk(KERN_INFO fmt, ##__VA_ARGS__)
#else
#define DBG(fmt, ...)
#endif

/* operations vectors defined in specific files */
extern const struct file_operations sandfs_main_fops;
extern const struct file_operations sandfs_dir_fops;
extern const struct inode_operations sandfs_main_iops;
extern const struct inode_operations sandfs_dir_iops;
extern const struct inode_operations sandfs_symlink_iops;
extern const struct super_operations sandfs_sops;
extern const struct dentry_operations sandfs_dops;
extern const struct address_space_operations sandfs_aops, sandfs_dummy_aops;
extern const struct vm_operations_struct sandfs_vm_ops;
extern const struct export_operations sandfs_export_ops;
extern const struct xattr_handler *sandfs_xattr_handlers[];

extern int sandfs_init_inode_cache(void);
extern void sandfs_destroy_inode_cache(void);
extern int sandfs_init_dentry_cache(void);
extern void sandfs_destroy_dentry_cache(void);
extern int sandfs_new_dentry_private_data(struct dentry *dentry);
extern void sandfs_free_dentry_private_data(struct dentry *dentry);
extern struct dentry *sandfs_lookup(struct inode *dir, struct dentry *dentry,
				    unsigned int flags);
extern struct inode *sandfs_iget(struct super_block *sb,
				 struct inode *lower_inode);
extern int sandfs_interpose(struct dentry *dentry, struct super_block *sb,
			    struct path *lower_path);

extern int sandfs_register_bpf_prog_ops(void);
extern int sandfs_request_bpf_op(void *priv, struct sandfs_args *args);
extern int sandfs_set_bpf_ops(struct super_block *sb, int fd);
extern void sandfs_clear_bpf_ops(struct super_block *sb);

/* file private data */
struct sandfs_file_info {
	struct file *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
};

/* sandfs inode data in memory */
struct sandfs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
};

/* sandfs dentry data in memory */
struct sandfs_dentry_info {
	spinlock_t lock;	/* protects lower_path */
	struct path lower_path;
};

/* sandfs super-block data in memory */
struct sandfs_sb_info {
	struct super_block *lower_sb;
	void *priv;
};

/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * sandfs_inode_info structure, SANDFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct sandfs_inode_info *SANDFS_I(const struct inode *inode)
{
	return container_of(inode, struct sandfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define SANDFS_D(dent) ((struct sandfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define SANDFS_SB(super) ((struct sandfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define SANDFS_F(file) ((struct sandfs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *sandfs_lower_file(const struct file *f)
{
	return SANDFS_F(f)->lower_file;
}

static inline void sandfs_set_lower_file(struct file *f, struct file *val)
{
	SANDFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *sandfs_lower_inode(const struct inode *i)
{
	return SANDFS_I(i)->lower_inode;
}

static inline void sandfs_set_lower_inode(struct inode *i, struct inode *val)
{
	SANDFS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *sandfs_lower_super(
	const struct super_block *sb)
{
	return SANDFS_SB(sb)->lower_sb;
}

static inline void sandfs_set_lower_super(struct super_block *sb,
					  struct super_block *val)
{
	SANDFS_SB(sb)->lower_sb = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void sandfs_get_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&SANDFS_D(dent)->lock);
	pathcpy(lower_path, &SANDFS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&SANDFS_D(dent)->lock);
	return;
}
static inline void sandfs_put_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	path_put(lower_path);
	return;
}
static inline void sandfs_set_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&SANDFS_D(dent)->lock);
	pathcpy(&SANDFS_D(dent)->lower_path, lower_path);
	spin_unlock(&SANDFS_D(dent)->lock);
	return;
}
static inline void sandfs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&SANDFS_D(dent)->lock);
	SANDFS_D(dent)->lower_path.dentry = NULL;
	SANDFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&SANDFS_D(dent)->lock);
	return;
}
static inline void sandfs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&SANDFS_D(dent)->lock);
	pathcpy(&lower_path, &SANDFS_D(dent)->lower_path);
	SANDFS_D(dent)->lower_path.dentry = NULL;
	SANDFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&SANDFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	inode_unlock(d_inode(dir));
	dput(dir);
}
#endif	/* not _SANDFS_H_ */
