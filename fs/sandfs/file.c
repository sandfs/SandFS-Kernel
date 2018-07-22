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

static ssize_t sandfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	struct sandfs_args args;
	const char *path;
	void *path_buf = vmalloc(PATH_MAX);
	if (IS_ERR(path_buf)) {
		pr_err("[%s:%d] Failed to alloc memory for file path\n",
			__func__, __LINE__);
		return -ENOMEM;
	}

	lower_file = sandfs_lower_file(file);

	path = file_path(lower_file, (char *)path_buf, PATH_MAX);
	if (!path) {
		pr_err("[%s:%d] Failed to get path\n", __func__, __LINE__);
		err = -EIO;
		goto out;
	}

	args.args[0].size = strlen(path);
	args.args[0].value = (void *)path;
	args.args[1].size = sizeof(loff_t);
	args.args[1].value = (void *)ppos;
	args.args[2].size = sizeof(size_t);
	args.args[2].value = (void *)&count;

	args.num_args = 3;
	args.op = SANDFS_READ;
	err = sandfs_request_bpf_op(SANDFS_SB(file_inode(file)->i_sb)->priv, &args);
	if (err < 0)
		goto out;

	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

out:
	vfree(path_buf);
	return err;
}

static ssize_t sandfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	struct sandfs_args args;
	const char *path;
	void *path_buf = vmalloc(PATH_MAX);
	if (IS_ERR(path_buf)) {
		pr_err("[%s:%d] Failed to alloc memory for file path\n",
			__func__, __LINE__);
		return -ENOMEM;
	}

	lower_file = sandfs_lower_file(file);

	path = file_path(lower_file, (char *)path_buf, PATH_MAX);
	if (!path) {
		pr_err("[%s:%d] Failed to get path\n", __func__, __LINE__);
		err = -EIO;
		goto out;
	}

	args.args[0].size = strlen(path);
	args.args[0].value = (void *)path;
	args.args[1].size = sizeof(loff_t);
	args.args[1].value = (void *)ppos;
	args.args[2].size = sizeof(size_t);
	args.args[2].value = (void *)&count;

	args.num_args = 3;
	args.op = SANDFS_WRITE;
	err = sandfs_request_bpf_op(SANDFS_SB(file_inode(file)->i_sb)->priv, &args);
	if (err < 0)
		goto out;

	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
					file_inode(lower_file));
	}

out:
	vfree(path_buf);
	return err;
}

struct sandfs_getdents_callback {
    struct dir_context ctx;
    struct dir_context *caller;
    struct super_block *sb;
    int filldir_called;
    int entries_written;
};

int sandfs_read_dirent(char **plaintext_name,
                     size_t *plaintext_name_size,
                     struct super_block *sb,
                     const char *name, size_t name_size)
{
	*plaintext_name = name;
	*plaintext_name_size = name_size;
	return 0;
}

/* Inspired by generic filldir in fs/readdir.c */
static int
sandfs_filldir(struct dir_context *ctx, const char *lower_name,
         int lower_namelen, loff_t offset, u64 ino, unsigned int d_type)
{   
    struct sandfs_getdents_callback *buf =
        container_of(ctx, struct sandfs_getdents_callback, ctx);
    size_t name_size;
    char *name;
    int rc = 0;

	buf->filldir_called++;

	pr_err("dirent name %s size: %d\n",
			lower_name, lower_namelen);

	rc = sandfs_read_dirent(&name, &name_size,
                          buf->sb, lower_name,
                          lower_namelen);
	if (rc) {
        pr_err("%s: Error attempting to read entry %s: %d\n",
			__func__, lower_name, rc);
		goto out;
	}

    buf->caller->pos = buf->ctx.pos;
    rc = !dir_emit(buf->caller, name, name_size, ino, d_type);
    kfree(name);
    if (!rc)    
        buf->entries_written++;
out:
    return rc;
}

static int sandfs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct inode *inode = file_inode(file);
    //struct sandfs_getdents_callback buf = {
    //    .ctx.actor = sandfs_filldir,
    //    .caller = ctx,
    //    .sb = inode->i_sb,
    //};

	lower_file = sandfs_lower_file(file);
	err = iterate_dir(lower_file, ctx); //&buf.ctx);
	file->f_pos = lower_file->f_pos;
	//ctx->pos = buf.ctx.pos;

	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}

static long sandfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = sandfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

	/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
	if (!err)
		fsstack_copy_attr_all(file_inode(file),
				      file_inode(lower_file));
out:
	return err;
}

#ifdef CONFIG_COMPAT
static long sandfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = sandfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int sandfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = sandfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		pr_err("sandfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!SANDFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			pr_err("sandfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &sandfs_vm_ops;

	file->f_mapping->a_ops = &sandfs_aops; /* set our aops */
	if (!SANDFS_F(file)->lower_vm_ops) /* save for our ->fault */
		SANDFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int sandfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct sandfs_file_info), GFP_KERNEL);
	if (!SANDFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link sandfs's file struct to lower's */
	sandfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = sandfs_lower_file(file);
		if (lower_file) {
			sandfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		sandfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(SANDFS_F(file));
	else
		fsstack_copy_attr_all(inode, sandfs_lower_inode(inode));
out_err:
	return err;
}

static int sandfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sandfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int sandfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = sandfs_lower_file(file);
	if (lower_file) {
		sandfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(SANDFS_F(file));
	return 0;
}

static int sandfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = sandfs_lower_file(file);
	sandfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	sandfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int sandfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sandfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Sandfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t sandfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = sandfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Sandfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
sandfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sandfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Sandfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
sandfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sandfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations sandfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= sandfs_read,
	.write		= sandfs_write,
	.unlocked_ioctl	= sandfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sandfs_compat_ioctl,
#endif
	.mmap		= sandfs_mmap,
	.open		= sandfs_open,
	.flush		= sandfs_flush,
	.release	= sandfs_file_release,
	.fsync		= sandfs_fsync,
	.fasync		= sandfs_fasync,
	.read_iter	= sandfs_read_iter,
	.write_iter	= sandfs_write_iter,
};

/* trimmed directory options */
const struct file_operations sandfs_dir_fops = {
	.llseek		= sandfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= sandfs_readdir,
	.unlocked_ioctl	= sandfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sandfs_compat_ioctl,
#endif
	.open		= sandfs_open,
	.release	= sandfs_file_release,
	.flush		= sandfs_flush,
	.fsync		= sandfs_fsync,
	.fasync		= sandfs_fasync,
};
