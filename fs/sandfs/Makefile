SANDFS_VERSION="0.1"

EXTRA_CFLAGS += -DSANDFS_VERSION=\"$(SANDFS_VERSION)\"

obj-$(CONFIG_WRAP_FS) += sandfs.o

sandfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o bpf.o
