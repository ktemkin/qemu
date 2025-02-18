/*
 * 9p utilities
 *
 * Copyright IBM, Corp. 2017
 *
 * Authors:
 *  Greg Kurz <groug@kaod.org>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef QEMU_9P_UTIL_H
#define QEMU_9P_UTIL_H

#ifdef O_PATH
#define O_PATH_9P_UTIL O_PATH
#else
#define O_PATH_9P_UTIL 0
#endif

// XXX: temporary hacks to test symlink method'y
#undef XATTR_NOFOLLOW
#define XATTR_NOFOLLOW 0
#undef O_NOFOLLOW
#define O_NOFOLLOW 0
#undef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0

#ifdef CONFIG_DARWIN
#define qemu_fgetxattr(...) fgetxattr(__VA_ARGS__, 0, 0)
#define qemu_lgetxattr(...) getxattr(__VA_ARGS__, 0, XATTR_NOFOLLOW)
#define qemu_llistxattr(...) listxattr(__VA_ARGS__, XATTR_NOFOLLOW)
#define qemu_lremovexattr(...) removexattr(__VA_ARGS__, XATTR_NOFOLLOW)
static inline int qemu_lsetxattr(const char *path, const char *name,
                                 const void *value, size_t size, int flags) {
  return setxattr(path, name, value, size, 0, flags | XATTR_NOFOLLOW);
}
#else
#define qemu_fgetxattr fgetxattr
#define qemu_lgetxattr lgetxattr
#define qemu_llistxattr llistxattr
#define qemu_lremovexattr lremovexattr
#define qemu_lsetxattr lsetxattr
#endif

static inline void close_preserve_errno(int fd) {
  int serrno = errno;
  close(fd);
  errno = serrno;
}

static inline int openat_dir(int dirfd, const char *name) {
  return openat(dirfd, name,
                O_DIRECTORY | O_RDONLY | O_NOFOLLOW | O_PATH_9P_UTIL);
}

static inline int openat_file(int dirfd, const char *name, int flags,
                              mode_t mode) {
  int fd, serrno, ret;

again:
  fd = openat(dirfd, name, flags | O_NOFOLLOW | O_NOCTTY | O_NONBLOCK, mode);
  if (fd == -1) {
#ifndef CONFIG_DARWIN
    if (errno == EPERM && (flags & O_NOATIME)) {
      /*
       * The client passed O_NOATIME but we lack permissions to honor it.
       * Rather than failing the open, fall back without O_NOATIME. This
       * doesn't break the semantics on the client side, as the Linux
       * open(2) man page notes that O_NOATIME "may not be effective on
       * all filesystems". In particular, NFS and other network
       * filesystems ignore it entirely.
       */
      flags &= ~O_NOATIME;
      goto again;
    }
#endif
    return -1;
  }

  serrno = errno;
  /* O_NONBLOCK was only needed to open the file. Let's drop it. We don't
   * do that with O_PATH since fcntl(F_SETFL) isn't supported, and openat()
   * ignored it anyway.
   */
  if (!(flags & O_PATH_9P_UTIL)) {
    ret = fcntl(fd, F_SETFL, flags);
    assert(!ret);
  }
  errno = serrno;
  return fd;
}

ssize_t fgetxattrat_nofollow(int dirfd, const char *path, const char *name,
                             void *value, size_t size);
int fsetxattrat_nofollow(int dirfd, const char *path, const char *name,
                         void *value, size_t size, int flags);
ssize_t flistxattrat_nofollow(int dirfd, const char *filename, char *list,
                              size_t size);
ssize_t fremovexattrat_nofollow(int dirfd, const char *filename,
                                const char *name);

#endif

/**
 * Darwin has d_seekoff, which appears to function similarly to d_off.
 * However, it does not appear to be supported on all file systems,
 * so ensure it is manually injected earlier and call here when
 * needed.
 */
inline off_t qemu_dirent_off(struct dirent *dent) {
#ifdef CONFIG_DARWIN
  return dent->d_seekoff;
#else
  return dent->d_off;
#endif
}
