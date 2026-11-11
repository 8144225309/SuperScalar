#include "superscalar/secure_file.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Temporary files are "<destination><TMP_INFIX>XXXXXX". */
#define TMP_INFIX ".ss-partial."
#define TMP_RANDOM_LEN 6

int secure_file_exists(const char *path) {
    if (!path) return 0;
    struct stat st;
    return !(lstat(path, &st) != 0 && errno == ENOENT);
}

static int is_symlink(const char *path) {
    struct stat st;
    return lstat(path, &st) == 0 && S_ISLNK(st.st_mode);
}

static int write_all(int fd, const unsigned char *data, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, data, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return 0;
        }
        data += n;
        len -= (size_t)n;
    }
    return 1;
}

/* Flush the directory entry for path.  Best effort: the file itself is already
   complete and in place, and not every filesystem can fsync a directory. */
static void sync_parent_dir(const char *path) {
    char *copy = strdup(path);
    if (!copy) return;
    int dfd = open(dirname(copy), O_RDONLY | O_CLOEXEC);
    if (dfd >= 0) {
        (void)fsync(dfd);
        close(dfd);
    }
    free(copy);
}

/* Remove temporary files for path that an interrupted write left behind.
   Best effort.  Two writers must not target the same path at once: the later
   one removes the earlier one's temporary file, whose commit then fails. */
static void remove_stale_temporaries(const char *path) {
    char *dir_copy = strdup(path);
    char *base_copy = strdup(path);
    if (dir_copy && base_copy) {
        const char *dir = dirname(dir_copy);
        const char *base = basename(base_copy);
        size_t base_len = strlen(base);
        size_t infix_len = strlen(TMP_INFIX);

        DIR *d = opendir(dir);
        if (d) {
            int dfd = dirfd(d);
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                const char *name = de->d_name;
                if (strlen(name) != base_len + infix_len + TMP_RANDOM_LEN ||
                    strncmp(name, base, base_len) != 0 ||
                    strncmp(name + base_len, TMP_INFIX, infix_len) != 0)
                    continue;
                struct stat st;
                if (fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
                    S_ISREG(st.st_mode))
                    (void)unlinkat(dfd, name, 0);
            }
            closedir(d);
        }
    }
    free(dir_copy);
    free(base_copy);
}

char *secure_file_stage(const char *path, const unsigned char *data, size_t len) {
    if (!path || (!data && len > 0)) return NULL;

    /* Never write through, or replace, a symbolic link. */
    if (is_symlink(path)) return NULL;

    remove_stale_temporaries(path);

    size_t tmp_len = strlen(path) + strlen(TMP_INFIX) + TMP_RANDOM_LEN + 1;
    char *tmp = malloc(tmp_len);
    if (!tmp) return NULL;
    snprintf(tmp, tmp_len, "%s%sXXXXXX", path, TMP_INFIX);

    /* mkstemp creates the file exclusively, so it cannot follow a link. */
    int fd = mkstemp(tmp);
    if (fd < 0) {
        free(tmp);
        return NULL;
    }

    int ok = fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 &&
             fchmod(fd, S_IRUSR | S_IWUSR) == 0 &&
             write_all(fd, data, len) &&
             fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;

    if (!ok) {
        unlink(tmp);
        free(tmp);
        return NULL;
    }
    return tmp;
}

void secure_file_discard(char *staged) {
    if (!staged) return;
    unlink(staged);
    free(staged);
}

int secure_file_commit(char *staged, const char *path, int replace) {
    if (!staged) return 0;
    if (!path) {
        secure_file_discard(staged);
        return 0;
    }

    int ok;
    if (replace) {
        /* rename() replaces a link rather than following it, so the link's
           target is safe either way; refusing keeps the link as well. */
        ok = !is_symlink(path) && rename(staged, path) == 0;
    } else if (link(staged, path) == 0) {
        /* link() fails if anything exists at path, with no window in which
           an existing file could be replaced. */
        unlink(staged);
        ok = 1;
    } else if (errno == EPERM || errno == EOPNOTSUPP || errno == ENOSYS) {
        /* The filesystem has no hard links: check, then rename.  Only these
           errors mean that; any other failure (the path exists, no access,
           an I/O error, ...) fails the write. */
        struct stat st;
        ok = lstat(path, &st) != 0 && errno == ENOENT &&
             rename(staged, path) == 0;
    } else {
        ok = 0;
    }

    if (ok)
        sync_parent_dir(path);
    else
        unlink(staged);

    free(staged);
    return ok;
}

int secure_file_write_atomic(const char *path, const unsigned char *data,
                             size_t len, int replace) {
    char *staged = secure_file_stage(path, data, len);
    if (!staged) return 0;
    return secure_file_commit(staged, path, replace);
}

int secure_file_open_read(const char *path, int *via_symlink_out) {
    if (via_symlink_out) *via_symlink_out = 0;
    if (!path) return -1;

    /* O_NONBLOCK: opening a FIFO must not wait for a writer. */
    int flags = O_RDONLY | O_CLOEXEC | O_NONBLOCK;
    int fd = open(path, flags | O_NOFOLLOW);
    if (fd < 0) {
        struct stat lst;
        if (lstat(path, &lst) != 0 || !S_ISLNK(lst.st_mode)) return -1;
        fd = open(path, flags);
        if (fd < 0) return -1;
        if (via_symlink_out) *via_symlink_out = 1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }
    return fd;
}

secure_file_access_t secure_file_restrict(int fd, const char *path, int via_symlink) {
    const char *name = path ? path : "(file)";
    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "WARNING - cannot check the permissions of %s.\n", name);
        return SECURE_FILE_WORLD_ACCESSIBLE;
    }

    unsigned mode = (unsigned)(st.st_mode & 0777);
    if ((mode & (S_IRWXG | S_IRWXO)) == 0) return SECURE_FILE_PRIVATE;

    const char *why_not = NULL;
    if (!S_ISREG(st.st_mode))          why_not = "it is not a regular file";
    else if (via_symlink)              why_not = "it is reached through a symbolic link";
    else if (st.st_uid != geteuid())   why_not = "it is owned by another user";
    else if (st.st_nlink != 1)         why_not = "it has more than one hard link";
    else if (fchmod(fd, S_IRUSR | S_IWUSR) != 0)
                                       why_not = "its mode could not be changed";

    if (!why_not) {
        fprintf(stderr, "WARNING - %s was group/world-accessible (mode 0%o); "
                "tightened to 0600. If this host is shared, treat its content as "
                "exposed.\n", name, mode);
        return SECURE_FILE_PRIVATE;
    }

    int world = (mode & S_IRWXO) != 0;
    fprintf(stderr, "WARNING - %s is %s-accessible (mode 0%o) and was left "
            "unchanged: %s.\n", name, world ? "world" : "group", mode, why_not);
    return world ? SECURE_FILE_WORLD_ACCESSIBLE : SECURE_FILE_GROUP_ACCESSIBLE;
}
