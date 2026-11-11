#include "superscalar/secure_file.h"
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

FILE *secure_file_open_private(const char *path) {
    if (!path) return NULL;

    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) return NULL;

    /* open() only applies the mode when it creates the file. */
    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        close(fd);
        return NULL;
    }

    FILE *fp = fdopen(fd, "wb");
    if (!fp) close(fd);
    return fp;
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
    int dfd = open(dirname(copy), O_RDONLY);
    if (dfd >= 0) {
        (void)fsync(dfd);
        close(dfd);
    }
    free(copy);
}

int secure_file_write_atomic(const char *path, const unsigned char *data,
                             size_t len, int replace) {
    if (!path || (!data && len > 0)) return 0;

    static const char suffix[] = ".tmpXXXXXX";
    size_t tmp_len = strlen(path) + sizeof(suffix);
    char *tmp = malloc(tmp_len);
    if (!tmp) return 0;
    snprintf(tmp, tmp_len, "%s%s", path, suffix);

    int fd = mkstemp(tmp);
    if (fd < 0) {
        free(tmp);
        return 0;
    }

    int ok = fchmod(fd, S_IRUSR | S_IWUSR) == 0 &&
             write_all(fd, data, len) &&
             fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;

    if (ok && replace) {
        ok = rename(tmp, path) == 0;
    } else if (ok) {
        /* link() fails if path exists, with no window in which an existing
           file could be replaced. */
        if (link(tmp, path) == 0) {
            unlink(tmp);
        } else if (errno == EEXIST) {
            ok = 0;
        } else {
            /* Filesystem without hard links: check, then rename. */
            struct stat st;
            ok = lstat(path, &st) != 0 && errno == ENOENT &&
                 rename(tmp, path) == 0;
        }
    }

    if (ok)
        sync_parent_dir(path);
    else
        unlink(tmp);

    free(tmp);
    return ok;
}
