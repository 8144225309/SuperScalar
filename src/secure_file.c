#include "superscalar/secure_file.h"
#include <fcntl.h>
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
