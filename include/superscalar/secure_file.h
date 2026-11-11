#ifndef SUPERSCALAR_SECURE_FILE_H
#define SUPERSCALAR_SECURE_FILE_H

#include <stddef.h>
#include <stdio.h>

/* Open path for writing (created or truncated) as an owner-only file.
   The mode is forced to 0600 whatever the umask is and whatever mode a file
   already at that path has.  Returns NULL on error. */
FILE *secure_file_open_private(const char *path);

/* Atomically write len bytes to path as an owner-only (0600) file.  The data
   goes to a temporary file in the same directory, is flushed to disk and is
   then moved into place, so path holds either what it held before or the
   complete new content, never a partial write.
   replace != 0: a file already at path is replaced.
   replace == 0: fails if anything already exists at path and leaves it
                 untouched.
   Returns 1 on success, 0 on error. */
int secure_file_write_atomic(const char *path, const unsigned char *data,
                             size_t len, int replace);

#endif /* SUPERSCALAR_SECURE_FILE_H */
