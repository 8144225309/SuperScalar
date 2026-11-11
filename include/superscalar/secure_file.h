#ifndef SUPERSCALAR_SECURE_FILE_H
#define SUPERSCALAR_SECURE_FILE_H

#include <stddef.h>

/*
 * Writing files that hold secrets (keyfiles, backups, restored databases).
 *
 * Every write goes to a temporary file next to the destination, is flushed to
 * disk and is then moved into place.  The destination therefore holds either
 * what it held before or the complete new content, never a partial write, and
 * a write that fails (full disk, quota, I/O error) is reported and leaves the
 * destination as it was.  Files are created with mode 0600 whatever the umask.
 *
 * A destination that is a symbolic link is refused: nothing is written
 * through the link, and the link is not replaced.
 *
 * Temporary files are named "<destination>.ss-partial.XXXXXX".  One left
 * behind by a crash is removed by the next write to the same destination.
 */

/* Returns 0 only if there is definitely nothing at path.  Anything there
   counts (including a dangling symbolic link), and so does a path that cannot
   be examined. */
int secure_file_exists(const char *path);

/* Atomically write len bytes to path.
   replace != 0: a regular file already at path is replaced.
   replace == 0: fails if anything already exists at path, leaving it
                 untouched.
   Returns 1 on success, 0 on error. */
int secure_file_write_atomic(const char *path, const unsigned char *data,
                             size_t len, int replace);

/* Two-step form, for writing several files as one operation: stage every
   file first, then commit them.  Nothing appears at a destination until its
   commit.

   secure_file_stage() writes the data to a temporary file next to path and
   returns a handle for it, or NULL on error.
   secure_file_commit() moves a staged file to path (same meaning of replace
   as above).  It releases the handle whether it succeeds or not; on failure
   the temporary file is removed.
   secure_file_discard() removes a staged file that will not be committed.
   NULL is accepted. */
char *secure_file_stage(const char *path, const unsigned char *data, size_t len);
int secure_file_commit(char *staged, const char *path, int replace);
void secure_file_discard(char *staged);

#endif /* SUPERSCALAR_SECURE_FILE_H */
