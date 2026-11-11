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

/*
 * Reading files that hold secrets.
 */

/* Open a secret file for reading.  Only a regular file is opened; a FIFO or
   device at the path is refused without blocking.  A symbolic link is
   followed (a key or backup may legitimately be reached through one) and
   *via_symlink_out is set to 1 in that case, 0 otherwise.
   Returns a close-on-exec descriptor, or -1. */
int secure_file_open_read(const char *path, int *via_symlink_out);

/* Who, besides the owner, can still access a file after secure_file_restrict(). */
typedef enum {
    SECURE_FILE_PRIVATE = 0,       /* nobody (already, or tightened just now) */
    SECURE_FILE_GROUP_ACCESSIBLE,  /* its group; left as it was */
    SECURE_FILE_WORLD_ACCESSIBLE   /* everyone; left as it was */
} secure_file_access_t;

/* Make an open secret file owner-only where that is ours to do.

   A file that group or others can access is changed to mode 0600 only if it
   is a regular file, owned by the calling user, with a single hard link, and
   was not reached through a symbolic link (pass the via_symlink value from
   secure_file_open_read).  Anything else is left exactly as it is: it may be
   another user's file, a file deliberately shared with a group, or a
   different file that a link points at.

   A warning naming path is printed whenever the file was tightened or was
   left accessible to others.  The return value says what access remains; the
   caller decides whether that is acceptable. */
secure_file_access_t secure_file_restrict(int fd, const char *path, int via_symlink);

#endif /* SUPERSCALAR_SECURE_FILE_H */
