#ifndef SUPERSCALAR_SECURE_FILE_H
#define SUPERSCALAR_SECURE_FILE_H

#include <stdio.h>

/* Open path for writing (created or truncated) as an owner-only file.
   The mode is forced to 0600 whatever the umask is and whatever mode a file
   already at that path has.  Returns NULL on error. */
FILE *secure_file_open_private(const char *path);

#endif /* SUPERSCALAR_SECURE_FILE_H */
