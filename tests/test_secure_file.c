#include "superscalar/secure_file.h"
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return 0; \
    } \
} while(0)

#define SF_DIR "/tmp/test_secure_file.d"

static const unsigned char OLD_DATA[] = "old content";
static const unsigned char NEW_DATA[] = "new content, longer than the old one";
#define OLD_LEN (sizeof(OLD_DATA) - 1)
#define NEW_LEN (sizeof(NEW_DATA) - 1)

static int file_mode(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;
    return (int)(st.st_mode & 07777);
}

static int put(const char *path, const unsigned char *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return 0;
    size_t n = fwrite(data, 1, len, fp);
    return fclose(fp) == 0 && n == len;
}

static int holds(const char *path, const unsigned char *data, size_t len) {
    unsigned char buf[256];
    FILE *fp = fopen(path, "rb");
    if (!fp) return 0;
    size_t n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    return n == len && memcmp(buf, data, len) == 0;
}

/* Empty the scratch directory and (re)create it. */
static int fresh_dir(void) {
    DIR *d = opendir(SF_DIR);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            char p[512];
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
            snprintf(p, sizeof(p), SF_DIR "/%s", de->d_name);
            unlink(p);
        }
        closedir(d);
        rmdir(SF_DIR);
    }
    return mkdir(SF_DIR, 0700) == 0;
}

static int dir_entries(void) {
    int n = 0;
    DIR *d = opendir(SF_DIR);
    if (!d) return -1;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) n++;
    }
    closedir(d);
    return n;
}

/* Run a write with every file write failing (file size limit of zero), the
   way a full disk or an exhausted quota fails it. */
static int write_with_failing_disk(const char *path, const unsigned char *data,
                                   size_t len, int replace) {
    struct rlimit old_limit, no_writes;
    void (*old_handler)(int) = signal(SIGXFSZ, SIG_IGN);
    getrlimit(RLIMIT_FSIZE, &old_limit);
    no_writes = old_limit;
    no_writes.rlim_cur = 0;
    setrlimit(RLIMIT_FSIZE, &no_writes);

    int result = secure_file_write_atomic(path, data, len, replace);

    setrlimit(RLIMIT_FSIZE, &old_limit);
    signal(SIGXFSZ, old_handler);
    return result;
}

/* Files are owner-only whatever the umask, in both write modes and when a
   permissive file is replaced. */
int test_secure_file_mode_owner_only(void) {
    const char *a = SF_DIR "/a", *b = SF_DIR "/b";
    TEST_ASSERT(fresh_dir(), "scratch dir");

    mode_t old_umask = umask(0);
    int wrote_a = secure_file_write_atomic(a, NEW_DATA, NEW_LEN, 1);
    int mode_a = file_mode(a);
    int wrote_b = secure_file_write_atomic(b, NEW_DATA, NEW_LEN, 0);
    int mode_b = file_mode(b);
    int loosened = chmod(a, 0666) == 0;
    int rewrote_a = secure_file_write_atomic(a, OLD_DATA, OLD_LEN, 1);
    int mode_a2 = file_mode(a);
    umask(old_umask);

    TEST_ASSERT(wrote_a && wrote_b && loosened && rewrote_a, "writes succeed");
    TEST_ASSERT(mode_a == 0600, "replace-mode file is 0600");
    TEST_ASSERT(mode_b == 0600, "create-only file is 0600");
    TEST_ASSERT(mode_a2 == 0600, "file replacing a 0666 file is 0600");
    TEST_ASSERT(holds(a, OLD_DATA, OLD_LEN), "replaced content");
    TEST_ASSERT(dir_entries() == 2, "no temporary files left");
    return fresh_dir() && rmdir(SF_DIR) == 0;
}

/* Create-only mode leaves whatever is at the destination alone. */
int test_secure_file_create_only(void) {
    const char *path = SF_DIR "/file";
    TEST_ASSERT(fresh_dir(), "scratch dir");

    TEST_ASSERT(!secure_file_exists(path), "nothing there yet");
    TEST_ASSERT(secure_file_write_atomic(path, OLD_DATA, OLD_LEN, 0), "first write");
    TEST_ASSERT(secure_file_exists(path), "file exists");
    TEST_ASSERT(!secure_file_write_atomic(path, NEW_DATA, NEW_LEN, 0),
                "second create-only write is refused");
    TEST_ASSERT(holds(path, OLD_DATA, OLD_LEN), "first content kept");
    TEST_ASSERT(dir_entries() == 1, "no temporary files left");
    return fresh_dir() && rmdir(SF_DIR) == 0;
}

/* A write that fails is reported, leaves the old file intact and leaves no
   partial or temporary file. */
int test_secure_file_failed_write_keeps_old(void) {
    const char *path = SF_DIR "/file", *fresh = SF_DIR "/fresh";
    TEST_ASSERT(fresh_dir(), "scratch dir");
    TEST_ASSERT(put(path, OLD_DATA, OLD_LEN), "existing file");

    TEST_ASSERT(!write_with_failing_disk(path, NEW_DATA, NEW_LEN, 1),
                "failed replace is reported");
    TEST_ASSERT(holds(path, OLD_DATA, OLD_LEN), "old content intact");

    TEST_ASSERT(!write_with_failing_disk(fresh, NEW_DATA, NEW_LEN, 0),
                "failed create is reported");
    TEST_ASSERT(!secure_file_exists(fresh), "no partial file created");
    TEST_ASSERT(dir_entries() == 1, "no temporary files left");

    /* The limit is lifted again: the same write now succeeds. */
    TEST_ASSERT(secure_file_write_atomic(path, NEW_DATA, NEW_LEN, 1), "write succeeds");
    TEST_ASSERT(holds(path, NEW_DATA, NEW_LEN), "new content");
    return fresh_dir() && rmdir(SF_DIR) == 0;
}

/* A destination that is a symbolic link is refused in both modes: the
   target is not written or chmod-ed, and the link stays a link. */
int test_secure_file_refuses_symlink(void) {
    const char *target = SF_DIR "/target", *link_path = SF_DIR "/link";
    TEST_ASSERT(fresh_dir(), "scratch dir");
    TEST_ASSERT(put(target, OLD_DATA, OLD_LEN), "target file");
    TEST_ASSERT(chmod(target, 0644) == 0, "target mode");
    TEST_ASSERT(symlink(target, link_path) == 0, "symlink");

    for (int replace = 0; replace <= 1; replace++) {
        TEST_ASSERT(!secure_file_write_atomic(link_path, NEW_DATA, NEW_LEN, replace),
                    "write to a symlink is refused");
        TEST_ASSERT(holds(target, OLD_DATA, OLD_LEN), "target content untouched");
        TEST_ASSERT(file_mode(target) == 0644, "target mode untouched");
        struct stat st;
        TEST_ASSERT(lstat(link_path, &st) == 0 && S_ISLNK(st.st_mode), "link still a link");
        TEST_ASSERT(secure_file_stage(link_path, NEW_DATA, NEW_LEN) == NULL,
                    "staging for a symlink is refused");
    }
    TEST_ASSERT(dir_entries() == 2, "no temporary files left");
    return fresh_dir() && rmdir(SF_DIR) == 0;
}

/* A dangling link is still something at the path: nothing is created where
   it points, in either mode. */
int test_secure_file_refuses_dangling_symlink(void) {
    const char *missing = SF_DIR "/missing", *link_path = SF_DIR "/link";
    TEST_ASSERT(fresh_dir(), "scratch dir");
    TEST_ASSERT(symlink(missing, link_path) == 0, "dangling symlink");

    TEST_ASSERT(secure_file_exists(link_path), "a dangling link counts as existing");
    for (int replace = 0; replace <= 1; replace++) {
        TEST_ASSERT(!secure_file_write_atomic(link_path, NEW_DATA, NEW_LEN, replace),
                    "write to a dangling symlink is refused");
        TEST_ASSERT(!secure_file_exists(missing), "nothing created at the link target");
        struct stat st;
        TEST_ASSERT(lstat(link_path, &st) == 0 && S_ISLNK(st.st_mode), "link still a link");
    }
    TEST_ASSERT(dir_entries() == 1, "no temporary files left");
    return fresh_dir() && rmdir(SF_DIR) == 0;
}

/* Staged files appear only on commit, and can be dropped instead. */
int test_secure_file_stage_commit_discard(void) {
    const char *a = SF_DIR "/a", *b = SF_DIR "/b";
    TEST_ASSERT(fresh_dir(), "scratch dir");

    char *staged_a = secure_file_stage(a, NEW_DATA, NEW_LEN);
    char *staged_b = secure_file_stage(b, OLD_DATA, OLD_LEN);
    TEST_ASSERT(staged_a && staged_b, "stage two files");
    TEST_ASSERT(!secure_file_exists(a) && !secure_file_exists(b),
                "nothing at the destinations before commit");
    TEST_ASSERT(file_mode(staged_a) == 0600, "staged file is 0600");

    TEST_ASSERT(secure_file_commit(staged_a, a, 0), "commit a");
    secure_file_discard(staged_b);
    secure_file_discard(NULL);
    TEST_ASSERT(holds(a, NEW_DATA, NEW_LEN), "a committed");
    TEST_ASSERT(!secure_file_exists(b), "b discarded");
    TEST_ASSERT(dir_entries() == 1, "no temporary files left");
    return fresh_dir() && rmdir(SF_DIR) == 0;
}

/* A temporary file left by an interrupted write is cleared by the next write
   to that destination; similarly named files are not touched. */
int test_secure_file_removes_stale_temporaries(void) {
    const char *path = SF_DIR "/node.key";
    const char *stale = SF_DIR "/node.key.ss-partial.Ab12Cd";
    const char *other_dest = SF_DIR "/other.key.ss-partial.Ab12Cd";
    const char *lookalike = SF_DIR "/node.key.ss-partial.toolong";
    const char *unrelated = SF_DIR "/node.key.tmpbackup";
    TEST_ASSERT(fresh_dir(), "scratch dir");
    TEST_ASSERT(put(stale, OLD_DATA, OLD_LEN) && put(other_dest, OLD_DATA, OLD_LEN) &&
                put(lookalike, OLD_DATA, OLD_LEN) && put(unrelated, OLD_DATA, OLD_LEN),
                "leftover files");

    TEST_ASSERT(secure_file_write_atomic(path, NEW_DATA, NEW_LEN, 1), "write");
    TEST_ASSERT(!secure_file_exists(stale), "stale temporary removed");
    TEST_ASSERT(holds(other_dest, OLD_DATA, OLD_LEN), "another destination's file kept");
    TEST_ASSERT(holds(lookalike, OLD_DATA, OLD_LEN), "differently named file kept");
    TEST_ASSERT(holds(unrelated, OLD_DATA, OLD_LEN), "unrelated file kept");
    TEST_ASSERT(dir_entries() == 4, "destination plus the three kept files");
    return fresh_dir() && rmdir(SF_DIR) == 0;
}

/* Only a regular file is opened for reading; a link is followed and
   reported. */
int test_secure_file_open_read(void) {
    const char *file = SF_DIR "/file", *link_path = SF_DIR "/link";
    const char *dangling = SF_DIR "/dangling", *fifo = SF_DIR "/fifo";
    TEST_ASSERT(fresh_dir(), "scratch dir");
    TEST_ASSERT(put(file, OLD_DATA, OLD_LEN), "file");
    TEST_ASSERT(symlink(file, link_path) == 0, "symlink");
    TEST_ASSERT(symlink(SF_DIR "/missing", dangling) == 0, "dangling symlink");
    TEST_ASSERT(mkfifo(fifo, 0644) == 0, "fifo");

    int via = -1;
    int fd = secure_file_open_read(file, &via);
    TEST_ASSERT(fd >= 0 && via == 0, "regular file opens, not through a link");
    close(fd);

    via = -1;
    fd = secure_file_open_read(link_path, &via);
    TEST_ASSERT(fd >= 0 && via == 1, "a link to a file opens and is reported");
    close(fd);

    TEST_ASSERT(secure_file_open_read(dangling, &via) < 0, "dangling link");
    TEST_ASSERT(secure_file_open_read(SF_DIR "/missing", &via) < 0, "missing file");
    TEST_ASSERT(secure_file_open_read(SF_DIR, &via) < 0, "a directory is not opened");
    /* Must return at once: a FIFO without a writer would block a plain open. */
    TEST_ASSERT(secure_file_open_read(fifo, &via) < 0, "a FIFO is not opened");
    TEST_ASSERT(secure_file_open_read(NULL, &via) < 0, "NULL path");
    fd = secure_file_open_read(file, NULL);
    TEST_ASSERT(fd >= 0, "via_symlink_out is optional");
    close(fd);
    return fresh_dir() && rmdir(SF_DIR) == 0;
}

/* A file that others can access is tightened to 0600 when it is ours to
   change, and is otherwise left exactly as it is. */
int test_secure_file_restrict(void) {
    const char *path = SF_DIR "/file", *hard = SF_DIR "/hardlink";
    const char *fifo = SF_DIR "/fifo";
    TEST_ASSERT(fresh_dir(), "scratch dir");
    TEST_ASSERT(put(path, OLD_DATA, OLD_LEN), "file");

    /* Ours, regular, one link, opened directly: tightened. */
    static const int loose_modes[] = { 0644, 0640, 0604, 0660, 0666, 0755 };
    for (size_t i = 0; i < sizeof(loose_modes) / sizeof(loose_modes[0]); i++) {
        TEST_ASSERT(chmod(path, (mode_t)loose_modes[i]) == 0, "loosen");
        int fd = open(path, O_RDONLY);
        TEST_ASSERT(fd >= 0, "open");
        secure_file_access_t access = secure_file_restrict(fd, path, 0);
        close(fd);
        TEST_ASSERT(access == SECURE_FILE_PRIVATE, "tightened");
        TEST_ASSERT(file_mode(path) == 0600, "mode is 0600 afterwards");
    }

    /* Already owner-only: nothing changes. */
    TEST_ASSERT(chmod(path, 0400) == 0, "owner read-only");
    int fd = open(path, O_RDONLY);
    TEST_ASSERT(fd >= 0, "open");
    TEST_ASSERT(secure_file_restrict(fd, path, 0) == SECURE_FILE_PRIVATE, "already private");
    close(fd);
    TEST_ASSERT(file_mode(path) == 0400, "an owner-only mode is not changed");

    /* Reached through a symbolic link: left alone, whatever its mode. */
    TEST_ASSERT(chmod(path, 04755) == 0, "setuid mode");
    fd = open(path, O_RDONLY);
    TEST_ASSERT(fd >= 0, "open");
    TEST_ASSERT(secure_file_restrict(fd, path, 1) == SECURE_FILE_WORLD_ACCESSIBLE,
                "world access reported for a file behind a link");
    TEST_ASSERT(file_mode(path) == 04755, "mode behind a link untouched");
    TEST_ASSERT(chmod(path, 0640) == 0, "group mode");
    TEST_ASSERT(secure_file_restrict(fd, path, 1) == SECURE_FILE_GROUP_ACCESSIBLE,
                "group access reported for a file behind a link");
    TEST_ASSERT(file_mode(path) == 0640, "mode behind a link untouched");
    close(fd);

    /* A second hard link: the file may also be something else. */
    TEST_ASSERT(link(path, hard) == 0, "hard link");
    TEST_ASSERT(chmod(path, 0644) == 0, "loosen");
    fd = open(path, O_RDONLY);
    TEST_ASSERT(fd >= 0, "open");
    TEST_ASSERT(secure_file_restrict(fd, path, 0) == SECURE_FILE_WORLD_ACCESSIBLE,
                "world access reported for a hard-linked file");
    close(fd);
    TEST_ASSERT(file_mode(path) == 0644, "hard-linked file untouched");
    TEST_ASSERT(unlink(hard) == 0, "remove hard link");

    /* Not a regular file. */
    TEST_ASSERT(mkfifo(fifo, 0644) == 0, "fifo");
    fd = open(fifo, O_RDONLY | O_NONBLOCK);
    TEST_ASSERT(fd >= 0, "open fifo");
    TEST_ASSERT(secure_file_restrict(fd, fifo, 0) == SECURE_FILE_WORLD_ACCESSIBLE,
                "world access reported for a FIFO");
    close(fd);
    TEST_ASSERT(file_mode(fifo) == 0644, "FIFO untouched");

    /* Owned by another user.  Only root can set that up. */
    if (geteuid() == 0) {
        TEST_ASSERT(chmod(path, 0640) == 0 && chown(path, 65534, 65534) == 0,
                    "give the file away");
        fd = open(path, O_RDONLY);
        TEST_ASSERT(fd >= 0, "open");
        TEST_ASSERT(secure_file_restrict(fd, path, 0) == SECURE_FILE_GROUP_ACCESSIBLE,
                    "another user's group-shared file is reported");
        close(fd);
        TEST_ASSERT(file_mode(path) == 0640, "another user's file untouched");
    }

    TEST_ASSERT(secure_file_restrict(-1, path, 0) == SECURE_FILE_WORLD_ACCESSIBLE,
                "a file that cannot be examined is not called private");
    TEST_ASSERT(holds(path, OLD_DATA, OLD_LEN), "content untouched");
    return fresh_dir() && rmdir(SF_DIR) == 0;
}
