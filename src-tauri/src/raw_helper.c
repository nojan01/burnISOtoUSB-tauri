// Acquire one external whole-media descriptor, then permanently drop sudo privileges.
#include <CoreFoundation/CoreFoundation.h>
#include <DiskArbitration/DiskArbitration.h>
#include <IOKit/IOKitLib.h>
#include <ctype.h>
#include <err.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static unsigned long long decimal(const char *s) {
    if (!s || !*s || strspn(s, "0123456789") != strlen(s)) errx(1, "Invalid identifier");
    char *end;
    unsigned long long n = strtoull(s, &end, 10);
    if (*end || n == ULLONG_MAX) errx(1, "Invalid identifier");
    return n;
}

static void check_media(DASessionRef session, const char *name, uint64_t expected) {
    DADiskRef disk = DADiskCreateFromBSDName(NULL, session, name);
    if (!disk) errx(1, "Device disappeared");
    CFDictionaryRef info = DADiskCopyDescription(disk);
    io_service_t media = DADiskCopyIOMedia(disk);
    uint64_t actual = 0;
    if (!info || !media || IORegistryEntryGetRegistryEntryID(media, &actual) ||
        actual != expected ||
        CFDictionaryGetValue(info, kDADiskDescriptionMediaWholeKey) != kCFBooleanTrue ||
        (CFDictionaryGetValue(info, kDADiskDescriptionDeviceInternalKey) != kCFBooleanFalse &&
         CFDictionaryGetValue(info, kDADiskDescriptionMediaRemovableKey) != kCFBooleanTrue))
        errx(1, "Selected external medium changed or unavailable");
    IOObjectRelease(media);
    CFRelease(info);
    CFRelease(disk);
}

int main(int argc, char **argv) {
    if (argc < 5 || strncmp(argv[1], "disk", 4)) errx(1, "Expected disk, identity, mode and worker");
    decimal(argv[1] + 4);
    uint64_t identity = decimal(argv[2]);
    int flags;
    if (!strcmp(argv[3], "read")) flags = O_RDONLY;
    else if (!strcmp(argv[3], "write")) flags = O_RDWR;
    else errx(1, "Unknown access mode");
    unsigned long long user = decimal(getenv("SUDO_UID"));
    if (!user || user >= UINT_MAX || geteuid()) errx(1, "Expected sudo from a user account");
    struct passwd *pw = getpwuid((uid_t)user);
    if (!pw) errx(1, "Unknown account");
    gid_t gid = pw->pw_gid;
    DASessionRef session = DASessionCreate(NULL);
    if (!session) errx(1, "Disk Arbitration unavailable");
    char path[64];
    if (snprintf(path, sizeof(path), "/dev/r%s", argv[1]) >= (int)sizeof(path)) errx(1, "Device name too long");
    check_media(session, argv[1], identity);
    int fd = open(path, flags | O_NOFOLLOW);
    if (fd < 0) err(1, "open raw device");
    check_media(session, argv[1], identity);
    CFRelease(session);
    if (initgroups(pw->pw_name, gid) || setgid(gid) || setuid((uid_t)user) ||
        getuid() != user || geteuid() != user) err(1, "drop privileges");
    if (dup2(fd, 3) < 0) err(1, "transfer device descriptor");
    if (fd != 3) close(fd);
    if (setenv("BURNISO_RAW_DEVICE", path, 1)) err(1, "set worker device");
    execv(argv[4], argv + 4);
    err(1, "start unprivileged worker");
}
