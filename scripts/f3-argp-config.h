/* macOS 10.15+/11+ configuration for argp-standalone 1.5.0.
 * Only system libc is used; gettext and Homebrew are not required. */
#define HAVE_CONFIG_H 1
#define HAVE_ALLOCA_H 1
#define HAVE_LIMITS_H 1
#define HAVE_UNISTD_H 1
#define HAVE_ASPRINTF 1
#define HAVE_STRNDUP 1
#define HAVE_STRCASECMP 1
#define HAVE_DECL_FLOCKFILE 1
#define HAVE_DECL_PUTC_UNLOCKED 1
#define HAVE_DECL_PROGRAM_INVOCATION_NAME 0
#define HAVE_DECL_PROGRAM_INVOCATION_SHORT_NAME 0
#define HAVE_DECL_FWRITE_UNLOCKED 0
#define HAVE_DECL_FPUTS_UNLOCKED 0
#define HAVE_DECL_FPUTC_UNLOCKED 0
#define HAVE_MEMPCPY 0
#define HAVE_STRCHRNUL 0
#define NORETURN __attribute__((__noreturn__))
#define PRINTF_STYLE(f, a) __attribute__((__format__(__printf__, f, a)))
#define UNUSED __attribute__((__unused__))
