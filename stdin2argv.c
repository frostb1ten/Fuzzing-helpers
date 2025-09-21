#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <spawn.h>
#include <stdarg.h>

typedef int (*libc_start_main_fn)(
    int (*main)(int, char **, char **),
    int, char **, void (*init)(void),
    void (*fini)(void), void (*rtld_fini)(void), void *);

static libc_start_main_fn real_start = NULL;
static int (*real_main_fn)(int, char **, char **) = NULL;
#define ALLOWED_FLAGS_ENV "ALLOWED_FLAGS"
#define MAX_INPUT_SIZE (1 << 12)  /* 4KB buffer */
#define MAX_ARGV_SIZE 512         /* Max arguments */

static void log_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

static int allow_flag(const char *flag) {
    if (!flag || flag[0] != '-') {
        return 0;
    }
    if (getenv("ALLOW_ALL_FLAGS")) {
        return 1;
    }
    static const char *default_allowed[] = {"-V", "-h", "-K", "-C", "-T", "-n", NULL};
    const char *env_flags = getenv(ALLOWED_FLAGS_ENV);
    char *flags_copy = NULL;
    int allowed = 0;
    for (int i = 0; default_allowed[i]; i++) {
        if (strcmp(flag, default_allowed[i]) == 0) {
            return 1;
        }
    }
    if (env_flags) {
        flags_copy = strdup(env_flags);
        if (!flags_copy) {
            log_error("stdin2argv: Failed to allocate memory for flags\n");
            return 0;
        }
        char *token = strtok(flags_copy, ",");
        while (token) {
            if (strcmp(flag, token) == 0) {
                allowed = 1;
                break;
            }
            token = strtok(NULL, ",");
        }
        free(flags_copy);
    }
    return allowed;
}

static int wrapped_main(int argc, char **argv, char **envp) {
    static char buf[MAX_INPUT_SIZE];
    static char *new_argv[MAX_ARGV_SIZE];
    ssize_t n;
    n = read(STDIN_FILENO, buf, MAX_INPUT_SIZE - 1);
    if (n < 0) {
        log_error("stdin2argv: Failed to read from stdin: %s\n", strerror(errno));
        return real_main_fn(argc, argv, envp);
    }
    if (n == 0) {
        log_error("stdin2argv: Empty input from stdin\n");
        return real_main_fn(argc, argv, envp);
    }
    buf[n] = '\0';
    int new_argc = 0;
    char *token = strtok(buf, " \t\r\n");
    if (token && token[0] != '\0') {
        new_argv[new_argc++] = token;
        token = strtok(NULL, " \t\r\n");
    } else {
        new_argv[new_argc++] = argv[0];
    }
    while (token && new_argc < MAX_ARGV_SIZE - 1) {
        new_argv[new_argc++] = allow_flag(token) ? token : (char *)"-V";
        token = strtok(NULL, " \t\r\n");
    }
    new_argv[new_argc] = NULL;
    extern char *program_invocation_name, *program_invocation_short_name;
    program_invocation_name = new_argv[0];
    program_invocation_short_name = new_argv[0];
    return real_main_fn(new_argc, new_argv, envp);
}

int __libc_start_main(
    int (*main)(int, char **, char **),
    int argc, char **ubp_av,
    void (*init)(void), void (*fini)(void),
    void (*rtld_fini)(void), void *stack_end) {
    real_start = (libc_start_main_fn)dlsym(RTLD_NEXT, "__libc_start_main");
    if (!real_start) {
        log_error("stdin2argv: dlsym failed for __libc_start_main: %s\n", dlerror());
        _exit(1);
    }
    real_main_fn = main;
    return real_start(wrapped_main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}

static int deny_exec_errno(void) {
    errno = EPERM;
    return -1;
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    (void)path; (void)argv; (void)envp;
    log_error("stdin2argv: execve blocked\n");
    return deny_exec_errno();
}

int execv(const char *path, char *const argv[]) {
    (void)path; (void)argv;
    log_error("stdin2argv: execv blocked\n");
    return deny_exec_errno();
}

int execvp(const char *file, char *const argv[]) {
    (void)file; (void)argv;
    log_error("stdin2argv: execvp blocked\n");
    return deny_exec_errno();
}

int execvpe(const char *file, char *const argv[], char *const envp[]) {
    (void)file; (void)argv; (void)envp;
    log_error("stdin2argv: execvpe blocked\n");
    return deny_exec_errno();
}

int posix_spawn(
    pid_t *__restrict pid,
    const char *__restrict path,
    const posix_spawn_file_actions_t *__restrict file_actions,
    const posix_spawnattr_t *__restrict attrp,
    char *const argv[__restrict],
    char *const envp[__restrict]) {
    (void)pid; (void)path; (void)file_actions; (void)attrp; (void)argv; (void)envp;
    log_error("stdin2argv: posix_spawn blocked\n");
    return EPERM;
}

int posix_spawnp(
    pid_t *__restrict pid,
    const char *__restrict file,
    const posix_spawn_file_actions_t *__restrict file_actions,
    const posix_spawnattr_t *__restrict attrp,
    char *const argv[__restrict],
    char *const envp[__restrict]) {
    (void)pid; (void)file; (void)file_actions; (void)attrp; (void)argv; (void)envp;
    log_error("stdin2argv: posix_spawnp blocked\n");
    return EPERM;
}

int system(const char *cmd) {
    (void)cmd;
    log_error("stdin2argv: system blocked\n");
    return 127;
}

FILE *popen(const char *command, const char *type) {
    (void)command; (void)type;
    log_error("stdin2argv: popen blocked\n");
    errno = EPERM;
    return NULL;
}
