#include "config.h"
#include "proxy.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

static int use_syslog;

void log_message(const char *format, ...)
{
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    if (use_syslog) syslog(LOG_NOTICE, "%s", message);
    else fprintf(stderr, "vergeauth: %s\n", message);
}

static void usage(FILE *out)
{
    fprintf(out,
        "Usage: vergeauth [-f config] [-d | -r]\n"
        "  -f path  Configuration file (default: $HOME/.vergeauth)\n"
        "  -d       Run as a daemon\n"
        "  -r       Ask the running instance to reload users (SIGHUP)\n"
        "  -h       Show help\n"
        "  -v       Show version\n");
}

static int open_pidfile(const char *path, int create)
{
    int fd = open(path, O_RDWR | O_NOFOLLOW | (create ? O_CREAT : 0), 0600);
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid()) {
        close(fd); errno = EPERM; return -1;
    }
    if (fcntl(fd, F_SETFD, FD_CLOEXEC)) { close(fd); return -1; }
    return fd;
}

static int lock_instance(const char *path)
{
    int fd = open_pidfile(path, 1);
    struct flock lock = {0};
    char pid[32];
    int length;
    if (fd < 0) {
        log_message("cannot open PID file %s: %s", path, strerror(errno)); return -1;
    }
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    if (fcntl(fd, F_SETLK, &lock)) {
        log_message("cannot lock %s (instance may already be running): %s", path, strerror(errno));
        close(fd); return -1;
    }
    length = snprintf(pid, sizeof(pid), "%ld\n", (long)getpid());
    if (ftruncate(fd, 0) || write(fd, pid, (size_t)length) != length) {
        log_message("cannot write PID file: %s", strerror(errno)); close(fd); return -1;
    }
    return fd;
}

static int reload_instance(const char *path)
{
    int fd = open_pidfile(path, 0), result = -1;
    struct flock lock = {0};
    if (fd < 0) {
        log_message("cannot open PID file %s: %s", path, strerror(errno)); return -1;
    }
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    if (fcntl(fd, F_GETLK, &lock)) log_message("cannot inspect PID lock: %s", strerror(errno));
    else if (lock.l_type == F_UNLCK || lock.l_pid <= 1) log_message("no running instance for %s", path);
    else if (kill(lock.l_pid, SIGHUP)) log_message("cannot send reload signal: %s", strerror(errno));
    else {
        log_message("reload signal sent to process %ld", (long)lock.l_pid);
        result = 0;
    }
    close(fd);
    return result;
}

/* Return 0 in the final child, 1/2 in the parent (startup success/failure). */
static int daemonize(int *ready_fd)
{
    int pipefd[2], nullfd;
    pid_t pid;
    if (pipe(pipefd)) return -1;
    pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (pid > 0) {
        char status = 0;
        ssize_t length;
        close(pipefd[1]);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
        do { length = read(pipefd[0], &status, 1); } while (length < 0 && errno == EINTR);
        close(pipefd[0]);
        return length == 1 && status == '1' ? 1 : 2;
    }
    close(pipefd[0]);
    *ready_fd = pipefd[1];
    if (setsid() < 0) return -1;
    pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);
    umask(077);
    if (chdir("/")) return -1;
    nullfd = open("/dev/null", O_RDWR);
    if (nullfd < 0) return -1;
    for (int i = 0; i < 3; ++i) {
        if (dup2(nullfd, i) < 0) { close(nullfd); return -1; }
    }
    if (nullfd > 2) close(nullfd);
    use_syslog = 1;
    openlog("vergeauth", LOG_PID, LOG_DAEMON);
    return 0;
}

int main(int argc, char **argv)
{
    int opt, daemon_mode = 0, reload = 0, ready_fd = -1, pid_fd = -1, result = EXIT_FAILURE;
    const char *selected_path = NULL;
    char *default_path = NULL, *path = NULL, *pid_path = NULL;
    char error[512];
    struct config config = {0};
    while ((opt = getopt(argc, argv, "f:drhv")) != -1) {
        switch (opt) {
        case 'f': selected_path = optarg; break;
        case 'd': daemon_mode = 1; break;
        case 'r': reload = 1; break;
        case 'h': usage(stdout); return EXIT_SUCCESS;
        case 'v': puts("vergeauth 1.0.0"); return EXIT_SUCCESS;
        default: usage(stderr); return EXIT_FAILURE;
        }
    }
    if (optind != argc || (daemon_mode && reload)) { usage(stderr); return EXIT_FAILURE; }
    if (!selected_path) {
        const char *home = getenv("HOME");
        if (!home || !*home) { log_message("HOME is not set; use -f <path>"); goto cleanup; }
        default_path = malloc(strlen(home) + sizeof("/.vergeauth"));
        if (!default_path) goto cleanup;
        sprintf(default_path, "%s/.vergeauth", home);
        selected_path = default_path;
    }
    path = realpath(selected_path, NULL);
    if (!path) { log_message("cannot resolve %s: %s", selected_path, strerror(errno)); goto cleanup; }
    pid_path = malloc(strlen(path) + sizeof(".pid"));
    if (!pid_path) goto cleanup;
    sprintf(pid_path, "%s.pid", path);
    if (reload) { result = reload_instance(pid_path) ? EXIT_FAILURE : EXIT_SUCCESS; goto cleanup; }
    if (config_load(path, 0, &config, error, sizeof(error))) { log_message("%s", error); goto cleanup; }
    signal(SIGPIPE, SIG_IGN);
    if (daemon_mode) {
        int status = daemonize(&ready_fd);
        if (status != 0) {
            if (status == 1) result = EXIT_SUCCESS;
            else log_message("daemon startup failed; check the configuration, port and system log");
            goto cleanup;
        }
    }
    pid_fd = lock_instance(pid_path);
    if (pid_fd < 0) goto cleanup;
    result = proxy_run(&config, path, ready_fd) ? EXIT_FAILURE : EXIT_SUCCESS;
    ready_fd = -1; /* proxy_run always closes its notification descriptor. */
cleanup:
    if (ready_fd >= 0) close(ready_fd);
    if (pid_fd >= 0) {
        /* Keep the inode: unlinking a lock file can let two processes own it. */
        if (ftruncate(pid_fd, 0)) log_message("cannot clear PID file: %s", strerror(errno));
        close(pid_fd);
    }
    config_free(&config);
    free(default_path); free(path); free(pid_path);
    if (use_syslog) closelog();
    return result;
}
