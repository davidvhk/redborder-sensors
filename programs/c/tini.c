#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

pid_t child_pid = -1;

void forward_signal(int sig) {
    if (child_pid > 0) {
        kill(child_pid, sig);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    // Skip optional '--' separator (e.g. tini -- /bin/agent args)
    int cmd_start = 1;
    if (argc > 1 && strcmp(argv[1], "--") == 0) {
        cmd_start = 2;
    }
    if (cmd_start >= argc) {
        fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
        return 1;
    }

    // Register signal handlers to forward signals to the child
    int signals[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2};
    struct sigaction sa;
    sa.sa_handler = forward_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    for (int i = 0; i < (int)(sizeof(signals) / sizeof(signals[0])); i++) {
        sigaction(signals[i], &sa, NULL);
    }

    child_pid = fork();
    if (child_pid < 0) {
        perror("fork");
        return 1;
    }

    if (child_pid == 0) {
        // Restore default signal behaviors for the child
        sa.sa_handler = SIG_DFL;
        for (int i = 0; i < (int)(sizeof(signals) / sizeof(signals[0])); i++) {
            sigaction(signals[i], &sa, NULL);
        }
        
        // Execute the target program
        execvp(argv[cmd_start], &argv[cmd_start]);
        perror("execvp");
        return 127;
    }

    // Parent (PID 1): Reap zombies and wait for the child
    int status;
    while (1) {
        pid_t reaped = wait(&status);
        if (reaped < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (reaped == child_pid) {
            // The main child exited. Exit with its status.
            if (WIFEXITED(status)) {
                return WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                return 128 + WTERMSIG(status);
            }
            return 0;
        }
    }
    return 0;
}
