#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

// Author: David Vanhoucke <dvanhoucke@redborder.com>

int main() {
    printf("==========================================\n");
    printf(" Hello from an independent C binary!\n");
    printf("==========================================\n");

    // 1. Check Process Isolation
    printf("[+] My isolated PID inside this environment is: %d\n", getpid());

    // 2. Test File Isolation (Write a file inside the environment)
    printf("[+] Attempting to write a file to /pepe.txt...\n");
    FILE *f = fopen("/pepe.txt", "w");
    if (f == NULL) {
        perror("[-] File write failed");
    } else {
        fprintf(f, "Containers are just isolated processes!\n");
        fclose(f);
        printf("[+] Success! Check 'cat /pepe.txt' in your container shell.\n");
    }

    printf("==========================================\n");
    return 0;
}

