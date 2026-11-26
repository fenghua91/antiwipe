
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
int main(int argc, char **argv) {
    if (argc < 3) { printf("usage: fdprobe <path> ro|rw [secs]\n"); return 2; }
    int rw = !strcmp(argv[2], "rw");
    int secs = argc > 3 ? atoi(argv[3]) : 3;
    printf("[fdprobe] pid=%d open %s (%s)\n", getpid(), argv[1], rw ? "O_RDWR" : "O_RDONLY");
    fflush(stdout);
    int fd = open(argv[1], rw ? O_RDWR : O_RDONLY);
    if (fd < 0) { printf("[fdprobe] open failed: %s\n", strerror(errno)); return 1; }
    printf("[fdprobe] fd=%d hold %ds (no write)\n", fd, secs);
    fflush(stdout);
    sleep(secs);
    printf("[fdprobe] survived\n");
    close(fd);
    return 0;
}
