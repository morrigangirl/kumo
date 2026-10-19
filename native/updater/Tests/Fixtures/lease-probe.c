#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    int fd;
    if (!strcmp(argv[1], "holding-fd")) fd = atoi(argv[2]);
    else {
        fd = open(argv[2], O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) return 65;
        if (flock(fd, LOCK_SH | LOCK_NB) != 0) return 73;
        if (!strcmp(argv[1], "try-sh")) { close(fd); return 0; }
        if (strcmp(argv[1], "inherit")) return 64;
        if (fcntl(fd, F_SETFD, 0) < 0) return 66;
        char number[32]; snprintf(number, sizeof(number), "%d", fd);
        execl(argv[0], argv[0], "holding-fd", number, NULL);
        return 67;
    }
    struct stat state;
    if (fstat(fd, &state) != 0 || !S_ISREG(state.st_mode)) return 68;
    puts("ready"); fflush(stdout);
    char byte; (void)read(STDIN_FILENO, &byte, 1);
    close(fd); return 0;
}
