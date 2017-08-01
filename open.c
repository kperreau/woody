#include "woody.h"

static int stat_file(int fd, struct stat *stat)
{
    if (fstat(fd, stat) < 0)
        return 0;
    else
        return 1;
}

static int map_file(int fd, size_t size, char **data)
{
    if ((*data = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
        return 0;
    else
        return 1;
}

void *read_file(char *fn, size_t *len)
{
    struct stat stat;
    int         fd;
    char        *data;
    char        *out;

    if ((fd = open(fn, O_RDONLY)) == -1)
        goto open_error;
    if (!stat_file(fd, &stat))
        goto stat_error;
    if (!map_file(fd, stat.st_size, &data))
        goto map_error;
    *len = stat.st_size;
    out = malloc(stat.st_size);
    memcpy(out, data, stat.st_size);
    munmap(data, stat.st_size);
    return out;

map_error:
stat_error:
    close(fd);
open_error:
    printf("[-] %s: %s\n", fn, strerror(errno));
    return 0;
}

int write_file(char *fn, char *data, size_t size)
{
    int fd;

    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd == -1)
    {
        printf("[-] %s: %s\n", fn, strerror(errno));
        return 0;
    }
    if (!write(fd, data, size))
    {
        printf("[-] %s write failed\n", fn);
        return 0;
    }
    printf("[+] wrote %s\n", fn);
    return 1;
}

