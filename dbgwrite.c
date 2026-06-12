#include <unistd.h>
#include <sys/syscall.h>
#include <bits/syscall.h>

#ifndef SYS_clocal
#define SYS_clocal 127
#endif

int main(void) {
    char buf[1024];
    ssize_t n;
    while ((n = read(0, buf, sizeof(buf))) > 0) {
        (void)syscall(SYS_clocal, 1, buf, (unsigned int)n, 0, 0);
    }
    return 0;
}
