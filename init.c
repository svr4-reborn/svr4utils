#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stropts.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <stdlib.h>

#define SAD_SAP (('D' << 8) | 0x01)
#define SAP_RANGE 2
#define SAP_ALL 3
#define FMNAMESZ 8
#define MAXAPUSH 8
#define GVID_SETTABLE ((('G' << 8) | 'v') << 16 | 1)
#define SVR4_IOCPARM_MASK 0xffUL
#define SVR4_IOC_IN 0x80000000UL
#define SVR4_IOW(group, number, type) \
    (SVR4_IOC_IN | ((sizeof(type) & SVR4_IOCPARM_MASK) << 16) | ((group) << 8) | (number))
#define SVR4_SIOCSIFADDR SVR4_IOW('i', 12, struct ifreq)
#define SVR4_SIOCSIFFLAGS SVR4_IOW('i', 16, struct ifreq)
#define SVR4_SIOCSIFNETMASK SVR4_IOW('i', 26, struct ifreq)
#define SVR4_SIOCSIFNAME SVR4_IOW('i', 73, struct ifreq)

typedef unsigned int major_t;

typedef struct gvid {
    unsigned long gvid_num;
    dev_t *gvid_buf;
    major_t gvid_maj;
} gvid_t;

struct apcommon {
    unsigned int apc_cmd;
    long apc_major;
    long apc_minor;
    long apc_lastminor;
    unsigned int apc_npush;
};

struct strapush {
    struct apcommon sap_common;
    char sap_list[MAXAPUSH][FMNAMESZ + 1];
};

#define sap_cmd sap_common.apc_cmd
#define sap_major sap_common.apc_major
#define sap_minor sap_common.apc_minor
#define sap_lastminor sap_common.apc_lastminor
#define sap_npush sap_common.apc_npush

static int workstation_initialized;

static int open_console(void) {
    int fd;

    fd = open("/dev/vt00", O_RDWR);
    if(fd >= 0)
        return fd;
    fd = open("/dev/syscon", O_RDWR);
    if(fd < 0)
        fd = open("/dev/console", O_RDWR);
    if(fd < 0)
        fd = open("/dev/null", O_RDWR);
    return fd;
}

static void configure_autopush_entry(long major, long minor, long lastminor,
        unsigned int command, const char *const modules[], unsigned int count) {
    struct strapush push = {0};
    int fd;
    unsigned int i;

    fd = open("/dev/sad/admin", O_RDWR);
    if(fd < 0)
        return;

    push.sap_cmd = command;
    push.sap_major = major;
    push.sap_minor = minor;
    push.sap_lastminor = lastminor;
    push.sap_npush = count;

    for(i = 0; i < count && i < MAXAPUSH; ++i) {
        snprintf(push.sap_list[i], sizeof(push.sap_list[i]), "%s", modules[i]);
    }

    ioctl(fd, SAD_SAP, &push);
    close(fd);
}

static void configure_console_autopush(void) {
    static const char *const console_modules[] = {
        "char",
        "ansi",
        "ldterm",
        "ttcompat"
    };
    static const char *const tty_modules[] = {
        "ldterm",
        "ttcompat"
    };

    configure_autopush_entry(5, -1, 0, SAP_ALL,
        console_modules, sizeof(console_modules) / sizeof(console_modules[0]));
    configure_autopush_entry(3, 0, 129, SAP_RANGE,
        tty_modules, sizeof(tty_modules) / sizeof(tty_modules[0]));
}

static void initialize_workstation_console(void) {
    struct stat kdvm_stat;
    struct stat mux_stat;
    gvid_t mapping;
    dev_t video_devices[1];
    int muxfd;
    int devfd;
    int gvidfd;

    if(workstation_initialized)
        return;

    muxfd = open("/dev/vt00", O_RDWR);
    if(muxfd < 0)
        return;

    if(fstat(muxfd, &mux_stat) < 0) {
        close(muxfd);
        return;
    }

    devfd = open("/dev/kd/kd00", O_RDWR);
    if(devfd < 0) {
        close(muxfd);
        return;
    }

    if(ioctl(muxfd, I_PLINK, devfd) < 0) {
        close(devfd);
        close(muxfd);
        return;
    }

    if(stat("/dev/kd/kdvm00", &kdvm_stat) == 0) {
        video_devices[0] = kdvm_stat.st_rdev;
        gvidfd = open("/dev/vidadm", O_RDWR);
        if(gvidfd >= 0) {
            mapping.gvid_num = 1;
            mapping.gvid_buf = video_devices;
            mapping.gvid_maj = (major_t)getmajor(mux_stat.st_rdev);
            ioctl(gvidfd, GVID_SETTABLE, &mapping);
            close(gvidfd);
        }
    }

    close(devfd);
    close(muxfd);
    workstation_initialized = 1;
}

static unsigned long ipv4_address(unsigned int first, unsigned int second,
        unsigned int third, unsigned int fourth) {
    return ((fourth & 0xff) << 24) | ((third & 0xff) << 16)
        | ((second & 0xff) << 8) | (first & 0xff);
}

static int stream_ioctl(int fd, int command, void *buffer, int length) {
    struct strioctl request;

    memset(&request, 0, sizeof(request));
    request.ic_cmd = command;
    request.ic_timout = 0;
    request.ic_len = length;
    request.ic_dp = buffer;
    return ioctl(fd, I_STR, &request);
}

static int name_loopback_provider(int ipfd, int linkid) {
    struct ifreq request;

    memset(&request, 0, sizeof(request));
    snprintf(request.ifr_name, sizeof(request.ifr_name), "lo0");
    request.ifr_metric = linkid;
    return stream_ioctl(ipfd, SVR4_SIOCSIFNAME, &request, sizeof(request));
}

static void fill_ipv4_request(struct ifreq *request, unsigned long address) {
    struct sockaddr_in *sin;

    memset(request, 0, sizeof(*request));
    snprintf(request->ifr_name, sizeof(request->ifr_name), "lo0");
    sin = (struct sockaddr_in *)&request->ifr_addr;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = address;
}

static int configure_loopback_provider(int ipfd) {
    struct ifreq request;

    memset(&request, 0, sizeof(request));
    snprintf(request.ifr_name, sizeof(request.ifr_name), "lo0");
    request.ifr_flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
    if(stream_ioctl(ipfd, SVR4_SIOCSIFFLAGS, &request, sizeof(request)) < 0)
        return -1;

    fill_ipv4_request(&request, ipv4_address(255, 0, 0, 0));
    if(stream_ioctl(ipfd, SVR4_SIOCSIFNETMASK, &request, sizeof(request)) < 0)
        return -1;

    fill_ipv4_request(&request, ipv4_address(127, 0, 0, 1));
    return stream_ioctl(ipfd, SVR4_SIOCSIFADDR, &request, sizeof(request));
}

static void link_protocol_to_ip(const char *protocol_path) {
    int protocolfd;
    int ipfd;

    protocolfd = open(protocol_path, O_RDWR);
    if(protocolfd < 0)
        return;

    ipfd = open("/dev/ip", O_RDWR);
    if(ipfd >= 0) {
        ioctl(protocolfd, I_PLINK, ipfd);
        close(ipfd);
    }
    close(protocolfd);
}

static void initialize_network_loopback(void) {
    static const char *const protocol_paths[] = {
        "/dev/tcp",
        "/dev/udp",
        "/dev/rawip",
        "/dev/icmp"
    };
    unsigned int i;
    int ipfd;
    int loopfd;
    int linkid;

    ipfd = open("/dev/ip", O_RDWR);
    if(ipfd < 0)
        return;

    loopfd = open("/dev/loop", O_RDWR);
    if(loopfd < 0) {
        close(ipfd);
        return;
    }

    linkid = ioctl(ipfd, I_PLINK, loopfd);
    if(linkid >= 0 && name_loopback_provider(ipfd, linkid) == 0) {
        if(configure_loopback_provider(ipfd) == 0) {
            for(i = 0; i < sizeof(protocol_paths) / sizeof(protocol_paths[0]); ++i) {
                link_protocol_to_ip(protocol_paths[i]);
            }
        }
    }

    close(loopfd);
    close(ipfd);
}

static void configure_console(int fd) {
    struct termios modes;

    if(fd < 0 || !isatty(fd))
        return;
    if(tcgetattr(fd, &modes) < 0)
        return;

    modes.c_iflag &= ~(IGNCR | INLCR);
    modes.c_iflag |= BRKINT | IGNPAR | ISTRIP | IXON | IXANY | ICRNL;
    modes.c_oflag |= OPOST | ONLCR | XTABS;
    modes.c_cflag &= ~CSIZE;
    modes.c_cflag |= CS8 | CREAD;
    modes.c_lflag |= ISIG | ICANON | ECHO | ECHOK;
    modes.c_cc[VINTR] = 0x7f;
    modes.c_cc[VQUIT] = 0x1c;
    modes.c_cc[VERASE] = '\b';
    modes.c_cc[VKILL] = 0x15;
    modes.c_cc[VEOF] = 0x04;
    tcsetattr(fd, TCSANOW, &modes);
}

static void init_stdio(void) {
    int fd;

    fd = open_console();
    if(fd < 0)
        return;

    configure_console(fd);

    if(fd != STDIN_FILENO) {
        dup2(fd, STDIN_FILENO);
    }
    if(fd != STDOUT_FILENO) {
        dup2(fd, STDOUT_FILENO);
    }
    if(fd != STDERR_FILENO) {
        dup2(fd, STDERR_FILENO);
    }
    if(fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != STDERR_FILENO) {
        close(fd);
    }
}

char* const default_environ[] = {
    "PATH=/bin:/usr/bin:/sbin:/usr/sbin",
    "HOME=/root",
    "TERM=vt100",
    nullptr
};

int launch_process(const char *path, char *const argv[], char *const envp[]) {
    if(fork() == 0) {
        if(setsid() >= 0) {
            init_stdio();
        }
        execve(path, argv, envp);
        _exit(1);
    }
    return 0;
}

int main(int argc, char **argv) {
    static char *const shell_argv[] = {
        (char *)"-bash",
        nullptr
    };

    configure_console_autopush();
    initialize_workstation_console();
    initialize_network_loopback();
    init_stdio();
    printf("The system is coming up.\r\n");
    fflush(stdout);

    launch_process("/bin/bash", shell_argv, default_environ);

    for(;;) {
        pause();
    }
}