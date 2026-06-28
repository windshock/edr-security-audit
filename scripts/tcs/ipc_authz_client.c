#define _GNU_SOURCE

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SO_PASSCRED
#define SO_PASSCRED 16
#endif

static const unsigned char DEFAULT_SELECTOR[8] = {
    0xa2, 0xd6, 0xed, 0x9c, 0xfc, 0x61, 0xe5, 0x8c
};

static int parse_hex_selector(const char *hex, unsigned char out[8]) {
    if (strlen(hex) != 16) {
        return -1;
    }
    for (size_t i = 0; i < 8; i++) {
        unsigned int byte = 0;
        if (sscanf(hex + (i * 2), "%2x", &byte) != 1) {
            return -1;
        }
        out[i] = (unsigned char)byte;
    }
    return 0;
}

static int find_agent_ipc(char *out, size_t out_len) {
    FILE *fp = fopen("/proc/net/unix", "r");
    if (!fp) {
        perror("fopen /proc/net/unix");
        return -1;
    }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *name = strstr(line, "@agent_ipc_");
        if (!name) {
            continue;
        }
        name[strcspn(name, " \t\r\n")] = '\0';
        if (strlen(name) + 1 > out_len) {
            fclose(fp);
            errno = ENAMETOOLONG;
            return -1;
        }
        strcpy(out, name);
        fclose(fp);
        return 0;
    }

    fclose(fp);
    errno = ENOENT;
    return -1;
}

static void print_hex(const unsigned char *buf, ssize_t len) {
    for (ssize_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

static uint64_t le64(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return v;
#else
    return __builtin_bswap64(v);
#endif
}

static uint32_t read_le32(const unsigned char *p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

int main(int argc, char **argv) {
    int use_passcred = 1;
    int combined = 0;
    unsigned char selector[8];
    memcpy(selector, DEFAULT_SELECTOR, sizeof(selector));

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-passcred") == 0) {
            use_passcred = 0;
        } else if (strcmp(argv[i], "--combined") == 0) {
            combined = 1;
        } else if (strcmp(argv[i], "--selector") == 0 && i + 1 < argc) {
            if (parse_hex_selector(argv[++i], selector) != 0) {
                fprintf(stderr, "invalid selector: %s\n", argv[i]);
                return 2;
            }
        } else {
            fprintf(stderr, "usage: %s [--no-passcred] [--combined] [--selector 16hex]\n", argv[0]);
            return 2;
        }
    }

    char name[128];
    if (find_agent_ipc(name, sizeof(name)) != 0) {
        perror("find_agent_ipc");
        return 1;
    }

    printf("uid=%ld euid=%ld exe=%s socket=%s passcred=%d combined=%d\n",
           (long)getuid(), (long)geteuid(), argv[0], name, use_passcred, combined);

    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    if (use_passcred) {
        int one = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) != 0) {
            perror("setsockopt SO_PASSCRED");
            close(fd);
            return 1;
        }
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t name_len = strlen(name);
    if (name_len >= sizeof(addr.sun_path)) {
        fprintf(stderr, "socket name too long\n");
        close(fd);
        return 1;
    }
    addr.sun_path[0] = '\0';
    memcpy(addr.sun_path + 1, name + 1, name_len - 1);
    socklen_t addr_len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + name_len);

    if (connect(fd, (struct sockaddr *)&addr, addr_len) != 0) {
        perror("connect");
        close(fd);
        return 1;
    }

    struct timeval zero = {0, 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &zero, sizeof(zero));

    uint64_t len = le64(sizeof(selector));
    if (combined) {
        unsigned char packet[16];
        memcpy(packet, &len, 8);
        memcpy(packet + 8, selector, sizeof(selector));
        if (sendto(fd, packet, sizeof(packet), 0, NULL, 0) != (ssize_t)sizeof(packet)) {
            perror("sendto combined");
            close(fd);
            return 1;
        }
    } else {
        if (sendto(fd, &len, sizeof(len), 0, NULL, 0) != (ssize_t)sizeof(len)) {
            perror("sendto length");
            close(fd);
            return 1;
        }
        (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &zero, sizeof(zero));
        if (sendto(fd, selector, sizeof(selector), 0, NULL, 0) != (ssize_t)sizeof(selector)) {
            perror("sendto selector");
            close(fd);
            return 1;
        }
    }

    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &zero, sizeof(zero));

    unsigned char hdr[8];
    ssize_t got = recvfrom(fd, hdr, sizeof(hdr), 0, NULL, NULL);
    if (got < 0) {
        perror("recvfrom header");
        close(fd);
        return 1;
    }
    if (got != (ssize_t)sizeof(hdr)) {
        fprintf(stderr, "short header: %zd bytes\n", got);
        close(fd);
        return 1;
    }

    uint64_t body_len = 0;
    memcpy(&body_len, hdr, sizeof(body_len));
    body_len = le64(body_len);
    printf("response_len=%lu\n", (unsigned long)body_len);

    unsigned char body[4096];
    if (body_len > sizeof(body)) {
        fprintf(stderr, "body too large: %lu\n", (unsigned long)body_len);
        close(fd);
        return 1;
    }

    got = recvfrom(fd, body, (size_t)body_len, 0, NULL, NULL);
    if (got < 0) {
        perror("recvfrom body");
        close(fd);
        return 1;
    }

    printf("body_hex=");
    print_hex(body, got);
    printf("\n");
    printf("first_le32=");
    for (ssize_t i = 0; i + 4 <= got && i < 32; i += 4) {
        printf("%s%u", i == 0 ? "" : ",", read_le32(body + i));
    }
    printf("\n");

    close(fd);
    return 0;
}
