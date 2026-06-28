// iouring_file.c — raw io_uring 파일 생성/쓰기 PoC (liburing 불필요)
// openat + write 를 모두 io_uring op 로 수행 → openat(2)/write(2) syscall 미발생.
// 목적: io_uring 경로 파일작업이 EDR telemetry(syscall kprobe 기반)에 잡히는지 검증.
// 사용: ./iouring_file <path> <content>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>

static int io_uring_setup(unsigned e, struct io_uring_params *p){ return (int)syscall(__NR_io_uring_setup, e, p); }
static int io_uring_enter(int fd, unsigned ts, unsigned mc, unsigned fl){ return (int)syscall(__NR_io_uring_enter, fd, ts, mc, fl, NULL, 0); }

int main(int argc, char **argv){
    if (argc < 3){ fprintf(stderr,"usage: %s <path> <content>\n",argv[0]); return 2; }
    const char *path = argv[1];
    const char *data = argv[2];
    size_t dlen = strlen(data);

    struct io_uring_params p; memset(&p,0,sizeof(p));
    int ring = io_uring_setup(8,&p);
    if (ring<0){ perror("io_uring_setup"); return 1; }

    int sring_sz = p.sq_off.array + p.sq_entries*sizeof(unsigned);
    int cring_sz = p.cq_off.cqes  + p.cq_entries*sizeof(struct io_uring_cqe);
    if (p.features & IORING_FEAT_SINGLE_MMAP){
        if (cring_sz > sring_sz) sring_sz = cring_sz;
        cring_sz = sring_sz;
    }
    void *sq = mmap(0,sring_sz,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_POPULATE,ring,IORING_OFF_SQ_RING);
    void *cq = (p.features & IORING_FEAT_SINGLE_MMAP) ? sq
             : mmap(0,cring_sz,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_POPULATE,ring,IORING_OFF_CQ_RING);
    struct io_uring_sqe *sqes = mmap(0,p.sq_entries*sizeof(struct io_uring_sqe),
                                     PROT_READ|PROT_WRITE,MAP_SHARED|MAP_POPULATE,ring,IORING_OFF_SQES);
    if (sq==MAP_FAILED||cq==MAP_FAILED||sqes==MAP_FAILED){ perror("mmap"); return 1; }

    unsigned *s_tail = sq + p.sq_off.tail;
    unsigned *s_mask = sq + p.sq_off.ring_mask;
    unsigned *s_arr  = sq + p.sq_off.array;
    unsigned *c_head = cq + p.cq_off.head;
    unsigned *c_tail = cq + p.cq_off.tail;
    unsigned *c_mask = cq + p.cq_off.ring_mask;
    struct io_uring_cqe *cqes = cq + p.cq_off.cqes;

    // --- 1) IORING_OP_OPENAT (O_CREAT|O_WRONLY|O_TRUNC) ---
    unsigned idx = *s_tail & *s_mask;
    struct io_uring_sqe *sqe = &sqes[idx];
    memset(sqe,0,sizeof(*sqe));
    sqe->opcode = IORING_OP_OPENAT;
    sqe->fd = AT_FDCWD;
    sqe->addr = (unsigned long)path;
    sqe->open_flags = O_CREAT|O_WRONLY|O_TRUNC;
    sqe->len = 0644;            // mode
    sqe->user_data = 1;
    s_arr[idx] = idx;
    (*s_tail)++; __sync_synchronize();
    if (io_uring_enter(ring,1,1,IORING_ENTER_GETEVENTS)<0){ perror("enter openat"); return 1; }

    // CQE → fd
    __sync_synchronize();
    struct io_uring_cqe *c = &cqes[*c_head & *c_mask];
    int newfd = c->res;
    (*c_head)++; __sync_synchronize();
    if (newfd < 0){ fprintf(stderr,"openat op failed: %s\n", strerror(-newfd)); return 1; }
    printf("io_uring OPENAT ok, fd=%d (path=%s)\n", newfd, path);

    // --- 2) IORING_OP_WRITE ---
    idx = *s_tail & *s_mask;
    sqe = &sqes[idx];
    memset(sqe,0,sizeof(*sqe));
    sqe->opcode = IORING_OP_WRITE;
    sqe->fd = newfd;
    sqe->addr = (unsigned long)data;
    sqe->len = dlen;
    sqe->off = 0;
    sqe->user_data = 2;
    s_arr[idx] = idx;
    (*s_tail)++; __sync_synchronize();
    if (io_uring_enter(ring,1,1,IORING_ENTER_GETEVENTS)<0){ perror("enter write"); return 1; }
    __sync_synchronize();
    c = &cqes[*c_head & *c_mask];
    int wres = c->res;
    (*c_head)++; __sync_synchronize();
    if (wres < 0){ fprintf(stderr,"write op failed: %s\n", strerror(-wres)); return 1; }
    printf("io_uring WRITE ok, %d bytes\n", wres);

    printf("DONE (no openat/write syscall issued; only io_uring_setup/enter)\n");
    return 0;
}
