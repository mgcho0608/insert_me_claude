/*
 * io_ops.c - fixture file for insert_me seeder tests.
 * Contains memcpy, memmove, read, recv, recvfrom patterns.
 * Intentionally realistic; not a security reference.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#define BUFSIZE 256

// Buffer copy with memcpy - potential destination overflow
void process_packet(char *dst, const char *src, size_t len)
{
    memcpy(dst, src, len);
}

// Move overlapping memory region
void compact_buffer(char *buf, size_t start, size_t count)
{
    memmove(buf, buf + start, count);
}

// Read from file descriptor - length not validated against buffer
int read_input(int fd, char *buf)
{
    int n = read(fd, buf, BUFSIZE);
    return n;
}

// Receive data from socket - no bounds check on caller's buffer
int recv_command(int sock, char *cmd_buf, size_t buf_len)
{
    int n = recv(sock, cmd_buf, buf_len, 0);
    return n;
}

// recvfrom for UDP - length passed unchecked
int recv_udp(int sock, char *data_buf, struct sockaddr *peer, socklen_t *plen)
{
    int n = recvfrom(sock, data_buf, BUFSIZE, 0, peer, plen);
    return n;
}

// Combination: recv then memcpy without size validation
void relay_data(int src_sock, char *dst_buf)
{
    char tmp[BUFSIZE];
    int n = recv(src_sock, tmp, sizeof(tmp), 0);
    if (n > 0)
        memcpy(dst_buf, tmp, n);
}
