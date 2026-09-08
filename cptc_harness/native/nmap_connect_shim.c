#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * This library is loaded only into the network-namespaced Nmap process.  It
 * does not proxy a socket: it asks the guarded parent to make one exact TCP
 * attempt, then returns that attempt's errno to Nmap.  The parent never gives
 * its connected socket to this process.
 */

#define REQUEST_MAGIC UINT32_C(0x43504e51) /* CPNQ */
#define RESPONSE_MAGIC UINT32_C(0x43504e52) /* CPNR */

struct bridge_request {
    uint32_t magic;
    uint16_t version;
    uint16_t family;
    uint16_t port;
    uint16_t reserved;
    unsigned char address[16];
};

struct bridge_response {
    uint32_t magic;
    int32_t result;
    int32_t error_number;
};

static int bridge_fd(void) {
    const char *value = getenv("CPTC_NMAP_RPC_FD");
    char *end = NULL;
    long fd;

    if (value == NULL || *value == '\0') {
        return -1;
    }
    errno = 0;
    fd = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || fd < 0 || fd > 1048576) {
        return -1;
    }
    return (int)fd;
}

static int transfer(int fd, void *buffer, size_t size, int sending) {
    size_t done = 0;
    while (done < size) {
        ssize_t count = sending ? send(fd, (const char *)buffer + done, size - done, MSG_NOSIGNAL)
                                : recv(fd, (char *)buffer + done, size - done, 0);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return -1;
        }
        done += (size_t)count;
    }
    return 0;
}

int connect(int fd, const struct sockaddr *address, socklen_t address_length) {
    struct bridge_request request;
    struct bridge_response response;
    int rpc;

    (void)fd;
    if (address == NULL || (address->sa_family != AF_INET && address->sa_family != AF_INET6)) {
        errno = EPERM;
        return -1;
    }
    memset(&request, 0, sizeof(request));
    request.magic = REQUEST_MAGIC;
    request.version = 1;
    request.family = (uint16_t)address->sa_family;

    if (address->sa_family == AF_INET) {
        const struct sockaddr_in *ipv4;
        if (address_length < sizeof(*ipv4)) {
            errno = EINVAL;
            return -1;
        }
        ipv4 = (const struct sockaddr_in *)address;
        request.port = ntohs(ipv4->sin_port);
        memcpy(request.address, &ipv4->sin_addr, sizeof(ipv4->sin_addr));
    } else {
        const struct sockaddr_in6 *ipv6;
        if (address_length < sizeof(*ipv6)) {
            errno = EINVAL;
            return -1;
        }
        ipv6 = (const struct sockaddr_in6 *)address;
        request.port = ntohs(ipv6->sin6_port);
        memcpy(request.address, &ipv6->sin6_addr, sizeof(ipv6->sin6_addr));
    }

    rpc = bridge_fd();
    if (rpc < 0 || transfer(rpc, &request, sizeof(request), 1) != 0 ||
        transfer(rpc, &response, sizeof(response), 0) != 0 || response.magic != RESPONSE_MAGIC) {
        errno = EIO;
        return -1;
    }
    if (response.result == 0) {
        return 0;
    }
    errno = response.error_number > 0 ? response.error_number : EIO;
    return -1;
}
