#ifndef __NET_API_H__
#define __NET_API_H__


#include <sys/types.h>
#include <sys/socket.h>

int net_socket(int domain, int type, int protocol);
int net_bind(int sockid, const struct sockaddr *addr, socklen_t addrlen);
int net_listen(int sockid, int backlog);
int net_accept(int sockid, struct sockaddr *addr, socklen_t *addrlen);
ssize_t net_recv(int sockid, char *buf, size_t len, int flags);
ssize_t net_send(int sockid, const char *buf, size_t len);
int net_close(int sockid);

void net_tcp_setup(void);


int socket(int domain, int type, int protocol);
int bind(int sockid, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockid, int backlog);
int accept(int sockid, struct sockaddr *addr, socklen_t *addrlen);
ssize_t recv(int sockid, void *buf, size_t len, int flags);
ssize_t send(int sockid, const void *buf, size_t len, int flags);

#endif
