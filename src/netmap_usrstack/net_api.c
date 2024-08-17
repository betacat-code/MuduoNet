#include "netmap_usrstack/net_buffer.h"
#include "netmap_usrstack/net_header.h"
#include "netmap_usrstack/net_tcp.h"
#include "netmap_usrstack/net_api.h"
#include "netmap_usrstack/net_epoll.h"
#include "netmap_usrstack/net_socket.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

extern net_tcp_manager *net_get_tcp_manager(void);

// 从 TCP 接收缓冲区中复制数据到用户空间缓冲区
static int net_copy_to_user(net_tcp_stream *cur_stream, char *buf, int len) {
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (tcp == NULL) return -1;
	
	net_tcp_recv *rcv = cur_stream->rcv;

	int copylen = MIN(rcv->recvbuf->merged_len, len);
	if (copylen < 0) {
		errno = EAGAIN;
		return -1;
	} else if (copylen == 0){
		errno = 0;
		return 0;
	}

	memcpy(buf, rcv->recvbuf->head, copylen);

	RBRemove(tcp->rbm_rcv, rcv->recvbuf, copylen, AT_APP);
	rcv->rcv_wnd = rcv->recvbuf->size - rcv->recvbuf->merged_len;


	if (cur_stream->need_wnd_adv) {
		if (rcv->rcv_wnd > cur_stream->snd->eff_mss) {
			if (!cur_stream->snd->on_ackq) {
				cur_stream->snd->on_ackq = 1;
				StreamEnqueue(tcp->ackq, cur_stream);

				cur_stream->need_wnd_adv = 0;
				tcp->wakeup_flag = 0;
			}
		}
	}

	return copylen;
}


static int net_copy_from_user(net_tcp_stream *cur_stream, const char *buf, int len) {
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (tcp == NULL) return -1;
	
	net_tcp_send *snd = cur_stream->snd;
	
	int sndlen = MIN((int)snd->snd_wnd, len);
	if (sndlen <= 0) {
		errno = EAGAIN;
		return -1;
	}

	if (!snd->sndbuf) {
		snd->sndbuf = SBInit(tcp->rbm_snd, snd->iss + 1);
		if (!snd->sndbuf) {
			cur_stream->close_reason = TCP_NO_MEM;
			errno = ENOMEM;
			return -1;
		}
	}

	int ret = SBPut(tcp->rbm_snd, snd->sndbuf, buf, sndlen);
	assert(ret == sndlen);
	if (ret <= 0) {
		net_trace_api("SBPut failed. reason: %d (sndlen: %u, len: %u\n", 
				ret, sndlen, snd->sndbuf->len);
		errno = EAGAIN;
		return -1;
	}

	snd->snd_wnd = snd->sndbuf->size - snd->sndbuf->len;
	if (snd->snd_wnd <= 0) {
		net_trace_api("%u Sending buffer became full!! snd_wnd: %u\n", 
				cur_stream->id, snd->snd_wnd);
	}

	return ret;
}


static int net_close_stream_socket(int sockid) {
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	net_tcp_stream *cur_stream = tcp->smap[sockid].stream;
	if (!cur_stream) {
		net_trace_api("Socket %d: stream does not exist.\n", sockid);
		errno = ENOTCONN;
		return -1;
	}

	if (cur_stream->closed) {
		net_trace_api("Socket %d (Stream %u): already closed stream\n", 
				sockid, cur_stream->id);
		return 0;
	}
	cur_stream->closed = 1;
	
	net_trace_api("Stream %d: closing the stream.\n", cur_stream->id);
	cur_stream->socket = NULL;

	if (cur_stream->state == NET_TCP_CLOSED) {
		printf("Stream %d at TCP_ST_CLOSED. destroying the stream.\n", 
				cur_stream->id);
		
		StreamEnqueue(tcp->destroyq, cur_stream);
		tcp->wakeup_flag = 1;
		
		return 0;
	} else if (cur_stream->state == NET_TCP_SYN_SENT) {
		
		StreamEnqueue(tcp->destroyq, cur_stream);		
		tcp->wakeup_flag = 1;
		
		return -1;
	} else if (cur_stream->state != NET_TCP_ESTABLISHED &&
			   cur_stream->state != NET_TCP_CLOSE_WAIT) {
		net_trace_api("Stream %d at state %d\n", 
				cur_stream->id, cur_stream->state);
		errno = EBADF;
		return -1;
	}

	cur_stream->snd->on_closeq = 1;
	int ret = StreamEnqueue(tcp->closeq, cur_stream);
	tcp->wakeup_flag = 1;

	if (ret < 0) {
		net_trace_api("(NEVER HAPPEN) Failed to enqueue the stream to close.\n");
		errno = EAGAIN;
		return -1;
	}

	return 0;
}


static int net_close_listening_socket(int sockid) {

	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	struct _net_tcp_listener *listener = tcp->smap[sockid].listener;
	if (!listener) {
		errno = EINVAL;
		return -1;
	}

	if (listener->acceptq) {
		DestroyStreamQueue(listener->acceptq);
		listener->acceptq = NULL;
	}

	pthread_mutex_lock(&listener->accept_lock);
	pthread_cond_signal(&listener->accept_cond);
	pthread_mutex_unlock(&listener->accept_lock);

	pthread_cond_destroy(&listener->accept_cond);
	pthread_mutex_destroy(&listener->accept_lock);

	free(listener);
	tcp->smap[sockid].listener = NULL;

	return 0;
}

// 模拟了socket() 系统调用
int net_socket(int domain, int type, int protocol) {

	if (domain != AF_INET) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	if (type == SOCK_STREAM) {
		type = NET_TCP_SOCK_STREAM;
	} else {
		errno = EINVAL;
		return -1;
	}

	net_socket_map *socket = net_allocate_socket(type, 0);
	if (!socket) {
		errno = ENFILE;
		return -1;
	}

	return socket->id;
}

// 模拟了 bind() 系统调用 将一个套接字绑定到一个特定的地址和端口
int net_bind(int sockid, const struct sockaddr *addr, socklen_t addrlen) {

	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	if (sockid < 0 || sockid >= NET_MAX_CONCURRENCY) {
		errno = EBADF;
		return -1;
	}

	if (tcp->smap[sockid].socktype == NET_TCP_SOCK_UNUSED) {
		net_trace_api("Invalid socket id: %d\n", sockid);
		errno = EBADF;
		return -1;
	}

	if (tcp->smap[sockid].socktype != NET_TCP_SOCK_STREAM &&
		tcp->smap[sockid].socktype != NET_TCP_SOCK_LISTENER) {
		net_trace_api("Not a stream socket id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}

	if (!addr) {
		net_trace_api("Socket %d: empty address!\n", sockid);
		errno = EINVAL;
		return -1;
	}

	if (tcp->smap[sockid].opts & NET_TCP_ADDR_BIND) {
		net_trace_api("Socket %d: adress already bind for this socket.\n", sockid);
		errno = EINVAL;
		return -1;
	}

	if (addr->sa_family != AF_INET || addrlen < sizeof(struct sockaddr_in)) {
		net_trace_api("Socket %d: invalid argument!\n", sockid);
		errno = EINVAL;
		return -1;
	}

    //赋值给套接字的地址字段 这一步绑定
	struct sockaddr_in *addr_in = (struct sockaddr_in*)addr;
	tcp->smap[sockid].s_addr = *addr_in;

    //// 设置该套接字的绑定标志
	tcp->smap[sockid].opts |= NET_TCP_ADDR_BIND;

	return 0;
}

// 
int net_listen(int sockid, int backlog) {
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	if (sockid < 0 || sockid >= NET_MAX_CONCURRENCY) {
		errno = EBADF;
		return -1;
	}
	if (tcp->smap[sockid].socktype == NET_TCP_SOCK_UNUSED) {
		net_trace_api("Socket %d: invalid argument!\n", sockid);
		errno = EBADF;
		return -1;
	}
	if (tcp->smap[sockid].socktype == NET_TCP_SOCK_STREAM) {
		tcp->smap[sockid].socktype = NET_TCP_SOCK_LISTENER;
	}
	if (tcp->smap[sockid].socktype != NET_TCP_SOCK_LISTENER) {
		net_trace_api("Not a listening socket. id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}

	if (ListenerHTSearch(tcp->listeners, &tcp->smap[sockid].s_addr.sin_port)) {
		errno = EADDRINUSE;
		return -1;
	}
	
    // 分配一个新的监听器结构体
	net_tcp_listener *listener = (net_tcp_listener*)calloc(1, sizeof(net_tcp_listener));
	if (!listener) {
		return -1;
	}

	listener->sockid = sockid;
	listener->backlog = backlog;
	listener->socket = &tcp->smap[sockid];

	if (pthread_cond_init(&listener->accept_cond, NULL)) {
		net_trace_api("pthread_cond_init of ctx->accept_cond\n");
		free(listener);
		return -1;
	}

	if (pthread_mutex_init(&listener->accept_lock, NULL)) {
		net_trace_api("pthread_mutex_init of ctx->accept_lock\n");
		free(listener);
		return -1;
	}

    // 创建一个流队列，用于存储连接请求
	listener->acceptq = CreateStreamQueue(backlog);
	if (!listener->acceptq) {
		free(listener);
		errno = ENOMEM;
		return -1;
	}

    // 将监听器关联到套接字，并将其插入监听器哈希表
	tcp->smap[sockid].listener = listener;
	ListenerHTInsert(tcp->listeners, listener);

	return 0;
}

int net_accept(int sockid, struct sockaddr *addr, socklen_t *addrlen) {

	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	if (sockid < 0 || sockid >= NET_MAX_CONCURRENCY) {
		errno = EBADF;
		return -1;
	}

	if (tcp->smap[sockid].socktype != NET_TCP_SOCK_LISTENER) {
		errno = EINVAL;
		return -1;
	}

    // 获取监听器，并尝试从其接受队列中取出一个连接
    // 非阻塞直接返回 阻塞需要等待
	net_tcp_listener *listener = tcp->smap[sockid].listener;
	net_tcp_stream *accepted = StreamDequeue(listener->acceptq);
	if (!accepted) {
		if (listener->socket->opts & NET_TCP_NONBLOCK) {
            // 如果是非阻塞套接字，返回 `EAGAIN` 错误。
			errno = EAGAIN;
			return -1;
		} else {
            // 阻塞模式下，进入等待队列，直到有新的连接或发生异常。
			pthread_mutex_lock(&listener->accept_lock);
			while (accepted == NULL && ((accepted = StreamDequeue(listener->acceptq)) == NULL)) {
				pthread_cond_wait(&listener->accept_cond, &listener->accept_lock);
				if (tcp->ctx->done || tcp->ctx->exit) {
					pthread_mutex_unlock(&listener->accept_lock);
					errno = EINTR;
					return -1;
				}
			}
			pthread_mutex_unlock(&listener->accept_lock);
		}
	}

    // 分配新的套接字用于存储被接受的连接
	net_socket_map *socket = NULL;
	if (!accepted->socket) {
		socket = net_allocate_socket(NET_TCP_SOCK_STREAM, 0);
		if (!socket) {
			net_trace_api("Failed to create new socket!\n");
			/* TODO: destroy the stream */
			errno = ENFILE;
			return -1;
		}

        // 将新的套接字与连接流相关联
		socket->stream = accepted;
		accepted->socket = socket;

		socket->s_addr.sin_family = AF_INET;
		socket->s_addr.sin_port = accepted->dport;
		socket->s_addr.sin_addr.s_addr = accepted->daddr;
	}

    // 如果套接字不是边缘触发模式并且接受队列不为空，则添加 `NET_EPOLLIN` 事件
	if (!(listener->socket->epoll & NET_EPOLLET) &&
		!StreamQueueIsEmpty(listener->acceptq)) {
		net_epoll_add_event(tcp->ep, USR_SHADOW_EVENT_QUEUE, listener->socket, NET_EPOLLIN);		
	}
	net_trace_api("Stream %d accepted.\n", accepted->id);

	if (addr && addrlen) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		addr_in->sin_family = AF_INET;
		addr_in->sin_port = accepted->dport;
		addr_in->sin_addr.s_addr = accepted->daddr;
		*addrlen = sizeof(struct sockaddr_in);
	}

	return accepted->socket->id;
}


ssize_t net_recv(int sockid, char *buf, size_t len, int flags) {
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	if (sockid < 0 || sockid >= NET_MAX_CONCURRENCY) {
		errno = EBADF;
		return -1;
	}

	net_socket_map *socket = &tcp->smap[sockid];
	if (socket->socktype == NET_TCP_SOCK_UNUSED) {
		errno = EINVAL;
		return -1;
	}
	
	if (socket->socktype != NET_TCP_SOCK_STREAM) {
		errno = ENOTSOCK;
		return -1;
	}
	
    // 检查当前 TCP 流的状态，流应处于 
    //ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2 或 CLOSE_WAIT 状态
	net_tcp_stream *cur_stream = socket->stream;
	if (!cur_stream ||
		!(cur_stream->state == NET_TCP_ESTABLISHED ||
		  cur_stream->state == NET_TCP_CLOSE_WAIT ||
		  cur_stream->state == NET_TCP_FIN_WAIT_1 ||
		  cur_stream->state == NET_TCP_FIN_WAIT_2)) {
		errno = ENOTCONN;
		return -1;
	}
	
	net_tcp_recv *rcv = cur_stream->rcv;
    // 如果流在 CLOSE_WAIT 状态，检查接收缓冲区是否为空
	if (cur_stream->state == NET_TCP_CLOSE_WAIT) {
		if (!rcv->recvbuf) return 0;
		if (rcv->recvbuf->merged_len == 0) return 0;
	}

	if (socket->opts & NET_TCP_NONBLOCK) {
		if (!rcv->recvbuf || rcv->recvbuf->merged_len == 0) {
			errno = EAGAIN;
			return -1;
		}
	}
	
	pthread_mutex_lock(&rcv->read_lock);

#if NET_ENABLE_BLOCKING
    // 如果是阻塞模式，则等待数据到来
	if (!(socket->opts & NET_TCP_NONBLOCK)) {
		
		while (!rcv->recvbuf || rcv->recvbuf->merged_len == 0) {
			if (!cur_stream || cur_stream->state != NET_TCP_ESTABLISHED) {
				pthread_mutex_unlock(&rcv->read_lock);
				
                // 如果没有可用数据，返回 0 表示断开连接
				if (rcv->recvbuf->merged_len == 0) {
					errno = 0;
					return 0;
				} else {
					errno = EINTR;
					return -1;
				}
			}
			
			pthread_cond_wait(&rcv->read_cond, &rcv->read_lock);
		}
	}
#endif

	int ret = 0;
	switch (flags) {
		case 0: {
            // 将接收到的数据从内核缓冲区复制到用户空间缓冲区
			ret = net_copy_to_user(cur_stream, buf, len);
			break;
		}
		default: {
			pthread_mutex_unlock(&rcv->read_lock);
			ret = -1;
			errno = EINVAL;
			return ret;
		}		
	}

	int event_remaining = 0;
	if (socket->epoll & NET_EPOLLIN) {

        // 如果使用了水平触发且缓冲区中还有数据 改剩余数据标志
		if (!(socket->epoll & NET_EPOLLET) && rcv->recvbuf->merged_len > 0) {
			event_remaining = 1;
		}
	}

	if (cur_stream->state == NET_TCP_CLOSE_WAIT && 
	    rcv->recvbuf->merged_len == 0 && ret > 0) {
		event_remaining = 1;
	}
	
	pthread_mutex_unlock(&rcv->read_lock);

    // 如果有剩余事件，则重新加入 epoll 事件队列
	if (event_remaining) {
		if (socket->epoll) {
			net_epoll_add_event(tcp->ep, USR_SHADOW_EVENT_QUEUE, socket, NET_EPOLLIN);

#if NET_ENABLE_BLOCKING
		} else if (!(socket->opts & NET_TCP_NONBLOCK)) {
            
            // 如果是阻塞模式，将流加入接收阻塞列表中
			if (!cur_stream->on_rcv_br_list) {
				cur_stream->on_rcv_br_list = 1;
				TAILQ_INSERT_TAIL(&tcp->rcv_br_list, cur_stream, rcv->rcv_br_link);
				tcp->rcv_br_list_cnt ++;
			}
		}
#endif

	}

	net_trace_api("Stream %d: mtcp_recv() returning %d\n", cur_stream->id, ret);
    return ret;
}

// 通过TCP流发送数据
ssize_t net_send(int sockid, const char *buf, size_t len) {
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	if (sockid < 0 || sockid >= NET_MAX_CONCURRENCY) {
		errno = EBADF;
		return -1;
	}
	
	net_socket_map *socket = &tcp->smap[sockid];
	if (socket->socktype == NET_TCP_SOCK_UNUSED) {
		errno = EINVAL;
		return -1;
	}
	if (socket->socktype != NET_TCP_SOCK_STREAM) {
		errno = ENOTSOCK;
		return -1;
	}

	net_tcp_stream *cur_stream = socket->stream;
	if (!cur_stream ||
		!(cur_stream->state == NET_TCP_ESTABLISHED ||
		  cur_stream->state == NET_TCP_CLOSE_WAIT)) {
		errno = ENOTCONN;
		return -1;
	}

	if (len <= 0) {
		if (socket->opts & NET_TCP_NONBLOCK) {
			errno = EAGAIN;
			return -1;
		} else {
			return 0;
		}
	}

	net_tcp_send *snd = cur_stream->snd;

	pthread_mutex_lock(&snd->write_lock);

#if NET_ENABLE_BLOCKING
	if (!(socket->opts & NET_TCP_NONBLOCK)) {
		while (snd->snd_wnd <= 0) {
			if (!cur_stream || cur_stream->state != NET_TCP_ESTABLISHED) {
				pthread_mutex_unlock(&snd->write_lock);
				errno = EINTR;
				return -1;
			}
			
			pthread_cond_wait(&snd->write_cond, &snd->write_lock);
		}
	}
#endif
	int ret = net_copy_from_user(cur_stream, buf, len);
	pthread_mutex_unlock(&snd->write_lock);

	net_trace_api("net_copy_from_user --> %d, %d\n", 
		snd->on_sendq, snd->on_send_list);
	if (ret > 0 && !(snd->on_sendq || snd->on_send_list)) {
		snd->on_sendq = 1;
		StreamEnqueue(tcp->sendq, cur_stream);
		tcp->wakeup_flag = 1;
	}

	if (ret == 0 && (socket->opts & NET_TCP_NONBLOCK)) {
		ret = -1;
		errno = EAGAIN;
	}

	if (snd->snd_wnd > 0) {
		if ((socket->epoll & NET_EPOLLOUT) && !(socket->epoll & NET_EPOLLET)) {
			net_epoll_add_event(tcp->ep, USR_SHADOW_EVENT_QUEUE, socket, NET_EPOLLOUT);
#if NET_ENABLE_BLOCKING
		} else if (!(socket->opts & NET_TCP_NONBLOCK)) {
			if (!cur_stream->on_snd_br_list) {
				cur_stream->on_snd_br_list = 1;
				TAILQ_INSERT_TAIL(&tcp->snd_br_list, cur_stream, snd->snd_br_link);
				tcp->snd_br_list_cnt ++;
			}
#endif
		}
	}
	
	net_trace_api("Stream %d: mtcp_write() returning %d\n", cur_stream->id, ret);
	return ret;
}

int net_close(int sockid) {
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	if (sockid < 0 || sockid >= NET_MAX_CONCURRENCY) {
		errno = EBADF;
		return -1;
	}

	net_socket_map *socket = &tcp->smap[sockid];
	if (socket->socktype == NET_TCP_SOCK_UNUSED) {
		errno = EINVAL;
		return -1;
	}
	net_trace_api("Socket %d: mtcp_close called.\n", sockid);

	int ret = -1;
	switch (tcp->smap[sockid].socktype) {
		case NET_TCP_SOCK_STREAM: {
			ret = net_close_stream_socket(sockid);
			break;
		}
		case NET_TCP_SOCK_LISTENER: {
			ret = net_close_listening_socket(sockid);
			break;
		}
		case NET_TCP_SOCK_EPOLL: {
			ret = net_close_epoll_socket(sockid);
			break;
		}
		default: {
			errno = EINVAL;
			ret = -1;
			break;
		}
	}

	net_free_socket(sockid, 0);
	return ret;
}

// 用以上函数替换系统调用

#if NET_ENABLE_POSIX_API

int socket(int domain, int type, int protocol) {
	
	if (domain != AF_INET) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	if (type == SOCK_STREAM) {
		type = NET_TCP_SOCK_STREAM;
	} else {
		errno = EINVAL;
		return -1;
	}

	struct _net_socket *socket = net_socket_allocate(type);
	if (!socket) {
		errno = ENFILE;
		return -1;
	}

	return socket->id;
}

int bind(int sockid, const struct sockaddr *addr, socklen_t addrlen) {
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	if (sockid < 0) {
		errno = EBADF;
		return -1;
	}

	if (tcp->fdtable == NULL) {
		errno = EBADF;
		return -1;
	}

	net_trace_api(" Enter Bind \n");
	struct _net_socket *s = tcp->fdtable->sockfds[sockid];
	if (s == NULL) {
		errno = EBADF;
		return -1;
	}

	if (s->socktype == NET_TCP_SOCK_UNUSED) {
		net_trace_api("Invalid socket id: %d\n", sockid);
		errno = EBADF;
		return -1;
	}

	if (s->socktype != NET_TCP_SOCK_STREAM &&
		s->socktype != NET_TCP_SOCK_LISTENER) {
		net_trace_api("Not a stream socket id: %d\n", sockid);
		errno = ENOTSOCK;
		return -1;
	}

	if (!addr) {
		net_trace_api("Socket %d: empty address!\n", sockid);
		errno = EINVAL;
		return -1;
	}

	if (s->opts & NET_TCP_ADDR_BIND) {
		net_trace_api("Socket %d: adress already bind for this socket.\n", sockid);
		errno = EINVAL;
		return -1;
	}

	if (addr->sa_family != AF_INET || addrlen < sizeof(struct sockaddr_in)) {
		net_trace_api("Socket %d: invalid argument!\n", sockid);
		errno = EINVAL;
		return -1;
	}

	struct sockaddr_in *addr_in = (struct sockaddr_in*)addr;
	s->s_addr= *addr_in;
	s->opts |= NET_TCP_ADDR_BIND;

	return 0;
}


int listen(int sockid, int backlog) {
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	if (sockid < 0) {
		errno = -EBADF;
		return -1;
	}

	if (tcp->fdtable == NULL) {
		errno = -EBADF;
		return -1;
	}
	net_trace_api(" Enter listen\n");
	struct _net_socket *s = tcp->fdtable->sockfds[sockid];
	if (s == NULL) {
		errno = -EBADF;
		return -1;
	}

	net_trace_api(" Enter listen 1111\n");
	if (s->socktype == NET_TCP_SOCK_UNUSED) {
		net_trace_api("Socket %d: invalid argument!\n", sockid);
		errno = -EBADF;
		return -1;
	}
	if (s->socktype == NET_TCP_SOCK_STREAM) {
		s->socktype = NET_TCP_SOCK_LISTENER;
	}
	if (s->socktype != NET_TCP_SOCK_LISTENER) {
		net_trace_api("Not a listening socket. id: %d\n", sockid);
		errno = -ENOTSOCK;
		return -1;
	}

	if (ListenerHTSearch(tcp->listeners, &s->s_addr.sin_port)) {
		errno = EADDRINUSE;
		return -1;
	}
	
	net_tcp_listener *listener = (net_tcp_listener*)calloc(1, sizeof(net_tcp_listener));
	if (!listener) {
		return -1;
	}

	listener->sockid = sockid;
	listener->backlog = backlog;
	listener->s = s;

	if (pthread_cond_init(&listener->accept_cond, NULL)) {
		net_trace_api("pthread_cond_init of ctx->accept_cond\n");
		free(listener);
		return -1;
	}

	if (pthread_mutex_init(&listener->accept_lock, NULL)) {
		net_trace_api("pthread_mutex_init of ctx->accept_lock\n");
		free(listener);
		return -1;
	}

	listener->acceptq = CreateStreamQueue(backlog);
	if (!listener->acceptq) {
		free(listener);
		errno = -ENOMEM;
		return -1;
	}
	listener->sockid = sockid;

	net_trace_api(" CreateStreamQueue \n");
	s->listener = listener;
	ListenerHTInsert(tcp->listeners, listener);

	net_trace_api(" ListenerHTInsert \n");
	return 0;
}

int accept(int sockid, struct sockaddr *addr, socklen_t *addrlen) {

	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	if (sockid < 0) {
		errno = -EBADF;
		return -1;
	}
	
	if (tcp->fdtable == NULL) {
		errno = -EBADF;
		return -1;
	}
	struct _net_socket *s = tcp->fdtable->sockfds[sockid];

	if (s == NULL) {
		errno = -EBADF;
		return -1;
	}

	if (s->socktype != NET_TCP_SOCK_LISTENER) {
		errno = EINVAL;
		return -1;
	}

	net_tcp_listener *listener = s->listener;
	net_tcp_stream *accepted = StreamDequeue(listener->acceptq);
	if (!accepted) {
		if (listener->s->opts & NET_TCP_NONBLOCK) {
			errno = -EAGAIN;
			return -1;
		} else {
			net_trace_api(" Enter accept :%d, sockid:%d\n", s->id, sockid);
			pthread_mutex_lock(&listener->accept_lock);
			while (accepted == NULL && ((accepted = StreamDequeue(listener->acceptq)) == NULL)) {
				pthread_cond_wait(&listener->accept_cond, &listener->accept_lock);

				if (tcp->ctx->done || tcp->ctx->exit) {
					pthread_mutex_unlock(&listener->accept_lock);
					errno = -EINTR;
					return -1;
				}
			}
			pthread_mutex_unlock(&listener->accept_lock);
		}
	}

	struct _net_socket *socket = NULL;
	if (!accepted->s) {
		socket = net_socket_allocate(NET_TCP_SOCK_STREAM);
		if (!socket) {
			net_trace_api("Failed to create new socket!\n");
			errno = -ENFILE;
			return -1;
		}

		socket->stream = accepted;
		accepted->s = socket;

		socket->s_addr.sin_family = AF_INET;
		socket->s_addr.sin_port = accepted->dport;
		socket->s_addr.sin_addr.s_addr = accepted->daddr;
	}

	net_trace_api("Stream %d accepted.\n", accepted->id);

	if (addr && addrlen) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		addr_in->sin_family = AF_INET;
		addr_in->sin_port = accepted->dport;
		addr_in->sin_addr.s_addr = accepted->daddr;
		*addrlen = sizeof(struct sockaddr_in);
	}

	return accepted->s->id;

}

ssize_t recv(int sockid, void *buf, size_t len, int flags) {
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	if (sockid < 0) {
		errno = EBADF;
		return -1;
	}

	if (tcp->fdtable == NULL) {
		errno = EBADF;
		return -1;
	}
	struct _net_socket *s = tcp->fdtable->sockfds[sockid];
	if (s == NULL) {
		errno = EBADF;
		return -1;
	}
	if (s->socktype == NET_TCP_SOCK_UNUSED) {
		errno = EINVAL;
		return -1;
	}
	
	if (s->socktype != NET_TCP_SOCK_STREAM) {
		errno = ENOTSOCK;
		return -1;
	}
	
	net_tcp_stream *cur_stream = s->stream;
	if (!cur_stream ||
		!(cur_stream->state == NET_TCP_ESTABLISHED ||
		  cur_stream->state == NET_TCP_CLOSE_WAIT ||
		  cur_stream->state == NET_TCP_FIN_WAIT_1 ||
		  cur_stream->state == NET_TCP_FIN_WAIT_2)) {
		errno = ENOTCONN;
		return -1;
	}
	
	net_tcp_recv *rcv = cur_stream->rcv;
	if (cur_stream->state == NET_TCP_CLOSE_WAIT) {
		if (!rcv->recvbuf) return 0;
		if (rcv->recvbuf->merged_len == 0) return 0;
	}

	if (s->opts & NET_TCP_NONBLOCK) {
		if (!rcv->recvbuf || rcv->recvbuf->merged_len == 0) {
			errno = EAGAIN;
			return -1;
		}
	}
	
	pthread_mutex_lock(&rcv->read_lock);
#if NET_ENABLE_BLOCKING

	if (!(s->opts & NET_TCP_NONBLOCK)) {
		
		while (!rcv->recvbuf || rcv->recvbuf->merged_len == 0) {
			if (!cur_stream || cur_stream->state != NET_TCP_ESTABLISHED) {
				pthread_mutex_unlock(&rcv->read_lock);
				
				if (rcv->recvbuf->merged_len == 0) { //disconnect
					errno = 0;
					return 0;
				} else {
					errno = -EINTR;
					return -1;
				}
			}
			
			pthread_cond_wait(&rcv->read_cond, &rcv->read_lock);
		}
	}
#endif

	int ret = 0;
	switch (flags) {
		case 0: {
			ret = net_copy_to_user(cur_stream, buf, len);
			break;
		}
		default: {
			pthread_mutex_unlock(&rcv->read_lock);
			ret = -1;
			errno = EINVAL;
			return ret;
		}		
	}

	pthread_mutex_unlock(&rcv->read_lock);

	net_trace_api("Stream %d: mtcp_recv() returning %d\n", cur_stream->id, ret);
	
    return ret;
}

ssize_t send(int sockid, const void *buf, size_t len, int flags) {
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	if (sockid < 0) {
		errno = EBADF;
		return -1;
	}
	
	if (tcp->fdtable == NULL) {
		errno = EBADF;
		return -1;
	}
	struct _net_socket *s = tcp->fdtable->sockfds[sockid];
	if (s->socktype == NET_TCP_SOCK_UNUSED) {
		errno = EINVAL;
		return -1;
	}
	if (s->socktype != NET_TCP_SOCK_STREAM) {
		errno = ENOTSOCK;
		return -1;
	}

	net_tcp_stream *cur_stream = s->stream;
	if (!cur_stream ||
		!(cur_stream->state == NET_TCP_ESTABLISHED ||
		  cur_stream->state == NET_TCP_CLOSE_WAIT)) {
		errno = ENOTCONN;
		return -1;
	}

	if (len <= 0) {
		if (s->opts & NET_TCP_NONBLOCK) {
			errno = EAGAIN;
			return -1;
		} else {
			return 0;
		}
	}

	net_tcp_send *snd = cur_stream->snd;

	pthread_mutex_lock(&snd->write_lock);

#if NET_ENABLE_BLOCKING
	if (!(s->opts & NET_TCP_NONBLOCK)) {
		while (snd->snd_wnd <= 0) {
			if (!cur_stream || cur_stream->state != NET_TCP_ESTABLISHED) {
				pthread_mutex_unlock(&snd->write_lock);
				errno = EINTR;
				return -1;
			}
			
			pthread_cond_wait(&snd->write_cond, &snd->write_lock);
		}
	}
#endif
	int ret = net_copy_from_user(cur_stream, buf, len);
	pthread_mutex_unlock(&snd->write_lock);

	net_trace_api("net_copy_from_user --> %d, %d\n", 
		snd->on_sendq, snd->on_send_list);
	if (ret > 0 && !(snd->on_sendq || snd->on_send_list)) {
		snd->on_sendq = 1;
		StreamEnqueue(tcp->sendq, cur_stream);
		tcp->wakeup_flag = 1;
	}

	if (ret == 0 && (s->opts & NET_TCP_NONBLOCK)) {
		ret = -1;
		errno = EAGAIN;
	}

	net_trace_api("Stream %d: mtcp_write() returning %d\n", cur_stream->id, ret);
	return ret;
}

int close(int sockid) {
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	if (sockid < 0) {
		errno = EBADF;
		return -1;
	}

	if (!tcp->fdtable) return -1;
	
	struct _net_socket *s = tcp->fdtable->sockfds[sockid];
	if (s->socktype == NET_TCP_SOCK_UNUSED) {
		errno = EINVAL;
		return -1;
	}
	net_trace_api("Socket %d, type:%d mtcp_close called.\n", sockid, s->socktype);

	int ret = -1;
	switch (s->socktype) {
		case NET_TCP_SOCK_STREAM: {
			ret = net_socket_close_stream(sockid);
			break;
		}
		case NET_TCP_SOCK_LISTENER: {
			ret = net_socket_close_listening(sockid);
			break;
		}
		case NET_TCP_SOCK_EPOLL: {
			ret = net_epoll_close_socket(sockid);
			break;
		}
		default: {
			errno = EINVAL;
			ret = -1;
			break;
		}
	}

	net_socket_free(sockid);
	return ret;
}


#endif


