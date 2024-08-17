#include <pthread.h>

#include "netmap_usrstack/net_tcp.h"
#include "netmap_usrstack/net_socket.h"

#define TCP_MAX_SEQ		4294967295

static unsigned int next_seed;

char *state_str[] = {
	"TCP_ST_CLOSED", 
	"TCP_ST_LISTEN", 
	"TCP_ST_SYN_SENT", 
	"TCP_ST_SYN_RCVD", 
	"TCP_ST_ESTABILSHED", 
	"TCP_ST_FIN_WAIT_1", 
	"TCP_ST_FIN_WAIT_2", 
	"TCP_ST_CLOSE_WAIT", 
	"TCP_ST_CLOSING", 
	"TCP_ST_LAST_ACK", 
	"TCP_ST_TIME_WAIT"
};

char *close_reason_str[] = {
	"NOT_CLOSED", 
	"CLOSE", 
	"CLOSED", 
	"CONN_FAIL", 
	"CONN_LOST", 
	"RESET", 
	"NO_MEM", 
	"DENIED", 
	"TIMEDOUT"
};

//extern net_addr_pool *global_addr_pool[ETH_NUM];
net_addr_pool *global_addr_pool[ETH_NUM] = {NULL};

extern void RemoveFromRTOList(net_tcp_manager *tcp, net_tcp_stream *cur_stream);
extern void RemoveFromTimeoutList(net_tcp_manager *tcp, net_tcp_stream *cur_stream);
extern void RemoveFromTimewaitList(net_tcp_manager *tcp, net_tcp_stream *cur_stream);
extern int GetOutputInterface(uint32_t daddr);

char *TCPStateToString(net_tcp_stream *stream) {
	return state_str[stream->state];
}


void InitializeTCPStreamManager()
{
	next_seed = time(NULL);
}

void RaiseReadEvent(net_tcp_manager *tcp, net_tcp_stream *stream) {
	if (stream->socket) {
		if (stream->socket->epoll & NET_EPOLLIN) {
#if NET_ENABLE_EPOLL_RB
			epoll_event_callback(tcp->ep, stream->socket->id, NET_EPOLLIN);
#else	
			net_epoll_add_event(tcp->ep, NET_EVENT_QUEUE, stream->socket, NET_EPOLLIN);
#endif
#if NET_ENABLE_BLOCKING
		} else if (!(stream->socket->opts & NET_TCP_NONBLOCK)) {
			if (!stream->on_rcv_br_list) {
				stream->on_rcv_br_list = 1;
				TAILQ_INSERT_TAIL(&tcp->rcv_br_list, stream, rcv->rcv_br_link);
				tcp->rcv_br_list_cnt ++;
			}
#endif	
		}
	} else {
		printf("Stream %d: Raising read without a socket!\n", stream->id);
	}
}

void RaiseWriteEvent(net_tcp_manager *tcp, net_tcp_stream *stream) {
	if (stream->socket) {
		if (stream->socket->epoll & NET_EPOLLOUT) {
#if NET_ENABLE_EPOLL_RB
			//should be stream callback
			epoll_event_callback(tcp->ep, stream->socket->id, NET_EPOLLOUT);
#else
			net_epoll_add_event(tcp->ep, NET_EVENT_QUEUE, stream->socket, NET_EPOLLOUT);
#endif
#if NET_ENABLE_BLOCKING
		} else if (!(stream->socket->opts & NET_TCP_NONBLOCK)) {
			if (!stream->on_snd_br_list) {
				stream->on_snd_br_list = 1;
				TAILQ_INSERT_TAIL(&tcp->snd_br_list, stream, snd->snd_br_link);
				tcp->snd_br_list_cnt ++;
			}
#endif
		}
	} else {
		printf("Stream %d: Raising write without a socket!\n", stream->id);
	}
}

void RaiseCloseEvent(net_tcp_manager *tcp, net_tcp_stream *stream) {
	if (stream->socket) {
		if (stream->socket->epoll & NET_EPOLLRDHUP) {
#if NET_ENABLE_EPOLL_RB
			epoll_event_callback(tcp->ep, stream->socket->id, NET_EPOLLRDHUP);
#else
			net_epoll_add_event(tcp->ep, NET_EVENT_QUEUE, stream->socket, NET_EPOLLRDHUP);
#endif
#if NET_ENABLE_BLOCKING
		} else if (!(stream->socket->opts & NET_TCP_NONBLOCK)) {
			if (!stream->on_rcv_br_list) {
				stream->on_rcv_br_list = 1;
				TAILQ_INSERT_TAIL(&tcp->rcv_br_list, stream, rcv->rcv_br_link);
				tcp->rcv_br_list_cnt ++;
			} 
			if (!stream->on_snd_br_list) {
				stream->on_snd_br_list = 1;
				TAILQ_INSERT_TAIL(&tcp->snd_br_list, stream, snd->snd_br_link);
				tcp->snd_br_list_cnt ++;
			} 
#endif
		}
	} else {
		printf("Stream %d: Raising close without a socket!\n", stream->id);
	}
}

void RaiseErrorEvent(net_tcp_manager *tcp, net_tcp_stream *stream) {
	if (stream->socket) {
		if (stream->socket->epoll & NET_EPOLLERR) {
#if NET_ENABLE_EPOLL_RB
			epoll_event_callback(tcp->ep, stream->socket->id, NET_EPOLLERR);
#else
			net_epoll_add_event(tcp->ep, NET_EVENT_QUEUE, stream->socket, NET_EPOLLERR);
#endif
#if NET_ENABLE_BLOCKING
		} else if (!(stream->socket->opts & NET_TCP_NONBLOCK)) {
			if (!stream->on_rcv_br_list) {
				stream->on_rcv_br_list = 1;
				TAILQ_INSERT_TAIL(&tcp->rcv_br_list, stream, rcv->rcv_br_link);
				tcp->rcv_br_list_cnt ++;
			} 
			if (!stream->on_snd_br_list) {
				stream->on_snd_br_list = 1;
				TAILQ_INSERT_TAIL(&tcp->snd_br_list, stream, snd->snd_br_link);
				tcp->snd_br_list_cnt ++;
			} 
#endif
		}
	} else {
		printf("Stream %d: Raising close without a socket!\n", stream->id);
	}
}


net_tcp_stream *CreateTcpStream(net_tcp_manager *tcp, struct _net_socket_map *socket, int type, 
		uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport) {

	net_tcp_stream *stream = NULL;

	pthread_mutex_lock(&tcp->ctx->flow_pool_lock);

	stream = net_mempool_alloc(tcp->flow);
	if (stream == NULL) {
		pthread_mutex_unlock(&tcp->ctx->flow_pool_lock);
		return NULL;
	}
	memset(stream, 0, sizeof(net_tcp_stream));

	stream->rcv = (net_tcp_recv*)net_mempool_alloc(tcp->rcv);
	if (stream->rcv == NULL) {
		net_mempool_free(tcp->flow, stream);
		pthread_mutex_unlock(&tcp->ctx->flow_pool_lock);
		return NULL;
	}
	memset(stream->rcv, 0, sizeof(net_tcp_recv));

	stream->snd = (net_tcp_send*)net_mempool_alloc(tcp->snd);
	if (!stream->snd) {
		net_mempool_free(tcp->rcv, stream->rcv);
		net_mempool_free(tcp->flow, stream);
		
		pthread_mutex_unlock(&tcp->ctx->flow_pool_lock);
		return NULL;
	}
	memset(stream->snd, 0, sizeof(net_tcp_send));
	
	stream->id = tcp->gid ++;
	stream->saddr = saddr;
	stream->sport = sport;
	stream->daddr = daddr;
	stream->dport = dport;

	int ret = StreamHTInsert(tcp->tcp_flow_table, stream);
	if (ret < 0) {
		net_mempool_free(tcp->rcv, stream->rcv);
		net_mempool_free(tcp->snd, stream->snd);
		net_mempool_free(tcp->flow, stream);
		
		pthread_mutex_unlock(&tcp->ctx->flow_pool_lock);
		return NULL;
	}
	
	stream->on_hash_table = 1;
	tcp->flow_cnt ++;
	pthread_mutex_unlock(&tcp->ctx->flow_pool_lock);

	if (socket) {
		stream->socket = socket;
		socket->stream = stream;
	}

	stream->stream_type = type;
	stream->state = NET_TCP_LISTEN;
	stream->on_rto_idx = -1;

	stream->snd->ip_id = 0;
	stream->snd->mss = TCP_DEFAULT_MSS;
	stream->snd->wscale_mine = TCP_DEFAULT_WSCALE;
	stream->snd->wscale_peer = 0;
	stream->snd->nif_out = 0;

	stream->snd->iss = rand_r(&next_seed) % TCP_MAX_SEQ;
	stream->rcv->irs = 0;

	stream->snd_nxt = stream->snd->iss;
	stream->snd->snd_una = stream->snd->iss;
	stream->snd->snd_wnd = NET_SEND_BUFFER_SIZE;
	
	stream->rcv_nxt = 0;
	stream->rcv->rcv_wnd = TCP_INITIAL_WINDOW;
	stream->rcv->snd_wl1 = stream->rcv->irs - 1;

	stream->snd->rto = TCP_INITIAL_RTO;

#if NET_ENABLE_BLOCKING

	if (pthread_mutex_init(&stream->rcv->read_lock, NULL)) {
		printf("pthread_spin_init \n");
		return NULL;
	}

	if (pthread_mutex_init(&stream->snd->write_lock, NULL)) {
		pthread_mutex_destroy(&stream->rcv->read_lock);
		printf("pthread_spin_init \n");
		return NULL;
	}

	if (pthread_cond_init(&stream->rcv->read_cond, NULL)) {
		perror("pthread_cond_init of read_cond");
		return NULL;
	}
	
	if (pthread_cond_init(&stream->snd->write_cond, NULL)) {
		perror("pthread_cond_init of write_cond");
		return NULL;
	}

#else
	if (pthread_spin_init(&stream->rcv->read_lock, PTHREAD_PROCESS_PRIVATE)) {
		printf("pthread_spin_init \n");
		return NULL;
	}

	if (pthread_spin_init(&stream->snd->write_lock, PTHREAD_PROCESS_PRIVATE)) {
		pthread_spin_destroy(&stream->rcv->read_lock);
		printf("pthread_spin_init \n");
		return NULL;
	}
#endif
	uint8_t *sa = (uint8_t*)&stream->saddr;
	uint8_t *da = (uint8_t*)&stream->daddr;

	printf("CREATED NEW TCP STREAM %d: "
			"%u.%u.%u.%u(%d) -> %u.%u.%u.%u(%d) (ISS: %u)\n", stream->id, 
			sa[0], sa[1], sa[2], sa[3], ntohs(stream->sport), 
			da[0], da[1], da[2], da[3], ntohs(stream->dport), 
			stream->snd->iss);

	return stream;
}


void DestroyTcpStream(net_tcp_manager *tcp, net_tcp_stream *stream) {

	uint8_t *sa = (uint8_t*)&stream->saddr;
	uint8_t *da = (uint8_t*)&stream->daddr;

	printf("DESTROY TCP STREAM %d: "
			"%u.%u.%u.%u(%d) -> %u.%u.%u.%u(%d) (%s)\n", stream->id, 
			sa[0], sa[1], sa[2], sa[3], ntohs(stream->sport), 
			da[0], da[1], da[2], da[3], ntohs(stream->dport), 
			close_reason_str[stream->close_reason]);

	if (stream->snd->sndbuf) {
		printf("Stream %d: send buffer "
				"cum_len: %lu, len: %u\n", stream->id, 
				stream->snd->sndbuf->cum_len, 
				stream->snd->sndbuf->len);
	}

	if (stream->rcv->recvbuf) {
		printf("Stream %d: recv buffer "
				"cum_len: %lu, merged_len: %u, last_len: %u\n", stream->id, 
				stream->rcv->recvbuf->cum_len, 
				stream->rcv->recvbuf->merged_len, 
				stream->rcv->recvbuf->last_len);
	}

	int bound_addr = 0;
	struct sockaddr_in addr;
	if (stream->is_bound_addr) {
		bound_addr = 0;
		addr.sin_addr.s_addr = stream->saddr;
		addr.sin_port = stream->sport;
	}

	net_tcp_remove_controllist(tcp, stream);
	net_tcp_remove_sendlist(tcp, stream);
	net_tcp_remove_acklist(tcp, stream);

	if (stream->on_rto_idx >= 0) {
		RemoveFromRTOList(tcp, stream);
	}
	if (stream->on_timewait_list) {
		RemoveFromTimewaitList(tcp, stream);
	}
	RemoveFromTimeoutList(tcp, stream);

#if NET_ENABLE_BLOCKING
	pthread_mutex_destroy(&stream->rcv->read_lock);
	pthread_mutex_destroy(&stream->snd->write_lock);
#else
	SBUF_LOCK_DESTROY(&stream->rcv->read_lock);
	SBUF_LOCK_DESTROY(&stream->snd->write_lock);
#endif
	assert(stream->on_hash_table == 1);

	if (stream->snd->sndbuf) {
		SBFree(tcp->rbm_snd, stream->snd->sndbuf);
		stream->snd->sndbuf = NULL;
	}

	if (stream->rcv->recvbuf) {
		RBFree(tcp->rbm_rcv, stream->rcv->recvbuf);
		stream->rcv->recvbuf = NULL;
	}

	pthread_mutex_lock(&tcp->ctx->flow_pool_lock);

	StreamHTRemove(tcp->tcp_flow_table, stream);
	stream->on_hash_table = 0;

	tcp->flow_cnt --;

	net_mempool_free(tcp->rcv, stream->rcv);
	net_mempool_free(tcp->snd, stream->snd);
	net_mempool_free(tcp->flow, stream);

	pthread_mutex_unlock(&tcp->ctx->flow_pool_lock);

	int ret = -1;
	if (bound_addr) {
		if (tcp->ap) {
			ret = FreeAddress(tcp->ap, &addr);
		} else {
			int nif = GetOutputInterface(addr.sin_addr.s_addr);
			if (nif < 0) {
				printf("nif is negative!\n");
				ret = -1;
			} else {
				int idx = 0;
				ret = FreeAddress(global_addr_pool[idx], &addr);
			}
		}

		if (ret < 0) {
			printf("(NEVER HAPPEN) Failed to free address.\n");
		}
	}
	
}


