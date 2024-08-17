#include "netmap_usrstack/net_buffer.h"
#include "netmap_usrstack/net_timer.h"
#include "netmap_usrstack/net_tcp.h"


extern void DestroyTcpStream(net_tcp_manager *tcp, net_tcp_stream *stream);

// 初始化一个重传超时 (RTO) 哈希存储
net_rto_hashstore *InitRTOHashstore(void) {
	net_rto_hashstore *hs = calloc(1, sizeof(net_rto_hashstore));
	if (!hs) {
		return NULL;
	}
	
	int i = 0;
	for (i = 0;i < RTO_HASH+1;i ++) {
		TAILQ_INIT(&hs->rto_list[i]);
	}
	return hs;
}

// 将一个TCP流添加到RTO列表
void AddtoRTOList(net_tcp_manager *tcp, net_tcp_stream *cur_stream) {

	if (!tcp->rto_list_cnt) {
		tcp->rto_store->rto_now_idx = 0;
		tcp->rto_store->rto_now_ts = cur_stream->snd->ts_rto;
	}

	if (cur_stream->on_rto_idx < 0) {

		int diff = (int32_t)(cur_stream->snd->ts_rto - tcp->rto_store->rto_now_ts);
		if (diff < RTO_HASH) {
			int offset = cur_stream->snd->ts_rto % RTO_HASH;
			cur_stream->on_rto_idx = offset;
			TAILQ_INSERT_TAIL(&(tcp->rto_store->rto_list[offset]),
				cur_stream, snd->timer_link);
		} else {
			cur_stream->on_rto_idx = RTO_HASH;
			TAILQ_INSERT_TAIL(&(tcp->rto_store->rto_list[RTO_HASH]),
				cur_stream, snd->timer_link);
		}
		tcp->rto_list_cnt ++;
	}
}


void RemoveFromRTOList(net_tcp_manager *tcp, net_tcp_stream *cur_stream) {
	if (cur_stream->on_rto_idx < 0) return ;

	TAILQ_REMOVE(&(tcp->rto_store->rto_list[cur_stream->on_rto_idx]),
		cur_stream, snd->timer_link);

	cur_stream->on_rto_idx = -1;
	tcp->rto_list_cnt --;
}

void AddtoTimewaitList(net_tcp_manager *tcp, net_tcp_stream *cur_stream, uint32_t cur_ts)
{
	cur_stream->rcv->ts_tw_expire = cur_ts + NET_TCP_TIMEWAIT;

	if (cur_stream->on_timewait_list) {
		// Update list in sorted way by ts_tw_expire
		TAILQ_REMOVE(&tcp->timewait_list, cur_stream, snd->timer_link);
		TAILQ_INSERT_TAIL(&tcp->timewait_list, cur_stream, snd->timer_link);	
	} else {
		if (cur_stream->on_rto_idx >= 0) {
			net_trace_timer("Stream %u: cannot be in both "
					"timewait and rto list.\n", cur_stream->id);
			//assert(0);
			RemoveFromRTOList(tcp, cur_stream);
		}

		cur_stream->on_timewait_list = 1;
		TAILQ_INSERT_TAIL(&tcp->timewait_list, cur_stream, snd->timer_link);
		tcp->timewait_list_cnt++;
	}
}

void RemoveFromTimewaitList(net_tcp_manager *tcp, net_tcp_stream *cur_stream) {
	if (!cur_stream->on_timewait_list) {
		assert(0);
		return;
	}
	
	TAILQ_REMOVE(&tcp->timewait_list, cur_stream, snd->timer_link);
	cur_stream->on_timewait_list = 0;
	tcp->timewait_list_cnt--;
}

void AddtoTimeoutList(net_tcp_manager *tcp, net_tcp_stream *cur_stream)
{
	if (cur_stream->on_timeout_list) {
		assert(0);
		return;
	}

	cur_stream->on_timeout_list = 1;
	TAILQ_INSERT_TAIL(&tcp->timeout_list, cur_stream, snd->timeout_link);
	tcp->timeout_list_cnt++;
}

void RemoveFromTimeoutList(net_tcp_manager *tcp, net_tcp_stream *cur_stream)
{
	if (cur_stream->on_timeout_list) {
		cur_stream->on_timeout_list = 0;
		TAILQ_REMOVE(&tcp->timeout_list, cur_stream, snd->timeout_link);
		tcp->timeout_list_cnt--;
	}
}

void UpdateTimeoutList(net_tcp_manager *tcp, net_tcp_stream *cur_stream)
{
	if (cur_stream->on_timeout_list) {
		TAILQ_REMOVE(&tcp->timeout_list, cur_stream, snd->timeout_link);
		TAILQ_INSERT_TAIL(&tcp->timeout_list, cur_stream, snd->timeout_link);
	}
}

void UpdateRetransmissionTimer(net_tcp_manager *tcp, 
		net_tcp_stream *cur_stream, uint32_t cur_ts)
{
	assert(cur_stream->snd->rto > 0);
	cur_stream->snd->nrtx = 0;

	if (cur_stream->on_rto_idx >= 0) {
		RemoveFromRTOList(tcp, cur_stream);
	}

	if (TCP_SEQ_GT(cur_stream->snd_nxt, cur_stream->snd->snd_una)) {
		cur_stream->snd->ts_rto = cur_ts + cur_stream->snd->rto;
		AddtoRTOList(tcp, cur_stream);

	} else {
		net_trace_timer("All packets are acked. snd_una: %u, snd_nxt: %u\n", 
				cur_stream->snd->snd_una, cur_stream->snd_nxt);
	}
}

int HandleRTO(net_tcp_manager *tcp, uint32_t cur_ts, net_tcp_stream *cur_stream) {

	uint8_t backoff;

	if (cur_stream->snd->nrtx < TCP_MAX_RTX) {
		cur_stream->snd->nrtx ++;
	} else {
		if (cur_stream->state < NET_TCP_ESTABLISHED) {
			cur_stream->state = NET_TCP_CLOSED;
			cur_stream->close_reason = TCP_CONN_FAIL;
			DestroyTcpStream(tcp, cur_stream);
		} else {
			cur_stream->state = NET_TCP_CLOSED;
			cur_stream->close_reason = TCP_CONN_LOST;
			if (cur_stream->socket) {
				//RaiseErrorEvent
			} else {
				DestroyTcpStream(tcp, cur_stream);
			}
		}

		return -1;
	}

	if (cur_stream->snd->nrtx > cur_stream->snd->max_nrtx) {
		cur_stream->snd->max_nrtx = cur_stream->snd->nrtx;
	}

	// 根据 TCP 连接的状态来决定如何关闭连接
	if (cur_stream->state >= NET_TCP_ESTABLISHED) {
		uint32_t rto_prev;
		backoff = MIN(cur_stream->snd->nrtx, TCP_MAX_BACKOFF);

		rto_prev = cur_stream->snd->rto;
		cur_stream->snd->rto = ((cur_stream->rcv->srtt >> 3) + cur_stream->rcv->rttvar) << backoff;
		if (cur_stream->snd->rto <= 0) {
			cur_stream->snd->rto = rto_prev;
		}
	} 
	// 如果处于 SYN 发送状态，检查是否超过了最大重传次数
	else if (cur_stream->state >= NET_TCP_SYN_SENT) {
		if (cur_stream->snd->nrtx < TCP_MAX_BACKOFF) {
			cur_stream->snd->rto <<= 1;
		}
	}

	cur_stream->snd->ssthresh = MIN(cur_stream->snd->cwnd, cur_stream->snd->peer_wnd) / 2;
	if (cur_stream->snd->ssthresh < (2 * cur_stream->snd->mss)) {
		cur_stream->snd->ssthresh = cur_stream->snd->mss * 2;
	}
	cur_stream->snd->cwnd = cur_stream->snd->mss;

	net_trace_timer("Stream %d Timeout. cwnd: %u, ssthresh: %u\n", 
			cur_stream->id, cur_stream->snd->cwnd, cur_stream->snd->ssthresh);

	if (cur_stream->state == NET_TCP_SYN_SENT) {
		if (cur_stream->snd->nrtx > TCP_MAX_SYN_RETRY) {
			cur_stream->state = NET_TCP_CLOSED;
			cur_stream->close_reason = TCP_CONN_FAIL;
			net_trace_timer("Stream %d: SYN retries exceed maximum retries.\n", 
					cur_stream->id);
			if (cur_stream->socket) {
				//RaiseErrorEvent(mtcp, cur_stream);
			} else {
				DestroyTcpStream(tcp, cur_stream);
			}

			return -1;
		}
		net_trace_timer("Stream %d Retransmit SYN. snd_nxt: %u, snd_una: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->snd->snd_una);

	} else if (cur_stream->state == NET_TCP_SYN_RCVD) {
		net_trace_timer("Stream %d: Retransmit SYN/ACK. snd_nxt: %u, snd_una: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->snd->snd_una);
	}  else if (cur_stream->state == NET_TCP_ESTABLISHED) {
		/* Data lost */
		net_trace_timer("Stream %d: Retransmit data. snd_nxt: %u, snd_una: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->snd->snd_una);

	} else if (cur_stream->state == NET_TCP_CLOSE_WAIT) {
		/* Data lost */
		net_trace_timer("Stream %d: Retransmit data. snd_nxt: %u, snd_una: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->snd->snd_una);

	} else if (cur_stream->state == NET_TCP_LAST_ACK) {
		/* FIN/ACK lost */
		net_trace_timer("Stream %d: Retransmit FIN/ACK. "
				"snd_nxt: %u, snd_una: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->snd->snd_una);

	} else if (cur_stream->state == NET_TCP_FIN_WAIT_1) {
		/* FIN lost */
		net_trace_timer("Stream %d: Retransmit FIN. snd_nxt: %u, snd_una: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->snd->snd_una);
	} else if (cur_stream->state == NET_TCP_CLOSING) {
		net_trace_timer("Stream %d: Retransmit ACK. snd_nxt: %u, snd_una: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->snd->snd_una);
		//TRACE_DBG("Stream %d: Retransmitting at CLOSING\n", cur_stream->id);

	} else {
		net_trace_timer("Stream %d: not implemented state! state: %d, rto: %u\n", 
				cur_stream->id, 
				cur_stream->state, cur_stream->snd->rto);
		assert(0);
		return -1;
	}

	cur_stream->snd_nxt = cur_stream->snd->snd_una;
	if (cur_stream->state == NET_TCP_ESTABLISHED || 
			cur_stream->state == NET_TCP_CLOSE_WAIT) {

		net_tcp_addto_sendlist(tcp, cur_stream);

	} else if (cur_stream->state == NET_TCP_FIN_WAIT_1 || 
			cur_stream->state == NET_TCP_CLOSING || 
			cur_stream->state == NET_TCP_LAST_ACK) {

		if (cur_stream->snd->fss == 0) {
			net_trace_timer("Stream %u: fss not set.\n", cur_stream->id);
		}
		
		if (TCP_SEQ_LT(cur_stream->snd_nxt, cur_stream->snd->fss)) {
			
			if (cur_stream->snd->on_control_list) {
				net_tcp_remove_controllist(tcp, cur_stream);
			}
			cur_stream->control_list_waiting = 1;
			net_tcp_addto_sendlist(tcp, cur_stream);

		} else {
			
			net_tcp_addto_controllist(tcp, cur_stream);
		}

	} else {
		net_tcp_addto_controllist(tcp, cur_stream);
	}

	return 0;
}


static inline void RearrangeRTOStore(net_tcp_manager *tcp) {
	net_tcp_stream *walk, *next;
	struct rto_head* rto_list = &tcp->rto_store->rto_list[RTO_HASH];
	int cnt = 0;

	for (walk = TAILQ_FIRST(rto_list);
			walk != NULL; walk = next) {
		next = TAILQ_NEXT(walk, snd->timer_link);

		int diff = (int32_t)(tcp->rto_store->rto_now_ts - walk->snd->ts_rto);
		if (diff < RTO_HASH) {
			int offset = (diff + tcp->rto_store->rto_now_idx) % RTO_HASH;
			TAILQ_REMOVE(&tcp->rto_store->rto_list[RTO_HASH],
					            walk, snd->timer_link);
			walk->on_rto_idx = offset;
			TAILQ_INSERT_TAIL(&(tcp->rto_store->rto_list[offset]),
					walk, snd->timer_link);
		}
		cnt++;
	}	
}


void CheckRtmTimeout(net_tcp_manager *tcp, uint32_t cur_ts, int thresh) {

	net_tcp_stream *walk, *next;
	struct rto_head *rto_list;

	if (!tcp->rto_list_cnt) {
		return;
	}

	int cnt = 0;
	
	while (1) {

		rto_list = &tcp->rto_store->rto_list[tcp->rto_store->rto_now_idx];
		if ((int32_t)(cur_ts - tcp->rto_store->rto_now_ts) < 0) {
			break;
		}

		for (walk = TAILQ_FIRST(rto_list);walk != NULL;walk = next) {
			if (++cnt > thresh) break;

			next = TAILQ_NEXT(walk, snd->timer_link);

			if (walk->on_rto_idx >= 0) {
				TAILQ_REMOVE(rto_list, walk, snd->timer_link);
				tcp->rto_list_cnt --;

				walk->on_rto_idx = -1;
				HandleRTO(tcp, cur_ts, walk);
				
			} else {
				net_trace_timer("Stream %d: not on rto list.\n", walk->id);
			}
		}

		if (cnt < thresh) break;
		else {
			tcp->rto_store->rto_now_idx = (tcp->rto_store->rto_now_idx + 1) % RTO_HASH;
			tcp->rto_store->rto_now_ts ++;
			if (!(tcp->rto_store->rto_now_idx % 1000)) {
				RearrangeRTOStore(tcp);
			}
		}
	}
	
}

void CheckTimewaitExpire(net_tcp_manager *tcp, uint32_t cur_ts, int thresh)
{
	net_tcp_stream *walk, *next;
	int cnt;

	cnt = 0;

	for (walk = TAILQ_FIRST(&tcp->timewait_list); 
				walk != NULL; walk = next) {
		if (++cnt > thresh)
			break;
		next = TAILQ_NEXT(walk, snd->timer_link);
		
		if (walk->on_timewait_list) {
			if ((int32_t)(cur_ts - walk->rcv->ts_tw_expire) >= 0) {
				if (!walk->snd->on_control_list) {
					
					TAILQ_REMOVE(&tcp->timewait_list, walk, snd->timer_link);
					walk->on_timewait_list = 0;
					tcp->timewait_list_cnt--;

					walk->state = NET_TCP_CLOSED;
					walk->close_reason = TCP_ACTIVE_CLOSE;
					net_trace_timer("Stream %d: TCP_ST_CLOSED\n", walk->id);
					DestroyTcpStream(tcp, walk);
				}
			} else {
				break;
			}
		} else {
			net_trace_timer("Stream %d: not on timewait list.\n", walk->id);
		}
	}

}


void CheckConnectionTimeout(net_tcp_manager *tcp, uint32_t cur_ts, int thresh)
{
	net_tcp_stream *walk, *next;
	int cnt;

	cnt = 0;
	for (walk = TAILQ_FIRST(&tcp->timeout_list);
			walk != NULL; walk = next) {
		if (++cnt > thresh)
			break;
		next = TAILQ_NEXT(walk, snd->timeout_link);
		if ((int32_t)(cur_ts - walk->last_active_ts) >= 
				(NET_TCP_TIMEOUT * 1000)) {

			walk->on_timeout_list = 0;
			TAILQ_REMOVE(&tcp->timeout_list, walk, snd->timeout_link);
			tcp->timeout_list_cnt--;
			walk->state = NET_TCP_CLOSED;
			walk->close_reason = TCP_TIMEDOUT;

			if (walk->socket) {
				//RaiseErrorEvent(mtcp, walk);
			} else {
				DestroyTcpStream(tcp, walk);
			}
		} else {
			break;
		}

	}
}



