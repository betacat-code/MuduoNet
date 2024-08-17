#include "netmap_usrstack/net_header.h"
#include "netmap_usrstack/net_nic.h"
#include "netmap_usrstack/net_arp.h"

#include <pthread.h>
#include <uchar.h>

//gcc -o net_stack *.o -lpthread -lhugetlbfs

unsigned short in_cksum(unsigned short *addr, int len) {
	register int nleft = len;
	register unsigned short *w = addr;
	register int sum = 0;
	unsigned short answer = 0;

	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w ;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);	
	sum += (sum >> 16);			
	answer = ~sum;
	
	return (answer);

}


uint8_t *EthernetOutput(net_tcp_manager *tcp, uint16_t h_proto,
	int nif, unsigned char* dst_haddr, uint16_t iplen) {

	net_thread_context *ctx = tcp->ctx;

	uint8_t *buf = (uint8_t*)net_nic_get_wbuffer(ctx->io_private_context, 0, iplen+ETHERNET_HEADER_LEN);
	if (buf == NULL) return NULL;

	struct ethhdr *ethh = (struct ethhdr*)buf;
	int i = 0;

	str2mac((char*)ethh->h_source, NET_SELF_MAC);
	for (i = 0;i < ETH_ALEN;i ++) {
		ethh->h_dest[i] = dst_haddr[i];
	}
	ethh->h_proto = htons(h_proto);

	return (uint8_t*)(ethh+1);
}

extern int net_ipv4_process(net_nic_context *ctx, unsigned char *stream);

static int net_eth_process(net_nic_context *ctx, unsigned char *stream) {

	struct ethhdr *eh = (struct ethhdr*)stream;

	if (ntohs(eh->h_proto) == PROTO_IP) {
		net_ipv4_process(ctx, stream);
	} else if (ntohs(eh->h_proto) == PROTO_ARP) {
		net_arp_process(ctx, stream);
	}

	return 0;
}


extern net_tcp_manager *net_get_tcp_manager(void);
extern void CheckRtmTimeout(net_tcp_manager *tcp, uint32_t cur_ts, int thresh);
extern void CheckTimewaitExpire(net_tcp_manager *tcp, uint32_t cur_ts, int thresh);
extern void CheckConnectionTimeout(net_tcp_manager *tcp, uint32_t cur_ts, int thresh);



static void *net_tcp_run(void *arg) {
	net_nic_context *ctx = (net_nic_context *)arg;

	net_tcp_manager *tcp = net_get_tcp_manager();

	while (1) {

		struct pollfd pfd = {0};
		pfd.fd = ctx->nmr->fd;
		pfd.events = POLLIN | POLLOUT;
		
		int ret = poll(&pfd, 1, -1);
		if (ret < 0) continue;

		// check send data should 
		struct timeval cur_ts = {0};
		gettimeofday(&cur_ts, NULL);
		uint32_t ts = TIMEVAL_TO_TS(&cur_ts);

		if (tcp->flow_cnt > 0) {
			CheckRtmTimeout(tcp, ts, NET_MAX_CONCURRENCY);
			CheckTimewaitExpire(tcp, ts, NET_MAX_CONCURRENCY);
			CheckConnectionTimeout(tcp, ts, NET_MAX_CONCURRENCY);
			
			net_tcp_handle_apicall(ts);
		}

		net_tcp_write_chunks(ts);
		
		if (!(pfd.revents & POLLERR)) ctx->dev_poll_flag = 1;

		if (pfd.revents & POLLIN) {

			unsigned char *stream = NULL;
			net_nic_read(ctx, &stream);
			net_eth_process(ctx, stream);

		} else if (pfd.revents & POLLOUT) {

			net_nic_send_pkts(ctx, 0);
		} 
				
	}

	return NULL;
}

void net_tcp_setup(void) {
	net_thread_context *tctx = (net_thread_context*)calloc(1, sizeof(net_thread_context));
	assert(tctx != NULL);
	printf("net_stack start\n");

	//int ret = NET_NIC_INIT(tctx, "netmap:eth0");
	int ret = net_nic_init(tctx, "netmap:ens33");
	if (ret != 0) {
		printf("init nic failed\n");
		return ;
	}
	net_tcp_init_thread_context(tctx);
	net_nic_context *ctx = (net_nic_context*)tctx->io_private_context;

	net_arp_init_table();

	pthread_t thread_id;
	ret = pthread_create(&thread_id, NULL, net_tcp_run, ctx);
	assert(ret == 0);

}


