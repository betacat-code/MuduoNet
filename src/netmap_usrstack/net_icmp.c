#include "netmap_usrstack/net_header.h"
#include "netmap_usrstack/net_nic.h"


extern unsigned short in_cksum(unsigned short *addr, int len);

void net_icmp_pkt(struct icmppkt *icmp, struct icmppkt *icmp_rt) {

	memcpy(icmp_rt, icmp, sizeof(struct icmppkt));

	icmp_rt->icmp.type = 0x0; 
	icmp_rt->icmp.code = 0x0; 
	icmp_rt->icmp.check = 0x0;

	icmp_rt->ip.saddr = icmp->ip.daddr;
	icmp_rt->ip.daddr = icmp->ip.saddr;

	memcpy(icmp_rt->eh.h_dest, icmp->eh.h_source, ETH_ALEN);
	memcpy(icmp_rt->eh.h_source, icmp->eh.h_dest, ETH_ALEN);

	icmp_rt->icmp.check = in_cksum((unsigned short*)&icmp_rt->icmp, sizeof(struct icmphdr));
	
}

int net_icmp_process(net_nic_context *ctx, unsigned char *stream) {

	struct icmppkt *icmph = (struct icmppkt*)stream;

	if (icmph->icmp.type == 0x08) {
		struct icmppkt icmp_rt;
		memset(&icmp_rt, 0, sizeof(struct icmppkt));
		
		net_icmp_pkt(icmph, &icmp_rt);
		net_nic_write(ctx, &icmp_rt, sizeof(struct icmppkt));
	}
	return 0;
}



