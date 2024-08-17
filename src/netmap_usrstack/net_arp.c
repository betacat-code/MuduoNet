#include "netmap_usrstack/net_header.h"
#include "netmap_usrstack/net_tcp.h"
#include "netmap_usrstack/net_nic.h"
#include "netmap_usrstack/net_arp.h"

#include <pthread.h>

// 发送ARP数据包
static int net_arp_output(net_tcp_manager *tcp, int nif, int opcode,
		uint32_t dst_ip, unsigned char *dst_haddr, unsigned char *target_haddr);


// ARP数据包结构
struct arppkt {
	struct ethhdr eh;  // 以太网头部
	struct arphdr arp; // ARP头部
};

// ARP操作码枚举
enum arp_opcode {
	arp_op_request = 1, // ARP请求操作
	arp_op_reply = 2,   // ARP响应操作
};


// ARP队列条目结构，用于管理ARP请求/响应
typedef struct _net_arp_queue_entry {
	uint32_t ip;         // 与此ARP条目关联的IP地址
	int nif_out;         // 用于发送ARP数据包的网络接口
	uint32_t ts_out;     // ARP请求/响应的时间戳
	TAILQ_ENTRY(_net_arp_queue_entry) arp_link; // 队列管理的链接
} net_arp_queue_entry;

// 线程安全的ARP管理结构
typedef struct _net_arp_manager {
	TAILQ_HEAD(, _net_arp_queue_entry) list;  // ARP条目队列
	pthread_mutex_t lock; // 用于线程安全访问队列的互斥锁
} net_arp_manager;

// 全局ARP管理实例
net_arp_manager global_arp_manager;

// 全局ARP表指针
net_arp_table *global_arp_table = NULL;

// 将字符串表示的MAC地址转换为字节数组
int str2mac(char *mac, char *str) {

	char *p = str;
	unsigned char value = 0x0;
	int i = 0;

	while (*p != '\0') {
		
		if (*p == ':') {
			mac[i++] = value;
			value = 0x0;
		} else {
			// 将字符转换为对应的十六进制值
			unsigned char temp = *p;
			if (temp <= '9' && temp >= '0') {
				temp -= '0';
			} else if (temp <= 'f' && temp >= 'a') {
				temp -= 'a';
				temp += 10;
			} else if (temp <= 'F' && temp >= 'A') {
				temp -= 'A';
				temp += 10;
			} else {	
				break;
			}
			value <<= 4;
			value |= temp;
		}
		p ++;
	}

	mac[i] = value;

	return 0;
}

void print_mac(unsigned char *mac) {
	int i = 0;
	for (i = 0;i < ETH_ALEN-1;i ++) {
		printf("%02x:", mac[i]);
	}
	printf("%02x", mac[i]);
}

// 处理 ARP 数据包，将 ARP 请求包转换为 ARP 回复包
void net_arp_pkt(struct arppkt *arp, struct arppkt *arp_rt, char *hmac) {

	memcpy(arp_rt, arp, sizeof(struct arppkt));
	// 将 ARP 请求包的源 MAC 地址设置为 ARP 回复包的目的 MAC 地址
	memcpy(arp_rt->eh.h_dest, arp->eh.h_source, ETH_ALEN);
	
	// 将传入的硬件 MAC 地址 hmac 转换为字节数组
	// 设置为 ARP 回复包的源 MAC 地址(以太网头部)
	str2mac((char*)arp_rt->eh.h_source, hmac);

	// 复制协议类型到 ARP 回复包
	arp_rt->eh.h_proto = arp->eh.h_proto;

	arp_rt->arp.h_addrlen = 6;
	arp_rt->arp.protolen = 4;

	// 设置 ARP 操作码为 2（表示 ARP 回复）
	arp_rt->arp.oper = htons(2);
	
	//设置为arp头部
	str2mac((char*)arp_rt->arp.smac, hmac);

	// 将 ARP 回复包的源 IP 地址设置为 ARP 请求包的目的 IP 地址
	arp_rt->arp.sip = arp->arp.dip;
	
	// 将 ARP 回复包的目的 MAC 地址设置为 ARP 请求包的源 MAC 地址
	memcpy(arp_rt->arp.dmac, arp->arp.smac, ETH_ALEN);

	//交换目的和源IP地址
	arp_rt->arp.dip = arp->arp.sip;

}

extern net_tcp_manager *net_get_tcp_manager(void);

// 处理 ARP 请求
int net_arp_process_request(struct arphdr *arph) {

	// 获取源 IP 地址对应的目标硬件地址
	unsigned char *tmp = GetDestinationHWaddr(arph->sip);
	if (!tmp) {
		// 注册新的 ARP 表项，保存源 IP 和源 MAC 地址
		net_arp_register_entry(arph->sip, arph->smac);
	}

	// 获取 TCP 管理器实例 输出回复
	net_tcp_manager *tcp = net_get_tcp_manager();
	net_arp_output(tcp, 0, arp_op_reply, arph->sip, arph->smac, NULL);

	return 0;
}

// 处理 ARP 回复 需要删除旧的或过时的 ARP 表项
int net_arp_process_reply(struct arphdr *arph) {
	unsigned char *tmp = GetDestinationHWaddr(arph->sip);
	if (!tmp) {
		net_arp_register_entry(arph->sip, arph->smac);
	}

	pthread_mutex_lock(&global_arp_manager.lock);

	net_arp_queue_entry *ent = NULL;
	// 遍历全局 ARP 管理器中的 ARP 表项列表
	TAILQ_FOREACH(ent, &global_arp_manager.list, arp_link) {
		if (ent->ip == arph->sip) {
			// 找到匹配的源 IP 地址 删除
			TAILQ_REMOVE(&global_arp_manager.list, ent, arp_link);
			free(ent);
			break;
		}
	}
	pthread_mutex_unlock(&global_arp_manager.lock);

	return 0;
}

// 初始化全局 ARP 表
int net_arp_init_table(void) {
	global_arp_table = (net_arp_table*)calloc(1, sizeof(net_arp_table));
	if (!global_arp_table) return -1;

	global_arp_table->entries = 0;
	global_arp_table->entry = (net_arp_entry*)calloc(MAX_ARPENTRY, sizeof(net_arp_entry));
	if (!global_arp_table->entry) return -1;

	TAILQ_INIT(&global_arp_manager.list);

	// 初始化互斥锁以保护全局 ARP 管理器的访问
	pthread_mutex_init(&global_arp_manager.lock, NULL);

	return 0;
}


void net_arp_print_table(void) {
	int i = 0;

	for (i = 0;i < global_arp_table->entries;i ++) {
		uint8_t *da = (uint8_t*)&global_arp_table->entry[i].ip;

		printf("IP addr: %u.%u.%u.%u, "
				"dst_hwaddr: %02X:%02X:%02X:%02X:%02X:%02X\n",
				da[0], da[1], da[2], da[3],
				global_arp_table->entry[i].haddr[0],
				global_arp_table->entry[i].haddr[1],
				global_arp_table->entry[i].haddr[2],
				global_arp_table->entry[i].haddr[3],
				global_arp_table->entry[i].haddr[4],
				global_arp_table->entry[i].haddr[5]);
	}

	if (global_arp_table->entries == 0)
		printf("(blank)\n");

	return ;
}

// 注册一个新的 ARP 表条目
int net_arp_register_entry(uint32_t ip, const unsigned char *haddr) {
	assert(global_arp_table != NULL);
	
	int idx = global_arp_table->entries;
	global_arp_table->entry[idx].prefix = 32;
	global_arp_table->entry[idx].ip = ip;

	memcpy(global_arp_table->entry[idx].haddr, haddr, ETH_ALEN);

	global_arp_table->entry[idx].ip_mask = -1;
	global_arp_table->entry[idx].ip_masked = ip;

	global_arp_table->entries = idx + 1;


	printf("Learned new arp entry.\n");
	net_arp_print_table();

	return 0;
}

// 发送 ARP 数据包
static int net_arp_output(net_tcp_manager *tcp, int nif, int opcode,
		uint32_t dst_ip, unsigned char *dst_haddr, unsigned char *target_haddr) {

	if (!dst_haddr) return -1;

	struct arphdr *arph = (struct arphdr*)EthernetOutput(tcp, PROTO_ARP, nif, dst_haddr, sizeof(struct arphdr));
	if (!arph) return -1;

	arph->h_type = htons(1);
	arph->h_proto = htons(PROTO_IP);
	arph->h_addrlen = ETH_ALEN;
	arph->protolen = 4;
	arph->oper = htons(opcode);

	arph->sip = NET_SELF_IP_HEX;
	arph->dip = dst_ip;

	str2mac((char*)arph->smac, NET_SELF_MAC);
	if (target_haddr) {
		memcpy(arph->dmac, target_haddr, arph->h_addrlen);
	} else {
		memcpy(arph->dmac, dst_haddr, arph->h_addrlen);
	}

	print_mac(arph->smac);
	printf("\n");
	print_mac(arph->dmac);
	printf("\n");
	printf("sip:%x, dip:%x\n", arph->sip, arph->dip);

	return 0;
}

// 发送 ARP 请求，获取指定 IP 地址的 MAC 地址
void net_arp_request(net_tcp_manager *tcp, uint32_t ip, int nif, uint32_t cur_ts) {

	unsigned char haddr[ETH_ALEN];
	unsigned char taddr[ETH_ALEN];
	net_arp_queue_entry *ent;

	pthread_mutex_lock(&global_arp_manager.lock);

	// 遍历 ARP 请求队列，检查是否已存在该 IP 地址的请求
	TAILQ_FOREACH(ent, &global_arp_manager.list, arp_link) {
		if (ent->ip == ip) {
			// 存在相同请求直接返回
			pthread_mutex_unlock(&global_arp_manager.lock);
			return ;
		}
	}

	ent = (net_arp_queue_entry*)calloc(1, sizeof(net_arp_queue_entry));
	ent->ip = ip;
	ent->nif_out = nif;
	ent->ts_out = cur_ts;

	TAILQ_INSERT_TAIL(&global_arp_manager.list, ent, arp_link);
	
	pthread_mutex_unlock(&global_arp_manager.lock);

	// 初始化目标和源硬件地址
    memset(haddr, 0xFF, ETH_ALEN); // 目标硬件地址设置为全 1 (广播)
    memset(taddr, 0x00, ETH_ALEN); // 源硬件地址设置为全 0

	// arp_op_request  请求枚举
	net_arp_output(tcp, nif, arp_op_request, ip, haddr, taddr);
}

// 处理接收到的 ARP 数据包
int net_arp_process(net_nic_context *ctx, unsigned char *stream) {

	if (stream == NULL) return -1;

	// 将输入流转换为 ARP 数据包结构体指针
	struct arppkt *arp = (struct arppkt*)stream;
	
	// 检查目标 IP 地址
	if (arp->arp.dip == inet_addr(NET_SELF_IP)) {
		// 根据 ARP 操作类型进行请求 回复
		switch (ntohs(arp->arp.oper)) {
			case arp_op_request : {
				net_arp_process_request(&arp->arp);
				break;
			}
			case arp_op_reply : {
				net_arp_process_reply(&arp->arp);
				break;
			}
		}
	}
	return 0;
}






