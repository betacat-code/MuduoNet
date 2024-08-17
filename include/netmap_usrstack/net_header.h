

#ifndef __NET_HEADER_H__
#define __NET_HEADER_H__


#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <sys/poll.h>

#include "netmap_usrstack/net_config.h"

//__attribute__ ((packed)) 确保结构体按紧凑格式存储
//以避免编译器插入填充字节

#define ETH_ALEN		6 //以太网地址长度

#define IP_HEADER_LEN		20 //IP头部长度
#define TCP_HEADER_LEN		20 //TCP头部长度

#define PROTO_IP	0x0800
#define PROTO_ARP	0x0806

//协议常量 这些需要装入IP数据包
#define PROTO_UDP	17
#define PROTO_TCP	6
#define PROTO_ICMP	1
#define PROTO_IGMP	2

//以太网帧头部
struct ethhdr {
	unsigned char h_dest[ETH_ALEN]; // 目的 MAC 地址
	unsigned char h_source[ETH_ALEN];  // 源 MAC 地址
	unsigned short h_proto; // 上层协议类型字段
} __attribute__ ((packed));

//IP头部
struct iphdr {
	unsigned char ihl:4,
				version:4;
	unsigned char tos;
	unsigned short tot_len;
	unsigned short id;
	unsigned short flag_off;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short check;
	unsigned int saddr;
	unsigned int daddr;
} __attribute__ ((packed));

//UDP头部
struct udphdr {
	unsigned short source;
	unsigned short dest;
	unsigned short len;
	unsigned short check;
} __attribute__ ((packed));

//UDP数据包 数据部分最大128字节
struct udppkt {
	struct ethhdr eh;
	struct iphdr ip;
	struct udphdr udp;
	unsigned char body[128];
} __attribute__ ((packed));

//TCP头部
struct tcphdr {
	unsigned short source; // 源端口号
	unsigned short dest; // 目的端口号
	unsigned int seq; // 序列号
	unsigned int ack_seq; // 确认号

	unsigned short res1:4,  // 保留位，通常为 0
		doff:4, // 数据偏移，即头部长度
		fin:1, // 结束标志
		syn:1, // 同步标志
		rst:1, // 重置标志
		psh:1, // 推送标志
		ack:1, // 确认标志
		urg:1, // 紧急标志
		ece:1, // 显式拥塞通知标志
		cwr:1; // 拥塞窗口缩减标志
	unsigned short window;
	unsigned short check; // 校验和
	unsigned short urg_ptr;
} __attribute__ ((packed));

//ARP头部,用于地址解析
struct arphdr {
	unsigned short h_type; // 硬件类型
	unsigned short h_proto; // 协议类型
	unsigned char h_addrlen; // 硬件地址长度字段
	unsigned char protolen; // 协议地址长度字段
	unsigned short oper; // 操作码字段
	unsigned char smac[ETH_ALEN]; // 源 MAC 地址
	unsigned int sip;
	unsigned char dmac[ETH_ALEN]; // 目的 MAC 地址
	unsigned int dip; // 目的 IP 地址
} __attribute__ ((packed));

//ICMP头部
struct icmphdr {
	unsigned char type;
	unsigned char code;
	unsigned short check;
	unsigned short identifier;
	unsigned short seq;
	unsigned char data[32];
} __attribute__ ((packed));

//ICMP数据包
struct icmppkt {
	struct ethhdr eh;
	struct iphdr ip;
	struct icmphdr icmp;
} __attribute__ ((packed));


#endif


