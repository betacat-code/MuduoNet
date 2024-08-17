#ifndef __NET_ARP_H__
#define __NET_ARP_H__

#include "net_header.h"

// 最大 ARP 表项数量
#define MAX_ARPENTRY	256

typedef struct _net_arp_entry {
	uint32_t ip; // IP 地址
	int8_t prefix; // 子网前缀长度
	uint32_t ip_mask; // IP 子网掩码
	uint32_t ip_masked; // 掩码处理后的 IP 地址
	unsigned char haddr[ETH_ALEN]; // 硬件地址 
} net_arp_entry;

//  ARP 表结构
typedef struct _net_arp_table {
	net_arp_entry *entry; // 指向 ARP 表项的指针数组
	int entries; // 当前表项数量
} net_arp_table;


// 根据目标 IP 地址获取对应的硬件地址
unsigned char *GetDestinationHWaddr(uint32_t dip);

// 根据目标 IP 地址获取输出接口
int GetOutputInterface(uint32_t daddr);

// 注册新的 ARP 表项
int net_arp_register_entry(uint32_t ip, const unsigned char *haddr);

// 处理 ARP 数据包
int net_arp_process(net_nic_context *ctx, unsigned char *stream);

// 初始化 ARP 表
int net_arp_init_table(void);

// 将 MAC 地址字符串转换为硬件地址
int str2mac(char *mac, char *str);


#endif



