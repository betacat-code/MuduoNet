#ifndef __NET_NIC_H__
#define __NET_NIC_H__


#include "netmap_usrstack/net_tcp.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define NETMAP_WITH_LIBS

#include <net/netmap_user.h> 
#pragma pack(1)

// 网卡接口

#define MAX_PKT_BURST 64  // 最大数据包突发传输数目
#define MAX_DEVICES 16  // 最大设备数目

#define EXTRA_BUFS 512  // 额外缓冲区数目

#define ETHERNET_FRAME_SIZE 1514  // 以太网帧大小
#define ETHERNET_HEADER_LEN 14  // 以太网头部长度

#define IDLE_POLL_COUNT 10  // 空闲轮询计数
#define IDLE_POLL_WAIT 1  // 空闲轮询等待时间

typedef struct _net_nic_context {
    struct nm_desc *nmr;  // 指向 netmap 描述符的指针
    unsigned char snd_pktbuf[ETHERNET_FRAME_SIZE];  // 发送数据包缓冲区
    unsigned char *rcv_pktbuf[MAX_PKT_BURST];  // 接收数据包缓冲区数组
    uint16_t rcv_pkt_len[MAX_PKT_BURST];  // 接收数据包长度数组
    uint16_t snd_pkt_size;  // 发送数据包大小
    uint8_t dev_poll_flag;  // 设备轮询标志
    uint8_t idle_poll_count;  // 空闲轮询计数
} net_nic_context;

// 网络接口处理器
typedef struct _net_nic_handler {
	int (*init)(net_thread_context *ctx, const char *ifname);
	int (*read)(net_nic_context *ctx, unsigned char **stream);
	int (*write)(net_nic_context *ctx, const void *stream, int length);
	unsigned char* (*get_wbuffer)(net_nic_context *ctx, int nif, uint16_t pktsize);
} net_nic_handler;

// 获取缓冲区
unsigned char* net_nic_get_wbuffer(net_nic_context *ctx, int nif, uint16_t pktsize);
unsigned char* net_nic_get_rbuffer(net_nic_context *ctx, int nif, uint16_t *len);

// 发送接收数据包
int net_nic_send_pkts(net_nic_context *ctx, int nif);
int net_nic_recv_pkts(net_nic_context *ctx, int ifidx);

// 读取写入数据包
int net_nic_read(net_nic_context *ctx, unsigned char **stream);
int net_nic_write(net_nic_context *ctx, const void *stream, int length);


int net_nic_init(net_thread_context *tctx, const char *ifname);
int net_nic_select(net_nic_context *ctx);


#endif



