#ifndef __NET_CONFIG_H__
#define __NET_CONFIG_H__


#include <stdio.h>

//自身网络地址和MAC地址
#define NET_SELF_IP		"192.168.131.130"//"192.168.1.108" 
#define NET_SELF_IP_HEX	0x8283A8C0 //0x8301A8C0 //
#define NET_SELF_MAC	"00:0c:29:00:04:39"
#define NET_ETH_NAME ens33  

//网络缓冲区和并发设置
#define NET_MAX_CONCURRENCY        1024 // 最大并发连接数
#define NET_SNDBUF_SIZE            8192 // 发送缓冲区大小
#define NET_RCVBUF_SIZE            8192 // 接收缓冲区大小
#define NET_MAX_NUM_BUFFERS        1024 // 最大缓冲区数量
#define NET_BACKLOG_SIZE           1024 // 最大待处理连接数

//网络选项
#define NET_ENABLE_MULTI_NIC       0 // 是否启用多个网络接口卡（NIC）
#define NET_ENABLE_BLOCKING        1 // 是否启用阻塞模式
#define NET_ENABLE_EPOLL_RB        1 // 启用基于 Epoll 的环形缓冲区
#define NET_ENABLE_SOCKET_C10M     1 // 是否启用Socket C10M（大规模连接）
#define NET_ENABLE_POSIX_API       1 // 是否启用POSIX API



#define NET_SOCKFD_NR            (1024*1024) // 最大文件描述符数
#define NET_BITS_PER_BYTE        8 // 每字节的位数


//#define NET_DEBUG 1
#ifdef NET_DEBUG
#define netdbg(format, ...) 			fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define net_trace_api(format, ...) 		fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define net_trace_tcp(format, ...) 		fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define net_trace_buffer(format, ...) 	fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define net_trace_eth(format, ...) 		fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define net_trace_ip(format, ...) 		fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define net_trace_timer(format, ...) 	fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define net_trace_epoll(format, ...)	fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)
#define net_trace_socket(format, ...)	fprintf(stdout, " [File:"__FILE__", line:%05d] : "format, __LINE__, ##__VA_ARGS__)

#else
#define netdbg(format, ...) 
#define net_trace_api(format, ...)
#define net_trace_tcp(format, ...) 
#define net_trace_buffer(format, ...)
#define net_trace_eth(format, ...)
#define net_trace_ip(format, ...)
#define net_trace_timer(format, ...)
#define net_trace_epoll(format, ...)
#define net_trace_socket(format, ...)


#endif

#define UNUSED(expr)	do {(void)(expr); } while(0)


#endif



