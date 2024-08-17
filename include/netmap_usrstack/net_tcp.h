#ifndef __NET_TCP_H__
#define __NET_TCP_H__

#include "netmap_usrstack/net_timer.h"
#include "netmap_usrstack/net_buffer.h"
#include "netmap_usrstack/net_hash.h"
#include "netmap_usrstack/net_addr.h"
#include "netmap_usrstack/net_config.h"
#include "netmap_usrstack/net_epoll_inner.h"

#define ETH_NUM		4


typedef enum _net_tcp_state {
	NET_TCP_CLOSED = 0,         // TCP连接关闭状态
	NET_TCP_LISTEN = 1,         // TCP监听状态
	NET_TCP_SYN_SENT = 2,       // 发送SYN请求状态
	NET_TCP_SYN_RCVD = 3,       // 收到SYN请求状态
	NET_TCP_ESTABLISHED = 4,    // TCP连接建立状态
	NET_TCP_CLOSE_WAIT = 5,     // 等待关闭状态
	NET_TCP_FIN_WAIT_1 = 6,     // 等待对方的FIN状态
	NET_TCP_CLOSING = 7,        // 关闭中状态
	NET_TCP_LAST_ACK = 8,       // 等待最后的ACK状态
	NET_TCP_FIN_WAIT_2 = 9,     // 等待对方的FIN状态
	NET_TCP_TIME_WAIT = 10,     // 等待超时等待状态
} net_tcp_state;

#define NET_TCPHDR_FIN		0x01   // FIN标志位
#define NET_TCPHDR_SYN		0x02   // SYN标志位
#define NET_TCPHDR_RST		0x04   // RST标志位
#define NET_TCPHDR_PSH		0x08   // PSH标志位
#define NET_TCPHDR_ACK		0x10   // ACK标志位
#define NET_TCPHDR_URG		0x20   // URG标志位
#define NET_TCPHDR_ECE		0x40   // ECE标志位
#define NET_TCPHDR_CWR		0x80   // CWR标志位

#define NET_TCPOPT_MSS_LEN				4   // TCP MSS选项长度
#define NET_TCPOPT_WSCALE_LEN			3   // TCP 窗口缩放选项长度
#define NET_TCPOPT_SACK_PERMIT_LEN		2   // TCP SACK允许选项长度
#define NET_TCPOPT_SACK_LEN				10  // TCP SACK选项长度
#define NET_TCPOPT_TIMESTAMP_LEN		10  // TCP 时间戳选项长度

#define TCP_DEFAULT_MSS		1460   // TCP默认的最大段大小
#define TCP_DEFAULT_WSCALE	7      // TCP默认的窗口缩放因子
#define TCP_INITIAL_WINDOW	14600  // TCP初始窗口大小
#define TCP_MAX_WINDOW		65535  // TCP最大窗口大小

#define NET_SEND_BUFFER_SIZE		8192  // TCP发送缓冲区大小
#define NET_RECV_BUFFER_SIZE		8192  // TCP接收缓冲区大小
#define NET_TCP_TIMEWAIT			0     // TCP TIME-WAIT状态超时时间
#define NET_TCP_TIMEOUT				30    // TCP超时时间

#define TCP_MAX_RTX					16    // TCP最大重传次数
#define TCP_MAX_SYN_RETRY			7     // TCP最大SYN重试次数
#define TCP_MAX_BACKOFF				7     // TCP最大退避时间


#define TCP_SEQ_LT(a,b) 		((int32_t)((a)-(b)) < 0)
#define TCP_SEQ_LEQ(a,b)		((int32_t)((a)-(b)) <= 0)
#define TCP_SEQ_GT(a,b) 		((int32_t)((a)-(b)) > 0)
#define TCP_SEQ_GEQ(a,b)		((int32_t)((a)-(b)) >= 0)
#define TCP_SEQ_BETWEEN(a,b,c)	(TCP_SEQ_GEQ(a,b) && TCP_SEQ_LEQ(a,c))

// 时钟的赫兹频率为1000
#define HZ						1000

//每个时钟滴答的时间，以微秒(us)为单位
#define TIME_TICK				(1000000/HZ)

// 将`struct timeval`结构转换为时间戳
#define TIMEVAL_TO_TS(t)		(uint32_t)((t)->tv_sec * HZ + ((t)->tv_usec / TIME_TICK))

// 将时间戳转换为微秒
#define TS_TO_USEC(t)			((t) * TIME_TICK)

// 将时间戳转换为毫秒
#define TS_TO_MSEC(t)			(TS_TO_USEC(t) / 1000)

// 将毫秒数转换为微秒
#define MSEC_TO_USEC(t)			((t) * 1000)

// 将微秒数转换为秒
#define USEC_TO_SEC(t)			((t) / 1000000)

//TCP初始重传超时时间，单位为时钟滴答数
#define TCP_INITIAL_RTO 		(MSEC_TO_USEC(500) / TIME_TICK)


#if NET_ENABLE_BLOCKING
// 启用阻塞模式，使用 pthread_mutex 锁
#define SBUF_LOCK_INIT(lock, errmsg, action);		\
	if (pthread_mutex_init(lock, PTHREAD_PROCESS_PRIVATE)) {		\
		perror("pthread_spin_init" errmsg);			\
		action;										\
	}
#define SBUF_LOCK_DESTROY(lock)	pthread_mutex_destroy(lock)
#define SBUF_LOCK(lock)			pthread_mutex_lock(lock)
#define SBUF_UNLOCK(lock)		pthread_mutex_unlock(lock)


#else


#define SBUF_LOCK_INIT(lock, errmsg, action);		\
	if (pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE)) {		\
		perror("pthread_spin_init" errmsg);			\
		action;										\
	}
#define SBUF_LOCK_DESTROY(lock)	pthread_spin_destroy(lock)
#define SBUF_LOCK(lock)			pthread_spin_lock(lock)
#define SBUF_UNLOCK(lock)		pthread_spin_unlock(lock)


#endif

enum tcp_option {
    TCP_OPT_END     = 0,  // 表示选项结束
    TCP_OPT_NOP     = 1,  // 无操作
    TCP_OPT_MSS     = 2,  // 最大分段大小选项（MSS）
    TCP_OPT_WSCALE  = 3,  // 窗口缩放选项
    TCP_OPT_SACK_PERMIT = 4,  // 选择性确认许可选项（SACK）
    TCP_OPT_SACK    = 5,  // 选择性确认选项
    TCP_OPT_TIMESTAMP = 8  // 时间戳选项
};

// TCP 连接关闭原因，用于标识不同的连接关闭原因
enum tcp_close_reason {
    TCP_NOT_CLOSED      = 0,  // 连接未关闭
    TCP_ACTIVE_CLOSE    = 1,  // 主动关闭（主动断开）
    TCP_PASSIVE_CLOSE   = 2,  // 被动关闭（被对方断开）
    TCP_CONN_FAIL       = 3,  // 连接失败
    TCP_CONN_LOST       = 4,  // 连接丢失
    TCP_RESET           = 5,  // 连接被重置（RST）
    TCP_NO_MEM          = 6,  // 内存不足导致连接关闭
    TCP_NOT_ACCEPTED    = 7,  // 连接未被接受（可能是监听端未处理连接）
    TCP_TIMEDOUT        = 8   // 连接超时
};

// ACK 选项，用于标识不同的确认（ACK）策略
enum ack_opt {
    ACK_OPT_NOW,        // 立即发送 ACK
    ACK_OPT_AGGREGATE,  // 聚合 ACK，批量发送
    ACK_OPT_WACK,       // 等待 ACK（延迟确认）
};

// 套接字类型，用于标识 TCP 套接字的不同类型
enum socket_type {
    NET_TCP_SOCK_UNUSED,    // 未使用的套接字
    NET_TCP_SOCK_STREAM,    // 流式套接字
    NET_TCP_SOCK_PROXY,     // 代理套接字
    NET_TCP_SOCK_LISTENER,  // 监听套接字
    NET_TCP_SOCK_EPOLL,     // epoll 套接字
    NET_TCP_SOCK_PIPE,      // 管道套接字
};

// TCP 时间戳，用于存储 TCP 包中的时间戳值
typedef struct _net_tcp_timestamp {
    uint32_t ts_val;  // 时间戳值（发送方发送的时间戳）
    uint32_t ts_ref;  // 时间戳参考值（接收方返回的时间戳）
} net_tcp_timestamp;

// 重传统计，用于记录与 TCP 重传相关的统计数据
typedef struct _net_rtm_stat {
    uint32_t tdp_ack_cnt;    // 接收到的 ACK 数量
    uint32_t tdp_ack_bytes;  // 接收到的 ACK 确认的字节数
    uint32_t ack_upd_cnt;    // 更新后的 ACK 数量
    uint32_t ack_upd_bytes;  // 更新后的 ACK 确认的字节数
    uint32_t rto_cnt;        // 重传超时（RTO）次数
    uint32_t rto_bytes;      // 重传超时的字节数
} net_rtm_stat;


// 用于表示 TCP 数据的接收端状态信息
typedef struct _net_tcp_recv {
    uint32_t rcv_wnd;                // 接收窗口大小
    uint32_t irs;                    // 初始接收序列号
    uint32_t snd_wl1;                // 最近一次接收到的窗口更新的序列号段起点
    uint32_t snd_wl2;                // 最近一次接收到的窗口更新的序列号段终点

    uint8_t dup_acks;                // 重复的 ACK 数量
    uint32_t last_ack_seq;           // 最近接收到的 ACK 序列号

    uint32_t ts_recent;              // 最近接收到的 TCP 时间戳
    uint32_t ts_lastack_rcvd;        // 最近接收到的 ACK 的时间戳
    uint32_t ts_last_ts_upd;         // 最近一次更新时间戳的时间
    uint32_t ts_tw_expire;           // TIME-WAIT 状态的到期时间

    uint32_t srtt;                   // 平滑的往返时间
    uint32_t mdev;                   // 平均偏差
    uint32_t mdev_max;               // 最大偏差
    uint32_t rttvar;                 // RTT 的方差
    uint32_t rtt_seq;                // 当前测量 RTT 的序列号

    struct _net_ring_buffer *recvbuf; // 指向接收缓冲区的指针，用于存储接收到的数据

    TAILQ_ENTRY(_net_tcp_stream) he_link; // 哈希表链表链接，连接到 TCP 流的哈希表中

#if NET_ENABLE_BLOCKING
    TAILQ_ENTRY(_net_tcp_stream) rcv_br_link; // 只有在阻塞模式下才使用，接收缓冲区的阻塞链接
    pthread_cond_t read_cond;      // 用于接收线程的条件变量
    pthread_mutex_t read_lock;     // 读操作的互斥锁
#else
    pthread_spinlock_t read_lock;  // 非阻塞模式下使用的自旋锁
#endif

} net_tcp_recv;

// 表示 TCP 数据的发送端状态信息
typedef struct _net_tcp_send {
    uint16_t ip_id;                 // IP 包标识符
    uint16_t mss;                   // 最大分段大小
    uint16_t eff_mss;               // 实际有效的 MSS，可能会根据网络情况调整

    uint8_t wscale_mine;            // 本地主机的窗口缩放值
    uint8_t wscale_peer;            // 对等方的窗口缩放值
    int8_t nif_out;                 // 出站网络接口的标识

    unsigned char *d_haddr;         // 目标硬件地址指针
    uint32_t snd_una;               // 最后未确认的发送序列号
    uint32_t snd_wnd;               // 发送窗口大小

    uint32_t peer_wnd;              // 对等方的窗口大小
    uint32_t iss;                   // 初始发送序列号
    uint32_t fss;                   // FIN（结束标志）发送序列号

    uint8_t nrtx;                   // 重传次数
    uint8_t max_nrtx;               // 最大重传次数
    uint32_t rto;                   // 重传超时时间
    uint32_t ts_rto;                // 最近一次重传超时的时间戳

    uint32_t cwnd;                  // 拥塞窗口大小
    uint32_t ssthresh;              // 拥塞避免的慢启动阈值
    uint32_t ts_lastack_sent;       // 最近发送 ACK 的时间戳

    uint8_t is_wack:1,              // 是否正在等待 ACK
            ack_cnt:6;              // 等待 ACK 的计数

    uint8_t on_control_list;        // 是否在控制列表中
    uint8_t on_send_list;           // 是否在发送列表中
    uint8_t on_ack_list;            // 是否在 ACK 列表中
    uint8_t on_sendq;               // 是否在发送队列中
    uint8_t on_ackq;                // 是否在 ACK 队列中
    uint8_t on_closeq;              // 是否在关闭队列中
    uint8_t on_resetq;              // 是否在重置队列中

    uint8_t on_closeq_int:1,        // 是否在内部关闭队列中
            on_resetq_int:1,        // 是否在内部重置队列中
            is_fin_sent:1,          // 是否已发送 FIN
            is_fin_ackd:1;          // 是否已收到 FIN 的 ACK

    TAILQ_ENTRY(_net_tcp_stream) control_link;  // 链接到控制列表
    TAILQ_ENTRY(_net_tcp_stream) send_link;     // 链接到发送列表
    TAILQ_ENTRY(_net_tcp_stream) ack_link;      // 链接到 ACK 列表
    TAILQ_ENTRY(_net_tcp_stream) timer_link;    // 链接到定时器列表
    TAILQ_ENTRY(_net_tcp_stream) timeout_link;  // 链接到超时列表

    struct _net_send_buffer *sndbuf; // 指向发送缓冲区的指针，用于存储要发送的数据

#if NET_ENABLE_BLOCKING
    TAILQ_ENTRY(_net_tcp_stream) snd_br_link; // 只有在阻塞模式下才使用，发送缓冲区的阻塞链接
    pthread_cond_t write_cond;    // 用于发送线程的条件变量
    pthread_mutex_t write_lock;   // 写操作的互斥锁
#else
    pthread_spinlock_t write_lock; // 非阻塞模式下使用的自旋锁
#endif

} net_tcp_send;

// TCP流
typedef struct _net_tcp_stream {
#if NET_ENABLE_SOCKET_C10M
    struct _net_socket *s;  // 套接字指针，当启用C10M模式时使用
#endif
    struct _net_socket_map *socket;  // 套接字映射，指向套接字的映射表项
    uint32_t id:24,  // 流的唯一标识符，占24位
             stream_type:8;  // 流的类型，占8位

    uint32_t saddr;  // 源地址（IPv4）
    uint32_t daddr;  // 目标地址（IPv4）

    uint16_t sport;  // 源端口号
    uint16_t dport;  // 目标端口号

    uint8_t state;  // TCP状态，如LISTEN, SYN_SENT, ESTABLISHED等
    uint8_t close_reason;  // 关闭的原因，如正常关闭或错误
    uint8_t on_hash_table;  // 表示此流是否在哈希表中
    uint8_t on_timewait_list;  // 表示此流是否在TIME_WAIT列表中

    uint8_t ht_idx;  // 哈希表中的索引
    uint8_t closed;  // 表示流是否已关闭
    uint8_t is_bound_addr;  // 表示是否绑定了地址
    uint8_t need_wnd_adv;  // 是否需要窗口更新通知

    int16_t on_rto_idx;  // RTO（重传超时）哈希表中的索引
    uint16_t on_timeout_list:1,  // 是否在超时列表中
             on_rcv_br_list:1,  // 是否在接收阻塞列表中
             on_snd_br_list:1,  // 是否在发送阻塞列表中
             saw_timestamp:1,  // 是否看到TCP时间戳选项
             sack_permit:1,  // 是否允许选择性确认(SACK)
             control_list_waiting:1,  // 是否在控制列表等待
             have_reset:1;  // 是否收到了重置标志（RST）

    uint32_t last_active_ts;  // 最后活动时间戳

    net_tcp_recv *rcv;  // 指向TCP接收方的结构体
    net_tcp_send *snd;  // 指向TCP发送方的结构体

    uint32_t snd_nxt;  // 下一个要发送的字节序列号
    uint32_t rcv_nxt;  // 下一个要接收的字节序列号

} net_tcp_stream;

// 维护TCP流的发送控制列表、发送列表、确认列表
typedef struct _net_sender {
    int ifidx;  // 接口索引
    TAILQ_HEAD(control_head, _net_tcp_stream) control_list;  // 控制列表，维护流的控制信息
    TAILQ_HEAD(send_head, _net_tcp_stream) send_list;  // 发送列表，待发送的数据流
    TAILQ_HEAD(ack_head, _net_tcp_stream) ack_list;  // 确认列表，等待确认的数据流

    int control_list_cnt;  // 控制列表中的流数
    int send_list_cnt;  // 发送列表中的流数
    int ack_list_cnt;  // 确认列表中的流数
} net_sender;

// 线程上下文，保存与网络线程相关的信息
typedef struct _net_thread_context {
    int cpu;  // 该线程运行的CPU编号
    pthread_t thread;  // POSIX线程
    uint8_t done:1,  // 线程是否完成
            exit:1,  // 线程是否退出
            interrupt:1;  // 线程是否被中断

    struct _net_tcp_manager *tcp_manager;  // 指向TCP管理器的指针
    void *io_private_context;  // I/O操作的私有上下文

    pthread_mutex_t smap_lock;  // 锁定套接字映射的互斥锁
    pthread_mutex_t flow_pool_lock;  // 锁定流池的互斥锁
    pthread_mutex_t socket_pool_lock;  // 锁定套接字池的互斥锁
} net_thread_context;


// TCP管理器
typedef struct _net_tcp_manager {

    struct _net_mempool *flow;  // 流的内存池
    struct _net_mempool *rcv;  // 接收方的内存池
    struct _net_mempool *snd;  // 发送方的内存池
    struct _net_mempool *mv;  // 其他资源的内存池

    struct _net_sb_manager *rbm_snd;  // 发送缓冲区管理器
    struct _net_rb_manager *rbm_rcv;  // 接收缓冲区管理器

    struct _net_hashtable *tcp_flow_table;  // TCP流的哈希表

#if NET_ENABLE_SOCKET_C10M
    struct _net_socket_table *fdtable;  // 文件描述符表，用于C10M模式
#endif

    uint32_t s_index;  // 套接字的索引
    struct _net_socket_map *smap;  // 套接字映射表
    TAILQ_HEAD(, _net_socket_map) free_smap;  // 空闲套接字映射的队列

    struct _net_addr_pool *ap;  // 地址池
    uint32_t gid;  // 全局ID
    uint32_t flow_cnt;  // 流的计数器

    net_thread_context *ctx;  // 网络线程的上下文
#if NET_ENABLE_EPOLL_RB
    void *ep;  // epoll反应器
#else
    struct _net_epoll *ep;  // epoll对象
#endif
    uint32_t ts_last_event;  // 上次事件的时间戳

    struct _net_hashtable *listeners;  // 监听器的哈希表

    struct _net_stream_queue *connectq;  // 连接队列
    struct _net_stream_queue *sendq;  // 发送队列
    struct _net_stream_queue *ackq;  // 确认队列

    struct _net_stream_queue *closeq;  // 关闭队列
    struct _net_stream_queue_int *closeq_int;  // 内部关闭队列

    struct _net_stream_queue *resetq;  // 重置队列
    struct _net_stream_queue_int *resetq_int;  // 内部重置队列

    struct _net_stream_queue *destroyq;  // 销毁队列

    struct _net_sender *g_sender;  // 全局发送器
    struct _net_sender *n_sender[ETH_NUM];  // 每个网络接口的发送器

    struct _net_rto_hashstore *rto_store;  // RTO哈希存储
    TAILQ_HEAD(timewait_head, _net_tcp_stream) timewait_list;  // TIME_WAIT列表
    TAILQ_HEAD(timeout_head, _net_tcp_stream) timeout_list;  // 超时列表

    int rto_list_cnt;  // RTO列表中的条目数
    int timewait_list_cnt;  // TIME_WAIT列表中的条目数
    int timeout_list_cnt;  // 超时列表中的条目数

#if NET_ENABLE_BLOCKING
    TAILQ_HEAD(rcv_br_head, _net_tcp_stream) rcv_br_list;  // 接收阻塞列表
    TAILQ_HEAD(snd_br_head, _net_tcp_stream) snd_br_list;  // 发送阻塞列表
    int rcv_br_list_cnt;  // 接收阻塞列表中的流数
    int snd_br_list_cnt;  // 发送阻塞列表中的流数
#endif

    uint32_t cur_ts;  // 当前时间戳
    int wakeup_flag;  // 唤醒标志
    int is_sleeping;  // 是否处于睡眠状态

} net_tcp_manager;


#include <arpa/inet.h>

typedef struct _net_tcp_listener {
	int sockid;

#if NET_ENABLE_SOCKET_C10M
	struct _net_socket *s; // 套接字结构指针
#endif

	struct _net_socket_map *socket; // 指向socket映射的指针

	int backlog; // 允许排队的最大连接数
	struct _net_stream_queue *acceptq; // 用于存储已接受但尚未处理的TCP连接队列

	pthread_mutex_t accept_lock; // 互斥锁，用于保护accept操作
	pthread_cond_t accept_cond; // 条件变量，用于控制accept操作的同步

	TAILQ_ENTRY(_net_tcp_listener) he_link;
} net_tcp_listener; 

// 将数据通过以太网帧进行封装并输出
uint8_t *EthernetOutput(net_tcp_manager *tcp, uint16_t h_proto,
	int nif, unsigned char* dst_haddr, uint16_t iplen);

//将TCP数据流通过IP层进行封装并输出
uint8_t *IPOutput(net_tcp_manager *tcp, net_tcp_stream *stream, uint16_t tcplen);


net_tcp_stream *CreateTcpStream(net_tcp_manager *tcp, struct _net_socket_map *socket, int type, 
		uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);

//用于独立发送IP数据包而不依赖于TCP流
uint8_t *IPOutputStandalone(net_tcp_manager *tcp, uint8_t protocol, 
		uint16_t ip_id, uint32_t saddr, uint32_t daddr, uint16_t payloadlen);

// 将当前TCP流添加到发送列表中
void net_tcp_addto_sendlist(net_tcp_manager *tcp, net_tcp_stream *cur_stream);

// 将当前TCP流添加到控制列表中
void net_tcp_addto_controllist(net_tcp_manager *tcp, net_tcp_stream *cur_stream);

// 从控制列表中移除当前TCP流
void net_tcp_remove_controllist(net_tcp_manager *tcp, net_tcp_stream *cur_stream);

// 从发送列表中移除当前TCP流
void net_tcp_remove_sendlist(net_tcp_manager *tcp, net_tcp_stream *cur_stream);

// 从ACK列表中移除当前TCP流
void net_tcp_remove_acklist(net_tcp_manager *tcp, net_tcp_stream *cur_stream);



// 处理数据的分块写入操作
void net_tcp_write_chunks(uint32_t cur_ts);

// 处理来自应用程序的TCP API调用
int net_tcp_handle_apicall(uint32_t cur_ts);

// 初始化TCP管理器
int net_tcp_init_manager(net_thread_context *ctx);

// 初始化TCP线程上下文
void net_tcp_init_thread_context(net_thread_context *ctx);


// 触发读 写 关闭 错误 事件，当数据到达时通知应用层
void RaiseReadEvent(net_tcp_manager *tcp, net_tcp_stream *stream);
void RaiseWriteEvent(net_tcp_manager *tcp, net_tcp_stream *stream);
void RaiseCloseEvent(net_tcp_manager *tcp, net_tcp_stream *stream);
void RaiseErrorEvent(net_tcp_manager *tcp, net_tcp_stream *stream);



#endif


