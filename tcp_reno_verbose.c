#define DEBUG
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/vmalloc.h>

#include <linux/once.h>   /* for DO_ONCE() in newer kernels */

/*
 * MY_LOG_ONCE() will:
 *  - act like pr_info() if DEBUG is not defined
 *  - act like pr_debug() but print only once if DEBUG is defined
 */
#ifdef DEBUG
# define my_log_once(fmt, ...) \
    pr_debug(fmt, ##__VA_ARGS__)
#else
# define my_log_once(fmt, ...) \
    pr_info(fmt, ##__VA_ARGS__)
#endif

static int initial_ssthresh __read_mostly;
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");


static ktime_t module_load_time;
struct vrenotcp {
	u32 saved_reset_cnt;

};


static inline void tcp_snd_cwnd_set(struct tcp_sock *tp, u32 val)
{
	pr_debug("My set %u", val);
	pr_debug("cwnd %u, packets out %u, retrans out %u, cwnd used %u, cwnd usage seq %u", 
		tp->snd_cwnd, tp->packets_out, tp->retrans_out, tp->snd_cwnd_used, tp->max_packets_seq);

	WARN_ON_ONCE((int)val <= 0);
	tp->snd_cwnd = val;
}


void tcp_vreno_in_ack_event(struct sock *sk, u32 flags)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *isock = inet_sk(sk);

	uint16_t sport = ntohs(isock->inet_sport);
	uint16_t dport = ntohs(isock->inet_dport);

	if(sport == 80 || sport == 8080) { // HTTP server doing
		pr_debug("ACK Received. sourcep: %u dstp: %u proto%u send window: %u recv window: %u ssthresh: %u slow-start: %u\n",
				sport, dport, sk->sk_protocol, tp->snd_cwnd, tp->rcv_wnd, tp->snd_ssthresh, tp->snd_cwnd < tp->snd_ssthresh);
	}
}


static inline void vreno_reset(struct vrenotcp *ca)
{

		ca->saved_reset_cnt = 0;
}


void tcp_vreno_init(struct sock *sk) 
{

	struct vrenotcp *ca = inet_csk_ca(sk);

	s64 ms_since_load = ktime_to_ms(ktime_sub(ktime_get(), module_load_time));

    /* Convert to h:m:s */
    long total_sec = div_s64(ms_since_load, 1000);
    long hours     = total_sec / 3600;
    long minutes   = (total_sec % 3600) / 60;
    long seconds   = total_sec % 60;

    pr_debug("Module loaded %02ld:%02ld:%02ld ago\n",
           hours, minutes, seconds);

	if(initial_ssthresh) 
	{
		pr_debug("INITIAL SSTHRESH: %u", initial_ssthresh);
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
	}

	vreno_reset(ca);
}


void vreno_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{

	pr_debug("Congestion window event occurred: %u", ev);
	if(ev == CA_EVENT_CWND_RESTART)
	{
		const struct inet_sock *isock = inet_sk(sk);
		const struct tcp_sock *tp = tcp_sk(sk);
		struct vrenotcp *ca = inet_csk_ca(sk);

		uint16_t sport = ntohs(isock->inet_sport);
		uint16_t dport = ntohs(isock->inet_dport);

		ca->saved_reset_cnt++;

		my_log_once("CWND RESET. Reset count: %u Resetting sourcep: %u dstp: %u send window: %u recv window: %u ssthresh: %u\n",
			 ca->saved_reset_cnt, sport, dport, tp->snd_cwnd, tp->rcv_wnd, tp->snd_ssthresh);
	}

}


void tcp_trace_state(struct sock* sk, u8 new_state)
{
	switch(new_state)
	{
		case TCP_CA_CWR:
			pr_debug("Trace event: Entering CWR state (ECN mark or qdisc drop)\n");
			break;
		case TCP_CA_Recovery:
			pr_debug("Trace event: Loss. Entering fast retransmit state (dup acks)\n");
			break;
		case TCP_CA_Loss:
			pr_debug("Trace event: Loss. Entering loss recovery (Timeout)\n");
			break;
		default:
			pr_debug("Trace event: Unknown %u\n", new_state);
	}

}


struct tcp_congestion_ops tcp_reno_verbose = {
	.init		= tcp_vreno_init,
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "reno_verbose",
	.owner		= THIS_MODULE,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
//	.set_state  = vreno_set_state,
	.cwnd_event = vreno_cwnd_event,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.in_ack_event = tcp_vreno_in_ack_event,

	.set_state	= tcp_trace_state,
};


static int __init tcp_reno_verbose_register(void)
{
	pr_debug("Verbose Reno Going Up5");
	module_load_time = ktime_get();
	return tcp_register_congestion_control(&tcp_reno_verbose);
}


static void __exit tcp_reno_verbose_unregister(void)
{
	pr_debug("Verbose Reno Shutting Down5");
	tcp_unregister_congestion_control(&tcp_reno_verbose);
}



module_init(tcp_reno_verbose_register);
module_exit(tcp_reno_verbose_unregister);

MODULE_AUTHOR("Yanev");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Verbose reno");
