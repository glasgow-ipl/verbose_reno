#include <linux/module.h>
#include <net/tcp.h>
#include <linux/vmalloc.h>


static int initial_ssthresh __read_mostly;
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");

struct vrenotcp {
	u32 saved_reset_cnt;

};


void tcp_vreno_in_ack_event(struct sock *sk, u32 flags)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *isock = inet_sk(sk);

	uint16_t sport = ntohs(isock->inet_sport);
	uint16_t dport = ntohs(isock->inet_dport);

	if(sport == 80) { // HTTP server doing
		printk(KERN_INFO "ACK Received. sourcep: %u dstp: %u proto%u send window: %u recv window: %u ssthresh: %u slow-start: %u\n",
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


	if(initial_ssthresh) 
	{
		printk(KERN_INFO "INITIAL SSTHRESH: %u", initial_ssthresh);
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
	}

	vreno_reset(ca);
}


void vreno_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{

	printk(KERN_INFO "Congestion window event occurred: %u", ev);
	if(ev == CA_EVENT_CWND_RESTART)
	{
		struct vrenotcp *ca = inet_csk_ca(sk);
		ca->saved_reset_cnt++;
		printk(KERN_INFO "Reset count: %u\n", ca->saved_reset_cnt);
	}

}


void tcp_trace_state(struct sock* sk, u8 new_state)
{
	switch(new_state)
	{
		case TCP_CA_CWR:
			printk(KERN_INFO "Trace event: Entering CWR state (ECN mark or qdisc drop)\n");
			break;
		case TCP_CA_Recovery:
			printk(KERN_INFO "Trace event: Loss. Entering fast retransmit state (dup acks)\n");
			break;
		case TCP_CA_Loss:
			printk(KERN_INFO "Trace event: Loss. Entering loss recovery (Timeout)\n");
			break;
		default:
			printk(KERN_INFO "Trace event: Unknown %u\n", new_state);
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
	printk(KERN_INFO "Verbose Reno Going Up5");
	return tcp_register_congestion_control(&tcp_reno_verbose);
}


static void __exit tcp_reno_verbose_unregister(void)
{
	printk(KERN_INFO "Verbose Reno Shutting Down5");
	tcp_unregister_congestion_control(&tcp_reno_verbose);
}



module_init(tcp_reno_verbose_register);
module_exit(tcp_reno_verbose_unregister);

MODULE_AUTHOR("Yanev");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Verbose reno");
