/*
	1. Get Rates for transfer from application (hardcode)
	2. Calculate "useful" window upon reset
	3. Perform jump to useful_window / 2?
*/
#include <linux/module.h>
#include <net/tcp.h>
#include <linux/vmalloc.h>


static int initial_ssthresh __read_mostly;
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");

#define HINTS_NO 3
static int application_hints[HINTS_NO] = {50, 125, 200};


enum AACC_state {
	RESTARTING_AFTER_IDLE=0,
	CWND_GROWTH_SUSPENSION,
	SAFE_RETREAT,
	NORMAL
};


static inline void tcp_snd_cwnd_set(struct tcp_sock *tp, u32 val)
{

	WARN_ON_ONCE((int)val <= 0);
	tp->snd_cwnd = val;
}

struct vrenotcp {
	u32 saved_reset_cnt;
	u32 max_cwnd;
	u32 prev_rtt;
	u8 should_resume;
	u8 cwnd_growth_suspension_rounds;
	u32 cwnd_suspension_start_time;
	enum AACC_state aacc_state;
};


void tcp_aacc_in_ack_event(struct sock *sk, u32 flags)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *isock = inet_sk(sk);

	uint16_t sport = ntohs(isock->inet_sport);
	uint16_t dport = ntohs(isock->inet_dport);

	if(sport == 80 || sport == 8080) { // HTTP server doing
		printk(KERN_INFO "ACK Received. sourcep: %u dstp: %u proto%u send window: %u recv window: %u ssthresh: %u slow-start: %u\n",
				sport, dport, sk->sk_protocol, tp->snd_cwnd, tp->rcv_wnd, tp->snd_ssthresh, tp->snd_cwnd < tp->snd_ssthresh);
	}
}


static inline void tcp_aacc_reset(struct vrenotcp *ca)
{

		ca->saved_reset_cnt = 0;
		ca->max_cwnd = 0;
		ca->prev_rtt = 0;
}


void tcp_aacc_init(struct sock *sk) 
{

	struct vrenotcp *ca = inet_csk_ca(sk);


	if(initial_ssthresh) 
	{
		printk(KERN_INFO "INITIAL SSTHRESH: %u", initial_ssthresh);
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
	}

	tcp_aacc_reset(ca);
}


void tcp_aacc_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{

	printk(KERN_INFO "Congestion window event occurred: %u", ev);
	if(ev == CA_EVENT_CWND_RESTART)
	{
		const struct inet_sock *isock = inet_sk(sk);
		const struct tcp_sock *tp = tcp_sk(sk);
		struct vrenotcp *ca = inet_csk_ca(sk);

		uint16_t sport = ntohs(isock->inet_sport);
		uint16_t dport = ntohs(isock->inet_dport);

		ca->saved_reset_cnt++;

		printk(KERN_INFO "CWND RESET. Reset count: %u Resetting sourcep: %u dstp: %u send window: %u recv window: %u ssthresh: %u\n",
			 ca->saved_reset_cnt, sport, dport, tp->snd_cwnd, tp->rcv_wnd, tp->snd_ssthresh);
		
		ca->prev_rtt = tp->srtt_us;
	}

}


void tcp_trace_state(struct sock* sk, u8 new_state)
{

	// It might be beneficial to disallow use of max_cwnd if it cwnd was reset during recovery, i.e., _after_ a loss but before reaching the prior_cwnd
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


/* In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w),
 * for every packet that was ACKed.
 */
// void tcp_cong_avoid_ai(struct tcp_sock *tp, u32 w, u32 acked)
// {
// 	/* If credits accumulated at a higher w, apply them gently now. */
// 	if (tp->snd_cwnd_cnt >= w) {
// 		tp->snd_cwnd_cnt = 0;
// 		tcp_snd_cwnd_set(tp, tcp_snd_cwnd(tp) + 1);
// 	}

// 	tp->snd_cwnd_cnt += acked;
// 	if (tp->snd_cwnd_cnt >= w) {
// 		u32 delta = tp->snd_cwnd_cnt / w;

// 		tp->snd_cwnd_cnt -= delta * w;
// 		tcp_snd_cwnd_set(tp, tcp_snd_cwnd(tp) + delta);
// 	}
// 	tcp_snd_cwnd_set(tp, min(tcp_snd_cwnd(tp), tp->snd_cwnd_clamp));
// }

/* Slow start is used when congestion window is no greater than the slow start
 * threshold. We base on RFC2581 and also handle stretch ACKs properly.
 * We do not implement RFC3465 Appropriate Byte Counting (ABC) per se but
 * something better;) a packet is only considered (s)acked in its entirety to
 * defend the ACK attacks described in the RFC. Slow start processes a stretch
 * ACK of degree N as if N acks of degree 1 are received back to back except
 * ABC caps N to 2. Slow start exits when cwnd grows over ssthresh and
 * returns the leftover acks to adjust cwnd in congestion avoidance mode.
 */
// u32 tcp_slow_start(struct tcp_sock *tp, u32 acked)
// {
// 	u32 cwnd = min(tcp_snd_cwnd(tp) + acked, tp->snd_ssthresh);

// 	acked -= cwnd - tcp_snd_cwnd(tp);
// 	tcp_snd_cwnd_set(tp, min(cwnd, tp->snd_cwnd_clamp));

// 	return acked;
// }

/*
 * TCP Reno congestion control
 * This is special case used for fallback as well.
 */
/* This is Jacobson's slow start and congestion avoidance.
 * SIGCOMM '88, p. 328.
 */
void tcp_aacc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct vrenotcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (ca->prev_rtt)
	{
		printk(KERN_INFO "Starting Retransmission, saved RTT us %u MAX_CWND %u", ca->prev_rtt, ca->max_cwnd);
		ca->prev_rtt = 0;
		ca->max_cwnd = 0;
	}

	// Let Reno handle cwnd calculation
	tcp_reno_cong_avoid(sk, ack, acked);


	if (ca->max_cwnd < tp->snd_cwnd)
	{
		ca->max_cwnd = tp->snd_cwnd;
	}

}


// Called when we enter fast retransmit:
// returns: value that cwnd is reduced to after loss
u32 tcp_reno_ssthresh(struct sock *sk)
{
	return max(tcp_snd_cwnd(tp) >> 1U, 2U);
}



u32 tcp_reno_undo_cwnd(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return max(tcp_snd_cwnd(tp), tp->prior_cwnd);
}

struct tcp_congestion_ops tcp_reno_verbose = {
	.init		= tcp_aacc_init,
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "aacc",
	.owner		= THIS_MODULE,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_aacc_cong_avoid,
//	.set_state  = vreno_set_state,
	.cwnd_event = tcp_aacc_cwnd_event,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.in_ack_event = tcp_aacc_in_ack_event,

	.set_state	= tcp_trace_state,
};


static int __init tcp_aacc_register(void)
{
	printk(KERN_INFO "TCP AACC Going Up");
	return tcp_register_congestion_control(&tcp_reno_verbose);
}


static void __exit tcp_aacc_unregister(void)
{
	printk(KERN_INFO "TCP AACC Going Down");
	tcp_unregister_congestion_control(&tcp_reno_verbose);
}



module_init(tcp_aacc_register);
module_exit(tcp_aacc_unregister);

MODULE_AUTHOR("Yanev");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AA Reno");
