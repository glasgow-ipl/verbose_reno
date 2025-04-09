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
	AACC_RESTARTING_AFTER_IDLE=0,
	AACC_CWND_JUMP_CONFIRMATION,
	AACC_CWND_JUMP_LOSS_MONITORING,
	AACC_CWND_GROWTH_SUSPENSION,
	AACC_SAFE_RETREAT,
	AACC_NORMAL
};


static inline void tcp_snd_cwnd_set(struct tcp_sock *tp, u32 val)
{
	printk(KERN_INFO "My set %u", val);
	printk(KERN_INFO "cwnd %u, packets out %u, retrans out %u, cwnd used %u, cwnd usage seq %u", tp->snd_cwnd, tp->packets_out, tp->retrans_out, tp->snd_cwnd_used, tp->max_packets_seq);

	WARN_ON_ONCE((int)val <= 0);
	tp->snd_cwnd = val;
}

struct vrenotcp {
	u32 saved_reset_cnt;
	u32 max_cwnd;
	u32 prev_rtt;
	u32 cwnd_jump_mark;
	u32 cwnd_restart_flight_mark;
	u32 pre_jump_window;
	u8 should_resume;
	u8 AACC_CWND_GROWTH_SUSPENSION_rounds;
	u32 cwnd_suspension_start_time;
	enum AACC_state aacc_state;
};


void tcp_aacc_in_ack_event(struct sock *sk, u32 flags)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *isock = inet_sk(sk);
	struct vrenotcp *ca = inet_csk_ca(sk);

	uint16_t sport = ntohs(isock->inet_sport);
	uint16_t dport = ntohs(isock->inet_dport);

	if(sport == 80 || sport == 8080) { // HTTP server OR test TCP server doing
		printk(KERN_INFO "ACK Received. sourcep: %u dstp: %u proto%u send window: %u recv window: %u ssthresh: %u slow-start: %u should_resume: %u\n",
				sport, dport, sk->sk_protocol, tp->snd_cwnd, tp->rcv_wnd, tp->snd_ssthresh, tp->snd_cwnd < tp->snd_ssthresh, ca->should_resume);
		printk(KERN_INFO "Delivered %u byte to ack %u", tp->delivered, tp->snd_una);

		if (tp->delivered)
		{
			if (tp->delivered >= ca->cwnd_restart_flight_mark)
			{
				printk(KERN_INFO "Flight mark acknowledged");
				ca->cwnd_restart_flight_mark = TCP_INFINITE_SSTHRESH;
				ca->aacc_state = AACC_CWND_JUMP_CONFIRMATION;
			}

			if (tp->delivered >= ca->cwnd_jump_mark)
			{
				printk(KERN_INFO "CWND Jump Acknowledged");
				ca->cwnd_jump_mark = TCP_INFINITE_SSTHRESH;
				ca->aacc_state = AACC_CWND_GROWTH_SUSPENSION;
			}
		}
		
	}
}


static inline void tcp_aacc_reset(struct vrenotcp *ca)
{
		ca->saved_reset_cnt = 0;
		ca->max_cwnd = 0;
		ca->prev_rtt = 0;
		ca->AACC_CWND_GROWTH_SUSPENSION_rounds = 0;
		ca->cwnd_jump_mark = TCP_INFINITE_SSTHRESH;
		ca->cwnd_restart_flight_mark = TCP_INFINITE_SSTHRESH;
}


void tcp_aacc_init(struct sock *sk) 
{

	struct vrenotcp *ca = inet_csk_ca(sk);
	ca->should_resume = 0;
	ca->cwnd_suspension_start_time = 0;

	ca->aacc_state = AACC_NORMAL;
	printk(KERN_INFO "AACC connection initiated.");

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

	// CA_EVENT_COMPLETE_CWR is emitted when the lost packet (3 dup acks for example) is ACK'd and CC can continue to normal  
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

		ca->aacc_state = AACC_RESTARTING_AFTER_IDLE;
		
		ca->prev_rtt = tp->srtt_us;
		ca->should_resume = 1;
	}

}


void tcp_trace_state(struct sock* sk, u8 new_state)
{

	// It might be beneficial to disallow use of max_cwnd if it cwnd was reset during recovery, i.e., _after_ a loss but before reaching the prior_cwnd
	switch(new_state)
	{
		case TCP_CA_Open:
			printk(KERN_INFO "Trace event: All normal (Recovery completed)");
			break;
		case TCP_CA_CWR:
			printk(KERN_INFO "Trace event: Entering CWR state (ECN mark or qdisc drop)\n");
			break;
		case TCP_CA_Recovery:
			printk(KERN_INFO "Trace event: Loss. Entering fast retransmit state (dup acks)\n");
			// When we lose a packet due to dup acks, we are sending too fast, scale back the max_cwnd by applying CUBIC BETA 717/1024
			struct vrenotcp *ca = inet_csk_ca(sk);
			u32 old_window = ca->max_cwnd;
			ca->max_cwnd = ca->max_cwnd * 717/1024;
			printk(KERN_INFO "Dup ACK loss. Reducing cwnd from %u to %u", old_window, ca->max_cwnd);

			// If we lose a packet while validating the jump then the selected jump was too high!
			// Forget the current max cwnd value
			if (ca->aacc_state == AACC_CWND_GROWTH_SUSPENSION) 
			{
				printk(KERN_INFO "Repeated loss detected.");
				ca->max_cwnd = TCP_INIT_CWND;
			}

			if (ca->aacc_state == AACC_RESTARTING_AFTER_IDLE)
			{
				//TODO:
			}

			if (ca->aacc_state == AACC_CWND_JUMP_CONFIRMATION)
			{
				// We have lost a packet before acknowledging the cwnd jump. The jump may have been too aggressive, enter SR immediately
				printk(KERN_INFO "Dup ack loss occurred before jump window could be confirmed, entering SR...");
			}

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

static inline u32 tcp_snd_cwnd(const struct tcp_sock *tp)
{
	return tp->snd_cwnd;
}

/* Slow start is used when congestion window is no greater than the slow start
 * threshold. We base on RFC2581 and also handle stretch ACKs properly.
 * We do not implement RFC3465 Appropriate Byte Counting (ABC) per se but
 * something better;) a packet is only considered (s)acked in its entirety to
 * defend the ACK attacks described in the RFC. Slow start processes a stretch
 * ACK of degree N as if N acks of degree 1 are received back to back except
 * ABC caps N to 2. Slow start exits when cwnd grows over ssthresh and
 * returns the leftover acks to adjust cwnd in congestion avoidance mode.
 */
u32 tcp_slow_start(struct tcp_sock *tp, u32 acked)
{
	printk(KERN_INFO "Slow Start CCA");
	u32 cwnd = min(tcp_snd_cwnd(tp) + acked, tp->snd_ssthresh);

	acked -= cwnd - tcp_snd_cwnd(tp);
	tcp_snd_cwnd_set(tp, min(cwnd, tp->snd_cwnd_clamp));

	return acked;
}


/* In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w),
 * for every packet that was ACKed.
 */
void tcp_cong_avoid_ai(struct tcp_sock *tp, u32 w, u32 acked)
{
	printk(KERN_INFO "cong avoid called");

	/* If credits accumulated at a higher w, apply them gently now. */
	if (tp->snd_cwnd_cnt >= w) {
		tp->snd_cwnd_cnt = 0;
		tcp_snd_cwnd_set(tp, tcp_snd_cwnd(tp) + 1);
	}

	tp->snd_cwnd_cnt += acked;
	if (tp->snd_cwnd_cnt >= w) {
		u32 delta = tp->snd_cwnd_cnt / w;

		tp->snd_cwnd_cnt -= delta * w;
		tcp_snd_cwnd_set(tp, tcp_snd_cwnd(tp) + delta);
	}
	tcp_snd_cwnd_set(tp, min(tcp_snd_cwnd(tp), tp->snd_cwnd_clamp));
}

/*
 * TCP Reno congestion control
 * This is special case used for fallback as well.
 */
/* This is Jacobson's slow start and congestion avoidance.
 * SIGCOMM '88, p. 328.
 */
void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	printk(KERN_INFO "Reno CCA");
	struct tcp_sock *tp = tcp_sk(sk);
	
	// Prevent Reno CCA from modifying cwnd if we are in the cwnd growth suspension phase
	struct vrenotcp *ca = inet_csk_ca(sk);
	if (ca->cwnd_suspension_start_time && ca->AACC_CWND_GROWTH_SUSPENSION_rounds)
	{
		u32 time_now = tcp_jiffies32;
		u32 smoothed_rtt_us = tp->srtt_us >> 3;

		u32 time_since_reset_jiffies = time_now - ca->cwnd_suspension_start_time;
		 
		u32 time_since_reset_us = (time_since_reset_jiffies*1000000) / HZ;

		u32 cwnd_growth_cooldown = smoothed_rtt_us * ca->AACC_CWND_GROWTH_SUSPENSION_rounds;
		u32 reset_rtts = cwnd_growth_cooldown / ((tp->srtt_us >> 3) / 1000);
		printk(KERN_INFO "Time since reset us %u. cwnd growth cooldown %u, RTTs %u (%u/%u)", time_since_reset_us, cwnd_growth_cooldown, reset_rtts, time_since_reset_us / 1000, reset_rtts);

		if (time_since_reset_us < cwnd_growth_cooldown)
		{
			return;
		}

		ca->aacc_state = AACC_NORMAL;
		printk(KERN_INFO "Entering Reno CCA");
	}


	if (!tcp_is_cwnd_limited(sk))
		return;

	/* In "safe" area, increase. */
	if (tcp_in_slow_start(tp)) {
		printk(KERN_INFO "Calling SS");
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}
	/* In dangerous area, increase slowly. */
	tcp_cong_avoid_ai(tp, tcp_snd_cwnd(tp), acked);
}


unsigned int pick_cwnd_jump_value(int max_cwnd) {
	int selected_value = 0;
	int i=0;
	for (i=0; i< sizeof(application_hints) / sizeof(application_hints[0]); i++)
	{
		if (application_hints[i] < max_cwnd)
		{
			selected_value = application_hints[i];
		}
	}

	return selected_value;
}

/*
 * TCP Reno congestion control
 * This is special case used for fallback as well.
 */
/* This is Jacobson's slow start and congestion avoidance.
 * SIGCOMM '88, p. 328.
 */
void tcp_aacc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	printk(KERN_INFO "AACC CA CALLED");
	struct vrenotcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (ca->cwnd_suspension_start_time) 
	{
		u32 time_since_reset = tcp_jiffies32 - ca->cwnd_suspension_start_time;
		printk(KERN_INFO "Time of reset %u Time since reset %u. Time (ms) %u", ca->cwnd_suspension_start_time, time_since_reset, (time_since_reset*1000) / HZ);
		printk(KERN_INFO "Prev RTT %u Prev RTT (ms) %u", (tp->srtt_us >> 3), (tp->srtt_us*1000) / HZ);
	}

	if (ca->prev_rtt)
	{
		unsigned int selected_cwnd = pick_cwnd_jump_value(ca->max_cwnd);
		printk(KERN_INFO "Restarting after idle, saved RTT us %u MAX_CWND %u, selected value: %u", ca->prev_rtt, ca->max_cwnd, selected_cwnd);
		ca->prev_rtt = 0;
		ca->max_cwnd = 0;
		ca->pre_jump_window = tp->snd_cwnd;
		// Set the restart flight and cwnd jump marks
		ca->cwnd_restart_flight_mark = tp->delivered + tp->snd_cwnd - 1;
		ca->cwnd_jump_mark = tp->delivered + tp->snd_cwnd + selected_cwnd - 1;

		// We are pesimistically adding one to the suspension rounds as the computation below returns the whole part of the number
		u8 AACC_CWND_GROWTH_SUSPENSION_rounds = ilog2(selected_cwnd / tp->snd_cwnd) + 1;
		ca->AACC_CWND_GROWTH_SUSPENSION_rounds = AACC_CWND_GROWTH_SUSPENSION_rounds;
		ca->cwnd_suspension_start_time = tcp_jiffies32;

		printk(KERN_INFO "Setting cwnd to %u. Waiting for %u RTTs before increasing cwnd. Setting reset time to %u", selected_cwnd, AACC_CWND_GROWTH_SUSPENSION_rounds, 
			ca->cwnd_suspension_start_time);
		
		// Set the congestion window based on the selected cwnd value
		tcp_snd_cwnd_set(tp, selected_cwnd);
		ca->aacc_state = AACC_CWND_GROWTH_SUSPENSION;
	}

	// Let Reno handle cwnd calculation
	tcp_reno_cong_avoid(sk, ack, acked);

	// Only store max_cwnd value when we are not in in SS
	if (tp->snd_cwnd > tp->snd_ssthresh && ca->max_cwnd < tp->snd_cwnd)
	{
		ca->max_cwnd = tp->snd_cwnd;
	}

}


// Called when we enter fast retransmit:
// returns: value that cwnd is reduced to after loss
u32 tcp_reno_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct vrenotcp *ca = inet_csk_ca(sk);

	u32 reno_reduced_cwnd = tcp_snd_cwnd(tp) >> 1U;
	u32 cubic_reduced_cwnd = 0;

	if (ca->aacc_state = AACC_CWND_GROWTH_SUSPENSION)
	{
		//We found loss after agressively reshaping the cwnd, i.e.:
		// 1. After a cwnd jump
		// 2. After loss detection and using beta (B) > 0.7 (cwnd = cwnd*b)
		ca->aacc_state = AACC_SAFE_RETREAT;
//TODO:
// Implement CR
	}

	u32 desired_cwnd = pick_cwnd_jump_value(tp->snd_cwnd);

	printk(KERN_INFO "Recalculating ssthresh after loss. AACC desired cwnd %u. Reno reduction %u. Cubic Reduction %u.", desired_cwnd, reno_reduced_cwnd, cubic_reduced_cwnd);

	if (desired_cwnd < reno_reduced_cwnd)
	{
		printk(KERN_INFO "Normal cwnd reduction");
		// We do not need to worry, standard CCA will not cause bit-rate oscillation
		return max(tcp_snd_cwnd(tp) >> 1U, 2U);
	} else if (desired_cwnd > reno_reduced_cwnd && desired_cwnd < cubic_reduced_cwnd)
	{
		// The cwnd that we want is between reno and cubic cwnd decrease, we may be more liberal with future losses
	} else {
		// We are aiming to use a very high B (cwnd = cwnd * B), B < 1, so we need to be careful if further losses occur
		printk(KERN_INFO "Low AACC cwnd reduction after loss, dangerous territory.");
		u8 cwnd_suspension_rounds = desired_cwnd - reno_reduced_cwnd; // we increase by 1 MTU every RTT, so we need to wait desired_cwnd - reno_reduced_cwnd rounds, before we can start increasing again
		ca->AACC_CWND_GROWTH_SUSPENSION_rounds = cwnd_suspension_rounds;
		ca->aacc_state = AACC_CWND_GROWTH_SUSPENSION;

		return desired_cwnd;
	}

	// Default, should never really get here
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
