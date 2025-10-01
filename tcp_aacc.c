// Day 1
// Need to further research how reno sets ssthresh during reset. 
//It could be that AACC is stagnating growth for _too long_

// Day 2
// Provide shadow cwnd implementation for cwnd growth suspension. Compare time spent using mathematical model to shadow cwnd.

// changes:
// Bugfixes
// Safe Retreat PIPE ack is 0.7'd instead of 0.5'd

// What happens in the case where:
// 1. We attempted a jump
// 2. The jump failed
// 3. We recovered in SR
// 4. The "SR exit ssthresh" is **lower** than the ssthresh that we had from __before__ the reset? 

/*
	1. Get Rates for transfer from application (hardcode)
	2. Calculate "useful" window upon reset
	3. Perform jump to useful_window / 2?
*/
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

// TODO Implement:
// [x] 1. Connection Start
// [] 2. Normal CC
// 3. Restart After Idle
// 4. CW Jump Confirmation
// 5. CWND Growth Suspension
// 6. Loss Monitoring
// 7. SR

	// +++++++++++++++++++++
	// FUNCTION: tcp_reno_ssthresh
	// -------Called when we enter fast retransmit:
	// returns: value that cwnd is reduced to after loss
	// -------Comments:
	// Presumption is that after calling this function TCP Reno attempts to bring the cwnd to match the ssthresh
	// It _may_ trigger a transition of the TCP state machine to TCP_LOSS, we _may_ need to overwrite this if we enter cwnd growth suspension...
	// +++++++++++++++++++++

	// +++++++++++++++++++++
	// FUNCTION: vreno_set_state
	// ---------- The TCP State machine updates cwnd in this function.
	// This function is called after an ACK is received.
	// When a loss occurs tcp_reno_ssthresh is called.
	// tcp_reno_ssthresh applies beta to cwnd and sets that as the ssthresh
	// .cong_avoid	= tcp_aacc_cong_avoid,
	// +++++++++++++++++++++

	// +++++++++++++++++++++
	// FUNCTION: tcp_aacc_cwnd_event
	// 	Notification of congestion-related events:
	// CA_EVENT_TX_START, ****CA_EVENT_CWND_RESTART****, CA_EVENT_COMPLETE_CWR, etc.
	// (f.e., CA_EVENT_CWND_RESTART)
	// +++++++++++++++++++++

	// +++++++++++++++++++++
	// FUNCTION: tcp_reno_undo_cwnd
	// Called if TCP thinks a loss recovery was spurious (e.g., false retransmission).
	// Purpose: allows restoring cwnd to a prior value.
	// ------> Comments: We may need special handling for that one depending on the TCP Phase/State 
	// +++++++++++++++++++++

	// +++++++++++++++++++++
	// FUNCTION: tcp_aacc_in_ack_event
	// Called when ACKs are received, even duplicate ones.
	// Purpose: handle ACK-based events that don’t advance sequence space.
	// +++++++++++++++++++++

	// +++++++++++++++++++++
	// FUNCTION: tcp_aacc_pkts_acked
	// Called with ACK timing info for each batch of packets acked.
	// Purpose: update RTT/throughput estimators, react to ACK pacing.
	// ---------> Comments: We use it to build the PipeSize
	// +++++++++++++++++++++

	// +++++++++++++++++++++
	// FUNCTION: tcp_trace_state
	// 	Called when TCP’s internal state machine changes (TCP_CA_Open, TCP_CA_CWR, …).
	// Purpose: handle transitions like open → recovery.
	// +++++++++++++++++++++

static ktime_t module_load_time;
const static char *AACC_STATE_LOOKUP[] = {
	"AACC_NORMAL",
	"AACC_RESTARTING_AFTER_IDLE",
	"AACC_CWND_JUMP_CONFIRMATION",
	"AACC_LOSS_MONITORING",
	"AACC_CWND_GROWTH_SUSPENSION",
	"AACC_SAFE_RETREAT",
};

static int initial_ssthresh __read_mostly;
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");

#define HINTS_NO 3
static int application_hints[HINTS_NO] = {50, 125, 200};


static inline void tcp_snd_cwnd_set(struct tcp_sock *tp, u32 val)
{
	pr_debug("My set %u", val);
	pr_debug("cwnd %u, packets out %u, retrans out %u, cwnd used %u, cwnd usage seq %u", 
		tp->snd_cwnd, tp->packets_out, tp->retrans_out, tp->snd_cwnd_used, tp->max_packets_seq);

	WARN_ON_ONCE((int)val <= 0);
	tp->snd_cwnd = val;
}


enum AACC_state {
	AACC_NORMAL=0,
	AACC_RESTARTING_AFTER_IDLE,
	AACC_CWND_JUMP_CONFIRMATION,
	AACC_LOSS_MONITORING,
	AACC_CWND_GROWTH_SUSPENSION,
	AACC_SAFE_RETREAT,
	
};

struct vrenotcp {
	u32 saved_reset_cnt;
	u32 max_cwnd;
	u32 prev_max_cwnd;
	u32 prev_rtt;
	u32 cwnd_jump_mark;
	u32 cwnd_restart_flight_mark;
	u32 pre_jump_window;
	u32 pipe_ack;
	// There already is a variable prior_cwnd in struct tcp_sock (tp->prior_cwnd), we may use that instead?	
	u32 cwnd_red; // cwnd that is set after a loss is discovered (in tcp_reno_ssthresh)
	u8 should_resume;
	u8 AACC_CWND_GROWTH_SUSPENSION_rounds;
	u32 cwnd_suspension_start_time;
	enum AACC_state aacc_state;
};


static inline void enter_aacc_state(struct vrenotcp *ca, enum AACC_state state)
{
	pr_debug("Entering AACC state %s", AACC_STATE_LOOKUP[state]);
	ca->aacc_state = state;
}

static inline void tcp_aacc_reset(struct vrenotcp *ca)
{
		ca->saved_reset_cnt = 0;
		ca->max_cwnd = 0;
		ca->prev_max_cwnd = 0;
		ca->prev_rtt = 0;
		ca->AACC_CWND_GROWTH_SUSPENSION_rounds = 0;
		ca->cwnd_jump_mark = TCP_INFINITE_SSTHRESH;
		ca->cwnd_restart_flight_mark = TCP_INFINITE_SSTHRESH;
		ca->pipe_ack = 0;
}


// Init Function
void tcp_aacc_init(struct sock *sk) 
{

	struct vrenotcp *ca = inet_csk_ca(sk);
	ca->should_resume = 0;
	ca->cwnd_suspension_start_time = 0;

	enter_aacc_state(ca, AACC_NORMAL);

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

	tcp_aacc_reset(ca);
}


void tcp_aacc_pkts_acked(struct sock *sk, const struct ack_sample *sample)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *isock = inet_sk(sk);
	struct vrenotcp *ca = inet_csk_ca(sk);

	uint16_t sport = ntohs(isock->inet_sport);
	uint16_t dport = ntohs(isock->inet_dport);

	if(sport == 80 || sport == 8080) { // HTTP server OR test TCP server doing
	
		pr_debug("Num packet(s) ACK'd: %u", sample->pkts_acked);

		if (tp->delivered)
		{

			if(ca->aacc_state == AACC_CWND_JUMP_CONFIRMATION)
			{
				ca->pipe_ack += sample->pkts_acked;
				pr_debug("Increasing PIPE ACK to %u", ca->pipe_ack);
			}

			if (tp->delivered >= ca->cwnd_restart_flight_mark)
			{
				pr_debug("Flight mark acknowledged");

				// TODO: We need to verify the restart_srtt here!!!

				ca->cwnd_restart_flight_mark = TCP_INFINITE_SSTHRESH;
				ca->pipe_ack = tp->snd_cwnd;
				enter_aacc_state(ca, AACC_CWND_JUMP_CONFIRMATION);

				// Should we set the cwnd here or in cong_avoid?
				// Picking cong avoid for now
			}

			if (tp->delivered >= ca->cwnd_jump_mark)
			{
				pr_debug("CWND Jump Acknowledged");
				ca->cwnd_jump_mark = TCP_INFINITE_SSTHRESH;
				enter_aacc_state(ca, AACC_CWND_GROWTH_SUSPENSION);
			}
		}
	}
}


// ACK Received
void tcp_aacc_in_ack_event(struct sock *sk, u32 flags)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *isock = inet_sk(sk);
	struct vrenotcp *ca = inet_csk_ca(sk);

	uint16_t sport = ntohs(isock->inet_sport);
	uint16_t dport = ntohs(isock->inet_dport);

	if(sport == 80 || sport == 8080) { // HTTP server OR test TCP server doing
		pr_debug("ACK Received. sourcep: %u dstp: %u proto%u send window: %u recv window: %u ssthresh: %u slow-start: %u should_resume: %u in flight: %u retrans out: %u",
				sport, dport, sk->sk_protocol, tp->snd_cwnd, tp->rcv_wnd, tp->snd_ssthresh, tp->snd_cwnd < tp->snd_ssthresh, ca->should_resume, (tp->packets_out - tcp_left_out(tp) + tp->retrans_out), tp->retrans_out);
		pr_debug("Delivered %u byte to ack %u", tp->delivered, tp->snd_una);
	}
}


// CWND Event (CW Reset)
void tcp_aacc_cwnd_event(struct sock *sk, enum tcp_ca_event ev)
{

	pr_debug("Congestion window event occurred: %u", ev);

	// CA_EVENT_COMPLETE_CWR is emitted when the lost packet (3 dup acks for example) is ACK'd and CC can continue to normal  
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

		enter_aacc_state(ca, AACC_RESTARTING_AFTER_IDLE);
		// TODO: Does TCP Input modify ssthresh?
		
		// Set the max cwnd observed during this period to prev_max_cwnd
		ca->prev_max_cwnd = ca->max_cwnd;
		ca->max_cwnd = 0;

		ca->prev_rtt = tp->srtt_us;
		ca->should_resume = 1;
		ca->pipe_ack = 0;
	}

}


// Loss Detection (initial)
void tcp_trace_state(struct sock* sk, u8 new_state)
{

	// It might be beneficial to disallow use of max_cwnd if it cwnd was reset during recovery, i.e., _after_ a loss but before reaching the prior_cwnd
	switch(new_state)
	{
		case TCP_CA_Open:
			pr_debug("Trace event: All normal (Recovery completed)");
			break;
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
 * ABC caps N to 2.
 *  
 * !!!!Slow start exits when cwnd grows over ssthresh and
 * returns the leftover acks to adjust cwnd in congestion avoidance mode.
 */
u32 tcp_slow_start(struct tcp_sock *tp, u32 acked)
{
	pr_debug("Slow Start CCA");
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
	pr_debug("cong avoid called");

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
	pr_debug("Reno CCA");
	struct tcp_sock *tp = tcp_sk(sk);
	
	if (!tcp_is_cwnd_limited(sk))
		return;

	/* In "safe" area, increase. */
	if (tcp_in_slow_start(tp)) {
		pr_debug("Calling SS");
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


// The TCP State machine updates cwnd in this function.
// This function is called after an ACK is received.
// When a loss occurs tcp_reno_ssthresh is called.
// tcp_reno_ssthresh applies beta to cwnd and sets that as the ssthresh


/*
 * TCP Reno congestion control
 * This is special case used for fallback as well.
 */
/* This is Jacobson's slow start and congestion avoidance.
 * SIGCOMM '88, p. 328.
 */
void tcp_aacc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	pr_debug("AACC CA CALLED");
	struct vrenotcp *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	unsigned int selected_cwnd = pick_cwnd_jump_value(ca->prev_max_cwnd);

	pr_debug("Selected cwnd: %u", selected_cwnd);
	// if (ca->aacc_state == AACC_CWND_GROWTH_SUSPENSION)
	// {
	// 	// TODO: Update the shadow cwnd
	// 	// if shadow cwnd >= cwnd => transition to NORMAL CC State 
	// 	return;
	// }

	if (ca->cwnd_suspension_start_time) 
	{
		u32 time_since_reset = tcp_jiffies32 - ca->cwnd_suspension_start_time;
		pr_debug("Time of reset %u Time since reset %u. Time (ms) %u", ca->cwnd_suspension_start_time, time_since_reset, (time_since_reset*1000) / HZ);
		pr_debug("Prev RTT %u Prev RTT (ms) %u", (tp->srtt_us >> 3), (tp->srtt_us*1000) / HZ);
	}

	
	if (ca->aacc_state == AACC_RESTARTING_AFTER_IDLE && ca->prev_rtt)
	{
		pr_debug("Restarting after idle, saved RTT us %u MAX_CWND %u, selected value: %u", ca->prev_rtt, ca->prev_max_cwnd, selected_cwnd);
		// TODO: What should we do with the (prev) max rtt? 
		ca->prev_rtt = 0;

		if (selected_cwnd < tp->snd_ssthresh)
		{
			// AACC Note:
			// If ssthresh is bigger than the selected cwnd, technically, we could perform a jump to selected cwnd immediately, then allow the 
			// slow-start to further grow the cwnd.
			// We probably should not do this/will not gain much if ssthresh will be reached in "few" rounds.
			// TODO: Compute "few"
			// This is because after a jump we need to validate and stagnate the cwnd growth, performing complex calculations, wheras the 
			// slow start algorithm might be _good enough_ in this case.
			// For now we are rolling with letting slow-start take place and we do not enable any jump optimisation.  
			pr_debug("ssthresh (%u) is bigger than selected cwnd (%u). Letting normal CC play out for this transfer...", tp->snd_ssthresh, selected_cwnd);
			enter_aacc_state(ca, AACC_NORMAL);
		} else {
			ca->pre_jump_window = tp->snd_cwnd;
			// Set the restart flight and cwnd jump marks
			ca->cwnd_restart_flight_mark = tp->delivered + tp->snd_cwnd - 1;
			ca->cwnd_jump_mark = tp->delivered + tp->snd_cwnd + selected_cwnd - 1;
		}


	}

	if (ca->aacc_state == AACC_CWND_JUMP_CONFIRMATION)
	{
		if (tp->snd_cwnd < selected_cwnd)
		{
			// We have transitioned to cwnd jump confirmation, but we have not yet made the jump. 
			// Perform the jump now and exit cong_avoid.

			// We are pesimistically adding one to the suspension rounds as the computation below returns the whole part of the number
			u8 AACC_CWND_GROWTH_SUSPENSION_rounds = ilog2(selected_cwnd / tp->snd_cwnd) + 1;
			ca->AACC_CWND_GROWTH_SUSPENSION_rounds = AACC_CWND_GROWTH_SUSPENSION_rounds;
			ca->cwnd_suspension_start_time = tcp_jiffies32;

			pr_debug("Setting cwnd to %u. Waiting for %u RTTs before increasing cwnd. Setting reset time to %u", selected_cwnd, AACC_CWND_GROWTH_SUSPENSION_rounds, 
				ca->cwnd_suspension_start_time);
			
			// Set the congestion window based on the selected cwnd value
			// tcp_snd_cwnd_set(tp, selected_cwnd);

			pr_debug("Cwnd jumping to %u", selected_cwnd);
			tcp_snd_cwnd_set(tp, selected_cwnd);
			return;
		} else {
			// We have set the cwnd = jump window and are waiting to ack it. DO NOT INCREASE CWND HERE
			return;
		}
		
	}

	// Prevent CCA from modifying cwnd if we are in the cwnd growth suspension phase
	if (ca->aacc_state == AACC_CWND_GROWTH_SUSPENSION && ca->cwnd_suspension_start_time && ca->AACC_CWND_GROWTH_SUSPENSION_rounds)
	{
		u32 time_now = tcp_jiffies32;
		u32 smoothed_rtt_us = tp->srtt_us >> 3;

		u32 time_since_reset_jiffies = time_now - ca->cwnd_suspension_start_time;
		 
		u32 time_since_reset_us = (time_since_reset_jiffies*1000000) / HZ;

		u32 cwnd_growth_cooldown = smoothed_rtt_us * ca->AACC_CWND_GROWTH_SUSPENSION_rounds;
		u32 reset_rtts = cwnd_growth_cooldown / ((tp->srtt_us >> 3) / 1000);
		pr_debug("Time since reset us %u. cwnd growth cooldown %u, RTTs %u (%u/%u)", 
			time_since_reset_us, cwnd_growth_cooldown, reset_rtts, time_since_reset_us / 1000, reset_rtts);

		if (time_since_reset_us < cwnd_growth_cooldown)
		{
			return;
		}

		enter_aacc_state(ca, AACC_NORMAL);
		pr_debug("Entering Reno CCA");
	}


	// Let Reno handle cwnd calculation
	tcp_reno_cong_avoid(sk, ack, acked);

	// Only store max_cwnd value when we are not in in SS
	if (tp->snd_cwnd > tp->snd_ssthresh && ca->max_cwnd < tp->snd_cwnd)
	{
		pr_debug("Setting max cwnd to %u", tp->snd_cwnd);
		ca->max_cwnd = tp->snd_cwnd;
	}

}


// Called when we enter fast retransmit:
// returns: value that cwnd is reduced to after loss

// Comments:
// Presumption is that after calling this function TCP Reno attempts to bring the cwnd to match the ssthresh
// It _may_ trigger a transition of the TCP state machine to TCP_LOSS, we _may_ need to overwrite this if we enter cwnd growth suspension...
u32 tcp_aacc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct vrenotcp *ca = inet_csk_ca(sk);

	pr_debug("Recalculating ssthresh rst count %u state %d state=normal? %u aacc ssthresh check %u", 
		ca->saved_reset_cnt, ca->aacc_state, ca->aacc_state == AACC_NORMAL, ca->aacc_state == AACC_NORMAL && ca->saved_reset_cnt);
	// 
	// Taken From Trace State
	// 

	if ((ca->aacc_state == AACC_RESTARTING_AFTER_IDLE || ca->aacc_state == AACC_NORMAL) && ca->saved_reset_cnt)
	{
		// When we lose a packet due to dup acks, we are sending too fast, scale back the max_cwnd by applying CUBIC BETA 717/1024
		u32 old_window = ca->max_cwnd;
		ca->max_cwnd = ca->max_cwnd * 717/1024;
		pr_debug("Dup ACK loss. Reducing cwnd from %u to %u", old_window, ca->max_cwnd);

		u32 cwnd_red_reno = tcp_snd_cwnd(tp) >> 1U;
		u32 cwnd_red_cubic = tcp_snd_cwnd(tp) * 717/1024;

		//FIXME: Should this not be the **current** desired_cwnd, 
		// i.e., the cwnd may have grown too high and may be attempting to support an even higher transmission
		u32 desired_cwnd = pick_cwnd_jump_value(tp->snd_cwnd);

		if (cwnd_red_reno < desired_cwnd)
		{
			//TODO: We need to enter cwnd growth suspension until cwnd converges
			enter_aacc_state(ca, AACC_CWND_GROWTH_SUSPENSION);
			//TODO IMPL
			//Is it done for NORMAL CC?
			// we increase by 1 MTU every RTT, so we need to wait desired_cwnd - reno_reduced_cwnd rounds, before we can start increasing again
			u8 cwnd_suspension_rounds = desired_cwnd - cwnd_red_reno; 
			ca->AACC_CWND_GROWTH_SUSPENSION_rounds = cwnd_suspension_rounds;
			pr_debug("Should be reducing ssthresh to %u", desired_cwnd);

			//TODO: FIXME This should be NON Reno SSTRESH
			return max(tcp_snd_cwnd(tp) >> 1U, 2U);
		}
		else {
			// we have accumulated such a large CWND in CA, that we can let TCP Reno reduce it and still manage to deliver the required quality
			pr_debug("Exiting with Reno ssthresh");
			return max(cwnd_red_reno, 2U);
		}
	}

	if (ca->aacc_state == AACC_CWND_GROWTH_SUSPENSION || ca->aacc_state == AACC_CWND_JUMP_CONFIRMATION)
	{
		pr_debug("Loss during Growth Suspension or CWND jump confirmation. Entering SR");
		ca->cwnd_jump_mark = TCP_INFINITE_SSTHRESH;
		enter_aacc_state(ca, AACC_SAFE_RETREAT);
		// We could experiment by reducing the cwnd to 0.7 * pipe_ack instead of 0.5 * pipe_ack
		u32 cubic_pipe_ack = ca->pipe_ack * 717 / 1024;

		return max(cubic_pipe_ack, 2U);
	}
	

// 	// If we lose a packet while validating the jump then the selected jump was too high!
// 	// Forget the current max cwnd value
// 	if (ca->aacc_state == AACC_CWND_GROWTH_SUSPENSION) 
// 	{
// 		pr_debug("Repeated loss detected.");
// 		ca->max_cwnd = TCP_INIT_CWND;
// 	}

// 	if (ca->aacc_state == AACC_RESTARTING_AFTER_IDLE)
// 	{
// 		//TODO:
// 	}

// 	if (ca->aacc_state == AACC_CWND_JUMP_CONFIRMATION)
// 	{
// 		// We have lost a packet before acknowledging the cwnd jump. The jump may have been too aggressive, enter SR immediately
// 		pr_debug("Dup ack loss occurred before jump window could be confirmed, entering SR... Jump window %u Pipe ACK %u", tp->snd_cwnd, ca->pipe_ack); // the current cwnd _should_ be the jump window in this case
// 	}

// 	//
// 	// End Taken From Trace State
// 	//

// 	u32 reno_reduced_cwnd = tcp_snd_cwnd(tp) >> 1U;
// 	u32 cubic_reduced_cwnd = 0;

// 	if (ca->aacc_state = AACC_CWND_GROWTH_SUSPENSION)
// 	{
// 		//We found loss after agressively reshaping the cwnd, i.e.:
// 		// 1. After a cwnd jump
// 		// 2. After loss detection and using beta (B) > 0.7 (cwnd = cwnd*b)
// 		ca->aacc_state = AACC_SAFE_RETREAT;
// //TODO:
// // Implement SR
// 	}

// 	u32 desired_cwnd = pick_cwnd_jump_value(tp->snd_cwnd);

// 	pr_debug("Recalculating ssthresh after loss. AACC desired cwnd %u. Reno reduction %u. Cubic Reduction %u.", desired_cwnd, reno_reduced_cwnd, cubic_reduced_cwnd);

// 	// We can Force SR if we remove this if statement **AND** supply desired cwnd > link capacity
// 	if (ca->should_resume)
// 	{
// 		// Only enable AACC calculations _after_ the first cwnd reset. Leave TCP Reno handle loss before that.
// 		if (desired_cwnd < reno_reduced_cwnd)
// 		{
// 			pr_debug("Normal cwnd reduction");
// 			// We do not need to worry, standard CCA will not cause bit-rate oscillation
// 			return max(tcp_snd_cwnd(tp) >> 1U, 2U);
// 		} else if (desired_cwnd > reno_reduced_cwnd && desired_cwnd < cubic_reduced_cwnd)
// 		{
// 			// The cwnd that we want is between reno and cubic cwnd decrease, we may be more liberal with future losses
// 		} else {
// 			// We are aiming to use a very high B (cwnd = cwnd * B), B < 1, so we need to be careful if further losses occur
// 			pr_debug("Low AACC cwnd reduction after loss, dangerous territory.");
// 			u8 cwnd_suspension_rounds = desired_cwnd - reno_reduced_cwnd; // we increase by 1 MTU every RTT, so we need to wait desired_cwnd - reno_reduced_cwnd rounds, before we can start increasing again
// 			ca->AACC_CWND_GROWTH_SUSPENSION_rounds = cwnd_suspension_rounds;
// 			ca->aacc_state = AACC_CWND_GROWTH_SUSPENSION;

// 			return desired_cwnd;
// 		}
// 	}

	pr_debug("No CWND Invalidations occured, defaulting to underlying CCA");
	return max(tcp_snd_cwnd(tp) >> 1U, 2U);
}


u32 tcp_reno_undo_cwnd(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return max(tcp_snd_cwnd(tp), tp->prior_cwnd);
}


// void aacc_cong_control(struct sock *sk, const struct rate_sample *rs)
// {
// 	pr_debug("Cong control called. Packets (S)ACKED: %u", rs->acked_sacked);
// }


struct tcp_congestion_ops tcp_reno_verbose = {
	.init		= tcp_aacc_init,
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "aacc",
	.owner		= THIS_MODULE,

	// -------Called when we enter fast retransmit:
	// returns: value that cwnd is reduced to after loss
	// -------Comments:
	// Presumption is that after calling this function TCP Reno attempts to bring the cwnd to match the ssthresh
	// It _may_ trigger a transition of the TCP state machine to TCP_LOSS, we _may_ need to overwrite this if we enter cwnd growth suspension...
	.ssthresh	= tcp_aacc_ssthresh,

	// ---------- The TCP State machine UPDATES CWND in this function.
	// This function is called after an ACK is received.
	// When a loss occurs tcp_reno_ssthresh is called.
	// tcp_reno_ssthresh applies beta to cwnd and sets that as the ssthresh
	.cong_avoid	= tcp_aacc_cong_avoid,
	// .cong_avoid = tcp_reno_cong_avoid,

	// 	Notification of congestion-related events:
	// CA_EVENT_TX_START, ****CA_EVENT_CWND_RESTART****, CA_EVENT_COMPLETE_CWR, etc.
	// (f.e., CA_EVENT_CWND_RESTART)
	.cwnd_event = tcp_aacc_cwnd_event,

	// Called if TCP thinks a loss recovery was spurious (e.g., false retransmission).
	// Purpose: allows restoring cwnd to a prior value.
	// ------> Comments: We may need special handling for that one depending on the TCP Phase/State 
	.undo_cwnd	= tcp_reno_undo_cwnd,

	// Called when ACKs are received, even duplicate ones.
	// Purpose: handle ACK-based events that don’t advance sequence space.
	.in_ack_event = tcp_aacc_in_ack_event,

	// Called with ACK timing info for each batch of packets acked.
	// Purpose: update RTT/throughput estimators, react to ACK pacing.
	// ---------> Comments: We use it to build the PipeSize
	.pkts_acked = tcp_aacc_pkts_acked,

	// DO NOT USE THE FOLLOWING FUNCTION!!!! IT overwrites cong_avoid! Both cannot exist at the same time.
	// .cong_control = aacc_cong_control,


	// 	Called when TCP’s internal state machine changes (TCP_CA_Open, TCP_CA_CWR, …).
	// Purpose: handle transitions like open → recovery.
	.set_state	= tcp_trace_state,
};


static int __init tcp_aacc_register(void)
{
	pr_debug("TCP AACC Going Up");
	module_load_time = ktime_get();
	return tcp_register_congestion_control(&tcp_reno_verbose);
}


static void __exit tcp_aacc_unregister(void)
{
	pr_debug("TCP AACC Going Down");
	tcp_unregister_congestion_control(&tcp_reno_verbose);
}



module_init(tcp_aacc_register);
module_exit(tcp_aacc_unregister);

MODULE_AUTHOR("Yanev");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AA Reno");
