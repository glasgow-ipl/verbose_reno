#include <linux/module.h>
#include <net/tcp.h>
#include <linux/vmalloc.h>



void tcp_vreno_in_ack_event(struct sock *sk, u32 flags)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *isock = inet_sk(sk);

	uint16_t sport = ntohs(isock->inet_sport);
	uint16_t dport = ntohs(isock->inet_dport);

	if(sport == 80 || dport == 80) { // HTTP server doing 
		printk(KERN_INFO "ACK Received. sourcep: %u dstp: %u proto%u send window: %u recv window %u\n",
				sport, dport, sk->sk_protocol, tp->snd_cwnd, tp->rcv_wnd);
	}
}

void clamp_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	tp->snd_cwnd_clamp=42;
}


struct tcp_congestion_ops tcp_reno_verbose = {
	.init		= clamp_init,
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "reno_verbose",
	.owner		= THIS_MODULE,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.undo_cwnd	= tcp_reno_undo_cwnd,
	.in_ack_event = tcp_vreno_in_ack_event,
};


static int __init tcp_reno_verbose_register(void)
{
    printk(KERN_INFO "Verbose Reno Going Up4");
	return tcp_register_congestion_control(&tcp_reno_verbose);
}


static void __exit tcp_reno_verbose_unregister(void)
{
    printk(KERN_INFO "Verbose Reno Shutting Down4");
    tcp_unregister_congestion_control(&tcp_reno_verbose);
}



module_init(tcp_reno_verbose_register);
module_exit(tcp_reno_verbose_unregister);

MODULE_AUTHOR("Yanev");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Verbose reno");