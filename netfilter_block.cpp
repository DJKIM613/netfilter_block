#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <libnet.h>
#include <stdlib.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

char *block_adr;
const char *http_method[6] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i % 16 == 0)
			printf("\n");
		printf("%02x ", buf[i]);
	}
}


/* returns packet id */
static void netfilter (struct nfq_data *tb, bool *is_drop, u_int32_t *id)
{
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) *id = ntohl(ph->packet_id);
    else{
        *is_drop = true;
        return;
    }

    int len = nfq_get_payload(tb, &data);
	
    libnet_ipv4_hdr *ipv4_hdr = (libnet_ipv4_hdr *)data;

    if(ipv4_hdr->ip_p == 0x06){
        libnet_tcp_hdr *tcp_hdr = (libnet_tcp_hdr *)(ipv4_hdr + 1);
        char *tcp_data = (char *)tcp_hdr + (tcp_hdr->th_off) * 4;
        int is_method = 0;
        
        for(int i= 0 ; i < 6 ; i++) if(strncmp(tcp_data, http_method[i], strlen(http_method[i])) == 0) is_method = 1;
        
        if(is_method){
            char *start_pos = strstr(tcp_data, "Host: ");   start_pos += strlen("Host: ");
            char *end_pos = strstr(start_pos, "\x0d\x0a");
            if(end_pos - start_pos == strlen(block_adr) && strncmp(start_pos, block_adr, strlen(block_adr)) == 0){
                *is_drop = true; return;
            }
        }
    }


    *is_drop = false;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id;   bool is_drop;   
    netfilter(nfa, &is_drop, &id);
	if(is_drop) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void usage(){
    printf("netfilter_block <host>\n");
    exit(0);
}
int main(int argc, char **argv)
{
    if(argc != 2) usage();

    block_adr = argv[1];
    printf("%s\n", block_adr);
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
