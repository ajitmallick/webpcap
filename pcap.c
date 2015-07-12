#include "webcap.h"

pkt_handler(u_char *first, struct pcap_pkthdr *hdr, char *pkt) {
	struct ether_header *eth_hdr;
	struct ip *ip_hdr;
	struct tcphdr *tcp_hdr;
	u_char *payload;
	int size_eth = sizeof (struct ether_header);
	if (hdr->caplen < 64) {
		return;
	}
	eth_hdr = (struct ether_header *)(pkt);
	if ( ntohs(eth_hdr->ether_type) != ETHERTYPE_IP ) {
		if (verbose) fprintf (stderr, "Non IP packet!\n");
		return;
	}
	ip_hdr = (struct ip *)(pkt + size_eth);
	if (ntohs(ip_hdr->ip_off) & IP_OFFMASK) {
		if (verbose) fprintf (stderr, "Fragment cant handle!\n");
		return;
	}
	if (ip_hdr->ip_p != 6) {
		if (verbose) fprintf (stderr, "Non TCP packet\n");
		return;
	}
	if (hdr->caplen != (ntohs(ip_hdr->ip_len) +  size_eth)) {
		if (verbose) fprintf (stderr, "Truncated pcaket cant handle!\n");
		return;
	}
	tcp_hdr = (struct tcphdr *)(pkt + size_eth + (4 * ip_hdr->ip_hl));
	payload = (u_char *)(pkt + size_eth + (4 * ip_hdr->ip_hl) + (4 * tcp_hdr->doff));
	int payl_size = (int)ntohs(ip_hdr->ip_len) - ((4 * ip_hdr->ip_hl) + (4 * tcp_hdr->doff));/*data=ip-(iphdr + tcphdr)*/
	int dstport = ntohs(tcp_hdr->dest);
	int srcport = ntohs(tcp_hdr->source);
	in_addr_t srcaddr = ip_hdr->ip_src.s_addr;
	in_addr_t dstaddr = ip_hdr->ip_dst.s_addr;

	
	if (payl_size > 15 ) {
		if (dstport == 80) {
			req(payload, payl_size, srcaddr, dstaddr, srcport, dstport);
		}
		if (srcport == 80) {
			resp(payload, payl_size, dstaddr, srcaddr, dstport, srcport);
		}
	}
return;
}

int capture (void) {
	pcap_t *handle;                        /* Session handle */
	struct bpf_program filter;            /* The compiled filter */
	char filter_app[30] = "port 80 and host ";       /* The filter expression */
	u_char *header;          /* The header that pcap gives us */
	bpf_u_int32 mask;               //device mask
	bpf_u_int32 net;                //device net

	/* Find mask and net for the device */
	if ((pcap_lookupnet(dev, &net, &mask, errbuf)) < 0) {
		if (verbose) fprintf ("Error: %s\n", errbuf);
		return(0);
	}
	if (verbose) fprintf (stderr, "Dev: %s\n Net: %s\n", dev, inet_ntoa(net));
	if (verbose) fprintf (stderr, "Mask: %s\n", inet_ntoa(mask));

	/* Open the session */
	if (!(handle = pcap_open_live(dev, BUFSIZ, promis, 0, errbuf))) {
		if (verbose) fprintf (stderr, "Error: %s\n", errbuf);
		return(0);
	}
	/* Compile and apply the filter */
	if (strcat(filter_app, inet_ntoa(mys))) {
		if (verbose) fprintf (stderr, "Applying filter \"%s\"\n", filter_app);
	}
	if ((pcap_compile(handle, &filter, filter_app, 0, mask)) < 0) {
		if (verbose) fprintf (stderr, "Error: Compiling filter\n");
		return(0);
	}
	if ((pcap_setfilter(handle, &filter)) < 0) {
		if (verbose) fprintf (stderr, "Error: Applying filter\n");
		return(0);
	}
	/* And close the session */
	pcap_loop(handle, COUNT, pkt_handler, header);
	pcap_close(handle);
	return(0);
}
