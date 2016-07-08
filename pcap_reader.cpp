

#include "pcap_reader.h"
#include <cassert>

extern srtp_packets_t srtp_stream;
extern long ssrc;

bool is_ip_over_eth(const u_char* packet)
{
	struct ether_header *eptr;  /* net/ethernet.h */

	/* lets start with the ether header... */
	eptr = (struct ether_header *) packet;

	//fprintf(stdout, "ethernet header source: %s", ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
	// fprintf(stdout, " destination: %s ", ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));

	/* check to see if we have an ip packet */
	if (ntohs(eptr->ether_type) == ETHERTYPE_IP)
		return true;
	else
		return false;
}

/* Callback function invoked by libpcap for every incoming packet */
void p_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	/*
	* unused parameter
	*/
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

	/* print timestamp and length of the packet */
	// printf("%s.%.6d len:%d \n", timestr, header->ts.tv_usec, header->len);


	int eth_hdr_size = is_ip_over_eth(pkt_data) ? 14 : 0;

	/* retireve the position of the ip header */
	ih = (ip_header *)(pkt_data + eth_hdr_size); //length of ethernet header

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header *)((u_char*)ih + ip_len);

	/* convert from network byte order to host byte order */
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	/* print ip addresses and udp ports */
/*	printf("%s.%.6d	%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d  length:%d  \n",
		timestr, header->ts.tv_usec,
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		sport,
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4,
		dport,
		header->len
		);
		*/

	if (header->len == 127)
		int fff = 0;

	int const udp_header_size = 8;
	int const turn_header_size = 4;
	int udp_size = ntohs(uh->len);

	char* turn_body = (char*)uh + udp_header_size;
	channel_data_header* turn_hdr = (channel_data_header*)turn_body;

	int rtp_size = 0;
	char* rtp_body = 0;

	if (turn_hdr->channel_number == 0x40)
	{
		rtp_size = udp_size - udp_header_size - turn_header_size;
		rtp_body = (char*)uh + udp_header_size + turn_header_size;
		assert(rtp_size == ntohs(turn_hdr->message_size));
	}
	else
	{
		rtp_size = udp_size - udp_header_size;
		rtp_body = (char*)uh + udp_header_size;
	}

	srtp_hdr_t *hdr = (srtp_hdr_t *)rtp_body;
	bool is_rtp = hdr->version == 2;

	if (is_rtp)
	{
		int debug_ssrc = ntohl(hdr->ssrc);
		if (ssrc == ntohl(hdr->ssrc))
		{
			srtp_packet_t srtp_packet(rtp_body, rtp_body + rtp_size);
			srtp_stream->push_back(srtp_packet);
//			printf("new rtp packet, seq %d\n", ntohl(hdr->seq));
		}
//		else
//			printf("ignore rtp packet, seq %d\n", ntohs(hdr->seq));
	}

	// TO DO RTCP
	// Oy vey iz mir https://tools.ietf.org/html/rfc5761#page-4 

}


bool read_pcap(std::string const& file)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int i = 0;
	struct bpf_program fcode;

	/* Open the capture file */
	if ((fp = pcap_open_offline(file.c_str(),			// name of the device
		errbuf					// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file %s\n", file.c_str());
		return  false;
	}


	char packet_filter[] = "udp";
	u_int netmask;

	netmask = 0xffffff;

	//compile the filter
	if (pcap_compile(fp, &fcode, packet_filter, 1, netmask) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_close(fp);
		return  false;

	}

	//set the filter
	if (pcap_setfilter(fp, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_close(fp);
		return  false;

	}

	pcap_loop(fp, 0, &p_handler, NULL);


	pcap_close(fp);
	return  true;

}
