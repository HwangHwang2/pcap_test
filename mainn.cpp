#include <stdio.h>
#include <pcap.h>

void got_packet(u_char *args, const struct pcap_pkthdr * header, const u_char *packet)
{


}	

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	char dev[] = "rl0";
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "port 23";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;

	
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldnt' find default device: %s\n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);
	
	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
	if (handle == NULL) {
		fprintf(stderr, "Couldn't find default device %s\n", dev, errbuf);
		return(2);
	}

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n",dev);
		return(2);
	}

	
	packet = pcap_next(handle, &header);
	printf("Jacked a packet with length of {%d]\n", header.len);
	pcap_close(handle);
	
	struct pcap_pkthdr {
                struct timeval ts;
                bpf_u_int32 caplen;
                bpf_u_int32 len;
        };

        struct sniff_ethernet {
                u_char ether_dhost[ETHER_ADDR_LEN];
                u_char ether_shost[ETHER_ADDR_LEN];
                u_short ether_type;
        };

        struct sniff_ip{
                u_char ip_vhl;
                u_char ip_tos;
                u_short ip_len;
                u_short ip_id;
                u_short ip_off;
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
                u_char ip_ttl;
                u_char ip_p;
                u_short ip_sum;
                struct in_addr ip_src, ip_dst;
        };
        #define IP_HL(ip)
        #define IP_V(ip)

	typedef u_int tcp_seq;

        struct sniff_tcp {
                u_short th_sport;
                u_short th_dport;
                tcp_seq th_seq;
                tcp_seq th_ack;
                u_char th_offx2;
        #define TH_OFF(th)
                u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_Flags (TH_FIN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
                u_short th_win;
                u_short th_sum;
                u_short th_urp;
        };

        #define SIZE_ETHERNET 14

        const struct sniff_ethernet *ethernet;
        const struct sniff_ip *ip;
        const struct sniff_tcp *tcp;
        const char *payload;

        u_int size_ip;
        u_int size_tcp;

	ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
                printf("        *invalid IP header length: %u bytes\n", size_ip);
                return;
        }
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
                printf("        *invalid TCP header length: %u bytes\n", size_tcp);
                return;
        }
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);






	
	return(0);
}

