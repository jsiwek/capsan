#include <getopt.h>
#include <cstdio>
#include <cstdlib>
#include <inttypes.h>
#include <string>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>

#ifdef __linux__
#define __FAVOR_BSD
#endif // __linux__

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <pcap/pcap.h>

#include "Packet.hpp"
#include "LinkLayerSanitizer.hpp"
#include "IPv4Anonymizer.hpp"
#include "PortAnonymizer.hpp"

using namespace std;
using namespace capsan;

static void usage(const string& program)
	{
	fprintf(stderr, "%s -r <input> -w <output> [options]\n", program.c_str());
	fprintf(stderr, "    -h|--help        | display usage info\n");
	fprintf(stderr, "    -r|--read-pcap   | input pcap file to read\n");
	fprintf(stderr, "    -w|--write-pcap  | output pcap file to write\n");
	fprintf(stderr, "    -k|--key-file    | key file to read (or create)\n");
	fprintf(stderr, "    -a|--addr-map    | file to write anonymization map\n");
	fprintf(stderr, "    -p|--port-map    | file to write anonymization map\n");
	fprintf(stderr, "    -n|--anon-addr   | anonymize an IP\n");
	fprintf(stderr, "    -t|--anon-port   | anonymize a port\n");
	fprintf(stderr, "    -v|--reverse     | deanonymize for -n or -t\n");
	fprintf(stderr, "    -x|--no-addrs    | don't anonymize IPs\n");
	fprintf(stderr, "    -z|--no-ports    | don't anonymize ports\n");
	}

static option long_options[] = {
	{"read-pcap",          required_argument,       0, 'r'},
	{"write-pcap",         required_argument,       0, 'w'},
	{"key-file",           required_argument,       0, 'k'},
	{"addr-map",           required_argument,       0, 'a'},
	{"port-map",           required_argument,       0, 'p'},
	{"anon-addr",          required_argument,       0, 'n'},
	{"anon-port",          required_argument,       0, 't'},
	{"reverse",            no_argument,             0, 'v'},
	{"no-addrs",           no_argument,             0, 'x'},
	{"no-ports",           no_argument,             0, 'z'},
	{"help",               no_argument,             0, 'h'},
	{0,                    0,                       0,   0},
};

static const char* opt_string = "r:w:k:a:p:n:t:vxzh";

// - adapted from tcpdump
// Returns the ones-complement checksum of a chunk of b short-aligned bytes.
static uint32_t ones_complement_checksum(const void* p, int b, uint32_t sum)
	{
	const u_short* sp = reinterpret_cast<const u_short*>(p);// better be aligned

	b /= 2; // convert to count of short's

	/* No need for endian conversions. */
	while ( --b >= 0 )
		sum += *sp++;

	while ( sum > 0xffff )
		sum = (sum & 0xffff) + (sum >> 16);

	return sum;
	}

static uint32_t ones_complement_checksum(const ip* ipv4, const udphdr* udp,
                                         int udp_len)
	{
	uint32_t sum;

	if ( udp_len % 2 == 1 )
		// Add in pad byte.
		sum = htons(reinterpret_cast<const u_char*>(udp)[udp_len - 1] << 8);
	else
		sum = 0;

	sum = ones_complement_checksum(&ipv4->ip_src, 4, sum);
	sum = ones_complement_checksum(&ipv4->ip_dst, 4, sum);
	sum += htons(IPPROTO_UDP);
	sum += htons(static_cast<u_short>(udp_len));
	sum = ones_complement_checksum(udp, udp_len, sum);
	return sum;
	}

static uint32_t ones_complement_checksum(const ip* ipv4, const tcphdr* tcp,
                                         int tcp_len)
	{
	uint32_t sum;
	int payload_len = tcp_len - (tcp->th_off * 4);
	sum = ones_complement_checksum(&ipv4->ip_src, 4, 0);
	sum = ones_complement_checksum(&ipv4->ip_dst, 4, sum);
	sum += htons(IPPROTO_TCP);

	if ( payload_len % 2 == 1 )
		// Add in pad byte.
		sum += htons(reinterpret_cast<const u_char*>(tcp)[tcp_len - 1] << 8);

	sum += htons(static_cast<u_short>(tcp_len));
	sum = ones_complement_checksum(tcp, tcp_len, sum);
	return sum;
	}

static void fix_checksum(ip* ipv4, int ip_hdr_len, bool force_incorrect)
	{
	ipv4->ip_sum = 0;
	uint32_t new_chksum = ~ ones_complement_checksum(ipv4, ip_hdr_len, 0);
	ipv4->ip_sum = force_incorrect ? new_chksum + 1 : new_chksum;
	}

static void fix_checksum(const ip* ipv4, udphdr* udp, int udp_len,
                         bool force_incorrect)
	{
	udp->uh_sum = 0;
	uint32_t new_chksum = ~ ones_complement_checksum(ipv4, udp, udp_len);
	udp->uh_sum = force_incorrect ? new_chksum + 1 : new_chksum;
	}

static void fix_checksum(const ip* ipv4, tcphdr* tcp, int tcp_len,
                         bool force_incorrect)
	{
	tcp->th_sum = 0;
	uint32_t new_chksum = ~ ones_complement_checksum(ipv4, tcp, tcp_len);
	tcp->th_sum = force_incorrect ? new_chksum + 1 : new_chksum;
	}

static int safe_open(const char* filename, int flags)
	{
	char buf[128];
	int fd;

	if ( flags & O_CREAT )
		fd = open(filename, flags, 0600);
	else
		fd = open(filename, flags);

	if ( fd == -1 )
		{
		strerror_r(errno, buf, sizeof(buf));
		fprintf(stderr, "Failed to open %s: %s\n", filename, buf);
		exit(1);
		}

	return fd;
	}

static void read_key(uint8_t key[34], const char* filename)
	{
	int fd = safe_open(filename, O_RDONLY);
	int numread = 0;

	while ( numread < 34 )
		{
		ssize_t n = read(fd, key + numread, 34 - numread);

		if ( n < 0 )
			{
			char buf[128];
			strerror_r(errno, buf, sizeof(buf));
			fprintf(stderr, "Failed reading %s: %s\n", filename, buf);
			exit(1);
			}

		numread += n;

		if ( n == 0 && numread < 34 )
			{
			fprintf(stderr, "Failure: not enough data in %s for 34 byte key\n",
			        filename);
			exit(1);
			}
		}

	close(fd);
	}

static void write_key(const uint8_t key[34], const char* filename)
	{
	int fd = safe_open(filename, O_WRONLY|O_CREAT);
	int numwritten = 0;

	while ( numwritten < 34 )
		{
		ssize_t n = write(fd, key + numwritten, 34 - numwritten);

		if ( n < 0 )
			{
			char buf[128];
			strerror_r(errno, buf, sizeof(buf));
			fprintf(stderr, "Failed riting %s: %s\n", filename, buf);
			exit(1);
			}

		numwritten += n;
		}

	close(fd);
	}

static bool file_exists(const char* filename)
	{
	return access(filename, F_OK) != -1;
	}

static void init_key(uint8_t key[34], const string& key_file)
	{
	if ( key_file.empty() )
		read_key(key, "/dev/random");
	else
		{
		if ( file_exists(key_file.c_str()) )
			read_key(key, key_file.c_str());
		else
			{
			read_key(key, "/dev/random");
			write_key(key, key_file.c_str());
			}
		}
	}

static void reverse_addr(const string& addr, const uint8_t key[34],
                         bool reverse)
	{
	IPv4Anonymizer l3anon(key);
	uint32_t addr_n;

	if ( inet_pton(AF_INET, addr.c_str(), &addr_n) != 1 )
		{
		fprintf(stderr, "Failed to convert '%s' to IP address.\n",
		        addr.c_str());
		exit(1);
		}

	addr_n = reverse ? l3anon.DeAnonymize(addr_n) : l3anon.Anonymize(addr_n);
	char addrstr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &addr_n, addrstr, sizeof(addrstr));
	printf("%s\n", addrstr);
	}

static void reverse_port(const string& port, const uint8_t key[34],
	                     bool reverse)
	{
	PortAnonymizer l4anon(*reinterpret_cast<const uint16_t*>(key + 32));
	errno = 0;
	uint16_t port_h = strtol(port.c_str(), 0, 10);

	if ( errno )
		{
		fprintf(stderr, "Failed to convert '%s' to port number.\n",
		        port.c_str());
		exit(1);
		}

	if ( reverse )
		printf("%"PRIu16"\n", ntohs(l4anon.DeAnonymize(htons(port_h))));
	else
		printf("%"PRIu16"\n", ntohs(l4anon.Anonymize(htons(port_h))));
	}

int main(int argc, char** argv)
	{
	string input_pcap_name, output_pcap_name, key_file, addr_map_file,
	       port_map_file, addr_to_convert, port_to_convert;
	bool addr_anon = true, port_anon = true, reverse = false;
	pcap_t* input_pcap = 0;
	pcap_dumper_t* output_pcap = 0;

	for ( ; ; )
		{
		int o = getopt_long(argc, argv, opt_string, long_options, 0);

		if ( o == -1 )
			break;

		switch ( o ) {
		case 'r':
			input_pcap_name = optarg;
			break;
		case 'w':
			output_pcap_name = optarg;
			break;
		case 'k':
			key_file = optarg;
			break;
		case 'a':
			addr_map_file = optarg;
			break;
		case 'p':
			port_map_file = optarg;
			break;
		case 'n':
			addr_to_convert = optarg;
			break;
		case 't':
			port_to_convert = optarg;
			break;
		case 'v':
			reverse = true;
			break;
		case 'x':
			addr_anon = false;
			break;
		case 'z':
			port_anon = false;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
		}

	uint8_t key[34];
	init_key(key, key_file);

	if ( ! addr_to_convert.empty() )
		{
		reverse_addr(addr_to_convert, key, reverse);
		return 0;
		}

	if ( ! port_to_convert.empty() )
		{
		reverse_port(port_to_convert, key, reverse);
		return 0;
		}

	if ( ! key_file.empty() &&
	     input_pcap_name.empty() && output_pcap_name.empty() )
			// Just wanted to generate a key.
			return 0;

	if ( input_pcap_name.empty() || output_pcap_name.empty() )
		{
		usage(argv[0]);
		return 1;
		}

	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	input_pcap = pcap_open_offline(input_pcap_name.c_str(), pcap_errbuf);

	if ( ! input_pcap )
		{
		fprintf(stderr, "Failed to open %s: %s\n", input_pcap_name.c_str(),
		        pcap_errbuf);
		return 1;
		}

	LinkLayerSanitizer l2san(pcap_datalink(input_pcap));

	if ( ! l2san.Valid() )
		{
		fprintf(stderr, "Unknown Link-Layer type: %d\n", l2san.LinkType());
		pcap_close(input_pcap);
		return 1;
		}

	output_pcap = pcap_dump_open(input_pcap, output_pcap_name.c_str());

	if ( ! output_pcap )
		{
		fprintf(stderr, "Failed to open %s: %s\n", output_pcap_name.c_str(),
		        pcap_geterr(input_pcap));
		pcap_close(input_pcap);
		return 1;
		}

	IPv4Anonymizer l3anon(key, ! addr_map_file.empty());
	PortAnonymizer l4anon(*reinterpret_cast<uint16_t*>(key + 32));

	pcap_pkthdr* pkt_header = 0;
	const u_char* pkt_data = 0;
	int num_reads = 0;
	int num_writes = 0;
	int num_truncations = 0;
	int num_non_ipv4 = 0;
	int num_non_udptcp = 0;
	int num_fragments = 0;
	int res;

	while ( (res = pcap_next_ex(input_pcap, &pkt_header, &pkt_data)) == 1 )
		{
		++num_reads;
		Packet p(pkt_header, pkt_data);
		int l2len = l2san.Sanitize(p);

		if ( l2len == -1 )
			{
			// Don't even have link layer header.
			++num_truncations;
			continue;
			}

		if ( l2len == -2 )
			{
			++num_non_ipv4;
			continue;
			}

		int caplen = p.header.caplen - l2len;
		u_char* ip_data = p.data + l2len;

		if ( caplen < static_cast<int>(sizeof(ip)) )
			{
			// Don't have the main IPv4 header.
			++num_truncations;
			continue;
			}

		ip* ipv4_hdr = reinterpret_cast<ip*>(ip_data);

		if ( ipv4_hdr->ip_v != 4 )
			{
			++num_non_ipv4;
			continue;
			}

		if ( ipv4_hdr->ip_p != IPPROTO_TCP && ipv4_hdr->ip_p != IPPROTO_UDP )
			{
			++num_non_udptcp;
			continue;
			}

		int l3len = ipv4_hdr->ip_hl * 4;

		if ( l3len < static_cast<int>(sizeof(ip)) )
			{
			// A bogus IP header length.
			++num_truncations;
			continue;
			}

		if ( caplen < l3len )
			{
			// Don't have the full IPv4 header (including options).
			++num_truncations;
			continue;
			}

		if ( (ntohs(ipv4_hdr->ip_off) & 0x3fff) != 0 )
			{
			++num_fragments;
			continue;
			}

		int l4len = ntohs(ipv4_hdr->ip_len) - l3len;
		caplen -= l3len;
		u_char* l4data = ip_data + l3len;

		if ( caplen < l4len )
			{
			// Don't have the full IP payload (as advertised by IP header).
			++num_truncations;
			continue;
			}

		bool valid_l4_chksum;

		if ( ipv4_hdr->ip_p == IPPROTO_UDP )
			{
			if ( caplen < static_cast<int>(sizeof(udphdr)) )
				{
				// Don't have full UDP header.
				++num_truncations;
				continue;
				}

			udphdr* udp = reinterpret_cast<udphdr*>(l4data);
			valid_l4_chksum = ! udp->uh_sum ||
			        ones_complement_checksum(ipv4_hdr, udp, l4len) == 0xffff;
			}
		else
			{
			if ( caplen < static_cast<int>(sizeof(tcphdr)) )
				{
				// Don't have main TCP header.
				++num_truncations;
				continue;
				}

			tcphdr* tcp = reinterpret_cast<tcphdr*>(l4data);
			int tcp_hdr_len = tcp->th_off * 4;

			if ( tcp_hdr_len < static_cast<int>(sizeof(tcphdr)) )
				{
				// Bogus TCP header length.
				++num_truncations;
				continue;
				}

			if ( caplen < tcp_hdr_len )
				{
				// Don't have full TCP header (including options).
				++num_truncations;
				continue;
				}

			valid_l4_chksum =
			        ones_complement_checksum(ipv4_hdr, tcp, l4len) == 0xffff;
			}

		if ( addr_anon )
			{
			bool valid_ip_chksum =
			        ones_complement_checksum(ipv4_hdr, l3len, 0) == 0xffff;
			ipv4_hdr->ip_src.s_addr = l3anon.Anonymize(ipv4_hdr->ip_src.s_addr);
			ipv4_hdr->ip_dst.s_addr = l3anon.Anonymize(ipv4_hdr->ip_dst.s_addr);
			fix_checksum(ipv4_hdr, l3len, ! valid_ip_chksum);
			}

		if ( port_anon )
			{
			uint16_t* sport = reinterpret_cast<uint16_t*>(l4data);
			uint16_t* dport = reinterpret_cast<uint16_t*>(l4data + 2);
			*sport = l4anon.Anonymize(*sport);
			*dport = l4anon.Anonymize(*dport);

			if ( ipv4_hdr->ip_p == IPPROTO_UDP )
				fix_checksum(ipv4_hdr, reinterpret_cast<udphdr*>(l4data), l4len,
				             ! valid_l4_chksum);
			else
				fix_checksum(ipv4_hdr, reinterpret_cast<tcphdr*>(l4data), l4len,
				             ! valid_l4_chksum);
			}

		++num_writes;
		pcap_dump(reinterpret_cast<u_char*>(output_pcap), &p.header, p.data);
		}

	if ( res == -1 )
		fprintf(stderr, "Failed reading packet: %s\n", pcap_geterr(input_pcap));

	if ( ! addr_map_file.empty() )
		l3anon.WriteMappings(addr_map_file.c_str());

	if ( ! port_map_file.empty() )
		l4anon.WriteMappings(port_map_file.c_str());

	printf("Packets read:                %d\n", num_reads);
	printf("Packets written:             %d\n", num_writes);
	printf("Skipped truncated packets:   %d\n", num_truncations);
	printf("Skipped non-IPv4 packets:    %d\n", num_non_ipv4);
	printf("Skipped non-UDP/TCP packets: %d\n", num_non_udptcp);
	printf("Skipped IP fragments:        %d\n", num_fragments);

	pcap_dump_close(output_pcap);
	pcap_close(input_pcap);
	return res == -1 ? 1 : 0;
	}
