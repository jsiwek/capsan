#ifndef PACKET_HPP
#define PACKET_HPP

#include <pcap/pcap.h>
#include <cstring>

namespace capsan {

/**
 * Wrapper class around pcap header/data for a given packet.
 */
class Packet {
public:

	Packet(const pcap_pkthdr* pkt_header, const u_char* pkt_data)
		: header(*pkt_header), data(0)
		{
		data = new u_char[header.caplen];
		memcpy(data, pkt_data, header.caplen);
		}

	~Packet()
		{ delete [] data; }

	pcap_pkthdr header;
	u_char* data;
};

} // namespace capsan

#endif // PACKET_HPP
