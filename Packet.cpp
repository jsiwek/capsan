#include "Packet.hpp"

#include <cstring>

using namespace std;
using namespace capsan;

Packet::Packet(const pcap_pkthdr* pkt_header, const u_char* pkt_data)
	: header(*pkt_header), data(0)
	{
	data = new u_char[header.caplen];
	memcpy(data, pkt_data, header.caplen);
	}
