#include "LinkLayerSanitizer.hpp"

#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>

using namespace std;
using namespace capsan;

int sanitize_dlt_null(const Packet& pkt)
	{
	if ( pkt.header.caplen < 4 )
		return -1;

	// The field is written in host-order, guessing it's little-endian...
	uint32_t p = (pkt.data[3] << 24) + (pkt.data[2] << 16) +
	             (pkt.data[1] <<  8) +  pkt.data[0];

	if ( p != AF_INET
		// The value of AF_INET6 may be platform dependent so also accept other
		// values in case the pcap comes from another system w/ those values.
	    /* && p != AF_INET6 && p != 24 && p != 28 && p != 30 */ )
		return -2;

	return 4;
	}

int sanitize_dlt_raw(const Packet& pkt)
	{
	return 0;
	}

int sanitize_dlt_linux_sll(const Packet& pkt)
	{
	if ( pkt.header.caplen < 16 )
		return -1;

	uint16_t p = ntohs(*reinterpret_cast<uint16_t*>(pkt.data + 14));

	if ( p != 0x0800 /* && p != 0x86dd */ )
		// Not IP.
		return -2;

	// Zero out link-layer address-length and address.
	memset(pkt.data + 4, 0, 10);
	return 16;
	}

int sanitize_dlt_en10mb(const Packet& pkt)
	{
	if ( pkt.header.caplen < 14 )
		return -1;

	uint16_t p = ntohs(*reinterpret_cast<uint16_t*>(pkt.data + 12));

	int rval = 14;

	if ( p == 0x8100 )
		{
		// Frame has Q-tag.
		if ( pkt.header.caplen < 18 )
			return -1;

		p = ntohs(*reinterpret_cast<uint16_t*>(pkt.data + 16));
		rval = 18;
		}

	if ( p != 0x0800 /* && p != 0x86dd */ )
		// Not IP.
		return -2;

	// Zero out MACs.
	memset(pkt.data, 0, 12);
	return rval;
	}

LinkLayerSanitizer::LinkLayerSanitizer(int arg_link_type)
	: link_type(arg_link_type), sanitizer(0)
	{
	switch ( link_type ) {
	case DLT_NULL:
		sanitizer = sanitize_dlt_null;
		break;

	case DLT_EN10MB:
		sanitizer = sanitize_dlt_en10mb;
		break;

	case DLT_RAW:
		sanitizer = sanitize_dlt_raw;
		break;

	case DLT_LINUX_SLL:
		sanitizer = sanitize_dlt_linux_sll;
		break;

	default:
		break;
	}
	}
