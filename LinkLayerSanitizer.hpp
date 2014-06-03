#ifndef LINKLAYERSANITIZER_HPP
#define LINKLAYERSANITIZER_HPP

#include "Packet.hpp"

namespace capsan {

class LinkLayerSanitizer {
public:

	/**
	 * @param link_type a link-layer type returned by pcap_datalink.
	 */
	LinkLayerSanitizer(int link_type);

	int LinkType() const
		{ return link_type; }

	/**
	 * @return true if the link type can be handled.
	 */
	bool Valid() const
		{ return sanitizer != 0; }

	/**
	 * Parse and optionally sanitize a link-layer header.
	 * @param pkt packet data read by libpcap.
	 * @return number of bytes in the link-layer header, or a negative
	 * value if it can't be determined (e.g. caplen too small), or if the
	 * network-layer payload is not IPv4.  Specifically, -1 is returned
	 * for caplen problems and -2 for non-IPv4 payloads.
	 */
	int Sanitize(const capsan::Packet& pkt) const
		{ return (*sanitizer)(pkt); }

private:

	typedef int (*sanitize_func)(const capsan::Packet& pkt);

	int link_type;
	sanitize_func sanitizer;
};

} // namespace capsan

#endif // LINKLAYERSANITIZER_HPP
