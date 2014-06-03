#ifndef PORTANONYMIZER_HPP
#define PORTANONYMIZER_HPP

#include <stdint.h>

namespace capsan {

class PortAnonymizer {
public:

	/**
	 * Initializes the port anonymizer.  The random permutation of the port
	 * space is fixed for the anonymizer object's lifetime.
	 * @param seed a seed for the RNG.
	 */
	PortAnonymizer(unsigned seed);

	/**
	 * @param port a 16-bit transport-layer port in network order.
	 * @return the anonymized version of the port in network order.
	 */
	uint16_t Anonymize(uint16_t port) const;

	/**
	 * @param port a 16-bit anonymize transport-layer port in network order.
	 * @return the original port in network order.
	 */
	uint16_t DeAnonymize(uint16_t port) const;

	/**
	 * @param filename Write anonymized port -> original port mappings in file.
	 */
	void WriteMappings(const char* filename) const;

private:

	static const int NUM_PORTS = 65535;

	uint16_t port_map[NUM_PORTS];
	uint16_t reverse_map[NUM_PORTS];
};

} // namespace capsan

#endif // PORTANONYMIZER_HPP
