#include "PortAnonymizer.hpp"

#include <errno.h>
#include <cstdio>
#include <cstdlib>
#include <cinttypes>
#include <algorithm>
#include <arpa/inet.h>

using namespace std;
using namespace capsan;

static const int RANDOM_MAX = 2147483647;

/**
 * @return an int in range [0, upper], inclusive.
 */
static long random_int(long upper)
	{
	long r;
	++upper;
	long last_valid_random_val = RANDOM_MAX - (RANDOM_MAX % upper) - 1;
	// Remove modulo bias.
	do { r = random(); } while ( r > last_valid_random_val );
	return r % upper;
	}

PortAnonymizer::PortAnonymizer(unsigned seed)
	{
	char state[256];
	const char* prev_state = initstate(seed, state, sizeof(state));

	for ( uint16_t i = 0; i < NUM_PORTS; ++i )
		port_map[i] = i;

	// Sattolo's shuffling algorithm.
	for ( uint16_t i = NUM_PORTS - 1; i > 0; --i )
		swap(port_map[i], port_map[random_int(i - 1)]);

	for ( uint16_t i = 0; i < NUM_PORTS; ++i )
		reverse_map[port_map[i]] = i;

	setstate(prev_state);
	}

uint16_t PortAnonymizer::Anonymize(uint16_t port) const
	{
	return htons(port_map[ntohs(port)]);
	}

uint16_t PortAnonymizer::DeAnonymize(uint16_t port) const
	{
	return htons(reverse_map[ntohs(port)]);
	}

void PortAnonymizer::WriteMappings(const char* filename) const
	{
	FILE* f = fopen(filename, "w");

	if ( ! f )
		{
		char buf[128];
		strerror_r(errno, buf, sizeof(buf));
		fprintf(stderr, "Failed to open %s: %s\n", filename, buf);
		exit(1);
		}

	for ( uint16_t i = 0; i < NUM_PORTS; ++i )
		fprintf(f, "%"PRIu16": %"PRIu16"\n", i, reverse_map[i]);

	fclose(f);
	}
