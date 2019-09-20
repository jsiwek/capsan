#include "IPv4Anonymizer.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>
#include <openssl/err.h>

using namespace std;
using namespace capsan;

static inline uint32_t bitmask32(uint8_t num_lsb)
	{
	return (((uint64_t) 1) << num_lsb) - 1;
	}

static inline uint32_t choose_bit(uint8_t i, uint32_t bits)
	{
	// Selecting a different bit position each iteration introduces
	// better randomness in resulting anonymized addresses: the input
	// to the PRF is not guaranteed to change between iterations, so
	// always selecting the same bit position causes anonymized addr
	// to share bits w/ original too frequently.
	return (((uint32_t) 0x80000000) >> i) & bits;
	//return (bits & 0x80000000) >> i;
	}

static inline void encrypt(EVP_CIPHER_CTX* ctx, uint8_t* out, const uint8_t* in)
	{
	int outl;

	if ( EVP_EncryptUpdate(ctx, out, &outl, in, 16) )
		return;

	char buf[120];
	ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
	fprintf(stderr, "Failed to encrypt: %s\n", buf);
	exit(1);
	}

uint32_t IPv4Anonymizer::ChooseFlips(uint32_t addr, bool reverse)
	{
	uint32_t zero = 0;
	uint32_t& rval = reverse ? addr : zero;
	uint8_t in[16];
	uint8_t out[16];
	uint32_t pad_first_32;
	memcpy(&pad_first_32, pad, sizeof(pad_first_32));
	memcpy(in, pad, sizeof(in));

	for ( uint8_t i = 0; i < 32; ++i )
		{
		uint32_t mask = bitmask32(32 - i);
		uint32_t in_first_32 = htonl((~mask & addr) | (mask & pad_first_32));
		memcpy(in, &in_first_32, sizeof(in_first_32));
		encrypt(ctx, out, in);
		uint32_t out_first_32;
		memcpy(&out_first_32, out, sizeof(out_first_32));
		uint32_t bit = choose_bit(i, ntohl(out_first_32));

		if ( reverse )
			rval ^= bit;
		else
			rval |= bit;
		}

	if ( reverse )
		return rval;
	else
		return addr ^ rval;
	}

IPv4Anonymizer::IPv4Anonymizer(const uint8_t key[32], bool save_mapping)
	{
	ctx = EVP_CIPHER_CTX_new();

	if ( ! EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), 0, key, 0) )
		{
		char buf[120];
		ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
		fprintf(stderr, "Failed to initialize encryption: %s\n", buf);
		exit(1);
		}

	encrypt(ctx, pad, key + 16);
	have_mappings = save_mapping;
	}

IPv4Anonymizer::~IPv4Anonymizer()
	{
	EVP_CIPHER_CTX_free(ctx);
	}

uint32_t IPv4Anonymizer::Anonymize(uint32_t addr)
	{
	addr = ntohl(addr);
	// Probably faster to lookup if have mappings; keeping code simple for now.
	uint32_t rval = ChooseFlips(addr, false);

	if ( have_mappings )
		mappings[rval] = addr;

	return htonl(rval);
	}

uint32_t IPv4Anonymizer::DeAnonymize(uint32_t addr)
	{
	return htonl(ChooseFlips(ntohl(addr), true));
	}

void IPv4Anonymizer::WriteMappings(const char* filename) const
	{
	FILE* f = fopen(filename, "w");

	if ( ! f )
		{
		char buf[128];
		strerror_r(errno, buf, sizeof(buf));
		fprintf(stderr, "Failed to open %s: %s\n", filename, buf);
		exit(1);
		}

	for ( std::map<uint32_t, uint32_t>::const_iterator it = mappings.begin();
	      it != mappings.end(); ++it )
		{
		uint32_t anon_n = htonl(it->first);
		uint32_t orig_n = htonl(it->second);
		char anon[INET_ADDRSTRLEN];
		char orig[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &anon_n, anon, sizeof(anon));
		inet_ntop(AF_INET, &orig_n, orig, sizeof(orig));
		fprintf(f, "%s: %s\n", anon, orig);
		}

	fclose(f);
	}
