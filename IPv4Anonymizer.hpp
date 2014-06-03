#ifndef IPV4ANONYMIZER_HPP
#define IPV4ANONYMIZER_HPP

#include <cstdint>
#include <map>
#include <openssl/evp.h>

namespace capsan {

class IPv4Anonymizer {
public:

	/**
	 * Initialize a one-to-one, prefix-preserving, cryptographic-based
	 * IPv4 address anonymizer.
	 * @param key a 256-bit secret key that can be used to make the
	 * anonymization consistent across runs: the same IP and key as input
	 * always produces the same anonymized IP as output.
	 * @param save_mapping whether to keep a mapping of anonymized to original
	 * addresses (e.g. to later output to a file).  Note that reversing
	 * anonymized addresses doesn't require this if you still have the same
	 * key that was used to produce the anonymized addresses.
	 */
	IPv4Anonymizer(const uint8_t key[32], bool save_mapping = false);

	~IPv4Anonymizer();

	/**
	 * Anonymize an IPv4 address.
	 * @param addr An IPv4 address in network order.
	 * @return An anonymized version of \a addr.
	 */
	uint32_t Anonymize(uint32_t addr);

	/**
	 * Get the original IPv4 address from an anonymized version that was
	 * produced the same key as this anonymizer.
	 * @param addr An anonymized IPv4 address in network order.
	 * @return The original address.
	 */
	uint32_t DeAnonymize(uint32_t addr);

	/**
	 * @param filename Write anonymized IP -> original IP mappings to this file.
	 */
	void WriteMappings(const char* filename) const;

private:

	/**
	 * Algorithm for anonymizing IPv4 addresses in a prefix-preserving manner.
	 * @param addr An IPv4 address in host order.
	 * @param reverse Whether \a addr is an original address to anonymize,
	 * or an anonymized address to revert to its original form.
	 * @return when not reversing, the anonymized version of \a addr in host
	 * order, else the original version of \a addr in host order.
	 */
	uint32_t ChooseFlips(uint32_t addr, bool reverse);

	uint8_t pad[16];
	EVP_CIPHER_CTX ctx;
	bool have_mappings;
	std::map<uint32_t, uint32_t> mappings; // anon -> orig (host order)
};

} // namespace capsan

#endif // IPV4ANONYMIZER_HPP
