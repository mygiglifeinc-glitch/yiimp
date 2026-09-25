// Hash regression test for the stratum hash libraries (algos/ and sha3/).
//
//   make hashtest && ./hashtest            # print one line per algo
//   ./hashtest > new.txt; diff old.txt new.txt
//
// Checks sha256d against the bitcoin genesis block hash and prints the hash
// of a fixed header for every algo of the stratum, so that the output of two
// builds (compiler, flags, library changes...) can be compared.

#include "stratum.h"

// same wrappers as in stratum.cpp
static void scrypt_hash(const char* input, char* output, uint32_t len)
{
	scrypt_1024_1_1_256((unsigned char *)input, (unsigned char *)output);
}

static void scryptn_hash(const char* input, char* output, uint32_t len)
{
	scrypt_N_R_1_256(input, output, 2048, 1, len);
}

static void neoscrypt_hash(const char* input, char* output, uint32_t len)
{
	neoscrypt((unsigned char *)input, (unsigned char *)output, 0x80000620);
}

struct test_algo {
	const char *name;
	YAAMP_HASH_FUNCTION hash;
};

static const struct test_algo algos[] = {
	{ "a5a", a5a_hash },
	{ "aergo", aergo_hash },
	{ "allium", allium_hash },
	{ "argon2d-crds", argon2d_crds_hash },
	{ "argon2d-dyn", argon2d_dyn_hash },
	{ "argon2d-uis", argon2d_uis_hash },
	{ "argon2m", argon2m_hash },
	{ "astralhash", astralhash_hash },
	{ "balloon", balloon_hash },
	{ "bastion", bastion_hash },
	{ "bcd", bcd_hash },
	{ "bitcore", timetravel10_hash },
	{ "blake", blake_hash },
	{ "blake2b", blake2b_hash },
	{ "blake2s", blake2s_hash },
	{ "blakecoin", blakecoin_hash },
	{ "bmw", bmw_hash },
	{ "bmw512", bmw512_hash },
	{ "c11", c11_hash },
	{ "decred", decred_hash },
	{ "dedal", dedal_hash },
	{ "deep", deep_hash },
	{ "dmd-gr", groestl_hash },
	{ "exosis", exosis_hash },
	{ "fresh", fresh_hash },
	{ "geek", geek_hash },
	{ "groestl", groestl_hash },
	{ "hex", hex_hash },
	{ "hmq1725", hmq17_hash },
	{ "hsr", hsr_hash },
	{ "jeonghash", jeonghash_hash },
	{ "jha", jha_hash },
	{ "keccak", keccak256_hash },
	{ "keccakc", keccak256_hash },
	{ "lbk3", lbk3_hash },
	{ "lbry", lbry_hash },
	{ "luffa", luffa_hash },
	{ "lyra2", lyra2re_hash },
	{ "lyra2v2", lyra2v2_hash },
	{ "lyra2v3", lyra2v3_hash },
	{ "lyra2vc0ban", lyra2vc0ban_hash },
	{ "lyra2z330", lyra2z330_hash },
	{ "lyra2z", lyra2z_hash },
	{ "lyra2zz", lyra2zz_hash },
	{ "m7m", m7m_hash },
	{ "minotaur", minotaur_hash },
	{ "myr-gr", groestlmyriad_hash },
	{ "neoscrypt", neoscrypt_hash },
	{ "nist5", nist5_hash },
	{ "pawelhash", pawelhash_hash },
	{ "penta", penta_hash },
	{ "phi", phi_hash },
	{ "phi2", phi2_hash },
	{ "phi1612", phi1612_hash },
	{ "pipe", pipe_hash },
	{ "polytimos", polytimos_hash },
	{ "quark", quark_hash },
	{ "qubit", qubit_hash },
	{ "rainforest", rainforest_hash },
	{ "scrypt", scrypt_hash },
	{ "scryptn", scryptn_hash },
	{ "sha256", sha256_double_hash },
	{ "sha256q", sha256q_hash },
	{ "sha256t", sha256t_hash },
	{ "sib", sib_hash },
	{ "skein", skein_hash },
	{ "skein2", skein2_hash },
	{ "skunk", skunk_hash },
	{ "sonoa", sonoa_hash },
	{ "timetravel", timetravel_hash },
	{ "tribus", tribus_hash },
	{ "vanilla", blakecoin_hash },
	{ "veltor", veltor_hash },
	{ "velvet", velvet_hash },
	{ "vitalium", vitalium_hash },
	{ "whirlcoin", whirlpool_hash },
	{ "whirlpool", whirlpool_hash },
	{ "whirlpoolx", whirlpoolx_hash },
	{ "x11", x11_hash },
	{ "x11evo", x11evo_hash },
	{ "x12", x12_hash },
	{ "x13", x13_hash },
	{ "x14", x14_hash },
	{ "x15", x15_hash },
	{ "x16r", x16r_hash },
	{ "x16rv2", x16rv2_hash },
	{ "x16rt", x16rt_hash },
	{ "x16s", x16s_hash },
	{ "x17", x17_hash },
	{ "x17r", x17r_hash },
	{ "x18", x18_hash },
	{ "x20r", x20r_hash },
	{ "x21s", x21s_hash },
	{ "x22i", x22i_hash },
	{ "x25x", x25x_hash },
	{ "xevan", xevan_hash },
	{ "yespower", yespower_hash },
	{ "yespowerurx", yespowerurx_hash },
	{ "zr5", zr5_hash },
	{ NULL, NULL }
};

// bitcoin genesis block header (80 bytes)
static const char genesis_hex[] =
	"01000000"
	"0000000000000000000000000000000000000000000000000000000000000000"
	"3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
	"29ab5f49" "ffff001d" "1dac2b7c";
static const char genesis_hash[] = // displayed (big endian) hash
	"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

static void to_hex_be(const unsigned char *bin, int len, char *hex)
{
	for (int i = 0; i < len; i++)
		sprintf(hex + 2*i, "%02x", bin[len - 1 - i]);
}

static void to_hex(const unsigned char *bin, int len, char *hex)
{
	for (int i = 0; i < len; i++)
		sprintf(hex + 2*i, "%02x", bin[i]);
}

int main(int argc, char **argv)
{
	unsigned char input[256];
	unsigned char output[256];
	char hex[513];
	int errors = 0;

	memset(input, 0, sizeof(input));
	for (int i = 0; i < 80; i++) {
		unsigned int v;
		sscanf(genesis_hex + 2*i, "%02x", &v);
		input[i] = (unsigned char) v;
	}

	memset(output, 0, sizeof(output));
	sha256_double_hash((const char *) input, (char *) output, 80);
	to_hex_be(output, 32, hex);
	if (strcmp(hex, genesis_hash)) {
		printf("FAIL sha256d genesis: %s\n", hex);
		errors++;
	} else {
		printf("OK   sha256d genesis\n");
	}

	// extend the header with a pattern for the algos using longer headers
	for (int i = 80; i < (int) sizeof(input); i++)
		input[i] = (unsigned char) (i * 7);

	for (int a = 0; algos[a].name; a++) {
		const char *name = algos[a].name;
		if (argc > 1 && strcmp(argv[1], name)) continue;
		uint32_t len = 80;
		if (!strcmp(name, "decred")) len = 180;
		else if (!strcmp(name, "lbry")) len = 112;

		memset(output, 0, sizeof(output));
		algos[a].hash((const char *) input, (char *) output, len);
		to_hex(output, 32, hex);
		printf("%-14s %s\n", name, hex);
	}

	return errors ? 1 : 0;
}
