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
	{ "flex", flex_hash },
	{ "geek", geek_hash },
	{ "ghostrider", ghostrider_hash },
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
	{ "mike", mike_hash },
	{ "minotaur", minotaur_hash },
	{ "minotaurx", minotaurx_hash },
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

// Known answer tests: 80-byte block headers (serialized, hex) and the expected PoW hash
// (displayed, big endian). "chain" vectors are real blocks whose hash was checked against
// the block target (the chain itself only stores the block id).
struct kat_vector {
	const char *name;
	YAAMP_HASH_FUNCTION hash;
	const char *header;
	const char *expected;
	const char *source;
};

static const struct kat_vector kats[] = {
	// Raptoreum mainnet block 1437000 (a4f85d05803cba9bcc17cbc68378b6c41b57b2cb4686dc5aef3ffcb056469668),
	// bits 1d0b1bcb; also checked on blocks 1, 5000, 250000, 800000, 1200000, 1436990
	{ "ghostrider", ghostrider_hash,
	  "00000020ec99747e276395fac51fa2fa06f7db4ba714c5d7de09f1e402b2201af97a81ea3eeee81e058f7ae783aa059eb57d8a633befcfa5202bf1cec2a59da30b8f4d9b2bcfb56acb1b0b1d62000700",
	  "000000049c87fbffb8a48536d82ded5c4d43e28ac85048eb08f137e0093c5a89", "RTM block 1437000" },
	// VKAX mainnet genesis (ef99ea0231cf5ccee64a5350f79d8b17348f9a72cc1899113c4082c9f6aa1987),
	// bits 20001fff, nonce 140 is the first nonce meeting the target
	{ "mike", mike_hash,
	  "0400000000000000000000000000000000000000000000000000000000000000000000003ce42dd41a0ead4764d88555bec2112f297d1319340c09b64a150713be0692c510f3a862ff1f00208c000000",
	  "001e00af492cad6158de291018e6a2674aa393d983cc9a28898e98c48d3e05c1", "VKAX genesis" },
	// Litecoin Cash mainnet block 4522303 (33045efb468ce515dc01b088df8dff36824f485d38cee0cbeeddd3fb0e708243),
	// MinotaurX block (nVersion 0x00010000), bits 1d3370ff
	{ "minotaurx", minotaurx_hash,
	  "00000100b95bc9244cac8ca986ecedc01bb64fe3988067ea44446503a4d3be02b2879e0d21be074001e6db4e298487aeab8bb1438d754a706d29f28fd3c64ed344f1dcba42fab56aff70331d372c55d1",
	  "00000009a63a77b3884a8e28c103efb5d263f7aa8b2de5364fbdd09fc84dfdae", "LCC block 4522303" },
	// no mainnet KCN/LCN header could be fetched: Kylacoin regtest block 115 accepted by
	// kylacoind (Kylacoin Core eeeeb47b), hash identical to Kylacoin Core's flex_hash()
	{ "flex", flex_hash,
	  "00800020b03d9892780e946e6eb5bd3ab9fc1d8177794ddbe8eb9328eb614863769d99d117dbc5be30a15f9df8730e3aa62e07e8f38edf19dc2757c31efac40bd23a3aba9d77b66affff7f20504f0000",
	  "00016053e4873256c467657a2aa4814d98050479b67c9568a4b374bc38035592", "KCN regtest block 115 / Kylacoin Core flex_hash" },
	// flex of the LCC header above, computed with Kylacoin Core's flex_hash()
	{ "flex", flex_hash,
	  "00000100b95bc9244cac8ca986ecedc01bb64fe3988067ea44446503a4d3be02b2879e0d21be074001e6db4e298487aeab8bb1438d754a706d29f28fd3c64ed344f1dcba42fab56aff70331d372c55d1",
	  "3f5f1b703df28379f41fb1e3121a6a3f72faf7869d16bb722e8ba94bed536571", "Kylacoin Core flex_hash" },
	{ NULL, NULL, NULL, NULL, NULL }
};

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

	for (int k = 0; kats[k].name; k++) {
		unsigned char hdr[80];
		if (argc > 1 && strcmp(argv[1], kats[k].name)) continue;
		for (int i = 0; i < 80; i++) {
			unsigned int v;
			sscanf(kats[k].header + 2*i, "%02x", &v);
			hdr[i] = (unsigned char) v;
		}
		memset(output, 0, sizeof(output));
		kats[k].hash((const char *) hdr, (char *) output, 80);
		to_hex_be(output, 32, hex);
		if (strcmp(hex, kats[k].expected)) {
			printf("FAIL %s KAT (%s): %s\n", kats[k].name, kats[k].source, hex);
			errors++;
		} else {
			printf("OK   %s KAT (%s)\n", kats[k].name, kats[k].source);
		}
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
