// Hash regression test for the stratum hash libraries (algos/ and sha3/).
//
//   make hashtest && ./hashtest            # print one line per algo
//   ./hashtest > new.txt; diff old.txt new.txt
//
// Checks sha256d against the bitcoin genesis block hash, runs the known-answer
// tests (real block headers, see kats[] below) and prints the hash of a fixed
// header for every algo of the stratum, so that the output of two builds
// (compiler, flags, library changes...) can be compared.

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
	{ "cpupower", cpupower_hash },
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
	{ "power2b", power2b_hash },
	{ "quark", quark_hash },
	{ "qubit", qubit_hash },
	{ "rainforest", rainforest_hash },
	{ "scrypt", scrypt_hash },
	{ "scryptn", scryptn_hash },
	{ "sha256", sha256_double_hash },
	{ "sha256q", sha256q_hash },
	{ "sha256t", sha256t_hash },
	{ "sha3-256t", sha3_256t_hash },
	{ "sha512256d", sha512256d_hash },
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
	{ "yescrypt", yescrypt_hash },
	{ "yescryptR8", yescryptR8_hash },
	{ "yescryptR16", yescryptR16_hash },
	{ "yescryptR32", yescryptR32_hash },
	{ "yespower", yespower_hash },
	{ "yespowerADVC", yespowerADVC_hash },
	{ "yespowerARWN", yespowerARWN_hash },
	{ "yespowerIC", yespowerIC_hash },
	{ "yespowerLITB", yespowerLITB_hash },
	{ "yespowerLTNCG", yespowerLTNCG_hash },
	{ "yespowerMGPC", yespowerMGPC_hash },
	{ "yespowerR16", yespowerR16_hash },
	{ "yespowerSUGAR", yespowerSUGAR_hash },
	{ "yespowerTIDE", yespowerTIDE_hash },
	{ "yespowerurx", yespowerurx_hash },
	{ "zr5", zr5_hash },
	{ NULL, NULL }
};

// Known-answer tests: real mainnet block headers (80 bytes, hex as serialized)
// and their proof-of-work hash (displayed, big endian).  "exact" entries are
// checked against a hash published by the coin (genesis assert or block hash);
// the others were checked to be below the block's nBits target, with the
// header verified against the block hash (sha256d) given by an explorer.
struct kat {
	const char *algo;
	const char *header;
	const char *hash;
};

static const struct kat kats[] = {
	{ "cpupower", // CPUchain genesis, exact (= hashGenesisBlock)
	  "0100000000000000000000000000000000000000000000000000000000000000000000009046a0f16062e319198ca56736b404a82c5922ad4aea6e775b897396e75737840036215dffff3f1ec01e0900",
	  "000024d8766043ea0e1c9ad42e7ea4b5fdb459887bd80b8f9756f3d87e128f12" },
	{ "power2b", // MicroBitcoin genesis, exact (= hashGenesisBlockWork)
	  "010000000000000000000000000000000000000000000000000000000000000000000000df88deb6f10587e13df6826ca867cabe31cb44aaddefb64a4ae11730adcc263425d99d5dffff3f1fc5020000",
	  "001cb6047ddf13074c4bce354ed3cf0cdd96a4287aa562b032eb81d03e183da8" },
	{ "sha3-256t", // BitcoinIII block 60000, exact (= block hash)
	  "0010002064a6ffc22ad8c07e6573beb8ffa90aefeab3a6f5d41dd91de30f0000000000000a97cb61fd5e5f3f056860c8134f6d749e45130f951b341811e14515e965a57a32679d6a804d6a1a837c0169",
	  "0000000000002b7101d9a41dc0c72284ce35860c2b8cd68a0f17f4a0ceed9914" },
	{ "sha512256d", // Radiant genesis, exact (= hashGenesisBlock)
	  "010000000000000000000000000000000000000000000000000000000000000000000000372cbaf89794aeed5e711b02e78ec4502ad8b315a987c2e2758a85e36a3f7c02aadeaf62ffff001d7980b72a",
	  "0000000065d8ed5d8be28d6876b3ffb660ac2a6c0ca59e437e1f7a6f4e003fb4" },
	{ "yescrypt", // GlobalBoost-Y block 600000, meets its target
	  "00000020d471ca3a815bc4c93fd22838a6b8bbaf30730b02aa35885be676f22bc5b3f93a800033859ee149e0daf13454ac6bcb76a062b0555af85584fb10e71207119b3a1152a76aba9c041d82c40020",
	  "000000028924f1138ff2a805c125ff1ab2dcb6894e7dff6b5f20432ff00757bf" },
	{ "yescryptR8", // BitZeny genesis, exact (= hashGenesisBlock)
	  "010000000000000000000000000000000000000000000000000000000000000000000000d2a4db3bce9f2044558211b401dc45c72806a9ffc7f8a3df9c3a58b491e526a6930e5d54ffff3f1ec2a40500",
	  "000009f7e55e9e3b4781e22bd87a7cfa4acada9e4340d43ca738bf4e9fb8f5ce" },
	{ "yescryptR16", // Yenten genesis (yescryptR16 era), exact (= hashGenesisBlock)
	  "0100000000000000000000000000000000000000000000000000000000000000000000002a67f93c1e533f3d383eda5c359496f703ee33f735732adeed2ca121724e8792687dd359ffff3f1e68930200",
	  "00001828d845205a951f9609e011775e035b00c7fb476310261ef30460cdccab" },
	{ "yescryptR32", // WAVI genesis, exact (= hashGenesisBlock)
	  "01000000000000000000000000000000000000000000000000000000000000000000000017b0c168c5d279adc600d25eaebe5e25f501645d6b2b5edcd93b82dbdbd495a9943ea55af0ff0f1e0c110c00",
	  "00000d39b78c04cc35653abe2442a106a428c5e92ba41ec4967a80a09abf4725" },
	{ "yescryptR32", // LuckyPepe block 290000, meets its target
	  "00000020004a5f73359c8d62d8c8f64e4aeeaf242be57b029a75d0d56bc3d2a663265002ce921cbd4e32210f5f628052eb339075cfe202652c6b6557eb63ab8cdd619165e14cb36a65b6021e23060000",
	  "0000027b8296a4bfa44dcbd7f7911097d3e72d6cf382559d063d3b8fdefb071a" },
	{ "yespowerADVC", // AdventureCoin genesis, meets its target
	  "010000000000000000000000000000000000000000000000000000000000000000000000e43c2fd91767a1efc419c56634e42228737b90a834d644fb511911e5c50fc5e364540668ffff3f1e60700200",
	  "000034171f11f86c4764d4f9dc316cfb8a464f3aeebd131446de37ccc99ec68b" },
	{ "yespowerARWN", // Arowanacoin genesis, meets its target
	  "010000000000000000000000000000000000000000000000000000000000000000000000ab193cca5966475336f429c96b99394c69e5323dbcf1266e9f4c79f23249e08209aac560ffff0f1fa3120000",
	  "000e40df84630b10a9e9004e0552e06e91865535d748dcfb19bba0fce65da313" },
	{ "yespowerLITB", // LightBit genesis, exact (= hashGenesisBlock)
	  "0100000000000000000000000000000000000000000000000000000000000000000000005989b04d9759f28de85cb729bd87a9836e0f8ef1f1e53976edd0a2f36119730fc0af4e5dffff1f1f07140000",
	  "001a37ca994627042609a8ff350c446b935bb912069c37ec543fbdb0a5ed77b3" },
	{ "yespowerLTNCG", // Crionic block 5700003, meets its target
	  "00000020d25eaf28dbc5b555024ed5f006e9f3c180afd24674261aa5eb3eb76a49d847d2daa7aa1db6408f83eaea0704cbdc6ea74065784f22a76616bc35f04d09b0cbc79cbcac6ad1dd001f31070000",
	  "00004d0f0f2dc316da271f0951c62abdbc0830c43b1d7a3c4aadd6088d116292" },
	{ "yespowerMGPC", // MagpieCoin genesis, meets its target
	  "010000000000000000000000000000000000000000000000000000000000000000000000c925b94b786c237b25add6fc9d8b5aaccc641f3a3951a0b93baba12af0997c542c334a60f0ff0f1e071e0900",
	  "00000ad436508c04c3545a914bdb941310f1bdfa6d26877ec8e2964a1d781834" },
	{ "yespowerR16", // Yenten block 2200000, meets its target
	  "000000208e121b164248c7b6e59eef9a294dd6def092549e418b97499239438eda05c3128ca98435da280abb4aa8d2342fb8a8a731434b61ffc23e9550dd00658d6ba74740b6116aad1d011e213f3333",
	  "00000027a4fc66badfa63bc68a34f9c93eb1c2cdbe9a4cffcc2ac25375f3db30" },
	{ "yespowerSUGAR", // Sugarchain genesis, meets its target
	  "010000000000000000000000000000000000000000000000000000000000000000000000b050e156acdac2cada87b39ce5f137f5b872901e6b9e1c1d41b09c572ace77767073555dffff3f1ff7000000",
	  "0031205acedcc69a9c18f79b84790179d68fb90588bedee6587ff701bdde04eb" },
	{ "yespowerTIDE", // Tidecoin block 2000000, meets its target
	  "000000200d6b220f491e0073eebaf8a90adf413a07bab12aaf52e1df46b259ec4487c42b60aadef295865efcb2bfe9ffcfa3aacb7782ff117d17be6c0c62de399151f34e5e34fb67948a081d8c180000",
	  "000000016d311f7e1109d806ae4deb76b1e470d8701f37327edd9ad3f6125543" },
	{ NULL, NULL, NULL }
};

static YAAMP_HASH_FUNCTION find_algo(const char *name);

static void from_hex(const char *hex, unsigned char *bin, int len)
{
	for (int i = 0; i < len; i++) {
		unsigned int v;
		sscanf(hex + 2*i, "%02x", &v);
		bin[i] = (unsigned char) v;
	}
}

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

static YAAMP_HASH_FUNCTION find_algo(const char *name)
{
	for (int a = 0; algos[a].name; a++)
		if (!strcmp(algos[a].name, name)) return algos[a].hash;
	return NULL;
}

// returns the number of failures
static int run_kats(const char *only)
{
	unsigned char input[80];
	unsigned char output[64];
	char hex[129];
	int errors = 0;

	for (int k = 0; kats[k].algo; k++) {
		if (only && strcmp(only, kats[k].algo)) continue;
		YAAMP_HASH_FUNCTION fn = find_algo(kats[k].algo);
		from_hex(kats[k].header, input, 80);
		memset(output, 0, sizeof(output));
		fn((const char *) input, (char *) output, 80);
		to_hex_be(output, 32, hex);
		if (strcmp(hex, kats[k].hash)) {
			printf("FAIL %s KAT: %s\n", kats[k].algo, hex);
			errors++;
		} else {
			printf("OK   %s KAT\n", kats[k].algo);
		}
	}

	return errors;
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

	errors += run_kats(argc > 1 ? argv[1] : NULL);

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
