// Notify the stratum of a new block (to be called by the coin daemon)
//
// usage: blocknotify server:port coinid blockhash
// e.g. in the coin .conf file: blocknotify=blocknotify 127.0.0.1:3433 1234 %s

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

// the installer replaces this password, it must match the TCP:password of
// the stratum config files
#define BLOCKNOTIFY_PASSWORD "tu8tu5"

#define BLOCKNOTIFY_TIMEOUT 10 // seconds

static int usage()
{
	fprintf(stderr, "usage: blocknotify server:port coinid blockhash\n");
	return 1;
}

static bool is_hex(const char *s, size_t maxlen)
{
	size_t len = strlen(s);
	if (!len || len > maxlen) return false;
	for (size_t i = 0; i < len; i++)
		if (!isxdigit((unsigned char) s[i])) return false;
	return true;
}

static bool parse_long(const char *s, long min, long max, long *out)
{
	char *end = NULL;
	errno = 0;
	long v = strtol(s, &end, 10);
	if (errno || end == s || *end || v < min || v > max) return false;
	*out = v;
	return true;
}

static bool send_all(int sock, const char *buffer, size_t len)
{
	while (len > 0) {
		ssize_t n = send(sock, buffer, len, MSG_NOSIGNAL);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) return false;
		buffer += n;
		len -= (size_t) n;
	}
	return true;
}

int main(int argc, char **argv)
{
	if (argc < 4)
		return usage();

	// host:port, the host may be a name, an ipv4 or a [ipv6] address
	char host[256];
	const char *sep = strrchr(argv[1], ':');
	if (!sep || sep == argv[1] || (size_t)(sep - argv[1]) >= sizeof(host))
		return usage();

	memcpy(host, argv[1], sep - argv[1]);
	host[sep - argv[1]] = '\0';
	if (host[0] == '[' && host[strlen(host)-1] == ']') {
		memmove(host, host + 1, strlen(host));
		host[strlen(host)-1] = '\0';
	}

	long port, coinid;
	if (!parse_long(sep + 1, 1, 65535, &port)) {
		fprintf(stderr, "blocknotify: invalid port %s\n", sep + 1);
		return 1;
	}
	if (!parse_long(argv[2], 1, INT_MAX, &coinid)) {
		fprintf(stderr, "blocknotify: invalid coin id %s\n", argv[2]);
		return 1;
	}
	// block hashes are hex strings (64 chars for most coins)
	if (!is_hex(argv[3], 128)) {
		fprintf(stderr, "blocknotify: invalid block hash for coin %ld\n", coinid);
		return 1;
	}

	char portstr[16];
	snprintf(portstr, sizeof(portstr), "%ld", port);

	struct addrinfo hints, *res = NULL, *ai;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int err = getaddrinfo(host, portstr, &hints, &res);
	if (err) {
		fprintf(stderr, "blocknotify: cannot resolve %s (%s) id %ld\n", host, gai_strerror(err), coinid);
		return 1;
	}

	int sock = -1;
	for (ai = res; ai; ai = ai->ai_next) {
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0) continue;

		struct timeval tv = { BLOCKNOTIFY_TIMEOUT, 0 };
		setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

		if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) break;
		close(sock);
		sock = -1;
	}
	freeaddrinfo(res);

	if (sock < 0) {
		fprintf(stderr, "blocknotify: cannot connect to %s:%ld id %ld\n", host, port, coinid);
		return 1;
	}

	char buffer[1024];
	int len = snprintf(buffer, sizeof(buffer),
		"{\"id\":1,\"method\":\"mining.update_block\",\"params\":[\"%s\",%ld,\"%s\"]}\n",
		BLOCKNOTIFY_PASSWORD, coinid, argv[3]);
	if (len < 0 || (size_t) len >= sizeof(buffer)) {
		close(sock);
		return 1;
	}

	bool ok = send_all(sock, buffer, (size_t) len);
	close(sock);

	if (!ok) {
		fprintf(stderr, "blocknotify: send error to %s:%ld id %ld\n", host, port, coinid);
		return 1;
	}

	return 0;
}
