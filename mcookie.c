#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define COOKIE_LEN 16

static const char version_string[] = "mcookie (svr4_utils) 1.0";

static const struct option long_options[] = {
	{ "file", required_argument, NULL, 'f' },
	{ "max-size", required_argument, NULL, 'm' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 }
};

static int
read_all(int fd, unsigned char *buffer, size_t length)
{
	size_t offset;

	offset = 0;
	while (offset < length) {
		ssize_t chunk;

		chunk = read(fd, buffer + offset, length - offset);
		if (chunk < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		if (chunk == 0) {
			errno = EIO;
			return (-1);
		}
		offset += (size_t)chunk;
	}

	return (0);
}

static int
get_cookie(unsigned char *cookie, size_t length)
{
	static const char *const sources[] = {
		"/dev/urandom",
		"/dev/random"
	};
	int index;

	for (index = 0; index < (int)(sizeof(sources) / sizeof(sources[0])); index++) {
		int fd;

		fd = open(sources[index], O_RDONLY);
		if (fd < 0)
			continue;
		if (read_all(fd, cookie, length) == 0) {
			close(fd);
			return (0);
		}
		close(fd);
	}

	return (-1);
}

static void
usage(FILE *stream, const char *program_name)
{
	(void)fprintf(stream,
	    "Usage:\n"
	    " %s [options]\n"
	    "\n"
	    "Generate magic cookies for xauth.\n"
	    "\n"
	    "Options:\n"
	    " -f, --file <file>     use file as a cookie seed\n"
	    " -m, --max-size <num>  limit how much is read from seed files\n"
	    " -v, --verbose         explain what is being done\n"
	    "\n"
	    " -h, --help            display this help\n"
	    " -V, --version         display version\n"
	    "\n"
	    "Arguments:\n"
	    " Values for <num> may be followed by a suffix: KiB, MiB,\n"
	    " GiB, TiB, PiB, EiB, ZiB, or YiB (where the \"iB\" is optional).\n"
	    "\n"
	    "For more details see mcookie(1).\n",
	    program_name);
}

static size_t
parse_max_size(const char *text, int *ok)
{
	char *end;
	unsigned long long value;
	unsigned long long multiplier;

	*ok = 0;
	if (text == NULL || *text == '\0')
		return (0);

	errno = 0;
	value = strtoull(text, &end, 10);
	if (errno != 0 || end == text)
		return (0);

	multiplier = 1;
	if (*end != '\0') {
		if (strcmp(end, "K") == 0 || strcmp(end, "KB") == 0 || strcmp(end, "KiB") == 0)
			multiplier = 1024ULL;
		else if (strcmp(end, "M") == 0 || strcmp(end, "MB") == 0 || strcmp(end, "MiB") == 0)
			multiplier = 1024ULL * 1024ULL;
		else if (strcmp(end, "G") == 0 || strcmp(end, "GB") == 0 || strcmp(end, "GiB") == 0)
			multiplier = 1024ULL * 1024ULL * 1024ULL;
		else if (strcmp(end, "T") == 0 || strcmp(end, "TB") == 0 || strcmp(end, "TiB") == 0)
			multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
		else if (strcmp(end, "P") == 0 || strcmp(end, "PB") == 0 || strcmp(end, "PiB") == 0)
			multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
		else if (strcmp(end, "E") == 0 || strcmp(end, "EB") == 0 || strcmp(end, "EiB") == 0)
			multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
		else if (strcmp(end, "Z") == 0 || strcmp(end, "ZB") == 0 || strcmp(end, "ZiB") == 0)
			multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
		else if (strcmp(end, "Y") == 0 || strcmp(end, "YB") == 0 || strcmp(end, "YiB") == 0)
			multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
		else
			return (0);
	}

	if (multiplier != 0 && value > (unsigned long long)SIZE_MAX / multiplier)
		return (0);

	*ok = 1;
	return ((size_t)(value * multiplier));
}

static int
mix_seed_file(unsigned char *cookie, size_t cookie_length, const char *path, size_t max_size, int verbose)
{
	unsigned char buffer[4096];
	size_t total;
	int fd;

	if (path == NULL)
		return (0);

	if (verbose)
		(void)fprintf(stderr, "mcookie: seeding from %s\n", path);

	if (strcmp(path, "-") == 0)
		fd = STDIN_FILENO;
	else
		fd = open(path, O_RDONLY);
	if (fd < 0)
		return (-1);

	total = 0;
	while (total < max_size) {
		size_t request;
		ssize_t chunk;
		size_t index;

		request = sizeof(buffer);
		if (request > max_size - total)
			request = max_size - total;

		chunk = read(fd, buffer, request);
		if (chunk < 0) {
			if (errno == EINTR)
				continue;
			if (fd != STDIN_FILENO)
				close(fd);
			return (-1);
		}
		if (chunk == 0)
			break;

		for (index = 0; index < (size_t)chunk; index++)
			cookie[(total + index) % cookie_length] ^= buffer[index];
		total += (size_t)chunk;
	}

	if (fd != STDIN_FILENO)
		(void)close(fd);

	return (0);
}

int
main(int argc, char *argv[])
{
	unsigned char cookie[COOKIE_LEN];
	static const char hex[] = "0123456789abcdef";
	const char *seed_file;
	size_t max_size;
	int verbose;
	int saw_max_size;
	int index;
	int option;

	seed_file = NULL;
	max_size = 256;
	verbose = 0;
	saw_max_size = 0;
	opterr = 0;
	optind = 1;

	while ((option = getopt_long(argc, argv, "f:m:vhV", long_options, NULL)) != -1) {
		switch (option) {
		case 'f':
			seed_file = optarg;
			break;
		case 'm':
			max_size = parse_max_size(optarg, &saw_max_size);
			if (!saw_max_size) {
				(void)fprintf(stderr, "%s: invalid max-size value: %s\n", argv[0], optarg);
				return (1);
			}
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
			usage(stdout, argv[0]);
			return (0);
		case 'V':
			(void)puts(version_string);
			return (0);
		case '?':
		default:
			usage(stderr, argv[0]);
			return (1);
		}
	}

	if (optind != argc) {
		usage(stderr, argv[0]);
		return (1);
	}

	if (get_cookie(cookie, sizeof(cookie)) != 0) {
		(void)fprintf(stderr, "%s: unable to generate cookie: %s\n", argv[0], strerror(errno));
		return (1);
	}

	if (seed_file != NULL && mix_seed_file(cookie, sizeof(cookie), seed_file, max_size, verbose) != 0) {
		(void)fprintf(stderr, "%s: unable to read seed file %s: %s\n", argv[0], seed_file, strerror(errno));
		return (1);
	}

	if (verbose) {
		(void)fprintf(stderr, "mcookie: generating %u-byte cookie\n", (unsigned int)sizeof(cookie));
	}

	for (index = 0; index < (int)sizeof(cookie); index++)
		(void)putchar(hex[(cookie[index] >> 4) & 0x0f]);
	for (index = 0; index < (int)sizeof(cookie); index++)
		(void)putchar(hex[cookie[index] & 0x0f]);
	(void)putchar('\n');

	if (fflush(stdout) != 0) {
		(void)fprintf(stderr, "%s: write failed: %s\n", argv[0], strerror(errno));
		return (1);
	}

	return (0);
}
