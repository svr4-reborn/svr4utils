#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_COUNT 4
#define DEFAULT_INTERVAL_MS 1000
#define DEFAULT_TIMEOUT_MS 1000
#define DEFAULT_PAYLOAD_SIZE 56
#define MAX_PAYLOAD_SIZE 1472
#define ICMP_ECHOREPLY 0
#define ICMP_ECHO 8
#define IP_HEADER_MIN_SIZE 20
#define ICMP_HEADER_SIZE 8
#define NSEC_PER_MSEC 1000000L
#define NSEC_PER_SEC 1000000000L

struct ping_options {
	const char *host;
	int count;
	int interval_ms;
	int timeout_ms;
	size_t payload_size;
};

struct icmp_echo_header {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t id;
	uint16_t sequence;
};

struct parsed_reply {
	const struct icmp_echo_header *icmp;
	size_t icmp_length;
	int ttl;
};

static volatile sig_atomic_t stop_requested;

static void handle_interrupt(int signal_number)
{
	(void)signal_number;
	stop_requested = 1;
}

static void print_usage(const char *program)
{
	printf("usage: %s [-c count] [-i interval-ms] [-s payload-bytes] [-W timeout-ms] host\n", program);
}

static int parse_int_option(const char *text, int min_value, int max_value, int *value)
{
	char *end;
	long parsed;

	errno = 0;
	parsed = strtol(text, &end, 10);
	if (errno || !end || *end || parsed < min_value || parsed > max_value)
		return -1;

	*value = (int)parsed;
	return 0;
}

static int parse_size_option(const char *text, size_t *value)
{
	char *end;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno || !end || *end || parsed > MAX_PAYLOAD_SIZE)
		return -1;

	*value = (size_t)parsed;
	return 0;
}

static int parse_options(int argc, char **argv, struct ping_options *options)
{
	int index;

	memset(options, 0, sizeof(*options));
	options->count = DEFAULT_COUNT;
	options->interval_ms = DEFAULT_INTERVAL_MS;
	options->timeout_ms = DEFAULT_TIMEOUT_MS;
	options->payload_size = DEFAULT_PAYLOAD_SIZE;

	for (index = 1; index < argc; ++index) {
		if (!strcmp(argv[index], "--help") || !strcmp(argv[index], "-h")) {
			print_usage(argv[0]);
			return 1;
		}
		if (!strcmp(argv[index], "-c")) {
			if (++index == argc || parse_int_option(argv[index], 0, 1000000, &options->count) < 0) {
				fprintf(stderr, "%s: invalid count\n", argv[0]);
				return -1;
			}
			continue;
		}
		if (!strcmp(argv[index], "-i")) {
			if (++index == argc || parse_int_option(argv[index], 1, 3600000, &options->interval_ms) < 0) {
				fprintf(stderr, "%s: invalid interval\n", argv[0]);
				return -1;
			}
			continue;
		}
		if (!strcmp(argv[index], "-s")) {
			if (++index == argc || parse_size_option(argv[index], &options->payload_size) < 0) {
				fprintf(stderr, "%s: invalid payload size\n", argv[0]);
				return -1;
			}
			continue;
		}
		if (!strcmp(argv[index], "-W")) {
			if (++index == argc || parse_int_option(argv[index], 1, 3600000, &options->timeout_ms) < 0) {
				fprintf(stderr, "%s: invalid timeout\n", argv[0]);
				return -1;
			}
			continue;
		}
		if (argv[index][0] == '-') {
			fprintf(stderr, "%s: unknown option '%s'\n", argv[0], argv[index]);
			return -1;
		}
		if (options->host) {
			fprintf(stderr, "%s: only one host may be specified\n", argv[0]);
			return -1;
		}
		options->host = argv[index];
	}

	if (!options->host) {
		print_usage(argv[0]);
		return -1;
	}

	return 0;
}

static uint16_t internet_checksum(const void *buffer, size_t length)
{
	const uint8_t *bytes;
	uint32_t sum;

	bytes = buffer;
	sum = 0;
	while (length > 1) {
		sum += ((uint16_t)bytes[0] << 8) | bytes[1];
		bytes += 2;
		length -= 2;
	}
	if (length)
		sum += (uint16_t)bytes[0] << 8;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t)~sum;
}

static long monotonic_ms(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;

	return (long)(now.tv_sec * 1000 + now.tv_nsec / NSEC_PER_MSEC);
}

static void sleep_ms(int milliseconds)
{
	struct timespec delay;

	if (milliseconds <= 0)
		return;

	delay.tv_sec = milliseconds / 1000;
	delay.tv_nsec = (milliseconds % 1000) * NSEC_PER_MSEC;
	while (nanosleep(&delay, &delay) < 0 && errno == EINTR && !stop_requested)
		;
}

static int resolve_host(const char *host, struct sockaddr_in *address, char *numeric, size_t numeric_size)
{
	struct addrinfo hints;
	struct addrinfo *result;
	struct addrinfo *entry;
	int error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMP;

	result = NULL;
	error = getaddrinfo(host, NULL, &hints, &result);
	if (error) {
		fprintf(stderr, "svr4-ping: cannot resolve %s: %s\n", host, gai_strerror(error));
		return -1;
	}

	for (entry = result; entry; entry = entry->ai_next) {
		if (entry->ai_addrlen >= (socklen_t)sizeof(*address)) {
			memcpy(address, entry->ai_addr, sizeof(*address));
			break;
		}
	}

	freeaddrinfo(result);
	if (!entry) {
		fprintf(stderr, "svr4-ping: no IPv4 address for %s\n", host);
		return -1;
	}

	if (!inet_ntop(AF_INET, &address->sin_addr, numeric, numeric_size))
		strncpy(numeric, host, numeric_size);
	numeric[numeric_size - 1] = '\0';
	return 0;
}

static int build_echo_request(uint8_t *packet, size_t packet_size, uint16_t id, uint16_t sequence)
{
	struct icmp_echo_header *header;
	size_t index;

	if (packet_size < ICMP_HEADER_SIZE)
		return -1;

	memset(packet, 0, packet_size);
	header = (struct icmp_echo_header *)packet;
	header->type = ICMP_ECHO;
	header->code = 0;
	header->id = htons(id);
	header->sequence = htons(sequence);

	for (index = ICMP_HEADER_SIZE; index < packet_size; ++index)
		packet[index] = (uint8_t)(index & 0xff);

	header->checksum = htons(internet_checksum(packet, packet_size));
	return 0;
}

static int parse_reply(const uint8_t *packet, ssize_t packet_length, struct parsed_reply *reply)
{
	size_t header_length;

	memset(reply, 0, sizeof(*reply));
	reply->ttl = -1;

	if (packet_length < ICMP_HEADER_SIZE)
		return -1;

	if (packet_length >= IP_HEADER_MIN_SIZE && (packet[0] >> 4) == 4) {
		header_length = (packet[0] & 0x0f) * 4;
		if (header_length < IP_HEADER_MIN_SIZE || header_length + ICMP_HEADER_SIZE > (size_t)packet_length)
			return -1;
		if (packet[9] != IPPROTO_ICMP)
			return -1;
		reply->ttl = packet[8];
		reply->icmp = (const struct icmp_echo_header *)(packet + header_length);
		reply->icmp_length = (size_t)packet_length - header_length;
		return 0;
	}

	reply->icmp = (const struct icmp_echo_header *)packet;
	reply->icmp_length = (size_t)packet_length;
	return 0;
}

static int wait_for_reply(int fd, uint16_t id, uint16_t sequence, int timeout_ms,
		const char *numeric_host, long sent_ms)
{
	uint8_t packet[2048];
	struct sockaddr_in source;
	socklen_t source_length;
	long deadline_ms;
	char source_name[INET_ADDRSTRLEN];

	deadline_ms = monotonic_ms() + timeout_ms;
	for (;;) {
		struct pollfd pollfd;
		struct parsed_reply reply;
		long now_ms;
		int remaining_ms;
		int ready;
		ssize_t received;

		if (stop_requested)
			return 0;

		now_ms = monotonic_ms();
		remaining_ms = (int)(deadline_ms - now_ms);
		if (remaining_ms <= 0)
			return 0;

		pollfd.fd = fd;
		pollfd.events = POLLIN;
		pollfd.revents = 0;
		ready = poll(&pollfd, 1, remaining_ms);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			perror("svr4-ping: poll");
			return -1;
		}
		if (!ready)
			return 0;

		source_length = sizeof(source);
		received = recvfrom(fd, packet, sizeof(packet), 0, (struct sockaddr *)&source, &source_length);
		if (received < 0) {
			if (errno == EINTR)
				continue;
			perror("svr4-ping: recvfrom");
			return -1;
		}

		if (parse_reply(packet, received, &reply) < 0)
			continue;
		if (reply.icmp->type != ICMP_ECHOREPLY)
			continue;
		if (ntohs(reply.icmp->id) != id || ntohs(reply.icmp->sequence) != sequence)
			continue;

		if (!inet_ntop(AF_INET, &source.sin_addr, source_name, sizeof(source_name)))
			strncpy(source_name, numeric_host, sizeof(source_name));
		source_name[sizeof(source_name) - 1] = '\0';

		now_ms = monotonic_ms();
		printf("%lu bytes from %s: icmp_seq=%u", (unsigned long)reply.icmp_length,
		    source_name, (unsigned int)sequence);
		if (reply.ttl >= 0)
			printf(" ttl=%d", reply.ttl);
		printf(" time=%ld ms\n", now_ms - sent_ms);
		return 1;
	}
}

static int run_ping(const struct ping_options *options)
{
	struct sockaddr_in destination;
	char numeric_host[INET_ADDRSTRLEN];
	uint8_t *request;
	size_t request_size;
	uint16_t id;
	int fd;
	int transmitted;
	int received;
	int status;

	if (resolve_host(options->host, &destination, numeric_host, sizeof(numeric_host)) < 0)
		return 2;

	request_size = ICMP_HEADER_SIZE + options->payload_size;
	request = malloc(request_size);
	if (!request) {
		perror("svr4-ping: malloc");
		return 2;
	}

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd < 0) {
		perror("svr4-ping: socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)");
		free(request);
		return 2;
	}

	id = (uint16_t)getpid();
	transmitted = 0;
	received = 0;
	status = 0;

	printf("PING %s (%s): %lu data bytes\n", options->host, numeric_host,
	    (unsigned long)options->payload_size);

	while (!stop_requested && (options->count == 0 || transmitted < options->count)) {
		long sent_ms;
		ssize_t sent;
		uint16_t sequence;
		int reply_status;

		sequence = (uint16_t)(transmitted + 1);
		if (build_echo_request(request, request_size, id, sequence) < 0) {
			status = 2;
			break;
		}

		sent_ms = monotonic_ms();
		sent = sendto(fd, request, request_size, 0,
		    (struct sockaddr *)&destination, sizeof(destination));
		if (sent < 0) {
			perror("svr4-ping: sendto");
			status = 2;
			break;
		}
		++transmitted;

		reply_status = wait_for_reply(fd, id, sequence, options->timeout_ms, numeric_host, sent_ms);
		if (reply_status < 0) {
			status = 2;
			break;
		}
		if (reply_status > 0)
			++received;
		else
			printf("Request timeout for icmp_seq=%u\n", (unsigned int)sequence);

		if (!stop_requested && (options->count == 0 || transmitted < options->count))
			sleep_ms(options->interval_ms);
	}

	printf("--- %s ping statistics ---\n", options->host);
	printf("%d packets transmitted, %d packets received, %d%% packet loss\n",
	    transmitted, received, transmitted ? ((transmitted - received) * 100) / transmitted : 0);

	close(fd);
	free(request);
	if (status)
		return status;
	return received ? 0 : 1;
}

int main(int argc, char **argv)
{
	struct ping_options options;
	int parse_status;

	parse_status = parse_options(argc, argv, &options);
	if (parse_status > 0)
		return 0;
	if (parse_status < 0)
		return 2;

	signal(SIGINT, handle_interrupt);
	return run_ping(&options);
}
