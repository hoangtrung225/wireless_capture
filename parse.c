#define _BSD_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <endian.h>
#include <errno.h>
#include "radiotap_iter.h"

static const struct radiotap_align_size align_size_000000_00[] = {
	[0] = { .align = 1, .size = 4, },
};

static const struct ieee80211_radiotap_namespace vns_array[] = {
	{
		.oui = 0x000000,
		.subns = 0,
		.n_bits = sizeof(align_size_000000_00),
		.align_size = align_size_000000_00,
	},
};

static const struct ieee80211_radiotap_vendor_namespaces vns = {
	.ns = vns_array,
	.n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
};

static void print_radiotap_namespace(struct ieee80211_radiotap_iterator *iter)
{
	switch (iter->this_arg_index) {
	case IEEE80211_RADIOTAP_TSFT:
		printf("\tTSFT: %llu\n", le64toh(*(unsigned long long *)iter->this_arg));
		break;
	case IEEE80211_RADIOTAP_FLAGS:
		printf("\tflags: %02x\n", *iter->this_arg);
		break;
	case IEEE80211_RADIOTAP_RATE:
	case IEEE80211_RADIOTAP_CHANNEL:
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
	case IEEE80211_RADIOTAP_ANTENNA:
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
	case IEEE80211_RADIOTAP_RX_FLAGS:
	case IEEE80211_RADIOTAP_TX_FLAGS:
	case IEEE80211_RADIOTAP_RTS_RETRIES:
	case IEEE80211_RADIOTAP_DATA_RETRIES:
		break;
	default:
		printf("\tBOGUS DATA\n");
		break;
	}
}

static void print_test_namespace(struct ieee80211_radiotap_iterator *iter)
{
	switch (iter->this_arg_index) {
	case 0:
		printf("\t00:00:00-00|0: %.2x/%.2x/%.2x/%2.x\n",
			*iter->this_arg, *(iter->this_arg + 1),
			*(iter->this_arg + 2), *(iter->this_arg + 3));
		break;
	default:
		printf("\tBOGUS DATA\n");
		break;
	}
}

int main(int argc, char *argv[])
{
	struct ieee80211_radiotap_iterator iter;
	struct stat statbuf;
	int fd, err;
	void *data;

	if (argc != 2) {
		fprintf(stderr, "usage: parse <file>\n");
		return 2;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 2;
	}

	if (fstat(fd, &statbuf)) {
		perror("fstat");
		return 2;
	}

	data = mmap(NULL, statbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);

	err = ieee80211_radiotap_iterator_init(&iter, data, statbuf.st_size, &vns);
	if (err) {
		printf("malformed radiotap header (init returns %d)\n", err);
		return 3;
	}

	while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
		if (iter.is_radiotap_ns)
			print_radiotap_namespace(&iter);
		else if (iter.current_namespace == &vns_array[0])
			print_test_namespace(&iter);
	}

	if (err != -ENOENT) {
		printf("malformed radiotap data\n");
		return 3;
	}

	return 0;
}