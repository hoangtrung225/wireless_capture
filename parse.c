#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pcap.h>
#if defined(__APPLE__)
#include <machine/endian.h>
#else
#include <endian.h>
#endif

#include "radiotap_iter.h"

#define SELECT_FILTER "wlan host "

static int fcshdr = 0;

static const struct radiotap_align_size align_size_000000_00[] = {
	[0] = { .align = 1, .size = 4, },
	[52] = { .align = 1, .size = 4, },
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
		break;
	case IEEE80211_RADIOTAP_FLAGS:
		break;
	case IEEE80211_RADIOTAP_RATE:
		break;
	case IEEE80211_RADIOTAP_CHANNEL:
		break;
	case IEEE80211_RADIOTAP_FHSS:
		break;
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
		printf("\ttin hieu antenna: %ddbm\tkhoang cach voi AccessPoint: %dm\n", *iter->this_arg - 256, (256 - *iter->this_arg) / 10);
		break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
		printf("\tantenna noise receive\n");
		break;
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
		break;
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
		printf("\ttransmite antenna signal: %d\n", *iter->this_arg - 256);
		break;
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
		printf("\ttransmite antenna signal: %d\n", *iter->this_arg - 256);
		break;
	case IEEE80211_RADIOTAP_ANTENNA:
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
	case IEEE80211_RADIOTAP_TX_FLAGS:
		break;
	case IEEE80211_RADIOTAP_RX_FLAGS:
		break;
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
	case 52:
		printf("\t00:00:00-00|%d: %.2x/%.2x/%.2x/%.2x\n",
			iter->this_arg_index,
			*iter->this_arg, *(iter->this_arg + 1),
			*(iter->this_arg + 2), *(iter->this_arg + 3));
		break;
	default:
		printf("\tBOGUS DATA - vendor ns %d\n", iter->this_arg_index);
		break;
	}
}

static const struct radiotap_override overrides[] = {
	{ .field = 14, .align = 4, .size = 4, }
};

int print_help(void){
	fprintf(stderr, "parse [interface] [MACaddr]\n");
	return -1;
}

int main(int argc, char *argv[])
{
       	pcap_t *handle;			/* Session handle */
       	char *dev; 			/* The device to sniff on */
       	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
       	struct pcap_pkthdr header;	/* The header that pcap gives us */
       	const u_char *packet;		/* The actual packet */
       	int err, i;
	struct ieee80211_radiotap_iterator iter;
        /* Define the device */
        //dev = pcap_lookupdev(errbuf);
	if(argc != 3)
		return -1;

	dev = argv[1];
        if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		print_help();
         	return(2);
        }

        /* Open the session in promiscuous mode */
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
         	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
         	return(2);
        }
        pcap_set_snaplen(handle, 2048);  // Set the snapshot length to 2048
        pcap_set_promisc(handle, 1);     // Turn promiscuous mode off
        pcap_set_timeout(handle, 512);   // Set the timeout to 512 milliseconds
        int status = pcap_activate(handle);
        
        if(pcap_set_rfmon(handle,1)==0 )
        {
         	printf("monitor mode enabled\n");
        }

        if(pcap_set_datalink(handle, DLT_IEEE802_11_RADIO) == -1) {
         	printf("Couldn't set datalink type %s: %s\n", dev, pcap_geterr(handle));
        }

	char filter[64];
	memset(filter, 0, 64);
       	strncpy(filter, SELECT_FILTER, strlen(SELECT_FILTER));
       	strncpy(filter + strlen(SELECT_FILTER), argv[2], strlen(argv[2]));	// beacon frame WLAN
	fprintf(stderr, "Selected filter string: %s\n", filter);
	struct bpf_program fp; 
	bpf_u_int32 netp; // Berkley Packet Filter (same as u_int32_t i believe)
	if(pcap_compile(handle,&fp,filter,0,netp)==-1) // -1 means failed
		fprintf(stderr,"Error compiling Libpcap filter, %s\n",filter);
	if(pcap_setfilter(handle,&fp)==-1) // -1 means failed - but we don't exit(1)
		fprintf(stderr,"Error setting Libpcap filter, %s\n",filter); // same as above

	printf("Type: %d\n",pcap_datalink(handle));

	while((packet = pcap_next(handle, &header)) != NULL) {
	/* Print its length */
//	printf("Jacked a packet with length of [%d]\n", header.len);
	err = ieee80211_radiotap_iterator_init(&iter, packet, header.len, &vns);
	if (err) {
	       printf("malformed radiotap header (init returns %d)\n", err);
	       return 3;
	}

         	while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
         	if (iter.this_arg_index == IEEE80211_RADIOTAP_VENDOR_NAMESPACE) {
         		printf("\tvendor NS (%.2x-%.2x-%.2x:%d, %d bytes)\n",
         			iter.this_arg[0], iter.this_arg[1],
         			iter.this_arg[2], iter.this_arg[3],
         			iter.this_arg_size - 6);
         		for (i = 6; i < iter.this_arg_size; i++) {
         			if (i % 8 == 6)
         				printf("\t\t");
         			else
         				printf(" ");
         			printf("%.2x", iter.this_arg[i]);
         		}
         		printf("\n");
         	} else if (iter.is_radiotap_ns)
         		print_radiotap_namespace(&iter);
         	else if (iter.current_namespace == &vns_array[0])
         		print_test_namespace(&iter);
         }

        }
        /* And close the session */
        pcap_close(handle);
        return(0);
}
