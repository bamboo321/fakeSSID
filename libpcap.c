#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <unistd.h>


void printPcap_if(pcap_if_t *a) {
    printf("next: %p\n", a->next);
    printf("name: %s\n", a->name);
    printf("description: %s\n", a->description);
    printf("address: %p\n", a->addresses);
    printf("flags: %d\n", a->flags);
    printf("-------------\n");
}

void printUsage() {
    printf("Usage: ./fakeSSID device ssidlist\n");
    printf("\tdevice: wireless device name  e.g. wlan0");
    printf("\tssidlist: SSID you want to show to neighbors. you can specify multiple SSID.\n");
}

int main(int argc, char *argv[]) {
    //
    //variables for getopt
    //
    int ch;
    extern char *optarg;
    extern int optind, opterr, optopt;

    char *devname;
    char *ssidList;
    while ((ch = getopt(argc, argv, "d:f:")) != -1) {
        switch (ch) {
            case 'd':
                devname = optarg;
                break;

            case 'f':
                ssidList = optarg;
                break;

            default:
                printUsage();
                exit(EXIT_FAILURE);
        }
    }

    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0] = '\0';

    //
    //find wireless device
    //
    pcap_if_t *alldevsp;
    if (pcap_findalldevs(&alldevsp, pcap_errbuf) == -1) {
        printf("%s\n", pcap_errbuf);
        exit(EXIT_FAILURE);
    }


    pcap_if_t *currentAddress = alldevsp;
    while (currentAddress->next != NULL) {
        printPcap_if(currentAddress);
        currentAddress = currentAddress->next;
    }

    pcap_t *pcap = pcap_open_live(devname, 96, 0, 0, pcap_errbuf);

    if (pcap_errbuf[0] != '\0') {
        fprintf(stderr, "%s", pcap_errbuf);
    }

    if (!pcap) {
        exit(1);
    }
}

