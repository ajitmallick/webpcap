#include "webcap.h"

int main(int argc, char *argv[]){

	char c;
	struct hostent *myserver;
	struct pcap_if *alldev;
	char server[64];
	char ofile[32];
	char device[8];
	int daemon = 0;
	int opterr = 1;

	dev[0] = NULL;
	ofile[0] = NULL;
	server[0] = NULL;
	mys.s_addr = 0;
	verbose = 0;
	promis = 0;

	while ( (c = getopt(argc, argv, "pi:s:l:dv")) != EOF ) {
		switch (c) {
		case 'p':
			promis = 1;
			break;
		case 'i':
			if (strlen(optarg) < 8) {
				if (pcap_findalldevs(&alldev, errbuf) == 0) {
					while(alldev) {
						if ( strcmp(alldev->name, optarg) == 0) {
							strcpy(dev, alldev->name);
							
						}
						alldev = alldev->next;
					}
				}
			}
			break;
		case 's':
			if (strlen(optarg) < 64) {
				if (myserver = gethostbyname(optarg)) {
					bcopy (myserver->h_addr, &mys, myserver->h_length);
				}
			}
			break;
		case 'l':
			if (strlen(optarg) < 32) {
				if (fd = fopen(optarg, "a")) {
					strcpy(ofile, optarg);
				}
			}
			break;
		case 'd':
			daemon = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case '?':
			printf("Argument not valid\n");
			break;
		}
	}
	if ( !(mys.s_addr) ) {
		fprintf (stderr, "Invalid or no server name supplied\n");
		exit(-1);
	}
	if ( !(dev[0]) ) {
		fprintf (stderr, "Device for listening  not supplied or could not be opened for listening\n");
		exit(-1);
	}
	if ( !(ofile[0]) ) {
		fprintf (stderr, "Log file not supplied or could not be opened for output\n");
		exit(-1);
	}

	if (verbose) {
		fprintf(stderr, "Log output filename is: %s\n", ofile);
		fprintf(stderr, "Device to listen on: %s\n", dev);
		fprintf(stderr, "Server is: %s\n", inet_ntoa(mys));
		fprintf(stderr, "Promiscuous:%d, Daemon:%d\n", promis, daemon);
		fprintf(stderr, "My pid is: %d\n", getpid());
	}

	if (daemon) {
		pid_t pid = fork();
		if ( pid != 0) exit(0);
		setsid(); 
		chdir("/");
		umask(0);
		if (verbose) fprintf(stderr, "Daemonised my new pid is %d\n", getpid());
	}
	if (!(root = malloc(sizeof(struct entry)))) {
                fprintf(stderr, "Error in memory allocation\n");
                return(0);
        }
	root->cli = inet_addr("128.128.128.128");
	root->srv = inet_addr("128.128.128.128");
	root->clip = (in_port_t) NULL;
	root->srvp = (in_port_t) NULL;
	root->left = NULL;
	root->right = NULL;
	int cap = capture();
	if (verbose) fprintf(stderr, "Captured %d packets\n", cap);
	return(0);
}
