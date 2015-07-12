#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#define COUNT -1
#define GET 512
#define HOST 56


struct entry {
	in_addr_t cli;	//Client IP
	in_addr_t srv;	//Server IP
	int clip;	//Client port
	int srvp;	//Server port
	int req_hdr_len;	//Request header length
	char *req_hdr;	//Request header
	char host[HOST];//Hostname
	int pipe;	//Pipelined req
	int cont_len;	//Content Length
	time_t get_time;//Time of request
	struct entry *left;
	struct entry *right;
};

struct entry *root;	//Root entry
struct entry *found;	//search() sets it to the matching entry
struct entry *parent;	//search() sets it to parent of matching entry
struct entry find;	//
FILE *fd;		//file to output log entries
char dev[6];		//device for capturing traffic
int promis;		//flag for Promiscuous mode
int verbose;		//flag for verbose error message printing
struct in_addr mys;	//server address 

char errbuf[PCAP_ERRBUF_SIZE];	//pcap error message

int 	sock_comp	 (struct entry *, struct entry *);
void 	insert		 (struct entry *, struct entry *);
void	search		 (struct entry *, struct entry *, struct entry *);
void	move		 (struct entry *, struct entry *);
void 	req 		 (u_char *, int, in_addr_t, in_addr_t, in_port_t, in_port_t);
void 	resp 		 (u_char *, int, in_addr_t, in_addr_t, in_port_t, in_port_t);
int 	capture		 (void);
