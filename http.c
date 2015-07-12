#include "webcap.h"

/*req() checks the packet for valid HTTP request,
  if found an entry is created for  http request
  and inserted into the session table*/
void req(u_char *payload, int payl_size, in_addr_t cli, in_addr_t srv, in_port_t clip, in_port_t srvp) {
	int method = 0;
	char *hdrend = NULL;
	char *ch = NULL;
	struct entry *new;
	register int i = 0;

	if (strncmp((char *)payload, "GET "	, 4) == 0) method = 1;
	if (strncmp((char *)payload, "POST "	, 5) == 0) method = 2;
	if (strncmp((char *)payload, "HEAD "	, 5) == 0) method = 3;
	if (strncmp((char *)payload, "PUT "	, 4) == 0) method = 4;
	if (strncmp((char *)payload, "OPTIONS "	, 8) == 0) method = 5;
	if (strncmp((char *)payload, "CONNECT "	, 8) == 0) method = 6;
	if (strncmp((char *)payload, "TRACE "	, 6) == 0) method = 7;
	if (strncmp((char *)payload, "DELETE "	, 7) == 0) method = 8;

	if (method == 0) {
		if (verbose) fprintf(stderr, "req:Invalid request\n");
		return;
	}

	if (!(hdrend = memmem(payload, payl_size, "\015\012\015\012", 4))) {
		if (verbose) fprintf(stderr, "req:Header too long\n");
		return;
	}
	for ( ch = payload; ch != hdrend; ch++ ) {
		i++;
        }

	if ( i == 1 || i == payl_size ) return;

	if (!(new = malloc(sizeof(struct entry)))) {
		if (verbose) fprintf(stderr, "Error in memory allocation\n");
		return;
	}
	if ( (new->req_hdr = malloc(sizeof(char) * (i + 2))) == 0 ) {
		if (verbose) fprintf(stderr, "Error in memory allocation\n");
		return;
	}
	
	if ( memcpy(new->req_hdr, (char *) payload, i) != new->req_hdr ) return;
	new->req_hdr[i] = (char) NULL;
	new->req_hdr_len = i;

	new->cli = cli;
	new->srv = srv;
	new->clip = clip;
	new->srvp = srvp;
	new->pipe = 0;
	new->left = NULL;
	new->right = NULL;
	insert(root, new);
}

/*resp() checks the packet for valid HTTP response,
  if found a matching request is searched in the sessiontable
  if an entry foud inthe session table, a log entry is created 
  and written to log file, and entry from session table is deleted*/
void resp (u_char *payload, int payl_size, in_addr_t cli, in_addr_t srv, in_port_t clip, in_port_t srvp) {
	char *len;
	char *start_stat;
	char *end_stat;
	char *host;
	char *req_hdr_end;
        register int i = 0;
	int con_len = 0;
	int status = 0;
	if (strncmp((char *)payload, "HTTP", 4) != 0) {
		return;
	}

	if ((len = memmem(payload, payl_size, "Content-Length:", 15))) {
		if ( memmem(len, 27, "\015\012", 2) ) con_len = atoi(len + 15); /*con len can be 10 digits max*/
	}

	if ( start_stat = memmem(payload, 10, " ", 1) ) {
		if ( start_stat[4] == 32 ) status = atoi(start_stat+1); /*status can be 3 digits max*/
	}
		
			

	find.cli = cli;
	find.srv = srv;
	find.clip = clip;
	find.srvp = srvp;
	found = NULL;
	parent = NULL;
	search(root, &find, root);
	if ( (found == NULL) || (parent == NULL) ) {
		if (verbose) fprintf(stderr, "Resp without req\n");
		return;
	}

	/*Common log format :
		remotehost rfc931 authuser [date] "request" status bytes
	*/

	fprintf(fd, "%s ",inet_ntoa(found->cli)); /*remotehost*/
	fprintf(fd, "- - "); /*rfc931 and authuser*/

	time_t now = time(NULL);
	char *asc_time = ctime(&now);
	asc_time[24] = NULL;
	fprintf(fd, "[%s] ",asc_time); /*[date]*/


	/*if (host = memmem(found->req_hdr, found->req_hdr_len, "Host:", 5)) {
		i = 6;
		while ( (host[i] != 13) && (host[i] != req_hdr_end) ) {
			if (isprint(host[i])) fprintf (stdout, "%c", host[i]);
			i++;
		}
	}
	fprintf (stdout, "\t");*/


	fprintf(fd,"\""); /*"request line"*/
	while ( ((int)found->req_hdr[i] != 13) && (i < found->req_hdr_len) ) {
		if (isprint(found->req_hdr[i])) fprintf (fd, "%c", found->req_hdr[i]);
		i++;
	}
	fprintf(fd,"\" "); /*"request line"*/

	if (status) fprintf(fd, "%d ", status); /*status code*/

	if (con_len) fprintf(fd, "%d ", con_len); /*bytes*/

	fprintf(fd, "\n");
	fflush(fd);
	move(found, parent);
	free(found->req_hdr);
	free(found);
}
