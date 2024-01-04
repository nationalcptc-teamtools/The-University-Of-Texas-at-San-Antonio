#include <sys/time.h>
#ifndef _SERVER_H_
#define _SERVER_H_

#define MAXBUF 65536
#define BACKLOG 1
#define MAX_CLIENTS 30
#define PROMPT "HeadHunter/> "

fd_set readfds;
int master_socket, new_socket, max_clients = MAX_CLIENTS, client_socket[MAX_CLIENTS], client_status[MAX_CLIENTS], activity, i, sd, victim_count;
int max_sd;
struct timeval last_check[MAX_CLIENTS];
pthread_t threads[MAX_CLIENTS] = {0};
struct sockaddr_in cli;
socklen_t len;

// Declaration of struct "args" as the pthread_create function preferably takes a struct as a param
// This is the struct for the Writer thread
typedef struct args
{
    int src;
    int dest;
    int kill;
    char* beaconbuf;
    int beaconbufsize; 

} args;

args a;

#endif
