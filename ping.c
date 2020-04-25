/*
	Author: Sarker Nadir Afridi Azmi
	
	Compile the code on Linux using gcc
	
	Compile using: gcc ./ping.c -o ping -g
	
	Usage: sudo ./ping [-t ttl] destination
	
	Resources used:
	* Primary resource: https://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
	* TCP/IP Sockets in C - Practical Guide for Programmers - 2nd Edition
							Author: Michael J. Donaho, Kenneth L. Calvert
	* https://stackoverflow.com/questions/13543554/how-to-receive-icmp-request-in-c-with-raw-sockets
	* http://courses.cs.vt.edu/cs4254/fall04/slides/raw_6.pdf
	* https://www.geeksforgeeks.org/ping-in-c/
	* https://stackoverflow.com/questions/2876024/linux-is-there-a-read-or-recv-from-socket-with-timeout
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h> // Includes iphdr & icmphdr
#include <arpa/inet.h>		 // Includes inet_pton()
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>
#include <stdbool.h>

#define PACKET_SIZE 64
#define IP_ADDR_LEN 100
#define PORT_NO 0
#define DELAY_BETWEEN_ECHO_REQUESTS 1000000
#define RECEIVE_TIME_OUT 1
#define DEFAULT_TTL_VAL 64

static int PING_STOP = 1;

// The packet to be sent
// The structure is packed in order to make sure that the data type are contiguous *without* padding
typedef struct __attribute__((__packed__)) Packet
{
	struct icmphdr icmp;
	char data[PACKET_SIZE - sizeof(struct icmphdr)];
} Packet;

// This packet structure has solely been created to store the received packet information
// The received packets has the ip header included from which I extracted the ttl value of
// the received packet
typedef struct __attribute__((__packed__)) ReceivedPacket
{
	struct iphdr ip;
	struct icmphdr icmp;
	char data[PACKET_SIZE - sizeof(struct icmphdr) - sizeof(struct iphdr)];
} ReceivedPacket;

// Function construct the packet
// Param 1: Pass in a variable of type Packet
// Param 2: Pass in the sequence value of type int
void ConstructPacket(Packet * packet, int * sequenceValue)
{
	packet->icmp.type = ICMP_ECHO;
	packet->icmp.code = 0;
	packet->icmp.un.echo.sequence = (*sequenceValue)++;
	packet->icmp.un.echo.id = getpid();
}

// This piece of code was very helpful:
// https://gist.github.com/jirihnidek/bf7a2363e480491da72301b228b35d5d

// This function is responsible for doing a host lookup
// Param 1: String representing the host
// Param 2: Buffer to store the returned address
void ResolveHost(const char *host, char *dest)
{
	struct addrinfo hints, *res = NULL;
	void *ptr = NULL;
	memset(&hints, 0, sizeof (hints));
	
	// *** Allow any address family
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_flags |= AI_CANONNAME;
	
	if(getaddrinfo(host, NULL, &hints, &res) != 0)
	{
		perror("getaddrinfo failed");
		freeaddrinfo(res);
		exit(1);
	}
	
	if(res)
	{
		switch(res->ai_family)
		{
			case AF_INET:
				ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
			break;
			// For future expansion to AF_INET6
			case AF_INET6:
				ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
			break;
		}
		inet_ntop (res->ai_family, ptr, dest, IP_ADDR_LEN);
		freeaddrinfo(res);
	}
	else
	{
		printf("No result found for given domain/ip.\n");
		exit(1);
	}
}

// Parses the command line arguments
// Param 1: argc
// Param 2: argv
// Param 3: Destination ip buffer
// Param 4: Source ip buffer - This was included so that if I wanted to use a custom ip header, I can easily do so
// Param 5: Pointer to a ttl value
void ParseCmdArgs(int argc, char *argv[], char *destAddr, char *srcAddr, int *ttlVal)
{
	int cmdIdx = 1;
	
	// Check to see if the -t flag has been added or not
	if(argc == 4)
	{
		char flag[3];
		strncpy(flag, argv[1], 3);
		if(strcmp(flag, "-t") == 0)
		{
			*ttlVal = atoi(argv[2]);
			cmdIdx = 3;
		}
		else
		{
			printf("Invalid flag. Please follow the format: %s -t ttl <IP Address/Host Name>\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	else if(argc < 2 || argc > 2)
	{
		printf("Please follow the format: %s <IP Address/Host Name>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	// Get the host name
	char HostName[255];
	int HostNameCheck = gethostname(HostName, sizeof(HostName));
	
	if(HostNameCheck == -1)
	{
		perror("gethostname failed()");
		exit(EXIT_FAILURE);
	}
	
	ResolveHost(HostName, srcAddr);
	ResolveHost(argv[cmdIdx], destAddr);
	printf("PINGING %s (%s) %ld(%ld) bytes of data.\n", argv[cmdIdx], destAddr,
			PACKET_SIZE - sizeof(struct icmphdr), sizeof(Packet));
}

// This code has been directly taken from Geeksforgeeks
// This function calculates the checksum
// Param 1: Buffer containing data for which the check sum is to be found
// Param 2: Length of the buffer
unsigned short checksum(unsigned short *buf, int len) 
{
    unsigned int sum = 0; 
    unsigned short result; 
  
    for ( sum = 0; len > 1; len -= 2 ) 
        sum += *buf++; 
    if ( len == 1 ) 
        sum += *(unsigned char*)buf; 
    sum = (sum >> 16) + (sum & 0xFFFF); 
    sum += (sum >> 16); 
    result = ~sum; 
    return result; 
}

// Function to fill the data with random data
// Param 1: Data buffer
// Param 2: Length of data buffer
void FillData(char *data, int len)
{
	// Data inside of packet
	char EchoData[] = "CLOUDFLARE INTERNSHIP: Systems";
	strncpy(data, EchoData, strlen(EchoData) - 1);
	int i = 0;
	for(i = sizeof(EchoData); i < len - 1; i++)
		data[i] = 65 + i;
	
	data[i] = 0;
}

// Stops pinging
// Param: Unused
void StopPing(int temp)
{
	PING_STOP = 0;
}

int main(int argc, char *argv[])
{
	// Buffers to hold the destination and source ip's
	char DestIp[IP_ADDR_LEN];
	bzero(&DestIp, sizeof(DestIp));
	// The source IP has only been included for future expansion
	char SrcIp[IP_ADDR_LEN];
	bzero(&SrcIp, sizeof(SrcIp));
	int TTLVal = DEFAULT_TTL_VAL;
	
	ParseCmdArgs(argc, argv, DestIp, SrcIp, &TTLVal);
	
	// Packet to be sent over the network
	Packet packet;
	bzero(&packet, sizeof(packet));
	// Buffer to store information about received packet
	ReceivedPacket EchoPacket;
	bzero(&EchoPacket, sizeof(EchoPacket));
	
	// Values to keep track of packets
	// Set packet parameters
	// Record time values
	int seq = 0;
	
	struct timespec PacketSentTime, PacketReceivedTime, PingStartTime, PingEndTime;
	int RecvdMessageCount = 0;
	
	// Create a socket to send the packet
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sock < 0)
	{
		perror("socket() failed");
		exit(1);
	}
	
	// Set the socket options to accept a custom TTL value
	if(setsockopt(sock, IPPROTO_IP, IP_TTL, (char *)&TTLVal, sizeof(TTLVal)) == -1)
	{
		perror("Failed to set Time-to-live (TTL) value. setsockopt() failed");
		exit(1);
	}
	
	// Set timeout value for socket
	struct timeval TimeOut;
	bzero(&TimeOut, sizeof(TimeOut));
	TimeOut.tv_sec = RECEIVE_TIME_OUT;
	TimeOut.tv_usec = 0;
	
	if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&TimeOut, sizeof(TimeOut)) == -1)
	{
		perror("Failed to set time-out value. setsockopt() failed");
		exit(1);
	}
	
	struct sockaddr_in ConnectingAddress;
	bzero(&ConnectingAddress, sizeof(ConnectingAddress));
	
	// Fill in the sockaddr_in structure to store the destination address
	ConnectingAddress.sin_family = AF_INET;
	ConnectingAddress.sin_port = htons(PORT_NO);
	int inet_ptonReturnValue = inet_pton(AF_INET, DestIp, &ConnectingAddress.sin_addr.s_addr);
	
	if(inet_ptonReturnValue == 0)
	{
		printf("inet_pton() failed: Invalid address string.\n");
		exit(1);
	}
	else if(inet_ptonReturnValue < 0)
	{
		perror("inet_pton() failed");
		exit(1);
	}
	
	// Catch Ctrl-C
	signal(SIGINT, StopPing);
	
	// Get ping start time
	clock_gettime(CLOCK_MONOTONIC, &PingStartTime);
	// Ping
	while(PING_STOP)
	{
		// Set up the icmp packet
		ConstructPacket(&packet, &seq);
		FillData(packet.data, sizeof(packet.data));
		packet.icmp.checksum = checksum((unsigned short *)&packet, sizeof(packet));
		
		int MsgSent = 1;
		
		// Time when packet is sent
		clock_gettime(CLOCK_MONOTONIC, &PacketSentTime);
		if(sendto(sock, &packet, sizeof(Packet), 0, (struct sockaddr *)&ConnectingAddress, sizeof(ConnectingAddress)) <= 0)
		{
			printf("Failed to send the packet.\n");
			MsgSent = 0;
		}
		
		// Flag to check if packet was received or not
		int RevcFail = 0;
		struct sockaddr_in ReturnAddress;
		int addrLen = sizeof(ReturnAddress);
		
		if(recvfrom(sock, &EchoPacket, sizeof(EchoPacket), 0, (struct sockaddr *)&ReturnAddress, &addrLen) <= 0)
		{
			RevcFail = 1;
			perror("Failed to receive the packet");
		}
		else if(RevcFail != 1)
		{
			// Time when packet is received
			clock_gettime(CLOCK_MONOTONIC, &PacketReceivedTime);
			
			// Convert the time to milliseconds
			double TimeElapsed = (double)(PacketReceivedTime.tv_nsec - PacketSentTime.tv_nsec)/1000000;
			long double RTT = ((PacketReceivedTime.tv_sec - PacketSentTime.tv_sec) * 1000) + TimeElapsed;
			
			// Only send the message if there it has been sucessfully received
			if(MsgSent)
			{
				if(EchoPacket.icmp.type == ICMP_TIME_EXCEEDED && EchoPacket.icmp.code == ICMP_EXC_TTL)
				{
					char RevdAddrBuffer[IP_ADDR_LEN];
					printf("From %s icmp_seq=%d Time to live exceeded\n", inet_ntop (AF_INET, &EchoPacket.ip.saddr, RevdAddrBuffer, IP_ADDR_LEN), seq);
				}
				else if(EchoPacket.icmp.type == ICMP_DEST_UNREACH && EchoPacket.icmp.code == ICMP_HOST_UNREACH)
				{
					char RevdAddrBuffer[IP_ADDR_LEN];
					printf("From %s icmp_seq=%d Destination Host Unreachable\n", inet_ntop (AF_INET, &EchoPacket.ip.saddr, RevdAddrBuffer, IP_ADDR_LEN), seq);
				}
				else
				{
					printf("%ld bytes from %s: icmp_seq=%d, supplied ttl value = %d, received packet ttl=%d, rtt=%0.1Lf ms\n",
														sizeof(EchoPacket), DestIp, seq, TTLVal, EchoPacket.ip.ttl, RTT);
					// Increment the message count
					RecvdMessageCount++;
				}
			}
		}
		
		/*
		 * ***** IMPORTANT *****
		 * All of the structures have to be zeroed out
		 * We do not want any stray bits that might mess up the checksum or ip addresses
		*/
		// Reset both packet structure
		bzero(&packet, sizeof(packet));
		bzero(&EchoPacket, sizeof(EchoPacket));
		
		usleep(DELAY_BETWEEN_ECHO_REQUESTS);
	}
	
	// Close the socket
	close(sock);
	
	clock_gettime(CLOCK_MONOTONIC, &PingEndTime);
	
	double TotalPingTimeNSec = (PingEndTime.tv_nsec - PingStartTime.tv_nsec) / 1000000;
	long double TotalPingTime = ((PingEndTime.tv_sec - PingStartTime.tv_sec) * 1000) + TotalPingTimeNSec;
	printf("\n--- %s ping statistics ---\n", DestIp);
	printf("%d packets transmitted, %d packets received, %.1f%% packet loss, time %0.0Lf ms\n",
			seq, RecvdMessageCount, ((double)(seq - RecvdMessageCount)/(double)seq) * 100, TotalPingTime);
	
	return EXIT_SUCCESS;
}
