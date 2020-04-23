/*
	Author: Sarker Nadir Afridi Azmi
	
	Resources used:
	* Primary resource: https://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
	* https://stackoverflow.com/questions/13543554/how-to-receive-icmp-request-in-c-with-raw-sockets
	* http://courses.cs.vt.edu/cs4254/fall04/slides/raw_6.pdf
	* https://www.geeksforgeeks.org/ping-in-c/
	* https://stackoverflow.com/questions/2876024/linux-is-there-a-read-or-recv-from-socket-with-timeout
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>				// Includes iphdr & icmphdr
#include <arpa/inet.h>						// Includes inet_pton()
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <time.h>
#include <signal.h>

#define PACKET_SIZE 64
#define IP_ADDR_LEN 15
#define PORT_NO 0
#define DELAY_BETWEEN_ECHO_REQUESTS 1000000

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

void ParseCmdArgs(int argc, char *argv[], char *destAddr, char *srcAddr)
{
	if(argc < 2 || argc > 3)
	{
		printf("Please follow the format: %s <IP Address/Host Name>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	char HostName[255];
	int HostNameCheck = gethostname(HostName, sizeof(HostName));
	
	if(HostNameCheck == -1)
	{
		perror("gethostname failed()");
		exit(EXIT_FAILURE);
	}
	
	struct hostent *LocalHostEntry = gethostbyname(HostName);
	struct hostent *RemoteHostEntry = gethostbyname(argv[1]);
	
	if(LocalHostEntry == NULL)
	{
		perror("gethostbyname() failed");
		exit(EXIT_FAILURE);
	}
	
	strncpy(srcAddr, inet_ntoa(*((struct in_addr *)LocalHostEntry->h_addr_list[0])), IP_ADDR_LEN);
	strncpy(destAddr, inet_ntoa(*(struct in_addr *)RemoteHostEntry->h_addr), IP_ADDR_LEN);
	
	if(destAddr == NULL)
	{
		printf("Invalid domain/ip address. Exiting...\n");
		exit(1);
	}
}

// This code has been directly taken from Geeksforgeeks
// Calculating the Check Sum
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
void StopPing(int temp)
{
	PING_STOP = 0;
}

int main(int argc, char *argv[])
{
	// Buffers to hold the destination and source ip's
	char DestIp[IP_ADDR_LEN];
	char SrcIp[IP_ADDR_LEN];
	
	ParseCmdArgs(argc, argv, DestIp, SrcIp);
	
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
	int TTLVal = 64;
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
	
	clock_gettime(CLOCK_MONOTONIC, &PingStartTime);
	// Ping
	while(PING_STOP)
	{
		// Set up the icmp packet
		ConstructPacket(&packet, &seq);
		FillData(packet.data, sizeof(packet.data));
		packet.icmp.checksum = checksum((unsigned short *)&packet, sizeof(packet));
		
		// Time when packet is sent
		clock_gettime(CLOCK_MONOTONIC, &PacketSentTime);
		if(sendto(sock, &packet, sizeof(Packet), 0, (struct sockaddr *)&ConnectingAddress, sizeof(ConnectingAddress)) <= 0)
		{
			printf("Failed to send the packet.\n");
		}
		
		struct sockaddr_in ReturnAddress;
		int addrLen = sizeof(ReturnAddress);
		if(recvfrom(sock, &EchoPacket, sizeof(EchoPacket), 0, (struct sockaddr *)&ReturnAddress, &addrLen) <= 0)
		{
			printf("Failed to receive the packet.\n");
		}
		else
		{
			// Time when packet is received
			clock_gettime(CLOCK_MONOTONIC, &PacketReceivedTime);
			// Convert the time to milliseconds
			double TimeElapsed = (PacketReceivedTime.tv_nsec - PacketSentTime.tv_nsec)/1000000;
			
			printf("%ld bytes from %s: icmp_seq=%d ttl=%d time=%0.1f ms\n", sizeof(EchoPacket), DestIp, seq, EchoPacket.ip.ttl, TimeElapsed);
			
			// Increment the message count
			RecvdMessageCount++;
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
	
	double TotalPingTime = (PingEndTime.tv_nsec - PingStartTime.tv_nsec) / 1000000;
	printf("\n--- %s ping statistics ---\n", DestIp);
	printf("%d packets transmitted, %d packets received, %d%% loss, time %f ms\n",
			seq, RecvdMessageCount, ((seq - RecvdMessageCount)/seq) * 100, TotalPingTime);
	
	return EXIT_SUCCESS;
}
