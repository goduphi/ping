# Ping
This program was written as a submission for an internship position at Cloudflare.  

### API's used:
- Sockets API in C   

### Resources used:
- Practical Guide for Programmers - 2nd Edition  
Author: Michael J. Donaho, Kenneth L. Calvert
- https://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
- https://www.geeksforgeeks.org/ping-in-c/
  
### Compilation instructions:
```gcc ./ping.c -o ping -g```  

Note: This program currently only supports IPv4 addresses. 

### Usage
```sudo ./ping [-t ttl] destination```  

Note: The program needs to be run using sudo as it makes use of raw sockets.

### Features
A custom Time to Live (TTL) value can be set using the -t flag.
