#pragma GCC diagnostic ignored "-fpermissive"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <map>
#include <ctime>
#include <vector>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/time.h>
#include <algorithm>
#include <net/if.h>
#include "Shared-1to1.h"

#define MAXBUFSIZE 65536

//Variable to hold information on current configuration
ConfigInfo currentConf;

//Function for transmitting data using multicast UDP using IPv6
int doSend(char* data, int dataLen)
{
  int sock, status, socklen;
  char buffer[MAXBUFSIZE];
  struct sockaddr_in6 saddr;
  struct in6_addr iaddr;
  int ttl = 3;
  int loopback = 1;

  //Set content of struct saddr and imreq to zero
  memset(&saddr, 0, sizeof(struct sockaddr_in6));
  memset(&iaddr, 0, sizeof(struct in6_addr));

  //Create UDP socket
  sock = socket(PF_INET6, SOCK_DGRAM, 0);
  if (sock < 0)
  {
    perror("Error creating socket");
    exit(0);
  }

  //Configure and bind socket
  saddr.sin6_family = PF_INET6;
  saddr.sin6_port = htons(0); //Use first free port
  saddr.sin6_addr = in6addr_any; //Bind socket to any interface
  status = bind(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in6));

  if (status < 0)
  {
    perror("Error binding socket to interface");
    exit(0);
  }

  //Set the outgoing interface
  if(strcmp(currentConf.interface, "DEFAULT") == 0)
  {
    //Set the outgoing interface to DEFAULT
    iaddr = in6addr_any;
    status = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &iaddr, sizeof(struct in6_addr));
  }
  else
  {
    //Set the outgoing interface to one specified in configuration
    unsigned int outif = if_nametoindex(currentConf.interface);
    status = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &outif, sizeof(outif));
  }
  if (status < 0)
    perror("Error settings socket option IPV6_MULTICAST_IF.");

  //Set multicast packet TTL to 3; default TTL is 1
  status = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl));
  if (status < 0)
    perror("Error settings socket option IPV6_MULTICAST_HOPS.");

  //Send multicast traffic to own IP also
  status = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loopback, sizeof(loopback));
  if (status < 0)
    perror("Error settings socket option IPV6_MULTICAST_LOOP.");

  //Set destination multicast address and port (according to settings from configuration)
  saddr.sin6_family = PF_INET6;
  inet_pton(AF_INET6, currentConf.IP, &(saddr.sin6_addr));
  saddr.sin6_port = htons(currentConf.port);

  //Put some data in buffer
  //strcpy(buffer, "Hello world\n");
  memcpy(buffer, data, dataLen);

  socklen = sizeof(struct sockaddr_in6);
  //Send packet to socket
  status = sendto(sock, buffer, dataLen, 0, (struct sockaddr *)&saddr, socklen);

  //Gets the destination address as a string
  char dstAddrStr[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &saddr.sin6_addr, dstAddrStr, INET6_ADDRSTRLEN);

  //printf("Sent: %s\n", buffer);
  db_printf("Sent: %i bytes to %s.\n", dataLen, dstAddrStr);

  //Shutdown socket
  shutdown(sock, 2);
  //Close socket
  close(sock);

  return 0;
}

//Function for transmitting data using unicast UDP to a specific node using IPv6
int doSendUnicast(char* data, int dataLen, struct in6_addr dstAddr)
{
  int sock, status, socklen;
  char buffer[MAXBUFSIZE];
  struct sockaddr_in6 saddr;
  struct in6_addr iaddr;

  //Set content of struct saddr and imreq to zero
  memset(&saddr, 0, sizeof(struct sockaddr_in6));
  memset(&iaddr, 0, sizeof(struct in6_addr));

  //Create UDP socket
  sock = socket(PF_INET6, SOCK_DGRAM, 0);
  if (sock < 0)
  {
    perror("Error creating socket");
    exit(0);
  }

  //Configure and bind socket
  saddr.sin6_family = PF_INET6;
  saddr.sin6_port = htons(0); //Use first free port
  saddr.sin6_addr = in6addr_any; //Bind socket to any interface

  status = bind(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in6));
  if (status < 0)
  {
    perror("Error binding socket to interface");
    exit(0);
  }

  //Set destination address and port (according to setting from configuration and argument to function)
  saddr.sin6_family = PF_INET6;
  saddr.sin6_addr = dstAddr;
  //inet_pton(AF_INET6, currentConf.IP, &(saddr.sin6_addr));
  saddr.sin6_port = htons(currentConf.port);

  //Put some data in buffer
  //strcpy(buffer, "Hello world\n");
  memcpy(buffer, data, dataLen);

  socklen = sizeof(struct sockaddr_in6);

  //Send packet to socket
  status = sendto(sock, buffer, dataLen, 0, (struct sockaddr *)&saddr, socklen);

  //Gets the destination address as a string
  char dstAddrStr[INET6_ADDRSTRLEN];
  inet_ntop(AF_INET6, &saddr.sin6_addr, dstAddrStr, INET6_ADDRSTRLEN);

  //printf("Sent: %s\n", buffer);
  db_printf("Sent: %i bytes to %s.\n", dataLen, dstAddrStr);

  //Shutdown socket
  shutdown(sock, 2);
  //Close socket
  close(sock);

  return 0;
}

//Generates random alphanumeric string
void gen_random(char *s, const int len)
{
  static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  for (int i = 0; i < len; ++i)
  {
    s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
  }

  //s[len] = 0;
}

//Defined struct for information about a node so it can be stored in map
struct NodeInformation
{
  unsigned char nodeKey[32];
  struct in6_addr ipv6Addr;
};

//Prints overview of current nodes and subgroups
void printStatus(std::map<long int, NodeInformation> nodeList)
{
  typedef std::map<long int, NodeInformation>::iterator it_type;
  printf("\n");
  //printf("Summary of nodes:\n");
  printf(" nodeID\n");
  printf("--------------------------------------------\n");
  for(it_type iterator = nodeList.begin(); iterator != nodeList.end(); iterator++)
  {
    printf("%ld\n", iterator->first);
  }
}

/* Set up key manager (keying) information */

std::map<long int, NodeInformation> nodeList;
unsigned char newGroupKey[32];
unsigned char groupKey[32];

/* End Set up key manager (keying) information */

//Function for single leave of nodes (4.6)
void leave(long int leavingNodeID)
{
  //Generate newGroupKey
  gen_random(newGroupKey, 32);
  db_printf("newGroupKey: ");
  for(int i = 0 ; i < 32 ; i++)
    db_printf("%c", newGroupKey[i]);
  db_printf("\n");
  
  //Retrieves information on leaving node
  NodeInformation leavingNode = nodeList[leavingNodeID];
  
  //Prepare LEAVE Message type to each node  // |TYPE 1B|{New group key 32B}Node Key|
  typedef std::map<long int, NodeInformation>::iterator nit_type;
  for(nit_type iterator = nodeList.begin(); iterator != nodeList.end(); iterator++)
  {
    unsigned char buffer[160];
    buffer[0] = LEAVE;
    
    //Encrypted part (newGroupKey) encrypted w. nodeKey
    unsigned char cleartext[120], ciphertext[120];
    memcpy(cleartext, newGroupKey, 32);
    doAESEncrypt((iterator->second).nodeKey, cleartext, 32, ciphertext);
    memcpy(buffer + 1, ciphertext, 48);
    
    //Send LEAVE3 Message
    doSendUnicast(buffer, 1 + 48, (iterator->second).ipv6Addr);
    printf("Sent LEAVE message.\n");
    
    //Sleep before sending other message
    usleep(1000000);
  }
  
  /* Updates key manager information according to section 4.5.6 */

  //Deletes tokens and information associated with the leavingNode
  nodeList.erase(leavingNodeID);
  
  //Switch to new groupKey for next iteration
  memcpy(groupKey, newGroupKey, 32);   
}

int main(int arc, char *argv[])
{

 //Generate random groupKey
 gen_random(groupKey, 32);
 
 //Reads configuration information from file
 currentConf = readConfig("KeyManager-1to1.cfg");

 //For Snapshot mode
 uint8_t SnapMode = 0;
 uint8_t SnapCounter = 0;
 char SnapCommand[15] = "JJJJJJJJJJJJJJJ";
 char SnapRime[15 * 23] = "00:12:74:02:00:02:02:0200:12:74:03:00:03:03:0300:12:74:04:00:04:04:0400:12:74:05:00:05:05:0500:12:74:06:00:06:06:0600:12:74:07:00:07:07:0700:12:74:08:00:08:08:0800:12:74:09:00:09:09:0900:12:74:0a:00:0a:0a:0a00:12:74:0b:00:0b:0b:0b00:12:74:0c:00:0c:0c:0c00:12:74:0d:00:0d:0d:0d00:12:74:0e:00:0e:0e:0e00:12:74:0f:00:0f:0f:0f00:12:74:10:00:10:10:10";
 double cpu1, cpu0 = 0;

 //User interface loop
 while(1)
 {
  //Calculate computing time
  cpu1 = (double)clock() / CLOCKS_PER_SEC;
  if (cpu0 != 0) printf("Time elapsed in second: %f\n", cpu1 - cpu0);

  /* Asks user for command to perform */
  char command[15];
  printf("\n\n\n\n");
  printf("Enter command to execute. (J)oin, (L)eave, (T)opology, (S)napshot: ");

  //Calculate computing time
  cpu0  = (double)clock() / CLOCKS_PER_SEC;

  if (SnapMode == 1) command[0] = SnapCommand[SnapCounter];
  else scanf("%10s", command);
  
  //User chooses to print the current topology
  if(command[0] == 'T' || command[0] == 't')
  {
    printStatus(nodeList);
    printf("\n");
    continue;
  }
  //User chooses to execute the leave procedure
  else if(command[0] == 'L' || command[0] == 'l')
  {
    long int deleteNodeID;
    printf("Enter nodeID to delete: ");
    scanf("%ld", &deleteNodeID);
    
    //Checks if requested nodeID exists
    std::map<long int, NodeInformation>::iterator trg;
    trg = nodeList.find(deleteNodeID);
    if(trg == nodeList.end())
    {
      printf("NodeID does not exist!\n");
      continue;
    }
    else
    {
      leave(deleteNodeID);
      continue;
    }
  }
  else if(command[0] == 'S' || command[0] == 's')
  {
    SnapMode = 1;
    continue;
  }
  //User enters invalid command
  else if(command[0] != 'J' && command[0] != 'j')
  {
    printf("Invalid command!\n");
    continue;
  }

 
  /* Performs the join procedure (beginning 4.3) */
  
  //Asks user for Rime address of node (the node's IP is calculated from this)
  char nodeRimeAddress[24];
  printf("Enter Rime address of node: ");
  if (SnapMode == 1) {
    memcpy(nodeRimeAddress, &SnapRime[SnapCounter * 23], 23 * sizeof(char));
    nodeRimeAddress[23] = 0;
  }
  else scanf("%23s", nodeRimeAddress);

  //Generate refreshKey
  gen_random(newGroupKey, 32);
  db_printf("newGroupKey: ");
  for(int i = 0 ; i < 32 ; i++)
    db_printf("%c", newGroupKey[i]);
  db_printf("\n");
  
  //Open file to write configuration for joining node  
  FILE * fp;
  fp = fopen ("file.txt", "w");

  //Create struct instance for the new node
  NodeInformation newNode;  

  //Generate and store the groupKey
  cfg_printf(fp, "%s", "(new) groupKey (hex): ");
  for(int i = 0 ; i < 32 ; i++)
    cfg_printf(fp, "%02x", newGroupKey[i]);
  cfg_printf(fp, "%s", "\n");

  //Generate and store the nodeKey
  gen_random(newNode.nodeKey, 32);
  cfg_printf(fp, "%s", "nodeKey: ");
  for(int i = 0 ; i < 32 ; i++)
    cfg_printf(fp, "%02x", newNode.nodeKey[i]);
  cfg_printf(fp, "%s", "\n");
  
  //Generate nodeID in milliseconds
  long int nodeID;
  nodeID = time(NULL);
  #ifndef DEBUG
  printf("nodeID: %ld\n", nodeID);
  #endif
  cfg_printf(fp, "nodeID: %ld\n", nodeID);

  //Prepare JOIN Message type to group  // |TYPE 1B|{New Group key 32B}KG|
  unsigned char buffer[120];
  buffer[0] = JOIN;
    
  //Encrypted part (refreshKey) encrypted w. groupKey
  unsigned char cleartext[220], ciphertext[220];
  memcpy(cleartext, newGroupKey, 32);
  int ciphertext_len = doAESEncrypt(groupKey, cleartext, 32, ciphertext);
    
  memcpy(buffer + 1, ciphertext, ciphertext_len);
    
  //Send JOIN Message
  doSend(buffer, 1 + ciphertext_len);
  printf("Sent JOIN message.\n");

  //Checks to see that a valid Rime address has been input
  if(strlen(nodeRimeAddress) != 23)
  {
    printf("Error: Invalid Rime address!\n");
    memset(nodeRimeAddress, 0x00, 23);
  }
  
  //Flip bit 7 in nodeRimeAddress (note that it is stored as ASCII characters)
  nodeRimeAddress[1] -= 0x30; //Convert to integer
  nodeRimeAddress[1] |= 2;    //Flip bit 7
  nodeRimeAddress[1] += 0x30; //Convert back to ASCII
 
  char nodeIPv6Address[80]; 
  strcpy(nodeIPv6Address, "aaaa::");
  for(unsigned int n = 6, i = 0 ; i < strlen(nodeRimeAddress) ; n += 5, i += 6)
  {
    nodeIPv6Address[n + 0]  = nodeRimeAddress[i + 0];
    nodeIPv6Address[n + 1]  = nodeRimeAddress[i + 1];
    nodeIPv6Address[n + 2]  = nodeRimeAddress[i + 3];
    nodeIPv6Address[n + 3]  = nodeRimeAddress[i + 4];
    nodeIPv6Address[n + 4]  = ':';
  }
  nodeIPv6Address[25] = '\0';

  inet_pton(AF_INET6, nodeIPv6Address, &(newNode.ipv6Addr));
  cfg_printf(fp, "NodeIP: %s\n", nodeIPv6Address);  


  //Checks if this nodeID is already in the nodeList (overlap due to too fast creation, max is 1/second)
  if(nodeList.count(nodeID) != 0)
    printf("Warning: Node ID already exists!\n");

  //Store the struct instance describing the new node in map
  nodeList.insert(std::pair<long int, NodeInformation>(nodeID, newNode));
  
  //Switch to new groupKey for next iteration
  memcpy(groupKey, newGroupKey, 32); 

  //printStatus(subgroupList);
  printf("\n\n");
  
  //Sleeps to separate new node/subgroup creation
  usleep(1000000);
  
    
  //Close configuration file for new node
  fclose (fp);
 
  //Renames node configuration file according to nodeID of new node
  char name[30];
  snprintf(name, 29, "%ld", nodeID);
  strcat(name, ".nocfg");
  rename("file.txt", name);
  printf("Output node configuration file: %s\n", name);
  SnapCounter++;
  //Update old node configuration files
  if ((SnapMode == 1) && (SnapCounter == 15)) {
    //Updates node tokens for remaining nodes in compromised subgroups (hashing existing tokens with refreshKey)
    typedef std::map<long int, NodeInformation>::iterator nit_type;
    for(nit_type iterator1 = nodeList.begin(); iterator1 != nodeList.end(); iterator1++)
    {
      //Open file to write configuration for joining node  
      FILE * fp;
      snprintf(name, 29, "%ld", iterator1->first);
      strcat(name, ".nocfg");
      fp = fopen (name, "w");

      //Get new groupKey
      cfg_printf(fp, "%s", "(new) groupKey (hex): ");
      for(int i = 0 ; i < 32 ; i++)
        cfg_printf(fp, "%02x", newGroupKey[i]);
      cfg_printf(fp, "%s", "\n");

      //Create struct instance for the new node
      cfg_printf(fp, "%s", "nodeKey: ");
      for(int i = 0 ; i < 32 ; i++)
        cfg_printf(fp, "%02x", (iterator1->second).nodeKey[i]);
      cfg_printf(fp, "%s", "\n");

      //Get nodeID
      cfg_printf(fp, "nodeID: %ld\n", iterator1->first);

      inet_ntop(AF_INET6, &((iterator1->second).ipv6Addr), nodeIPv6Address, INET6_ADDRSTRLEN);
      cfg_printf(fp, "NodeIP: %s\n", nodeIPv6Address);  

      //Sleeps to separate new node/subgroup creation
      usleep(100000);
    
      //Close configuration file for new node
      fclose (fp);
      printf("Output node configuration updated: %s\n", name);
    }
  SnapMode = 0;
  SnapCounter = 0;
  }
 }
}

