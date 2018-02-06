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
#include "Shared.h"

#define MAXBUFSIZE 65536

//Variable to hold information on current configuration
ConfigInfo currentConf;

static  uint8_t packetLen = 70;		// number of bytes can be send excluding 8-byte UDP headerstatic
static double cpu1, cpu0 = 0;
static double cpu3, cpu2 = 0;

//Function for transmitting data using multicast UDP using IPv6
//int doSend(char* data, int dataLen)
int doSend(uint8_t* header, uint8_t headerLen, uint8_t* payload, uint8_t payloadLen)
{
  int sock, status, socklen;
  uint8_t buffer[MAXBUFSIZE];
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

  //Fragmentation
  uint8_t nframes;
  uint8_t ind;
  uint8_t j;
  uint8_t currentFragLen;
  uint8_t type = header[0];
  char dstAddrStr[INET6_ADDRSTRLEN];
  
/*
  printf("Header and Payload: ");
  for(j = 0; j < headerLen; j++) printf("%02x", header[j]);
  for(j = 0; j < payloadLen; j++) printf("%02x", payload[j]);
  printf("\n");
*/
  if (headerLen + payloadLen > packetLen) nframes = (payloadLen/(packetLen - headerLen - 1)) + 1;
  else {
    if ((type == 7) || (type == 11)) nframes = (payloadLen/(packetLen - headerLen - 2)) + 1;
    else nframes = 1;
  }
  printf("Number of frame: %d; type: %d\n", nframes, type);

  if ((type == 7) || (type == 11) || (nframes != 1)) {
    for(ind = 1; ind < nframes + 1; ind++) {
      if ((payloadLen - (ind * (packetLen - headerLen - 1))) < 0) {
	if ((type == 7) || (type == 11)) currentFragLen = payloadLen + packetLen - (nframes  * (packetLen - headerLen - 2));
        else currentFragLen = payloadLen + packetLen - (nframes  * (packetLen - headerLen - 1));
      }
      else currentFragLen = packetLen;

      memcpy(buffer, header, headerLen);
      memcpy(buffer + headerLen, &ind, sizeof(ind));

      if ((type == 7) || (type == 11)) {
	memcpy(buffer + headerLen + 1, &nframes, sizeof(nframes));
	memcpy(buffer + headerLen + 2, payload + ((ind - 1) * (packetLen - headerLen - 2)), currentFragLen - headerLen - 2);
      }
      else {
	memcpy(buffer + headerLen + 1, payload + ((ind - 1) * (packetLen - headerLen - 1)), currentFragLen - headerLen - 1);
      }

      socklen = sizeof(struct sockaddr_in6);

      //Send packet to socket
      status = sendto(sock, buffer, currentFragLen, 0, (struct sockaddr *)&saddr, socklen);
      inet_ntop(AF_INET6, &saddr.sin6_addr, dstAddrStr, INET6_ADDRSTRLEN);
      //printf("Sent: %s\n", buffer);
      db_printf("Sent: %i bytes to %s.\n", currentFragLen, dstAddrStr);
      memset(buffer, 0, MAXBUFSIZE);
      usleep(1500000);
    }
  }
  else {
    memcpy(buffer, header, headerLen);
    memcpy(buffer + headerLen, payload, payloadLen);

    socklen = sizeof(struct sockaddr_in6);

    //Send packet to socket
    status = sendto(sock, buffer, headerLen + payloadLen, 0, (struct sockaddr *)&saddr, socklen);
    inet_ntop(AF_INET6, &saddr.sin6_addr, dstAddrStr, INET6_ADDRSTRLEN);
    //printf("Sent: %s\n", buffer);
    db_printf("Sent: %i bytes to %s.\n", headerLen + payloadLen, dstAddrStr);
    usleep(1500000);
  }

  //Shutdown socket
  shutdown(sock, 2);
  //Close socket
  close(sock);

  return 0;
}

//Function for transmitting data using unicast UDP to a specific node using IPv6
//int doSendUnicast(char* data, int dataLen, struct in6_addr dstAddr)
int doSendUnicast(uint8_t* header, uint8_t headerLen, uint8_t* payload, uint8_t payloadLen, struct in6_addr dstAddr)
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
  //memcpy(buffer, data, dataLen);

  //Fragmentation
  uint8_t nframes;
  uint8_t ind;
  uint8_t j;
  uint8_t currentFragLen;
  uint8_t type = REKEY2;
  char dstAddrStr[INET6_ADDRSTRLEN];
  
/*
  printf("Header and Payload for REKEY2: ");
  for(j = 0; j < headerLen; j++) printf("%02x", header[j]);
  for(j = 0; j < payloadLen; j++) printf("%02x", payload[j]);
  printf("\n");
*/
  nframes = (payloadLen/(packetLen - headerLen - 2)) + 1;
  printf("Number of frame: %d; type: %d\n", nframes, type);

  for(ind = 1; ind < nframes + 1; ind++) {
    if ((payloadLen - (ind * (packetLen - headerLen - 2))) < 0) {
      currentFragLen = payloadLen + packetLen - (nframes  * (packetLen - headerLen - 2));
    }
    else currentFragLen = packetLen;

    memcpy(buffer, header, headerLen);
    memcpy(buffer + headerLen, &ind, sizeof(ind));

    memcpy(buffer + headerLen + 1, &nframes, sizeof(nframes));
    memcpy(buffer + headerLen + 2, payload + ((ind - 1) * (packetLen - headerLen - 2)), currentFragLen - headerLen - 2);

    socklen = sizeof(struct sockaddr_in6);

    //Send packet to socket
    status = sendto(sock, buffer, currentFragLen, 0, (struct sockaddr *)&saddr, socklen);

    //Gets the destination address as a string
    char dstAddrStr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &saddr.sin6_addr, dstAddrStr, INET6_ADDRSTRLEN);

    //printf("Sent: %s\n", buffer);
    db_printf("Sent: %i bytes to %s.\n", currentFragLen, dstAddrStr);
    memset(buffer, 0, MAXBUFSIZE);
    usleep(500000);
  }

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
  long int subgroupID;
  unsigned char nodeTokenBackward[32];
  unsigned char nodeTokenForward[32];
  unsigned char nodeKey[32];
  unsigned char masterNodeToken[32];
  struct in6_addr ipv6Addr;
};

//Defined struct for information about a subgroup so it can be stored in map
struct SubgroupInformation
{
  std::vector<long int> nodeIDs;
  unsigned char subgroupTokenBackward[32];
  unsigned char subgroupTokenForward[32];
  unsigned char subgroupKey[32];
  unsigned char masterSubgroupToken[32];
};

//Prints overview of current nodes and subgroups
void printStatus(std::map<long int, SubgroupInformation> subgroupList)
{
  typedef std::map<long int, SubgroupInformation>::iterator it_type;
  printf("\n");
  //printf("Summary of subgroups and nodes:\n");
  printf(" subgroupID | nodeID\n");
  printf("--------------------------------------------\n");
  for(it_type iterator = subgroupList.begin(); iterator != subgroupList.end(); iterator++)
  {
    printf("%ld  | ", iterator->first);
    
    std::vector<long int> containedNodes = (iterator->second).nodeIDs;
    for (size_t i = 0; i < containedNodes.size(); i++)
      printf("%ld ", containedNodes[i]);
    printf("\n");
  }
}

/* Set up key manager (keying) information */

std::map<long int, NodeInformation> nodeList;
std::map<long int, SubgroupInformation> subgroupList;
unsigned char refreshKey[32];
unsigned char groupKey[32];

/* End Set up key manager (keying) information */

//Function for sending DATA message encrypted with groupKey to all nodes in group
int sendDataMessage(char* data, int dataLen)
{
  char buffer[150];
  buffer[0] = DATA;
  
  unsigned char cleartext[220], ciphertext[220];
  memcpy(cleartext, data, dataLen);
  int ciphertext_len = doAESEncrypt(groupKey, cleartext, dataLen, ciphertext);
  //memcpy(buffer + 1, ciphertext, ciphertext_len);
  
  return doSend(buffer, 1, ciphertext, ciphertext_len);
}

//Function for multiple leave (recovery) of nodes (4.7)
void recovery(std::vector<long int> compromisedNodes)
{
  //for(unsigned int i = 0 ; i < compromisedNodes.size() ; i++)
  //  printf("%ld\n", compromisedNodes[i]);
    
  //Creates vector of compromised subgroups
  std::vector<long int> compromisedSubgroups;
  for(unsigned int i = 0 ; i < compromisedNodes.size() ; i++)
  {
    //If nodeID exists add its subgroupID
    if(nodeList.find(compromisedNodes[i]) != nodeList.end())
    {
      NodeInformation theNode = nodeList[compromisedNodes[i]];
      compromisedSubgroups.push_back(theNode.subgroupID);
    }
  }
  
  //Removes duplicate values from vector  
  sort(compromisedSubgroups.begin(), compromisedSubgroups.end());
  compromisedSubgroups.erase(unique(compromisedSubgroups.begin(), compromisedSubgroups.end()), compromisedSubgroups.end());
  
  db_printf("Compromised subgroups: ");
  for(unsigned int i = 0 ; i < compromisedSubgroups.size() ; i++)
    db_printf("%ld ", compromisedSubgroups[i]);
  db_printf("\n");
  
  //Return if no nodes or no subgroups are compromised (or if only 1 node since the leave function should be used then)
  if(compromisedNodes.size() == 0 || compromisedNodes.size() == 1 || compromisedSubgroups.size() == 0)
    return;
  
  //Creates vector of subgroups where all nodes are compromised, and one of subgroups where one more (but not all) nodes are compromised
  std::vector<long int> allNodesCompromisedSubgroups;
  std::vector<long int> someNodesCompromisedSubgroups;
  for(unsigned int i = 0 ; i < compromisedSubgroups.size() ; i++)
  {
    SubgroupInformation theSubgroup = subgroupList[compromisedSubgroups[i]];
    
    //Checks the list of nodeIDs in a subgroup and check if all are contained in compromisedNodes
    bool exists = true;
    for(unsigned int n = 0 ; n < theSubgroup.nodeIDs.size() ; n++)
    {
      if(std::find(compromisedNodes.begin(), compromisedNodes.end(), theSubgroup.nodeIDs[n]) == compromisedNodes.end())
       exists = false;
    }
    
    if(exists != false)
    {
      allNodesCompromisedSubgroups.push_back(compromisedSubgroups[i]);  
    }
    else
    {
      someNodesCompromisedSubgroups.push_back(compromisedSubgroups[i]);
    }
  }
    
  db_printf("All nodes compromised subgroups: ");
  for(unsigned int i = 0 ; i < allNodesCompromisedSubgroups.size() ; i++)
    db_printf("%ld ", allNodesCompromisedSubgroups[i]);
  db_printf("\n");
  
  db_printf("Some nodes compromised subgroups (not all): ");
  for(unsigned int i = 0 ; i < someNodesCompromisedSubgroups.size() ; i++)
    db_printf("%ld ", someNodesCompromisedSubgroups[i]);
  db_printf("\n");
  
  //Generate refreshKey
  gen_random(refreshKey, 32);
  db_printf("refreshKey: ");
  for(int i = 0 ; i < 32 ; i++)
    db_printf("%c", refreshKey[i]);
  db_printf("\n");

  //Generate new groupKey (using refreshKey and old groupKey)
  unsigned char newGroupKey[32];
  doHMAC(groupKey, 32, refreshKey, 32, newGroupKey);
  db_printf("(new) groupKey (hex): ");
  for(int i = 0 ; i < 32 ; i++)
    db_printf("%02x", newGroupKey[i]);
  db_printf("\n");
  
  //Performs local rekeying of subgroups that have one or more nodes (not all) compromised (REKEY1 & REKEY2)
  for(unsigned int subgroup_i = 0 ; subgroup_i < someNodesCompromisedSubgroups.size() ; subgroup_i++)
  {
    long int theSubgroupID = someNodesCompromisedSubgroups[subgroup_i];
    SubgroupInformation theSubgroup = subgroupList[theSubgroupID];
  
    printf("\nPerforming local rekeying for subgroup %ld:\n", theSubgroupID);
      
    //Generate new subgroupKey (using refreshKey and old subgroupKey)
    unsigned char newSubgroupKey[32];
    doHMAC(theSubgroup.subgroupKey, 32, refreshKey, 32, newSubgroupKey);
    db_printf("(new) subGroupKey (hex): ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", newSubgroupKey[i]);
    db_printf("\n");
  
    //Creates vector of compromisedNodes in this subgroup
    std::vector<long int> compromisedNodesInSubgroup;
    for(unsigned n = 0 ; n < compromisedNodes.size() ; n++)
      if(nodeList[compromisedNodes[n]].subgroupID == theSubgroupID)
        compromisedNodesInSubgroup.push_back(compromisedNodes[n]);
        
    //Sorts the vector of compromisedNodes (Kiki mentioned this would be helpful to reduce processing on nodes)
    sort(compromisedNodesInSubgroup.begin(), compromisedNodesInSubgroup.end());
        
    db_printf("Compromised nodes in subgroup %ld: ", theSubgroupID);
    for(unsigned n = 0 ; n < compromisedNodesInSubgroup.size() ; n++)
      db_printf("%ld ", compromisedNodesInSubgroup[n]);
    printf("\n");
    
    //Find oldest and newest compromisedNodes
    long int oldestCompromisedNode = *std::min_element(compromisedNodesInSubgroup.begin(), compromisedNodesInSubgroup.end());
    long int newestCompromisedNode = *std::max_element(compromisedNodesInSubgroup.begin(), compromisedNodesInSubgroup.end());
    db_printf("oldestCompromisedNode: %ld\n", oldestCompromisedNode);
    db_printf("newestCompromisedNode: %ld\n", newestCompromisedNode);
    
    /* Rekeys uncompromised nodes in subgroup that have joined before the oldestCompromisedNode or after the newestCompromisedNode (REKEY1) */
       
    //Checks if there are suitable nodes to rekey in this way
    db_printf("Uncompromised nodes older than oldestCompromisedNode or newer than newestCompromisedNode: ");
    bool exists = false;
    for(unsigned int n = 0 ; n < theSubgroup.nodeIDs.size() ; n++)
      if(theSubgroup.nodeIDs[n] < oldestCompromisedNode || theSubgroup.nodeIDs[n] > newestCompromisedNode)
      {
        db_printf("%ld ", theSubgroup.nodeIDs[n]);
        exists = true;    
      }
    printf("\n");
      
    //If suitable nodes exist to rekey in this manner
    if(exists)
    {
      //Prepare REKEY1 Message type to subgroup
      // |TYPE 1B|Receiver subgroup ID 4B|Compromised nodes in subgroup # 1B|Compromised nodes in subgroup list 4*#B|{Refresh key 32B}KF|{Refresh key 32B}KB|

      unsigned char buffer[540];
      uint8_t cipher[240];
      uint8_t ciphertext_len;
      buffer[0] = REKEY1;
    
      unsigned char tempID[4];
      tempID[3] = (theSubgroupID >> 24) & 0xFF; tempID[2] = (theSubgroupID >> 16) & 0xFF;
      tempID[1] = (theSubgroupID >> 8) & 0xFF;  tempID[0] = (theSubgroupID) & 0xFF;
      memcpy(buffer + 1, tempID, 4);
    
      buffer[1 + 4] = compromisedNodesInSubgroup.size();
           
      for(unsigned int n = 0 ; n < compromisedNodesInSubgroup.size() ; n++)
      {
        tempID[3] = (compromisedNodesInSubgroup[n] >> 24) & 0xFF; tempID[2] = (compromisedNodesInSubgroup[n] >> 16) & 0xFF;
        tempID[1] = (compromisedNodesInSubgroup[n] >> 8) & 0xFF;  tempID[0] = (compromisedNodesInSubgroup[n]) & 0xFF;
        memcpy(cipher + n * 4, tempID, 4); 
      }
      
      //Generate keys to be used for encrypting refreshKey
      unsigned char keyForward[32];
      //doHMAC(nodeList[oldestCompromisedNode].nodeTokenForward, 32, nodeList[oldestCompromisedNode].nodeTokenForward, 32, keyForward);
      unsigned char staticData[32] = "abcdefghijklmnopqrstuvwxyzABCDEF";
      doHMAC(nodeList[oldestCompromisedNode].nodeTokenForward, 32, staticData, 32, keyForward);
      db_printf("keyForward (hex): ");
      for(int i = 0 ; i < 32 ; i++)
        db_printf("%02x", keyForward[i]);
      db_printf("\n");
    
      unsigned char keyBackward[32];
      //doHMAC(nodeList[newestCompromisedNode].nodeTokenBackward, 32, nodeList[newestCompromisedNode].nodeTokenBackward, 32, keyBackward);
      doHMAC(nodeList[newestCompromisedNode].nodeTokenBackward, 32, staticData, 32, keyBackward);
      db_printf("keyBackward (hex): ");
      for(int i = 0 ; i < 32 ; i++)
        db_printf("%02x", keyBackward[i]);
      db_printf("\n");
    
      //Encrypted part (refreshKey) encrypted w. keyForward
      unsigned char cleartext[120], ciphertext[120];
      memcpy(cleartext, refreshKey, 32);
      ciphertext_len = doAESEncrypt(keyForward, cleartext, 32, ciphertext);
      //memcpy(buffer + 1 + 4 + 1 + 4 * compromisedNodesInSubgroup.size(), ciphertext, 48);
      memcpy(cipher + 4 * compromisedNodesInSubgroup.size(), ciphertext, ciphertext_len);
    
      //Encrypted part (refreshKey) encrypted w. keyBackward
      memcpy(cleartext, refreshKey, 32);
      ciphertext_len = doAESEncrypt(keyBackward, cleartext, 32, ciphertext);
      //memcpy(buffer + 1 + 4 + 1 + 4 * compromisedNodesInSubgroup.size() + 48, ciphertext, 48);
      memcpy(cipher + 4 * compromisedNodesInSubgroup.size() + ciphertext_len, ciphertext, ciphertext_len);

      //Waits a moment before sending REKEY1 message
      usleep(1000000);
   
      //Send REKEY1 Message
      //doSend(buffer, 1 + 4 + 1 + 4 * compromisedNodesInSubgroup.size() + 48 + 48);
      doSend(buffer, 1 + 4 + 1, cipher, 4 * compromisedNodesInSubgroup.size() + 2 * ciphertext_len);
      printf("Sent RM1 message.\n");

      //Calculate computing time
      cpu3 = (double)clock() / CLOCKS_PER_SEC;
      if (cpu2 != 0) printf("Time elapsed in second (each message): %f\n", cpu3 - cpu2);
      cpu2  = (double)clock() / CLOCKS_PER_SEC;
    }          
    
    /* Rekeys uncompromised nodes in this subgroup that have joined between the oldestCompromisedNode and the newestCompromisedNode (REKEY2) */
      
    db_printf("Uncompromised nodes in subgroup %ld that have joined between the oldestCompromisedNode and the newestCompromisedNode: ", theSubgroupID);
    for(unsigned int n = 0 ; n < theSubgroup.nodeIDs.size() ; n++)
      if(theSubgroup.nodeIDs[n] > oldestCompromisedNode && theSubgroup.nodeIDs[n] < newestCompromisedNode)
      {
        if(std::find(compromisedNodes.begin(), compromisedNodes.end(), theSubgroup.nodeIDs[n]) == compromisedNodes.end())
          db_printf("%ld ", theSubgroup.nodeIDs[n]);
      }
      printf("\n");
    
    for(unsigned int n = 0 ; n < theSubgroup.nodeIDs.size() ; n++)
      if(theSubgroup.nodeIDs[n] > oldestCompromisedNode && theSubgroup.nodeIDs[n] < newestCompromisedNode)
      {    
        //Prepare REKEY2 Message type to subgroup
        // |TYPE 1B|Receiver node ID 4B|{Compromised nodes in subgroup # 1B|Compromised nodes in subgroup list 4*#B|Refresh key 32B}Ku|
        
        long int theNodeID = theSubgroup.nodeIDs[n];
        
        //If this is a compromised node do not rekey it
        if(std::find(compromisedNodes.begin(), compromisedNodes.end(), theNodeID) != compromisedNodes.end())
        {
          db_printf("\nSkipped local rekeying for node %ld in subgroup %ld (compromised)\n", theNodeID, theSubgroupID);
          continue;
        }
        
        db_printf("\nPerforming local rekeying for node %ld in subgroup %ld:\n", theNodeID, theSubgroupID);
      
        unsigned char buffer[540];
        uint8_t cipher[240];
        buffer[0] = REKEY2;
    
        unsigned char tempID[4];
        tempID[3] = (theNodeID >> 24) & 0xFF; tempID[2] = (theNodeID >> 16) & 0xFF;
        tempID[1] = (theNodeID >> 8) & 0xFF;  tempID[0] = (theNodeID) & 0xFF;
        memcpy(buffer + 1, tempID, 4);
    
        //Prepare encrypted three parts encrypted w. nodeKey
        unsigned char cleartext[4 * compromisedNodesInSubgroup.size() + 200], ciphertext[4 * compromisedNodesInSubgroup.size() + 200];    
        cleartext[0] = compromisedNodesInSubgroup.size();
           
        for(unsigned int n = 0 ; n < compromisedNodesInSubgroup.size() ; n++)
        {
          tempID[3] = (compromisedNodesInSubgroup[n] >> 24) & 0xFF; tempID[2] = (compromisedNodesInSubgroup[n] >> 16) & 0xFF;
          tempID[1] = (compromisedNodesInSubgroup[n] >> 8) & 0xFF;  tempID[0] = (compromisedNodesInSubgroup[n]) & 0xFF;
          memcpy(cleartext + 1 + n * 4, tempID, 4); 
        }
      
        memcpy(cleartext + 1 + 4 * compromisedNodesInSubgroup.size(), refreshKey, 32);
        
        //Encrypted three parts encrypted w. nodeKey
        int ciphertext_len = doAESEncrypt(nodeList[theNodeID].nodeKey, cleartext, 1 + 4 * compromisedNodesInSubgroup.size() + 32, ciphertext);
        memcpy(cipher, ciphertext, ciphertext_len);

        //Waits a moment before sending REKEY2 message
        usleep(1000000);

        //Send REKEY2 Message
        //doSend(buffer, 1 + 4 + ciphertext_len);
        doSendUnicast(buffer, 1 + 4, cipher, ciphertext_len, nodeList[theNodeID].ipv6Addr);
        printf("Sent RM2 message.\n"); 

        //Calculate computing time
        cpu3 = (double)clock() / CLOCKS_PER_SEC;
        if (cpu2 != 0) printf("Time elapsed in second (each message): %f\n", cpu3 - cpu2);
        cpu2  = (double)clock() / CLOCKS_PER_SEC;
      }
      

    //Switch to new subgroupKey for next iteration
    memcpy(subgroupList[theSubgroupID].subgroupKey, newSubgroupKey, 32);
  }
  
  
    /* Rekeys uncompromised subgroups that have joined before the oldestCompromisedSubgroup or after the newestCompromisedSubgroup (REKEY3) */
    
    //Find oldest and newest compromisedSubgroups
    long int oldestCompromisedSubgroup = *std::min_element(compromisedSubgroups.begin(), compromisedSubgroups.end());
    long int newestCompromisedSubgroup = *std::max_element(compromisedSubgroups.begin(), compromisedSubgroups.end());
    db_printf("oldestCompromisedSubgroup: %ld\n", oldestCompromisedSubgroup);
    db_printf("newestCompromisedSubgroup: %ld\n", newestCompromisedSubgroup);
       
    //Creates vector of uncompromised subgroups
    std::vector<long int> uncompromisedSubgroups;
    typedef std::map<long int, SubgroupInformation>::iterator sit_type;
    for(sit_type iterator = subgroupList.begin(); iterator != subgroupList.end(); iterator++)
    {
      long int theID = iterator->first;
      if(std::find(compromisedSubgroups.begin(), compromisedSubgroups.end(), theID) == compromisedSubgroups.end())
        uncompromisedSubgroups.push_back(theID);   
    }
    
    db_printf("No nodes compromised subgroups: ");
    for(unsigned int i = 0 ; i < uncompromisedSubgroups.size() ; i++)
      db_printf("%ld ", uncompromisedSubgroups[i]);
    db_printf("\n"); 
    
    //Checks if there are suitable subgroups to rekey in this way
    db_printf("Uncompromised subgroups older than oldestCompromisedSubgroup or newer than newestCompromisedSubgroup: ");
    bool exists = false;
    for(unsigned int n = 0 ; n < uncompromisedSubgroups.size() ; n++)
      if(uncompromisedSubgroups[n] < oldestCompromisedSubgroup || uncompromisedSubgroups[n] > newestCompromisedSubgroup)
      {
        db_printf("%ld ", uncompromisedSubgroups[n]);
        exists = true;    
      }
    printf("\n");
    
    //If suitable subgroups exist to rekey in this manner
    if(exists)
    {
      //Prepare REKEY3 Message type to group
      // |TYPE 1B|Oldest compromised subgroup ID 4B|Newest compromised subgroup ID 4B|{Refresh key 32B}KFS|{Refresh key 32B}KBS|
      
      printf("\nPerforming global rekeying for group:\n");
      
      unsigned char buffer[540];
      uint8_t cipher[240];
      uint8_t ciphertext_len;
      buffer[0] = REKEY3;
    
      unsigned char tempID[4];
      tempID[3] = (oldestCompromisedSubgroup >> 24) & 0xFF; tempID[2] = (oldestCompromisedSubgroup >> 16) & 0xFF;
      tempID[1] = (oldestCompromisedSubgroup >> 8) & 0xFF;  tempID[0] = (oldestCompromisedSubgroup) & 0xFF;
      memcpy(cipher, tempID, 4);
    
      tempID[3] = (newestCompromisedSubgroup >> 24) & 0xFF; tempID[2] = (newestCompromisedSubgroup >> 16) & 0xFF;
      tempID[1] = (newestCompromisedSubgroup >> 8) & 0xFF;  tempID[0] = (newestCompromisedSubgroup) & 0xFF;
      memcpy(cipher + 4, tempID, 4);
     
      //Generate keys to be used for encrypting refreshKey
      unsigned char keyForward[32];
      //doHMAC(subgroupList[oldestCompromisedSubgroup].subgroupTokenForward, 32, subgroupList[oldestCompromisedSubgroup].subgroupTokenForward, 32, keyForward);
      unsigned char staticData[32] = "abcdefghijklmnopqrstuvwxyzABCDEF";
      doHMAC(subgroupList[oldestCompromisedSubgroup].subgroupTokenForward, 32, staticData, 32, keyForward);
      db_printf("keyForward (hex): ");
      for(int i = 0 ; i < 32 ; i++)
        db_printf("%02x", keyForward[i]);
      db_printf("\n");
    
      unsigned char keyBackward[32];
      //doHMAC(subgroupList[newestCompromisedSubgroup].subgroupTokenBackward, 32, subgroupList[newestCompromisedSubgroup].subgroupTokenBackward, 32, keyBackward);
      doHMAC(subgroupList[newestCompromisedSubgroup].subgroupTokenBackward, 32, staticData, 32, keyBackward);
      db_printf("keyBackward (hex): ");
      for(int i = 0 ; i < 32 ; i++)
        db_printf("%02x", keyBackward[i]);
      db_printf("\n");
    
      //Encrypted part (refreshKey) encrypted w. keyForward
      unsigned char cleartext[120], ciphertext[120];
      memcpy(cleartext, refreshKey, 32);
      ciphertext_len = doAESEncrypt(keyForward, cleartext, 32, ciphertext);
      //memcpy(buffer + 1 + 4 + 4, ciphertext, 48);
      memcpy(cipher + 4 + 4, ciphertext, ciphertext_len);
    
      //Encrypted part (refreshKey) encrypted w. keyBackward
      memcpy(cleartext, refreshKey, 32);
      ciphertext_len = doAESEncrypt(keyBackward, cleartext, 32, ciphertext);
      // memcpy(buffer + 1 + 4 + 4 + 48, ciphertext, 48);
      memcpy(cipher + 4 + 4 + ciphertext_len, ciphertext, ciphertext_len);

      //Waits a moment before sending REKEY3 message
      usleep(1000000);
    
      //Send REKEY3 Message
      //doSend(buffer, 1 + 4 + 4 + 48 + 48);
      doSend(buffer, 1, cipher, 4 + 4 + 2 * ciphertext_len);
      printf("Sent RM3 message.\n");
      
      //Calculate computing time
      cpu3 = (double)clock() / CLOCKS_PER_SEC;
      if (cpu2 != 0) printf("Time elapsed in second (each message): %f\n", cpu3 - cpu2);
      cpu2  = (double)clock() / CLOCKS_PER_SEC;
    } 
    
    /* Rekeys uncompromised subgroups that have joined between the oldestCompromisedSubgroup and the newestCompromisedSubgroup (REKEY4) */

    for(unsigned int subgroup_i = 0 ; subgroup_i < uncompromisedSubgroups.size() ; subgroup_i++)
    {
      long int theSubgroupID = uncompromisedSubgroups[subgroup_i];
      SubgroupInformation theSubgroup = subgroupList[theSubgroupID];
          
      //If suitable subgroups exist to rekey in this manner (IDs between oldestCompromisedSubgroup and newestCompromisedSubgroup)
      if(theSubgroupID > oldestCompromisedSubgroup && theSubgroupID < newestCompromisedSubgroup)
      {
        //Prepare REKEY4 Message type to subgroup
        // |TYPE 1B|Receiver subgroup ID 4B|{Refresh key 32B}KS||
        
        printf("\nPerforming global rekeying for subgroup %ld:\n", theSubgroupID);
        
        unsigned char buffer[540];
        uint8_t cipher[240];
        uint8_t ciphertext_len;
        buffer[0] = REKEY4;
    
        unsigned char tempID[4];
        tempID[3] = (theSubgroupID >> 24) & 0xFF; tempID[2] = (theSubgroupID >> 16) & 0xFF;
        tempID[1] = (theSubgroupID >> 8) & 0xFF;  tempID[0] = (theSubgroupID) & 0xFF;
        memcpy(buffer + 1, tempID, 4);
     
        //Encrypted part (refreshKey) encrypted w. subgroupKey
        unsigned char cleartext[120], ciphertext[120];
        memcpy(cleartext, refreshKey, 32);
        ciphertext_len = doAESEncrypt(theSubgroup.subgroupKey, cleartext, 32, ciphertext);
        //memcpy(buffer + 1 + 4, ciphertext, 48);
	    memcpy(cipher, ciphertext, 48);

        //Waits a moment before sending REKEY4 message
        usleep(1000000);

        //Send REKEY4 Message
        //doSend(buffer, 1 + 4 + 48);
	doSend(buffer, 1 + 4, cipher, ciphertext_len);
        printf("Sent RM4 message.\n");

        //Calculate computing time
        cpu3 = (double)clock() / CLOCKS_PER_SEC;
        if (cpu2 != 0) printf("Time elapsed in second (each message): %f\n", cpu3 - cpu2);
        cpu2  = (double)clock() / CLOCKS_PER_SEC;      
    } 
  }
  
  //Switch to new groupKey for next iteration (note that this has to be done before creating REKEY5 message)
  memcpy(groupKey, newGroupKey, 32); 
  
  /* Sends message to group with information about empty subgroups */
  //Check if any empty groups were created (all nodes are compromised)
  int emptySubgroupCount = allNodesCompromisedSubgroups.size();
  if(emptySubgroupCount != 0)
  {
    //Prepare REKEY5 Message type to group
    // |TYPE 1B|Empty subgroups in group # 1B|{Empty subgroups in group list 4*#B}KG|
      
    printf("\nSends information about now empty subgroups:\n");
    
    unsigned char buffer[540];
    buffer[0] = REKEY5;
    
    buffer[1] = emptySubgroupCount;
    db_printf("Number of empty subgroups: %i\n", emptySubgroupCount);

    //Encrypted part (list of empty subgroups) encrypted w. groupKey
    unsigned char cleartext[4 * emptySubgroupCount + 100], ciphertext[4 * emptySubgroupCount + 100];
    unsigned char tempID[4];
    for(int n = 0 ; n < emptySubgroupCount ; n++)
    {
      tempID[3] = (allNodesCompromisedSubgroups[n] >> 24) & 0xFF; tempID[2] = (allNodesCompromisedSubgroups[n] >> 16) & 0xFF;
      tempID[1] = (allNodesCompromisedSubgroups[n] >> 8) & 0xFF;  tempID[0] = (allNodesCompromisedSubgroups[n]) & 0xFF;
      memcpy(cleartext + n * 4, tempID, 4); 
    }
    
    int ciphertext_len = doAESEncrypt(groupKey, cleartext, 4 * emptySubgroupCount, ciphertext);
    //memcpy(buffer + 1 + 1, ciphertext, ciphertext_len);

    //Waits a moment before sending REKEY5 message
    usleep(1000000);

    //Send REKEY5 Message
    //doSend(buffer, 1 + 1 + ciphertext_len);
    doSend(buffer, 1 + 1, ciphertext, ciphertext_len);
    printf("Sent RM5 message.\n");
  }       
  
  /* Updates key manager information according to section 4.7 */

  //Deletes tokens and information associated with the compromisedNodes
  for(unsigned int i = 0 ; i < compromisedNodes.size() ; i++)
    nodeList.erase(compromisedNodes[i]);
  
  //Deletes compromised node IDs from vector kept in the subgroups (list named nodeIDs)
  db_printf("Deleting information about compromised nodes: ");
  typedef std::map<long int, SubgroupInformation>::iterator sit_type;
  for(sit_type iterator = subgroupList.begin(); iterator != subgroupList.end(); iterator++)
  {
    SubgroupInformation theSubgroup = iterator->second;
     
    //If a nodeID exists in the compromisedNodes list delete it
    for(unsigned int n = 0 ; n < theSubgroup.nodeIDs.size() ; n++)
      if (std::find(compromisedNodes.begin(), compromisedNodes.end(), theSubgroup.nodeIDs[n]) != compromisedNodes.end())
      {
        db_printf("%ld ", theSubgroup.nodeIDs[n]);
        
        //First set the nodeID to -1
        (iterator->second).nodeIDs[n] = -1;
      }
      
    //Now perform the deletion of all -1 values
    ((iterator->second).nodeIDs).erase(std::remove(((iterator->second).nodeIDs).begin(), ((iterator->second).nodeIDs).end(), -1), ((iterator->second).nodeIDs).end());   
  }
  db_printf("\n");

  //Deletes subgroups that are now empty
  db_printf("Deleting information empty subgroups: ");
  std::vector<long int> toBeDeleted;
  typedef std::map<long int, SubgroupInformation>::iterator sit_type;
  for(sit_type iterator = subgroupList.begin(); iterator != subgroupList.end(); iterator++)
  {
    SubgroupInformation theSubgroup = iterator->second;
  
    //If the list of node IDs in this node is empty add it for deletion
    if(theSubgroup.nodeIDs.size() == 0)
    {
      db_printf("%ld ", iterator->first);
      toBeDeleted.push_back(iterator->first);
    }
  }
  db_printf("\n");
  for(unsigned int i = 0 ; i < toBeDeleted.size() ; i++)
    subgroupList.erase(toBeDeleted[i]);
  
  //Updates node tokens for remaining nodes in compromised subgroups (hashing existing tokens with refreshKey)
  typedef std::map<long int, NodeInformation>::iterator nit_type;
  for(nit_type iterator = nodeList.begin(); iterator != nodeList.end(); iterator++)
  {
    db_printf("*Node ID %ld. Subgroup ID %ld:\n", iterator->first, (iterator->second).subgroupID);
    
    db_printf("Existing nodeTokenBackward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).nodeTokenBackward[i]);
    db_printf("\n");
      
    db_printf("Existing nodeTokenForward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).nodeTokenForward[i]);
    db_printf("\n");
  
    //Checks that this node is in a compromised subgroup
    if(std::find(someNodesCompromisedSubgroups.begin(), someNodesCompromisedSubgroups.end(), (iterator->second).subgroupID) != someNodesCompromisedSubgroups.end())
    {
      //Update nodeTokenBackward using refreshKey and old nodeTokenBackward
      doSHA(refreshKey, 32, (iterator->second).nodeTokenBackward, 32, (iterator->second).nodeTokenBackward);
    
      //Update nodeTokenForward using refreshKey and old nodeTokenForward
      doSHA(refreshKey, 32, (iterator->second).nodeTokenForward, 32, (iterator->second).nodeTokenForward);
    }
    
    db_printf("New nodeTokenBackward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).nodeTokenBackward[i]);
    db_printf("\n");
      
    db_printf("New nodeTokenForward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).nodeTokenForward[i]);
    db_printf("\n");
  }
  
  //Updates subgroup tokens for remaining subgroups
  typedef std::map<long int, SubgroupInformation>::iterator sit_type;
  for(sit_type iterator = subgroupList.begin(); iterator != subgroupList.end(); iterator++)
  {
    db_printf("*Subgroup ID %ld:\n", iterator->first);
    
    db_printf("Existing subgroupTokenBackward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).subgroupTokenBackward[i]);
    db_printf("\n");
      
    db_printf("Existing subgroupTokenForward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).subgroupTokenForward[i]);
    db_printf("\n");
  
    //Update subgroupTokenBackward using refreshKey and old subgroupTokenBackward
    doSHA(refreshKey, 32, (iterator->second).subgroupTokenBackward, 32, (iterator->second).subgroupTokenBackward);
    
    //Update subgroupTokenForward using refreshKey and old subgroupTokenForward
    doSHA(refreshKey, 32, (iterator->second).subgroupTokenForward, 32, (iterator->second).subgroupTokenForward);

    db_printf("New subgroupTokenBackward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).subgroupTokenBackward[i]);
    db_printf("\n");
      
    db_printf("New subgroupTokenForward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).subgroupTokenForward[i]);
    db_printf("\n");
  }

}

//Function for single leave of nodes (4.6)
void leave(long int leavingNodeID)
{
  //Generate refreshKey
  gen_random(refreshKey, 32);
  db_printf("refreshKey: ");
  for(int i = 0 ; i < 32 ; i++)
    db_printf("%c", refreshKey[i]);
  db_printf("\n");

  //Generate new groupKey (using refreshKey and old groupKey)
  unsigned char newGroupKey[32];
  doHMAC(groupKey, 32, refreshKey, 32, newGroupKey);
  db_printf("(new) groupKey (hex): ");
  for(int i = 0 ; i < 32 ; i++)
    db_printf("%02x", newGroupKey[i]);
  db_printf("\n");
  
  //Retrieves information on leaving node
  NodeInformation leavingNode = nodeList[leavingNodeID];
  long int leavingSubgroupID = leavingNode.subgroupID;
  SubgroupInformation leavingSubgroup = subgroupList[leavingSubgroupID];
  
  printf("Leaving nodeID: %ld\n", leavingNodeID);
  printf("Leaving subgroupID: %ld\n", leavingSubgroupID);
  
  //Generate new subgroupKey (using refreshKey and old subgroupKey)
  unsigned char newSubgroupKey[32];
  doHMAC(leavingSubgroup.subgroupKey, 32, refreshKey, 32, newSubgroupKey);
  db_printf("(new) subGroupKey (hex): ");
  for(int i = 0 ; i < 32 ; i++)
    db_printf("%02x", newSubgroupKey[i]);
  db_printf("\n");
  
  //If leavingNodeID is only node in its subgroup
  if(leavingSubgroup.nodeIDs.size() == 1)
  {
    //Prepare LEAVE3 Message type to group  // |TYPE 1B|Leaving Subgroup ID 4B|{Refresh key 32B}KFS|{Refresh key 32B}KBS|
    unsigned char buffer[160];
    uint8_t cipher[96];
    uint8_t ciphertext_len;
    buffer[0] = LEAVE3;
    
    unsigned char tempID2[4];
    tempID2[3] = (leavingSubgroupID >> 24) & 0xFF; tempID2[2] = (leavingSubgroupID >> 16) & 0xFF;
    tempID2[1] = (leavingSubgroupID >> 8) & 0xFF;  tempID2[0] = (leavingSubgroupID) & 0xFF;
    memcpy(buffer + 1, tempID2, 4);
    
    //Generate keys to be used for encrypting refreshKey
    unsigned char keyForwardSubgroup[32];
    //doHMAC(leavingSubgroup.subgroupTokenForward, 32, leavingSubgroup.subgroupTokenForward, 32, keyForwardSubgroup);
    unsigned char staticData[32] = "abcdefghijklmnopqrstuvwxyzABCDEF";
    doHMAC(leavingSubgroup.subgroupTokenForward, 32, staticData, 32, keyForwardSubgroup);
    db_printf("keyForwardSubgroup (hex): ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", keyForwardSubgroup[i]);
    db_printf("\n");
    
    unsigned char keyBackwardSubgroup[32];
    //doHMAC(leavingSubgroup.subgroupTokenBackward, 32, leavingSubgroup.subgroupTokenBackward, 32, keyBackwardSubgroup);
    doHMAC(leavingSubgroup.subgroupTokenBackward, 32, staticData, 32, keyBackwardSubgroup);
    db_printf("keyBackwardSubgroup (hex): ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", keyBackwardSubgroup[i]);
    db_printf("\n");
    
    //Encrypted part (refreshKey) encrypted w. keyForwardSubgroup
    unsigned char cleartext[120], ciphertext[120];
    memcpy(cleartext, refreshKey, 32);
    ciphertext_len = doAESEncrypt(keyForwardSubgroup, cleartext, 32, ciphertext);
    //memcpy(buffer + 4 + 1, ciphertext, 48);
    memcpy(cipher, ciphertext, ciphertext_len);
    
    //Encrypted part (refreshKey) encrypted w. keyBackwardSubgroup
    memcpy(cleartext, refreshKey, 32);
    ciphertext_len = doAESEncrypt(keyBackwardSubgroup, cleartext, 32, ciphertext);
    //memcpy(buffer + 4 + 1 + 48, ciphertext, 48);
    memcpy(cipher + ciphertext_len, ciphertext, ciphertext_len);
    
    //Send LEAVE3 Message
    //doSend(buffer, 1 + 4 + 48 + 48);
    doSend(buffer, 1 + 4, cipher, 2 * ciphertext_len);
    printf("Sent LM3 message.\n");  
  }
  //If there are other nodes in the subgroup of leavingNodeID
  else
  {
    //Prepare LEAVE1 Message type to subgroup  // |TYPE 1B|Receiver subgroup ID 4B|Leaving Node ID 4B|{Refresh key 32B}KF|{Refresh key 32B}KB|
    unsigned char buffer[140];
    uint8_t cipher[96];
    uint8_t ciphertext_len;
    buffer[0] = LEAVE1;
    
    unsigned char tempID[4];
    tempID[3] = (leavingSubgroupID >> 24) & 0xFF; tempID[2] = (leavingSubgroupID >> 16) & 0xFF;
    tempID[1] = (leavingSubgroupID >> 8) & 0xFF;  tempID[0] = (leavingSubgroupID) & 0xFF;
    memcpy(buffer + 1, tempID, 4);
    
    tempID[3] = (leavingNodeID >> 24) & 0xFF; tempID[2] = (leavingNodeID >> 16) & 0xFF; tempID[1] = (leavingNodeID >> 8) & 0xFF; tempID[0] = (leavingNodeID) & 0xFF;
    memcpy(buffer + 1 + 4, tempID, 4);
    
    //Generate keys to be used for encrypting refreshKey
    unsigned char keyForward[32];
    //doHMAC(leavingNode.nodeTokenForward, 32, leavingNode.nodeTokenForward, 32, keyForward);
    unsigned char staticData[32] = "abcdefghijklmnopqrstuvwxyzABCDEF";
    doHMAC(leavingNode.nodeTokenForward, 32, staticData, 32, keyForward);
    db_printf("keyForward (hex): ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", keyForward[i]);
    db_printf("\n");
    
    unsigned char keyBackward[32];
    uint8_t j;
    printf("====================================\n");
    printf("leavingNode.nodeTokenBackward: ");
    for(j = 0; j < 32; j++) printf("%02x", leavingNode.nodeTokenBackward[j]);
    printf("\nkeyBackward: ");
    for(j = 0; j < 32; j++) printf("%02x", keyBackward[j]);
    //doHMAC(leavingNode.nodeTokenBackward, 32, leavingNode.nodeTokenBackward, 32, keyBackward);
    doHMAC(leavingNode.nodeTokenBackward, 32, staticData, 32, keyBackward);
    printf("\nafter-leavingNode.nodeTokenBackward: ");
    for(j = 0; j < 32; j++) printf("%02x", leavingNode.nodeTokenBackward[j]);
    printf("\nafter-keyBackward: ");
    for(j = 0; j < 32; j++) printf("%02x", keyBackward[j]);
    printf("\n");
    printf("====================================\n");
    db_printf("keyBackward (hex): ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", keyBackward[i]);
    db_printf("\n");
    
    //Encrypted part (refreshKey) encrypted w. keyForward
    unsigned char cleartext[120], ciphertext[120];
    memcpy(cleartext, refreshKey, 32);

    ciphertext_len = doAESEncrypt(keyForward, cleartext, 32, ciphertext);

    printf("====================================\n");
    printf("Clear text: ");
    for(j = 0; j < 32; j++) printf("%02x", cleartext[j]);
    printf("\nKey: ");
    for(j = 0; j < 32; j++) printf("%02x", keyForward[j]);
    printf("\nCipher text: ");
    for(j = 0; j < ciphertext_len; j++) printf("%02x", ciphertext[j]);
    printf("\n");
    printf("====================================\n");

    //memcpy(buffer + 1 + 4 + 4, ciphertext, 48);
    memcpy(cipher, ciphertext, ciphertext_len);

    //Encrypted part (refreshKey) encrypted w. keyBackward
    memcpy(cleartext, refreshKey, 32); 
    ciphertext_len = doAESEncrypt(keyBackward, cleartext, 32, ciphertext);

    printf("====================================\n");
    printf("Clear text: ");
    for(j = 0; j < 32; j++) printf("%02x", cleartext[j]);
    printf("\nKey: ");
    for(j = 0; j < 32; j++) printf("%02x", keyBackward[j]);
    printf("\nCipher text: ");
    for(j = 0; j < ciphertext_len; j++) printf("%02x", ciphertext[j]);
    printf("\n");
    printf("====================================\n");

    //memcpy(buffer + 1 + 4 + 4 + 48, ciphertext, 48);
    memcpy(cipher + ciphertext_len, ciphertext, ciphertext_len);

    //Send LEAVE1 Message
    //doSend(buffer, 1 + 4 + 4 + 48 + 48);
    doSend(buffer, 1 + 4 + 4, cipher, 2 * ciphertext_len);
    printf("Sent LM1 message.\n");
    
    //Calculate computing time
    cpu3 = (double)clock() / CLOCKS_PER_SEC;
    if (cpu2 != 0) printf("Time elapsed in second (each message): %f\n", cpu3 - cpu2);
    cpu2  = (double)clock() / CLOCKS_PER_SEC;

    //Waits a moment before sending LEAVE2 message
    usleep(1000000);   
     
    //Prepare LEAVE2 Message type to group  // |TYPE 1B|Leaving Subgroup ID 4B|{Refresh key 32B}KFS|{Refresh key 32B}KBS|
    buffer[0] = LEAVE2;
    
    tempID[3] = (leavingSubgroupID >> 24) & 0xFF; tempID[2] = (leavingSubgroupID >> 16) & 0xFF;
    tempID[1] = (leavingSubgroupID >> 8) & 0xFF;  tempID[0] = (leavingSubgroupID) & 0xFF;
    memcpy(buffer + 1, tempID, 4);
    
    //Generate keys to be used for encrypting refreshKey
    unsigned char keyForwardSubgroup[32];
    //doHMAC(leavingSubgroup.subgroupTokenForward, 32, leavingSubgroup.subgroupTokenForward, 32, keyForwardSubgroup);
    doHMAC(leavingSubgroup.subgroupTokenForward, 32, staticData, 32, keyForwardSubgroup);
    db_printf("keyForwardSubgroup (hex): ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", keyForwardSubgroup[i]);
    db_printf("\n");
    
    unsigned char keyBackwardSubgroup[32];
    //doHMAC(leavingSubgroup.subgroupTokenBackward, 32, leavingSubgroup.subgroupTokenBackward, 32, keyBackwardSubgroup);
    doHMAC(leavingSubgroup.subgroupTokenBackward, 32, staticData, 32, keyBackwardSubgroup);
    db_printf("keyBackwardSubgroup (hex): ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", keyBackwardSubgroup[i]);
    db_printf("\n");
    
    //Encrypted part (refreshKey) encrypted w. keyForwardSubgroup
    //unsigned char cleartext[120], ciphertext[120];
    memcpy(cleartext, refreshKey, 32);
    ciphertext_len = doAESEncrypt(keyForwardSubgroup, cleartext, 32, ciphertext);
    //memcpy(buffer + 1 + 4, ciphertext, 48);
    memcpy(cipher, ciphertext, ciphertext_len);

    //Encrypted part (refreshKey) encrypted w. keyBackwardSubgroup
    memcpy(cleartext, refreshKey, 32);
    ciphertext_len = doAESEncrypt(keyBackwardSubgroup, cleartext, 32, ciphertext);
    //memcpy(buffer + 1 + 4 + 48, ciphertext, 48);
    memcpy(cipher + ciphertext_len, ciphertext, ciphertext_len);

    //Send LEAVE2 Message
    //doSend(buffer, 1 + 4 + 48 + 48);
    doSend(buffer, 1 + 4, cipher, 2 * ciphertext_len);
    printf("Sent LM2 message.\n");

  }
  
  /* Updates key manager information according to section 4.5.6 */

  //Deletes tokens and information associated with the leavingNode
  nodeList.erase(leavingNodeID);
  
  //Deletes nodeID from vector kept in the subgroup (nodeID list is subgroupList[leavingSubgroupID].nodeIDs)
  for(unsigned int i = 0 ; i < subgroupList[leavingSubgroupID].nodeIDs.size() ; i++)
    if(subgroupList[leavingSubgroupID].nodeIDs[i] == leavingNodeID)
      subgroupList[leavingSubgroupID].nodeIDs.erase(subgroupList[leavingSubgroupID].nodeIDs.begin() + i);

  //Delete subgroup of leavingNode if now empty
  if(subgroupList[leavingSubgroupID].nodeIDs.size() == 0)
    subgroupList.erase(leavingSubgroupID);
  
  //Updates node tokens for remaining nodes in same subgroup (hashing existing tokens with refreshKey)
  typedef std::map<long int, NodeInformation>::iterator nit_type;
  for(nit_type iterator = nodeList.begin(); iterator != nodeList.end(); iterator++)
  {
    db_printf("*Node ID %ld. Subgroup ID %ld:\n", iterator->first, (iterator->second).subgroupID);
    
    db_printf("Existing nodeTokenBackward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).nodeTokenBackward[i]);
    db_printf("\n");
      
    db_printf("Existing nodeTokenForward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).nodeTokenForward[i]);
    db_printf("\n");
  
    //Checks that this node is in the same as the leaving node
    if((iterator->second).subgroupID == leavingSubgroupID)
    {
      //Update nodeTokenBackward using refreshKey and old nodeTokenBackward
      doSHA(refreshKey, 32, (iterator->second).nodeTokenBackward, 32, (iterator->second).nodeTokenBackward);
    
      //Update nodeTokenForward using refreshKey and old nodeTokenForward
      doSHA(refreshKey, 32, (iterator->second).nodeTokenForward, 32, (iterator->second).nodeTokenForward);
    }
    
    db_printf("New nodeTokenBackward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).nodeTokenBackward[i]);
    db_printf("\n");
      
    db_printf("New nodeTokenForward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).nodeTokenForward[i]);
    db_printf("\n");
  }
  
  //Updates subgroup tokens for remaining subgroups
  typedef std::map<long int, SubgroupInformation>::iterator sit_type;
  for(sit_type iterator = subgroupList.begin(); iterator != subgroupList.end(); iterator++)
  {
    db_printf("*Subgroup ID %ld:\n", iterator->first);
    
    db_printf("Existing subgroupTokenBackward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).subgroupTokenBackward[i]);
    db_printf("\n");
      
    db_printf("Existing subgroupTokenForward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).subgroupTokenForward[i]);
    db_printf("\n");
  
    //Update subgroupTokenBackward using refreshKey and old subgroupTokenBackward
    doSHA(refreshKey, 32, (iterator->second).subgroupTokenBackward, 32, (iterator->second).subgroupTokenBackward);
    
    //Update subgroupTokenForward using refreshKey and old subgroupTokenForward
    doSHA(refreshKey, 32, (iterator->second).subgroupTokenForward, 32, (iterator->second).subgroupTokenForward);

    db_printf("New subgroupTokenBackward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).subgroupTokenBackward[i]);
    db_printf("\n");
      
    db_printf("New subgroupTokenForward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", (iterator->second).subgroupTokenForward[i]);
    db_printf("\n");
  }
  
  //Switch to new groupKey for next iteration
  memcpy(groupKey, newGroupKey, 32); 
  
  //Switch to new subgroupKey for next iteration (if subgroup has not been deleted above due to being empty)
  if(subgroupList.count(leavingSubgroupID) != 0)
    memcpy(subgroupList[leavingSubgroupID].subgroupKey, newSubgroupKey, 32);
  
}

int main(int arc, char *argv[])
{

 //Generate random groupKey
 gen_random(groupKey, 32);
 
 //Reads configuration information from file
 currentConf = readConfig("KeyManager.cfg");

 //For Snapshot mode
 uint8_t SnapMode = 0;
 uint8_t SnapCounter = 0;
 char SnapCommand[15 * 2] = "JNJNJ1JNJ0J2J2JNJNJ3J3J4J1J2J2";
 char SnapRime[15 * 23] = "00:12:74:02:00:02:02:0200:12:74:03:00:03:03:0300:12:74:04:00:04:04:0400:12:74:05:00:05:05:0500:12:74:06:00:06:06:0600:12:74:07:00:07:07:0700:12:74:08:00:08:08:0800:12:74:09:00:09:09:0900:12:74:0a:00:0a:0a:0a00:12:74:0b:00:0b:0b:0b00:12:74:0c:00:0c:0c:0c00:12:74:0d:00:0d:0d:0d00:12:74:0e:00:0e:0e:0e00:12:74:0f:00:0f:0f:0f00:12:74:10:00:10:10:10";

 //For Experiment mode
 uint8_t ExpMode = 0;
 uint8_t ExpCounter = 0;
 char ExpCommand[4] = "J2LR";
 char ExpRime[23] = "00:12:74:11:00:11:11:11";

 //User interface loop
 while(1)
 {
  //Calculate computing time
  cpu1 = (double)clock() / CLOCKS_PER_SEC;
  if (cpu0 != 0) printf("Time elapsed in second: %f\n", cpu1 - cpu0);
  cpu3 = (double)clock() / CLOCKS_PER_SEC;
  if (cpu2 != 0) printf("Time elapsed in second (each message): %f\n", cpu3 - cpu2);
  cpu2  = (double)clock() / CLOCKS_PER_SEC;
 
  /* Asks user for command to perform */
  char command[15];
  printf("\n\n\n\n");
  printf("Enter command to execute. (J)oin, (L)eave, (T)opology, (R)ecovery, (M)essage, (S)napshot, (E)xperiment : ");

  //Calculate computing time
  cpu0  = (double)clock() / CLOCKS_PER_SEC;
  cpu2  = (double)clock() / CLOCKS_PER_SEC;

  if (SnapMode == 1) command[0] = SnapCommand[2 * SnapCounter];
  else if (ExpMode == 1) command[0] = ExpCommand[ExpCounter++];
  else scanf("%10s", command);
  
  //User chooses to print the current topology
  if(command[0] == 'T' || command[0] == 't')
  {
    printStatus(subgroupList);
    printf("\n");
    continue;
  }
  //User chooses to execute the leave procedure
  else if(command[0] == 'L' || command[0] == 'l')
  {
    long int deleteNodeID;
    uint8_t j = 0;
    printf("Enter nodeID to delete: ");
    if (ExpMode == 1) {
      typedef std::map<long int, SubgroupInformation>::iterator it_type;
      for(it_type iterator = subgroupList.begin(); iterator != subgroupList.end(); iterator++)
      {
	if (j == 2) {
    	std::vector<long int> containedNodes = (iterator->second).nodeIDs;
	deleteNodeID = containedNodes[2];
    	}
	j++;
      }

      //Waits a moment before proceeding
      usleep(600000);
    }
    else scanf("%ld", &deleteNodeID);
    
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
  //User chooses to execute the multiple leave (recovery) procedure
  else if(command[0] == 'R' || command[0] == 'r')
  {
    //Read nodeIDs to be deleted and places them in a vector
    long int deleteNodeID;
    uint8_t j = 0;
    uint8_t k = 0;
    std::vector<long int> compromisedNodes;
    printf("Enter nodeIDs to delete (stop with 0): ");
    do
    {
      j = 0;
      if (ExpMode == 1) {
	typedef std::map<long int, SubgroupInformation>::iterator it_type;
	if (k == 0) {
          for(it_type iterator = subgroupList.begin(); iterator != subgroupList.end(); iterator++)
	  {
	    if (j == 2) {
	      std::vector<long int> containedNodes = (iterator->second).nodeIDs;
	      deleteNodeID = containedNodes[1];
    	    }
	    j++;
          }
	  k++;
	}
	else if (k == 1) {
          for(it_type iterator = subgroupList.begin(); iterator != subgroupList.end(); iterator++)
	  {
	    if (j == 2) {
	      std::vector<long int> containedNodes = (iterator->second).nodeIDs;
	      deleteNodeID = containedNodes[3];
    	    }
	    j++;
          }
	  k++;
	}
	else if (k == 2) {
          for(it_type iterator = subgroupList.begin(); iterator != subgroupList.end(); iterator++)
	  {
	    if (j == 4) {
	      std::vector<long int> containedNodes = (iterator->second).nodeIDs;
	      deleteNodeID = containedNodes[1];
    	    }
	    j++;
          }
	  k++;
	}
	else {
	  deleteNodeID = 0;
	  ExpMode = 0;
	}
      }
      else scanf("%ld", &deleteNodeID);
      if(deleteNodeID != 0)
        compromisedNodes.push_back(deleteNodeID);
      printf("Enter nodeID: ");
    } while(deleteNodeID != 0);
    printf("\n");
    
    //Calls function to perform recovery
    recovery(compromisedNodes);
    continue;
  }
  //User chooses to send DATA message encrypted with groupKey to other nodes
  else if(command[0] == 'M' || command[0] == 'm')
  {
    char userInput[100];
    printf("Enter message to send to nodes: ");
    //scanf("%99s", userInput);
    scanf(" %99[^\n]s", userInput);
    if(strlen(userInput) == 99)
      scanf(" %*[^\n]s"); //Discard further input over 99 characters
    sendDataMessage(userInput, strlen(userInput));
    continue;
  }
  else if(command[0] == 'S' || command[0] == 's')
  {
    SnapMode = 1;
    continue;
  }
  else if(command[0] == 'E' || command[0] == 'e')
  {
    ExpMode = 1;
    continue;
  }
  //User enters invalid command
  else if(command[0] != 'J' && command[0] != 'j')
  {
    printf("Invalid command!\n");
    continue;
  }

 
  /* Performs the join procedure (beginning 4.3) */

  //Prints existing subgroups and asks for a target subgroup to add new node to
  //Shows a simple menu use can choose from without writing full subgroupID
  long int targetSubgroup, selectedSubgroup;
  char temp[50];
  
  int listSize = subgroupList.size();
  long int subgroupSelect[listSize];
  int count = 0;
  
  printf("Existing subgroups: \n");
  typedef std::map<long int, SubgroupInformation>::iterator st_type;
  for(st_type iterator = subgroupList.begin(); iterator != subgroupList.end(); iterator++)
  {
    printf("(%i) %ld\n", count, iterator->first);
    subgroupSelect[count] = iterator->first;
    count++;
  }
   
  printf("Add to which subgroup? (N)ew | (A)bort | #: ");
  if (SnapMode == 1) temp[0] = SnapCommand[2 * SnapCounter + 1];
  else if (ExpMode == 1) temp[0] = ExpCommand[ExpCounter++];
  else scanf("%49s", temp);
  if(temp[0] == 'A' || temp[0] == 'a')
    continue;
  else if(temp[0] == 'N' || temp[0] == 'n')
    targetSubgroup = -1;
  else //Can either enter full subgroupID or short-hand choice number
  {
    sscanf(temp, "%ld", &selectedSubgroup);
    if((unsigned long int)selectedSubgroup < subgroupList.size())
      targetSubgroup = subgroupSelect[selectedSubgroup];
    else
      targetSubgroup = selectedSubgroup;
  }   
    
  std::map<long int, SubgroupInformation>::iterator it;
  it = subgroupList.find(targetSubgroup);

  //Asks user for Rime address of node (the node's IP is calculated from this)
  char nodeRimeAddress[24];
  printf("Enter Rime address of node: ");
  if (SnapMode == 1) memcpy(nodeRimeAddress, &SnapRime[SnapCounter * 23], 23 * sizeof(char));
  else if (ExpMode == 1) memcpy(nodeRimeAddress, &ExpRime, 23 * sizeof(char));
  else scanf("%23s", nodeRimeAddress);

  //Generate refreshKey
  gen_random(refreshKey, 32);
  db_printf("refreshKey: ");
  for(int i = 0 ; i < 32 ; i++)
    db_printf("%c", refreshKey[i]);
  db_printf("\n");
  
  //Open file to write configuration for joining node  
  FILE * fp;
  fp = fopen ("\Conf\file.txt", "w");
  
  //Generate new groupKey (using refreshKey and old groupKey)
  unsigned char newGroupKey[32];
  doHMAC(groupKey, 32, refreshKey, 32, newGroupKey);
  /*printf("(old) groupKey (hex): ");
  for(int i = 0 ; i < 32 ; i++)
    printf("%02x", groupKey[i]);
  printf("\n");*/
  cfg_printf(fp, "%s", "(new) groupKey (hex): ");
  for(int i = 0 ; i < 32 ; i++)
    cfg_printf(fp, "%02x", newGroupKey[i]);
  cfg_printf(fp, "%s", "\n");

  //Create struct instance for the new node
  NodeInformation newNode;  
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
  
  //Generate and store nodeTokenBackward
  gen_random(newNode.nodeTokenBackward, 32);
  db_printf("nodeTokenBackward: "); 
  for(int i = 0 ; i < 32 ; i++)
    db_printf("%02x", newNode.nodeTokenBackward[i]);
  db_printf("\n");
  
  //First generate masterNodeToken
  gen_random(newNode.masterNodeToken, 32);
    db_printf("masterNodeToken: "); 
  for(int i = 0 ; i < 32 ; i++)
    db_printf("%02x", newNode.masterNodeToken[i]);
  db_printf("\n");
    
  //Generate and store nodeTokenForward from masterNodeToken and refreshKey
  doHMAC(newNode.masterNodeToken, 32, refreshKey, 32, newNode.nodeTokenForward);
  db_printf("nodeTokenForward: "); 
  for(int i = 0 ; i < 32 ; i++)
    db_printf("%02x", newNode.nodeTokenForward[i]);
  db_printf("\n");

  //Asks for a target subgroup and checks if it exists
  /*long int targetSubgroup;
  printf("Add to which subgroup: ");
  scanf("%ld", &targetSubgroup);
  std::map<long int, SubgroupInformation>::iterator it;
  it = subgroupList.find(targetSubgroup);*/

  //If subgroup does not exist, create it
  if (it == subgroupList.end())
  {
    printf("Subgroup not found!\n");
    
    //Create struct instance for the new subgroup
    SubgroupInformation newSubgroup;
    
    //Generate and store the subgroupKey
    gen_random(newSubgroup.subgroupKey, 32);
    /*printf("subgroupKey: ");
    for(int i = 0 ; i < 32 ; i++)
      printf("%c", newSubgroup.subgroupKey[i]);
    printf("\n");*/
    cfg_printf(fp, "%s", "subGroupKey (hex): ");
    for(int i = 0 ; i < 32 ; i++)
      cfg_printf(fp, "%02x", newSubgroup.subgroupKey[i]);
    cfg_printf(fp, "%s", "\n");
      
    //Generate subgroupID in milliseconds
    long int subgroupID;
    subgroupID = time(NULL);
    #ifndef DEBUG
    printf("subgroupID: %ld\n", subgroupID);
    #endif
    cfg_printf(fp, "subgroupID: %ld\n", subgroupID);
    //Store subgroupID for for the new node
    newNode.subgroupID = subgroupID;
    
    //Prints information on existing nodes in subgroup
    cfg_printf(fp, "%s", "Information on currently existing nodes in this subgroup:\n");
    printf("-\n");
    
    //Generate and store subgroupTokenBackward
    gen_random(newSubgroup.subgroupTokenBackward, 32);
    db_printf("subgroupTokenBackward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", newSubgroup.subgroupTokenBackward[i]);
    db_printf("\n");
    
    //First generate masterSubgroupToken
    gen_random(newSubgroup.masterSubgroupToken, 32);
    db_printf("masterSubgroupToken: "); 
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", newSubgroup.masterSubgroupToken[i]);
    db_printf("\n");
  
    //Generate and store subgroupTokenForward from masterSubgroupToken and refreshKey
    doHMAC(newSubgroup.masterSubgroupToken, 32, refreshKey, 32, newSubgroup.subgroupTokenForward);
    db_printf("subgroupTokenForward: ");
    for(int i = 0 ; i < 32 ; i++)
      db_printf("%02x", newSubgroup.subgroupTokenForward[i]);
    db_printf("\n");
    
    //Adds this nodeID to list of nodeIDs in subgroup
    newSubgroup.nodeIDs.push_back(nodeID);
    
    //Checks if this subgroupID is already in the subgroupList (overlap due to too fast creation, max is 1/second)
    if(subgroupList.count(subgroupID) != 0)
      printf("Warning: Subgroup ID already exists!\n");
    
    //Store the struct instance describing the new subgroup in map
    subgroupList.insert(std::pair<long int, SubgroupInformation>(subgroupID, newSubgroup));
    
    //Prepare JOIN3 Message type to group  // |TYPE 1B|Joining subgroup ID 4B|{Joining master subgroup token 32B|Refresh key 32B}KG|
    unsigned char buffer[220];
    buffer[0] = JOIN3;
    
    unsigned char tempID[4];
    tempID[3] = (subgroupID >> 24) & 0xFF; tempID[2] = (subgroupID >> 16) & 0xFF; tempID[1] = (subgroupID >> 8) & 0xFF; tempID[0] = (subgroupID) & 0xFF;
    memcpy(buffer + 1, tempID, 4);
    
    //Encrypted parts (masterSubgroupToken and refreshKey) encrypted w. groupKey
    unsigned char cleartext[220], ciphertext[220];
    memcpy(cleartext, newSubgroup.masterSubgroupToken, 32);
    memcpy(cleartext + 32, refreshKey, 32);
    int ciphertext_len = doAESEncrypt(groupKey, cleartext, 32 + 32, ciphertext);
    uint8_t j;
    //memcpy(buffer + 1 + 4, ciphertext, ciphertext_len);

    //Send JOIN3 Message
	//doSend(buffer, 1 + 4 + ciphertext_len);
    if (SnapMode == 0) doSend(buffer, 1 + 4, ciphertext, ciphertext_len);
    printf("Sent JM3 message (%i byte).\n", 1 + 4 + ciphertext_len);
  }
  //If subgroup exists add the new to node to it
  else
  {
    //printf("Adding to existing subgroup: %ld\n", it->first);
      
    //Retrieve subgroup information from list
    SubgroupInformation theSubgroup = it->second;
    
    //Retrieve subgroupID
    long int subgroupID;
    subgroupID = it->first;
    #ifndef DEBUG
    printf("subgroupID: %ld\n", subgroupID);
    #endif
    //cfg_printf(fp, "subgroupID: %ld\n", subgroupID);
    //Store subgroupID for for the new node
    newNode.subgroupID = subgroupID;
    
    //Remove old information about subgroup
    subgroupList.erase(it);
    
    //Print the current subgroupKey
    /*printf("(old) subGroupKey (hex): ");
    for(int i = 0 ; i < 32 ; i++)
      printf("%02x", theSubgroup.subgroupKey[i]);
    printf("\n");*/
    
    //Generate new subgroupKey (using refreshKey and old subgroupKey)
    unsigned char newSubgroupKey[32];
    doHMAC(theSubgroup.subgroupKey, 32, refreshKey, 32, newSubgroupKey);
    //cfg_printf(fp, "%s", "(new) subGroupKey (hex): ");
    cfg_printf(fp, "%s", "subGroupKey (hex): ");
    for(int i = 0 ; i < 32 ; i++)
      cfg_printf(fp, "%02x", newSubgroupKey[i]);
    cfg_printf(fp, "%s", "\n");

    //Write subgroupID in node configuration file (down here because of order)
    cfg_printf(fp, "subgroupID: %ld\n", subgroupID);
    
    //Prints information on existing nodes in subgroup (needed for new nodes as described in 4.4)
    cfg_printf(fp, "%s", "Information on currently existing nodes in this subgroup:\n");
    for (size_t i = 0; i < theSubgroup.nodeIDs.size(); i++)
    {
      long int subgroupNode = theSubgroup.nodeIDs[i];
      cfg_printf(fp, "nodeID nodeTokenBackward: %ld ", subgroupNode);
      
      for(int n = 0 ; n < 32 ; n++)
        cfg_printf(fp, "%02x", nodeList[subgroupNode].nodeTokenBackward[n]);
      cfg_printf(fp, "%s", "\n");
    }
       
    //Adds this nodeID to list of nodeIDs in subgroup
    theSubgroup.nodeIDs.push_back(nodeID); 
  
    //Prepare JOIN1 Message type to this subgroup  // |TYPE 1B|Receiver subgroup ID 4B|Joining node ID 4B|{Joining node master node token 32B|Refresh key 32B}KS|
    unsigned char buffer[120];
    buffer[0] = JOIN1;
    
    unsigned char tempID[4];
    tempID[3] = (subgroupID >> 24) & 0xFF; tempID[2] = (subgroupID >> 16) & 0xFF; tempID[1] = (subgroupID >> 8) & 0xFF; tempID[0] = (subgroupID) & 0xFF;
    memcpy(buffer + 1, tempID, 4);
    
    unsigned char tempID2[4];
    tempID2[3] = (nodeID >> 24) & 0xFF; tempID2[2] = (nodeID >> 16) & 0xFF; tempID2[1] = (nodeID >> 8) & 0xFF; tempID2[0] = (nodeID) & 0xFF;
    memcpy(buffer + 1 + 4, tempID2, 4);
    
    //Encrypted part (joining masterNodeToken and refreshKey) encrypted w. subgroupKey
    unsigned char cleartext[220], ciphertext[220];
    memcpy(cleartext, newNode.masterNodeToken, 32);
    memcpy(cleartext + 32, refreshKey, 32);
    int ciphertext_len = doAESEncrypt(theSubgroup.subgroupKey, cleartext, 32 + 32, ciphertext);
    uint8_t j;
    //memcpy(buffer + 1 + 4 + 4, ciphertext, ciphertext_len);

    //Send JOIN1 Message
    //doSend(buffer, 1 + 4 + 4 + ciphertext_len);
    if (SnapMode == 0) doSend(buffer, 1 + 4 + 4, ciphertext, ciphertext_len);
    printf("Sent JM1 message.\n");

    //Calculate computing time
    cpu3 = (double)clock() / CLOCKS_PER_SEC;
    if (cpu2 != 0) printf("Time elapsed in second (each message): %f\n", cpu3 - cpu2);
    cpu2  = (double)clock() / CLOCKS_PER_SEC;
    
    //Waits a moment before sending JOIN2 message
    usleep(1000000);
        
    //Prepare JOIN2 Message type to group  // |TYPE 1B|{Refresh key 32B}KG|
    buffer[0] = JOIN2;
    
    //Encrypted part (refreshKey) encrypted w. groupKey
    memcpy(cleartext, refreshKey, 32);
    ciphertext_len = doAESEncrypt(groupKey, cleartext, 32, ciphertext);
    
    memcpy(buffer + 1, ciphertext, ciphertext_len);
    
    //Send JOIN2 Message
    //doSend(buffer, 1 + ciphertext_len);
    if (SnapMode == 0) doSend(buffer, 1, ciphertext, ciphertext_len);
    printf("Sent JM2 message.\n");
     
    //Switch to new subgroupKey for next iteration
    memcpy(theSubgroup.subgroupKey, newSubgroupKey, 32);
    
    //Store the struct instance describing the updated subgroup in map
    subgroupList.insert(std::pair<long int, SubgroupInformation>(subgroupID, theSubgroup));
  }
      
  //Prints information on existing older subgroups in group (needed for new nodes as described in 4.4)
  cfg_printf(fp, "%s", "Information on currently existing older subgroups:\n");
  typedef std::map<long int, SubgroupInformation>::iterator it_type;
  for(it_type iterator = subgroupList.begin(); iterator != subgroupList.end(); iterator++)
  {
    if(newNode.subgroupID > iterator->first) //Is this subgroup older than the one the node is member of
    {
      cfg_printf(fp, "subgroupID subgroupTokenBackward: %ld ", iterator->first);
      
      for(int n = 0 ; n < 32 ; n++)
        cfg_printf(fp, "%02x", (iterator->second).subgroupTokenBackward[n]);
      cfg_printf(fp, "%s", "\n");
    }
  }
  
  //Prints information on existing newer subgroups in group (needed for new nodes as described in 4.4)
  cfg_printf(fp, "%s", "Information on currently existing newer subgroups:\n");
  //typedef std::map<long int, SubgroupInformation>::iterator it_type;
  for(it_type iterator = subgroupList.begin(); iterator != subgroupList.end(); iterator++)
  {
    if(newNode.subgroupID < iterator->first) //Is this subgroup newer than the one the node is member of
    {
      cfg_printf(fp, "subgroupID subgroupTokenForward: %ld ", iterator->first);
      
      for(int n = 0 ; n < 32 ; n++)
        cfg_printf(fp, "%02x", (iterator->second).subgroupTokenForward[n]);
      cfg_printf(fp, "%s", "\n");
    }
  }
  cfg_printf(fp, "%s\n", "Config End");


  /* Prints and stores information about IPv6 unicast address of node (calculated from nodeRimeAddress) */

  /* 
  To convert it take the Rime address of form 04:0f:07:b2:00:12:4b:00 and concatenate it to:
  040f:07b2:0012:4b00.

  Now flip bit number 7 to get:
  060f:07b2:0012:4b00.

  Finally add the prefix aaaa:: to form:
  aaaa::060f:07b2:0012:4b00.
  
  char nodeIPv6Address[100] = { 'a', 'a', 'a', 'a', ':', ':',
  nodeRimeAddress[0],  nodeRimeAddress[1],  nodeRimeAddress [3], nodeRimeAddress[4],  ':',
  nodeRimeAddress[6],  nodeRimeAddress[7],  nodeRimeAddress [9], nodeRimeAddress[10], ':',
  nodeRimeAddress[12], nodeRimeAddress[13], nodeRimeAddress[15], nodeRimeAddress[16], ':',
  nodeRimeAddress[18], nodeRimeAddress[19], nodeRimeAddress[21], nodeRimeAddress[22] };*/
  
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
  strcat(name, ".ncfg");
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
      strcat(name, ".ncfg");
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

      //Get subgroupKey
      cfg_printf(fp, "%s", "subGroupKey (hex): ");
      std::map<long int, SubgroupInformation>::iterator it;
      it = subgroupList.find((iterator1->second).subgroupID);
      for(int i = 0 ; i < 32 ; i++)
        cfg_printf(fp, "%02x", (it->second).subgroupKey[i]);
      cfg_printf(fp, "%s", "\n");
      
      //Get subgroupID
      cfg_printf(fp, "subgroupID: %ld\n", (iterator1->second).subgroupID);

      //Prints information on existing nodes in subgroup (needed for new nodes as described in 4.4)
      cfg_printf(fp, "%s", "Information on currently existing nodes in this subgroup:\n");
      for (size_t i = 0; i < (it->second).nodeIDs.size(); i++)
      {
        long int subgroupNode = (it->second).nodeIDs[i];
      
	if (subgroupNode < iterator1->first) {
          cfg_printf(fp, "nodeID nodeTokenBackward: %ld ", subgroupNode);
          for(int n = 0 ; n < 32 ; n++)
            cfg_printf(fp, "%02x", nodeList[subgroupNode].nodeTokenBackward[n]);
          cfg_printf(fp, "%s", "\n");
	}
	else if (subgroupNode > iterator1->first) {
          cfg_printf(fp, "nodeID nodeTokenForward: %ld ", subgroupNode);
          for(int n = 0 ; n < 32 ; n++)
            cfg_printf(fp, "%02x", nodeList[subgroupNode].nodeTokenForward[n]);
          cfg_printf(fp, "%s", "\n");
	}
      }

      //Prints information on existing older subgroups in group (needed for new nodes as described in 4.4)
      cfg_printf(fp, "%s", "Information on currently existing older subgroups:\n");
      typedef std::map<long int, SubgroupInformation>::iterator it_type;
      for(it_type iterator2 = subgroupList.begin(); iterator2 != subgroupList.end(); iterator2++)
      {
        if((iterator1->second).subgroupID > iterator2->first) //Is this subgroup older than the one the node is member of
        {
          cfg_printf(fp, "subgroupID subgroupTokenBackward: %ld ", iterator2->first);
      
          for(int n = 0 ; n < 32 ; n++)
            cfg_printf(fp, "%02x", (iterator2->second).subgroupTokenBackward[n]);
          cfg_printf(fp, "%s", "\n");
        }
	else if((iterator1->second).subgroupID < iterator2->first) //Is this subgroup older than the one the node is member of
        {
          cfg_printf(fp, "subgroupID subgroupTokenForward: %ld ", iterator2->first);
      
          for(int n = 0 ; n < 32 ; n++)
            cfg_printf(fp, "%02x", (iterator2->second).subgroupTokenForward[n]);
          cfg_printf(fp, "%s", "\n");
        }
      }
      cfg_printf(fp, "%s\n", "Config End");

      inet_ntop(AF_INET6, &((iterator1->second).ipv6Addr), nodeIPv6Address, INET6_ADDRSTRLEN);
      cfg_printf(fp, "NodeIP: %s\n", nodeIPv6Address);  

      //Sleeps to separate new node/subgroup creation
      usleep(50000);
    
      //Close configuration file for new node
      fclose (fp);
      printf("Output node configuration updated: %s\n", name);
    }
    SnapMode = 0;
  }
 }
}
