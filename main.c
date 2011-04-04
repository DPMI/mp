/***************************************************************************
                          main.c  -  description
                             -------------------
    begin                : Wed Nov 27 16:16:40 CET 2002
    copyright            : (C) 2002 by Anders Ekberg
                           (C) 2002-2005 Patrik Arlos
                           (C) 2011 David Sveningsson
    email                : anders.ekberg@bth.se
                           patrik.arlos@bth.se
                           david.sveningsson@bth.se
                         
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/
/***************************************************************************
 This is the main thread of the mp. It takes care of initializations
 and post processing information.


***************************************************************************/

#include <string.h>
#include <errno.h>

#include "capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <caputils/caputils.h>

struct sched_param prio;         // Priority schedule variable

struct packet_stat{              // struct for interface statistics
  u_int pkg_recv;
  u_int	pkg_drop;
};

void setpromisc(int sd, char* device); // function for setting interfaces to listen on all traffic
int packet_stats(int sd, struct packet_stat *stat); // function for collecting statistics
//int tcp_connect(const char *host, int port); // function for connectiong to tcpserver
//int udp_connect(const char *host, int port); // function for connectiong to tcpserver
//int ethernet_connect(int index); // function for connectiong to tcpserver

void info(int sd);// function for presentating statistics
char ebuf[ERRBUF_SIZE]; // buffer for output of error messages

short int iflag=0;  // number of capture interfaces
short int tdflag=0; // Number of T_delta definitions.
pid_t allC;
sem_t semaphore;
union semun arg;

int dagfd[CI_NIC];
void* dagbuf[CI_NIC];
int skipflag = 0;


struct option {
  const char *name;
  int has_arg;
  int *flag;
  int val;
};

static struct option myOptions[]={
  {"MAnic=",1,0,1},
  {"ENCRYPT",0,0,2},
  {"BUFFER=",1,0,3},
  {"CAPSIZE=",1,0,4},
  {"CI=",1,0,5},
  {"TD=",1,0,6},
  {"MAip=",1,0,7},
  {"LOCAL",0,0,8}
};

int main (int argc, char **argv)
{

  register int op;
  short int hflag=0;            // flag to indicate that the option help is choosen
  int i;
  int __attribute__((__unused__)) port;            // portnumber and interfaceindex

  char line[100];
  int argCount=0;
  int noOptions=sizeof(myOptions)/sizeof(struct option);
  int k, optionIndex;


  //saveProcess mySave;
  sendProcess mySend;

  int destination;              // 0 locally to file, 1 to MA. Default 0.

  globalDropcount=0;
  memDropcount=0;

  char dagdev[9];

  struct ifreq ifr;
  int s;

  // Init semaphore
  if ( sem_init(&semaphore, 0, 0) != 0 ){
    int saved = errno;
    fprintf(stderr, "%s: sem_init() returned %d: %s\n", argv[0], saved, strerror(saved));
    exit(1);
  }

  // If set to 0, it will store data locally. If 1 it will send to a TCPserver (MA)
  // 0 requires mpid and comment, 1 requires IP optional port.
  destination=0;

  // Configure rules.
  noRules=0;
  myRules=0;
  ENCRYPT=0;
  MAIPaddr=0;

  // Joint signaling to threads to terminate nicely.
  terminateThreads=0;
 /* activating signal*/
  signal(SIGINT, cleanup);
  signal(SIGTERM, cleanup);



  /* prioschedule*/
  //prio.sched_priority=sched_get_priority_max(SCHED_RR)-10;
  //sched_setscheduler(0, SCHED_RR,&prio);


  /*Get my PID*/
  mainPID=pthread_self(); // This is the PID for the main thread.


  FILE *infile;
  int cfgfile=0;
  if ( (infile=fopen("mp.conf","rt"))==NULL){
    printf("No configuration file found. Using command line arguments only.\n");
    if(argc<2){ // If no arguments are present, leave!
      printf("use %s -h for help\n",argv[0]);
      exit(0);
    }
  } else {
    printf("Will read config from mp.conf, and then overwrite these options with\n");
    printf("found in the commnad line arguments.\n");
    cfgfile=1;
  }

// Parse config file  
  if(cfgfile==1) {
    while( fgets(line, sizeof(line),infile) != NULL) {
      argCount++;
      if(line[0]=='#') {
//	printf("Line %d is a comment.\n",argCount);
      } else if (strlen(line)<2){
	//	printf("empty line.\n");
      }else {
	//		printf("Line %d: %s (%d) ",argCount,line, strlen(line));
//-- Argument parsing
	optionIndex=-1;
	for(k=0;k<noOptions;k++){
	  if(strstr(line,myOptions[k].name)!=NULL){
	    //	    printf("<-> %s --> return %d \n", myOptions[k].name, myOptions[k].val);
	    optionIndex=k;
	    optarg=(char*)&line+strlen(myOptions[k].name);
	    //	    printf("\tLine = %p, optarg=%p\n", line, optarg);
	    //	    printf("\tArglen = %d \n",strlen(myOptions[k].name));
	    break;
	  }
	}
	if(optionIndex==-1){
	  printf("Unknown option.\n");
	}
	if(optionIndex>-1) {
	  op=myOptions[optionIndex].val;
	  switch(op){
	  case 8: // LOCAL 
	    LOCAL=1;
	    printf("Local operating mode enabled.\n");
	    break;
	  case 7: // MAIP addr
	    MAIPaddr=(char*)malloc(strlen(optarg)+1);
	      bzero(MAIPaddr,strlen(optarg)+1);
	      strncpy(MAIPaddr,optarg, strlen(optarg)-1);
	      break;
	    case 6: // Timestamp accuracy X
	      tdflag++;
	      tsAcc[tdflag-1]=atoi(optarg);
	      printf("Setting T_delta(%d) = %d.\n",iflag-1,atoi(optarg));
	      break;
	    case 5: // Capture Interface X
	      iflag++;
	      //      nic[iflag-1][4]='\0';
	      strncpy(nic[iflag-1],optarg,strlen(optarg)-1);
	      printf("Setting CI(%d) = %s (%zd)\n",iflag-1,nic[iflag-1], strlen(nic[iflag-1]));
	      break;
	    case 4: // Maximum CAPTURE SIZE 
	      printf("Setting Maximum capture size to %d bytes.\n",atoi(optarg));
	      break;
	    case 3: // BUFFER SIZE 
	      printf("Setting Buffer size to %d PDUs.\n",atoi(optarg));
	      break;
	    case 2: // Encrypt addresses. 
	      srand(time(NULL));
	      ENCRYPT=1+rand()%7;
	      printf("Encryption is enabled, with %d as the key.\n", ENCRYPT);
	      break;
	    case 1: // MA network ID.
	      destination=1;
	      MAnic=(char*)malloc(strlen(optarg)+1);
	      bzero(MAnic,strlen(optarg)+1);
	      strncpy(MAnic,optarg, strlen(optarg)-1);
	      strncpy(ifr.ifr_name, MAnic, IFNAMSIZ);
	      printf("MAnic =  %s\n",MAnic);
	      s = socket(AF_PACKET, SOCK_RAW, htons(MYPROTO));
	      if(ioctl(s,SIOCGIFINDEX, &ifr) == -1 ) {
		perror("SIOCGIFINDEX");
		exit(1);
	      }
	      ifindex = ifr.ifr_ifindex;
	      printf("MA interface index = %d\t",ifindex);
	      if(ioctl(s,SIOCGIFMTU, &ifr) == -1 ) {
		perror("SIOCGIFMTU");
		exit(1);
	      }
	      /*Get my MAC */
	      if(ioctl(s,SIOCGIFHWADDR,&ifr) == -1) {
		perror("SIOCGIFHWADDR");
		exit(1);
	      }
	      
	      printf("MAC ADDRESS: ");
	      for(i=0;i<ETH_ALEN;i++) {
		my_mac[i] = ifr.ifr_hwaddr.sa_data[i];
	      }
	      printf("ifAdd = %02X:%02X:%02X:%02X:%02X:%02X\n",my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]);
	      
	      /*Get my MTU */
	      if(ioctl(s,SIOCGIFMTU,&ifr) == -1) {
		perror("SIOCGIFMTU");
		exit(1);
	      }
	      printf("MAC Interface MTU: %d \n",ifr.ifr_mtu);
	      MAmtu=ifr.ifr_mtu; // Store the MA network MTU. 
	      maSendsize=(ifr.ifr_mtu-sizeof(struct sendhead))/(sizeof(cap_head)+PKT_CAPSIZE);
	      printf("maSendsize:%d \n",maSendsize);
	      if(maSendsize<minSENDSIZE){
		maSendsize=minSENDSIZE;
	      }
	      if(maSendsize>maxSENDSIZE){
		maSendsize=maxSENDSIZE;
	      }
	      printf("maSendsize:%d \n",maSendsize);
	      close(s);
	      
	      break;
	    default: 
	      printf("No function Implemented.\n");
	      break;
	  }
	  if(myOptions[optionIndex].has_arg==1){
	    i++;
	  }
	}// if(optionIndex>-1)
      }// else (if line[0]...
    }//while(fgets(line...
    fclose(infile);
    //iflag=0;
    //tdflag=0;
  } // if(cfgfile==1)

//  if(argc<2 ){
//    printf("use %s -h for help\n",argv[0]);
//    exit(0);
//  }
 
 
//Begin Parsing Command options
  while ( (op =getopt(argc, argv, "Lthd:i:s:p:"))!=EOF)
    switch (op){
    case 'L':  // LOCAL
      LOCAL=1;
      break;
      
    case 'd': // interface to listen on
      tdflag++;
      //      nic[iflag-1][4]='\0';
      tsAcc[tdflag-1]=atoi(optarg);
      break;
    case 'i': // interface to listen on
      iflag++;
      //      nic[iflag-1][4]='\0';
      strcpy(nic[iflag-1],optarg);
      printf("Setting CI(%d) = %s (%zd)\n",iflag-1,nic[iflag-1], strlen(nic[iflag-1]));
      break;
      
    case 's':  // MA Network Interface name
      if(destination==1) { // Overwriting config file
	printf("Overriding mp.conf for MAnic.\n");
	free(MAnic);
      }
      destination=1;
      MAnic=(char*)malloc(strlen(optarg)+1);
      strcpy(MAnic,optarg);
      strncpy(ifr.ifr_name, MAnic, IFNAMSIZ);
      s = socket(AF_PACKET, SOCK_RAW, htons(MYPROTO));
      if(ioctl(s,SIOCGIFINDEX, &ifr) == -1 ) {
	perror("SIOCGIFINDEX");
	exit(1);
      }
      ifindex = ifr.ifr_ifindex;
      printf("MA interface index = %d\t",ifindex);
      if(ioctl(s,SIOCGIFMTU, &ifr) == -1 ) {
	perror("SIOCGIFINDEX");
	exit(1);
      }
      /*Get my MAC */
      if(ioctl(s,SIOCGIFHWADDR,&ifr) == -1) {
	perror("SIOCGIFHWADDR");
	exit(1);
      }

      printf("MAC ADDRESS: ");
      for(i=0;i<ETH_ALEN;i++) {
	my_mac[i] = ifr.ifr_hwaddr.sa_data[i];
      }
      printf("ifAdd = %02X:%02X:%02X:%02X:%02X:%02X\n",my_mac[0],my_mac[1],my_mac[2],my_mac[3],my_mac[4],my_mac[5]);

      /*Get my MTU */
      if(ioctl(s,SIOCGIFMTU,&ifr) == -1) {
	perror("SIOCGIFMTU");
	exit(1);
      }
      printf("MAC Interface MTU: %d \n",ifr.ifr_mtu);
      MAmtu=ifr.ifr_mtu; // Store the MA network MTU. 
      maSendsize=(ifr.ifr_mtu-sizeof(struct sendhead))/(sizeof(cap_head)+PKT_CAPSIZE);
      printf("maSendsize:%d \n",maSendsize);
      if(maSendsize<minSENDSIZE){
	maSendsize=minSENDSIZE;
      }
      if(maSendsize>maxSENDSIZE){
	maSendsize=maxSENDSIZE;
      }
      printf("maSendsize:%d \n",maSendsize);


      close(s);
      break;

    case 't':
	++ skipflag;
	break;

    case 'p': // server port
      port=atoi(optarg);
      break;
		
			
    case 'h': /*Help*/
      hflag = 1;
      printf("MP Broadcast style. \n");
      printf("help caputils version %s\n", CAPUTILS_VERSION);
      printf("This is a MP that uses ETHERNET to multicast its measurement data.\n");
      printf("NO localstorage is possible.\n");
      printf("Fully implemented filtering. \n");
      printf("This software was developed for the INGA project in 2004.\n");
      printf("(C)2004 patrik.carlsson@bth.se \n");
      printf("Usage:\n%s -i <interface> ... -i <interface> -s <BROADCASTIP> -p <PORT> -t \n", argv[0]);
      printf(" -h             help (this text)\n");
      printf(" -s [MA NIC]    MA Interface.\n");
      printf(" -p [PORT]      Receiver Portnumber        (default 1500)\n");
      printf(" -i [NIC]       Capture Interface          (REQUIRED)\n\n");
      printf(" -t             Throw away (skip) frames with any of the \n");
      printf("                error flags set\n");
      printf(" -L             LOCAL MODE, do not talk to MArC, capture everything and store to file.\n"); 
      break;
      
  }
  
  /*Control of flags*/
  if (hflag) exit(0);

  
  
  printf("Capture Interfaces \n");
  for (i=0; i < iflag; i++) {
    printf(" CI[%d]=%s (%zd) T_delta = %d digits\n", i, nic[i], strlen(nic[i]),tsAcc[i]);
    if (!strncmp("dag", nic[i], 3)) {
      strcpy(dagdev,"/dev/");
      strncat(dagdev,nic[i], 4);
      printf("nic[%d]=%s (%zd)\n", i, dagdev,strlen(dagdev));
      printf("No support for DAG in this version, only RAW and PCAP.\n");
      exit(1);
    }
  }
  

//  printf("Leaving.. Was the parsing ok?.\n");
//  return(0);

//End Parsing Command options
/*
  tid1.tv_sec=60;
  tid1.tv_usec=0;
  tid2.tv_sec=60;
  tid2.tv_usec=0;

  difftime.it_interval=tid2;
  difftime.it_value=tid1;
  signal(SIGALRM, cleanup);
  setitimer(ITIMER_REAL,&difftime,NULL);
*/
  
  if (LOCAL==1){
    destination=0;
  }

// Start of realprogram :)
  FILEd=0;

  for(i=0; i<CONSUMERS; i++) {
    MAsd[i].stream = NULL;
    MAsd[i].status = 0;
  }
  printf("Consumer Sockets are initialized, i.e. set to zero.\n");

  noCI=iflag;
  recvPkts=0;
  matchPkts=0;
  
  // No use doing this if we cant send the data somewhere..
  // We should also do some initialization here. Ie. get information from the MA.
  // Thats a later story.
  // Create child process for configuration, OR let the config be running separately and use SHM.
  
  //Bind Socket to Interfaces
  for (i=0;i<iflag;i++) {
    if (strncmp("dag", nic[i], 3)==0) {
      _DEBUG_MSG (fprintf(stderr,"No need to bind dag to socket.\n"))
    } else if (strncmp("pcap",nic[i], 4)==0) {
      _DEBUG_MSG (fprintf(stderr,"No need to bind pcap to socket.\n"))
    } else {
      _DEBUG_MSG (fprintf(stderr,"Bind PF_PACKET to raw_socket.\n"))
      sd[i]=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
      ifindex=iface_get_id(sd[i],nic[i] , ebuf);
      iface_bind(sd[i], ifindex,ebuf);
      setpromisc(sd[i],nic[i]);
    }
  }
  
  // Create childprocess for the Sender/Saver
  mySend.nics=iflag;
  mySend.nic=*nic;
  mySend.semaphore=&semaphore;
  
  //mySave.nics=iflag;
  //mySave.nic=*nic;
  //mySave.semaphore=semaphore;
  
  
  if(destination==1) {  
    if ( pthread_create( &senderPID, NULL, sender, &mySend) ){
      printf("error creating thread.");
      abort();
    }
  }

  // Create childprocess for each Nic
  printf("Creating capture_threads.\n");
  for (i=0;i<iflag;i++) {
    const char* current = nic[i];

    ourCaptures[i].semaphore = &semaphore;
    ourCaptures[i].nic = nic[i];
    ourCaptures[i].id = i;
    ourCaptures[i].accuracy=tsAcc[i];
    ourCaptures[i].pktCnt=0;

    void* (*func)(void*) = NULL;
    
    if ( strncmp("pcap", current, 4) == 0 ){
      memmove(nic[i], &current[4], strlen(&current[4])+1); /* plus terminating */
      printf("\tpcap for %s.\n", current);
      ourCaptures[i].sd=sd[i];
      func = pcap_capture;
    } else { // Default is RAW_SOCKET.
      printf("\tRAW for %s.\n", current);
      ourCaptures[i].sd = -1; // DAG doesn't use sockets
      func = capture;
    }

    if ( pthread_create( &child[i], NULL, func, &ourCaptures[i]) ) {
      fprintf(stderr,"Error creating capture thread.");
      abort();
    }
  }
  
  printf("Waiting 1s befor starting controler thread.\n");
  sleep(1);
  /* 
     Connect to the MA-controller 
  */
  if(pthread_create(&controlPID, NULL, control, NULL) ) {
    fprintf(stderr,"Error creating Control Thread. \n");
    abort();
  }
  
  printf("my Children.\n");
  for(i=0;i<iflag;i++)
  {
    _DEBUG_MSG (fprintf(stderr,"Child %d known as %d working on %s.\n",i,(int)child[i],nic[i]))
  }
  _DEBUG_MSG (fprintf(stderr,"Child %d working on sender.\n", (int)senderPID))
  _DEBUG_MSG (fprintf(stderr,"Child %d working as controller.\n",(int)controlPID))

  //Main will wait here for all children
    printf("Waiting for them to die.\n");
  //End parent when all children are dead
  if(destination==1) {
    pthread_join( senderPID, NULL);
  }
  for(i=0;i < iflag; i++)  {
    pthread_join( child[i], NULL);
  }
  
  _DEBUG_MSG (fprintf(stderr,"\n----------TERMINATING---------------\n\n"))
  _DEBUG_MSG (fprintf(stderr,"Captured %d pkts\nSent %d pkts\n",recvPkts, sentPkts))
  
//Print out statistics on screen  
  printf("Socket stats.\n");
  for (i=0;i<iflag;i++)  {
    printf("%s\n",nic[i]);
    if (!strncmp("dag", nic[i], 3)) {

    } else {
      info(sd[i]);
      close(sd[i]);
    }
  }
  
  printf("Closing MA connection....");
  for(i=0;i<CONSUMERS;i++){
    if ( !MAsd[i].stream ){
      continue;
    }

    int ret = 0;
    if ( (ret=closestream(MAsd[i].stream)) != 0 ){
      fprintf(stderr, "closestream() returned %d: %s\n", ret, caputils_error_string(ret));
    }
    MAsd[i].stream = NULL;
  }

  printf("OK.\nIt's terrible to out live your own children, so I die to.\n");
  
  if ( sem_destroy(&semaphore) != 0 ){
    fprintf(stderr, "%s: sem_destroy() returned %d: %s\n", argv[0], errno, strerror(errno));
  }

  return 0;
} // Main end

void cleanup(int sig) {
  /*  starts when program closes*/
  // activated by SIGTERM, SIGINT, SIGALRM
  pthread_t self=pthread_self();
  printf("Thread %ld caught \n", self);
  
  terminateThreads++;
  printf("Termination signal received %d times.\n",terminateThreads);

  if(self!=senderPID && self!=mainPID && self!=controlPID) { // Incase there are problems 
    // This thread is not the CONTROL/SEND/MAIN thread. So we can kill it!
    // Helps to prevent the capturethreads to stay in the recv for ever. 
    printf("\nHARAKIRI BY %ld !!!!!\n\n",pthread_self());
    pthread_exit(NULL);
  }

  return;
}

//Function presenting dropped packets
void info(int sd)
{
  struct packet_stat stat;

  if (packet_stats(sd, &stat) < 0)
  {
    (void)fprintf(stderr, "packet_stats failed\n");
    return;
  }
    (void)fprintf(stderr, "\t%d packets received by filter\n", stat.pkg_recv);
    (void)fprintf(stderr, "\t%d packets dropped by kernel\n", stat.pkg_drop);
}



//Sets Nic to promisc mode
void setpromisc(int sd, char* device)
{
  struct ifreq	ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

  if(ioctl(sd, SIOCGIFFLAGS, &ifr)==-1)
  {
    printf("can't open flags");
    exit(1);
  }
  if (ifr.ifr_flags & IFF_PROMISC)
  {
    return;
  }
  else
  {
    ifr.ifr_flags |= IFF_PROMISC;
    if(ioctl(sd, SIOCSIFFLAGS, &ifr)==-1)
    {
     printf("can't enter promisc");
     return;
    }
  }
  return;
}

//Get the right id for nic (ethX->interface index) Used for bind
int iface_get_id(int sd, const char *device, char *ebuf)
{
  struct ifreq	ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
  if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1)
  {
    printf("ioctl: %d",errno);
    return -1;
  }
	return ifr.ifr_ifindex;
}

//Bind socket to Interface
int iface_bind(int fd, int ifindex, char *ebuf)
{
  struct sockaddr_ll	sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family		= PF_PACKET;
  sll.sll_ifindex		= ifindex;
  sll.sll_protocol	= htons(ETH_P_ALL);

  if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) == -1)
  {
    printf("bind: %d", errno);
    return -1;
  }
  return 0;
}

//create statistics for Nic (pkgdrop)
int packet_stats(int sd, struct packet_stat *stats)
{
#define HAVE_TPACKET_STATS
#ifdef HAVE_TPACKET_STATS
  struct tpacket_stats kstats;
  socklen_t len = sizeof (struct tpacket_stats);

  /*
   * Try to get the packet counts from the kernel.
   */
  if (getsockopt(sd, SOL_PACKET, PACKET_STATISTICS,&kstats, &len) > -1)
  {
    stats->pkg_recv = kstats.tp_packets;
    stats->pkg_drop = kstats.tp_drops;
  }
  else
  {
    /*
     * If the error was EOPNOTSUPP, fall through, so that
     * if you build the library on a system with
     * "struct tpacket_stats" and run it on a system
     * that doesn't, it works as it does if the library
     * is built on a system without "struct tpacket_stats".
     */
    if (errno != EOPNOTSUPP)
    {
      printf("stats: %d", errno);
      return -1;
    }
  }
#else
  printf("missing PACKET_STATISTICS\n");
#endif
  return 0;
}

// Function for connecting to tcpserver
int tcp_connect(const char *serv, int port){
  printf("tcp_connect() \n");
  int sockfd,result;
  struct sockaddr_in	servaddr;
  sockfd = socket(AF_INET, SOCK_STREAM , 0);
  iface_bind(sockfd,ifindex,ebuf); // Bind to MArC interface.

  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port=htons(port);
  inet_aton(serv, &servaddr.sin_addr);
  setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(void*)1,sizeof(int));

  result=connect(sockfd,(struct sockaddr*)&servaddr,sizeof(servaddr));
  if(result!=0)  {
    perror("tcp_connect, fail ");
    return(0);
  }

  printf("tcp_connect, successfull. %s:%d \n", serv, port);

  struct sendhead SH;
  SH.sequencenr=-1;
  SH.nopkts=0;
  SH.flush=0;
  SH.version.major=htons(CAPUTILS_VERSION_MAJOR);
  SH.version.minor=htons(CAPUTILS_VERSION_MINOR);
  write(sockfd,&SH,sizeof(struct sendhead));
  printf("Sent File header.\n");

  return(sockfd);
}
/* end tcp_connect */



// Function for connecting to tcpserver
int udp_connect(const char *serv, int port){
  printf("udp_connect() \n");
  int sockfd,result,rc;
  struct sockaddr_in	servaddr, cliaddr;
  sockfd = socket(AF_INET, SOCK_DGRAM , 0);
//  setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &option, sizeof(option) );
  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port=htons(port);
  inet_aton(serv, &servaddr.sin_addr);
  cliaddr.sin_family = AF_INET;
  cliaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  cliaddr.sin_port = 0;

  rc=bind(sockfd, (struct sockaddr *)&cliaddr,sizeof(cliaddr));
  if(rc<0){
    perror("udp_connect, fail to bind.");
    return(0);
  }
  iface_bind(sockfd,ifindex,ebuf); // Bind to MArC interface.
  result=connect(sockfd,(struct sockaddr*)&servaddr,sizeof(servaddr));
  if(result!=0)  {
    perror("udp_connect, fail");
    return(0);
  }

  printf("udp_connect, successfull. %s:%d \n", serv, port);
  return(sockfd);
}
/* end udp_connect */

void socket_stats(int sd,int cid) {
  struct packet_stat stat;
  if (packet_stats(sd, &stat) < 0)
  {
    (void)fprintf(stderr, "packet_stats failed\n");
    return;
  }
  CIstat[cid].recvpkts=stat.pkg_recv;
  CIstat[cid].droppkts=stat.pkg_drop;
  return;
}
