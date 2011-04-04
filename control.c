/***************************************************************************
                          Control.c  -  description
                             -------------------
    begin                : Wed Jul 7 2004
    copyright            : (C) 2004-2005 by Patrik Arlos
    email                : patrik.arlos@bth.se
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
  This thread handles the control of the MP and the communications with the MAC.

 ***************************************************************************/ 

#include "capture.h"
#include <mysql.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>

int convMySQLtoFPI(struct FPI *rule,  MYSQL_RES *result);// 
int convUDPtoFPI(struct FPI *rule,  struct FPI result);// 
static char hex_string[IFHWADDRLEN * 3] = "00:00:00:00:00:00";

char query[2000];
char statusQ[2000];
char statusQ2[100];


/* Structures used in MA-MP communications */

struct Generic{
  int type;
  char payload[1400];
};

struct MPinitialization {
  int type;          // Type of message (1). This is present in _ALL_ structures. 
  char mac[8];            // MAC address of Measurement Point
  char name[200];         // Name of MP
  uint8_t ipaddress[4];   // ipaddress 
  uint16_t port;          // UDP port that the MP listens to
  uint16_t maxFilters;    // Maximum number of filters
  uint16_t noCI;          // Number of capture interfaces
  char MAMPid[16];        // ID string provided by MARC.
};

struct MPstatus {
  int type; // Type of message (2).
  char MAMPid[16]; // Name of MP
  int noFilters; // Number of filters present on MP.
  int matched; // Number of matched packets.
  int noCI; // Number of CIs.
  char CIstats[1100]; // String specifying CI status.
};

  
struct MPFilter {
  int type;   // Type of message (3).
  char MAMPid[16]; // Name of MP
  struct FPI theFilter; // Filter
};

struct MPVerifyFilter {
  int type;  // Type of message (6).
  char MAMPid[16]; // Name of MP
  int filter_id; // Filter id.
  int flags; // 0 No filter present. 1 filter present. 
  struct FPI theFilter; // Filter
};

MYSQL_RES *result;
MYSQL_ROW row;
MYSQL *connection, mysql;
int state;

void* control(void* prt){

struct sockaddr_in myAddr;          
  struct Generic *mpmamsgPtr;
  int cliLen;
  struct ifreq IFinfo;
  int option=1;
  int i,slen;
  MAMPid=0;
  struct timeval tid1, tid2;    // times used with runtime
  struct itimerval difftime;    // timer used with runtime
  bzero(&statusQ,sizeof(statusQ));
  bzero(&hostname,sizeof(hostname));
  
  result=0;
  connection=0;

  printf("Control Thread %ld\n", pthread_self());
  bcastS=socket(AF_INET, SOCK_DGRAM, 0);
  if(bcastS<0) {
    perror("Cannot open socket for MA communication.\n");
    /* I.e the shit has hit the fan, how do we terminate all other threads?? */
    exit(1);
  }

  printf("CT: IP stuff\n");
  memset(&IFinfo,0,sizeof(IFinfo));
  strncpy(IFinfo.ifr_name, MAnic, IFNAMSIZ);
  if(ioctl(bcastS,SIOCGIFADDR, &IFinfo) == -1 ) {
    perror("Obtaining IP address of interface .\n");
    exit(1);
  }
  if(IFinfo.ifr_addr.sa_family == AF_INET) {
    memcpy(&myAddr, &(IFinfo.ifr_addr), sizeof(struct sockaddr_in));
  } else { 
    perror("INTERFACE DOES NOT HAVE A IP ADDRESS!\n");
    exit(1);
  }

  if(MAIPaddr!=0){
    inet_aton(MAIPaddr,&myAddr.sin_addr);
    
  }
  printf("Interface IP: %s \n",inet_ntoa(myAddr.sin_addr));  

  if(setsockopt(bcastS,SOL_SOCKET,SO_BROADCAST, &option,sizeof(option))<0){
    perror("Cannot set broadcast option for socket.\n");
    exit(1);
  }
  
  bzero(&servAddr,sizeof(servAddr)); /* Make sure that the struct is empty */
  servAddr.sin_family = AF_INET;
  servAddr.sin_port   = htons(MAPORT);
  servAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

  printf("Should be 255.255.255.255 --> %s \n",inet_ntoa(servAddr.sin_addr));

  /* We should now be able to send a message to the ma */
  /* But we cannot read the reply, since its reply will be to my local addres. */
  /* bcastS listens to the broadcast address... */

  clientAddr.sin_family = AF_INET;
  clientAddr.sin_addr.s_addr = myAddr.sin_addr.s_addr;
  clientAddr.sin_port = htons(MYPORT);

  if(bind(bcastS,(struct sockaddr*)&clientAddr,sizeof(clientAddr))){
    perror("Cannot bind to local port. \n");
    exit(1);
  }


  struct MAINFO myInfo;
  myInfo.version=2;
  sprintf(myInfo.address,"%s",inet_ntoa(clientAddr.sin_addr));
  myInfo.port=clientAddr.sin_port;

  printf("Sending %s:%d -> ",inet_ntoa(clientAddr.sin_addr),ntohs(clientAddr.sin_port));
  printf("%s:%d\n",inet_ntoa(servAddr.sin_addr),ntohs(servAddr.sin_port));
  
  slen=sendto(bcastS,&myInfo,sizeof(struct MAINFO),0,(struct sockaddr*)&servAddr,sizeof(servAddr));
  if(slen==-1){
    perror("Cannot send data.\n");
    exit(1);
  }
  printf("Sent %d bytes.\n", slen);


  char message[250];
//  i=read(bcastS, message, 100);//, (struct sockaddr *)&clientAddr, (socklen_t*)slen);
  cliLen = sizeof(clientAddr);
  i = recvfrom(bcastS, message, sizeof(message), 0, (struct sockaddr *) &clientAddr,(socklen_t*) &cliLen);
  if(i<0) {
    perror("Cannot receive data.. \n");
    exit(1);
  }
  printf("GOT  %d bytes from ", i );
  printf("%s:%d (MArelayD)\n",inet_ntoa(clientAddr.sin_addr),ntohs(clientAddr.sin_port));

  struct MAINFO *maInfo=(struct MAINFO*)message;
  printf("The MA information is:\n\tMArC (%d) :%s\n\tPORT:%d  / %d\n",maInfo->version,maInfo->address,maInfo->port,maInfo->portUDP);
  printf("\tDatabase: %s\n\tUser: %s\n\tPassword: %s\n",maInfo->database, maInfo->user,maInfo->password);


  if(maInfo->version<2) {
    printf("The MArelayD has only version 0.5 information. ");
    printf("This MP uses v 0.6, i.e., it preferes UDP not MySQL for \n");
    printf("information exchange. However, v 0.6  is backward compatible.");
    printf("Please update MArelayD, v 0.7 will not be backward compatible.\n");
    printf("Returned version number is %d\n", maInfo->version);
    //    exit(1);
  }

  gethostname(hostname,200);
  useVersion=maInfo->version;

  if(useVersion==1) { /* Stuck in MySQL land */
    printf("Stuck in MySQL land.\n");
    /* Now we can connect to the mysql DB */
    /*  MYSQL_RES *result;
	MYSQL_ROW row;
	MYSQL *connection, mysql;
	int state;*/
    int k;
    
    /* connect to the MySQL database at localhost */
    mysql_init(&mysql);
    connection = mysql_real_connect(&mysql, 
				    maInfo->address, 
				    maInfo->user, //"genmp",
				    maInfo->password,
				    maInfo->database, //"measproj", 
				    0,
				    0,0);
    /* check for a connection error */
    if ( connection == NULL) { /* print the message */
      printf("%s\n", mysql_error(&mysql));
      exit(1);
    }
    /*  char query[2000];
	char hostname[200];*/
    
    sprintf(query, "SELECT * FROM measurementpoints WHERE mac='%s' AND name='%s'",hexdump_address(my_mac),hostname);
    state=mysql_query(connection,query);
    if(state != 0) {
      printf("%s\n", mysql_error(connection));
      exit(1);
    }
    result=mysql_store_result(connection);
    if(mysql_num_rows(result)==0){ /* WE are a new MP..  */
      mysql_free_result(result);
      sprintf(query, "INSERT INTO measurementpoints SET name='%s',ip='%s',port='%d',mac='%s',maxFilters=%d,noCI=%d"
	      ,hostname
	      ,inet_ntoa(clientAddr.sin_addr)
	      ,MYPORT
	      ,hexdump_address(my_mac)
	      ,CONSUMERS
	      ,noCI);
      printf("Adding using this QUERY\n%s\n",query);
      state=mysql_query(connection,query);
      if(state != 0) {
	printf("%s\n", mysql_error(connection));
	exit(1);
      }
      printf("VERIFYING.\n");
      state = mysql_query(connection,"SELECT name,ip,mac FROM measurementpoints");
      if(state != 0) {
	printf("%s\n", mysql_error(connection));
	exit(1);
      }
      /* must call mysql_store_results() */
      result = mysql_store_result(connection);
      printf("Rows: %d\n",(int)mysql_num_rows(result));
      printf("Cols: %d\n",mysql_num_fields(result));
      
      /*process each row*/
      while( (row=mysql_fetch_row(result)) != NULL ) {
	for(k=0;k<mysql_num_fields(result);k++){
	  printf("%s\t",(row[k] ? row[k] : "NULL"));
	}
	printf("\n");
      }
      /* free the result set */
      mysql_free_result(result);
      /* close connection */
//    mysql_close(connection);
      printf("Done.\n");
    } else { /* This is Version 0.6 */
      printf("The MP exists in MA.\n");
      row=mysql_fetch_row(result);
      MAMPid=malloc(strlen(row[7]));
      strcpy(MAMPid,row[7]);
      mysql_free_result(result);
      printf("MAMPid = %s (%zd) \n", MAMPid, strlen(MAMPid));
      if(strlen(MAMPid)!=0){ // The MP exists, but isnt authorized.
/* Lets check if we have any filters waiting for us? */
	printf("Checking for filters, %s_filterlist.\n",MAMPid);
	sprintf(query, "SELECT * from %s_filterlist",MAMPid);
	state=mysql_query(connection,query);
	if(state != 0) {
	  printf("%s\n", mysql_error(connection));
	  exit(1);
	}
	/* must call mysql_store_results() */
	int rows;
	result = mysql_store_result(connection);
	rows=(int)mysql_num_rows(result);
	printf("We have %d filters waiting for us..\n",rows);
	
	
	/*process each row*/
	struct FPI *newRule;
	for(k=0;k<rows;k++){
	  newRule=calloc(1, sizeof(struct FPI));
	  convMySQLtoFPI(newRule,result);
	  printFilter(newRule);
	  addFilter(newRule);
	  
	}
	/* free the result set */
	mysql_free_result(result);
      } else {
	printf("However, it is not authorized.\n");
      }
    }

  } else { /* if(maInfo->version==1) stuck in MySQL land */
    printf("UDP com.\n");
    struct MPinitialization MPinit;
    MPinit.type=htonl(1);
    bzero(MPinit.mac,8);
    memcpy(MPinit.mac,my_mac,6);
    memcpy(MPinit.name,hostname,sizeof(hostname));
    memcpy(MPinit.ipaddress,&myAddr.sin_addr.s_addr,sizeof(struct in_addr));
    MPinit.port=htons(MYPORT); //clientAddr.sin_port;
    MPinit.maxFilters=htons(CONSUMERS);
    MPinit.noCI=htons(noCI);
    bzero(MPinit.MAMPid,16);


    printf("type   = %d\n",ntohl(MPinit.type));
    printf("mac    = %s\n",MPinit.mac);
    printf("name   = %s\n",MPinit.name);
    printf("port   = %d\n",ntohs(MPinit.port));
    printf("maxF   = %d\n",ntohs(MPinit.maxFilters));
    printf("noCI   = %d / %d \n",ntohs(MPinit.noCI), noCI);
    printf("ipaddr = 0x%02x%02x%02x%02x \n", MPinit.ipaddress[0], MPinit.ipaddress[1], MPinit.ipaddress[2], MPinit.ipaddress[3]);
   /* Reusing socket, just disable broadcast. */
    option=0; 
    if(setsockopt(bcastS,SOL_SOCKET,SO_BROADCAST, &option,sizeof(option))<0){
      perror("Cannot disable broadcast option for socket.\n");
      exit(1);
    }
  
    bzero(&servAddr,sizeof(servAddr)); /* Make sure that the struct is empty */
    servAddr.sin_family = AF_INET;
    servAddr.sin_port   = htons(maInfo->portUDP);
    inet_aton((char*)&maInfo->address,(struct in_addr*)&servAddr.sin_addr.s_addr);

    printf("MArCd at %s : %d \n",inet_ntoa(servAddr.sin_addr), ntohs(servAddr.sin_port));
    

    /* We should now be able to send a message to the ma */
    /* But we cannot read the reply, since its reply will be to my local addres. */
    /* bcastS listens to the broadcast address... */

    printf("Sending %s:%d -> ",inet_ntoa(clientAddr.sin_addr),ntohs(clientAddr.sin_port));
    printf("%s:%d\n",inet_ntoa(servAddr.sin_addr),ntohs(servAddr.sin_port));
    
    slen=sendto(bcastS,&MPinit,sizeof(MPinit),0,(struct sockaddr*)&servAddr,sizeof(servAddr));
    if(slen==-1){
      perror("Cannot send data.\n");
      exit(1);
    }
    printf("Sent %d bytes.\n", slen);
   
/* Waiting for response. */

    char message[1450];
//    struct timeval timeout;// Timeout impl.
    fd_set masterfds;// Timeout impl.
    FD_ZERO(&masterfds);// Timeout impl.
    FD_SET(bcastS,&masterfds);// Timeout impl.
    cliLen = sizeof(clientAddr);

/* Old impl. No timeout */
    i = recvfrom(bcastS, message, sizeof(message), 0, (struct sockaddr *) &clientAddr,(socklen_t*) &cliLen);
    if(i<0) {
      perror("Cannot receive data.. \n");
      exit(1);
    }
// End old impl.

    printf("GOT  %d bytes from ", i );
    printf("%s:%d (MArelayD)\n",inet_ntoa(clientAddr.sin_addr),ntohs(clientAddr.sin_port));

    mpmamsgPtr=(struct Generic*)message;
    printf("Type = %d \n",ntohl(mpmamsgPtr->type));
    printf("%02x %02x %02x %02x .\n",message[0], message[1], message[2], message[3]);
    if(ntohl(mpmamsgPtr->type)==1){
	struct MPinitialization* MPinit=(struct MPinitialization*)&message;
	if(strlen(MPinit->MAMPid)>0){
	  MAMPid=malloc(strlen(MPinit->MAMPid));
	  strcpy(MAMPid,MPinit->MAMPid);
	  printf("This MP is known as %s.\n",MAMPid);
	} else {
	  printf("This is a unauthorized MP.\n");
	}
    } else {
	printf("Server didnt respond with correct type.\n");
    }
    

  }


  tid1.tv_sec=60;
  tid1.tv_usec=0;
  tid2.tv_sec=60;
  tid2.tv_usec=0;

  difftime.it_interval=tid2;
  difftime.it_value=tid1;
  signal(SIGALRM, CIstatus);
  setitimer(ITIMER_REAL,&difftime,NULL); //used for termination with SIGALRM

  printf("Entering (3:am) Eternal loop.\n");
  struct Generic *maMSG;
  int messageType;
  struct FPI* rule;
//  struct sockaddr_in clientAddress;
  char message2[1450];

  struct timeval timeout;
  fd_set fds;
  timeout.tv_sec=5;
  timeout.tv_usec=0;
  FD_ZERO(&fds);
  FD_SET(bcastS,&fds);
  int selectReturn=0;
  int flushBuffer_id=0;

  while(terminateThreads==0){
    bzero(&message2,sizeof(message2));
    //i=read(bcastS, message2, 1450);//, (struct sockaddr *)&clientAddr, (socklen_t*)slen);

    //    printf("Control: Entering select.\n");fflush(stdout);
    while( (selectReturn=select(bcastS+1,&fds,NULL,NULL, &timeout))<=0 && terminateThreads==0){
      if(terminateThreads!=0){
	perror("Control:Got a break signal.\n");
	break;
      }
      if(selectReturn==-1){
	perror("CONTROL:Select error:");
	//EXIT SOMEHOW
	pthread_exit(NULL);
      } else if(selectReturn==0){
	FD_SET(bcastS, &fds);
	timeout.tv_sec=5;
	timeout.tv_usec=0;
	//	printf("Control: Timeout happend, on control socket.\n");fflush(stdout);
      }
    }
    if(terminateThreads!=0){
      //printf("Control: LEAVE!\n");
      break;
    }
    //printf("Control: Waiting for input.\n");fflush(stdout);
    i = recvfrom(bcastS, message2, 1450, 0, (struct sockaddr *) &clientAddr,(socklen_t*) &cliLen);

    if(i<0) {
      perror("Cannot receive data.. \n");
      exit(1);
    }
    int messageLen=i;
    printf("GOT  %d bytes from ", i );
    printf("%s:%d \n",inet_ntoa(clientAddr.sin_addr),ntohs(clientAddr.sin_port));
    maMSG=(struct Generic*)message2; 
    /* Find out what message that arrived */
    for(i=0;i<20;i++){
      printf("%02x:",message2[i]);
    }
    printf("\n");
    messageType=ntohl(maMSG->type);
    printf("MessageType = %d \n", messageType);
    switch(messageType){
      case 1:
	if(maMSG->payload[0]==0){
	  //Not correct.
	  break;
	}
	printf("We got the authorization message. .\n");
	printf("Our MAMPid is [%02x] %s \n",maMSG->payload[0],maMSG->payload);
	MAMPid=malloc(strlen(maMSG->payload));
	strcpy(MAMPid,maMSG->payload);
	printf("This means that we are authorized. And we are in the game!;) Now we wait for filters!.\n");
	break;

      case 2:
	printf("We got a filter indication.\n");
	printf("This type means that we should get a complete set of filters.\n");
	printf("Fetch Lycos!\n");
	break;

      case 3:
	printf("We got a new filter indication.\n");
	printf("This type means that we should get one filter, and add it.\n");
	bzero(&query,sizeof(query));
	
	if(useVersion==1) {
	  sprintf(query,"SELECT * FROM %s_filterlist WHERE filter_id=%d",MAMPid, atoi(maMSG->payload));
	  printf("SQL: %s \n",query);
	  state=mysql_query(connection, query);
	  if(state != 0 ) {
	    printf("%s\n", mysql_error(connection));
	    break;
	  }
	  result = mysql_store_result(connection);
	  rule=calloc(1, sizeof(struct FPI));
	  /* WE ARE HERE */ 
	  /* About to read the rule, and store it in a FPI, that we apply addfilter() to */
	  
	  printf("Got it?\n");
	  convMySQLtoFPI(rule,result);
	  printFilter(rule);	
	  addFilter(rule);
	  /* free the result set */
	  mysql_free_result(result);
	} else {
	  printf("Filter request: %d bytes in request.\n",messageLen);
	  if(messageLen<100) { // This message is from PHP. 
	    struct MPFilter filter;
	    filter.type=htonl(3);
	    sprintf(filter.MAMPid,"%s",MAMPid);
	    filter.theFilter.filter_id=atoi(maMSG->payload);
	    slen=sendto(bcastS,&filter,sizeof(filter),0,(struct sockaddr*)&servAddr,sizeof(servAddr));
	    if(slen==-1){
	      perror("Cannot send data.\n");
	      exit(1);
	    }
	    printf("Sent %d bytes.\n",slen);
	    char message[1450];
	    
	    cliLen = sizeof(clientAddr);
	    i = recvfrom(bcastS, message, sizeof(message), 0, (struct sockaddr *) &clientAddr,(socklen_t*) &cliLen);
	    if(i<0) {
	      perror("Cannot receive data.. \n");
	      exit(1);
	    }
	    printf("GOT  %d bytes from ", i );
	    printf("%s:%d (MArelayD)\n",inet_ntoa(clientAddr.sin_addr),ntohs(clientAddr.sin_port));	  
	    mpmamsgPtr=(struct Generic*)message;
	  } else { // This is the response from a MArCD . I.e., filter is present.
	    printf("Message contains FPI.\n");
	    mpmamsgPtr=(struct Generic*)message2;
	  }
	  
	  printf("Type = %d \n",ntohl(mpmamsgPtr->type));
	  if(ntohl(mpmamsgPtr->type)==3){
	    struct MPFilter* filterReply=(struct MPFilter*)mpmamsgPtr;
	    if(strcmp(filterReply->MAMPid,MAMPid)!=0){
	      printf("This reply was intened for a different MP (%s).\n",filterReply->MAMPid);
	    } else { // Correct MP.
	      rule=calloc(1,sizeof(struct FPI));
	      convUDPtoFPI(rule,filterReply->theFilter);
	      printFilter(rule);
	      addFilter(rule);
	      printf("Added the filter.\n");
	    }
	  } else { 
	    printf("Server didnt respond with correct type.\n");
	    for(i=0;i<20;i++){
	      printf("%02x:",message2[i]);
	    }
	    printf("\n");
	  }

	}
	break;

      case 4:
	printf("We got a change filter indication.\n");
	printf("This means that we should change particular filter.\n");

	if(useVersion==1){
	  sprintf(query,"SELECT * FROM %s_filterlist WHERE filter_id=%d",MAMPid, atoi(maMSG->payload));
	  printf("SQL: %s \n",query);
	  state=mysql_query(connection, query);
	  if(state != 0 ) {
	    printf("%s\n", mysql_error(connection));
	    break;
	  }
	  result = mysql_store_result(connection);
	  rule=calloc(1, sizeof(struct FPI));
	  /* WE ARE HERE */ 
	  /* About to read the rule, and store it in a FPI, that we apply addfilter() to */
	  
	  printf("Got it?\n");
	  convMySQLtoFPI(rule,result);
	  printFilter(rule);
	  if(changeFilter(rule)){
	    printf("Rule replaced.\n");
	  } else {
	    printf("Error: cannot replace rule.\n");
	  }
	  /* free the result set */
	  mysql_free_result(result);
	} else {
	  printf("Change filter request: %d bytes in request.\n",messageLen);
	  if(messageLen<100) { // This message is from PHP. 
	    struct MPFilter filter;
	    filter.type=htonl(3);
	    sprintf(filter.MAMPid,"%s",MAMPid);
	    filter.theFilter.filter_id=atoi(maMSG->payload);
	    slen=sendto(bcastS,&filter,sizeof(filter),0,(struct sockaddr*)&servAddr,sizeof(servAddr));
	    if(slen==-1){
	      perror("Cannot send data.\n");
	      exit(1);
	    }
	    printf("Sent %d bytes.\n",slen);
	    char message[1450];
	    
	    cliLen = sizeof(clientAddr);
	    i = recvfrom(bcastS, message, sizeof(message), 0, (struct sockaddr *) &clientAddr,(socklen_t*) &cliLen);
	    if(i<0) {
	      perror("Cannot receive data.. \n");
	      exit(1);
	    }
	    printf("GOT  %d bytes from ", i );
	    printf("%s:%d (MArelayD)\n",inet_ntoa(clientAddr.sin_addr),ntohs(clientAddr.sin_port));	  
	    mpmamsgPtr=(struct Generic*)message;
	  } else { // This is the response from a MArCD . I.e., filter is present.
	    printf("Message contains FPI.\n");
	    mpmamsgPtr=(struct Generic*)message2;
	  }
	  
	  printf("Type = %d \n",ntohl(mpmamsgPtr->type));
	  if(ntohl(mpmamsgPtr->type)==3){
	    struct MPFilter* filterReply=(struct MPFilter*)mpmamsgPtr;
	    if(strcmp(filterReply->MAMPid,MAMPid)!=0){
	      printf("This reply was intened for a different MP (%s).\n",filterReply->MAMPid);
	    } else { // Correct MP.
	      rule=calloc(1,sizeof(struct FPI));
	      convUDPtoFPI(rule,filterReply->theFilter);
	      printFilter(rule);
	      if(changeFilter(rule)){
		printf("Rule replaced.\n");
	      } else {
		printf("Error: Cannot replace rule.\n");
	      }
	    }
	  } else { 
	    printf("Server didnt respond with correct type.\n");
	    for(i=0;i<20;i++){
	      printf("%02x:",message2[i]);
	    }
	    printf("\n");
	  }


	}
	break;

      case 5:
	printf("We got a drop filter indication.\n");
	delFilter(atoi(maMSG->payload));
	break;

      case 6:
	printf("Verification of a filter.\n");
	printf("This means that we should get a particular filter.\n");

	if(useVersion==1){
	  bzero(&query,sizeof(query));
	  printMysqlFilter(query,MAMPid,atoi(maMSG->payload));
	  printf("SQL: %s \n",query);
	  state=mysql_query(connection, query);
	  if(state != 0 ) {
	    printf("%s\n", mysql_error(connection));
	    break;
	  }
	  bzero(&query,sizeof(query));
	} else { // i.e. UDP.
	  int desiredFilter=atoi(maMSG->payload);
	  struct MPVerifyFilter myVerify;
	  myVerify.type=htonl(6);
	  sprintf(myVerify.MAMPid,"%s",MAMPid);
	  myVerify.filter_id=desiredFilter;
	  struct FPI* F;
	  F=myRules;
	  while(F!=0 && F->filter_id!=desiredFilter){
	    F=F->next;
	  }
	  if(F==0){ // Did not find a filter that matched.
	    myVerify.flags=0;
	  } else { // Did find a filter that matched. F holds the pointer.
	    myVerify.flags=1;
	    memcpy(&myVerify.theFilter,F,sizeof(struct FPI));
	  }
	  slen=sendto(bcastS,&myVerify,sizeof(myVerify),0,(struct sockaddr*)&servAddr,sizeof(servAddr));
	  if(slen==-1){
	    perror("Cannot send data.\n");
	    exit(1);
	  }
	  printf("Sent %d bytes.\n",slen);
	  
	}// else (i.e. UDP)
	break;


      case 7:
	printf("Verification of all filters.\n");
	struct FPI *F;
	F=myRules;
	
	if(useVersion==1) {
	  if(F==0) { // NO rules.
	    sprintf(query, "INSERT INFO %s_filterlistverify SET comment='NO RULES PRESENT'",MAMPid);
	  } else {
	    while(F!=0){
	      bzero(&query,sizeof(query));
	      sprintf(query,"INSERT INTO %s_filterlistverify SET filter_id='%d', ind='%d', CI_ID='%s', VLAN_TCI='%d', VLAN_TCI_MASK='%d',ETH_TYPE='%d', ETH_TYPE_MASK='%d',ETH_SRC='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X',ETH_SRC_MASK='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X', ETH_DST='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X', ETH_DST_MASK='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X',IP_PROTO='%d', IP_SRC='%s', IP_SRC_MASK='%s', IP_DST='%s', IP_DST_MASK='%s', SRC_PORT='%d', SRC_PORT_MASK='%d', DST_PORT='%d', DST_PORT_MASK='%d', TYPE='%d', CAPLEN='%d', consumer='%d'",
		      MAMPid,F->filter_id,F->index,F->CI_ID,F->VLAN_TCI,F->VLAN_TCI_MASK,
		      F->ETH_TYPE,F->ETH_TYPE_MASK, 
		      (unsigned char)(F->ETH_SRC[0]),(unsigned char)(F->ETH_SRC[1]),(unsigned char)(F->ETH_SRC[2]),(unsigned char)(F->ETH_SRC[3]),(unsigned char)(F->ETH_SRC[4]),(unsigned char)(F->ETH_SRC[5]),
		      (unsigned char)(F->ETH_SRC_MASK[0]),(unsigned char)(F->ETH_SRC_MASK[1]),(unsigned char)(F->ETH_SRC_MASK[2]),(unsigned char)(F->ETH_SRC_MASK[3]),(unsigned char)(F->ETH_SRC_MASK[4]),(unsigned char)(F->ETH_SRC_MASK[5]),
		      
		      (unsigned char)(F->ETH_DST[0]),(unsigned char)(F->ETH_DST[1]),(unsigned char)(F->ETH_DST[2]),(unsigned char)(F->ETH_DST[3]),(unsigned char)(F->ETH_DST[4]),(unsigned char)(F->ETH_DST[5]),
		      (unsigned char)(F->ETH_DST_MASK[0]),(unsigned char)(F->ETH_DST_MASK[1]),(unsigned char)(F->ETH_DST_MASK[2]),(unsigned char)(F->ETH_DST_MASK[3]),(unsigned char)(F->ETH_DST_MASK[4]),(unsigned char)(F->ETH_DST_MASK[5]),
		      F->IP_PROTO,
		      F->IP_SRC,F->IP_SRC_MASK,F->IP_DST,F->IP_DST_MASK,
		      F->SRC_PORT,F->SRC_PORT_MASK,F->DST_PORT,F->DST_PORT_MASK,
		      F->TYPE, 
		      F->CAPLEN,
		      F->consumer);
	    
	      if(F->TYPE==1) {
		sprintf(query,"%s, DESTADDR='%2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X' ",query, (unsigned char)(F->DESTADDR[0]),(unsigned char)(F->DESTADDR[1]),(unsigned char)(F->DESTADDR[2]),(unsigned char)(F->DESTADDR[3]),(unsigned char)(F->DESTADDR[4]),(unsigned char)(F->DESTADDR[5]));
	      } else {
		sprintf(query,"%s, DESTADDR='%s' ",query, F->DESTADDR);
	      }
	      
	      
	      printf("SQL: %s \n",query);
	      state=mysql_query(connection, query);
	      if(state != 0 ) {
		printf("%s\n", mysql_error(connection));
		break;
	      }
	      F=F->next; 
	    }
	  }
	  bzero(&query,sizeof(query));
	} else { // useVersion>1 i.e., UDP.
	  struct MPVerifyFilter myVerify;
	  sprintf(myVerify.MAMPid,"%s",MAMPid);
	  myVerify.type=htonl(6);
  
	  if(F==0) { // NO rules.
	    myVerify.filter_id=0;
	    myVerify.flags=0;
	    slen=sendto(bcastS,&myVerify,sizeof(myVerify),0,(struct sockaddr*)&servAddr,sizeof(servAddr));
	    if(slen==-1){
	      perror("Cannot send data.\n");
	      exit(1);
	    }
	    
	  } else {
	    while(F!=0){

	      myVerify.flags=1;
	      myVerify.filter_id=F->filter_id;
	      memcpy(&myVerify.theFilter,F,sizeof(struct FPI));
	      
	      printf("Sending Verification of filter_id = %d.\n",F->filter_id);
	      slen=sendto(bcastS,&myVerify,sizeof(myVerify),0,(struct sockaddr*)&servAddr,sizeof(servAddr));
	      if(slen==-1){
		perror("Cannot send data.\n");
		exit(1);
	      }
	      F=F->next; 
	    }//while(F!=0)
	}
	  bzero(&query,sizeof(query));

	}
	break;

      case 8:
	printf("Termination received. \n");
	printf("Shutting down the shop.\n");
	printf("TerminateThreads = %d \n",terminateThreads);
	if(strcmp(maMSG->payload,"konkelbar")==0){
	  terminateThreads++;
	} else {
	  printf("Magic word incorrect: %s \n", maMSG->payload);
	}
	break;
	
      case 9:
	printf("Flush buffers request recived.\n");
	for(i=0;i<CONSUMERS;i++){
	  flushBuffer(i);
	}
	break;
	
    case 10:
      flushBuffer_id=atoi(maMSG->payload);
      printf("Flush buffer request obtained.\n");
      flushBuffer(flushBuffer_id);
      break;
      


      default:
	printf("%d is a unknown message.\n",(int)messageType);
	printf("PAYLOAD: %s\n",maMSG->payload);
	break;
    }
    
    
  }
  _DEBUG_MSG (fprintf(stderr,"Child %ld My work here is done %s.\n", pthread_self(), nic[i]))
  printf("Leaving Control Thread.\n");
  return(NULL);

}


int inet_atoP(char *dest,char *org){
  printf("org = %p\n",org);
  if(useVersion==2) {
    strncpy(dest,org, ETH_ALEN);
    printf("ethlen=%d, \n",ETH_ALEN);
    printf("org = %02x:%02x:%02x:%02x:%02x:%02x \n",*(org),*(org+1),*(org+2),*(org+3),*(org+4),*(org+5));
    printf("dst = %02x:%02x:%02x:%02x:%02x:%02x \n",*(dest),*(dest+1),*(dest+2),*(dest+3),*(dest+4),*(dest+5));
    return 1;
  }

  char tmp[3];
  tmp[2]='\0';
  int j,k;
  j=k=0;
  int t;
  for(j=0;j<ETH_ALEN;j++){
    strncpy(tmp,org+k,2);
    t=(int)strtoul(tmp,NULL,16);
    printf("%02x ",t);
    *(dest+j)=t;
    k=k+2;
  }
  return 1;
}


char *hexdump_address (const unsigned char address[IFHWADDRLEN]){
  int i;

  for (i = 0; i < IFHWADDRLEN - 1; i++) {
    sprintf (hex_string + 3*i, "%2.2X:", (unsigned char) address[i]);
  }  
  sprintf (hex_string + 15, "%2.2X", (unsigned char) address[i]);
  return (hex_string);
}

int convMySQLtoFPI(struct FPI *rule,  MYSQL_RES *result){
  char *pos=0;
  MYSQL_ROW row;  
  row=mysql_fetch_row(result);
  rule->filter_id=atoi(row[0]);
  rule->index=atoi(row[1]);
  strncpy(rule->CI_ID,row[2],8);
  rule->VLAN_TCI=atol(row[3]);
  rule->VLAN_TCI_MASK=atol(row[4]);
  rule->ETH_TYPE=atol(row[5]);
  rule->ETH_TYPE_MASK=atol(row[6]);
  
  
  rule->IP_PROTO=atoi(row[11]);
  strncpy((char*)(rule->IP_SRC),row[12],16);
  strncpy((char*)(rule->IP_SRC_MASK),row[13],17);
  strncpy((char*)(rule->IP_DST),row[14],18);
  strncpy((char*)(rule->IP_DST_MASK),row[15],19);
  
  rule->SRC_PORT=atoi(row[16]);
  rule->SRC_PORT_MASK=atoi(row[17]);
  rule->DST_PORT=atoi(row[18]);
  rule->DST_PORT_MASK=atoi(row[19]);
  rule->consumer=atoi(row[20]);
  
  inet_atoP((char*)(rule->ETH_SRC),row[7]);
  inet_atoP((char*)(rule->ETH_SRC_MASK),row[8]);
  inet_atoP((char*)(rule->ETH_DST),row[9]);
  inet_atoP((char*)(rule->ETH_DST_MASK),row[10]);

  rule->TYPE=atoi(row[22]);
  rule->CAPLEN=atoi(row[23]);
  if(rule->CAPLEN>PKT_CAPSIZE){ // Make sure that the User doesnt request more information than we can give. 
    rule->CAPLEN=PKT_CAPSIZE;
  }
  switch(rule->TYPE){
    case 3: // TCP
    case 2: // UDP
      // DESTADDR is ipaddress:port
      strncpy((char*)(rule->DESTADDR),row[21],22);
      pos=index((char*)(rule->DESTADDR),':');
      if(pos!=NULL) {
	*pos=0;
	rule->DESTPORT=atoi(pos+1);
      } else {
	rule->DESTPORT=MYPROTO;
      }
      break;
    case 1: // Ethernet
      inet_atoP((char*)(rule->DESTADDR),row[21]);
      break;
    case 0: // File
      strncpy((char*)(rule->DESTADDR),row[21],22);
      break;
  }

  return 1;
}


int convUDPtoFPI(struct FPI *rule,  struct FPI result){
  char *pos=0;
  rule->filter_id=result.filter_id;
  rule->index=result.index;
  strncpy(rule->CI_ID,result.CI_ID,8);
  rule->VLAN_TCI=result.VLAN_TCI;
  rule->VLAN_TCI_MASK=result.VLAN_TCI_MASK;
  rule->ETH_TYPE=result.ETH_TYPE;
  rule->ETH_TYPE_MASK=result.ETH_TYPE_MASK;
  
  
  rule->IP_PROTO=result.IP_PROTO;
  strncpy((char*)(rule->IP_SRC),(char*)(result.IP_SRC),16);
  strncpy((char*)(rule->IP_SRC_MASK),(char*)(result.IP_SRC_MASK),16);
  strncpy((char*)(rule->IP_DST),(char*)(result.IP_DST),16);
  strncpy((char*)(rule->IP_DST_MASK),(char*)(result.IP_DST_MASK),16);
  
  rule->SRC_PORT=result.SRC_PORT;
  rule->SRC_PORT_MASK=result.SRC_PORT_MASK;
  rule->DST_PORT=result.DST_PORT;
  rule->DST_PORT_MASK=result.DST_PORT_MASK;
  rule->consumer=result.consumer;
  
  memcpy(rule->ETH_SRC,result.ETH_SRC,ETH_ALEN);
  memcpy(rule->ETH_SRC_MASK,result.ETH_SRC_MASK,ETH_ALEN);
  memcpy(rule->ETH_DST,result.ETH_DST,ETH_ALEN);
  memcpy(rule->ETH_DST_MASK,result.ETH_DST_MASK,ETH_ALEN);

  rule->TYPE=result.TYPE;
  rule->CAPLEN=result.CAPLEN;
  if(rule->CAPLEN>PKT_CAPSIZE){ // Make sure that the User doesnt request more information than we can give. 
    rule->CAPLEN=PKT_CAPSIZE;
  }
  switch(rule->TYPE){
    case 3: // TCP
    case 2: // UDP
      // DESTADDR is ipaddress:port
      strncpy((char*)(rule->DESTADDR),(char*)(result.DESTADDR),22);
      pos=index((char*)(rule->DESTADDR),':');
      if(pos!=NULL) {
	*pos=0;
	rule->DESTPORT=atoi(pos+1);
      } else {
	rule->DESTPORT=MYPROTO;
      }
      break;
    case 1: // Ethernet
      printf("Ethernet DST = %s \n",hexdump_address(result.DESTADDR));
      memcpy(rule->DESTADDR,result.DESTADDR,ETH_ALEN);
      break;
    case 0: // File
      strncpy((char*)(rule->DESTADDR),(char*)(result.DESTADDR),22);
      break;
  }

  return 1;
}


void CIstatus(int sig){ // Runs when ever a ALRM signal is received.
  int slen;
  struct timeval tid1;
  char chartest[20];
  chartest[19]='\0';
  struct tm *dagtid;



  gettimeofday(&tid1,NULL);
  dagtid=localtime(&tid1.tv_sec);
  strftime(chartest,20,"%Y-%m-%d %H.%M.%S",dagtid);

  /*
  printf("%s %d packets recived, %d lost packets \n", chartest, msgcounter, lossCounter);
  printf("THREAD %llu/%llu wish to do CIstatus..\n",pthread_self(),controlPID);

  printf("mainPID= %ld\tctrlPID=%ld\tsenderPID=%ld\n",mainPID,controlPID,senderPID);
  if(pthread_self()!=controlPID) {
    printf("You dont belong here..\n");
    return;
  }
  */
  if(MAMPid==0){
    printf("Not authorized. No need to inform MArC about the status.\n");
    return;
  }
  if(useVersion==1) { // Use MYSQL 
    bzero(&statusQ,sizeof(statusQ));
    bzero(&statusQ2,sizeof(statusQ2));
    int i=0;
    char *query,*ifStats;
    query=statusQ;
    ifStats=statusQ2;
    
    sprintf(statusQ,"INSERT INTO %s_CIload SET noFilters='%d', matchedPkts='%d' ", MAMPid, noRules, matchPkts);
    for(i=0;i<noCI;i++){
      sprintf(statusQ2,", CI%d='%s', PKT%d='%ld', BU%d='%d' ",i,ourCaptures[i].nic,i,ourCaptures[i].pktCnt, i, bufferUsage[i]);
      query=strcat(query,ifStats);
    }
    
    if(connection==0){
      printf("MySQL connection == 0?!=\n");
    }
    state=mysql_query(connection, query);
    if(state != 0 ) {
      printf("%s\n", mysql_error(connection));
      return;
    }
    
    printf("Status report for %s\n\t%d Filters Present.\n\t%d Packets Matched Filters.\n", MAMPid, noRules,matchPkts);
    for(i=0;i<noCI;i++){
      printf("\tCI%d=%s  PKT%d=%ld BU%d=%d\n",i,ourCaptures[i].nic,i,ourCaptures[i].pktCnt, i, bufferUsage[i]);
    }
  } else { // Use UDP.

    bzero(&statusQ,sizeof(statusQ));
    bzero(&statusQ2,sizeof(statusQ2));
    int i=0;
    char *query,*ifStats;
    query=statusQ;
    ifStats=statusQ2;
    
    struct MPstatus MPstat;
    sprintf(MPstat.MAMPid,"%s",MAMPid);
    MPstat.type=htonl(2);
    MPstat.noFilters=ntohl(noRules);
    MPstat.matched=ntohl(matchPkts);
    MPstat.noCI=ntohl(noCI);
    for(i=0;i<noCI;i++){
      sprintf(statusQ2,", CI%d='%s', PKT%d='%ld', BU%d='%d' ",i,ourCaptures[i].nic,i,ourCaptures[i].pktCnt, i, bufferUsage[i]);
      query=strcat(query,ifStats);
    }
    sprintf(MPstat.CIstats,"%s",query);

    slen=sendto(bcastS,&MPstat,sizeof(MPstat),0,(struct sockaddr*)&servAddr,sizeof(servAddr));
    if(slen==-1){
      perror("Cannot send data.\n");
      exit(1);
    }

    printf("%s Status report for %s\n\t%d Filters Present\n\t%d Capture Interfaces.\n\t%d Packets Matched Filters.\n", chartest, MAMPid, noRules,noCI,matchPkts);
    for(i=0;i<noCI;i++){
      printf("\tCI%d=%s  PKT%d=%ld BU%d=%d\n",i,ourCaptures[i].nic,i,ourCaptures[i].pktCnt, i, bufferUsage[i]);
    }
    printf("Message was %d bytes long, and it was sent to the MArC.\n", slen);
  }
    
  return;
}


void flushBuffer(int i){
  int written;
  written=-1;

  struct consumer* con = &MAsd[i];
  
  /* no consumer */
  if ( !con ){
    return;
  }

  /* no packages to send */
  if ( con->sendcount == 0 ){
    return;
  }

  con->shead=(struct sendhead*)(sendmem[i]+sizeof(struct ethhdr)); // Set pointer to the sendhead, i.e. mp transmission protocol 
  con->shead->flush=htons(1);

  printf("Consumer %d needs to be flushed, contains %d pkts\n", i, con->sendcount);
  //for(k=0;k<ETH_ALEN;k++){// Copy the destination address from the ethernet header to the socket header.
  //  socket_address.sll_addr[k] = ethhead[i]->h_dest[k];// Set the destination address, defaults to 0x01:00:00:00:[i]
  //}
  memcpy(socket_address.sll_addr, con->ethhead->h_dest, ETH_ALEN);


  size_t len = con->sendpointer - con->sendptrref;
  con->stream->write(con->stream, con->sendptrref, len);

  /* switch(consumerType[i]){ */
  /* case 3: */
  /*   printf("Sending TCP.\t"); */
  /*   written = write(MAsd[i], */
  /* 		    sendpointer[i], */
  /* 		    (sendpointer[i]-sendptrref[i])); */
  /*   break; */
  /* case 2: */
  /*   printf("Sending UDP .\t"); */
  /*   written = write(MAsd[i], */
  /* 		    sendmem[i]+sizeof(struct ethhdr), */
  /* 		    sizeof(struct sendhead)+(sendpointer[i]-sendptrref[i])); */
  /*   break; */
  /* case 1: */
  /*   printf("Sending Ethernet.\t"); */
  /*   written=sendto(MAsd[i], */
  /* 		   sendmem[i], */
  /* 		   sizeof(struct ethhdr)+sizeof(struct sendhead)+(sendpointer[i]-sendptrref[i]), */
  /* 		   0, */
  /* 		   (struct sockaddr*)&socket_address, */
  /* 		   sizeof(socket_address)); */
  /*   break; */
  /* case 0: */
  /*   written = write(MAsd[i],sendpointer[i],(sendpointer[i]-sendptrref[i])); */
  /*   break; */
  /* } */



  printf("Sent %d bytes.\n",written);
  if(written==-1) {
    printf("sendto():");
  }

  con->shead->sequencenr=htonl(ntohl(con->shead->sequencenr)+1);
  if(ntohl(con->shead->sequencenr)>0xFFFF){
    con->shead->sequencenr=htonl(0);
  }

  writtenPkts += con->sendcount;// Update the total number of sent pkts. 
  con->sendcount=0;// Clear the number of packets in this sendbuffer[i]

  //printf("ST: Send %d bytes. Total %d packets.\n",written, writtenPkts);
  bzero(con->sendptrref,(maSendsize*(sizeof(cap_head)+PKT_CAPSIZE))); //Clear the memory location, for the packet data. 
  con->sendpointer = con->sendptrref; // Restore the pointer to the first spot where the next packet will be placed.
  con->shead->flush=htons(0); //Restore flush indicator
}
