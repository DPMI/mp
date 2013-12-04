/*************************************************************************** 
                         timesync.c  -  description                                                                                                                                        
                             -------------------                                                                                                                                             
begin                : Wed Dec 2013
copyright            : (C) 2013 by Patrik Arlos                                                                                                                                     
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
  This is used to retreive timesync information per CI.
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "timesync.h"
#include "log.h"
#include <dagapi.h>
#include <dag_platform.h>
#include <dagutil.h>
#include <dagclarg.h>
static int dagfd;
static duckinf_t duckinf;
static volatile uint8_t *iom;
static unsigned duck_base;
static void duckstatus(struct CI* myCI);
static void ntpstatus(struct CI* myCI);


int timesync_init(struct CI* myCI) {
  logmsg(verbose, "TIMESYNC", "Init of %s .\n", myCI->iface);

  int localerror;
  dag_reg_t result[DAG_REG_MAX_ENTRIES];
  unsigned regn;
  dag_reg_t *regs;
  duckinf.Set_Duck_Field = 0;
  duckinf.Last_TSC = 0;

  
  if(strncmp(myCI->iface,"dag",3)==0){
    dagfd=myCI->sd;
    iom = dag_iom(dagfd);
    /* Find DUCK */
    regs = dag_regs(dagfd);
    regn=0;
    
    if ((dag_reg_table_find(regs, 0, DAG_REG_DUCK, result, &regn)) || (!regn)) {
      dagutil_panic("Dag does not support DUCK functions\n");
      return(0);
    } else {
      duck_base = DAG_REG_ADDR(*result);
    }
    
    
    if((localerror = ioctl(dagfd, DAGIOCDUCK, &duckinf))){
      dagutil_panic("DAGIOCDUCK failed with %d\n", localerror);
    }
    duckstatus(myCI);
    
  } else { /* Default to NTP if no DAG is found */
    myCI->synchronized='U';
    
  }

  return(1);
}

int timesync_status(struct CI* myCI){
  logmsg(verbose, "TIMESYNC", "Status  %s .\n", myCI->iface);
  int localerror;
  
  if(strncmp(myCI->iface,"dag",3)==0){
    dagfd=myCI->sd;
    iom=dag_iom(dagfd);
    if((localerror = ioctl(dagfd, DAGIOCDUCK, &duckinf))){
      dagutil_panic("DAGIOCDUCK failed with %d\n", localerror);
      return(0);
    }
    duckstatus(myCI);
  } else {
    ntpstatus(myCI);
  }


  return(1);

}

enum {
  Duck_Command= 0x00,
  Duck_Config= 0x04,
  Duck_High_Load= 0x0c,
  Duck_DDS_Rate= 0x14,
  Duck_High_Read= 0x18,
  Duck_Low_Read= 0x1c,
};

# define DUCK(OFF) (*(volatile unsigned *)(iom+duck_base+(OFF)))



static void duckstatus(struct CI* myCI) {
  unsigned val; //, mask, none;
  //time_t last;
  //  char *last_tick;

  val = DUCK(Duck_Config);

  /*
    // DO not care about sync input..
  none = 1;

    printf("muxin\t");
  for( mask = 1 ; mask < 0x10; mask <<= 1)
    switch(val&mask) {
    case 0x00:
      continue;
    case 0x01:
      printf("rs422 ");
      none = 0;
      break;
    case 0x02:
      printf("host ");
      none = 0;
      break;
    case 0x04:
      printf("over ");
      none = 0;
      break;
    case 0x08:
      printf("aux ");
      none = 0;
      break;
    default:
      dagutil_panic("internal error at %s %u\n", __FILE__, __LINE__);
    }
  if(none) {
    printf("none ");
  }
  printf("\n");
  
  none = 1;
  printf("muxout\t");
  for( mask = 0x100 ; mask < 0x1000 ; mask <<=1 )
    switch(val&mask) {
    case 0x000:
      continue;
    case 0x100:
      printf("rs422 ");
      none = 0;
      break;
    case 0x200:
      printf("loop ");
      none = 0;
      break;
    case 0x400:
      printf("host ");
      none = 0;
      break;
    case 0x800:
      printf("over ");
      none = 0;
      break;
    default:
      dagutil_panic("internal error at %s line %u\n", __FILE__, __LINE__);
    }
  if(none){ 
    printf("none "); 
  }
  printf("\n");
  */

  if(duckinf.Health){
    myCI->synchronized='Y';// duckinf.Health?"Y":"N ";
  } else {
    myCI->synchronized='N';
  }
  myCI->frequency=duckinf.Crystal_Freq;
  myCI->starttime=duckinf.Stat_Start;
  if(duckinf.Last_Ticks) {
    myCI->citime= (time_t)((duckinf.Last_Ticks >> 32) + (int)(((duckinf.Last_Ticks&0xffffffff) + (double)0x80000000)/0x100000000ll));
  } else {
      myCI->citime= 0;
  }
  myCI->hosttime=duckinf.Stat_End;

  /*  
  printf("%sSynchronised ", duckinf.Health?"":"Not ");
  printf("Threshold %.0fns ", duckinf.Health_Thresh / (0x100000000ll/1000000000.0));
  printf("Phase correction %.0fns ", duckinf.Phase_Correction / (0x100000000ll/1000000000.0));
  printf("Failures %d ", duckinf.Sickness);
  printf("Resyncs %d\n", duckinf.Resyncs);

  printf("error\t");
  printf("Freq %.0fppb ", duckinf.Freq_Err / (0x100000000ll/1000000000.0));
  printf("Phase %.0fns ", duckinf.Phase_Err / (0x100000000ll/1000000000.0));
  printf("Worst Freq %.0fppb ", duckinf.Worst_Freq_Err / (0x100000000ll/1000000000.0));
  printf("Worst Phase %.0fns\n", duckinf.Worst_Phase_Err / (0x100000000ll/1000000000.0));

  printf("crystal\t");
  printf("Actual %dHz ", duckinf.Crystal_Freq);
  printf("Synthesized %dHz\n", duckinf.Synth_Freq);

  printf("input\t");
  printf("Total %d ", duckinf.Pulses);
  printf("Bad %d ", duckinf.Resyncs);
  printf("Singles Missed %d ", duckinf.Single_Pulses_Missing);
  printf("Longest Sequence Missed %d\n", duckinf.Longest_Pulse_Missing);

  last_tick = ctime(&duckinf.Stat_Start);
  printf("start\t%s", last_tick);

  last_tick = ctime(&duckinf.Stat_End);
  printf("host\t%s", last_tick);

  if(duckinf.Last_Ticks) {
    last = (time_t)((duckinf.Last_Ticks >> 32) + (int)(((duckinf.Last_Ticks&0xffffffff) + (double)0x80000000)/0x100000000ll));
    last_tick = ctime(&last);
    printf("dag\t%s", last_tick);
  } else {
    printf("dag\tNo active input - Free running\n");
  }
  if (0 != duckinf.Last_TSC){
    printf("TSC\t%"PRIu64"\n", duckinf.Last_TSC);
  }
  */
  return;
}


void ntpstatus(struct CI* myCI){
  logmsg(stderr,"TIMESYNC","NTP synchronization not supported.\n");
  myCI->synchronized='U';
  return;
}
