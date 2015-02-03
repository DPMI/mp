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

 
#define DAGDRIVER_MAJOR 5


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "timesync.h"
#include "log.h"
#include <string.h>

#ifdef HAVE_DRIVER_DAG
#if DAGDRIVER_MAJOR >3
 #include <dag_config_api.h>
 dag_card_ref_t card_ref;
 dag_component_t root_component; 
 uint32_t count;

#else 
 #include <dagapi.h>
 #include <dag_platform.h>
 #include <dagutil.h>
 #include <dagclarg.h>

 enum {
  Duck_Command= 0x00,
  Duck_Config= 0x04,
  Duck_High_Load= 0x0c,
  Duck_DDS_Rate= 0x14,
  Duck_High_Read= 0x18,
  Duck_Low_Read= 0x1c,
 };

 # define DUCK(OFF) (*(volatile unsigned *)(iom+duck_base+(OFF)))

 static int dagfd;
 static duckinf_t duckinf;
 static volatile uint8_t *iom;
 static unsigned duck_base;
#endif 

static void duckstatus(struct CI* myCI);
#endif /* HAVE_DRIVER_DAG */

#ifndef HAVE_DRIVER_DAG
static void ntpstatus(struct CI* myCI);
#endif


#ifndef OLDDAG
int timesync_init(struct CI* myCI) {
  logmsg(verbose, SYNC, "Init of %s .\n", myCI->iface);
#ifdef HAVE_DRIVER_DAG

#if DAGDRIVER_MAJOR >3
 card_ref = NULL;
 root_component = NULL;
#else
  dag_reg_t result[DAG_REG_MAX_ENTRIES];
  unsigned regn;
  dag_reg_t *regs;
  duckinf.Set_Duck_Field = 0;
  duckinf.Last_TSC = 0;
#endif /* DAGDRIVER_MAJOR 3 */
  if(strncmp(myCI->iface,"dag",3)==0){
#if DAGDRIVER_MAJOR > 3
    card_ref = dag_config_init(myCI->iface);
    root_component = dag_config_get_root_component(card_ref);
#else
    dagfd=myCI->sd;
    iom = dag_iom(dagfd);
    /*DUCK */
    regs = dag_regs(dagfd);
    regn=0;
    if ((dag_reg_table_find(regs, 0, DAG_REG_DUCK, result, &regn)) || (!regn)) {
      dagutil_panic("Dag does not support DUCK functions\n");
      return(0);
    } else {
      duck_base = DAG_REG_ADDR(*result);
    }

    int localerror;
    if((localerror = ioctl(dagfd, DAGIOCDUCK, &duckinf))){
      dagutil_panic("DAGIOCDUCK failed with %d\n", localerror);
    }
#endif /* DAGDRIVER_MAJOR >3 */

    duckstatus(myCI);

} else { /* Default to NTP if no DAG is found */
	  myCI->synchronized='U';
  }
  return(1);
}
#endif /* HAVE_DRIVER_DAG l71 */

int timesync_status(struct CI* myCI){
  logmsg(verbose, SYNC, "Status  %s .\n", myCI->iface);

#ifdef HAVE_DRIVER_DAG
  if(strncmp(myCI->iface,"dag",3)==0){
#if DAGDRIVER_MAJOR > 3

#else
    dagfd=myCI->sd;
    iom=dag_iom(dagfd);
    int localerror;

    if((localerror = ioctl(dagfd, DAGIOCDUCK, &duckinf))){
      dagutil_panic("DAGIOCDUCK failed with %d\n", localerror);
      return(0);
    }
#endif

    duckstatus(myCI);
  } else {
#else /* HAVE_DRIVER_DAG */
    ntpstatus(myCI);
#endif /* HAVE_DRIVER_DAG */
#ifdef HAVE_DRIVER_DAG
  }
#endif /* HAVE_DRIVER_DAG */

  return(1);
}

#ifdef HAVE_DRIVER_DAG
static void duckstatus(struct CI* myCI) {
#if DAGDRIVER_MAJOR >3
 dag_component_t port = NULL;
 port = dag_component_get_subcomponent(root_component, kComponentDUCK,0);


 if (dag_component_get_config_attribute_uuid(port,kBooleanAttributeDUCKSynchronized)){
  myCI->synchronized='Y';
 } else {
  myCI->synchronized='N';
 }
 
 myCI->frequency=dag_component_get_config_attribute_uuid(port, kUint32AttributeDUCKCrystalFrequency);
 myCI->starttime=0;
 myCI->citime= 0;
 myCI->hosttime=0;
#else
 DUCK(Duck_Config);

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
#endif

  return;
}
#endif /* HAVE_DRIVER_DAG */

#ifndef HAVE_DRIVER_DAG
static void ntpstatus(struct CI* myCI){
  logmsg(stderr,"TIMESYNC","NTP synchronization not supported.\n");
  myCI->synchronized='U';
  return;
}
#endif /* HAVE_DRIVER_DAG */



#else /* ifndef OLDDAG , i.e. if olddag is defined, we do not try to read sync */ 
int timesync_init(struct CI* myCI) {
  return(1);
}


void ntpstatus(struct CI* myCI){
  return;
}

int timesync_status(struct CI* myCI){
  logmsg(stderr,"TIMESYNC","DAG synchronization not supported.\n");
  myCI->synchronized='U';
  return(1);
}

#endif
