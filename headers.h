/* *******************************************************************
   headers.h -- Description
   ------------------------
   begin: Sun, 11 Dec. 2005
   Copyright: (C) Patrik Arlos
   email: patrik.arlos@bth.se

   This file holds the common headers used by both measurement points 
   as well as the consumer.

****************************************************************** */
/**************************************************************************
*                                                                         *
*   This program is free software; you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation; either version 2 of the License, or     *
*   (at your option) any later version.                                   *
*                                                                         *
***************************************************************************/  


#define VERSION "0.6"
#define VERSION_MAJOR 0
#define VERSION_MINOR 6
#define LLPROTO 0x0810
#define LISTENPORT 0x0810
#define PKT_CAPSIZE 1514 //Maximum nr of bytes captured from each packet

// Time struct for precision down to picoseconds                                           
struct picotime {                                                                          
  time_t tv_sec;                                                                         
  uint64_t tv_psec;                                                                      
} __attribute__((packed));                                                                 
                                                                                           
typedef struct picotime timepico;                                                          
                                                                                           
// Struct with the version of this libraryfile                                             
// A simple structure used to store a version number.                                      
// The number is divided into a major and minor number.                                    
struct file_version{                                                                       
  uint8_t major;                                                                           
  uint8_t minor;                                                                           
};                                                                                         
                                                                                           
// File header, when a cap file is stored to disk. This header is placed first.            
// The header has two parts, header and comment. After the comment the frames              
// are stored.                                                                             
struct file_header{                                                                        
  int comment_size;                     // How large is the comment                        
  struct file_version version;          // What version was used to store this file        
  char mpid[200];                       // Which MP(or MPs) created this file.             
};                

// Capture Header. This header is attached to each 
// packet that we keep, i.e. it matched a filter.
struct cap_header{                                                                      
  char nic[4];            // Identifies the CI where the frame was caught    
  char mampid[8];         // Identifies the MP where the frame was caught,   
  timepico ts;            // Identifies when the frame was caught            
  uint8_t tsAccuracy;     // Identifies the accuracy of the timestamp, number 
                          // of digits to trust.
  uint8_t flags;          // Identifies the flags set for the PDU.           
  uint16_t len;           // Identifies the lenght of the frame 
  uint16_t caplen;        // Identifies how much of the frame that we find here
  uint16_t reserved;         // Various flags. Needed to make the header a 
                          // multiple of 32 bits.
} __attribute__((packed));                                                         
typedef struct cap_header  cap_head;



// Send Structure, used infront of each send data packet. The sequence 
// number is indicates the number of sent data packets. I.e. after a 
// send packet this value is increased by one.
//                                                                                         
struct sendhead {
  long sequencenr;         // Sequence number.
  uint16_t nopkts;         // How many packets are here.
  uint16_t flush;          // Indicate that this is the last packet.
  uint16_t losscounter;    // How many PDUs were lost during the creation
                           // of this frame?
  struct file_version version; // What version of the file format is 
                           // used for stotring mp_pkts.
};


//Filter struct are base on binary indexing in filter.index                                
//Ex. to filter on source and destination adresses the index would look like:              
// 1000 0000 0000 0000 0000 0000 0011 1100                                                 
// and the fields src_mask, dst_mask, src_ip and dst_ip contains the information           
struct filter{                                                                             
  u_int32_t index;                      //{2^31} 
  timepico starttime;                   //{4096}    Start time
  timepico endtime;                     //{2048}    End time
  char mampid[8];                       //{1024]    mpid
  char nic[8];                          //{512}     if
  u_int16_t vlan;                       //{256}     eth.vlan
  u_int16_t eth_type;                   //{128}     eth.type
  unsigned char eth_src[6];             //{64}      eth.src
  unsigned char eth_dst[6];             //{32}      eth.dst
  u_int8_t ip_proto;                    //{16}      ip.proto
  char ip_src[16];                      //{8}       ip.src
  char ip_dst[16];                      //{4}       ip.dst
  u_int16_t tp_sport;                   //{2}       tp.port
  u_int16_t tp_dport;                   //{1}       tp.port
  u_int16_t vlan_mask;                  //
  u_int16_t eth_type_mask;              //
  unsigned char eth_src_mask[6];        //
  unsigned char eth_dst_mask[6];        //
  char ip_src_mask[16];                 //
  char ip_dst_mask[16];                 //
  u_int16_t tp_sport_mask;              //
  u_int16_t tp_dport_mask;              //
                                                                                           
};          
