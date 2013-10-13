/* 
 * File:   replay.h
 * Author: alex
 *
 * Created on October 13, 2013, 2:34 AM
 */

#ifndef REPLAY_H
#define	REPLAY_H

#include <stdint.h>

#ifdef	__cplusplus
extern "C" {
#endif

    typedef struct {
        uint16_t sourcePort;
        uint16_t destPort;
        uint32_t sequenceNumber; /* Network byte order! When we read these in,
                                  * we'll have to reverse them to be little-endian */
        uint32_t ackNumber;
        uint8_t dataOffset;
        uint8_t flags;
        uint16_t windowSize;
        uint16_t checksum;
        uint16_t urgentPtr;
    } tcp_header;
    
    typedef struct {
        int payloadSize;
        int sequenceNumber;
        tcp_header header;
        uint8_t* payload;
    } tcp_packet;


#ifdef	__cplusplus
}
#endif

#endif	/* REPLAY_H */

