#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>


#include "decap_includes.h"
#include "replay.h"

/**
 * Prints hello message.
 */
static void hello() {
    printf("replay %s %s\n", __DATE__, __TIME__);
}

/**
 * Prints usage message.
 */
static void usage() {
    printf("Usage: replay <capturefile>\n");
}

/**
 * Prints error message.
 * @param num The error number.
 */
static void error(int num) {
    printf("Error %d", num);
}

static void reverseBytes32(uint32_t* bytes) {
    uint32_t low = (*bytes) & 0xFF;
    uint32_t hi = (*bytes) & 0xFF000000;
    uint32_t left = (*bytes) & 0x00FF0000;
    uint32_t right = (*bytes) & 0x0000FF00;
    *bytes = ((low << 24) + (right << 8) + (left >> 8) + (hi >> 24));
}
/**
 * Given a reference to a pcap packet, look `offset` bytes in for a tcpPacket of
 * length `len` (also verify the length, I guess).
 * 
 * Also reverses the byte order because these fields are saved in network byte order...
 * 
 * @param packet
 * @param offset
 * @param len
 * @param tcpPacket
 */
int extractTCP(void* packetDataPtr, int offset, int len, tcp_packet* tcpPacket) {
    //Copy the header
    memcpy(&(tcpPacket->header), packetDataPtr + offset, sizeof (tcp_header));

    //Fix the data offset field... Stored in the upper nibble is the number of
    //words in this TCP header.
    tcpPacket->header.dataOffset = (tcpPacket->header.dataOffset >> 4) * 4;

    reverseBytes32(&(tcpPacket->header.sequenceNumber));
    printf("Sequence number %x\n", tcpPacket->header.sequenceNumber);

    int payloadLength = len - tcpPacket->header.dataOffset - 20; //Todo: find out where -20 correction factor came from...
    
    printf("The payload must be %d long, and the next sequence number should be %x\n",
            payloadLength, tcpPacket->header.sequenceNumber + payloadLength);
    
    if (payloadLength > 0) {
        printf("First character of payload: %c\n", ((char*)packetDataPtr)[offset + tcpPacket->header.dataOffset]);
    }
    return 1;
}

/**
 * Streams from a pcap file, looking for packets to reconstruct. Rebuilds TCP
 * PDUs and looks for ones that match a user-defined pattern. They are then
 * extracted and organized (via optional inspection parameters for things like
 * ID3 or JFIF tags).
 * 
 * NB: Tagged frames or non-EthernetII frames are not supported and will break.
 * 
 * @param argc Argument count.
 * @param argv Argument values.
 * @return Zero on normal exit, nonzero otherwise.
 */
int main(int argc, char** argv) {
    if (argc != 2) {
        usage();
        return 1;
    }

    hello();

    int fd = open(argv[1], O_RDONLY);

    if (fd < 0) {
        error(1);
        return 1;
    }


    pcap_file pcapFile;

    if (!load(fd, &pcapFile, 0)) {
        error(2);
        return 2;
    }


    /*
     * Extract TCP payloads by inspecting these packets and making sure the IP
     * container is consistent with what we expect.
     */
    for (;;) {
        sleep(1);
        if (!more(&pcapFile)) {
            continue;
        }

        //Begin by reading Ethernet frames out of the packets... Read a packet
        //and check its header for a reasonable size (< 1600 bytes))
        pcap_packet packet;
        readPacket(&pcapFile, &packet);

        if (packet.header.incl_len > 1600) {
            printf("Unreasonably large packet, skipping...\n");
            unloadPacket(&packet);
            continue;
        }

        //These should be EthernetII packets, without the 8-octet preamble. Not
        //that the header info really matters, we want the TCP frame info.

        //Check that this is an IP packet - 0x0800 should appear at bytes 12,13.
        //This is the Ethertype, assuming we're not dealing with tagged frames.
        if (!(packet.payload.data[12] == 0x08
                && packet.payload.data[13] == 0x00)) {
            printf("Not IP packet, skipping.\n");
            unloadPacket(&packet);
            continue;
        }

        //The payload is at _least_ 42 octets long, so we can read it and make
        //sure it's TCP over IP...
        if ((packet.payload.data[14] & 0xF0) != 0x40) {
            printf("Not IPv4, skipping.\n");
            unloadPacket(&packet);
            continue;
        }

        //The second nibble of that is the Internet Header Length which will
        //allow us to locate the data in this header...
        int ipDataOffset = (packet.payload.data[14] & 0x0F) * 4 + 14;


        //Also, make sure it's containing a TCP packet
        if (packet.payload.data[23] != 0x06) {
            printf("Not TCP, skipping.\n");
            unloadPacket(&packet);
            continue;
        }

        //Read the length...
        int ipDataLength = (packet.payload.data[16] << 8) + packet.payload.data[17];

        if ((ipDataLength < 8) || (ipDataLength > 1500)) {
            printf("This data length doesn't make sense: %d\n", ipDataLength);
            unloadPacket(&packet);
            continue;
        }
        printf("Packet payload length is %d\n", packet.payload.payloadSize);
        printf("IPdataLength is %d\n", ipDataLength);
        printf("Offset is %d\n", ipDataOffset);

        //We know this to be TCP, so extract a tcp_packet type from it.
        tcp_packet tcpPacket;

        if (!extractTCP(packet.payload.data, ipDataOffset, ipDataLength, &tcpPacket)) {
            printf("Couldn't extract to TCP, skipping.\n");
            unloadPacket(&packet);
            continue;
        }

    }

    unload(&pcapFile);
    close(fd);
    return (EXIT_SUCCESS);
}

