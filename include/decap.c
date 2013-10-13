#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "decap.h"
#include "pcapfile.h"

int load(int fd, pcap_file* pcapFile, int fixedSize) {
    if (fd < 0) {
        return 0;
    }

    lseek(fd, 0, SEEK_SET);

    //If the file is fixed-size, set the length.
    if (fixedSize) {
        pcapFile->fixedSize = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
    } else {
        pcapFile->fixedSize = 0;
    }


    pcapFile->fd = fd;
    pcapFile->header = malloc(sizeof (pcap_header));


    //Read the header and make sure we found the expected number of bytes.
    int headerBytesRead =
            read(pcapFile->fd, pcapFile->header, sizeof (pcap_header));

    if (headerBytesRead != sizeof (pcap_header)) {
        fprintf(stderr, "During header read, read %d bytes but expected %d.\n",
                headerBytesRead, sizeof (pcap_header));
        return 0;
    }


    //Read the magic number and infer the precision from it.
    uint32_t mn = pcapFile->header->magic_number;
    pcapFile->nanoResolution = 0;

    switch (mn) {
        case 0xa1b23c4d:
            pcapFile->nanoResolution = 1;
        case 0xa1b2c3d4:
            pcapFile->bytesNeedFlipping = 0;
            break;
        case 0x4d3cb2a1:
            pcapFile->nanoResolution = 1;
        case 0xd4c3b2a1:
            pcapFile->bytesNeedFlipping = 1;
            //TODO: Basically, if the platform that the pcap was created on
            //matches the platform endian-ness that we're reading it from, this
            //won't be a problem.
            //Otherwise, we'll need to do some extra work to flip bits.
            fprintf(stderr,
                    "Endian-flipped captures not supported yet.\n");
            return 0;

            break;
        default:
            fprintf(stderr,
                    "This isn't a pcap file.\n");
            return 0;
    }

    return 1;
}

int unload(pcap_file* pcapFile) {
    if (pcapFile == NULL) {
        return 0;
    }


    free(pcapFile->header);
    return 1;

}

int readPacket(pcap_file* pcapFile, pcap_packet* packet) {
    if (!more(pcapFile))
        return 0;

    //Position of filestream should be on the next header. Read it and the data.
    if (read(pcapFile->fd, &(packet->header), sizeof (pcap_packet_header))
            != sizeof (pcap_packet_header)) {
        fprintf(stderr,
                "Hit EOF reading header, but should have seen it coming.\n");
        return 0;
    }
    

    //Determine the length of this packet and allocate appropriately.
    packet->payload.size = packet->header.incl_len;
    if (packet->payload.size < 1) {
        fprintf(stderr, "Packet length less than 1?\n");
        return 0;
    }

    packet->payload.data = malloc(packet->payload.size);

    if (read(pcapFile->fd, packet->payload.data, packet->payload.size)
            != packet->payload.size) {
        fprintf(stderr,
                "Hit EOF reading data, but should have seen it coming.\n");
        unloadPacket(packet);
        return 0;
    }

    return 1;
}

int unloadPacket(pcap_packet* packet) {
    if (packet == NULL)
        return 0;


    free(packet->payload.data);
}

int more(pcap_file* pcapFile) {
    off_t cur = lseek(pcapFile->fd, 0, SEEK_CUR);


    //Speed optimization if the file isn't going to grow.
    if (pcapFile->fixedSize) {
        return cur != pcapFile->fixedSize;
    }

    //Otherwise, we have to find the end of the file every time.
    off_t end = lseek(pcapFile->fd, 0, SEEK_END);

    //And restore the position.
    lseek(pcapFile->fd, cur, SEEK_SET);

    return (cur != end);
}

int debug_printPackets(pcap_file* pcapFile) {
    int ret = 1;

    printFile(pcapFile);
    printFileHeader(pcapFile->header);

    pcap_packet* ppk = malloc(sizeof (pcap_packet));

    //Read until we can't anymore.
    while (more(pcapFile)) {
        if (!readPacket(pcapFile, ppk)) {
            ret = 0;
            break;
        }

        printPacketHeader(&(ppk->header));
        printPacketData(&(ppk->payload));
        unloadPacket(ppk);
    }


    free(ppk);
    return ret;
}