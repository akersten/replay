#ifndef PCAPFILE_H
#define	PCAPFILE_H

#include <stdint.h>


#ifdef	__cplusplus
extern "C" {
#endif

#define MTU 1500 /* This shouldn't change but it could in the far future. */

    /*
     * A lot of this is documented in the Wireshark development pages.
     * http://wiki.wireshark.org/Development/LibpcapFileFormat
     */

    typedef struct {
        uint32_t magic_number; /* magic number */
        uint16_t version_major; /* major version number */
        uint16_t version_minor; /* minor version number */
        uint32_t thiszone; /* GMT to local correction */
        uint32_t sigfigs; /* accuracy of timestamps */
        uint32_t snaplen; /* max length of captured packets, in octets */
        uint32_t network; /* data link type */
    } pcap_header;

    typedef struct {
        int fd;
        int bytesNeedFlipping; /* If the file was created on a platform whose
                                * endian-ness is opposite to this one, in which
                                * case any field reads need to be flipped. */
        int nanoResolution; /* Otherwise, microseconds only. */
        off_t fixedSize; /* Zero if this file may be appended to, otherwise the
                           * static size of this file - useful for functions
                           * like more() which would otherwise have to seek to
                           * the end of the file every time to determine if 
                           * there are more bytes to be read. Otherwise, set
                           * this size to the length of the file in bytes. */
        pcap_header* header;
    } pcap_file;

    typedef struct {
        uint32_t size;
        uint8_t* data;
    } pcap_packet_data;

    typedef struct {
        uint32_t ts_sec; /* timestamp seconds */
        uint32_t ts_usec; /* timestamp microseconds */
        uint32_t incl_len; /* number of octets of packet saved in file */
        uint32_t orig_len; /* actual length of packet */
    } pcap_packet_header;

    /**
     Separate definition, because adding things to pcap_packet_header would
     change its length, which we use to read things directly from the files...
     */
    typedef struct {
        pcap_packet_header header;
        pcap_packet_data payload; 
    } pcap_packet;



    void printPacketHeader(pcap_packet_header* header);
    void printPacketData(pcap_packet_data* header);
    void printFileHeader(pcap_header* header);
    void printFile(pcap_file* header);


#ifdef	__cplusplus
}
#endif

#endif	/* PCAPFILE_H */

