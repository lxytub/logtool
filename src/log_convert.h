/*
 * log_convert.h
 *
 *  Created on: 2019年12月16日
 *      Author: lxy
 */

#ifndef LOG_CONVERT_H_
#define LOG_CONVERT_H_

#define ETHERTYPE_IP 0x0800   //IP Protocal

#define FALSE 0
#define TRUE 1

#pragma pack( push, 1)
// 为了保证在windows和linux下都能正常编译，放弃使用INT64或者_int_64
typedef short _Int16;
typedef	long  _Int32;
typedef char Byte;

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

typedef signed char int8_t;
typedef signed short int16_t;
typedef signed int int32_t;

// pcap头占用24个字节，文件至少24个字节
#define MIN_FILE_SIZE 24

#define UDP_DEST_PORT_L2_LOG 8888

// Pcap文件头 24 bytes
typedef struct __file_header
{
	_Int32	iMagic;
	_Int16	iMaVersion;
	_Int16	iMiVersion;
	_Int32	iTimezone;
	_Int32	iSigFlags;
	_Int32	iSnapLen;
	_Int32	iLinkType;
} s_pcap_header;

/*
linktype为链路类型（4个字节）
常用类型：
0            BSD loopback devices, except for later OpenBSD
1            Ethernet, and Linux loopback devices
6            802.5 Token Ring
7            ARCnet
8            SLIP
9            PPP
10           FDDI
100         LLC/SNAP-encapsulated ATM
101         “raw IP”, with no link
102         BSD/OS SLIP
103         BSD/OS PPP
104         Cisco HDLC
105         802.11
108         later OpenBSD loopback devices (with the AF_value in network byte order)
113         special Linux “cooked” capture
114         LocalTal
*/

enum linktype
{
	LINKTYPE_ETHERNET = 1,
	LINKTYPE_SLL = 113
};


#define PKT_HEADER_LENGTH sizeof(s_pkt_header) //16 bytes
#define ETHERNET_HEADER_LENGTH sizeof(eth_header) //14bytes
#define SSL_HEADER_LENGTH sizeof(sll_header) //16bytes
#define IP_HEADER_LENGTH sizeof(s_ip_header) //20bytes
#define UDP_HEADER_LENGTH sizeof(s_udp_header) //8bytes
#define LUA_HEADER_LENGTH sizeof(WS_Proto_Head) //16bytes
//#define TOTAL_HEADER_LENGTH (PKT_HEADER_LENGTH + SSL_HEADER_LENGTH + IP_HEADER_LENGTH + UDP_HEADER_LENGTH + LUA_HEADER_LENGTH)
//#define SSL_IP_UDP_LUA_LENGTH (TOTAL_HEADER_LENGTH - PKT_HEADER_LENGTH)

#define MSG_UCI_IND_HEADER_LENGTH sizeof(RXUCIIndicationStruct)
#define MSG_UCI_IND_PAYLOAD_LENGTH sizeof(ULUCIPDUDataStruct)
#define MSG_UCI_IND_TOTAL_LENGTH (MSG_UCI_IND_HEADER_LENGTH + MSG_UCI_IND_PAYLOAD_LENGTH)

#define MSG_CRC_IND_HEADER_LENGTH sizeof(CRCIndicationStruct)
#define MSG_CRC_IND_PAYLOAD_LENGTH sizeof(ULCRCStruct)
#define MSG_CRC_IND_TOTAL_LENGTH (MSG_CRC_IND_HEADER_LENGTH + MSG_CRC_IND_PAYLOAD_LENGTH)

// 有8字节对齐???
#define MSG_ULSCH_IND_HEADER_LENGTH (sizeof(RXULSCHIndicationStruct) + 4)
#define MSG_ULSCH_IND_PAYLOAD_LENGTH (sizeof(ULSCHPDUDataStruct) + 4)
#define MSG_ULSCH_IND_TOTAL_LENGTH (MSG_ULSCH_IND_HEADER_LENGTH + MSG_ULSCH_IND_PAYLOAD_LENGTH)

#define MSG_RACH_IND_HEADER_LENGTH sizeof(RXRACHIndicationStruct)
#define MSG_RACH_IND_PAYLOAD_LENGTH sizeof(PreambleStruct)
#define MSG_RACH_IND_TOTAL_LENGTH (MSG_RACH_IND_HEADER_LENGTH + MSG_RACH_IND_PAYLOAD_LENGTH)

#define MSG_DL_CONFIG_REQ_HEADER_LENGTH sizeof(DLConfigRequestStruct)
#define MSG_DL_CONFIG_REQ_HEADER_WO_GROUP_LENGTH (MSG_DL_CONFIG_REQ_HEADER_LENGTH - sizeof(PDSCHGroupInfoStruct)*MAX_MIMO_GROUP_NUM)

#define MSG_UL_CONFIG_REQ_HEADER_LENGTH sizeof(ULConfigRequestStruct)
#define MSG_UL_CONFIG_REQ_HEADER_WO_GROUP_LENGTH (MSG_UL_CONFIG_REQ_HEADER_LENGTH - sizeof(PUSCHGroupInfoStruct)*MAX_MIMO_GROUP_NUM)

#define MSG_UL_DCI_REQ_HEADER_LENGTH sizeof(ULDCIRequestStruct)
#define MSG_UL_DCI_REQ_PAYLOAD_LENGTH sizeof(DCIPDUStruct)
#define MSG_UL_DCI_TOTAL_LENGTH (MSG_UL_DCI_REQ_HEADER_LENGTH + MSG_UL_DCI_REQ_PAYLOAD_LENGTH)

// 数据包头 16 bytes
typedef struct __pkthdr
{
	_Int32		iTimeSecond;
	_Int32		iTimeSS;
	_Int32		iPLength;
	_Int32		iLength;
} s_pkt_header;

// SLL header 16bytes
typedef struct _sllhdr
{
	u_short packetType;
	u_short linkLayerAdrType;
	u_short linkLayerAdrLength;
	u_char  linkLayerAddr[8];
	u_short protocolType;
} sll_header;

// ethernet header 14bytes
typedef struct _eth_hdr
{
    unsigned char dstmac[6]; //目标mac地址
    unsigned char srcmac[6]; //源mac地址
    unsigned short eth_type; //以太网类型
}eth_header;

//IP报头 20 bytes
typedef struct ip
{
    u_char ip_hl:4; //header length(报头长度)
    u_char ip_v:4; //version(版本)
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
} s_ip_header;

// UDP header 8 bytes
typedef struct UDPHeader {
	u_short SourcePort;             //源端口
	u_short DestinationPort;        //目的端口
	u_short Length;                 //长度
	u_short Checksum;               //检验和
} s_udp_header;

enum luaMsgType
{
  LUA_MSG_TYPE_PDCP_TO_RLC       = 0x16,
	LUA_MSG_TYPE_PHY_DL_CONFIG_REQ = 0x41,
	LUA_MSG_TYPE_PHY_UL_DCI_REQ    = 0x43,
	LUA_MSG_TYPE_PHY_UL_CONFIG_REQ = 0x44,
	LUA_MSG_TYPE_PHY_CRC_IND       = 0x51,
	LUA_MSG_TYPE_PHY_ULSCH_IND     = 0x52,
	LUA_MSG_TYPE_PHY_UCI_IND       = 0x53,
	LUA_MSG_TYPE_PHY_RACH_IND      = 0x54
};

#pragma pack( pop)

u_char writeFile(FILE* pFile, char *pBuffer, u_int size, long long iIndex);
void updLengthField(s_pkt_header *pPktHeader, s_ip_header * pIpHeader,
                    s_udp_header * pUdpHeader, void *pMsgHeader,
                    u_int linkHdrLen, u_char msgType);

#endif /* LOG_CONVERT_H_ */
