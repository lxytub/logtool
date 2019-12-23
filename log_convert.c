/*
 ============================================================================
 Name        : log_convert.c
 Author      : 
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include "log_convert.h"
#include "gnb_l1l2_api.h"
#include "cmn_udp_msg.h"

unsigned int MAGIC = 0xa1b2c3d4;

#define RETURN_ON_FAILURE(_inFile, _outFile) \
	fclose(_inFile); \
	fclose(_outFile); \
	return EXIT_SUCCESS;

int main(int argc, char **argv) {

	unsigned char buffer[2048] = {0};
	unsigned char *pBuf = buffer;
	//u_int rnti;
	int len, iIndex, iPktLength;
	int lenToWrite;
	s_pkt_header *pPktHeader;
	unsigned char * pPktPayload;
	//sll_header * pSLLHeader;
	void * pLinkHeader;
	//u_short sslProtocolType;
	u_short protocolType;
	s_ip_header * pIpHeader;
	u_char ipProtocolType;
	s_udp_header * pUdpHeader;
	u_short udpDestPort;
	WS_Proto_Head *pL2logHeader;


	u_char uciCount;
	RXUCIIndicationStruct * pUciIndHeader;
	ULUCIPDUDataStruct * pUciPdu;

	CRCIndicationStruct * pCrcIndHeader;
	ULCRCStruct * pCrcPdu;
	u_char crcCount;

	RXULSCHIndicationStruct *pUlschIndHeader;
	ULSCHPDUDataStruct * pUlschPdu;
	u_char ulschCount;

	RXRACHIndicationStruct *pRachIndHeader;
	PreambleStruct * pRachPdu;
	u_char pidCount;

	DLConfigRequestStruct *pDlConfigHeader;
	PDUStruct *pDlConfigPdu;
	u_char groupCount;
	u_char pduCount;

	ULConfigRequestStruct *pUlConfigHeader;
	PDUStruct *pUlConfigPdu;

	ULDCIRequestStruct *pUlDciHeader;
	DCIPDUStruct *pUlDciPdu;

	if (3 != argc && 4 != argc)
	{
		printf("Usage: %s inputfile outputfile\n", argv[0]);
		return EXIT_SUCCESS;
	}

	//rnti = atoi(argv[]);

	FILE* pInputFile = fopen(argv[1], "rb");
	FILE* pOutputFile = fopen(argv[2], "wb");

	if (pInputFile == 0)
	{
		printf("Failed to open %s\n", argv[1]);
		return EXIT_SUCCESS;
	}

	if (pOutputFile == 0)
	{
		printf("Failed to open %s\n", argv[2]);
		return EXIT_SUCCESS;
	}

	// 获取文件大小，最大2G
	fseek(pInputFile, 0, SEEK_END);
	long iFileLen = ftell(pInputFile);
	fseek(pInputFile, 0, SEEK_SET);

	// pcap文件头是24 bytes
	if (iFileLen < MIN_FILE_SIZE)
	{
		printf("Invalid file size: %ld\n", iFileLen);
		fclose( pInputFile);
		return EXIT_SUCCESS;
	}

	// 读取pcap头
	len = fread(pBuf, sizeof(char), sizeof(s_pcap_header), pInputFile);

	//printf("Read pcap header, len = %d\n", len);

	if (len != sizeof(s_pcap_header))
	{
		printf("Read pcap header failed, len = %d\n", len);
		fclose( pInputFile);
		return EXIT_SUCCESS;
	}

	s_pcap_header * pPcapHeader = (s_pcap_header *)pBuf;

	if ((unsigned int)pPcapHeader->iMagic != MAGIC)
	{
		printf("Invalid Pcap iMagic = 0x%x\n", (unsigned int)pPcapHeader->iMagic);
		fclose( pInputFile);
		return EXIT_SUCCESS;
	}

	//printf("iLinkType=%ld\n", pPcapHeader->iLinkType);
	u_int linkType = (u_int)pPcapHeader->iLinkType;
	if (linkType != LINKTYPE_SLL
	    && linkType != LINKTYPE_ETHERNET)
	{
		printf("Pcap file linktype (%d) not supported\n", (unsigned int)pPcapHeader->iLinkType);
		fclose( pInputFile);
		return EXIT_SUCCESS;
	}

	u_int linkHdrLen;
	if (linkType == LINKTYPE_SLL)
	{
		linkHdrLen = SSL_HEADER_LENGTH;
	}
	else if (linkType == LINKTYPE_ETHERNET)
	{
		linkHdrLen = ETHERNET_HEADER_LENGTH;
	}

	const u_int TOTAL_HEADER_LENGTH = PKT_HEADER_LENGTH + linkHdrLen + IP_HEADER_LENGTH + UDP_HEADER_LENGTH + LUA_HEADER_LENGTH;
	const u_int LINK_IP_UDP_LUA_LENGTH = TOTAL_HEADER_LENGTH - PKT_HEADER_LENGTH;
	const u_int LINK_HEADER_LENGTH = linkHdrLen;

	len = fwrite(pBuf, sizeof(char), sizeof(s_pcap_header), pOutputFile);
	if (len != sizeof(s_pcap_header))
	{
		printf("Write pcap header failed, len = %d\n", len);
		fclose(pOutputFile);
		return EXIT_SUCCESS;
	}

	iIndex = sizeof(s_pcap_header);

	while (iIndex < iFileLen)
	{
		// 读取包头
		len = fread(pBuf, sizeof(char), sizeof(s_pkt_header), pInputFile);
		if (len != sizeof(s_pkt_header))
		{
			printf("Failed to read package header, iIndex=%d, len=%d\n", iIndex, len);
			RETURN_ON_FAILURE(pInputFile, pOutputFile);
		}
		pPktHeader = (s_pkt_header *)pBuf;

		//printf("pPktHeader iLength=%ld, iPLength=%ld\n", pPktHeader->iLength, pPktHeader->iPLength);

		pBuf = pBuf + sizeof(s_pkt_header);
		iPktLength = pPktHeader->iPLength;

		// read packet payload
		len = fread(pBuf, sizeof(char), iPktLength, pInputFile);
		if (len != iPktLength)
		{
			printf("Failed to read package payload, iFileLen=%ld, iIndex=%d, iPktLength=%d, len=%d\n",
					iFileLen, iIndex, iPktLength, len);
			if ((iIndex + iPktLength) > iFileLen)
			{
				printf("Current packet is corrupt, previous packets have been saved to %s.\n", argv[2]);
			}
			RETURN_ON_FAILURE(pInputFile, pOutputFile);
		}

		pPktPayload = pBuf;
		if (linkType == LINKTYPE_SLL)
		{
			pLinkHeader = (sll_header *)pPktPayload;
			protocolType = ntohs(((sll_header *)pLinkHeader)->protocolType);
		}
		else if (linkType == LINKTYPE_ETHERNET)
		{
			pLinkHeader = (eth_header *)pPktPayload;
			protocolType = ntohs(((eth_header *)pLinkHeader)->eth_type);
		}

		//pSLLHeader = (sll_header *)pPktPayload;
		//protocolType = ntohs(pSLLHeader->protocolType);

		if (ETHERTYPE_IP == protocolType)
		{
			pIpHeader = (s_ip_header *)((char *)pLinkHeader + LINK_HEADER_LENGTH);

			ipProtocolType = pIpHeader->ip_p;

			if (IPPROTO_UDP == ipProtocolType)
			{
				pUdpHeader = (s_udp_header *)(pIpHeader + 1);
				udpDestPort = ntohs(pUdpHeader->DestinationPort);

				if (UDP_DEST_PORT_L2_LOG == udpDestPort)
				{
					pL2logHeader = (WS_Proto_Head *)(pUdpHeader + 1);
					u_short luaMsgType = pL2logHeader->usLuaMsgType;

					switch(luaMsgType)
					{
						case LUA_MSG_TYPE_PHY_UCI_IND:
							pUciIndHeader = (RXUCIIndicationStruct *)(pL2logHeader + 1);
							uciCount = pUciIndHeader->nUCI;

							if (uciCount < 2)
							{
								// write packet
								if (FALSE == writeFile(pOutputFile, (char *)pPktHeader, (sizeof(s_pkt_header) + iPktLength), iIndex))
								{
									RETURN_ON_FAILURE(pInputFile, pOutputFile);
								}

								/*
								len = fwrite((char *)pPktHeader, sizeof(char), sizeof(s_pkt_header) + iPktLength, pOutputFile);
								if (len != (sizeof(s_pkt_header) + iPktLength))
								{
									printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
									RETURN_ON_FAILURE(pInputFile, pOutputFile);
								}
								*/
							}
							else
							{
								for (int i = 0; i < uciCount; i++)
								{
									pUciPdu = pUciIndHeader->sULUCIPDUDataStruct + i;

									// write packet header
									lenToWrite = TOTAL_HEADER_LENGTH + MSG_UCI_IND_HEADER_LENGTH;

									// update the length field
									pPktHeader->iLength = LINK_IP_UDP_LUA_LENGTH + MSG_UCI_IND_TOTAL_LENGTH;
									pPktHeader->iPLength = pPktHeader->iLength;
									pIpHeader->ip_len = htons(pPktHeader->iLength - LINK_HEADER_LENGTH);
									pUdpHeader->Length = htons(ntohs(pIpHeader->ip_len) - IP_HEADER_LENGTH);
									pUciIndHeader->sMsgHdr.nMessageLen = MSG_UCI_IND_TOTAL_LENGTH;
									pUciIndHeader->nUCI = 1;

									if (fwrite((char *)pPktHeader, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}

									lenToWrite = sizeof(ULUCIPDUDataStruct);
									if (fwrite((char *)pUciPdu, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}
								}
							}
							break;
						case LUA_MSG_TYPE_PHY_CRC_IND:
							pCrcIndHeader = (CRCIndicationStruct *)(pL2logHeader + 1);
							crcCount = pCrcIndHeader->nCrc;

							if (crcCount < 2)
							{
								// write packet
								len = fwrite((char *)pPktHeader, sizeof(char), PKT_HEADER_LENGTH + iPktLength, pOutputFile);
								if (len != (PKT_HEADER_LENGTH + iPktLength))
								{
									printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
									RETURN_ON_FAILURE(pInputFile, pOutputFile);
								}
							}
							else
							{
								for (int i = 0; i < crcCount; i++)
								{
									pCrcPdu = pCrcIndHeader->sULCRCStruct + i;

									// write packet header
									lenToWrite = TOTAL_HEADER_LENGTH + MSG_CRC_IND_HEADER_LENGTH;

									// update the length field
									pPktHeader->iLength = LINK_IP_UDP_LUA_LENGTH + MSG_CRC_IND_TOTAL_LENGTH;
									pPktHeader->iPLength = pPktHeader->iLength;
									pIpHeader->ip_len = htons(pPktHeader->iLength - LINK_HEADER_LENGTH);
									pUdpHeader->Length = htons(ntohs(pIpHeader->ip_len) - IP_HEADER_LENGTH);
									pCrcIndHeader->sMsgHdr.nMessageLen = MSG_CRC_IND_TOTAL_LENGTH;
									pCrcIndHeader->nCrc = 1;

									if (fwrite((char *)pPktHeader, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}

									lenToWrite = MSG_CRC_IND_PAYLOAD_LENGTH;
									if (fwrite((char *)pCrcPdu, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}
								}
							}
							break;
						case LUA_MSG_TYPE_PHY_ULSCH_IND:
							pUlschIndHeader = (RXULSCHIndicationStruct *)(pL2logHeader + 1);
							ulschCount = pUlschIndHeader->nUlsch;

							if (ulschCount < 2)
							{
								// write packet
								len = fwrite((char *)pPktHeader, sizeof(char), PKT_HEADER_LENGTH + iPktLength, pOutputFile);
								if (len != (PKT_HEADER_LENGTH + iPktLength))
								{
									printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
									RETURN_ON_FAILURE(pInputFile, pOutputFile);
								}
							}
							else
							{
								for (int i = 0; i < ulschCount; i++)
								{
									pUlschPdu = (ULSCHPDUDataStruct *)((char *)pUlschIndHeader + MSG_ULSCH_IND_HEADER_LENGTH + i*MSG_ULSCH_IND_PAYLOAD_LENGTH);

									// write packet header
									lenToWrite = TOTAL_HEADER_LENGTH + MSG_ULSCH_IND_HEADER_LENGTH;

									// update the length field
									pPktHeader->iLength = LINK_IP_UDP_LUA_LENGTH + MSG_ULSCH_IND_TOTAL_LENGTH;
									pPktHeader->iPLength = pPktHeader->iLength;
									pIpHeader->ip_len = htons(pPktHeader->iLength - LINK_HEADER_LENGTH);
									pUdpHeader->Length = htons(ntohs(pIpHeader->ip_len) - IP_HEADER_LENGTH);
									pUlschIndHeader->sMsgHdr.nMessageLen = MSG_ULSCH_IND_TOTAL_LENGTH;
									pUlschIndHeader->nUlsch = 1;

									if (fwrite((char *)pPktHeader, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}

									lenToWrite = MSG_ULSCH_IND_PAYLOAD_LENGTH;
									if (fwrite((char *)pUlschPdu, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}
								}
							}
							break;
						case LUA_MSG_TYPE_PHY_RACH_IND:
							pRachIndHeader = (RXRACHIndicationStruct *)(pL2logHeader + 1);
							pidCount = pRachIndHeader->nNrOfPreamb;

							if (pidCount < 2)
							{
								// write packet
								len = fwrite((char *)pPktHeader, sizeof(char), PKT_HEADER_LENGTH + iPktLength, pOutputFile);
								if (len != (PKT_HEADER_LENGTH + iPktLength))
								{
									printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
									RETURN_ON_FAILURE(pInputFile, pOutputFile);
								}
							}
							else
							{
								for (int i = 0; i < pidCount; i++)
								{
									pRachPdu = pRachIndHeader->sPreambleStruct + i;

									// write packet header
									lenToWrite = TOTAL_HEADER_LENGTH + MSG_RACH_IND_HEADER_LENGTH;

									// update the length field
									pPktHeader->iLength = LINK_IP_UDP_LUA_LENGTH + MSG_RACH_IND_TOTAL_LENGTH;
									pPktHeader->iPLength = pPktHeader->iLength;
									pIpHeader->ip_len = htons(pPktHeader->iLength - LINK_HEADER_LENGTH);
									pUdpHeader->Length = htons(ntohs(pIpHeader->ip_len) - IP_HEADER_LENGTH);
									pRachIndHeader->sMsgHdr.nMessageLen = MSG_RACH_IND_TOTAL_LENGTH;
									pRachIndHeader->nNrOfPreamb = 1;

									if (fwrite((char *)pPktHeader, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}

									lenToWrite = MSG_RACH_IND_PAYLOAD_LENGTH;
									if (fwrite((char *)pRachPdu, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}
								}
							}
							break;
						case LUA_MSG_TYPE_PHY_DL_CONFIG_REQ:
							pDlConfigHeader = (DLConfigRequestStruct *)(pL2logHeader + 1);
							groupCount = pDlConfigHeader->nGroup;
							pduCount = pDlConfigHeader->nPDU;

							// write packet only include group info
							if (groupCount > 0)
							{
								// group info is included in the header
								lenToWrite = TOTAL_HEADER_LENGTH + MSG_DL_CONFIG_REQ_HEADER_LENGTH;

								// update the length field
								pPktHeader->iLength = LINK_IP_UDP_LUA_LENGTH + MSG_DL_CONFIG_REQ_HEADER_LENGTH;
								pPktHeader->iPLength = pPktHeader->iLength;
								pIpHeader->ip_len = htons(pPktHeader->iLength - LINK_HEADER_LENGTH);
								pUdpHeader->Length = htons(ntohs(pIpHeader->ip_len) - IP_HEADER_LENGTH);
								pDlConfigHeader->sMsgHdr.nMessageLen = MSG_DL_CONFIG_REQ_HEADER_LENGTH;
								pDlConfigHeader->nPDU = 0;

								if (fwrite((char *)pPktHeader, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
								{
									printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
									RETURN_ON_FAILURE(pInputFile, pOutputFile);
								}
							}

							if (pduCount > 0)
							{
								pDlConfigPdu = pDlConfigHeader->sDLPDU;

								for (int i = 0; i < pduCount; i++)
								{
									// write packet header without group info
									lenToWrite = TOTAL_HEADER_LENGTH + MSG_DL_CONFIG_REQ_HEADER_WO_GROUP_LENGTH;

									// update the length field
									pPktHeader->iLength = LINK_IP_UDP_LUA_LENGTH + MSG_DL_CONFIG_REQ_HEADER_WO_GROUP_LENGTH + pDlConfigPdu->nPDUSize;
									pPktHeader->iPLength = pPktHeader->iLength;
									pIpHeader->ip_len = htons(pPktHeader->iLength - LINK_HEADER_LENGTH);
									pUdpHeader->Length = htons(ntohs(pIpHeader->ip_len) - IP_HEADER_LENGTH);
									pDlConfigHeader->sMsgHdr.nMessageLen = MSG_DL_CONFIG_REQ_HEADER_WO_GROUP_LENGTH + pDlConfigPdu->nPDUSize;
									pDlConfigHeader->nPDU = 1;
									pDlConfigHeader->nGroup = 0;

									if (fwrite((char *)pPktHeader, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}

									lenToWrite = pDlConfigPdu->nPDUSize;
									if (fwrite((char *)pDlConfigPdu, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}

									pDlConfigPdu = (PDUStruct *)((u_char *)pDlConfigPdu + pDlConfigPdu->nPDUSize);
								}
							}
							break;
						case LUA_MSG_TYPE_PHY_UL_CONFIG_REQ:
							pUlConfigHeader = (ULConfigRequestStruct *)(pL2logHeader + 1);
							groupCount = pUlConfigHeader->nGroup;
							pduCount = pUlConfigHeader->nPDU;

							// write packet only include group info
							if (groupCount > 0)
							{
								// group info is included in the header
								lenToWrite = TOTAL_HEADER_LENGTH + MSG_UL_CONFIG_REQ_HEADER_LENGTH;

								// update the length field
								pPktHeader->iLength = LINK_IP_UDP_LUA_LENGTH + MSG_UL_CONFIG_REQ_HEADER_LENGTH;
								pPktHeader->iPLength = pPktHeader->iLength;
								pIpHeader->ip_len = htons(pPktHeader->iLength - LINK_HEADER_LENGTH);
								pUdpHeader->Length = htons(ntohs(pIpHeader->ip_len) - IP_HEADER_LENGTH);
								pUlConfigHeader->sMsgHdr.nMessageLen = MSG_UL_CONFIG_REQ_HEADER_LENGTH;
								pUlConfigHeader->nPDU = 0;

								if (fwrite((char *)pPktHeader, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
								{
									printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
									RETURN_ON_FAILURE(pInputFile, pOutputFile);
								}
							}

							if (pduCount > 0)
							{
								pUlConfigPdu = pUlConfigHeader->sULPDU;

								for (int i = 0; i < pduCount; i++)
								{
									// write packet header without group info
									lenToWrite = TOTAL_HEADER_LENGTH + MSG_UL_CONFIG_REQ_HEADER_WO_GROUP_LENGTH;

									// update the length field
									pPktHeader->iLength = LINK_IP_UDP_LUA_LENGTH + MSG_UL_CONFIG_REQ_HEADER_WO_GROUP_LENGTH + pUlConfigPdu->nPDUSize;
									pPktHeader->iPLength = pPktHeader->iLength;
									pIpHeader->ip_len = htons(pPktHeader->iLength - LINK_HEADER_LENGTH);
									pUdpHeader->Length = htons(ntohs(pIpHeader->ip_len) - IP_HEADER_LENGTH);
									pUlConfigHeader->sMsgHdr.nMessageLen = MSG_DL_CONFIG_REQ_HEADER_WO_GROUP_LENGTH + pUlConfigPdu->nPDUSize;
									pUlConfigHeader->nPDU = 1;
									pUlConfigHeader->nGroup = 0;

									if (fwrite((char *)pPktHeader, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}

									lenToWrite = pUlConfigPdu->nPDUSize;
									if (fwrite((char *)pUlConfigPdu, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}

									pUlConfigPdu = (PDUStruct *)((u_char *)pUlConfigPdu + pUlConfigPdu->nPDUSize);
								}
							}
							break;
						case LUA_MSG_TYPE_PHY_UL_DCI_REQ:
							pUlDciHeader = (ULDCIRequestStruct *)(pL2logHeader + 1);
							pduCount = pUlDciHeader->nDCI;

							if (pduCount < 2)
							{
								// write packet
								len = fwrite((char *)pPktHeader, sizeof(char), PKT_HEADER_LENGTH + iPktLength, pOutputFile);
								if (len != (PKT_HEADER_LENGTH + iPktLength))
								{
									printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
									RETURN_ON_FAILURE(pInputFile, pOutputFile);
								}
							}
							else
							{
								for (int i = 0; i < pduCount; i++)
								{
									pUlDciPdu = pUlDciHeader->sULDCIPDU + i;

									// write packet header
									lenToWrite = TOTAL_HEADER_LENGTH + MSG_UL_DCI_REQ_HEADER_LENGTH;

									// update the length field
									pPktHeader->iLength = LINK_IP_UDP_LUA_LENGTH + MSG_UL_DCI_TOTAL_LENGTH;
									pPktHeader->iPLength = pPktHeader->iLength;
									pIpHeader->ip_len = htons(pPktHeader->iLength - LINK_HEADER_LENGTH);
									pUdpHeader->Length = htons(ntohs(pIpHeader->ip_len) - IP_HEADER_LENGTH);
									pUlDciHeader->sMsgHdr.nMessageLen = MSG_UL_DCI_TOTAL_LENGTH;
									pUlDciHeader->nDCI = 1;

									if (fwrite((char *)pPktHeader, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}

									lenToWrite = MSG_UL_DCI_REQ_PAYLOAD_LENGTH;
									if (fwrite((char *)pUlDciPdu, sizeof(char), lenToWrite, pOutputFile) != lenToWrite)
									{
										printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
										RETURN_ON_FAILURE(pInputFile, pOutputFile);
									}
								}
							}
							break;
						default:
							// write packet
							len = fwrite((char *)pPktHeader, sizeof(char), sizeof(s_pkt_header) + iPktLength, pOutputFile);
							if (len != (sizeof(s_pkt_header) + iPktLength))
							{
								printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
								RETURN_ON_FAILURE(pInputFile, pOutputFile);
							}
					}
				}
			}
			else
			{
				// write packet
				lenToWrite = PKT_HEADER_LENGTH + iPktLength;
				len = fwrite((char *)pPktHeader, sizeof(char), lenToWrite, pOutputFile);
				if (len != lenToWrite)
				{
					printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
					RETURN_ON_FAILURE(pInputFile, pOutputFile);
				}
			}
		}

		iIndex += PKT_HEADER_LENGTH + iPktLength;
		pBuf = buffer;
	}


	fclose(pInputFile);
	fclose(pOutputFile);
	printf("PCAP file converted successfully.\n");
	return EXIT_SUCCESS;
}

u_char writeFile(FILE* pFile, char *pBuffer, u_int size, int iIndex)
{
	int len;

	len = fwrite((char *)pBuffer, sizeof(char), size, pFile);

	if (len != size)
	{
		printf("Failed to write package, iIndex=%d, len=%d\n", iIndex, len);
		return FALSE;
	}

	return TRUE;
}
