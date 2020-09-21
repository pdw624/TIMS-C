// SocketClient.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <io.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib,"ws2_32")

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <fcntl.h>


#define BUF_SIZE 1024

static const unsigned short crc16tab[256] = {
		   0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
		   0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
		   0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
		   0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
		   0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
		   0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
		   0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
		   0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
		   0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
		   0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
		   0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
		   0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
		   0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
		   0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
		   0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
		   0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
		   0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
		   0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
		   0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
		   0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
		   0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
		   0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
		   0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
		   0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
		   0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
		   0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
		   0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
		   0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
		   0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
		   0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
		   0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
		   0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
};

//Header Type A
#pragma pack(push, 1)
typedef struct __tagTIMSNetProtocolHeader_A
{
	unsigned char    ucPacketIndicator = 65;//0x41	[1]				Packet Indicator
	unsigned char    ucHederSize = 24;//0x18		[1]
	unsigned char    ucProtocolVersion = 1;//0x01	[1]
	unsigned char    ucPacketID = 0;//0x00			[1]
	unsigned char    ucFlowControl = 47;//0x2F		[1]
	unsigned char    ucOpCode = 97;//0x61			[1]
	unsigned short   usAPDULength = 19;//0x13		[2]
	unsigned int      unSourceAddress = 0;//0x00	[4]
	unsigned int      unDestAddress = 0;//0x00		[4]
	unsigned short   usCurrentIndex = 0;//0x00		[2]
	unsigned short   usTotalIndex = 0;//0x00		[2]
	unsigned char    cReserved[4] = { 0,0,0,0 };//0x00[1]

}TIMS_PROTOCOL_HEADER_A;
#pragma pack(pop)

//Payload Init Response
#pragma pack(push, 1)
typedef struct __tagTIMSNetProtocolPayload_INIT_RES
{
	unsigned char ucAttributeCount = 1;//0x01		[1]
	unsigned short usAttributeId = 2000;//0x07D0	[2]
	unsigned short usAttributeSize = 14;//0x000E	[2]
	unsigned char id[10] = { 'I','M' ,'P' ,'0' ,'0' ,'1' ,'0' ,'0' ,'0' ,'0' };
	unsigned char key[4] = { 0,0,0,0 };

}TIMS_PROTOCOL_PAYLOAD_A_INIT_RES;
#pragma pack(pop)

//Payload Get Request
#pragma pack(push, 1)
typedef struct __tagTIMSNetProtocolPayload_GET_REQ
{
	unsigned char ucAttributeCount = 1;//0x01		[1]
	unsigned short usAttributeId = 100;//0x07D0		[2]

}TIMS_PROTOCOL_PAYLOAD_A_GET_REQ;
#pragma pack(pop)

//Payload Set Request
#pragma pack(push, 1)
typedef struct __tagTIMSNetProtocolPayload_SET_REQ
{
	unsigned char ucAttributeCount = 1;//0x01		[1]
	unsigned short usAttributeId = 100;//0x07D0		[2]
	unsigned short usAttributeSize = 7;//			[2]
	unsigned char ucAttributeData[7] = {20,1,1,12,34,56,78};
}TIMS_PROTOCOL_PAYLOAD_A_SET_REQ;
#pragma pack(pop)

//Payload Action Request
#pragma pack(push, 1)
typedef struct __tagTIMSNetProtocolPayload_ACTION_REQ
{
	unsigned short usAttributeId = 100;//0x07D0		[2]
	unsigned short usActionSize = 7;//			[2]
	unsigned char ucActionParameter[7] = { 20,1,1,12,34,56,78 };
}TIMS_PROTOCOL_PAYLOAD_A_ACTION_REQ;
#pragma pack(pop)

//CRC
#pragma pack(push, 1)
typedef struct __tagTIMSNetProtocolCRC
{
	//unsigned short crc = 17936;//0x4610;		[2]
	unsigned short crc=0;//0x4610;		[2]

}TIMS_PROTOCOL_CRC_A;
#pragma pack(pop)



typedef struct MyStruct
{
	char firstCh;
	char secondCh;
}MyStruct;

void initRes(char* buff, char* fullBuff, TIMS_PROTOCOL_HEADER_A tims_header, TIMS_PROTOCOL_PAYLOAD_A_INIT_RES tims_payload_init_res, TIMS_PROTOCOL_CRC_A tims_crc);
void getReq(char* buff, char* fullBuff, TIMS_PROTOCOL_HEADER_A tims_header, TIMS_PROTOCOL_PAYLOAD_A_GET_REQ tims_payload_get_req, TIMS_PROTOCOL_CRC_A tims_crc);
void setReq(char* buff, char* fullBuff, TIMS_PROTOCOL_HEADER_A tims_header, TIMS_PROTOCOL_PAYLOAD_A_SET_REQ tims_payload_set, TIMS_PROTOCOL_CRC_A tims_crc);
void actionReq(char* buff, char* fullBuff, TIMS_PROTOCOL_HEADER_A tims_header, TIMS_PROTOCOL_PAYLOAD_A_ACTION_REQ tims_payload_action, TIMS_PROTOCOL_CRC_A tims_crc);
void ErrorHandling(char* message);
unsigned short TIMS_MakeProtocolCRC(char* lpBuffer, int nDataSize);

int main(int argc, char* argv[])
{
	bool isInit = false;

	MyStruct ms;
	ms.firstCh = 'o';
	ms.secondCh = 'p';
	
	//TIMS_PROTOCOL_HEADER_A tims_A_recv;
	//TIMS_PROTOCOL_HEADER_A tims_A_send;

	FILE* stream;

	//header, body, tail의 사이즈
	int headerSize = sizeof(TIMS_PROTOCOL_HEADER_A);
	int payloadSize = sizeof(TIMS_PROTOCOL_PAYLOAD_A_INIT_RES);
	int crcSize = sizeof(TIMS_PROTOCOL_CRC_A);

	//buff = crc넘버를 구하기 위한 버퍼, fullBuff = 전송을 위한 메시지 폼(header, body, tail)
	char* buff = (char *)malloc(sizeof(char) * headerSize+payloadSize);
	char* fullBuff = (char*)malloc(sizeof(char) * headerSize + payloadSize + crcSize);

	//INIT RESPONSE 구조체 변수 선언
	TIMS_PROTOCOL_HEADER_A tims_header;
	TIMS_PROTOCOL_PAYLOAD_A_INIT_RES tims_payload_init_res;
	TIMS_PROTOCOL_CRC_A tims_crc;

	//initResponse CRC 정의, initResponse 메시지 정의
	initRes(buff, fullBuff, tims_header, tims_payload_init_res, tims_crc);
	

	WSADATA wsaData;
	SOCKET hSocket;
	char message[BUF_SIZE];
	int strLen;
	SOCKADDR_IN servAdr;
	
	
	printf("\n");
	
	if (argc != 3) {
		printf("Usage : %s <IP> <port>\n", argv[0]);
		exit(1);
	}

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		ErrorHandling((char *)"WSAStartup() error!");

	hSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (hSocket == INVALID_SOCKET)
		ErrorHandling((char*)"socket() error");
	///// 
	//u_long sock_on = 1;
	//strLen = ioctlsocket(hSocket, FIONBIO, &sock_on);
	//if (strLen == SOCKET_ERROR) {
	//	ErrorHandling((char*)"blocking() error");
	//}if (WSAGetLastError() != WSAEWOULDBLOCK) {
	//	//ErrorHandling((char*)"recv() error!");
	//	//break;
	//}
	///// 
	
	

	memset(&servAdr, 0, sizeof(servAdr));
	servAdr.sin_family = AF_INET;
	servAdr.sin_addr.s_addr = inet_addr(argv[1]);
	servAdr.sin_port = htons(atoi(argv[2]));

	if (connect(hSocket, (SOCKADDR*)&servAdr, sizeof(servAdr)) == SOCKET_ERROR)
		ErrorHandling((char*)"connect() error!");
	else
		puts("Connected...........");
	
	
	//받은 메시지(패킷) 저장 버퍼
	char* recvBuff = (char*)malloc(sizeof(char) * BUF_SIZE);
	int msgCnt = 0;

	

	 
	while (1)
	{
		

		if (!strcmp(message, "q\n") || !strcmp(message, "Q\n"))
			break;

		//send(hSocket, message, strlen(message), 0);//메시지 길이만큼 보내기
		////////////////////////////////////////////////////////////////////

		//send(hSocket, message, 1, 0);//1바이트만 보내기
		//send(hSocket, message, 2, 0);//2바이트만 보내기
		//send(hSocket, message, 3, 0);//3바이트만 보내기

		//send(hSocket, (const char*)&ms, sizeof(MyStruct), 0);//구조체 크기만큼 보내기
		
		strLen = recv(hSocket, message, BUF_SIZE - 1, 0);
		//msgCnt++;
		//memcpy((void*)recvBuff, message, headerSize + payloadSize + crcSize);
		memcpy((void*)recvBuff, message, BUF_SIZE);

		
		int getResBuff[7] = {};
		int getResIndex = 0;
		printf("받은 메시지[%d] : ",msgCnt);
		for (int i = 0; i < BUF_SIZE; i++) {
			printf("0x%02X ",recvBuff[i]);
		}

		if (recvBuff[5] == 17) {
			//29~35
			for (int i = 29; i < 36; i++) {
				getResBuff[getResIndex] = recvBuff[i];
				getResIndex++;
			}
			printf("[GetResponse]%d.%d.%d %d시 %d분 %d초 %d밀리초", 2000 + (int)getResBuff[0], getResBuff[1], getResBuff[2], getResBuff[3], getResBuff[4], getResBuff[5], getResBuff[6]);
			printf("\n");
		}
		else if (recvBuff[5] == 16) {
			printf("[Get Request]");
		}
		else if (recvBuff[5] == 32) {
			printf("[Set Request]");
		}
		else if (recvBuff[5] == 33) {
			printf("[Set Response]");
		}
		else if (recvBuff[5] == 48) {
			printf("[Action Request]");
		}
		else if (recvBuff[5] == 49) {
			printf("[Action Response]");
		}
		else if (recvBuff[5] == 64) {
			printf("[Event Request]");
		}
		else if (recvBuff[5] == 65) {
			printf("[Event Response]");
		}
		else if (recvBuff[5] == 96) {
			printf("[Init Request]");
		}
		//printf("0x%02X ", recvBuff[i]);

		printf("\n");

		

		//
		message[strLen] = 0;


		if (isInit == false) {

			send(hSocket, (const char*)fullBuff, headerSize + payloadSize + crcSize, 0);

			isInit = true;
		}
		else {
			fputs("Input message(Q to quit): ", stdout);
			fgets(message, BUF_SIZE, stdin);
			if (!strcmp(message, "get\n") || !strcmp(message, "GET\n")) {
				TIMS_PROTOCOL_PAYLOAD_A_GET_REQ tims_payload_get;

				fputs("Attribute ID를 입력해주세요 : ", stdout);
				fgets(message, BUF_SIZE, stdin);
				tims_payload_get.usAttributeId = atoi(message);

				//payload길이가 달라 다시 정의해야함
				payloadSize = sizeof(TIMS_PROTOCOL_PAYLOAD_A_GET_REQ);

				buff = (char*)malloc(sizeof(char) * (headerSize + payloadSize));
				fullBuff = (char*)malloc(sizeof(char) * (headerSize + payloadSize + crcSize));
				//GET REQ crc설정, message 설정
				getReq(buff, fullBuff, tims_header, tims_payload_get, tims_crc);

				int nSizeToSend = headerSize + payloadSize + crcSize;
				int nRetSend = send(hSocket, (const char*)fullBuff, nSizeToSend, 0);
				printf("보낸 메시지 : [GET REQUEST] : ToSend=%d, nRetSend=%d \r\n", nSizeToSend, nRetSend);


				/*printf("받은 메시지 : ");
				for (int i = 0; i < headerSize + payloadSize + crcSize; i++) {
					printf("0x%02X ", recvBuff[i]);
				}
				printf("\n");*/


			}
			else if (!strcmp(message, "set\n") || !strcmp(message, "SET\n")) {
				TIMS_PROTOCOL_PAYLOAD_A_SET_REQ tims_payload_set;


				fputs("시간을 설정해주세요 (년, 월, 일, 시, 분, 초, 밀리초) ", stdout);
				//22

				printf("ex ) [20 1 2 3 4 5 6] = [2020.01.02 3시 4분 5초 6밀리초]\n");
				fgets(message, BUF_SIZE, stdin);

				//printf("meassage 길이 : %d\n", strlen(message));
				char* ptr = strtok(message, " ");
				int i = 0;
				//printf("meassage 길이 : %d\n", strlen(message));

				while (ptr != NULL) {
					//printf("%s ", ptr);
					//printf("%d ", strlen(ptr));
					tims_payload_set.ucAttributeData[i] = atoi(ptr);
					ptr = strtok(NULL, " ");
					i++;
				}

				//memcpy(tims_payload_set.ucAttributeData, ptr, 7);


				//payload길이가 달라 다시 정의해야함
				payloadSize = sizeof(TIMS_PROTOCOL_PAYLOAD_A_SET_REQ);

				buff = (char*)malloc(sizeof(char) * (headerSize + payloadSize));
				fullBuff = (char*)malloc(sizeof(char) * (headerSize + payloadSize + crcSize));
				//SET REQ crc설정, message 설정
				setReq(buff, fullBuff, tims_header, tims_payload_set, tims_crc);

				send(hSocket, (const char*)fullBuff, headerSize + payloadSize + crcSize, 0);
				printf("[%d.%d.%d %d시 %d분 %d초 %d밀리초]로 SET 메시지를 보냈습니다", (2000 + (int)tims_payload_set.ucAttributeData[0]), tims_payload_set.ucAttributeData[1], tims_payload_set.ucAttributeData[2], tims_payload_set.ucAttributeData[3], tims_payload_set.ucAttributeData[4], tims_payload_set.ucAttributeData[5], tims_payload_set.ucAttributeData[6]);
				printf("\n");
			}
			else if (!strcmp(message, "action\n") || !strcmp(message, "ACTION\n")) {
				TIMS_PROTOCOL_PAYLOAD_A_ACTION_REQ tims_payload_action;


				fputs("시간을 설정해주세요 (년, 월, 일, 시, 분, 초, 밀리초) ", stdout);
				//22

				printf("ex ) [20 1 2 3 4 5 6] = [2020.01.02 3시 4분 5초 6밀리초]\n");
				fgets(message, BUF_SIZE, stdin);

				//printf("meassage 길이 : %d\n", strlen(message));
				char* ptr = strtok(message, " ");
				int i = 0;
				//printf("meassage 길이 : %d\n", strlen(message));

				while (ptr != NULL) {
					//printf("%s ", ptr);
					//printf("%d ", strlen(ptr));
					tims_payload_action.ucActionParameter[i] = atoi(ptr);
					ptr = strtok(NULL, " ");
					i++;
				}



				//payload길이가 달라 다시 정의해야함
				payloadSize = sizeof(TIMS_PROTOCOL_PAYLOAD_A_ACTION_REQ);

				buff = (char*)malloc(sizeof(char) * (headerSize + payloadSize));
				fullBuff = (char*)malloc(sizeof(char) * (headerSize + payloadSize + crcSize));
				//crc설정, message 설정
				actionReq(buff, fullBuff, tims_header, tims_payload_action, tims_crc);

				send(hSocket, (const char*)fullBuff, headerSize + payloadSize + crcSize, 0);
				printf("[%d.%d.%d %d시 %d분 %d초 %d밀리초]로 ACTION 메시지를 보냈습니다", (2000 + (int)tims_payload_action.ucActionParameter[0]), tims_payload_action.ucActionParameter[1], tims_payload_action.ucActionParameter[2], tims_payload_action.ucActionParameter[3], tims_payload_action.ucActionParameter[4], tims_payload_action.ucActionParameter[5], tims_payload_action.ucActionParameter[6]);
				printf("\n");

			}
			else {
				printf("get, set, action 을 입력하세요. \n");
			}


		}


		
		

		/*printf("Message from server: %s", message);
		int msg_num = atoi(message);
		printf("[16진수 : 0x%02X, 문자 : %c]\n", msg_num, msg_num);*/

		//메시지 바이트출력, ex) 'a' => 0x97 0x0A 0x00 
		/*for (int i = 0; i < strlen(message)+1; i++) {
			if (i % 16 == 0) printf("\n");
			printf("0x%02X ", message[i]);
		}
		printf("\n");*/

	}
	
	closesocket(hSocket);
	WSACleanup();
	free(buff);
	free(fullBuff);
	free(recvBuff);
	
	return 0;
}

void ErrorHandling(char* message)
{
	fputs(message, stderr);
	fputc('\n', stderr);
	exit(1);
}

unsigned short TIMS_MakeProtocolCRC(char* lpBuffer, int nDataSize)
{
	int counter;
	unsigned short crc = 0;
	for (counter = 0; counter < nDataSize; counter++)
		crc = (crc << 8) ^ crc16tab[((crc >> 8) ^ *(((char*)lpBuffer++))) & 0x00FF];
	return crc;
}

void initRes(char* buff,char * fullBuff, TIMS_PROTOCOL_HEADER_A tims_header, TIMS_PROTOCOL_PAYLOAD_A_INIT_RES tims_payload_init_res, TIMS_PROTOCOL_CRC_A tims_crc) {

	int headerSize = sizeof(TIMS_PROTOCOL_HEADER_A);
	int payloadSize = sizeof(TIMS_PROTOCOL_PAYLOAD_A_INIT_RES);
	int crcSize = sizeof(TIMS_PROTOCOL_CRC_A);

	memset(buff, 0, headerSize + payloadSize);
	memcpy((buff), &tims_header, headerSize);
	memcpy((buff + headerSize), &tims_payload_init_res, payloadSize);
	
	tims_crc.crc = TIMS_MakeProtocolCRC(buff, headerSize + payloadSize);

	memset(fullBuff, 0, headerSize + payloadSize + crcSize);
	memcpy(fullBuff, buff, headerSize + payloadSize);
	memcpy((fullBuff + headerSize + payloadSize), &tims_crc, crcSize);
}

void getReq(char* buff, char* fullBuff, TIMS_PROTOCOL_HEADER_A tims_header, TIMS_PROTOCOL_PAYLOAD_A_GET_REQ tims_payload_get, TIMS_PROTOCOL_CRC_A tims_crc) {

	int headerSize = sizeof(TIMS_PROTOCOL_HEADER_A);
	int payloadSize = sizeof(TIMS_PROTOCOL_PAYLOAD_A_GET_REQ);
	int crcSize = sizeof(TIMS_PROTOCOL_CRC_A);
	
	tims_header.ucFlowControl = 238;
	tims_header.ucOpCode = 16;
	tims_header.usAPDULength = 3;

	memset(buff, 0, headerSize + payloadSize);
	memcpy((buff), &tims_header, headerSize);
	memcpy((buff + headerSize), &tims_payload_get, payloadSize);

	tims_crc.crc = TIMS_MakeProtocolCRC(buff, headerSize + payloadSize);

	memset(fullBuff, 0, headerSize + payloadSize + crcSize);
	memcpy(fullBuff, buff, headerSize + payloadSize);
	memcpy((fullBuff + headerSize + payloadSize), &tims_crc, crcSize);
}

void setReq(char* buff, char* fullBuff, TIMS_PROTOCOL_HEADER_A tims_header, TIMS_PROTOCOL_PAYLOAD_A_SET_REQ tims_payload_set, TIMS_PROTOCOL_CRC_A tims_crc) {

	int headerSize = sizeof(TIMS_PROTOCOL_HEADER_A);
	int payloadSize = sizeof(TIMS_PROTOCOL_PAYLOAD_A_SET_REQ);
	int crcSize = sizeof(TIMS_PROTOCOL_CRC_A);

	tims_header.ucFlowControl = 47;
	tims_header.ucOpCode = 32;
	tims_header.usAPDULength = 12;

	memset(buff, 0, headerSize + payloadSize);
	memcpy((buff), &tims_header, headerSize);
	memcpy((buff + headerSize), &tims_payload_set, payloadSize);

	tims_crc.crc = TIMS_MakeProtocolCRC(buff, headerSize + payloadSize);

	memset(fullBuff, 0, headerSize + payloadSize + crcSize);
	memcpy(fullBuff, buff, headerSize + payloadSize);
	memcpy((fullBuff + headerSize + payloadSize), &tims_crc, crcSize);
}

void actionReq(char* buff, char* fullBuff, TIMS_PROTOCOL_HEADER_A tims_header, TIMS_PROTOCOL_PAYLOAD_A_ACTION_REQ tims_payload_action, TIMS_PROTOCOL_CRC_A tims_crc) {

	int headerSize = sizeof(TIMS_PROTOCOL_HEADER_A);
	int payloadSize = sizeof(TIMS_PROTOCOL_PAYLOAD_A_ACTION_REQ);//바꿔주기
	int crcSize = sizeof(TIMS_PROTOCOL_CRC_A);

	//바꿔주기
	tims_header.ucFlowControl = 0;
	tims_header.ucOpCode = 48;
	tims_header.usAPDULength = 11;

	memset(buff, 0, headerSize + payloadSize);
	memcpy((buff), &tims_header, headerSize);
	memcpy((buff + headerSize), &tims_payload_action, payloadSize);//바꿔주기

	tims_crc.crc = TIMS_MakeProtocolCRC(buff, headerSize + payloadSize);

	memset(fullBuff, 0, headerSize + payloadSize + crcSize);
	memcpy(fullBuff, buff, headerSize + payloadSize);
	memcpy((fullBuff + headerSize + payloadSize), &tims_crc, crcSize);
}