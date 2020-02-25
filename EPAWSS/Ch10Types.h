#pragma once

#include <stdint.h>

#define sizeof_CSDW 4

#define CH10_SYNC_PATTERN 0xEB25

#define MAX_CH10_PACKET_SIZE 524288


enum UnpackingMode
{
	UM_UINT = 0,
	UM_INT,
	UM_USHORT,
	UM_SHORT,
	UM_BYTE,
	UM_FLOAT
};



struct PacketHeader {
	uint16_t      uSync;                // Packet Sync Pattern
	uint16_t      uChID;                // Channel ID
	uint32_t      ulPacketLen;          // Total packet length
	uint32_t      ulDataLen;            // Data length
	uint8_t       ubyDataVer;           // Data Version
	uint8_t       ubySeqNum;            // Sequence Number
	uint8_t       ubyPacketFlags;       // Packet Flags
	uint8_t       ubyDataType;          // Data type
	uint8_t       aubyRelTime[6];       // Reference time
	uint16_t      uChecksum;            // Header Checksum
};

#define sizeof_PacketHeader 24

struct SecondaryHeader {
	uint16_t      uUnused;              //     
	uint16_t      uHighBinTime;         // High order time     
	uint16_t      uLowBinTime;          // Low order time     
	uint16_t      uUSecs;               // Microsecond time     
	uint16_t      uReserved;            //     
	uint16_t      uSecChecksum;         // Secondary Header Checksum     
};

struct CSDW_SetupRecordF1 {
	uint32_t    iCh10Ver        :  8;      // Recorder Ch 10 Version     
	uint32_t    bConfigChange   :  1;      // Recorder config changed     
	uint32_t    iReserved       : 23;      // Reserved     
};

#define sizeof_CSDW_SetupRecordF1 4

struct CSDW_MessageF0 {
	uint32_t    uCounter  : 16;      // Message/segment counter     
	uint32_t    uReserved : 14;      
	uint32_t    uType     :  2;      // Complete/segment type    
};

#define sizeof_CSDW_MessageF0 4

struct IPH_MessageF0 {
	uint64_t    suIntPktTime;           // Reference time
	uint32_t    uMsgLength      : 16;      // Message length    
	uint32_t    uSubChannel     : 14;      // Subchannel number    
	uint32_t    bFmtError       :  1;      // Format error flag      
	uint32_t    bDataError      :  1;      // Data error flag 
};

#define sizeof_IPH_MessageF0 12

struct CSDW_MILSTD1553 {
	uint32_t    uMsgCnt		 : 24;      // Message count
	uint32_t    Reserved     :  6;
	uint32_t    uTTB         :  2;      // Time tag bits
};

#define sizeof_CSDW_MILSTD1553 4

struct IPH_MILSTD1553 {
	uint64_t    suIntPktTime;           // Reference time
	uint16_t    Reserved1       : 3;    // Reserved
	uint16_t    bWordError      : 1;
	uint16_t    bSyncError      : 1;
	uint16_t    bWordCntError   : 1;
	uint16_t    Reserved2       : 3;
	uint16_t    bRespTimeout    : 1;
	uint16_t    bFmtError		: 1;
	uint16_t    bRT2RT          : 1;
	uint16_t    bMsgError       : 1;
	uint16_t    iBusID          : 1;
	uint16_t    Reserved3       : 2;
	uint8_t     uGapTime1;
	uint8_t     uGapTime2;
	uint16_t    uMsgLength;
};

#define sizeof_IPH_MILSTD1553 14

struct CSDW_TimeData {
	uint32_t uSrc : 4;
	uint32_t uFmt : 4;
	uint32_t uDate : 4;
	uint32_t Reserved : 20;
};

#define sizeof_CSDW_TimeData 4

struct CSDW_A429 {
	uint32_t    uMsgCount : 16;      // Message count     
	uint32_t    Reserved  : 16;      //     
};

#define sizeof_CSDW_A429 4

struct IPH_A429 {
	uint32_t    uGapTime		: 20;      // Gap Time     
	uint32_t    Reserved        :  1;      //      
	uint32_t    uBusSpeed       :  1;      // Bus Speed     
	uint32_t    bParityError    :  1;      // Parity Error     
	uint32_t    bFormatError    :  1;      // Format Error     
	uint32_t    uBusNum         :  8;      // Bus number     
};

#define sizeof_IPH_A429 4

struct Data_A249 {
	uint32_t    uLabel			:  8;      // Label     
	uint32_t    uSDI            :  2;      // Source/Destination ID     
	uint32_t    uData           : 19;      // Data     
	uint32_t    uSSM            :  2;      // Sign/Status Matrix     
	uint32_t    uParity         :  1;      // Parity     
};

#define sizeof_Data_A249 4


struct SuTime_MsgDayFmt {
	uint16_t    uTmn		:  4;      // Tens of milliseconds
	uint16_t    uHmn        :  4;      // Hundreds of milliseconds
	uint16_t    uSn         :  4;      // Units of seconds
	uint16_t    uTSn        :  3;      // Tens of seconds
	uint16_t    Reserved1   :  1;      // 0
	uint16_t    uMn         :  4;      // Units of minutes
	uint16_t    uTMn        :  3;      // Tens of minutes
	uint16_t    Reserved2   :  1;      // 0
	uint16_t    uHn         :  4;      // Units of hours
	uint16_t    uTHn        :  2;      // Tens of Hours
	uint16_t    Reserved3   :  2;      // 0
	uint16_t    uDn         :  4;      // Units of day number
	uint16_t    uTDn        :  4;      // Tens of day number
	uint16_t    uHDn        :  2;      // Hundreds of day number
	uint16_t    Reserved4   :  6;      // 0
}; 

#define sizeof_SuTime_MsgDayFmt 6

struct CSDW_EthernetF0 {
	uint32_t    uNumFrames : 16;      // Number of frames
	uint32_t    Reserved1       : 12;
	uint32_t    uFormat         :  4;      // Format of frames
}; 

#define sizeof_CSDW_EthernetF0 4

struct IPH_EthernetF0 {
	uint64_t    suIntraPckTime;            // Reference time
	uint32_t    uDataLen        : 14;      // Data length
	uint32_t    Reserved1       :  2;      //
	uint32_t    uNetID          :  8;      // Network identifier
	uint32_t    uSpeed          :  4;      // Ethernet speed
	uint32_t    uContent        :  2;      // Captured data content
	uint32_t    bFrameError     :  1;      // Frame error
	uint32_t    Reserved2       :  1;      // 
}; 

#define sizeof_IPH_EthernetF0 12

struct CSDW_FibreF0 {
	uint32_t numOfFrames : 16;
	uint32_t reserved1 : 12;
	uint32_t format : 4;
};

#define sizeof_CSDW_FibreF0 4

struct IPH_FibreF0 {
	uint64_t suIntraPckTime;
	uint32_t fe : 1;
	uint32_t ce : 1;
	uint32_t oe : 1;
	uint32_t sm : 1;
	uint32_t c : 2;
	uint32_t top : 2;
	uint32_t rsvd : 5;
	uint32_t eof : 3;
	uint32_t sof : 4;
	uint32_t fl : 12;
};

#define sizeof_IPH_FibreF0 12