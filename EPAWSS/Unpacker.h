#pragma once

#include <map>
#include <vector>
#include <string>

#include "Param.h"
#include "BlobParam.h"
#include "IadsTppCommon.h"

#include <atlbase.h>
#include <comutil.h>

#include <iostream>
#include <fstream>

#include "Ch10Types.h"

#include <intrin.h>

using namespace std;

#define PARAM_SET_ALL 0
#define PARAM_SET_RX 1
#define PARAM_SET_TX 2

//#define DEBUG_UNPACK
//#define DEBUG_2224
#define USE_SPECIALTY_PARAMS
#define USE_BLOB_PARAMS
#define USE_SELECTEDTHREAT_PARAM
//#define USE_OLD_THREATREPORT_PARAMS

class Unpacker
{

public:
	Unpacker();
	Unpacker(IIadsTppCh10PluginDataStream * dataStream, string paramCSVPath, int paramSet = 0);
	~Unpacker();

	void initSpecialtyParams();
	void createSpecialtyParams();
	void createBlobInjectionParams();
	void loadParams(string paramCSVPath, int paramSet);
	Param * createParam(
		string name,
		string description,
		string inUnits,
		uint32_t reportID,
		uint32_t startByte,
		uint32_t startBit,
		uint32_t numBits,
		UnpackingMode unpackMode,
		double factor,
		string group,
		string subgroup,
		MeasurementInputDataType midt = DOUBLE_TYPE
	);
	void addParam(Param * inParam);

	void unpack(BYTE *data, int len);
	void unpackEthernet(BYTE *data, int len);
	void unpackEPAWSS(BYTE* data, int len, LONGLONG iadsTimeForPacket);
	void putTimeFromReportTimeTag(LONGLONG iadsTimeForPacket, uint32_t timeTag32, uint32_t reportID = 0, bool makeSameTimeUnique = false);
	double extractParam(BYTE *data, int len, Param *param);

	int unpackMessage(BYTE* pData, int len, long long iadsTime);
	void surveyReports(BYTE* pData, int len, std::map<short, std::vector<int>> &reports);
	void sortReportLocations(std::map<short, std::vector<int>>& inReports, std::vector<int>& outSortedLocations);
	void decodeReports(BYTE* pByte, int len, std::vector<int> reportLocations, long long iadsTime);

	void addValueToBlob(short reportID, int paramIndex, double inValue);
	void commitBlobs();

private:

	struct ReportTimeRecord { // Used to hold values pertinent to keeping track of individual record times within a message
		uint32_t timetag_previous = 0; // holds record time tag from previous call
		uint32_t timetag_offset = 0; // holds number of time increments to add to computed time for consecutive calls with same record time tag
		uint64_t baseReportTimeTag = 0; // holds initial (for each unique IADS time) value computed from record time tag
	};
	std::map<uint32_t, ReportTimeRecord *> * timeRecords;


	std::map<uint32_t, std::vector<Param *> *> * reportIDMap;
	std::map<uint32_t, std::vector<BlobParam *> *> * blobParamMap;

	CComQIPtr<IIadsTppCh10PluginDataStream> ds;

	// Specialty Parameters
	struct ParamID {
		uint32_t reportID;
		uint32_t startByte;
		uint32_t startBit;
		ParamID(uint32_t inReportID, uint32_t inStartByte, uint32_t inStartBit) :
			reportID(inReportID), startByte(inStartByte), startBit(inStartBit) {}
	};

	void gatherSpecialtyParameters();
	bool isMatchingParamID(Param * inParam, ParamID inParamID);

#ifdef USE_SELECTEDTHREAT_PARAM
	CComQIPtr<IDerivedMeasurement> mSelectedThreat;
#endif

#ifdef USE_OLD_THREATREPORT_PARAMS
	CComQIPtr<IDerivedMeasurement> mEmitterControl;
	std::vector<ParamID> emitterControlParamIDs;
	std::vector<Param *> emitterControlParams;

	CComQIPtr<IDerivedMeasurement> mThreatType;
	std::vector<ParamID> threatTypeParamIDs;
	std::vector<Param *> threatTypeParams;
	CComQIPtr<IDerivedMeasurement> mRWR;
	std::vector<ParamID> rwrParamIDs;
	std::vector<Param *> rwrParams;
#endif
	// ========

	bool dualBus;

	byte overflowBuf[MAX_CH10_PACKET_SIZE];
	uint32_t overflowBufSize = 0;
	uint32_t overflowMsgLen = 0;

	short report_22_count, report_24_count = 0;
	Param* Report_22_Count = nullptr;
	Param* Report_24_Count = nullptr;
};