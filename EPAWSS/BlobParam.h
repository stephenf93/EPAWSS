#pragma once

#include <stdint.h>
#include <string>
#include <vector>
#include "IadsTppCommon.h"

#include <atlbase.h>
#include <comdef.h>

#include "Ch10Types.h"

#define maxBlobElements 128
#define maxBlobSize maxBlobElements * sizeof(int)

using namespace ATL;

enum BLOB_PARAM_DATA_TYPE {
	BLOB_INT_TYPE = 0,
	BLOB_FLOAT_TYPE = 1
};

class BlobParam
{

public:
	BlobParam(
		std::string strname, 
		uint32_t inReportID, 
		BLOB_PARAM_DATA_TYPE dt,
		std::string strGroup,
		std::string strSubgroup,
		IIadsTppCh10PluginDataStream* dataStream);
	~BlobParam();

	void addValue(double inValue);
	void commitData();

	std::string name;
	uint32_t reportID;
	BLOB_PARAM_DATA_TYPE dataType;

	CComQIPtr<IPluginMeasurement> mBlob;

private:

	void addValue(int inValue);
	void addValue(float inValue);

	CComQIPtr<IIadsTppCh10PluginDataStream> ds;

	std::vector<int> nextValuesI;
	std::vector<float> nextValuesF;
	byte dataBuf[maxBlobSize];
	SAFEARRAY * blobData;

#define SIZEOF_HEADER 64
#define SIZEOF_NAME 58
	struct Header {
		uint16_t size;
		uint16_t type;
		uint16_t rptID;
		byte name[SIZEOF_NAME];
	};
};

