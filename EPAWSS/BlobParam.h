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

class BlobParam
{

public:
	BlobParam(
		std::string strname, 
		uint32_t reportID, 
		std::string strGroup,
		std::string strSubgroup,
		IIadsTppCh10PluginDataStream* dataStream);
	~BlobParam();

	void addValue(int inValue);
	void commitData();

	std::string name;

	uint32_t reportID;

	CComQIPtr<IPluginMeasurement> mBlob;

private:
	CComQIPtr<IIadsTppCh10PluginDataStream> ds;

	std::vector<int> nextValues;
	byte dataBuf[maxBlobSize];
	SAFEARRAY * blobData;
};

