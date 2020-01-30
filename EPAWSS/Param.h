#pragma once

#include <stdint.h>
#include <string>
#include "IadsTppCommon.h"

#include <atlbase.h>
#include <comdef.h>

#include "Ch10Types.h"

using namespace ATL;

class Param
{

public:
	Param();
	~Param();

	std::string name;

	uint32_t reportID;
	uint32_t startByte;
	uint32_t startBit;
	uint32_t numBits;
	UnpackingMode unpackMode;
	double factor;
	
	CComQIPtr<IPluginMeasurement> measurement;

	std::string currentValue;

private:
};

