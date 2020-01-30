#include "Unpacker.h"

char out[256];

Unpacker::Unpacker() {}

Unpacker::Unpacker(IIadsTppCh10PluginDataStream * dataStream, string paramCSVPath, int paramSet)
{
	reportIDMap = new std::map<uint32_t, std::vector<Param *> *>();

	ds = dataStream;

	initSpecialtyParams();

	loadParams(paramCSVPath, paramSet);

	createSpecialtyParams();
}

Unpacker::~Unpacker()
{
}

void Unpacker::gatherSpecialtyParameters() {
	if (reportIDMap->find(24) != reportIDMap->end()) {
		{ // Emitter Control Parameters
			std::vector<Param *> * params = reportIDMap->at(24);

			for (int i = 0; i < emitterControlParamIDs.size(); i++) {
				for (int j = 0; j < params->size(); j++) {
					if (isMatchingParamID(params->at(j), emitterControlParamIDs.at(i)))
						emitterControlParams.push_back(params->at(j));
				}
			}
		}

		{ // Threat Type Parameters
			if (reportIDMap->find(22) != reportIDMap->end()) {
				std::vector<Param *> * params = reportIDMap->at(22);

				for (int i = 0; i < threatTypeParamIDs.size(); i++) {
					for (int j = 0; j < params->size(); j++) {
						if (isMatchingParamID(params->at(j), threatTypeParamIDs.at(i)))
							threatTypeParams.push_back(params->at(j));
					}
				}
			}
		}

		{ // RWR Data Parameters
			std::vector<Param *> * params = reportIDMap->at(24);

			for (int i = 0; i < rwrParamIDs.size(); i++) {
				for (int j = 0; j < params->size(); j++) {
					if (isMatchingParamID(params->at(j), rwrParamIDs.at(i)))
						rwrParams.push_back(params->at(j));
				}
			}
		}
	}
}

bool Unpacker::isMatchingParamID(Param * inParam, ParamID inParamID) {
	if (inParam->reportID == inParamID.reportID &&
		inParam->startByte == inParamID.startByte &&
		inParam->startBit == inParamID.startBit)
		return true;
	else
		return false;
}

void Unpacker::initSpecialtyParams() {
	// Add contributing ParamIDs to associated list

	// Emitter Control
	emitterControlParamIDs.push_back(ParamID(24, 196, 1568 % 8)); // Frequency_List_Num1__Last_
	//emitterControlParamIDs.push_back(ParamID(24, 200, 1600 % 8)); // Frequency_List_Num2_24
	//emitterControlParamIDs.push_back(ParamID(24, 204, 1632 % 8)); // Frequency_List_Num3_24
	//emitterControlParamIDs.push_back(ParamID(24, 208, 1664 % 8)); // Frequency_List_Num4_24
	//emitterControlParamIDs.push_back(ParamID(24, 212, 1696 % 8)); // Frequency_List_Num5_24
	//emitterControlParamIDs.push_back(ParamID(24, 216, 1728 % 8)); // Frequency_List_Num6_24
	//emitterControlParamIDs.push_back(ParamID(24, 220, 1760 % 8)); // Frequency_List_Num7_24
	//emitterControlParamIDs.push_back(ParamID(24, 224, 1792 % 8)); // Frequency_List_Num8_24
	//emitterControlParamIDs.push_back(ParamID(24, 228, 1824 % 8)); // Frequency_List_Num9_24
	//emitterControlParamIDs.push_back(ParamID(24, 232, 1856 % 8)); // Frequency_List_Num10_24
	//emitterControlParamIDs.push_back(ParamID(24, 236, 1888 % 8)); // Frequency_List_Num11_24
	//emitterControlParamIDs.push_back(ParamID(24, 240, 1920 % 8)); // Frequency_List_Num12_24
	//emitterControlParamIDs.push_back(ParamID(24, 244, 1952 % 8)); // Frequency_List_Num13_24
	//emitterControlParamIDs.push_back(ParamID(24, 248, 1984 % 8)); // Frequency_List_Num14_24
	//emitterControlParamIDs.push_back(ParamID(24, 252, 2016 % 8)); // Frequency_List_Num15_24
	//emitterControlParamIDs.push_back(ParamID(24, 256, 2048 % 8)); // Frequency_List_Num16__Oldest_
	emitterControlParamIDs.push_back(ParamID(24, 322, 2576 % 8)); // Technique_Class
	emitterControlParamIDs.push_back(ParamID(24, 24, 192 % 8));   // Primary_Emitter_ID_Num1_24
	emitterControlParamIDs.push_back(ParamID(24, 285, 2280 % 8)); // Jamming_Quadrant
	emitterControlParamIDs.push_back(ParamID(24, 321, 2568 % 8)); // Conflict_Cue_24
	emitterControlParamIDs.push_back(ParamID(24, 320, 2560 % 8)); // JAM_Request_24
	emitterControlParamIDs.push_back(ParamID(24, 12, 96 % 8));    // Emitter_Track_Number_24

	// Threat Type Information
	threatTypeParamIDs.push_back(ParamID(22, 8, 64 % 8));   // Report_22_Time_Tag
	threatTypeParamIDs.push_back(ParamID(22, 28, 224 % 8)); // Ownship_Persistence
	threatTypeParamIDs.push_back(ParamID(22, 12, 96 % 8));  // Weapon_System_Track_Number_22
	threatTypeParamIDs.push_back(ParamID(22, 14, 112 % 8)); // Reference_Emitter_Track_Number
	threatTypeParamIDs.push_back(ParamID(22, 39, 312 % 8)); // Primary_Weapon_System_Threat_Type

	// RWR Data
	rwrParamIDs.push_back(ParamID(24, 8, 64 % 8));     // Report_24_Time_Tag
	rwrParamIDs.push_back(ParamID(24, 23, 184 % 8));   // Ownship_Persistence_24
	rwrParamIDs.push_back(ParamID(24, 12, 96 % 8));    // Emitter_Track_Number_24
	rwrParamIDs.push_back(ParamID(24, 14, 112 % 8));   // Weapon_System_Track_Number_24
	rwrParamIDs.push_back(ParamID(24, 28, 224 % 8));   // Primary_Emitter_Threat_Mode_24
	rwrParamIDs.push_back(ParamID(24, 29, 232 % 8));   // Primary_Emitter_Allegiance
	rwrParamIDs.push_back(ParamID(24, 30, 240 % 8));   // ECM_Inhibit_Emitter_24
	rwrParamIDs.push_back(ParamID(24, 112, 896 % 8));  // Azimuth_Angle
	rwrParamIDs.push_back(ParamID(24, 128, 1024 % 8)); // Elevation_Angle_24
	rwrParamIDs.push_back(ParamID(24, 118, 944 % 8));  // Elevation_Angle_Valid
	rwrParamIDs.push_back(ParamID(24, 120, 960 % 8));  // Slant_Range_24
	rwrParamIDs.push_back(ParamID(24, 135, 1080 % 8)); // Geo_Solution_Applied
	rwrParamIDs.push_back(ParamID(24, 176, 1408 % 8)); // ECM_State
	rwrParamIDs.push_back(ParamID(24, 178, 1424 % 8)); // Jam_Status
	rwrParamIDs.push_back(ParamID(24, 284, 2272 % 8)); // JAM_Active_24
	rwrParamIDs.push_back(ParamID(24, 285, 2280 % 8)); // Jamming_Quadrant
}

void Unpacker::createSpecialtyParams() {
	{
		string nametmp = "Emitter_Report";

		int iadsDataOutSize = 256;

		string fStr = "SetDataOutputSize(" + to_string(iadsDataOutSize) + "),Sprintf(\"";
		string args = "";
		string triggerName = "";

		for (int i = 0; i < emitterControlParams.size(); i++) {
			if (emitterControlParams.at(i)->factor == 1)
				fStr += "%d";
			else
				fStr += "%f";
			args += emitterControlParams.at(i)->name;
			if (i != emitterControlParams.size() - 1) {
				fStr += ",";
				args += ",";
			}
			if (i == 1)
				triggerName = emitterControlParams.at(i)->name;
		}

		string sEquation = "SetTriggerParam(" + triggerName + ")," + fStr + "\", " + args + ")";

		bstr_t equation = sEquation.data();

		bstr_t name = nametmp.data();
		bstr_t name2 = nametmp.data();
		bstr_t units = string("").data();

		bstr_t longName = string("Sends_Emitter_Report_data_to_control").data();

		bstr_t grp = string("Control").data();
		bstr_t subgrp = string("Parameters").data();

		double sampleRate = 0.0;

		MeasurementInputDataType midt = ASCII;

		HRESULT h = ds->CreateDerivedMeasurement(name.Detach(), name2.Detach(), longName.Detach(), units.Detach(), midt, sampleRate, equation, STANDARD_DERIVED, &mEmitterControl);
		if (FAILED(h))
			OutputDebugString("failed to createBasicMeasurement\n");
		mEmitterControl->put_Group(grp);
		mEmitterControl->put_SubGroup(subgrp);
		ds->addMeasurement(mEmitterControl);
	}
	{
		string nametmp = "RWR_Report_Threat_Type";

		int iadsDataOutSize = 256;

		string fStr = "SetDataOutputSize(" + to_string(iadsDataOutSize) + "),Sprintf(\"";
		string args = "";
		string triggerName = "";

		for (int i = 0; i < threatTypeParams.size(); i++) {
			if (threatTypeParams.at(i)->factor == 1)
				fStr += "%d";
			else
				fStr += "%f";
			args += threatTypeParams.at(i)->name;
			if (i != threatTypeParams.size() - 1) {
				fStr += ",";
				args += ",";
			}
			if (i == 4)
				triggerName = threatTypeParams.at(i)->name;
		}

		string sEquation = "SetTriggerParam(" + triggerName + ")," + fStr + "\", " + args + ")";

		bstr_t equation = sEquation.data();

		bstr_t name = nametmp.data();
		bstr_t name2 = nametmp.data();
		bstr_t units = string("").data();

		bstr_t longName = string("Sends_Threat_Type_information_to_control").data();

		bstr_t grp = string("Control").data();
		bstr_t subgrp = string("Parameters").data();

		double sampleRate = 0.0;

		MeasurementInputDataType midt = ASCII;

		HRESULT h = ds->CreateDerivedMeasurement(name.Detach(), name2.Detach(), longName.Detach(), units.Detach(), midt, sampleRate, equation, STANDARD_DERIVED, &mThreatType);
		if (FAILED(h))
			OutputDebugString("failed to createBasicMeasurement\n");
		mThreatType->put_Group(grp);
		mThreatType->put_SubGroup(subgrp);
		ds->addMeasurement(mThreatType);
	}
	{
		string nametmp = "RWR_Report";

		int iadsDataOutSize = 256;

		string fStr = "SetDataOutputSize(" + to_string(iadsDataOutSize) + "),Sprintf(\"";
		string args = "";
		string triggerName = "";

		for (int i = 0; i < rwrParams.size(); i++) {
			if (rwrParams.at(i)->factor == 1)
				fStr += "%d";
			else
				fStr += "%f";
			args += rwrParams.at(i)->name;
			if (i != rwrParams.size() - 1) {
				fStr += ",";
				args += ",";
			}
			if (i == 15)
				triggerName = rwrParams.at(i)->name;
		}

		string sEquation = "SetTriggerParam(" + triggerName + ")," + fStr + "\", " + args + ")";

		bstr_t equation = sEquation.data();

		bstr_t name = nametmp.data();
		bstr_t name2 = nametmp.data();
		bstr_t units = string("").data();

		bstr_t longName = string("Sends_Threat_Type_information_to_control").data();

		bstr_t grp = string("Control").data();
		bstr_t subgrp = string("Parameters").data();

		double sampleRate = 0.0;

		MeasurementInputDataType midt = ASCII;

		HRESULT h = ds->CreateDerivedMeasurement(name.Detach(), name2.Detach(), longName.Detach(), units.Detach(), midt, sampleRate, equation, STANDARD_DERIVED, &mRWR);
		if (FAILED(h))
			OutputDebugString("failed to createBasicMeasurement\n");
		mRWR->put_Group(grp);
		mRWR->put_SubGroup(subgrp);
		ds->addMeasurement(mRWR);
	}
}

void Unpacker::loadParams(string paramCSVPath, int paramSet)
{
	double sampleRate = 0.0;
	ds->put_TimeSampleRate(sampleRate);

	// === Begin read CSV ===

	ifstream ifs(paramCSVPath.data(), std::ifstream::in);

	string tmp;

	uint32_t reportID;
	string name;
	uint32_t startByte;
	uint32_t startBit;
	uint32_t endBit;
	UnpackingMode unpackMode;
	string units;
	double factor;
	string description;
	
	string group;
	string subGroup;

	// throw away first line (header)
	if (ifs.good())
	{
		getline(ifs, tmp);
	}

	// read parameter csvs
	while (ifs.good())
	{
		getline(ifs, tmp, ','); reportID = atoi(tmp.data());
		
		if (reportID % 2 == 0)
			group = "TX";
		else
			group = "RX";
		
		sprintf_s(out, "Report_%02d", reportID);
		subGroup = out;

		getline(ifs, name, ',');
		getline(ifs, tmp, ','); startByte = atoi(tmp.data());
		getline(ifs, tmp, ','); startBit = atoi(tmp.data());
		getline(ifs, tmp, ','); endBit = atoi(tmp.data());


		getline(ifs, tmp, ',');
		if (!strcmp(tmp.data(), "bool") || !strcmp(tmp.data(), "boolean"))
			unpackMode = UM_BYTE;
		else if (!strcmp(tmp.data(), "unsigned short"))
			unpackMode = UM_USHORT;
		else if (!strcmp(tmp.data(), "unsigned"))
			unpackMode = UM_UINT;
		else if (!strcmp(tmp.data(), "enum") || !strcmp(tmp.data(), "enumeration"))
			unpackMode = UM_UINT;
		// TREATING FIXED AS WHOLE NUMBERS
		else if (!strcmp(tmp.data(), "short fixed"))
			unpackMode = UM_SHORT;
		else if (!strcmp(tmp.data(), "signed fixed") || !strcmp(tmp.data(), "fixed"))
			unpackMode = UM_INT;
		else if (!strcmp(tmp.data(), "unsigned fixed"))
			unpackMode = UM_UINT;
		else if (!strcmp(tmp.data(), "char"))
			unpackMode = UM_BYTE;
		else if (!strcmp(tmp.data(), "bitmask"))
			unpackMode = UM_UINT;
		else // none or unrecognized type
		{
			int numBits = endBit - startBit;
			if (numBits <= 8)
				unpackMode = UM_BYTE;
			else if (numBits <= 16)
				unpackMode = UM_USHORT;
			else
				unpackMode = UM_UINT;
		}

		int const bufsize = 5000;
		char buf[bufsize];

		if (ifs.peek() == '"') {
			ifs.get();
			ifs.get(buf, bufsize, '"');
			ifs.get();
			ifs.get();
			units = string(buf);
		}
		else
			getline(ifs, units, ',');
		if (units == "N/A") units = "";

		tmp.clear();
		if (ifs.peek() == ',')
		{
			factor = 1.0;
			ifs.get();
		}
		else 
		{
			getline(ifs, tmp, ',');
			if (tmp.empty())
				factor = 1.0;
			else
				factor = stod(tmp.data());
		}

		tmp.clear();
		if (ifs.peek() == '"') {
			ifs.get();
			ifs.get(buf, bufsize, '"');
			ifs.get();
			ifs.get();
			description = string(buf);
		}
		else
			getline(ifs, description);

		uint32_t numBits = endBit - startBit + 1;
		startBit = startBit % 8; // change to bit offset from startByte

		if ((paramSet == 1 && reportID % 2 == 0) || (paramSet == 2 && reportID % 2 == 1))
			continue; // skip this parameter

		addParam(createParam(name, description, units, reportID, startByte, startBit, numBits, unpackMode, factor, group, subGroup));
	}

	ifs.close();

	// === End read CSV ===


	gatherSpecialtyParameters();
}

Param * Unpacker::createParam (
	string inName,
	string description,
	string inUnits,
	uint32_t reportID,
	uint32_t startByte,
	uint32_t startBit,
	uint32_t numBits,
	UnpackingMode unpackMode,
	double factor,
	string group,
	string subgroup)
{

	bstr_t name = inName.data();
	bstr_t name2 = inName.data();
	bstr_t units = inUnits.data();

	bstr_t longName = description.data();
	
	bstr_t grp = group.data();
	bstr_t subgrp = subgroup.data();

	CComQIPtr<IPluginMeasurement> m;

	double sampleRate = 0.0;

	MeasurementInputDataType midt = DOUBLE_TYPE;

	//switch (unpackMode)
	//{
	//case UM_UINT:
	//	midt = UNSIGNED_BINARY;
	//	break;
	//case UM_INT:
	//	midt = TWOS_COMPLEMENT;
	//	break;
	//case UM_USHORT:
	//	midt = UNSIGNED_BINARY_16;
	//	break;
	//case UM_SHORT:
	//	midt = TWOS_COMPLEMENT_16;
	//	break;
	//case UM_BYTE:
	//	midt = TWOS_COMPLEMENT;
	//	break;
	//case UM_FLOAT:
	//	midt = FLOAT_TYPE;
	//	break;
	//default:
	//	break;
	//}

	ds->CreateBasicMeasurement(name.Detach(), name2.Detach(), longName.Detach(), units.Detach(), midt, sampleRate, &m);
	m->put_Group(grp);
	m->put_SubGroup(subgrp);
	ds->addMeasurement(m);

	Param * pm = new Param();

	pm->measurement = m;

	pm->name = inName;
	pm->reportID = reportID;
	pm->startByte = startByte;
	pm->startBit = startBit;
	pm->numBits = numBits;
	pm->unpackMode = unpackMode;
	pm->factor = factor;

	return pm;
}

void Unpacker::addParam(Param * inParam)
{
	uint32_t reportID = inParam->reportID;

	if (reportIDMap->find(reportID) == reportIDMap->end())
	{ // reportID key does not already exist
		reportIDMap->insert(std::pair<uint32_t, std::vector<Param *> *>(reportID, new std::vector<Param *>()));
	}

	std::vector<Param *> * params = reportIDMap->at(reportID);

	// Add new param to params vector sorted by increasing firstWord
	if (params->empty())
		params->push_back(inParam);
	else {
		for (std::vector<Param *>::iterator iter = params->begin(); iter != params->end(); ++iter)
		{
			if (inParam->startByte < (*iter)->startByte)
			{
				params->insert(iter, inParam);
				break;
			}

			if (iter + 1 == params->end()) {
				params->push_back(inParam);
				break;
			}
		}
	}
}


// Takes a pointer to an ethernet packet payload, and extracts any parameters 
// of interest.
void Unpacker::unpack(BYTE *data, int len)
{ // data points to beginning of ethernet payload

	__int64 intraPacketTime;

	// initialize CSDW structure
	CSDW_MessageF0 *csdw;
	csdw = (CSDW_MessageF0 *)data;

	int numMsg = csdw->uCounter;

	BYTE *pByte = data + sizeof_CSDW_MessageF0;
	len -= sizeof_CSDW_MessageF0;

	// initialize IPH structure
	IPH_MessageF0 *pHeader;

	while (numMsg > 0)
	{
		numMsg--;

		pHeader = (IPH_MessageF0 *)pByte;

		// check for valid length
		if (pHeader->uMsgLength <= 0) {
			break;
		}

		// check for data error
		if (pHeader->bDataError)
		{ // skip the rest of this message
			pByte += pHeader->uMsgLength + sizeof_IPH_MessageF0;
			len -= pHeader->uMsgLength + sizeof_IPH_MessageF0;
			continue;
		}

		// Set time
		intraPacketTime = -1;
		if (ds->CalcIadsTimeFromCh10Time(pHeader->suIntPktTime, &intraPacketTime) == S_OK && intraPacketTime != -1)
			;
			//ds->PutTime(intraPacketTime);
		//else
		//	OutputDebugString("Failed IADS Time calculation\n");

		// advance current position pointer
		pByte += sizeof_IPH_MessageF0;
		len -= sizeof_IPH_MessageF0;

		// check for valid message length
		if ((long)pHeader->uMsgLength > (long)len)
			return;



		short messageID, messageSize = 0;

		messageID = _byteswap_ushort(*(short*)&pByte[0]);
		messageSize = _byteswap_ushort(*(short*)&pByte[2]);

		//sprintf_s(out, "messageID: %d, messageSize: %d, len: %d\n", messageID, messageSize, len);
		//OutputDebugString(out);


		// Check for message with report data
		if (messageID == 1 ||
			messageID == 3 ||
			messageID == 4 ||
			messageID == 5 ||
			messageID == 6)
		{

			if (messageSize > len)
				return;

			int dataIndex = 20; // start after message header

			uint64_t baseReportTimeTag = 0;

			while (dataIndex < pHeader->uMsgLength)
			{

				short reportID, reportSize = 0;

				reportID = _byteswap_ushort(*(short*)&pByte[dataIndex]);
				reportSize = _byteswap_ushort(*(short*)&pByte[dataIndex + 4]);

				if (reportSize > (len - dataIndex))
					return;

				uint32_t timeTag32 = 0;
				timeTag32 = _byteswap_ulong(*(uint32_t*)&pByte[dataIndex + 8]); // multiply by 50000 gets nanoseconds

				putTimeFromReportTimeTag(intraPacketTime, timeTag32, reportID, true);


				//sprintf_s(out, "timeTag64: %lld\n", timeTag64);
				//OutputDebugString(out);

				if (reportIDMap->find(reportID) != reportIDMap->end())
				{ // Found reportID in the map
					vector<Param*>* params = reportIDMap->at(reportID);

					for (vector<Param*>::iterator iter = params->begin(); iter != params->end(); ++iter)
					{
						extractParam(&pByte[dataIndex], reportSize, (*iter));
					}
				}

				dataIndex += reportSize;
			}

			pByte += pHeader->uMsgLength;
			len -= pHeader->uMsgLength;

		}

	}

}


// Takes a pointer to an message packet payload, and extracts any parameters 
// of interest.
void Unpacker::unpackEthernet(BYTE *data, int len)
{ // data points to beginning of packet payload

	__int64 intraPacketTime;

	// initialize CSDW structure
	CSDW_EthernetF0 *csdw;
	csdw = (CSDW_EthernetF0 *)data;

	int numFrames = csdw->uNumFrames;

	BYTE *pByte = data + sizeof_CSDW_EthernetF0;
	len -= sizeof_CSDW_EthernetF0;

	// initialize IPH structure
	IPH_EthernetF0 *pHeader;

	while (numFrames > 0)
	{
		numFrames--;

		pHeader = (IPH_EthernetF0 *)pByte;

		// check for valid length
		if (pHeader->uDataLen <= 0) {
			break;
		}

		// check for data error
		if (pHeader->bFrameError)
		{ // skip the rest of this message
			pByte += pHeader->uDataLen + sizeof_IPH_EthernetF0;
			len -= pHeader->uDataLen + sizeof_IPH_EthernetF0;
			continue;
		}

		// Set time
		intraPacketTime = -1;
		if (ds->CalcIadsTimeFromCh10Time(pHeader->suIntraPckTime, &intraPacketTime) == S_OK && intraPacketTime != -1)
			;
			//ds->PutTime(intraPacketTime);
		//else
		//	OutputDebugString("Failed IADS Time calculation\n");

		// advance current position pointer
		pByte += sizeof_IPH_EthernetF0;
		len -= sizeof_IPH_EthernetF0;

		// check for valid message length
		if ((long)pHeader->uDataLen > (long)len) {
			OutputDebugString("Error: Ch10 data length shows greater than actual length of data\n");
			return;
		}


		pByte += 42; // 42 = pass over Ethernet header
		len -= 42; // 42 = pass over Ethernet header

		// See if there is a partial message in the overflow buffer
		if (overflowBufSize > 0) {
			if (overflowMsgLen - overflowBufSize > len) { // if overflowing again, discard data
				sprintf_s(out, "Error: overflowing on second pass. overflowBufSize: %d, overflowMsgLen: %d\n", overflowBufSize, overflowMsgLen);
				OutputDebugString(out);
				overflowBufSize = 0;
				overflowMsgLen = 0;
				return;
			}
			// copy remaining message to buffer
			memcpy_s(&overflowBuf[overflowBufSize], MAX_CH10_PACKET_SIZE - overflowBufSize, pByte, overflowMsgLen - overflowBufSize);
			overflowBufSize += overflowMsgLen - overflowBufSize;

			if (overflowBufSize != overflowMsgLen) {
				OutputDebugString("Error: something went wrong with the overflow data\n");
				overflowBufSize = 0;
				overflowMsgLen = 0;
				return;
			}

			pByte = overflowBuf;
			len = overflowMsgLen;
			overflowBufSize = 0;
			overflowMsgLen = 0;
		}

		short messageID, messageSize = 0;

		messageID = _byteswap_ushort(*(short*)& pByte[0]);
		messageSize = _byteswap_ushort(*(short*)& pByte[2]);

		//if (messageID == 4) {
		//	sprintf_s(out, "messageID: %d, messageSize: %d, len: %d\n", messageID, messageSize, len);
		//	OutputDebugString(out);
		//}

		uint64_t baseReportTimeTag = 0;


		std::vector<int> report22Locations;
		std::vector<int> report24Locations;

		// Check for message with report data
		if (messageID == 1 ||
			messageID == 3 ||
			messageID == 4 ||
			messageID == 5 ||
			messageID == 6)
		{

			// check for message overflow, and buffer
			if (messageSize > len) {
				memcpy_s(overflowBuf, MAX_CH10_PACKET_SIZE, pByte, len);
				overflowBufSize = len;
				overflowMsgLen = messageSize;
				return;
			}

			int dataIndex = 20; // start after message header

			OutputDebugString("=====\n");

			while (dataIndex < pHeader->uDataLen - 46) // - 46 accounts for ethernet header and trailer
			{
				short reportID, reportSize = 0;

				reportID = _byteswap_ushort(*(short*)&pByte[dataIndex]);
				reportSize = _byteswap_ushort(*(short*)&pByte[dataIndex + 4]);

				//OutputDebugString(std::string("reportID: " + std::to_string(reportID) + "\n").data());

				if (reportID != 22 && reportID != 24) {
				uint32_t timeTag32 = 0;
				timeTag32 = _byteswap_ulong(*(uint32_t*)&pByte[dataIndex + 8]); // multiply by 50000 gets nanoseconds

				putTimeFromReportTimeTag(intraPacketTime, timeTag32, reportID, true);


				if (reportSize > (len - dataIndex))
					return;

				if (reportIDMap->find(reportID) != reportIDMap->end())
				{ // Found reportID in the map
					vector<Param *> * params = reportIDMap->at(reportID);

					for (vector<Param *>::iterator iter = params->begin(); iter != params->end(); ++iter)
					{
						if ((*iter)->name == "Weapon_System_Track_Number_24")
							OutputDebugString(std::string("Weapon_System_Track_Number_24 time: " + std::to_string(intraPacketTime) + " : " + std::to_string(timeTag32) + "\n").data());
						extractParam(&pByte[dataIndex], reportSize, (*iter));
					}
				}
				else { // report 22 or 24
					if (reportID == 22)
						report22Locations.push_back(dataIndex);
					if (reportID == 24)
						report24Locations.push_back(dataIndex);
				}
			}

				decodeReports22and24(pByte, report22Locations, report24Locations, intraPacketTime);

				dataIndex += reportSize;
			}

			pByte += pHeader->uDataLen;
			len -= pHeader->uDataLen;

		}

	}

}



// Takes a pointer to an EPAWSS messages, and extracts any parameters 
// of interest from the contained reports.
void Unpacker::unpackEPAWSS(BYTE* data, int len, LONGLONG iadsTimeForPacket)
{ // data points to beginning of ethernet payload

	//ds->PutTime(iadsTimeForPacket);

	BYTE* pByte = data;

	//pByte += 42; // 42 = pass over Ethernet header
	//len -= 42; // 42 = pass over Ethernet header

	// See if there is a partial message in the overflow buffer
	if (overflowBufSize > 0) {
		if (overflowMsgLen - overflowBufSize > len) { // if overflowing again, discard data
			sprintf_s(out, "Error: overflowing on second pass. overflowBufSize: %d, overflowMsgLen: %d\n", overflowBufSize, overflowMsgLen);
			OutputDebugString(out);
			overflowBufSize = 0;
			overflowMsgLen = 0;
			return;
		}
		// copy remaining message to buffer
		memcpy_s(&overflowBuf[overflowBufSize], MAX_CH10_PACKET_SIZE - overflowBufSize, pByte, overflowMsgLen - overflowBufSize);
		overflowBufSize += overflowMsgLen - overflowBufSize;

		if (overflowBufSize != overflowMsgLen) {
			OutputDebugString("Error: something went wrong with the overflow data\n");
			overflowBufSize = 0;
			overflowMsgLen = 0;
			return;
		}

		pByte = overflowBuf;
		len = overflowMsgLen;
		overflowBufSize = 0;
		overflowMsgLen = 0;
	}

	short messageID, messageSize = 0;

	messageID = _byteswap_ushort(*(short*)&pByte[0]);
	messageSize = _byteswap_ushort(*(short*)&pByte[2]);

	//if (messageID == 4) {
		//sprintf_s(out, "messageID: %d, messageSize: %d, len: %d\n", messageID, messageSize, len);
		//OutputDebugString(out);
	//}


	// Check for message with report data
	if (messageID == 1 ||
		messageID == 3 ||
		messageID == 4 ||
		messageID == 5 ||
		messageID == 6)
	{

		// check for message overflow, and buffer
		if (messageSize > len) {
			memcpy_s(overflowBuf, MAX_CH10_PACKET_SIZE, pByte, len);
			overflowBufSize = len;
			overflowMsgLen = messageSize;
			return;
		}

		int dataIndex = 20; // start after message header

		while (dataIndex < len) // - 46 accounts for ethernet header and trailer
		{
			short reportID, reportSize = 0;

			reportID = _byteswap_ushort(*(short*)&pByte[dataIndex]);
			reportSize = _byteswap_ushort(*(short*)&pByte[dataIndex + 4]);

			uint32_t timeTag32 = 0;
			timeTag32 = _byteswap_ulong(*(uint32_t*)&pByte[dataIndex + 8]); // multiply by 50000 gets nanoseconds

			putTimeFromReportTimeTag(iadsTimeForPacket, timeTag32, reportID, true);

			if (reportSize > (len - dataIndex))
				return;

			if (reportIDMap->find(reportID) != reportIDMap->end())
			{ // Found reportID in the map
				vector<Param*>* params = reportIDMap->at(reportID);

				for (vector<Param*>::iterator iter = params->begin(); iter != params->end(); ++iter)
				{
					extractParam(&pByte[dataIndex], reportSize, (*iter));
				}
			}

			dataIndex += reportSize;
		}

	}

}


void Unpacker::putTimeFromReportTimeTag(LONGLONG iadsTimeForPacket, uint32_t timeTag32, uint32_t reportID, bool makeSameTimeUnique) {

	static LONGLONG lastIadsTime = 0; // holds last IADS time to determine if current call is new value

	if (!timeRecords) // initialize timeRecords
		timeRecords = new std::map<uint32_t, ReportTimeRecord *>();

	// If new IADS time, clear timeRecords map
	if (iadsTimeForPacket != lastIadsTime) {
		timeRecords->clear();
		lastIadsTime = iadsTimeForPacket;
	}

	ReportTimeRecord * r;

	// Look for existing record for this reportID
	if (timeRecords->find(reportID) == timeRecords->end()) { // no record exists
		r = new ReportTimeRecord();
		timeRecords->insert(std::pair<uint32_t, ReportTimeRecord*>(reportID, r));
		OutputDebugString("new record\n");
	}
	else {
		r = timeRecords->find(reportID)->second;
		OutputDebugString("update record\n");
	}
		OutputDebugString(std::string("ReportID: " + std::to_string(reportID) + "\n").data());

	// ==== Determine time using Report Time Tag ====
	if (timeTag32 != r->timetag_previous) {
		r->timetag_offset = 10;
		r->timetag_previous = timeTag32;
		OutputDebugString("different time tag\n");
	}
	else
		timeTag32 += (r->timetag_offset-- * 20 * 10); // adding an increasing number of miliseconds

	uint64_t timeTag64 = (uint64_t)timeTag32 * 50000; // convert to nanoseconds

	if (r->baseReportTimeTag == 0)
		r->baseReportTimeTag = timeTag64;

	ds->PutTime(iadsTimeForPacket + (timeTag64 - r->baseReportTimeTag));
	// ==============================================

	OutputDebugString(std::string("PutTime(" + std::to_string(iadsTimeForPacket + (timeTag64 - r->baseReportTimeTag)) + ")\n").data());
	//OutputDebugString(std::string("updated time tag: " + std::to_string(timeTag32) + "\n").data());
	//OutputDebugString(std::string("baseReportTimeTg: " + std::to_string(r->baseReportTimeTag) + "\n").data());
}



// Extracts a parameter from inDataWord using the attributes described in param
void Unpacker::extractParam(BYTE *data, int lenth, Param *param)
{
	static uint32_t dataMask[33] = {
		0x0000, 0x0001, 0x0003, 0x0007,
		0x000f, 0x001f, 0x003f, 0x007f,
		0x00ff, 0x01ff, 0x03ff, 0x07ff,
		0x0fff, 0x1fff, 0x3fff, 0x7fff,
		0x0ffff, 0x1ffff, 0x3ffff, 0x7ffff,
		0xfffff, 0x1fffff, 0x3fffff, 0x7fffff,
		0x0ffffff, 0x1ffffff, 0x3ffffff, 0x7ffffff,
		0x0fffffff, 0x1fffffff, 0x3fffffff, 0x7fffffff,
		0xffffffff };

	// Compute value from data and convert to EU using factor
	double eu;

	BYTE tmp[4];

	tmp[0] = data[param->startByte];
	tmp[1] = data[param->startByte + 1];
	tmp[2] = data[param->startByte + 2];
	tmp[3] = data[param->startByte + 3];

	*(uint32_t *)tmp = (_byteswap_ulong(*(uint32_t *)tmp) >> ((32 - param->startBit) - param->numBits)) & dataMask[param->numBits];

	uint32_t sign = *(uint32_t *)tmp & (0x01 << (param->numBits - 1));


	switch (param->unpackMode)
	{
	case UM_UINT:
	{
		uint32_t dataWord = *(uint32_t *)tmp;
		eu = (double)dataWord * param->factor;

		param->currentValue = to_string((uint32_t)eu);
		break;
	}
	case UM_INT:
	{
		uint32_t dataWord = *(uint32_t *)tmp;

		if (sign) // convert from Two's Complement
			dataWord = (~*(uint32_t *)tmp & dataMask[param->numBits]) + 1;

		eu = (double)dataWord * param->factor;

		if (sign)
			eu *= -1;

		param->currentValue = to_string((int)eu);

		break;
	}
	case UM_USHORT:
	{
		uint16_t dataWord = *(uint16_t *)tmp;
		eu = (double)dataWord * param->factor;

		param->currentValue = to_string((uint16_t)eu);
		break;
	}
	case UM_SHORT:
	{
		short dataWord = *(short *)tmp;

		if (sign) // convert from Two's Complement
			dataWord = (~*(uint16_t *)tmp & dataMask[param->numBits]) + 1;

		eu = (double)dataWord * param->factor;

		if (sign)
			eu *= -1;

		param->currentValue = to_string((short)eu);

		break;
	}
	case UM_BYTE:
	{
		BYTE dataWord = *(BYTE *)tmp;
		eu = (double)dataWord * param->factor;

		param->currentValue = to_string((uint8_t)eu);
		break;
	}
	case UM_FLOAT:
	{
		//uint32_t dataWord =
		//	(tmp[0] << 24) |
		//	(tmp[1] << 16) |
		//	(tmp[2] << 8) |
		//	tmp[3];
		//rawvalue.vt = VT_R4;
		//memcpy(&(rawvalue.fltVal), &dataWord, 4);
		float dataWord = *(float *)tmp;
		eu = (double)dataWord * param->factor;

		param->currentValue = to_string(eu);
		break;
	}
	default:
		break;
	}

	//char buf[20];
	//sprintf_s(buf, "value: %f\n", value.fltVal);
	//OutputDebugString(buf);

	// Create VARIANT data to be used in measurement
	VARIANT value;
	value.vt = VT_R8;
	value.dblVal = eu;

	// Add data to measurement
	ds->PutData(param->measurement, value);
}




void Unpacker::decodeReports22and24(BYTE *pByte, std::vector<int> report22Locations, std::vector<int> report24Locations, long long intraPacketTime) {

	int reportLocationIndex = 0;

	// TODO: decode reports 22 and 24
	while (reportLocationIndex < report22Locations.size() && reportLocationIndex < report24Locations.size())
	{
		// Report 22
		int dataIndex = report22Locations.at(reportLocationIndex);
		short reportID, reportSize = 0;

		reportID = _byteswap_ushort(*(short*)&pByte[dataIndex]);
		reportSize = _byteswap_ushort(*(short*)&pByte[dataIndex + 4]);

		uint32_t timeTag32 = 0;
		timeTag32 = _byteswap_ulong(*(uint32_t*)&pByte[dataIndex + 8]); // multiply by 50000 gets nanoseconds

		putTimeFromReportTimeTag(intraPacketTime, timeTag32, reportID, true);

		if (reportIDMap->find(reportID) != reportIDMap->end())
		{ // Found reportID in the map
			vector<Param*>* params = reportIDMap->at(reportID);

			for (vector<Param*>::iterator iter = params->begin(); iter != params->end(); ++iter)
			{
				extractParam(&pByte[dataIndex], reportSize, (*iter));
			}
		}


		// Report 24
		dataIndex = report24Locations.at(reportLocationIndex);

		reportID = _byteswap_ushort(*(short*)&pByte[dataIndex]);
		reportSize = _byteswap_ushort(*(short*)&pByte[dataIndex + 4]);

		timeTag32 = _byteswap_ulong(*(uint32_t*)&pByte[dataIndex + 8]); // multiply by 50000 gets nanoseconds

		putTimeFromReportTimeTag(intraPacketTime, timeTag32, reportID, true);

		if (reportIDMap->find(reportID) != reportIDMap->end())
		{ // Found reportID in the map
			vector<Param*>* params = reportIDMap->at(reportID);

			for (vector<Param*>::iterator iter = params->begin(); iter != params->end(); ++iter)
			{
				extractParam(&pByte[dataIndex], reportSize, (*iter));
			}
		}


		reportLocationIndex++;
	}
}