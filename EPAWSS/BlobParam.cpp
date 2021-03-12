#include "BlobParam.h"

#include <algorithm>

BlobParam::BlobParam(
    std::string strname, 
    uint32_t inReportID, 
    BLOB_PARAM_DATA_TYPE dt,
    std::string strGroup,
    std::string strSubgroup,
    IIadsTppCh10PluginDataStream* dataStream)
{
    ds = dataStream;

    name = strname;
    std::replace(name.begin(), name.end(), '_', ' ');
    reportID = inReportID;
    dataType = dt;

    bstr_t name = strname.data();
    bstr_t name2 = strname.data();
    bstr_t name3 = strname.data();
    bstr_t units = std::string("").data();

    bstr_t group = strGroup.data();
    bstr_t subgroup = strSubgroup.data();

    ds->CreateBasicMeasurement(name.Detach(), name2.Detach(), name3.Detach(), units.Detach(), BLOB_TYPE, 0.0, &mBlob);

    mBlob->put_BlobSizeInBytes(maxBlobSize);
    mBlob->put_Group(group.Detach());
    mBlob->put_SubGroup(subgroup.Detach());

    ds->addMeasurement(mBlob);

    SAFEARRAYBOUND bounds;
    bounds.lLbound = 0;
    bounds.cElements = maxBlobSize;
    blobData = ::SafeArrayCreate(VT_UI1, 1, &bounds);
    if (blobData == NULL)
        OutputDebugString("Failed to create blob parameter. Out of memory\n");
}


BlobParam::~BlobParam()
{
    ::SafeArrayDestroy(blobData);
}


void BlobParam::addValue(double inValue) {
    switch (dataType) {
        case BLOB_INT_TYPE:
            addValue((int)inValue);
            break;
        case BLOB_FLOAT_TYPE:
            addValue((float)inValue);
            break;
        default: break;
    }
}

void BlobParam::addValue(int inValue) {
	nextValuesI.push_back(inValue);
}

void BlobParam::addValue(float inValue) {
    nextValuesF.push_back(inValue);
}

void BlobParam::commitData() {
    if (!blobData) return;

    // check for data
    switch (dataType) {
        case BLOB_INT_TYPE:
            if (nextValuesI.empty()) return;
            break;
        case BLOB_FLOAT_TYPE:
            if (nextValuesF.empty()) return;
            break;
        default: return;
    }

    BYTE* byteData;
    SafeArrayAccessData(blobData, (void**)&byteData);
    memset(byteData, 0, maxBlobSize);


    // get number of elements to write
    uint16_t numElements = 0;
    switch (dataType) {
    case BLOB_INT_TYPE:
        numElements = nextValuesI.size();
        break;
    case BLOB_FLOAT_TYPE:
        numElements = nextValuesF.size();
        break;
    default: break;
    }


    // Fill data header
    Header h;
    h.size = (numElements * sizeof(int)) + SIZEOF_HEADER;
    h.type = dataType;
    h.rptID = (uint16_t)reportID;

    std::string nameToCopy = this->name.substr(5); // 5 is the length of "Blob_" prefix

    memset(h.name, 0, SIZEOF_NAME);
    if (nameToCopy.length() > SIZEOF_NAME)
    {
        nameToCopy = nameToCopy.substr(nameToCopy.length() - SIZEOF_NAME + 3);
        nameToCopy = "..." + nameToCopy;
        memcpy(h.name, nameToCopy.data(), nameToCopy.length());
    }
    else
        memcpy(h.name, nameToCopy.data(), nameToCopy.length());
    memcpy(byteData, &h, SIZEOF_HEADER);

    //OutputDebugString(std::string(std::to_string(byteData[0]) + " " + std::to_string(byteData[1]) + " " + 
    //    std::to_string(byteData[2]) + " " + std::to_string(byteData[3]) + "\n").data());

    // Fill data array with vector values
    int headerOffset = SIZEOF_HEADER;
    for (int i = 0; i < numElements; ++i)
        switch (dataType) {
            case BLOB_INT_TYPE:
                *((int*)&byteData[(i * sizeof(int)) + headerOffset]) = nextValuesI.at(i);
                break;
            case BLOB_FLOAT_TYPE:
                *((float*)&byteData[(i * sizeof(float)) + headerOffset]) = nextValuesF.at(i);
                break;
            default: break;
        }

    VARIANT vd;
    vd.vt = VT_ARRAY | VT_UI1;
    vd.parray = blobData;
    //vd.parray->rgsabound->cElements = nextValues.size();
    SafeArrayUnaccessData(blobData);
    byteData = NULL;

    //mBlob->put_BlobSizeInBytes(nextValues.size() * sizeof(int));
    nextValuesI.clear();
    nextValuesF.clear();

    ds->PutData(mBlob, vd);
}