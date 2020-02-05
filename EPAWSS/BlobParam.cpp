#include "BlobParam.h"

BlobParam::BlobParam(
    std::string strname, 
    uint32_t reportID, 
    std::string strGroup,
    std::string strSubgroup,
    IIadsTppCh10PluginDataStream* dataStream)
{
    ds = dataStream;

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


void BlobParam::addValue(int inValue) {
	nextValues.push_back(inValue);
}

void BlobParam::commitData() {
    if (!blobData) return;
    if (nextValues.empty()) return;

    BYTE* byteData;
    SafeArrayAccessData(blobData, (void**)&byteData);
    memset(byteData, 0, maxBlobSize);

    // Fill data array with vector values
    for (int i = 0; i < nextValues.size(); ++i)
        *((int*)&byteData[i * sizeof(int)]) = nextValues.at(i);


    VARIANT vd;
    vd.vt = VT_ARRAY | VT_UI1;
    vd.parray = blobData;
    vd.parray->rgsabound->cElements = nextValues.size();
    SafeArrayUnaccessData(blobData);
    byteData = NULL;

    //mBlob->put_BlobSizeInBytes(nextValues.size() * sizeof(int));
    nextValues.clear();

    ds->PutData(mBlob, vd);
}