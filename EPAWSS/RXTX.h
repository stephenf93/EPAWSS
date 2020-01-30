// RXTX.h : Declaration of the CRXTX

#pragma once
#include "resource.h"       // main symbols



#include "EPAWSS.h"

#include <comutil.h>
#include <atlstr.h> 
#include "IadsTppCommon.h"

#include "Unpacker.h"



using namespace ATL;


// CRXTX

class ATL_NO_VTABLE CRXTX :
	public CComObjectRootEx<CComMultiThreadModel>,
	public CComCoClass<CRXTX, &CLSID_RXTX>,
	public IDispatchImpl<IRXTX, &IID_IRXTX, &LIBID_EPAWSSLib, /*wMajor =*/ 1, /*wMinor =*/ 0>,
	public IDispatchImpl<IIadsTppCh10Plugin, &__uuidof(IIadsTppCh10Plugin), &LIBID_IadsTppCommonLib, /* wMajor = */ 1, /* wMinor = */ 0>
{
public:
	CRXTX()
	{
	}

DECLARE_REGISTRY_RESOURCEID(106)


BEGIN_COM_MAP(CRXTX)
	COM_INTERFACE_ENTRY(IRXTX)
	COM_INTERFACE_ENTRY2(IDispatch, IIadsTppCh10Plugin)
	COM_INTERFACE_ENTRY(IIadsTppCh10Plugin)
END_COM_MAP()



	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct()
	{
		return S_OK;
	}

	void FinalRelease()
	{
	}

public:

	string paramCSVPath;

	LONG packetNumber;

	Unpacker unpacker;

	CComQIPtr<IPluginMeasurement> mPacketCounter;



	// IIadsTppCh10Plugin Methods
public:
	STDMETHOD(get_DataSourceName)(BSTR* pVal)
	{
		_bstr_t name = "EPAWSS.RXTX";
		if (pVal == NULL) return E_POINTER;
		*pVal = name.Detach();
		return S_OK;
	}
	STDMETHOD(put_DataSourceName)(BSTR newVal)
	{
		// Add your function implementation here.
		return S_OK;
	}
	STDMETHOD(Init)(IIadsTppCh10PluginDataStream* dataStream, ULONG packetId)
	{
		// Add your function implementation here.

		//Sleep(2000);

		CHAR sValue[4096];
		ULONG pSize = -1;

		ExpandEnvironmentStrings("%PUBLIC%\\Documents\\f15config.ini", sValue, 2000);

		const size_t outstrsize = 256;
		char outstr[outstrsize];

		GetPrivateProfileString("general", "paramcsv", "C:\\CANIS\\params.csv", outstr, outstrsize, sValue);
		paramCSVPath = string(outstr);

		//char out[25];
		//sprintf_s(out, "\nerror: %d\n", ls);
		//OutputDebugString(out);


		CComQIPtr<IIadsTppCh10PluginDataStream> ds = dataStream;
		if (ds == NULL) return E_POINTER;

		// INIT UNPACKER HERE
		unpacker = Unpacker(ds, paramCSVPath, PARAM_SET_ALL);

		// Add your function implementation here.
		return S_OK;
	}
	STDMETHOD(ProcessCh10Packet)(IIadsTppCh10PluginDataStream* dataStream, VARIANT data, LONG packageSize, LONGLONG iadsTimeFromHeader)
	{

		//OutputDebugString("====Process Data====\n");

		// Add your function implementation here.
		dataStream->PutTime(iadsTimeFromHeader);

		byte* payload = NULL;
		HR(SafeArrayAccessData(data.parray, (void**)&payload));

		long upperBound = data.parray->rgsabound->cElements + data.parray->rgsabound->lLbound;
		long lowerBound = data.parray->rgsabound->lLbound;

		unpacker.unpack(payload, upperBound - lowerBound);

		//Make sure you unlock the array when you're done! 
		SafeArrayUnaccessData(data.parray);

		return S_OK;
	}
	STDMETHOD(get_Ch10PacketType)(ULONG* pval)
	{
		//Message F0 data is type 0x30
		if (pval == NULL) return E_POINTER;
		*pval = 0x30;
		return S_OK;
	}
};

OBJECT_ENTRY_AUTO(__uuidof(RXTX), CRXTX)
