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
	public IDispatchImpl<IIadsTppCh10EthernetPlugin2, &__uuidof(IIadsTppCh10EthernetPlugin2), &LIBID_IadsTppCommonLib, /* wMajor = */ 1, /* wMinor = */ 0>
{
public:
	CRXTX()
	{
	}

DECLARE_REGISTRY_RESOURCEID(106)


BEGIN_COM_MAP(CRXTX)
	COM_INTERFACE_ENTRY(IRXTX)
	COM_INTERFACE_ENTRY2(IDispatch, IIadsTppCh10EthernetPlugin2)
	COM_INTERFACE_ENTRY(IIadsTppCh10EthernetPlugin2)
	COM_INTERFACE_ENTRY(IIadsTppCh10EthernetPlugin)
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

	Unpacker unpacker;


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


		CComQIPtr<IIadsTppCh10PluginDataStream> ds = dataStream;
		if (ds == NULL) return E_POINTER;

		// INIT UNPACKER HERE
		unpacker = Unpacker(ds, paramCSVPath, PARAM_SET_ALL);

		// Add your function implementation here.
		return S_OK;
	}

	STDMETHOD(ProcessEthernetPayload)(IIadsTppCh10PluginDataStream* dataStream, VARIANT data, LONG packageSize, LONGLONG iadsTimeFromHeader)
	{
		return E_NOTIMPL;
	}

	STDMETHOD(ProcessEthernetPayloadMultiChannel)(IIadsTppCh10PluginDataStream* dataStream, VARIANT data, LONG packageSize, LONGLONG iadsTimeForPacket, LONG packetId)
	{
		byte* payload = NULL;
		HR(SafeArrayAccessData(data.parray, (void**)&payload));

		long upperBound = data.parray->rgsabound->cElements + data.parray->rgsabound->lLbound;
		long lowerBound = data.parray->rgsabound->lLbound;

		//OutputDebugString(std::string("data length: " + std::to_string(upperBound- lowerBound) + "\n").data());

		unpacker.unpackEPAWSS(payload, upperBound - lowerBound, iadsTimeForPacket);

		//Make sure you unlock the array when you're done! 
		SafeArrayUnaccessData(data.parray);

		return S_OK;
	}
	STDMETHOD(get_SupportsMultiChannel)(VARIANT_BOOL* doesSupport)
	{
		//OutputDebugString("get_supportsMultiChannel1\n");
		if (doesSupport == NULL) return E_POINTER;
		//OutputDebugString("get_supportsMultiChannel2\n");
		*doesSupport = VARIANT_TRUE;
		return S_OK;
	}
};

OBJECT_ENTRY_AUTO(__uuidof(RXTX), CRXTX)
