// dllmain.h : Declaration of module class.

class CEPAWSSModule : public ATL::CAtlDllModuleT< CEPAWSSModule >
{
public :
	DECLARE_LIBID(LIBID_EPAWSSLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_EPAWSS, "{f10668f0-2ac8-4017-8442-7fce34b1917d}")
};

extern class CEPAWSSModule _AtlModule;
