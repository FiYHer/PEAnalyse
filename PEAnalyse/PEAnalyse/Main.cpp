#include "PEAnalyse.h"
using namespace PEAnalyseSpace;
int main(int argc,char *argv[])
{
	WCHAR szBuf[100] = L"D://2222.exe";
	WCHAR szName[100] = L".shell";
	PEAnalyse MyTest;
	MyTest.LoadFile(szBuf);
	MyTest.AddSection(szName,1024, 
		IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE);
	system("pause");
	return 0;
}

