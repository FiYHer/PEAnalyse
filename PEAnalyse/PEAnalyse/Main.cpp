#include "PEAnalyse.h"
using namespace PEAnalyseSpace;
int main(int argc,char *argv[])
{
	WCHAR szBuf[100] = L"D://2222.exe";
	PEAnalyse MyTest;
	MyTest.LoadFile(szBuf);
	//MyTest.ShowExport();
	//MyTest.ShowImport();
	MyTest.ShowNullAddress();
	MyTest.SaveFile();
	system("pause");
	return 0;
}

