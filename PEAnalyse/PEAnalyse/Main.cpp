#include "PEAnalyse.h"
using namespace PEAnalyseSpace;
int main(int argc,char *argv[])
{
	WCHAR szBuf[100] = L"D://2222.dll";
	PEAnalyse MyTest;
	MyTest.LoadFile(szBuf);
	MyTest.ShowExport();
	system("pause");
	return 0;
}