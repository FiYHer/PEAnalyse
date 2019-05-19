#pragma once

#include <iostream>
#include <windows.h>
#include <Shlwapi.h>
#include <tchar.h>
#pragma comment(lib,"shlwapi.lib")
using namespace std;

#define CodeSectionName ".text"

namespace PEAnalyseSpace
{
	class PEAnalyse
	{
	private:
		//文件句柄
		HANDLE m_hFile;
		//文件map
		HANDLE m_hMap;
		//内存映射
		LPVOID m_lpBase;

		//DOS文件头
		PIMAGE_DOS_HEADER m_pDos;
		//NT文件头
		PIMAGE_NT_HEADERS m_pNt;

	private:
		/*检查文件类型
		//@pszFilePath:文件路径
		*/
		BOOL CheckFileType(PWCHAR pszFilePath);
		/*RAV转OFFSET
		*/
		DWORD RVAtoOffset(DWORD dwRva);
		/*创建一个新文件，在新文件上面操作
		//@pszFilePath:原来的文件名
		//@pszNewFilePath:返回新文件名字
		*/
		BOOL CreateNewFile(PWCHAR pszFilePath,PWCHAR szFilePath);

		DWORD Alignment(DWORD dwSize,DWORD dwAligment);
	public:
		PEAnalyse();
		~PEAnalyse();
	public:
		//加载文件到内存
		BOOL LoadFile(PWCHAR szFilePath);
		//输出导出表
		BOOL ShowExport();
		//输出导入表
		BOOL ShowImport();
		//输出空地址 主要是搜索 cc 90 00
		BOOL ShowNullAddress();
		//添加一个区段
		BOOL AddSection(PWCHAR szSectionName,
			DWORD dwSize,
			DWORD dwCharater);
		//插入shellcode
		BOOL InsertShellcode(DWORD dwOffsetAddress,
			DWORD dwVirtuaAddress,
			PWCHAR pwsOpcodeFilePath);
	};
}

