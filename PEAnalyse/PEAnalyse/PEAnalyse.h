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
		//文件路径
		PWCHAR m_lpFilePath;
		//文件句柄
		HANDLE m_hFile;
		//
		HANDLE m_hMap;
		//内存映射
		LPVOID m_lpBase;
		//文件大小
		DWORD m_dwFileSize;

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
	public:
		PEAnalyse();
		~PEAnalyse();
	public:
		//加载文件到内存
		BOOL LoadFile(PWCHAR szFilePath);
		//把内存中数据保存到文件
		BOOL SaveFile();
		//输出导出表
		BOOL ShowExport();
		//输出导入表
		BOOL ShowImport();
		//输出空地址 主要是搜索 cc 90 00
		BOOL ShowNullAddress();
	};
}

