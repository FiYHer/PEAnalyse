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
		//�ļ����
		HANDLE m_hFile;
		//�ļ�map
		HANDLE m_hMap;
		//�ڴ�ӳ��
		LPVOID m_lpBase;

		//DOS�ļ�ͷ
		PIMAGE_DOS_HEADER m_pDos;
		//NT�ļ�ͷ
		PIMAGE_NT_HEADERS m_pNt;

	private:
		/*����ļ�����
		//@pszFilePath:�ļ�·��
		*/
		BOOL CheckFileType(PWCHAR pszFilePath);
		/*RAVתOFFSET
		*/
		DWORD RVAtoOffset(DWORD dwRva);
		/*����һ�����ļ��������ļ��������
		//@pszFilePath:ԭ�����ļ���
		//@pszNewFilePath:�������ļ�����
		*/
		BOOL CreateNewFile(PWCHAR pszFilePath,PWCHAR szFilePath);

		DWORD Alignment(DWORD dwSize,DWORD dwAligment);
	public:
		PEAnalyse();
		~PEAnalyse();
	public:
		//�����ļ����ڴ�
		BOOL LoadFile(PWCHAR szFilePath);
		//���������
		BOOL ShowExport();
		//��������
		BOOL ShowImport();
		//����յ�ַ ��Ҫ������ cc 90 00
		BOOL ShowNullAddress();
		//���һ������
		BOOL AddSection(PWCHAR szSectionName,
			DWORD dwSize,
			DWORD dwCharater);
		//����shellcode
		BOOL InsertShellcode(DWORD dwOffsetAddress,
			DWORD dwVirtuaAddress,
			PWCHAR pwsOpcodeFilePath);
	};
}

