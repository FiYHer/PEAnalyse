#pragma once

#include <iostream>
#include <windows.h>
#include <Shlwapi.h>
#include <tchar.h>
#pragma comment(lib,"shlwapi.lib")
using namespace std;

namespace PEAnalyseSpace
{
	class PEAnalyse
	{
	private:
		//�ļ�·��
		PWCHAR m_lpFilePath;
		//�ļ����
		HANDLE m_hFile;
		//�ڴ�ӳ��
		LPVOID m_lpBase;
		//�ļ���С
		DWORD m_dwFileSize;

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
	public:
		PEAnalyse();
		~PEAnalyse();
	public:
		//�����ļ����ڴ�
		BOOL LoadFile(PWCHAR szFilePath);
		//���ڴ������ݱ��浽�ļ�
		BOOL SaveFile();
		//���������
		BOOL ShowExport();
	};
}
