#include "PEAnalyse.h"
using namespace PEAnalyseSpace;
#pragma warning(disable:4996)

PEAnalyse::PEAnalyse()
{
	m_lpFilePath = nullptr;
	m_hFile = INVALID_HANDLE_VALUE;
	m_hMap = NULL;
	m_lpBase = nullptr;
	m_dwFileSize = NULL;
	m_pDos = nullptr;
	m_pNt = nullptr;
}


PEAnalyse::~PEAnalyse()
{
	if (m_lpFilePath != nullptr)
	{
		VirtualFree((LPVOID)m_lpFilePath, NULL, MEM_RELEASE);
		m_lpFilePath = nullptr;
	}
	if (m_hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_hFile);
		m_hFile = INVALID_HANDLE_VALUE;
	}
	if (m_hMap != NULL)
	{
		CloseHandle(m_hMap);
		m_hMap = NULL;
	}
	if (m_lpBase != nullptr)
	{
		UnmapViewOfFile(m_lpBase);
		m_lpBase = nullptr;
	}
}

BOOL PEAnalyseSpace::PEAnalyse::CheckFileType(PWCHAR pszFilePath)
{
	//�ַ���ָ�벻��Ϊ��
	if (pszFilePath == nullptr)
	{
		return FALSE;
	}

	//�жϺ�׺��
	if (wcscmp(PathFindExtensionW(pszFilePath), L".exe") == 0 ||
		wcscmp(PathFindExtensionW(pszFilePath), L".dll") == 0)
	{
		return TRUE;
	}
	return FALSE;
}

DWORD PEAnalyseSpace::PEAnalyse::RVAtoOffset(DWORD dwRva)
{
	PIMAGE_SECTION_HEADER pSections = NULL;
	DWORD dwIndex = 0;

	//
	if (m_lpBase == NULL)
	{
		return 0;
	}

	//��ȡ��һ������
	pSections = IMAGE_FIRST_SECTION(m_pNt);

	//���RVAС�ڵ�һ�������Ļ�
	if (dwRva < pSections->VirtualAddress)
	{
		return 0;
	}

	//������ǰrva������һ������
	while (pSections[dwIndex].VirtualAddress != NULL)
	{
		if (pSections[dwIndex].VirtualAddress < dwRva && 
			dwRva < pSections[dwIndex+1].VirtualAddress)
		{
			return pSections[dwIndex].PointerToRawData + 
				(dwRva - pSections[dwIndex].VirtualAddress);
		}
		dwIndex++;
	}
	return 0;
}

BOOL PEAnalyseSpace::PEAnalyse::LoadFile(PWCHAR szFilePath)
{
	BOOL bRet = FALSE;
	DWORD dwByte = NULL;

	do 
	{
		//�ļ�·������Ϊ��
		if (szFilePath == NULL)
		{
			break;
		}

		//�жϺ�׺���ǲ���exe
		if (!CheckFileType(szFilePath))
		{
			break;
		}

		//�����ļ�·��
		if (wcslen(szFilePath) > 4 * 1024)
		{
			break;
		}

		//û������ռ�Ļ�������
		if (m_lpFilePath == NULL)
		{
			m_lpFilePath = (PWCHAR)VirtualAlloc(NULL, 4 * 1024, MEM_COMMIT, PAGE_READWRITE);
			if (m_lpFilePath == NULL)
			{
				break;
			}
		}

		//�����ļ�·��
		ZeroMemory((LPVOID)m_lpFilePath, 4 * 1024);
		wcsncpy((wchar_t*)m_lpFilePath, szFilePath, wcslen(szFilePath));

		//����ϴδ����ļ��Ļ����Ǿ�Ҫ�ȹر�
		if (m_hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(m_hFile);
			m_hFile = INVALID_HANDLE_VALUE;
		}
		m_hFile = CreateFileW(szFilePath, GENERIC_READ | GENERIC_WRITE,
			NULL, NULL, OPEN_EXISTING, NULL, NULL);

		//�����ʧ�ܵĻ�
		if (m_hFile == INVALID_HANDLE_VALUE)
		{
			break;
		}

		//��ȡ�ļ��Ĵ�С
		m_dwFileSize = GetFileSize(m_hFile, NULL);

		//���ͷ�
		if (m_hMap != NULL)
		{
			CloseHandle(m_hMap);
			m_hMap = NULL;
		}

		//�����ļ�map
		m_hMap = CreateFileMappingW(m_hFile, NULL, PAGE_READWRITE, NULL, NULL, NULL);
		if (m_hMap == NULL)
		{
			break;
		}

		//ԭ�ڴ�ӳ�񻹴��ڣ������ͷ�
		if (m_lpBase != NULL)
		{
			UnmapViewOfFile(m_lpBase);
			m_lpBase = NULL;
		}

		//�����ļ��ڴ�ӳ��
		m_lpBase = MapViewOfFile(m_hMap, FILE_MAP_ALL_ACCESS, NULL, NULL, NULL);
		if (m_lpBase == NULL)
		{
			break;
		}

		//��ȡdosͷ��ntͷָ��
		m_pDos = (PIMAGE_DOS_HEADER)m_lpBase;
		m_pNt = (PIMAGE_NT_HEADERS)((DWORD)m_pDos->e_lfanew + (DWORD)m_lpBase);

		bRet = TRUE;
	} while (FALSE);
	return bRet;
}

BOOL PEAnalyseSpace::PEAnalyse::SaveFile()
{
	BOOL bRet = FALSE;
	PWCHAR pszFilePath = nullptr;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	DWORD dwByte = 0;

	do 
	{
		//û���ļ���
		if (m_lpFilePath == NULL)
		{
			break;
		}

		//û�н����ļ�
		if (m_lpBase == NULL)
		{
			break;
		}

		//�����ڴ棬���ļ�·��
		pszFilePath = (PWCHAR)VirtualAlloc(nullptr, 4 * 1024, MEM_COMMIT, PAGE_READWRITE);
		if (pszFilePath == nullptr)
		{
			break;
		}
		ZeroMemory((LPVOID)pszFilePath, 4 * 1024);
		wcsncpy((wchar_t*)pszFilePath, m_lpFilePath, wcslen(m_lpFilePath));

		//ȥ����׺��
		PathRemoveExtensionW(pszFilePath);
		//������׺��
		wcscat(pszFilePath, L"_New.exe");

		//�����ļ�
		hFile = CreateFileW(pszFilePath, GENERIC_ALL, NULL, NULL, CREATE_ALWAYS, NULL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			break;
		}

		//д���ļ���
		WriteFile(hFile, m_lpBase, m_dwFileSize, &dwByte, NULL);
		if (dwByte == NULL)
		{
			break;
		}

		bRet = TRUE;
	} while (FALSE);
	if (pszFilePath != nullptr)
	{
		VirtualFree(pszFilePath, 0, MEM_RELEASE);
	}
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
	}
	return bRet;
}

BOOL PEAnalyseSpace::PEAnalyse::ShowExport()
{
	BOOL bRet = FALSE;//�Ƿ�ִ�гɹ�
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;//������ָ��
	PDWORD pNames = NULL;//���Ʊ�ָ��
	PWORD pOrders = NULL;//��ű�ָ��
	PDWORD pFuncs = NULL;//��ַ��ָ��
	PCHAR pszName = NULL;//ָ��������
	DWORD dwIndex = 0;//����
	DWORD dwNum = 0;//��������������
	do 
	{
		//û�н���
		if (m_lpBase == NULL)
		{
			break;
		}

		//������Ϊ��
		if (m_pNt->OptionalHeader.DataDirectory->Size == NULL)
		{
			break;
		}

		//��ȡ������
		pExport = (PIMAGE_EXPORT_DIRECTORY)
			(RVAtoOffset(m_pNt->OptionalHeader.DataDirectory->VirtualAddress)
				+(DWORD)m_lpBase);
		
		//��ȡ��������������
		dwNum = pExport->NumberOfFunctions;

		//��������
		pNames = (PDWORD)((PCHAR)RVAtoOffset(pExport->AddressOfNames) + (DWORD)m_lpBase);

		//�������
		pOrders = (PWORD)(RVAtoOffset(pExport->AddressOfNameOrdinals) + (DWORD)m_lpBase);

		//������ַ
		pFuncs = (PDWORD)(RVAtoOffset(pExport->AddressOfFunctions) + (DWORD)m_lpBase);

		//�������ģ�������
		cout << "Module Name Is: "
			<< (PCHAR)(RVAtoOffset(pExport->Name) + (DWORD)m_lpBase)
			<< endl;

		for (; dwIndex < dwNum; dwIndex++)
		{
			//��ȡ������
			pszName = (PCHAR)(RVAtoOffset(pNames[dwIndex]) + (DWORD)m_lpBase);
			cout << "ID: " << pOrders[dwIndex]
				<< "\tFunctionName: " << pszName
				<< "\tFunctionRVA: " << hex << "0x" << pFuncs[dwIndex]
				<< endl;
		}
		bRet = TRUE;
	} while (FALSE);
	return bRet;
}

BOOL PEAnalyseSpace::PEAnalyse::ShowImport()
{
	//ִ���Ƿ�ɹ�
	BOOL bRet = FALSE;

	//�����ָ��
	PIMAGE_IMPORT_DESCRIPTOR pImport = NULL;

	//ָ��
	PIMAGE_THUNK_DATA pThunk = NULL;

	//�������Ʊ�ָ��
	PIMAGE_IMPORT_BY_NAME pName = NULL;

	//�ַ���ָ��
	PCHAR pszName = NULL;

	do 
	{
		//û�н���
		if (m_lpBase == NULL)
		{
			break;
		}

		//û�е��뵼���,����ǲ����ܵ�
		if (m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == NULL)
		{
			break;
		}

		//��ȡ�����
		pImport = (PIMAGE_IMPORT_DESCRIPTOR)
			(RVAtoOffset(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
				+ (DWORD)m_lpBase);

		//ѭ������
		while (pImport->Name)
		{
			//��ȡ�����ַ��
			pThunk = (PIMAGE_THUNK_DATA)
				(RVAtoOffset(pImport->OriginalFirstThunk) + (DWORD)m_lpBase);

			//��ȡģ������
			pszName = (PCHAR)(RVAtoOffset(pImport->Name) + (DWORD)m_lpBase);


			cout << "Module Name Is: "
				<< pszName
				<< endl;

			//ѭ��������ַ
			while (pThunk->u1.AddressOfData)
			{
				//�ж�����ŵ��뻹�����Ƶ���
				//���
				if (IMAGE_SNAP_BY_ORDINAL32(pThunk->u1.AddressOfData))
				{
					cout << "Index Import -> ID: "
						<< hex
						<< (pThunk->u1.Ordinal & 0xffff)
						<< endl;
				}
				else//���Ƶ���
				{
					//��ȡ��������
					pName = (PIMAGE_IMPORT_BY_NAME)
						(RVAtoOffset(pThunk->u1.AddressOfData)
							+ (DWORD)m_lpBase);
					cout << "Name Import -> ID: "
						<< hex
						<< pName->Hint
						<< "\tName: "
						<< pName->Name
						<< endl;
				}
				pThunk++;
			}
			cout << endl;
			pImport++;
		}
		bRet = TRUE;
	} while (FALSE);
	return bRet;
}

BOOL PEAnalyseSpace::PEAnalyse::ShowNullAddress()
{
	BOOL bRet = FALSE;
	BOOL bFind = FALSE;
	PIMAGE_SECTION_HEADER pSection = NULL;
	LPBYTE pBegin = NULL;
	DWORD dwIndex = 0;
	DWORD dwSize = 0;
	DWORD dwOffset = 0;
	INT dwMax = 5;
	INT pNullCode[] = { 0x00,0x90,0xcc };
	INT nNull = 0;
	INT nNop = 0;
	INT nInt = 0;

	do 
	{
		//û�н���
		if (m_lpBase == NULL)
		{
			break;
		}

		//��ȡ.text�����
		pSection = IMAGE_FIRST_SECTION(m_pNt);
		while (pSection != NULL)
		{
			if (strncmp((char*)pSection->Name,
				CodeSectionName,
				strlen(CodeSectionName)) == 0)
			{
				bFind = TRUE;
				break;
			}
		}

		//û���ҵ�����
		if (!bFind)
		{
			break;
		}

		//��ȡ������ʼ��ַ
		pBegin = (LPBYTE)((DWORD)m_lpBase + pSection->PointerToRawData);

		//��ȡ�ļ���ƫ�Ƶ�ַ
		dwOffset = pSection->PointerToRawData;

		//��ȡ��ǰ���εĴ�С����һ�����εĿ�ʼ��ַ��ȥ������εĿ�ʼ��ַ
		dwSize = pSection->VirtualAddress;
		dwSize = (++pSection)->VirtualAddress - dwSize;

		//������ַ
		for (; dwIndex < dwSize; dwIndex++)
		{
			//���00�ĵ�ַ
			if (pBegin[dwIndex] == pNullCode[0])
			{
				nNull++;
			}
			else
			{
				if (nNull > dwMax)
				{
					cout << "Null Address Begin : 0x"
						<< hex
						<< dwOffset + dwIndex - nNull
						<< " To End : 0x"
						<< hex
						<< dwOffset + dwIndex
						<< " Len Is : "
						<< dec
						<< nNull
						<< endl;

				}
				nNull = 0;
			}

			if (pBegin[dwIndex] == pNullCode[1])
			{
				nNop++;
			}
			else
			{
				if (nNop > dwMax)
				{
					cout << "Nop Address Begin : 0x"
						<< hex
						<< dwOffset + dwIndex - nNop
						<< " To End : 0x"
						<< hex
						<< dwOffset + dwIndex
						<< " Len Is : "
						<< dec
						<< nNop
						<< endl;
				}
				nNop = 0;
			}

			if (pBegin[dwIndex] == pNullCode[2])
			{
				nInt++;
			}
			else
			{
				if (nInt > dwMax)
				{
					cout << "Int3 Address Begin : 0x"
						<< hex
						<< dwOffset + dwIndex - nInt
						<< " To End : 0x"
						<< hex
						<< dwOffset + dwIndex
						<< " Len Is : "
						<< dec
						<< nInt
						<< endl;
				}
				nInt = 0;
			}
		}

		RVAtoOffset(0);

		bRet = TRUE;
	} while (FALSE);
	return bRet;
}
