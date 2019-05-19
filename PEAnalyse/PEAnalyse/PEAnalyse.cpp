#include "PEAnalyse.h"
using namespace PEAnalyseSpace;
#pragma warning(disable:4996)

PEAnalyse::PEAnalyse()
{
	m_hFile = INVALID_HANDLE_VALUE;
	m_hMap = NULL;
	m_lpBase = nullptr;
	m_pDos = nullptr;
	m_pNt = nullptr;
}


PEAnalyse::~PEAnalyse()
{
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
	//����ָ��
	PIMAGE_SECTION_HEADER pSections = NULL;
	DWORD dwIndex = 0;

	//û�н���
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

BOOL PEAnalyseSpace::PEAnalyse::LoadFile(PWCHAR wsFilePath)
{
	BOOL bRet = FALSE;

	//���ļ�·��
	PWCHAR wsNewFilePath = NULL;

	do 
	{
		//�ļ�·������Ϊ��
		if (wsFilePath == NULL || wcslen(wsFilePath) == NULL)
		{
			break;
		}

		//�жϺ�׺���ǲ���exe
		if (!CheckFileType(wsFilePath))
		{
			break;
		}

		//�����ڴ�ռ���µ��ļ�·��
		wsNewFilePath = (PWCHAR)VirtualAlloc(NULL, 
			wcslen(wsFilePath) * 2, MEM_COMMIT, PAGE_READWRITE);
		if (wsNewFilePath == NULL)
		{
			break;
		}

		//��մ�С
		ZeroMemory(wsNewFilePath, wcslen(wsFilePath) * 2);

		//����һ�����ļ��������ļ�������в���
		CreateNewFile(wsFilePath, wsNewFilePath);

		//����ϴδ����ļ��Ļ����Ǿ�Ҫ�ȹر�
		if (m_hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(m_hFile);
			m_hFile = INVALID_HANDLE_VALUE;
		}

		//���ļ�
		m_hFile = CreateFileW(wsNewFilePath, GENERIC_READ | GENERIC_WRITE,
			NULL, NULL, OPEN_EXISTING, NULL, NULL);

		//�����ʧ�ܵĻ�
		if (m_hFile == INVALID_HANDLE_VALUE)
		{
			break;
		}

		//�ϴε��ļ�mapû�صĻ������ͷ�
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
	if (wsNewFilePath != NULL)
	{
		VirtualFree(wsNewFilePath, NULL, MEM_RELEASE);
	}
	return bRet;
}

BOOL PEAnalyseSpace::PEAnalyse::CreateNewFile(PWCHAR pwsFilePath, PWCHAR pwsNewFilePath)
{
	BOOL bRet = FALSE;

	do 
	{
		//�ַ�������
		wcsncpy(pwsNewFilePath, pwsFilePath, wcslen(pwsFilePath));

		//ȥ����׺��
		PathRemoveExtensionW(pwsNewFilePath);

		//������׺��
		wcscat(pwsNewFilePath, L"_New.exe");

		//�ļ�����
		if (!CopyFileW(pwsFilePath, pwsNewFilePath, FALSE))
		{
			break;
		}

		bRet = TRUE;
	} while (FALSE);
	return bRet;
}

DWORD PEAnalyseSpace::PEAnalyse::Alignment(DWORD dwSize, 
	DWORD dwAligment)
{
	DWORD dwRet = dwSize;
	DWORD dwBit = NULL;
	if (dwSize%dwAligment)
	{
		dwBit++;
	}
	dwRet = (dwSize / dwAligment + dwBit)*dwAligment;
	return dwRet;
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

BOOL PEAnalyseSpace::PEAnalyse::AddSection(PWCHAR szSectionName,
	DWORD dwSize, 
	DWORD dwCharater)
{
	BOOL bRet = FALSE;

	//��ʼ������ָ������һ������ָ��
	PIMAGE_SECTION_HEADER pBeginSection = NULL;
	PIMAGE_SECTION_HEADER pEndSection = NULL;

	//������ָ��
	PIMAGE_SECTION_HEADER pNewSection = NULL;

	//��������
	CHAR szName[8] = { 0 };

	//��������ָ��
	LPBYTE pBuffer = NULL;

	//д������
	DWORD dwByte = NULL;

	//�ļ�ƫ�����ڴ�ƫ��
	DWORD dwFileAlignment = NULL;
	DWORD dwSectionAlignment = NULL;

	//�����ε�����
	DWORD dwVirtualAddress = NULL;
	DWORD dwPointToRawData = NULL;
	DWORD dwVirtualSize = NULL;
	DWORD dwSizeOfRawData = NULL;

	do 
	{
		//û�н���
		if (!m_lpBase)
		{
			break;
		}

		//��ȡ��һ������ָ��
		pBeginSection = IMAGE_FIRST_SECTION(m_pNt);
		pEndSection = pBeginSection;

		//��ȡ���һ������ָ��
		while (pEndSection->VirtualAddress != NULL)
		{
			pEndSection++;
		}

		//������ָ��
		pNewSection = pEndSection;

		//���һ������ָ��
		pEndSection--;

		//�ļ�ƫ�����ڴ�ƫ��
		dwFileAlignment = m_pNt->OptionalHeader.FileAlignment;
		dwSectionAlignment = m_pNt->OptionalHeader.SectionAlignment;

		//�����ε��ļ�ƫ��
		dwPointToRawData = pEndSection->SizeOfRawData +
			pEndSection->PointerToRawData;

		//�����ε�RVA�Ĵ�С
		dwVirtualSize = Alignment(dwSize, dwSectionAlignment);

		//�����ε�RVA�Ŀ�ʼλ��
		if (pEndSection->Misc.VirtualSize%dwSectionAlignment)
		{
			dwVirtualAddress = (pEndSection->Misc.VirtualSize / dwSectionAlignment + 1)*dwSectionAlignment + pEndSection->VirtualAddress;
		}
		else
		{
			dwVirtualAddress = (pEndSection->Misc.VirtualSize / dwSectionAlignment)*dwSectionAlignment + pEndSection->VirtualAddress;
		}

		//�����ε��ļ���С
		dwSizeOfRawData = Alignment(dwSize, dwFileAlignment);

		//ת����������
		WideCharToMultiByte(CP_ACP, NULL, szSectionName, -1, szName, 7, NULL, FALSE);

		//�����½���������
		CopyMemory(pNewSection->Name, szName, 7);
		pNewSection->Misc.VirtualSize = dwVirtualSize;
		pNewSection->VirtualAddress = dwVirtualAddress;
		pNewSection->SizeOfRawData = dwSizeOfRawData;
		pNewSection->PointerToRawData = dwPointToRawData;
		pNewSection->Characteristics = dwCharater;

		//�޸Ľ�������
		m_pNt->FileHeader.NumberOfSections++;

		//�޸�ӳ���С
		m_pNt->OptionalHeader.SizeOfImage += dwVirtualSize;

		//�ѳ������ڵ�ַ�޸�Ϊ���ǵ����ο�ʼ
		m_pNt->OptionalHeader.AddressOfEntryPoint = dwVirtualAddress;

		//����½���������
		pBuffer = (LPBYTE)VirtualAlloc(NULL,
			dwSizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
		if (!pBuffer)
		{
			break;
		}
		ZeroMemory(pBuffer, dwSizeOfRawData);

		//�ƶ��ļ�ָ��
		SetFilePointer(m_hFile, 0, 0, FILE_END);

		//д������
		WriteFile(m_hFile, pBuffer, dwSizeOfRawData, &dwByte, NULL);
		if (!dwByte)
		{
			break;
		}

		char shellcode[] = "\x55\x8B\xEC\x81\xEC\xC0\x00\x00\x00\x53\x56\x57\xFC\x68\x6A\x0A\x38\x1E\x68\x63\x89\xD1\x4F\x68\x32\x74\x91\x0C\x8B\xF4\x8D\x7E\xF4\x33\xDB\xB7\x04\x2B\xE3\x66\xBB\x33\x32\x53\x68\x75\x73\x65\x72\x54\x33\xD2\x64\x8B\x1D\x30\x00\x00\x00\x8B\x5B\x0C\x8B\x5B\x0C\x8B\x1B\x8B\x1B\x8B\x5B\x18\x8B\xEB\xAD\x3D\x6A\x0A\x38\x1E\x75\x05\x95\xFF\x57\xF8\x95\x60\x8B\x45\x3C\x8B\x4C\x05\x78\x03\xCD\x8B\x59\x20\x03\xDD\x33\xFF\x47\x8B\x34\xBB\x03\xF5\x99\x0F\xBE\x06\x3A\xC4\x74\x08\xC1\xCA\x07\x03\xD0\x46\xEB\xF1\x3B\x54\x24\x1C\x75\xE4\x8B\x59\x24\x03\xDD\x66\x8B\x3C\x7B\x8B\x59\x1C\x03\xDD\x03\x2C\xBB\x95\x5F\xAB\x57\x61\x3D\x6A\x0A\x38\x1E\x75\xA9\x33\xDB\x53\x68\x46\x59\x48\x00\x8B\xC4\x53\x50\x50\x53\xFF\x57\xFC\x53\xFF\x57\xF8\x5F\x5E\x5B\x81\xC4\xC0\x00\x00\x00\x8B\xE5\x5D\xC3";

		//�ƶ��ļ��������ο�ʼ��ַ
		SetFilePointer(m_hFile, -((int)(dwSizeOfRawData)), 0, FILE_CURRENT);

		//д�����
		WriteFile(m_hFile, shellcode, sizeof(shellcode), &dwByte, NULL);
		if (!dwByte)
		{
			break;
		}

		//�ļ�ˢ��
		FlushViewOfFile(m_hFile, NULL);

		bRet = TRUE;
	} while (FALSE);
	if (pBuffer)
	{
		VirtualFree(pBuffer, NULL, MEM_RELEASE);
	}
	return bRet;
}

BOOL PEAnalyseSpace::PEAnalyse::InsertShellcode(DWORD dwOffsetAddress, 
	DWORD dwVirtualAddress,
	PWCHAR pwsOpcodeFilePath)
{
	BOOL bRet = FALSE;

	//��תָ��
	CHAR szJmp[] = "\xb8\x90\x90\x90\x90\xff\xe0\x00";

	//ԭ��oep
	DWORD dwOep = 0;

	//opcode�ļ����
	HANDLE hOpcodeFile = INVALID_HANDLE_VALUE;

	//opcode������
	LPBYTE pBuffer = NULL;
	LPBYTE pNewBuffer = NULL;
	LPBYTE pWrite = NULL;

	//�ļ���С
	DWORD dwSize = 0;
	DWORD dwNewSize = 0;

	//д����ֽ���
	DWORD dwByte = 0;

	//����
	DWORD dwIndex = 0;

	do 
	{
		//û�н���
		if (m_lpBase == NULL)
		{
			break;
		}

		//opcode�ļ����Ƿ���Ч
		if (pwsOpcodeFilePath == NULL || wcslen(pwsOpcodeFilePath) == NULL)
		{
			break;
		}

		//���ļ�
		hOpcodeFile = CreateFileW(pwsOpcodeFilePath,
			GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, NULL, NULL);
		if (hOpcodeFile == INVALID_HANDLE_VALUE)
		{
			break;
		}

		//��ȡ�ļ��Ĵ�С
		dwSize = GetFileSize(hOpcodeFile, NULL);
		if (dwSize == NULL)
		{
			break;
		}

		//����ռ�
		pBuffer = (LPBYTE)VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
		pNewBuffer = (LPBYTE)VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
		if (pBuffer == NULL || pNewBuffer == NULL)
		{
			break;
		}

		//��ȡ����
		ReadFile(hOpcodeFile, pBuffer, dwSize, &dwByte, NULL);
		if (dwByte == NULL)
		{
			break;
		}

		//��opcode�淶��
		for (dwIndex = 0; dwIndex < dwSize; dwIndex++)
		{
			if (pBuffer[dwIndex] != ' ')
			{
				pNewBuffer[dwNewSize++] = pBuffer[dwIndex];
			}
		}

		//_asm
		//{
		//	sub esp,dwNewSize
		//	push pNewBuffer
		//	lea pWrite,esp-0x4
		//}

		//���ļ�ָ���ƶ���ָ��λ��
		SetFilePointer(m_hFile, dwOffsetAddress, 0, FILE_BEGIN);

		//д��shellcode
		WriteFile(m_hFile, pNewBuffer, dwNewSize, &dwByte, NULL);
		if (dwByte == NULL)
		{
			break;
		}

		_asm
		{

		}

		//��ȡԭ����oep
		dwOep = m_pNt->OptionalHeader.ImageBase +
			m_pNt->OptionalHeader.AddressOfEntryPoint;

		//������ת��ԭoep��ָ��
		*(DWORD*)&szJmp[1] = dwOep;

		//��shellcode����д��
		WriteFile(m_hFile, szJmp, strlen(szJmp), &dwByte, NULL);
		if (dwByte == NULL)
		{
			break;
		}

		////�޸�ԭ����oepΪ�µ�oep
		//m_pNt->OptionalHeader.AddressOfEntryPoint =
		//	dwVirtualAddress - (DWORD)(BYTE*)m_lpBase;

		//ˢ�µ��ļ�
		FlushFileBuffers(m_hFile);

		bRet = TRUE;
	} while (FALSE);
	if (hOpcodeFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hOpcodeFile);
	}
	if (pBuffer != NULL)
	{
		VirtualFree(m_lpBase, NULL, MEM_RELEASE);
	}
	if (pNewBuffer != NULL)
	{
		VirtualFree(pNewBuffer, NULL, MEM_RELEASE);
	}
	return bRet;
}
