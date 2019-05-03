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
	//字符串指针不能为空
	if (pszFilePath == nullptr)
	{
		return FALSE;
	}

	//判断后缀名
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

	//获取第一个节区
	pSections = IMAGE_FIRST_SECTION(m_pNt);

	//如果RVA小于第一个节区的话
	if (dwRva < pSections->VirtualAddress)
	{
		return 0;
	}

	//遍历当前rva属于哪一个节区
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
		//文件路径不能为空
		if (szFilePath == NULL)
		{
			break;
		}

		//判断后缀名是不是exe
		if (!CheckFileType(szFilePath))
		{
			break;
		}

		//保存文件路径
		if (wcslen(szFilePath) > 4 * 1024)
		{
			break;
		}

		//没有申请空间的话，申请
		if (m_lpFilePath == NULL)
		{
			m_lpFilePath = (PWCHAR)VirtualAlloc(NULL, 4 * 1024, MEM_COMMIT, PAGE_READWRITE);
			if (m_lpFilePath == NULL)
			{
				break;
			}
		}

		//保存文件路径
		ZeroMemory((LPVOID)m_lpFilePath, 4 * 1024);
		wcsncpy((wchar_t*)m_lpFilePath, szFilePath, wcslen(szFilePath));

		//如果上次打开了文件的话，那就要先关闭
		if (m_hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(m_hFile);
			m_hFile = INVALID_HANDLE_VALUE;
		}
		m_hFile = CreateFileW(szFilePath, GENERIC_READ | GENERIC_WRITE,
			NULL, NULL, OPEN_EXISTING, NULL, NULL);

		//如果打开失败的话
		if (m_hFile == INVALID_HANDLE_VALUE)
		{
			break;
		}

		//获取文件的大小
		m_dwFileSize = GetFileSize(m_hFile, NULL);

		//先释放
		if (m_hMap != NULL)
		{
			CloseHandle(m_hMap);
			m_hMap = NULL;
		}

		//创建文件map
		m_hMap = CreateFileMappingW(m_hFile, NULL, PAGE_READWRITE, NULL, NULL, NULL);
		if (m_hMap == NULL)
		{
			break;
		}

		//原内存映像还存在，就先释放
		if (m_lpBase != NULL)
		{
			UnmapViewOfFile(m_lpBase);
			m_lpBase = NULL;
		}

		//创建文件内存映像
		m_lpBase = MapViewOfFile(m_hMap, FILE_MAP_ALL_ACCESS, NULL, NULL, NULL);
		if (m_lpBase == NULL)
		{
			break;
		}

		//获取dos头和nt头指针
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
		//没有文件名
		if (m_lpFilePath == NULL)
		{
			break;
		}

		//没有解析文件
		if (m_lpBase == NULL)
		{
			break;
		}

		//申请内存，放文件路径
		pszFilePath = (PWCHAR)VirtualAlloc(nullptr, 4 * 1024, MEM_COMMIT, PAGE_READWRITE);
		if (pszFilePath == nullptr)
		{
			break;
		}
		ZeroMemory((LPVOID)pszFilePath, 4 * 1024);
		wcsncpy((wchar_t*)pszFilePath, m_lpFilePath, wcslen(m_lpFilePath));

		//去除后缀名
		PathRemoveExtensionW(pszFilePath);
		//构建后缀名
		wcscat(pszFilePath, L"_New.exe");

		//创建文件
		hFile = CreateFileW(pszFilePath, GENERIC_ALL, NULL, NULL, CREATE_ALWAYS, NULL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			break;
		}

		//写入文件名
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
	BOOL bRet = FALSE;//是否执行成功
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;//导出表指针
	PDWORD pNames = NULL;//名称表指针
	PWORD pOrders = NULL;//序号表指针
	PDWORD pFuncs = NULL;//地址表指针
	PCHAR pszName = NULL;//指向函数名字
	DWORD dwIndex = 0;//索引
	DWORD dwNum = 0;//导出函数的数量
	do 
	{
		//没有解析
		if (m_lpBase == NULL)
		{
			break;
		}

		//导出表为空
		if (m_pNt->OptionalHeader.DataDirectory->Size == NULL)
		{
			break;
		}

		//获取导出表
		pExport = (PIMAGE_EXPORT_DIRECTORY)
			(RVAtoOffset(m_pNt->OptionalHeader.DataDirectory->VirtualAddress)
				+(DWORD)m_lpBase);
		
		//获取导出函数的数量
		dwNum = pExport->NumberOfFunctions;

		//导出函数
		pNames = (PDWORD)((PCHAR)RVAtoOffset(pExport->AddressOfNames) + (DWORD)m_lpBase);

		//导出序号
		pOrders = (PWORD)(RVAtoOffset(pExport->AddressOfNameOrdinals) + (DWORD)m_lpBase);

		//导出地址
		pFuncs = (PDWORD)(RVAtoOffset(pExport->AddressOfFunctions) + (DWORD)m_lpBase);

		//输出导出模块的名称
		cout << "Module Name Is: "
			<< (PCHAR)(RVAtoOffset(pExport->Name) + (DWORD)m_lpBase)
			<< endl;

		for (; dwIndex < dwNum; dwIndex++)
		{
			//获取函数名
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
	//执行是否成功
	BOOL bRet = FALSE;

	//导入表指针
	PIMAGE_IMPORT_DESCRIPTOR pImport = NULL;

	//指针
	PIMAGE_THUNK_DATA pThunk = NULL;

	//导入名称表指针
	PIMAGE_IMPORT_BY_NAME pName = NULL;

	//字符串指针
	PCHAR pszName = NULL;

	do 
	{
		//没有解析
		if (m_lpBase == NULL)
		{
			break;
		}

		//没有导入导入表,这个是不可能的
		if (m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == NULL)
		{
			break;
		}

		//获取导入表
		pImport = (PIMAGE_IMPORT_DESCRIPTOR)
			(RVAtoOffset(m_pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
				+ (DWORD)m_lpBase);

		//循环遍历
		while (pImport->Name)
		{
			//获取导入地址表
			pThunk = (PIMAGE_THUNK_DATA)
				(RVAtoOffset(pImport->OriginalFirstThunk) + (DWORD)m_lpBase);

			//获取模块名字
			pszName = (PCHAR)(RVAtoOffset(pImport->Name) + (DWORD)m_lpBase);


			cout << "Module Name Is: "
				<< pszName
				<< endl;

			//循环遍历地址
			while (pThunk->u1.AddressOfData)
			{
				//判断是序号导入还是名称导入
				//序号
				if (IMAGE_SNAP_BY_ORDINAL32(pThunk->u1.AddressOfData))
				{
					cout << "Index Import -> ID: "
						<< hex
						<< (pThunk->u1.Ordinal & 0xffff)
						<< endl;
				}
				else//名称导入
				{
					//获取导入名称
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
		//没有解析
		if (m_lpBase == NULL)
		{
			break;
		}

		//获取.text代码段
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

		//没有找到区段
		if (!bFind)
		{
			break;
		}

		//获取开区段始地址
		pBegin = (LPBYTE)((DWORD)m_lpBase + pSection->PointerToRawData);

		//获取文件基偏移地址
		dwOffset = pSection->PointerToRawData;

		//获取当前区段的大小，下一个区段的开始地址减去这个区段的开始地址
		dwSize = pSection->VirtualAddress;
		dwSize = (++pSection)->VirtualAddress - dwSize;

		//搜索地址
		for (; dwIndex < dwSize; dwIndex++)
		{
			//输出00的地址
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
