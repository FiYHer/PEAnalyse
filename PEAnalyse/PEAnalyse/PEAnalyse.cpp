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
	//节区指针
	PIMAGE_SECTION_HEADER pSections = NULL;
	DWORD dwIndex = 0;

	//没有解析
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

BOOL PEAnalyseSpace::PEAnalyse::LoadFile(PWCHAR wsFilePath)
{
	BOOL bRet = FALSE;

	//新文件路径
	PWCHAR wsNewFilePath = NULL;

	do 
	{
		//文件路径不能为空
		if (wsFilePath == NULL || wcslen(wsFilePath) == NULL)
		{
			break;
		}

		//判断后缀名是不是exe
		if (!CheckFileType(wsFilePath))
		{
			break;
		}

		//申请内存空间放新的文件路径
		wsNewFilePath = (PWCHAR)VirtualAlloc(NULL, 
			wcslen(wsFilePath) * 2, MEM_COMMIT, PAGE_READWRITE);
		if (wsNewFilePath == NULL)
		{
			break;
		}

		//清空大小
		ZeroMemory(wsNewFilePath, wcslen(wsFilePath) * 2);

		//创建一个新文件，在新文件上面进行操作
		CreateNewFile(wsFilePath, wsNewFilePath);

		//如果上次打开了文件的话，那就要先关闭
		if (m_hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(m_hFile);
			m_hFile = INVALID_HANDLE_VALUE;
		}

		//打开文件
		m_hFile = CreateFileW(wsNewFilePath, GENERIC_READ | GENERIC_WRITE,
			NULL, NULL, OPEN_EXISTING, NULL, NULL);

		//如果打开失败的话
		if (m_hFile == INVALID_HANDLE_VALUE)
		{
			break;
		}

		//上次的文件map没关的话，先释放
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
		//字符串复制
		wcsncpy(pwsNewFilePath, pwsFilePath, wcslen(pwsFilePath));

		//去除后缀名
		PathRemoveExtensionW(pwsNewFilePath);

		//构建后缀名
		wcscat(pwsNewFilePath, L"_New.exe");

		//文件复制
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

BOOL PEAnalyseSpace::PEAnalyse::AddSection(PWCHAR szSectionName,
	DWORD dwSize, 
	DWORD dwCharater)
{
	BOOL bRet = FALSE;

	//开始的区段指针和最后一个区段指针
	PIMAGE_SECTION_HEADER pBeginSection = NULL;
	PIMAGE_SECTION_HEADER pEndSection = NULL;

	//新区段指针
	PIMAGE_SECTION_HEADER pNewSection = NULL;

	//节区名字
	CHAR szName[8] = { 0 };

	//节区数据指针
	LPBYTE pBuffer = NULL;

	//写入数量
	DWORD dwByte = NULL;

	//文件偏移与内存偏移
	DWORD dwFileAlignment = NULL;
	DWORD dwSectionAlignment = NULL;

	//新区段的数据
	DWORD dwVirtualAddress = NULL;
	DWORD dwPointToRawData = NULL;
	DWORD dwVirtualSize = NULL;
	DWORD dwSizeOfRawData = NULL;

	do 
	{
		//没有解析
		if (!m_lpBase)
		{
			break;
		}

		//获取第一个区段指针
		pBeginSection = IMAGE_FIRST_SECTION(m_pNt);
		pEndSection = pBeginSection;

		//获取最后一个区段指针
		while (pEndSection->VirtualAddress != NULL)
		{
			pEndSection++;
		}

		//新区段指针
		pNewSection = pEndSection;

		//最后一个区段指针
		pEndSection--;

		//文件偏移与内存偏移
		dwFileAlignment = m_pNt->OptionalHeader.FileAlignment;
		dwSectionAlignment = m_pNt->OptionalHeader.SectionAlignment;

		//新区段的文件偏移
		dwPointToRawData = pEndSection->SizeOfRawData +
			pEndSection->PointerToRawData;

		//新区段的RVA的大小
		dwVirtualSize = Alignment(dwSize, dwSectionAlignment);

		//新区段的RVA的开始位置
		if (pEndSection->Misc.VirtualSize%dwSectionAlignment)
		{
			dwVirtualAddress = (pEndSection->Misc.VirtualSize / dwSectionAlignment + 1)*dwSectionAlignment + pEndSection->VirtualAddress;
		}
		else
		{
			dwVirtualAddress = (pEndSection->Misc.VirtualSize / dwSectionAlignment)*dwSectionAlignment + pEndSection->VirtualAddress;
		}

		//新区段的文件大小
		dwSizeOfRawData = Alignment(dwSize, dwFileAlignment);

		//转化节区名字
		WideCharToMultiByte(CP_ACP, NULL, szSectionName, -1, szName, 7, NULL, FALSE);

		//保存新节区的名字
		CopyMemory(pNewSection->Name, szName, 7);
		pNewSection->Misc.VirtualSize = dwVirtualSize;
		pNewSection->VirtualAddress = dwVirtualAddress;
		pNewSection->SizeOfRawData = dwSizeOfRawData;
		pNewSection->PointerToRawData = dwPointToRawData;
		pNewSection->Characteristics = dwCharater;

		//修改节区数量
		m_pNt->FileHeader.NumberOfSections++;

		//修改映像大小
		m_pNt->OptionalHeader.SizeOfImage += dwVirtualSize;

		//把程序的入口地址修改为我们的区段开始
		m_pNt->OptionalHeader.AddressOfEntryPoint = dwVirtualAddress;

		//添加新节区的数据
		pBuffer = (LPBYTE)VirtualAlloc(NULL,
			dwSizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
		if (!pBuffer)
		{
			break;
		}
		ZeroMemory(pBuffer, dwSizeOfRawData);

		//移动文件指针
		SetFilePointer(m_hFile, 0, 0, FILE_END);

		//写入数据
		WriteFile(m_hFile, pBuffer, dwSizeOfRawData, &dwByte, NULL);
		if (!dwByte)
		{
			break;
		}

		char shellcode[] = "\x55\x8B\xEC\x81\xEC\xC0\x00\x00\x00\x53\x56\x57\xFC\x68\x6A\x0A\x38\x1E\x68\x63\x89\xD1\x4F\x68\x32\x74\x91\x0C\x8B\xF4\x8D\x7E\xF4\x33\xDB\xB7\x04\x2B\xE3\x66\xBB\x33\x32\x53\x68\x75\x73\x65\x72\x54\x33\xD2\x64\x8B\x1D\x30\x00\x00\x00\x8B\x5B\x0C\x8B\x5B\x0C\x8B\x1B\x8B\x1B\x8B\x5B\x18\x8B\xEB\xAD\x3D\x6A\x0A\x38\x1E\x75\x05\x95\xFF\x57\xF8\x95\x60\x8B\x45\x3C\x8B\x4C\x05\x78\x03\xCD\x8B\x59\x20\x03\xDD\x33\xFF\x47\x8B\x34\xBB\x03\xF5\x99\x0F\xBE\x06\x3A\xC4\x74\x08\xC1\xCA\x07\x03\xD0\x46\xEB\xF1\x3B\x54\x24\x1C\x75\xE4\x8B\x59\x24\x03\xDD\x66\x8B\x3C\x7B\x8B\x59\x1C\x03\xDD\x03\x2C\xBB\x95\x5F\xAB\x57\x61\x3D\x6A\x0A\x38\x1E\x75\xA9\x33\xDB\x53\x68\x46\x59\x48\x00\x8B\xC4\x53\x50\x50\x53\xFF\x57\xFC\x53\xFF\x57\xF8\x5F\x5E\x5B\x81\xC4\xC0\x00\x00\x00\x8B\xE5\x5D\xC3";

		//移动文件到新区段开始地址
		SetFilePointer(m_hFile, -((int)(dwSizeOfRawData)), 0, FILE_CURRENT);

		//写入代码
		WriteFile(m_hFile, shellcode, sizeof(shellcode), &dwByte, NULL);
		if (!dwByte)
		{
			break;
		}

		//文件刷新
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

	//跳转指令
	CHAR szJmp[] = "\xb8\x90\x90\x90\x90\xff\xe0\x00";

	//原来oep
	DWORD dwOep = 0;

	//opcode文件句柄
	HANDLE hOpcodeFile = INVALID_HANDLE_VALUE;

	//opcode缓冲区
	LPBYTE pBuffer = NULL;
	LPBYTE pNewBuffer = NULL;
	LPBYTE pWrite = NULL;

	//文件大小
	DWORD dwSize = 0;
	DWORD dwNewSize = 0;

	//写入的字节数
	DWORD dwByte = 0;

	//索引
	DWORD dwIndex = 0;

	do 
	{
		//没有解析
		if (m_lpBase == NULL)
		{
			break;
		}

		//opcode文件名是否有效
		if (pwsOpcodeFilePath == NULL || wcslen(pwsOpcodeFilePath) == NULL)
		{
			break;
		}

		//打开文件
		hOpcodeFile = CreateFileW(pwsOpcodeFilePath,
			GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, NULL, NULL);
		if (hOpcodeFile == INVALID_HANDLE_VALUE)
		{
			break;
		}

		//获取文件的大小
		dwSize = GetFileSize(hOpcodeFile, NULL);
		if (dwSize == NULL)
		{
			break;
		}

		//申请空间
		pBuffer = (LPBYTE)VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
		pNewBuffer = (LPBYTE)VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
		if (pBuffer == NULL || pNewBuffer == NULL)
		{
			break;
		}

		//读取数据
		ReadFile(hOpcodeFile, pBuffer, dwSize, &dwByte, NULL);
		if (dwByte == NULL)
		{
			break;
		}

		//将opcode规范化
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

		//将文件指针移动到指定位置
		SetFilePointer(m_hFile, dwOffsetAddress, 0, FILE_BEGIN);

		//写入shellcode
		WriteFile(m_hFile, pNewBuffer, dwNewSize, &dwByte, NULL);
		if (dwByte == NULL)
		{
			break;
		}

		_asm
		{

		}

		//获取原来的oep
		dwOep = m_pNt->OptionalHeader.ImageBase +
			m_pNt->OptionalHeader.AddressOfEntryPoint;

		//构造跳转到原oep的指令
		*(DWORD*)&szJmp[1] = dwOep;

		//在shellcode后面写入
		WriteFile(m_hFile, szJmp, strlen(szJmp), &dwByte, NULL);
		if (dwByte == NULL)
		{
			break;
		}

		////修改原来的oep为新的oep
		//m_pNt->OptionalHeader.AddressOfEntryPoint =
		//	dwVirtualAddress - (DWORD)(BYTE*)m_lpBase;

		//刷新到文件
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
