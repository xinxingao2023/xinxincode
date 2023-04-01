#pragma once
#include <windows.h>
struct  StubConf
{
	DWORD dwOep;
	DWORD ImportRVA;//原始导入表地址
	DWORD RelocationRVA;//原始重定位表的地址
	DWORD TLStableRVA;//TLS表
	DWORD CallBack;//回调函数
};
//获取DOS头
PIMAGE_DOS_HEADER GetDosHeader(LPVOID pBase)
{
	return (PIMAGE_DOS_HEADER)pBase;
}
//获取NT头
PIMAGE_NT_HEADERS GetNtHeader(LPVOID pBase)
{
	return (PIMAGE_NT_HEADERS)
		(GetDosHeader(pBase)->e_lfanew + (DWORD)pBase);
}

//获取标准PE头
PIMAGE_FILE_HEADER GetPeHeader(LPVOID pBase)
{
	return (PIMAGE_FILE_HEADER)((DWORD)GetNtHeader(pBase) + 4);
}

//获取可选
PIMAGE_OPTIONAL_HEADER GetOptHeader(LPVOID pBase)
{
	return (PIMAGE_OPTIONAL_HEADER)((DWORD)GetPeHeader(pBase) + IMAGE_SIZEOF_FILE_HEADER);
}

//获取区段头
PIMAGE_SECTION_HEADER GetSectionHeader(LPVOID pBase)
{
	return (PIMAGE_SECTION_HEADER)((DWORD)GetOptHeader(pBase) + GetPeHeader(pBase)->SizeOfOptionalHeader);
}

//获取节的地址
PIMAGE_SECTION_HEADER  GetSectionAddress(LPVOID pBase, const char* Name){
	PIMAGE_SECTION_HEADER  TmpSection = GetSectionHeader(pBase);
	for (int a = 1; a <= GetPeHeader(pBase)->NumberOfSections; a++) {

		if (!memcmp(TmpSection->Name, Name, 6)) {
			return TmpSection;
		}
		TmpSection++;
	}
	return 0;
}