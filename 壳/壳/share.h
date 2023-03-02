#pragma once
#include <windows.h>
struct  StubConf
{
	DWORD dwOep;
	DWORD ImportRVA;//ԭʼ������ַ
	DWORD RelocationRVA;//ԭʼ�ض�λ��ĵ�ַ
	DWORD TLStableRVA;//TLS��
	DWORD CallBack;//�ص�����
};
//��ȡDOSͷ
PIMAGE_DOS_HEADER GetDosHeader(LPVOID pBase)
{
	return (PIMAGE_DOS_HEADER)pBase;
}
//��ȡNTͷ
PIMAGE_NT_HEADERS GetNtHeader(LPVOID pBase)
{
	return (PIMAGE_NT_HEADERS)
		(GetDosHeader(pBase)->e_lfanew + (DWORD)pBase);
}

//��ȡ��׼PEͷ
PIMAGE_FILE_HEADER GetPeHeader(LPVOID pBase)
{
	return (PIMAGE_FILE_HEADER)((DWORD)GetNtHeader(pBase) + 4);
}

//��ȡ��ѡ
PIMAGE_OPTIONAL_HEADER GetOptHeader(LPVOID pBase)
{
	return (PIMAGE_OPTIONAL_HEADER)((DWORD)GetPeHeader(pBase) + IMAGE_SIZEOF_FILE_HEADER);
}

//��ȡ����ͷ
PIMAGE_SECTION_HEADER GetSectionHeader(LPVOID pBase)
{
	return (PIMAGE_SECTION_HEADER)((DWORD)GetOptHeader(pBase) + GetPeHeader(pBase)->SizeOfOptionalHeader);
}

//��ȡ�ڵĵ�ַ
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