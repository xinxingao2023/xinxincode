#include "pch.h"
#include <Windows.h>
#include "stub.h"
#include <iostream>
#include <winternl.h>
#include "..\��\share.h"
#pragma comment(linker,"/section:.text,RWE")
//�޸�����
#pragma comment(linker,"/merge:.data=.text")
//�ϲ�
#pragma comment(linker,"/merge:.rdata=.text")
//�ϲ�
//
//_declspec(thread)int g_num;
extern "C" __declspec(dllexport) StubConf g_Sc = { 0 };
HMODULE g_hKernel32=0;
HMODULE g_hUser32 = 0;
HMODULE g_hModule = 0;
HMODULE g_Ntdll = 0;
FuGetProcAddress MyGetProcAddress = 0;
FuLoadLibraryExA MyLoadLibraryExA = 0;
FuMessageBoxW MyMessageBoxW = 0;
FuVirtualProtect   MyVirtualProtect = 0;
FuGetModuleHandleW MyGetModuleHandleW = 0;
FuNtQueryInformationProcess MyNtQueryInformationProcess = 0;
FuGetCurrentProcess MyGetCurrentProcess = 0;
bool NQIP_ProcessDebugPort();
//��ȡ��ַ
void GetKernel()
{
	__asm
	{
		mov eax, dword ptr fs :[30h] //ָ��PEB�ṹ
		mov eax, dword ptr[eax + 0Ch]// ָ��LDR Ptr32 _PEB_LDR_DATA
		mov eax, dword ptr[eax + 0Ch]//ָ��InLoadOrderModuleList _LIST_ENTRY
		mov eax, dword ptr[eax]//�ƶ�_LIST_ENTRY
		mov eax, dword ptr[eax]//ָ��Kernel32
		mov eax, dword ptr[eax + 18h]//ָ��DllBase��
		mov g_hKernel32,eax
	}
}
//strcmp(�ҵ�Ϊ1)
int StrCmpText( char* pBuff,const char* pStr)
{
	int nFlag = 1;
	__asm
	{
		mov esi, pStr;
		mov edi, pBuff;
		mov ecx, 0x8;
		cld;
		repe cmpsb;
		je _end;
		mov nFlag, 0;
	_end:

	}
	return nFlag;
}
//memcpy
void MemCpy(void* Dst, void const* Src, size_t Size) {

	_asm {

		push esi
		push edi
		push ecx
		mov         esi, Src
		mov         ecx, 0x8
		mov         edi, Dst
		cld
		rep movs    byte ptr es : [edi] , byte ptr[esi]
		pop ecx
		pop edi
		pop esi

	}

}
//��ȡGetProcAddress������ַ
void MyGetFunAddress()
{
	__asm
	{
		pushad
		mov ebp, esp
		sub esp, 0xc
		mov edx, g_hKernel32
		mov esi, [edx + 0x3c]     //NTͷ��RVA
		lea esi, [esi + edx]    //NTͷ��VA
		mov esi, [esi + 0x78]    //Export��Rva		
		lea edi, [esi + edx]      //Export��Va

		mov esi, [edi + 0x1c]     //����������ַ��Rva
		lea esi, [esi + edx]      //��Va
		mov[ebp - 0x4], esi       //�����ַ

		mov esi, [edi + 0x20]     //�����������Ƶ�Rva
		lea esi, [esi + edx]      //Va
		mov[ebp - 0x8], esi       //����

		mov esi, [edi + 0x24]     //��ŵ�Rva
		lea esi, [esi + edx]      //Va
		mov[ebp - 0xc], esi       //����

		xor ecx, ecx
		jmp _First
	_Zero:
		inc ecx;
	_First:
		mov esi, [ebp - 0x8]     //�����������Ƶ�Va
		mov esi, [esi + ecx * 4] //FunName��Rva

		lea esi, [esi + edx]     //FunName��Va
		cmp dword ptr[esi], 050746547h// GetProcAddress��16����47657450 726F6341 64647265 7373;��С�˴洢
		jne _Zero;                     
		cmp dword ptr[esi + 4], 041636f72h
		jne _Zero;
		cmp dword ptr[esi + 8], 065726464h
		jne _Zero;
		cmp word  ptr[esi + 0ch], 07373h
		jne _Zero

		xor ebx, ebx
		mov esi, [ebp - 0xc]     //��ŵ�Va
		mov bx, [esi + ecx * 2]  //�õ����

		mov esi, [ebp - 0x4]    //����������Va
		mov esi, [esi + ebx * 4] //FunAddr��Rva
		lea eax, [esi + edx]     //FunAddr
		mov MyGetProcAddress, eax
		add esp, 0xc
		popad
	}

}
//����
void Decryption()
{	
	/*//��ȡ.text������ͷauto pNt = GetNtHeader((char*)g_hModule);
	DWORD dwSecNum = pNt->FileHeader.NumberOfSections;
	auto pSec = IMAGE_FIRST_SECTION(pNt);
	
	//�ҵ���������
	for (size_t i = 0; i < dwSecNum; i++)
	{
		if (StrCmpText((char*)pSec[i].Name,".text"))
		{
			pSec += i;
			break;
		}
	}

	if (NQIP_ProcessDebugPort()) {
		__asm {
			ret
		}
	}
	//��ȡ������׵�ַ
	char* pTarText = pSec->VirtualAddress + (char*)g_hModule;
	int nSize = pSec->Misc.VirtualSize;
	DWORD old = 0;
	//���ܴ����
	MyVirtualProtect(pTarText, nSize, PAGE_READWRITE, &old);
	for (int i = 0; i < nSize; ++i) {
		pTarText[i] ^= 0x33;
	}
	
	MyVirtualProtect(pTarText, nSize, old, &old);*/
	auto pSectionHeader = GetSectionHeader((char*)g_hModule);
	auto pPeh = GetPeHeader((char*)g_hModule);
	
	for (int a = 0; a < pPeh->NumberOfSections; a++) {
		char name[9] = { 0 };
		MemCpy(name, pSectionHeader->Name, 8);

		char name1[9] = ".tls";
		char name2[9] = ".rsrc";
		char name3[9] = "hhhh";
		BOOL Flag = TRUE;
		
		if ((StrCmpText((char*)name, name1)) || (StrCmpText((char*)name, name2)) || (StrCmpText((char*)name, name3))) {
			Flag = FALSE;
		}
		if (Flag) {
			DWORD TextSection = pSectionHeader->SizeOfRawData;
			
			PBYTE pDate = (PBYTE)(pSectionHeader->VirtualAddress+(DWORD)g_hModule);
		
			DWORD old = 0;
			MyVirtualProtect(pDate, TextSection, PAGE_READWRITE, &old);
			for (int i = 0; i < TextSection; i++) {

				pDate[i] ^= 0x66;

			}
			MyVirtualProtect(pDate, TextSection, old, &old);

		}
		pSectionHeader = pSectionHeader + 1;
	}
}
//������
bool NQIP_ProcessDebugPort()
{
	int nDebugPort = 0;
	MyNtQueryInformationProcess(
		MyGetCurrentProcess (),//Ŀ����̾��
		ProcessDebugPort,   //��ѯ��Ϣ������
		&nDebugPort,        //�����ѯ����Ϣ
		sizeof(nDebugPort), //��ѯ���͵Ĵ�С
		NULL);

	return nDebugPort == 0xFFFFFFFF ? true : false;
}
void Funtion()
{
	MyLoadLibraryExA = (FuLoadLibraryExA)MyGetProcAddress(g_hKernel32, "LoadLibraryExA");
	g_hUser32 = MyLoadLibraryExA("user32.dll", 0, 0);
	MyGetModuleHandleW = (FuGetModuleHandleW)MyGetProcAddress(g_hKernel32,"GetModuleHandleW");
	//���ش��������̵�EXE�ļ��ļ��ص�ַ
	g_hModule=(HMODULE)MyGetModuleHandleW(0);
	MyVirtualProtect = (FuVirtualProtect)MyGetProcAddress(g_hKernel32,"VirtualProtect");
	MyGetCurrentProcess=(FuGetCurrentProcess)MyGetProcAddress(g_hKernel32,"GetCurrentProcess");
	g_Ntdll = MyLoadLibraryExA("Ntdll.dll", 0, 0);
	MyNtQueryInformationProcess = (FuNtQueryInformationProcess)MyGetProcAddress(g_Ntdll,"NtQueryInformationProcess");
	MyMessageBoxW = (FuMessageBoxW)MyGetProcAddress(g_hUser32, "MessageBoxW"); 
	
}
void FixRelocation() {
	
	if (g_Sc.RelocationRVA != 0) {
		
PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)(g_Sc.RelocationRVA+(DWORD)g_hModule);
	DWORD dwRelocOffset = (DWORD)g_hModule-GetOptHeader(g_hModule)->ImageBase;
	for (int a = 1; pRelocation->SizeOfBlock != 0 && pRelocation->VirtualAddress != 0; pRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocation + pRelocation->SizeOfBlock))
	{      //��λ�����ݴ�+0x8
		PWORD ReDate = (PWORD)((DWORD)pRelocation + 8);
		for (int i = 0; i < (pRelocation->SizeOfBlock - 8) / 2; i++, ReDate++)
		{
			
			//ǰ��λ������
			DWORD AddressAttribute = (*ReDate) >> 12;
			//printf("���ԣ�%x    ", AddressAttribute);
			if (AddressAttribute != 3) {
				continue;
			}
			DWORD RelocationAddressRVA = ((*ReDate) & 0xFFF) + pRelocation->VirtualAddress;
			
		
			PDWORD ReDates = (PDWORD)(RelocationAddressRVA + (DWORD)g_hModule);
			
			DWORD dwOld;
			MyVirtualProtect(ReDates, 4, PAGE_READWRITE, &dwOld);
			(*ReDates) += dwRelocOffset;
			MyVirtualProtect(ReDates, 4, dwOld, &dwOld);

		}

	}
	}
	
}
void ResumeImport()
{
	if (g_Sc.ImportRVA != 0) {
	PIMAGE_IMPORT_DESCRIPTOR pIID =(PIMAGE_IMPORT_DESCRIPTOR) (g_Sc.ImportRVA +(DWORD)(g_hModule));
for (; pIID->FirstThunk != NULL; pIID++)
{
	//ֱ�Ӷ�λFirstThunk����
	PIMAGE_THUNK_DATA pITD = (PIMAGE_THUNK_DATA)((DWORD)g_hModule + pIID->FirstThunk);
	//����LoadLibrary����DLL
	HINSTANCE hInstance = MyLoadLibraryExA((LPSTR)((DWORD)g_hModule + pIID->Name),0,0);

	for (; pITD->u1.Ordinal != 0; pITD++)
	{
		FARPROC fpFun;
		if (pITD->u1.Ordinal & 0x80000000)
		{
			///����������ŵķ�ʽ�����
			fpFun = MyGetProcAddress(hInstance, (LPCSTR)(pITD->u1.Ordinal & 0x0000ffff));
		}
		else
		{ //�����������Ʒ�ʽ�����
			PIMAGE_IMPORT_BY_NAME pIIBN = (PIMAGE_IMPORT_BY_NAME)(pITD->u1.Ordinal+(DWORD)g_hModule);
			fpFun = MyGetProcAddress(hInstance, (LPCSTR)pIIBN->Name);
		}

		if (fpFun == NULL)
		{
			return;
		}
		DWORD old = 0;
		MyVirtualProtect((LPVOID)pITD,sizeof(FARPROC), PAGE_READWRITE, &old);
		pITD->u1.Ordinal = (long)fpFun;
		MyVirtualProtect((LPVOID)pITD, sizeof(FARPROC), old, &old);

	}
}
PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)GetOptHeader((char*)g_hModule)->DataDirectory;
DWORD ImportRVA = (DWORD)pDataDirectory + 0x8;
DWORD old = 0;
MyVirtualProtect((LPVOID)ImportRVA, sizeof(DWORD), PAGE_READWRITE, &old);
GetOptHeader((char*)g_hModule)->DataDirectory[1].VirtualAddress = g_Sc.ImportRVA;

MyVirtualProtect((LPVOID)ImportRVA, sizeof(DWORD), old, &old);
	}

}
//�ر������ַ��
void relocation() {
	if (g_Sc.RelocationRVA != 0) {
		PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)GetOptHeader((char*)g_hModule)->DataDirectory;
		DWORD RelpcationRVA = (DWORD)pDataDirectory + 0x32;
		DWORD old = 0;
		MyVirtualProtect((LPVOID)RelpcationRVA, sizeof(DWORD), PAGE_READWRITE, &old);
		GetOptHeader((char*)g_hModule)->DataDirectory[5].VirtualAddress = g_Sc.RelocationRVA;
		MyVirtualProtect((LPVOID)RelpcationRVA, sizeof(DWORD), old, &old);
	}
}
void tlstable() {

	//�������TLS��
	if (g_Sc.TLStableRVA)
	{
		DWORD OldProtect = 0;
		MyVirtualProtect(&(GetOptHeader(g_hModule)->DataDirectory[9].VirtualAddress), 0x4, PAGE_EXECUTE_READWRITE, &OldProtect);
		//�ָ�Tls����
		GetOptHeader(g_hModule)->DataDirectory[9].VirtualAddress = g_Sc.TLStableRVA;
		MyVirtualProtect(&(GetOptHeader(g_hModule)->DataDirectory[9].VirtualAddress), 0x4, OldProtect, &OldProtect);
		auto TlsTable = (PIMAGE_TLS_DIRECTORY)(g_Sc.TLStableRVA + g_hModule);

		//�ֶ�����TLS�ص�����(ȥ�������ַҪ��-�ɵ�ImageBase+��)
		auto CallBackTable = (PIMAGE_TLS_CALLBACK*)(g_Sc.CallBack-GetOptHeader((char *)g_hModule)->ImageBase+g_hModule);
		while (*CallBackTable)
		{
			MyMessageBoxW(0, 0, 0, 0);
			(*CallBackTable)((PVOID)g_hModule, DLL_PROCESS_ATTACH, NULL);
			CallBackTable++;
		}
	}


}

extern "C" __declspec(dllexport) void Start();
__declspec(naked)  void Start()
{
	
	GetKernel();
	MyGetFunAddress();
	Funtion();
	Decryption();
	ResumeImport();
	FixRelocation();
	tlstable();
	MyMessageBoxW(0, L"��", L"��", 0);
		g_Sc.dwOep += (DWORD)g_hModule;
		__asm {
			jmp g_Sc.dwOep;
		}
}
