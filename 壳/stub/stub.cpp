#include "pch.h"
#include <Windows.h>
#include "stub.h"
#include <iostream>
#include <winternl.h>
#include "..\壳\share.h"
#pragma comment(linker,"/section:.text,RWE")
//修改属性
#pragma comment(linker,"/merge:.data=.text")
//合并
#pragma comment(linker,"/merge:.rdata=.text")
//合并
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
//获取基址
void GetKernel()
{
	__asm
	{
		mov eax, dword ptr fs :[30h] //指向PEB结构
		mov eax, dword ptr[eax + 0Ch]// 指向LDR Ptr32 _PEB_LDR_DATA
		mov eax, dword ptr[eax + 0Ch]//指向InLoadOrderModuleList _LIST_ENTRY
		mov eax, dword ptr[eax]//移动_LIST_ENTRY
		mov eax, dword ptr[eax]//指向Kernel32
		mov eax, dword ptr[eax + 18h]//指向DllBase基
		mov g_hKernel32,eax
	}
}
//strcmp(找到为1)
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
//获取GetProcAddress函数地址
void MyGetFunAddress()
{
	__asm
	{
		pushad
		mov ebp, esp
		sub esp, 0xc
		mov edx, g_hKernel32
		mov esi, [edx + 0x3c]     //NT头的RVA
		lea esi, [esi + edx]    //NT头的VA
		mov esi, [esi + 0x78]    //Export的Rva		
		lea edi, [esi + edx]      //Export的Va

		mov esi, [edi + 0x1c]     //导出函数地址的Rva
		lea esi, [esi + edx]      //上Va
		mov[ebp - 0x4], esi       //保存地址

		mov esi, [edi + 0x20]     //导出函数名称的Rva
		lea esi, [esi + edx]      //Va
		mov[ebp - 0x8], esi       //保存

		mov esi, [edi + 0x24]     //序号的Rva
		lea esi, [esi + edx]      //Va
		mov[ebp - 0xc], esi       //保存

		xor ecx, ecx
		jmp _First
	_Zero:
		inc ecx;
	_First:
		mov esi, [ebp - 0x8]     //导出函数名称的Va
		mov esi, [esi + ecx * 4] //FunName的Rva

		lea esi, [esi + edx]     //FunName的Va
		cmp dword ptr[esi], 050746547h// GetProcAddress的16进制47657450 726F6341 64647265 7373;（小端存储
		jne _Zero;                     
		cmp dword ptr[esi + 4], 041636f72h
		jne _Zero;
		cmp dword ptr[esi + 8], 065726464h
		jne _Zero;
		cmp word  ptr[esi + 0ch], 07373h
		jne _Zero

		xor ebx, ebx
		mov esi, [ebp - 0xc]     //序号的Va
		mov bx, [esi + ecx * 2]  //得到序号

		mov esi, [ebp - 0x4]    //导出函数的Va
		mov esi, [esi + ebx * 4] //FunAddr的Rva
		lea eax, [esi + edx]     //FunAddr
		mov MyGetProcAddress, eax
		add esp, 0xc
		popad
	}

}
//解密
void Decryption()
{	
	/*//获取.text的区段头auto pNt = GetNtHeader((char*)g_hModule);
	DWORD dwSecNum = pNt->FileHeader.NumberOfSections;
	auto pSec = IMAGE_FIRST_SECTION(pNt);
	
	//找到代码区段
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
	//获取代码段首地址
	char* pTarText = pSec->VirtualAddress + (char*)g_hModule;
	int nSize = pSec->Misc.VirtualSize;
	DWORD old = 0;
	//解密代码段
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
//反调试
bool NQIP_ProcessDebugPort()
{
	int nDebugPort = 0;
	MyNtQueryInformationProcess(
		MyGetCurrentProcess (),//目标进程句柄
		ProcessDebugPort,   //查询信息的类型
		&nDebugPort,        //输出查询的信息
		sizeof(nDebugPort), //查询类型的大小
		NULL);

	return nDebugPort == 0xFFFFFFFF ? true : false;
}
void Funtion()
{
	MyLoadLibraryExA = (FuLoadLibraryExA)MyGetProcAddress(g_hKernel32, "LoadLibraryExA");
	g_hUser32 = MyLoadLibraryExA("user32.dll", 0, 0);
	MyGetModuleHandleW = (FuGetModuleHandleW)MyGetProcAddress(g_hKernel32,"GetModuleHandleW");
	//返回创建本进程的EXE文件的加载地址
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
	{      //定位到数据处+0x8
		PWORD ReDate = (PWORD)((DWORD)pRelocation + 8);
		for (int i = 0; i < (pRelocation->SizeOfBlock - 8) / 2; i++, ReDate++)
		{
			
			//前四位是属性
			DWORD AddressAttribute = (*ReDate) >> 12;
			//printf("属性：%x    ", AddressAttribute);
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
	//直接定位FirstThunk即可
	PIMAGE_THUNK_DATA pITD = (PIMAGE_THUNK_DATA)((DWORD)g_hModule + pIID->FirstThunk);
	//调用LoadLibrary载入DLL
	HINSTANCE hInstance = MyLoadLibraryExA((LPSTR)((DWORD)g_hModule + pIID->Name),0,0);

	for (; pITD->u1.Ordinal != 0; pITD++)
	{
		FARPROC fpFun;
		if (pITD->u1.Ordinal & 0x80000000)
		{
			///函数是以序号的方式导入的
			fpFun = MyGetProcAddress(hInstance, (LPCSTR)(pITD->u1.Ordinal & 0x0000ffff));
		}
		else
		{ //函数是以名称方式导入的
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
//关闭随机地址后
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

	//如果存在TLS表
	if (g_Sc.TLStableRVA)
	{
		DWORD OldProtect = 0;
		MyVirtualProtect(&(GetOptHeader(g_hModule)->DataDirectory[9].VirtualAddress), 0x4, PAGE_EXECUTE_READWRITE, &OldProtect);
		//恢复Tls数据
		GetOptHeader(g_hModule)->DataDirectory[9].VirtualAddress = g_Sc.TLStableRVA;
		MyVirtualProtect(&(GetOptHeader(g_hModule)->DataDirectory[9].VirtualAddress), 0x4, OldProtect, &OldProtect);
		auto TlsTable = (PIMAGE_TLS_DIRECTORY)(g_Sc.TLStableRVA + g_hModule);

		//手动调用TLS回调函数(去随机基地址要改-旧的ImageBase+新)
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
	MyMessageBoxW(0, L"壳", L"壳", 0);
		g_Sc.dwOep += (DWORD)g_hModule;
		__asm {
			jmp g_Sc.dwOep;
		}
}
