#include <iostream>
#include <windows.h>
#include <tchar.h>
#include "share.h"
char path[1000] = "C://Users//GAOXINGXING//Desktop//ResourceHacker.exe";
DWORD fileSize = 0;
//stub信息结构体
struct StubInfo
{
	HMODULE hModule;//
	DWORD dwTextRva; //代码段RVA
	DWORD dwTextSize;//代码段大小
	DWORD dwOEP;//OEP
	StubConf* sc;
	
};
DWORD Align(DWORD ad, DWORD alignment) {
	if (ad % alignment == 0) {
		return ad;
	}
	else {
		return ((ad / alignment) + 1) * alignment;
	}
}
/// RVA转FOA
/// 参数  1.RVA		2.基地址
/// 返回FOA
DWORD RVAToFOA(LPVOID  pFileBuffer1, LPVOID pFileBuffer) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD pFileBuffer2 = 0;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//判断此时的RVA在不在头里
	for (int a = 1; a <= pPEHeader->NumberOfSections; a++) {

		//找到这个地址的FOA在这个节的偏移和文件尺寸大小之间
		if ((DWORD)pFileBuffer1 >= pSectionHeader->VirtualAddress && (DWORD)pFileBuffer1 <= (pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)) {
			pFileBuffer2 = ((DWORD)pFileBuffer1 - pSectionHeader->VirtualAddress) + pSectionHeader->PointerToRawData;
			return pFileBuffer2;
		}
		pSectionHeader++;
	}

}
DWORD FOAtoRVA(LPVOID  pFileBuffer1, LPVOID pFileBuffer) {
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	DWORD pFileBuffer2 = 0;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	//判断此时的FOA在不在头里
	for (int a = 1; a <= pPEHeader->NumberOfSections; a++) {

		//找到这个地址的FOA在这个节的偏移和文件尺寸大小之间
		if ((DWORD)pFileBuffer1 >= pSectionHeader->PointerToRawData && (DWORD)pFileBuffer1 <= (pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData)) {
			pFileBuffer2 = ((DWORD)pFileBuffer1 - pSectionHeader->PointerToRawData) + pSectionHeader->VirtualAddress;
			return pFileBuffer2;
		}
		pSectionHeader++;
	}

}
VOID writeFile(LPVOID NewBuffer, DWORD Size) {
	FILE* file;
	fopen_s(&file, "C://Users//GAOXINGXING//Desktop//4.0.exe", "wb");
	if (!file)
	{
		printf(" 无法打开 EXE 文件! ");
		exit(1);
	}
	size_t n = fwrite(NewBuffer, Size, 1, file);
	if (!n) {
		printf("文件写入失败");
		exit(1);
	}
	printf("文件写入成功");
	fclose(file);

}
//增添新节
LPVOID TestAddSection(OUT LPVOID* pFileBuffer1) {
	LPVOID pFileBuffer = NULL;
	FILE* pFile = NULL;
	BOOL promote = FALSE;
	//打开文件	
	fopen_s(&pFile, path, "rb");
	if (!pFile)
	{
		printf(" 无法打开 EXE 文件! ");
		return 0;
	}
	//读取文件大小		
	fseek(pFile, 0, SEEK_END);
	fileSize = ftell(pFile);
	DWORD AddFile = fileSize + 0x30000;
	fseek(pFile, 0, SEEK_SET);
	//分配缓冲区	
	pFileBuffer = malloc(AddFile);
	memset(pFileBuffer, 0, AddFile);
	if (!pFileBuffer)
	{
		printf(" 分配空间失败! ");
		fclose(pFile);
		return 0;
	}
	

	//将文件数据读取到缓冲区	
	size_t n = fread(pFileBuffer, fileSize, 1, pFile);
	if (!n)
	{
		printf(" 读取数据失败! ");
		free(pFileBuffer);
		fclose(pFile);
		return 0;
	}
	//关闭文件	
	fclose(pFile);
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	PIMAGE_SECTION_HEADER pSectionHeaderTemp = pSectionHeader;
	for (DWORD i = 0; i < pPEHeader->NumberOfSections; i++, pSectionHeaderTemp++)
	{

		// for结束后，pSectionHeaderTemp指向最后一个节表的后面
	}

	PBYTE Tmps = (PBYTE)pSectionHeaderTemp;
	PIMAGE_SECTION_HEADER pSectionHeaderLast = pSectionHeaderTemp;
	//pSectionHeaderTemp指向新节前一个节表

	pSectionHeaderTemp = pSectionHeaderLast - 1;
	if ((pOptionHeader->SizeOfHeaders - ((DWORD)pSectionHeaderTemp - (DWORD)pFileBuffer)) >= IMAGE_SIZEOF_SECTION_HEADER * 2)
	{

		for (int a = 0; a < IMAGE_SIZEOF_SECTION_HEADER * 2; a++, Tmps++)
		{
			if (*Tmps != 0)
			{
				printf("剩余位置无空白,尝试提升\n");
				promote = TRUE;
				break;
			}

		}
	}
	else
	{
		printf("空白不够添加！,尝试提升\n");
		promote = TRUE;
	}
	if (promote)
	{
		if ((DWORD)pNTHeader - (DWORD)pFileBuffer - sizeof(IMAGE_DOS_HEADER) >= IMAGE_SIZEOF_SECTION_HEADER * 2) {
			printf("开始提升\n");
			DWORD LengthDOStoNT = ((DWORD)pNTHeader - (DWORD)pFileBuffer - sizeof(IMAGE_DOS_HEADER));
			//x为提升偏移之前的NT
			DWORD x = pDosHeader->e_lfanew + (DWORD)pFileBuffer;
			pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);
			//s为NT到最后一个节表的长度
			DWORD  s = ((DWORD)pSectionHeaderLast - (DWORD)pNTHeader);
			//P为提升偏移之后的NT
			LPVOID P = (LPVOID)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
			//提升后新的最后一个节的末端就是要新加节的开始
			PIMAGE_SECTION_HEADER NewpSectionlast = (PIMAGE_SECTION_HEADER)((DWORD)P + s);
			memcpy(P, (LPVOID)x, s);
			memset(NewpSectionlast, 0, LengthDOStoNT);
			printf("提升成功\n");
			pSectionHeaderLast = NewpSectionlast;
			pSectionHeaderTemp = pSectionHeaderLast - 1;
			pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
			pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
			pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
			pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);

		}
		else {

			printf("DOS头和NT头之间空闲不够,加壳失败");
			exit(1);
		}

	}
	//新加一份节表
	memcpy(pSectionHeaderLast, pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);
	//修改
	memcpy(pSectionHeaderLast, "hhhh", 8);
	pPEHeader->NumberOfSections = pPEHeader->NumberOfSections + 1;
	pOptionHeader->SizeOfImage = pOptionHeader->SizeOfImage + 0x30000;
	pSectionHeaderLast->Misc.VirtualSize = 0x30000;
	DWORD z = pSectionHeaderTemp->Misc.VirtualSize > pSectionHeaderTemp->SizeOfRawData ? pSectionHeaderTemp->Misc.VirtualSize : pSectionHeaderTemp->SizeOfRawData;
	pSectionHeaderLast->VirtualAddress = pSectionHeaderTemp->VirtualAddress + Align(z, pOptionHeader->SectionAlignment);
	pSectionHeaderLast->SizeOfRawData = 0x30000;
	pSectionHeaderLast->PointerToRawData = pSectionHeaderTemp->SizeOfRawData + pSectionHeaderTemp->PointerToRawData;
	pSectionHeaderLast->Characteristics =0xE0000020;
	*pFileBuffer1 = pFileBuffer;
	return (LPVOID)(pSectionHeaderLast->VirtualAddress);
}
//加载壳代码
StubInfo LoadStub()
{
	StubInfo si = { 0 };
	HMODULE hStubDll = LoadLibraryExA("stub.dll", 0,
		DONT_RESOLVE_DLL_REFERENCES);
	si.hModule = hStubDll;
	
	si.dwTextRva = (DWORD)GetSectionAddress((LPVOID)hStubDll, ".text")->VirtualAddress;
	si.dwTextSize = (DWORD)GetSectionAddress((LPVOID)hStubDll, ".text")->SizeOfRawData;
	si.dwOEP = (DWORD)GetProcAddress(hStubDll,"Start");//壳代码的OEPVA
	//printf("dll句柄：%x，代码段的RVA：%x，Start函数的OEP：%x\n ", si.hModule, si.dwTextRva, si.dwOEP);
	si.sc= (StubConf*)GetProcAddress(hStubDll, "g_Sc");
	return si;
}
//修复重定位表（关闭随机基地址）
VOID FixReLocation(LPVOID pFileBuffer, HMODULE StubDll,LPVOID NewSection)
{
	//printf("被加壳程序的ImageBase:%x,Dll的Image是：%x\n", GetOptHeader(pFileBuffer)->ImageBase, GetOptHeader(StubDll)->ImageBase);
	
	//stub重定位表的VA
	PIMAGE_DATA_DIRECTORY	pDataDirectory = GetOptHeader(StubDll)->DataDirectory;
	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)(pDataDirectory[5].VirtualAddress+(DWORD)StubDll);
	//printf("重定位表的VA：%x,偏移：%x\n",(DWORD)pRelocation,pDataDirectory[5].VirtualAddress);
	//代码段的RVA
	DWORD TextRVA = GetSectionAddress(StubDll, ".text")->VirtualAddress;
	//壳的ImageBase
	DWORD KImageBase = GetOptHeader(StubDll)->ImageBase;
	// 修复里面的值
	//printf("VirtualAddress：%x，SizeOfBlock:%x  \n", pRelocation->VirtualAddress, pRelocation->SizeOfBlock);
	for (int a = 1; pRelocation->SizeOfBlock != 0 && pRelocation->VirtualAddress!= 0; pRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocation + pRelocation->SizeOfBlock))
	{
		//printf("++++++++++++++++++++++++++++++++++++++++++++++++++\n");
		//printf("基地址：%x\n", pRelocation->VirtualAddress);
		//printf("改表里面有%d个要改的地方\n",(( pRelocation->SizeOfBlock - 8) / 2));
		PWORD ReDate = (PWORD)((DWORD)pRelocation + 8);
		for (int i = 0; i < (pRelocation->SizeOfBlock - 8) / 2; i++,ReDate++)
		{
			//printf("表数据 ：% x\n", *ReDate);
			//前四位是属性
			DWORD AddressAttribute = (*ReDate) >> 12;
			//printf("属性：%x    ", AddressAttribute);
			if (AddressAttribute != 3) {
				continue;
			}
			DWORD RelocationAddressRVA = ((*ReDate) & 0xFFF) + pRelocation->VirtualAddress;
			//printf("地址RVA：%x\n", RelocationAddressRVA);
			PDWORD ReDates = (PDWORD)(RelocationAddressRVA + (DWORD)StubDll);
			//printf("修改前地址里的数据是：%x\n",*ReDates );
			DWORD dwOld;
			VirtualProtect(ReDates, 4, PAGE_READWRITE, &dwOld);
			(*ReDates) -= KImageBase;
			(*ReDates) -= TextRVA;
			(*ReDates) += GetOptHeader(pFileBuffer)->ImageBase;
			(*ReDates) += ((DWORD)NewSection);
			VirtualProtect(ReDates, 4, dwOld, &dwOld);
			//printf("偏移：%x", (DWORD)NewSection );
			//printf("修改后地址里的数据是：%x\n",*ReDates );
		}

	}

}
//替换重定位表
DWORD NewRelaction(LPVOID pFileBuffer, HMODULE StubDll, LPVOID NewSectionFVA, DWORD NewSectionRVA)
 { 
	DWORD KImageBase = GetOptHeader(StubDll)->ImageBase;
	DWORD TextRVA = GetSectionAddress(StubDll, ".text")->VirtualAddress;
	DWORD TextSize = GetSectionAddress(StubDll, ".text")->SizeOfRawData;
	//stub重定位表的VA
	PIMAGE_DATA_DIRECTORY	pDataDirectory = GetOptHeader(StubDll)->DataDirectory;
	PIMAGE_BASE_RELOCATION pRelocationDirectory = (PIMAGE_BASE_RELOCATION)(pDataDirectory[5].VirtualAddress + (DWORD)StubDll);
	//拷贝stub的重定位表
	DWORD Adder = (DWORD)NewSectionFVA ;
	DWORD Adder2 = (DWORD)NewSectionFVA;
	//printf("代码段后：%x\n", (DWORD)NewSectionFVA-(DWORD)pFileBuffer);
	PIMAGE_BASE_RELOCATION pRelocationDirectory2 = (PIMAGE_BASE_RELOCATION)pRelocationDirectory;
	//修复重定位表里需要重定位的实际RVA
	while (pRelocationDirectory->VirtualAddress) {
		DWORD dwOld;
		VirtualProtect(pRelocationDirectory, 4, PAGE_READWRITE, &dwOld);
		//新的内存页起始RVA = 原RVA - 原段RVA +stub复制段RVA
		//printf("RVA：%x\n", pRelocationDirectory->VirtualAddress);
		pRelocationDirectory->VirtualAddress = (pRelocationDirectory->VirtualAddress  - TextRVA + (DWORD)NewSectionRVA);
		//printf("RVA:%x\n", pRelocationDirectory->VirtualAddress);
		VirtualProtect(pDataDirectory, 4, dwOld, &dwOld);
		pRelocationDirectory = (PIMAGE_BASE_RELOCATION)(pRelocationDirectory->SizeOfBlock + (DWORD)pRelocationDirectory);		
	}
	pRelocationDirectory = pRelocationDirectory2;
	DWORD Size = 0;
	while (pRelocationDirectory->VirtualAddress != 0 && pRelocationDirectory->SizeOfBlock != 0)
	{
		Size += pRelocationDirectory->SizeOfBlock;
		//	将重定位块copy到目标地址
		//printf("VA是：%x,SizeofBlock:%x\n",pRelocationDirectory->VirtualAddress,pRelocationDirectory->SizeOfBlock);
		if ((pRelocationDirectory->VirtualAddress+ TextRVA - (DWORD)NewSectionRVA) < (TextRVA + TextSize)) {

			memcpy((LPVOID)(Adder), pRelocationDirectory, pRelocationDirectory->SizeOfBlock);

		}
		//printf("p->SizeOfBlock:%x\n", pRelocationDirectory->SizeOfBlock);
		//	将目标地址后移
		Adder = ((DWORD)Adder + pRelocationDirectory->SizeOfBlock);

		//将旧重定位表块后移
		pRelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationDirectory + pRelocationDirectory->SizeOfBlock);

	}
	Size += 0x8;
	//替换原程序重定位表
	GetOptHeader(pFileBuffer)->DataDirectory[5].VirtualAddress =FOAtoRVA((LPVOID)(Adder2-(DWORD)pFileBuffer),pFileBuffer);
	GetOptHeader(pFileBuffer)->DataDirectory[5].Size = GetOptHeader(StubDll)->DataDirectory[5].Size ;
	
	return (DWORD)NewSectionFVA + Size;
}
//植入stub
DWORD CopyStub(LPVOID NewSectionFVA,LPVOID pFileBuffer,LPVOID NewSectionRVA) {
	StubInfo si = LoadStub();
	si.sc->ImportRVA = GetOptHeader(pFileBuffer)->DataDirectory[1].VirtualAddress;
	si.sc->RelocationRVA = GetOptHeader(pFileBuffer)->DataDirectory[5].VirtualAddress;
	if (GetOptHeader(pFileBuffer)->DataDirectory[9].VirtualAddress) {
	si.sc->TLStableRVA=GetOptHeader(pFileBuffer)->DataDirectory[9].VirtualAddress;
	PIMAGE_TLS_DIRECTORY TLS=(PIMAGE_TLS_DIRECTORY)(RVAToFOA((LPVOID)(GetOptHeader(pFileBuffer)->DataDirectory[9].VirtualAddress),pFileBuffer)+(DWORD)pFileBuffer);
	si.sc->CallBack = TLS->AddressOfCallBacks;
	}
	FixReLocation(pFileBuffer, si.hModule, NewSectionRVA);
	LPVOID stubVA = (LPVOID)(si.dwTextRva+(DWORD)si.hModule);
	si.sc->dwOep = GetOptHeader(pFileBuffer)->AddressOfEntryPoint;
	memcpy(NewSectionFVA, stubVA, si.dwTextSize);
	DWORD NewLast = (DWORD)NewSectionFVA + si.dwTextSize;
	printf("壳代码段长度：%x\n", si.dwTextSize);
	DWORD NewLA =NewRelaction(pFileBuffer, si.hModule, (LPVOID)NewLast, (DWORD)NewSectionRVA);
	GetOptHeader(pFileBuffer)->AddressOfEntryPoint = (si.dwOEP-(DWORD)si.hModule - si.dwTextRva +(DWORD)NewSectionRVA);
	printf("改后OEP：%x\n", GetOptHeader(pFileBuffer)->AddressOfEntryPoint);
	return (NewLA);
}
//替换TLS表
DWORD CopyTLS(LPVOID pFileBuffer, HMODULE StubDll, LPVOID NewSectionFVA) {
	DWORD KImageBase = GetOptHeader(StubDll)->ImageBase;
	DWORD TextRVA = GetSectionAddress(StubDll, ".text")->VirtualAddress;
	DWORD ImageBase= GetOptHeader(pFileBuffer)->ImageBase;
	PIMAGE_DATA_DIRECTORY	pDataDirectory = GetOptHeader(StubDll)->DataDirectory;
	PIMAGE_TLS_DIRECTORY pTLS = (PIMAGE_TLS_DIRECTORY)(pDataDirectory[9].VirtualAddress + (DWORD)StubDll);
	DWORD Adder = (DWORD)NewSectionFVA;
	DWORD Adder2 = (DWORD)NewSectionFVA;
	PIMAGE_TLS_DIRECTORY pTLS2 = (PIMAGE_TLS_DIRECTORY)pTLS;
	pTLS->StartAddressOfRawData = pTLS->StartAddressOfRawData - KImageBase - TextRVA + ImageBase + FOAtoRVA((LPVOID)((DWORD)NewSectionFVA - (DWORD)pFileBuffer), pFileBuffer);
	pTLS->EndAddressOfRawData=pTLS->EndAddressOfRawData - KImageBase - TextRVA + ImageBase + FOAtoRVA((LPVOID)((DWORD)NewSectionFVA - (DWORD)pFileBuffer), pFileBuffer);
	pTLS->AddressOfIndex = pTLS->AddressOfIndex - KImageBase - TextRVA + ImageBase + FOAtoRVA((LPVOID)((DWORD)NewSectionFVA - (DWORD)pFileBuffer), pFileBuffer);
	pTLS->AddressOfCallBacks = pTLS->AddressOfCallBacks - KImageBase - TextRVA + ImageBase + FOAtoRVA((LPVOID)((DWORD)NewSectionFVA - (DWORD)pFileBuffer), pFileBuffer);
	memcpy((LPVOID)Adder, pTLS, sizeof(IMAGE_TLS_DIRECTORY));
	GetOptHeader(pFileBuffer)->DataDirectory[9].VirtualAddress = FOAtoRVA((LPVOID)(Adder2 - (DWORD)pFileBuffer), pFileBuffer);
	GetOptHeader(pFileBuffer)->DataDirectory[9].Size = GetOptHeader(StubDll)->DataDirectory[9].Size;

	return 0;
}
DWORD MoveImport(DWORD LastNewS, LPVOID pFileBuffer) {
	PIMAGE_DATA_DIRECTORY	pDataDirectory = GetOptHeader(pFileBuffer)->DataDirectory;
	DWORD ImportRVA = (DWORD)(pDataDirectory[1].VirtualAddress);
	DWORD importFOA = RVAToFOA((LPVOID)ImportRVA, pFileBuffer);
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(importFOA + (DWORD)pFileBuffer);
	PIMAGE_IMPORT_DESCRIPTOR pImport_Temp = pImport;
	
	//把原来的导入表全部移动到新增的节内
	//移动DLLName和Databases2结构
	while (pImport_Temp->OriginalFirstThunk != 0 && pImport_Temp->FirstThunk != 0)
	{
		pImport_Temp->TimeDateStamp = 0;
		DWORD DllName = ((DWORD)pFileBuffer + RVAToFOA((LPVOID)pImport_Temp->Name, pFileBuffer));
		char* NameOfCurrentDll = (char*)(DllName);
		//printf("NameDLL:%s\n", NameOfCurrentDll);
		DWORD lengthOfCurrentDllName = strlen(NameOfCurrentDll) + 1;
		memcpy((LPVOID)(LastNewS), NameOfCurrentDll, lengthOfCurrentDllName);
		//清空DLL名字
		//memset(NameOfCurrentDll, 0, lengthOfCurrentDllName);
		pImport_Temp->Name = (DWORD)FOAtoRVA((LPVOID)(LastNewS - (DWORD)pFileBuffer), pFileBuffer);
		//printf("DLLName改后的RVA是:%x\n", pImport_Temp->Name);
		LastNewS += lengthOfCurrentDllName;
		LPDWORD LastRe = (LPDWORD)LastNewS;
		DWORD OriginalThunkRVA = pImport_Temp->OriginalFirstThunk;
		LPDWORD OriginalThunkFVA = (LPDWORD)(RVAToFOA((LPVOID)OriginalThunkRVA, pFileBuffer) + (DWORD)pFileBuffer);
		LPDWORD OriginalThunkFVAtemp = OriginalThunkFVA;
		pImport_Temp->OriginalFirstThunk = (DWORD)FOAtoRVA((LPVOID)(LastNewS - (DWORD)pFileBuffer), pFileBuffer);
		//拷贝Date32结构
		while (1)
		{	 //data32也是连续存储的取得时候连续取
			//printf("RVA为：%x\n", *OriginalThunkFVA);
			memcpy((LPVOID)(LastNewS), OriginalThunkFVA, sizeof(DWORD));
			if (*OriginalThunkFVA != 0) {
				LastNewS += sizeof(DWORD);
				OriginalThunkFVA++;
			}
			else {
				LastNewS += sizeof(DWORD);
				break;
			}
		}
		LPDWORD pFT = (LPDWORD)((DWORD)pFileBuffer + RVAToFOA((LPVOID)pImport_Temp->FirstThunk, pFileBuffer));
		LPDWORD pFTtemp = pFT;
		pImport_Temp->FirstThunk = FOAtoRVA((LPVOID)(LastNewS - (DWORD)pFileBuffer), pFileBuffer);
		pDataDirectory[12].VirtualAddress = pImport_Temp->FirstThunk;
		 LPDWORD LastRe2 = (LPDWORD)LastNewS;
		while (1)
		{
			//printf("pFt:%x\n", *pFT);
			memcpy((LPVOID)(LastNewS), pFT, sizeof(DWORD));
			//printf("FirstThunk改后的RVA是:%x\n", pImport_Temp->FirstThunk);
			if (*pFT != 0) {

				LastNewS += sizeof(DWORD);
				pFT += 1;
			}
			else {

				LastNewS += sizeof(DWORD);

				break;
			}
		}
		OriginalThunkFVA = OriginalThunkFVAtemp;
		while (1)
		{
			if (*OriginalThunkFVA != 0) {
				if (((*OriginalThunkFVA) & 0x80000000) == 0) {

					DWORD NameFOA = RVAToFOA((LPVOID)(*OriginalThunkFVA), pFileBuffer);
					DWORD NameVA = ((DWORD)pFileBuffer + NameFOA);
					PIMAGE_IMPORT_BY_NAME   pName = (PIMAGE_IMPORT_BY_NAME)(DWORD)NameVA;

					//printf("Re之前的DATA32：%x\n", *LastRe);
					*LastRe = FOAtoRVA((LPVOID)(LastNewS - (DWORD)pFileBuffer), pFileBuffer);
					*LastRe2 = FOAtoRVA((LPVOID)(LastNewS - (DWORD)pFileBuffer), pFileBuffer);
					//printf("Re之后的DATA32：%x\n", *LastRe);
					LastRe += 1;
					LastRe2 += 1;
					//printf("按名字导入--函数名称是：%s\n", pName->Name);
					//拷贝hint
					memcpy((LPVOID)(LastNewS), (LPVOID)(pName), sizeof(WORD));
					LastNewS += sizeof(WORD);
					//拷贝函数名称
					DWORD FuctionNamelength = strlen(pName->Name) + 1;
					LPVOID  FuctionNameVA = (LPVOID)((DWORD)pName + sizeof(WORD));
					memcpy((LPVOID)(LastNewS), FuctionNameVA, FuctionNamelength);
					LastNewS += FuctionNamelength;
					//memset((LPDWORD)((DWORD)pFileBuffer + foaOriginalFirstThunk), 0, sizeOfOriginalFirstThunk);

				}
			}

			else {
				break;
			}
			OriginalThunkFVA++;
		}

		pImport_Temp = pImport_Temp + 1;

	}


        DWORD LastImport = LastNewS;

		pImport_Temp = pImport;
	while (1)
	{
		memcpy((LPVOID)LastNewS, (LPVOID)pImport_Temp, 0x14);//导入表的大小是20个字节 0x14先拷贝表的结构

		//printf("修改后导入表的FOA为：%x\n", LastNewS - (DWORD)pFileBuffer);


			if (pImport_Temp->OriginalFirstThunk != 0 ) {
				LastNewS += 0x14;
				pImport_Temp = pImport_Temp + 1;
			}
			else {
				LastNewS += 0x14;
				break;
			}

	}
		//修复DataDirectory中的VirtualAddress 别忘记里面是一个RVA的偏移。
		pDataDirectory[1].VirtualAddress = FOAtoRVA((LPVOID)(LastImport-(DWORD)pFileBuffer), pFileBuffer);

		//printf("修改后导入表的VA为：%x\n",pDataDirectory[1].VirtualAddress );
		return LastNewS;
	
}
DWORD MoveRelocation(DWORD LastNewS, LPVOID pFileBuffer) {
	PIMAGE_DATA_DIRECTORY	pDataDirectory = GetOptHeader(pFileBuffer)->DataDirectory;
	DWORD pRelocationRVA = (DWORD)(pDataDirectory[5].VirtualAddress);
	DWORD RelocationFoa = RVAToFOA((LPVOID)pRelocationRVA, pFileBuffer);
	PIMAGE_BASE_RELOCATION pRelocationDirectory = (PIMAGE_BASE_RELOCATION)(RelocationFoa + (DWORD)pFileBuffer);
	PDWORD pRelocationDirectory_Temp = (PDWORD)pRelocationDirectory;
	DWORD pNewSecAddr = (LastNewS);//定位新节表的地址
	printf("大小是：%x\n", pDataDirectory[5].Size);
	memcpy((LPVOID)LastNewS, pRelocationDirectory, pDataDirectory[5].Size);
	/*while (pRelocationDirectory->VirtualAddress != 0 && pRelocationDirectory->SizeOfBlock != 0)
	{
		//	将重定位块copy到目标地址
		memcpy((LPVOID)LastNewS, pRelocationDirectory, pRelocationDirectory->SizeOfBlock);
		//printf("p->SizeOfBlock:%x\n", pRelocationDirectory->SizeOfBlock);
		//	将目标地址后移
		LastNewS = ((DWORD)pNewSecAddr + pRelocationDirectory->SizeOfBlock);

		//将旧重定位表块后移
		pRelocationDirectory = (PIMAGE_BASE_RELOCATION)((DWORD)pRelocationDirectory + pRelocationDirectory->SizeOfBlock);
	}*/
	GetOptHeader(pFileBuffer)->DataDirectory[5].VirtualAddress = FOAtoRVA((LPVOID)(pNewSecAddr-(DWORD)pFileBuffer),pFileBuffer);
	return LastNewS + 8;
}
DWORD MoveTLS(DWORD LastNewS,LPVOID pFileBuffer) {
	PIMAGE_DATA_DIRECTORY	pDataDirectory = GetOptHeader(pFileBuffer)->DataDirectory;
	PIMAGE_TLS_DIRECTORY	pTLS = (PIMAGE_TLS_DIRECTORY)(RVAToFOA((LPVOID)pDataDirectory[9].VirtualAddress, pFileBuffer) + (DWORD)pFileBuffer);
	/*printf("TLS表：%x\n", pTLS->StartAddressOfRawData);
	printf("TLS表：%x\n", pTLS->EndAddressOfRawData);
	printf("TLS表：%x\n", pTLS->AddressOfIndex);
	printf("TLS表：%x\n", pTLS->AddressOfCallBacks);
	printf("TLS表：%x\n", pTLS->SizeOfZeroFill);
	printf("TLS表：%x\n", pTLS->Characteristics);*/
	memcpy((LPVOID)LastNewS, pTLS, sizeof(IMAGE_TLS_DIRECTORY));
	pDataDirectory[9].VirtualAddress = FOAtoRVA((LPVOID)(LastNewS - (DWORD)pFileBuffer), pFileBuffer);
	return LastNewS + sizeof(IMAGE_TLS_DIRECTORY);
}
int main()
{
	
	/*typedef void (*lpStart)();
	StubInfo si = LoadStub();
	lpStart Start=(lpStart)si.dwOEP;
	Start();*/
	DWORD LastNewS = 0;
	LPVOID pFileBuffer = NULL;
	LPVOID  NewFileSectionRVA = NULL;
	NewFileSectionRVA= TestAddSection(&pFileBuffer);
	LPVOID NewSectionFVA = (LPVOID)(RVAToFOA(NewFileSectionRVA,pFileBuffer) + (DWORD)pFileBuffer);
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	pDosHeader = GetDosHeader(pFileBuffer);
	pNTHeader = GetNtHeader(pFileBuffer);
	pPEHeader = GetPeHeader(pFileBuffer);
	pOptionHeader = GetOptHeader(pFileBuffer);
	pSectionHeader = GetSectionHeader(pFileBuffer);
	//判断是否是有效的MZ标志	
	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("不是有效的MZ标志\n");
		free(pFileBuffer);
		return 0;


	}
	//判断是否是有效的PE标志	
	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("不是有效的PE标志\n");
		free(pFileBuffer);
		return 0;
	}
	LastNewS = CopyStub(NewSectionFVA, pFileBuffer, NewFileSectionRVA);
	
	//移动
	//TLS
	if (GetOptHeader(pFileBuffer)->DataDirectory[9].VirtualAddress) {
		LastNewS = MoveTLS(LastNewS, pFileBuffer);
	}
	//移动导出表
	//LastNewS=MoveImport(LastNewS, pFileBuffer);
	//printf("lasyNew：%x", LastNewS-(DWORD)pFileBuffer);
	// 移动重定位表
	//MoveRelocation(LastNewS, pFileBuffer);
	//PrintRelocation(pFileBuffer);
	//加密
	for (int a = 0; a < pPEHeader->NumberOfSections; a++) {
		char name[9] = { 0 };
		BOOL Flag = TRUE;
		memcpy(name, pSectionHeader->Name, 8);
	
		if (!strcmp(name, ".tls") || !strcmp(name, ".rsrc")|| !strcmp(name, "hhhh")) {
			Flag = FALSE;
		}
		if (Flag) {
			DWORD TextSection = pSectionHeader->SizeOfRawData ;

			PBYTE pDate = (PBYTE)(pSectionHeader->PointerToRawData + (DWORD)pFileBuffer);
			if (pSectionHeader->PointerToRawData != 0) {
				for (int i = 0; i < TextSection; i++) {

					pDate[i] ^= 0x66;

				}

			}
		}
		pSectionHeader = pSectionHeader + 1;
	}


	auto ImportTable = GetOptHeader(pFileBuffer)->DataDirectory[1].Size = 0;
	auto ImportTable2 = GetOptHeader(pFileBuffer)->DataDirectory[1].VirtualAddress = 0;
	auto ImportTable3 = GetOptHeader(pFileBuffer)->DataDirectory[12].Size = 0;
	auto ImportTable4 = GetOptHeader(pFileBuffer)->DataDirectory[12].VirtualAddress = 0;
	//auto ImportTable7= GetOptHeader(pFileBuffer)->DataDirectory[9].Size = 0;
	//auto ImportTable8 = GetOptHeader(pFileBuffer)->DataDirectory[9].VirtualAddress = 0;
	/*DWORD Clear = GetOptHeader(pFileBuffer)->NumberOfRvaAndSizes;
	for (int a = 0; a < Clear; a++) {
		if (a==9&&a==11) {
			auto ImportTable = GetOptHeader(pFileBuffer)->DataDirectory[a].Size = 0;
			auto ImportTable2 = GetOptHeader(pFileBuffer)->DataDirectory[a].VirtualAddress = 0;
		}

	}
	*/
	//关闭随机基质
	//GetOptHeader(pFileBuffer)->DllCharacteristics &= (~0x40);
	writeFile(pFileBuffer, fileSize+0x30000);
	return 0;
}

	