#pragma once
#include <Windows.h>
#include <winternl.h>
typedef FARPROC(WINAPI* FuGetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
	);
typedef HMODULE(WINAPI* FuLoadLibraryExA)(
	_In_ LPCSTR lpLibFileName,
	_Reserved_ HANDLE hFile,
	_In_ DWORD dwFlags
	);
typedef int(WINAPI* FuMessageBoxW)(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType);
typedef BOOL(WINAPI* FuVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE(WINAPI* FuGetModuleHandleW)(_In_opt_ LPCTSTR lpModuleName);

typedef __kernel_entry NTSTATUS(NTAPI* FuNtQueryInformationProcess)(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL
);
typedef HANDLE(WINAPI* FuGetCurrentProcess)(VOID);
