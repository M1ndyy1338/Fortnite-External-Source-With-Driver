#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
namespace librarys
{
	HMODULE user32;
	HMODULE win32u;
	bool init()
	{
		HMODULE user32_lib = LoadLibraryA("user32.dll");
		if (!user32_lib) {
			std::cout << "user32_lib\n";
			return false;
		}
		HMODULE win32u_lib = LoadLibraryA("win32u.dll");
		if (!win32u_lib) {
			std::cout << "win32u_lib\n";
			return false;
		}

		user32 = GetModuleHandleA("user32.dll");
		if (!user32) {
			std::cout << "user32.dll\n";
			return false;
		}
		win32u = GetModuleHandleA("win32u.dll");
		if (!win32u) {
			std::cout << "win32u\n";
			return false;
		}
		return true;
	}
}

typedef __int64(__fastcall* NtUserFunction)(uintptr_t);
NtUserFunction nt_user_function = (NtUserFunction)NULL;
HMODULE ensure_dll_load()
{
#define LOAD_DLL(str) LoadLibrary((str))

	LOAD_DLL("user32.dll");

#undef LOAD_DLL
	return LoadLibrary(("win32u.dll"));
}

class _driver
{
private:

	enum REQUEST_TYPE : int
	{
		NONE,
		BASE,
		WRITE,
		READ
	};
	typedef struct _DRIVER_REQUEST
	{
		REQUEST_TYPE type;
		HANDLE pid;
		PVOID address;
		PVOID buffer;
		SIZE_T size;
		PVOID base;
	} DRIVER_REQUEST, * PDRIVER_REQUEST;
	void send_request(PDRIVER_REQUEST out)
	{
		RtlSecureZeroMemory(out, 0);
		nt_user_function(reinterpret_cast<uintptr_t>(out));
	}
public:
	int process_id;
	uintptr_t base_address;
	DWORD get_process_id(LPCTSTR process_name)
	{
		PROCESSENTRY32 pt{};
		HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pt.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hsnap, &pt))
		{
			do {
				if (!lstrcmpi(pt.szExeFile, process_name))
				{
					CloseHandle(hsnap);
					return pt.th32ProcessID;
				}
			} while (Process32Next(hsnap, &pt));
		}
		CloseHandle(hsnap);
		return 0;
	}
	bool init()
	{
		if (!nt_user_function)
		{
			HMODULE hDll = GetModuleHandle(("win32u.dll"));
			if (!hDll)
			{
				hDll = ensure_dll_load();
				if (!hDll)
				{
					std::cout << "!hDll\n";
					return false;
				}

			}

			nt_user_function = (NtUserFunction)GetProcAddress(hDll, ("NtUserGetPointerDeviceProperties")); //old func: NtUserRegisterErrorReportingDialog
			//NtOpenCompositionSurfaceSwapChainHandleInfo
			if (!nt_user_function)
			{
				std::cout << "!pHookFunc\n";
				nt_user_function = (NtUserFunction)NULL;
				return false;
			}
			std::cout << "\n [ hookedFunction NOT UD ] -> " << nt_user_function << "\n\n";
		}
		return true;
	}

	uintptr_t get_base_address()
	{
		DRIVER_REQUEST out{};
		out.type = BASE;
		out.pid = (HANDLE)process_id;
		send_request(&out);
		return (uintptr_t)out.base;
	}
	void writem(PVOID address, PVOID buffer, DWORD size)
	{
		DRIVER_REQUEST out{};
		out.type = WRITE;
		out.pid = (HANDLE)process_id;
		out.address = address;
		out.buffer = buffer;
		out.size = size;
		send_request(&out);
	}
	void readm(PVOID address, PVOID buffer, DWORD size)
	{
		DRIVER_REQUEST out{};
		out.type = READ;
		out.pid = (HANDLE)process_id;
		out.address = address;
		out.buffer = buffer;
		out.size = size;
		send_request(&out);
	}
	template<typename T> void write(uintptr_t address, T value)
	{
		writem((PVOID)address, &value, sizeof(T));
	}
	template<typename T> T read(uintptr_t address)
	{
		T buffer{};
		readm((PVOID)address, &buffer, sizeof(T));
		return buffer;
	}
};
_driver driver;