#include "SteamManifestFixer.h"

uint32_t GetProcessIdByName(std::string processName)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry))
	{
		while (Process32Next(snapshot, &entry))
		{
			if (processName.compare(entry.szExeFile) == 0)
			{
				return static_cast<uint32_t>(entry.th32ProcessID);
			}
		}
	}
	
	return -1;
}

HMODULE GetHandleForModule(HANDLE processHandle, std::string targetModule)
{
	HMODULE moduleHandles[1024];
	DWORD cbNeeded;

	if (EnumProcessModulesEx(
		processHandle,
		moduleHandles,
		sizeof(moduleHandles),
		&cbNeeded,
		0x03
	))
	{
		if (cbNeeded > 1024 * sizeof(HMODULE))
		{
			std::cout << "Missing module names, buffer too small." << std::endl;
		}

		for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			HMODULE moduleHandle = moduleHandles[i];

			TCHAR moduleName[MAX_PATH * 2];

			if (GetModuleFileNameEx(
				processHandle,
				moduleHandle,
				moduleName,
				sizeof(moduleName) / sizeof(TCHAR)))
			{
				std::cout << "ModuleName: " << moduleName << std::endl;

				if (std::string(moduleName).find(targetModule) != std::string::npos)
				{
					return moduleHandle;
				}
			}
			else
			{
				std::cerr << "Unable to get a module name for handle: " << moduleHandle << std::endl;
			}
		}
	}
	else 
	{
		std::cout << "Unable to enumerate process modules." << std::endl;

		throw std::runtime_error("EnumProcessModulesEx failed.");
	}

	std::cout << "Unable to find moduleHandle for processHandle: " << processHandle << ", with target: " << targetModule << std::endl;

	throw std::runtime_error("EnumProcessModules failed.");
}

uint32_t GetModuleSize(HANDLE processHandle, HMODULE moduleHandle)
{
	MODULEINFO moduleInfo = {};
	if (GetModuleInformation(
		processHandle,
		moduleHandle,
		&moduleInfo,
		sizeof(MODULEINFO)))
	{
		return moduleInfo.SizeOfImage;
	}
	
	return -1;
}

uintptr_t GetPatchAddress(HANDLE processHandle, uint32_t address, uint32_t size)
{
	uint8_t* buffer = (uint8_t*) malloc(size);

	SIZE_T bytesRead;
	
	if (ReadProcessMemory(
		processHandle,
		(LPCVOID)address,
		buffer,
		size,
		&bytesRead
	))
	{
		std::vector<uint8_t> egg = {
			0x84, 0xC0, 
			0x0F, 0x85, 0x2E, 0xFF, 0xFF, 0xFF	
		};

		std::vector<uint8_t> image(buffer, buffer + bytesRead);

		free(buffer);

		auto it = std::search(
			image.begin(),
		       	image.end(),
			egg.begin(),
		       	egg.end()
		);

		if (it != image.end())
		{
			uintptr_t offset = it - image.begin();

			return address + offset + 2;
		}
		else 
		{
			std::cerr << "Read process memory, but was unable to find egg." << std::endl;

			throw std::runtime_error("Unable to find egg.");
		}
	}

	auto err = GetLastError();

	std::cerr << "Unable to read process memory. Error: " << err << std::endl;

	throw std::runtime_error("ReadProcessMemory failed.");
}

bool WritePatch(HANDLE processHandle, uintptr_t imageBase, uint32_t imageSize, uint32_t patchAddress)
{
	DWORD oldProtection;

	if (!VirtualProtectEx(
		processHandle,
		(void*)imageBase,
		imageSize,
		PAGE_EXECUTE_READWRITE,
		&oldProtection))
	{
		return false;
	}

	std::vector<uint8_t> patch = {
		0x0F, 0x84, 0x2E, 0xFF, 0xFF, 0xFF
	};

	SIZE_T bytesWritten;

	return WriteProcessMemory
	(
		processHandle,
		(void*)patchAddress,
		std::data(patch),
		patch.size(),
		&bytesWritten
	);
}

int main()
{
	auto processId = GetProcessIdByName("steam.exe");

	auto processHandle = OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		processId
	);

	auto moduleHandle = GetHandleForModule(
		processHandle, 
		"steamclient.dll"
	);

	auto moduleSize = GetModuleSize(
		processHandle, 
		moduleHandle
	);

	std::cout 
		<< "steamclient.dll @ " 
		<< std::hex
		<< reinterpret_cast<uintptr_t>(moduleHandle)
		<< " -> "
		<< std::hex
		<< reinterpret_cast<uintptr_t>(moduleHandle) + moduleSize
		<< std::endl;

	auto patchAddress = GetPatchAddress(
		processHandle, 
		reinterpret_cast<uintptr_t>(moduleHandle),
		moduleSize
	);

	std::cout
		<< "instruction @ "
		<< std::hex
		<< patchAddress
		<< std::endl;

	if (WritePatch(
		processHandle,
		reinterpret_cast<uintptr_t>(moduleHandle),
		moduleSize,
		patchAddress
	))
	{
		std::cout << "Successfully patched!" << std::endl;
	}
	else
	{
		std::cout << "Something failed!" << std::endl;
	}

	std::getchar();

	return 0;
}
