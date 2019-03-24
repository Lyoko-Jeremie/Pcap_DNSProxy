// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on packet capturing
// Copyright (C) 2012-2019 Chengr28
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


#include "Environment.h"

#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//Increase time with milliseconds
uint64_t IncreaseMillisecondTime(
	const uint64_t CurrentTime, 
	const timeval IncreaseTime)
{
	return CurrentTime + IncreaseTime.tv_sec * SECOND_TO_MILLISECOND + IncreaseTime.tv_usec / MICROSECOND_TO_MILLISECOND;
}

//Get current system time
uint64_t GetCurrentSystemTime(
	void)
{
//Initialization
	timeval CurrentTime;
	memset(&CurrentTime, 0, sizeof(CurrentTime));

//Get time value from system.
	if (gettimeofday(&CurrentTime, nullptr) == 0)
		return IncreaseMillisecondTime(0, CurrentTime);

	return 0;
}
#endif

//Check runtime library version
bool CheckLibraryVersion(
	void)
{
//LibEvent
	if (event_get_version_number() < VERSION_REQUIRE_LIBEVENT)
	{
		PrintToScreen(true, false, L"[System Error] The version of LibEvent is too old.\n");
		return false;
	}

//LibSodium
#if defined(ENABLE_LIBSODIUM)
	if (!(sodium_library_version_major() >= VERSION_REQUIRE_LIBSODIUM_MAJOR && sodium_library_version_minor() >= VERSION_REQUIRE_LIBSODIUM_MINOR))
	{
		PrintToScreen(true, false, L"[System Error] The version of LibSodium is too old.\n");
		return false;
	}
#endif

//Npcap or Libpcap
//No more Npcap and LibPcap library linking version check.

//OpenSSL
#if defined(ENABLE_TLS)
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//No more OpenSSL library linking version check in below 1.1.0.
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1_0
	if (OpenSSL_version_num() < VERSION_REQUIRE_OPENSSL)
	{
		PrintToScreen(true, false, L"[System Error] The version of OpenSSL is too old.\n");
		return false;
	}
#endif
#endif
#endif

	return true;
}

//Load path and file name
bool LoadPathFileName(
	void)
{
#if defined(PLATFORM_WIN)
//Path initialization
	auto FilePathBuffer = std::make_unique<wchar_t[]>(PATH_FILE_NAME_SIZE + MEMORY_RESERVED_BYTES);
	wmemset(FilePathBuffer.get(), 0, PATH_FILE_NAME_SIZE + MEMORY_RESERVED_BYTES);
	std::wstring FilePathString;
	size_t BufferSize = PATH_FILE_NAME_SIZE;

//Get full module file name which is the location of program and not its working directory.
	while (BufferSize < PATH_FILE_NAME_MAXSIZE)
	{
		const auto ResultValue = GetModuleFileNameW(
			nullptr, 
			FilePathBuffer.get(), 
			static_cast<const DWORD>(BufferSize));

	//Fail to get module name.
		if (ResultValue == 0)
		{
			std::wstring Message(L"[System Error] Path initialization error");
			if (GetLastError() == 0)
			{
				Message.append(L".\n");
				PrintToScreen(true, false, Message.c_str());
			}
			else {
				ErrorCodeToMessage(LOG_ERROR_TYPE::SYSTEM, GetLastError(), Message);
				Message.append(L".\n");
				PrintToScreen(true, false, Message.c_str(), GetLastError());
			}

			return false;
		}
	//Buffer is too small to hold the module name.
		else if (ResultValue == BufferSize)
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				auto FilePathBufferTemp = std::make_unique<wchar_t[]>(BufferSize + PATH_FILE_NAME_SIZE);
				wmemset(FilePathBufferTemp.get(), 0, BufferSize + PATH_FILE_NAME_SIZE);
				std::swap(FilePathBuffer, FilePathBufferTemp);
				BufferSize += PATH_FILE_NAME_SIZE;
			}
		//Hold the whole module name.
			else {
				FilePathString = FilePathBuffer.get();
				break;
			}
		}
	//Hold the whole module name.
		else {
			FilePathString = FilePathBuffer.get();
			break;
		}
	}

//File name initialization
	FilePathBuffer.reset();
	if (BufferSize >= PATH_FILE_NAME_MAXSIZE || !FileNameInit(FilePathString, true, false))
	{
		PrintToScreen(true, false, L"[System Error] Path initialization error.\n");
		return false;
	}
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//Path initialization
	std::string FilePathString;

//Get current working directory.
	auto FilePathBuffer = getcwd(nullptr, 0);
	if (FilePathBuffer == nullptr || strnlen_s(FilePathBuffer, PATH_FILE_NAME_MAXSIZE) == 0)
	{
		std::wstring Message(L"[System Error] Path initialization error");
		if (errno == 0)
		{
			Message.append(L".\n");
			PrintToScreen(true, false, Message.c_str());
		}
		else {
			ErrorCodeToMessage(LOG_ERROR_TYPE::SYSTEM, errno, Message);
			Message.append(L".\n");
			PrintToScreen(true, false, Message.c_str(), errno);
		}

		return false;
	}
	else {
		FilePathString = FilePathBuffer;
		free(FilePathBuffer);
		FilePathBuffer = nullptr;
	}

//File name initialization
// If the current directory is not below the root directory of the current process(e.g., because the process set a new filesystem root
// using chroot(2) without changing its current directory into the new root), then, since Linux 2.6.36, the returned path will be prefixed
// with the string "(unreachable)".
	if (FilePathString.back() != ASCII_SLASH)
		FilePathString.append("/");
	if (FilePathString.compare(0, strlen("(unreachable)"), "(unreachable)") == 0 || 
		!FileNameInit(FilePathString, true, false))
	{
		PrintToScreen(true, false, L"[System Error] Path initialization error.\n");
		return false;
	}
#endif

	return true;
}

#if defined(PLATFORM_WIN)
//Set console codepage.
bool SetConsoleCodepage(
	void)
{
	if (SetConsoleCP(CP_UTF8) == 0 || SetConsoleOutputCP(CP_UTF8) == 0)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SYSTEM, L"Set console codepage error", GetLastError(), nullptr, 0);
		return false;
	}

	return true;
}
#endif

//Set screen to no any buffers
bool SetScreenBuffer(
	void)
{
	_set_errno(0);
	if (setvbuf(stderr, nullptr, _IONBF, 0) != 0)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SYSTEM, L"Screen output buffer settings error", errno, nullptr, 0);
		return false;
	}

	return true;
}

#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX))
//Set program to daemon mode
bool SetProgramDaemon(
	void)
{
	errno = 0;
	if (daemon(0, 0) == RETURN_ERROR)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SYSTEM, L"Set system daemon error", errno, nullptr, 0);
		return false;
	}

	return true;
}
#endif

//Get path of program from the main function parameter and Winsock initialization
#if defined(PLATFORM_WIN)
bool FileNameInit(
	const std::wstring &OriginalPath, 
	const bool IsStartupLoad, 
	const bool IsRewriteLogFile)
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
bool FileNameInit(
	const std::string &OriginalPath, 
	const bool IsStartupLoad, 
	const bool IsRewriteLogFile)
#endif
{
#if defined(PLATFORM_WIN)
//The path is location path with backslash not including module name at the end of this process, like "System:\\xxx\\".
//The path is full path name including module name from file name initialization.
//The path is location path not including module name from set path command.
	GlobalRunningStatus.Path_Global_WCS->clear();
	GlobalRunningStatus.Path_Global_WCS->emplace_back(OriginalPath);
	if (GlobalRunningStatus.Path_Global_WCS->front().rfind(L"\\") == std::wstring::npos)
		return false;
	else if (GlobalRunningStatus.Path_Global_WCS->front().rfind(L"\\") + 1U < GlobalRunningStatus.Path_Global_WCS->front().length())
		GlobalRunningStatus.Path_Global_WCS->front().erase(GlobalRunningStatus.Path_Global_WCS->front().rfind(L"\\") + 1U);
	for (size_t Index = 0;Index < GlobalRunningStatus.Path_Global_WCS->front().length();++Index)
	{
		if (GlobalRunningStatus.Path_Global_WCS->front().at(Index) == (L'\\'))
		{
			GlobalRunningStatus.Path_Global_WCS->front().insert(Index, L"\\");
			++Index;
		}
	}
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//The path is location path with slash not including module name at the end of this process, like "/xxx/".
	GlobalRunningStatus.Path_Global_MBS->clear();
	GlobalRunningStatus.Path_Global_MBS->emplace_back(OriginalPath);
	std::wstring StringTemp;
	if (!MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(OriginalPath.c_str()), PATH_MAX + NULL_TERMINATE_LENGTH, StringTemp))
		return false;
	GlobalRunningStatus.Path_Global_WCS->clear();
	GlobalRunningStatus.Path_Global_WCS->emplace_back(StringTemp);
	StringTemp.clear();
#endif

//Get path of log file.
	if (IsStartupLoad)
	{
	#if defined(PLATFORM_OPENWRT)
	//Set log file to stderr.
		*GlobalRunningStatus.Path_ErrorLog_WCS = L"stderr";
		*GlobalRunningStatus.Path_ErrorLog_MBS = "stderr";
	#else
	//Set log file to program location.
		*GlobalRunningStatus.Path_ErrorLog_WCS = GlobalRunningStatus.Path_Global_WCS->front();
		GlobalRunningStatus.Path_ErrorLog_WCS->append(ERROR_LOG_FILE_NAME_WCS);
	#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		*GlobalRunningStatus.Path_ErrorLog_MBS = GlobalRunningStatus.Path_Global_MBS->front();
		GlobalRunningStatus.Path_ErrorLog_MBS->append(ERROR_LOG_FILE_NAME_MBS);
	#endif
	#endif
	}
	else if (!IsRewriteLogFile)
	{
	//Set log file to program location.
		*GlobalRunningStatus.Path_ErrorLog_WCS = GlobalRunningStatus.Path_Global_WCS->front();
		GlobalRunningStatus.Path_ErrorLog_WCS->append(ERROR_LOG_FILE_NAME_WCS);
	#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		*GlobalRunningStatus.Path_ErrorLog_MBS = GlobalRunningStatus.Path_Global_MBS->front();
		GlobalRunningStatus.Path_ErrorLog_MBS->append(ERROR_LOG_FILE_NAME_MBS);
	#endif
	}

	return true;
}

//Set console status and mark program startup time
bool SetConsoleStartupTime(
	void)
{
//Set console status.
#if defined(PLATFORM_WIN)
	GlobalRunningStatus.IsConsole = true;
#endif

//Mark program startup time.
	GlobalRunningStatus.StartupTime = time(nullptr);
	if (GlobalRunningStatus.StartupTime <= 0)
		return false;

	return true;
}

#if defined(PLATFORM_WIN)
//Load Winsock module
bool LoadWinsock(
	void)
{
//Initialization
	WSAData WSA_StartupData;
	memset(&WSA_StartupData, 0, sizeof(WSA_StartupData));

//Winsock startup
	if (WSAStartup(
			MAKEWORD(WINSOCK_VERSION_BYTE_HIGH, WINSOCK_VERSION_BYTE_LOW), 
			&WSA_StartupData) != 0 || 
		HIBYTE(WSA_StartupData.wVersion) != WINSOCK_VERSION_BYTE_HIGH || LOBYTE(WSA_StartupData.wVersion) != WINSOCK_VERSION_BYTE_LOW)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::NETWORK, L"Winsock initialization error", WSAGetLastError(), nullptr, 0);
		return false;
	}
	else {
		GlobalRunningStatus.IsLoad_WinSock = true;
	}

	return true;
}

//Security attributes and descriptor initialization
bool SystemSecurityInit(
	const ACL * const ACL_Buffer, 
	SECURITY_ATTRIBUTES &SecurityAttributes, 
	SECURITY_DESCRIPTOR &SecurityDescriptor, 
	PSID &SID_Value)
{
//Initialize security descriptor.
	if (InitializeSecurityDescriptor(
			&SecurityDescriptor, 
			SECURITY_DESCRIPTOR_REVISION) == 0 || 
		InitializeAcl(
			const_cast<ACL *>(ACL_Buffer), 
			FILE_BUFFER_SIZE, 
			ACL_REVISION) == 0 || 
		ConvertStringSidToSidW(
			SID_ADMINISTRATORS_GROUP, 
			&SID_Value) == 0 || 
		AddAccessAllowedAce(
			const_cast<ACL *>(ACL_Buffer), 
			ACL_REVISION, 
			GENERIC_ALL, 
			SID_Value) == 0 || 
		SetSecurityDescriptorDacl(
			&SecurityDescriptor, 
			true, 
			const_cast<ACL *>(ACL_Buffer), 
			false) == 0)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Security attributes and descriptor initialization error", GetLastError(), nullptr, 0);
		if (SID_Value != nullptr)
		{
			LocalFree(SID_Value);
			SID_Value = nullptr;
		}

		return false;
	}
	else {
		SecurityAttributes.lpSecurityDescriptor = &SecurityDescriptor;
		SecurityAttributes.bInheritHandle = true;
	}

	return true;
}
#endif

//Process unique check
bool CheckProcessUnique(
	void)
{
#if defined(PLATFORM_WIN)
//System security initialization
	const auto ACL_Buffer = std::make_unique<uint8_t[]>(FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	memset(ACL_Buffer.get(), 0, FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	memset(&GlobalRunningStatus.MutexSecurityAttributes, 0, sizeof(GlobalRunningStatus.MutexSecurityAttributes));
	memset(&GlobalRunningStatus.MutexSecurityDescriptor, 0, sizeof(GlobalRunningStatus.MutexSecurityDescriptor));
	PSID SID_Value = nullptr;
	if (!SystemSecurityInit(reinterpret_cast<const ACL *>(ACL_Buffer.get()), GlobalRunningStatus.MutexSecurityAttributes, GlobalRunningStatus.MutexSecurityDescriptor, SID_Value))
	{
		if (SID_Value != nullptr)
		{
			LocalFree(SID_Value);
			SID_Value = nullptr;
		}

		return false;
	}

//Create mutex handle.
	GlobalRunningStatus.MutexHandle = CreateMutexW(
		&GlobalRunningStatus.MutexSecurityAttributes, 
		FALSE, 
		MUTEX_UNIQUE_NAME);
	if (GlobalRunningStatus.MutexHandle != nullptr)
	{
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Process already exists error", ERROR_ALREADY_EXISTS, nullptr, 0);
			CloseHandle(
				GlobalRunningStatus.MutexHandle);
			GlobalRunningStatus.MutexHandle = nullptr;
			if (SID_Value != nullptr)
			{
				LocalFree(SID_Value);
				SID_Value = nullptr;
			}

			return false;
		}
	}
	else {
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Process already exists error", GetLastError(), nullptr, 0);
		if (SID_Value != nullptr)
		{
			LocalFree(SID_Value);
			SID_Value = nullptr;
		}

		return false;
	}

//Free pointer.
	if (SID_Value != nullptr)
	{
		LocalFree(SID_Value);
		SID_Value = nullptr;
	}
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//Open current directory to make a file mutex handle.
	GlobalRunningStatus.MutexHandle = open(GlobalRunningStatus.Path_Global_MBS->front().c_str(), O_RDONLY | O_NONBLOCK);
	if (GlobalRunningStatus.MutexHandle == RETURN_ERROR)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Process already exists error", errno, nullptr, 0);
		return false;
	}

//Set file mutex handle.
	if (flock(GlobalRunningStatus.MutexHandle, LOCK_EX | LOCK_NB) == RETURN_ERROR)
	{
		close(GlobalRunningStatus.MutexHandle);
		GlobalRunningStatus.MutexHandle = RETURN_ERROR;
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Process already exists error", errno, nullptr, 0);

		return false;
	}
#endif

	return true;
}

//Set system signal handler
bool SetSignalHandler(
	void)
{
#if defined(PLATFORM_WIN)
	if (SetConsoleCtrlHandler(
			reinterpret_cast<PHANDLER_ROUTINE>(HandleSignal), 
			TRUE) == 0)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SYSTEM, L"Set console control handler error", GetLastError(), nullptr, 0);
		return false;
	}
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	errno = 0;
	if (signal(SIGHUP, HandleSignal) == SIG_ERR || 
		signal(SIGINT, HandleSignal) == SIG_ERR || 
		signal(SIGQUIT, HandleSignal) == SIG_ERR || 
		signal(SIGTERM, HandleSignal) == SIG_ERR)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SYSTEM, L"Handle system signals error", errno, nullptr, 0);
		return false;
	}

//Set system signal handler to ignore EPIPE signal when transmission with socket.
	errno = 0;
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SYSTEM, L"Ignore system signal error", errno, nullptr, 0);
		return false;
	}
#endif

	return true;
}

//Handle system signals
#if defined(PLATFORM_WIN)
BOOL WINAPI HandleSignal(
	const DWORD ControlType)
{
//Print to screen.
	if (GlobalRunningStatus.IsConsole)
	{
		switch (ControlType)
		{
		//Handle the CTRL-C signal.
			case CTRL_C_EVENT:
			{
				PrintToScreen(true, false, L"[Notice] Get Control-C.\n");
			}break;
		//Handle the CTRL-Break signal.
			case CTRL_BREAK_EVENT:
			{
				PrintToScreen(true, false, L"[Notice] Get Control-Break.\n");
			}break;
		//Handle other signals which are all closing signal.
			default:
			{
				PrintToScreen(true, false, L"[Notice] Get closing signal.\n");
			}break;
		}
	}

//Try to release all temporary resources.
	ReleaseTemporaryResource(&GlobalRunningStatus);

//Exit process.
	return FALSE;
}
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
void HandleSignal(
	const int SignalType)
{
//Print to screen.
	PrintToScreen(true, false, L"[Notice] Get closing signal.\n");

//Try to release all temporary resources.
	ReleaseTemporaryResource(&GlobalRunningStatus);

//Exit process.
	return;
}
#endif

#if defined(PLATFORM_WIN)
//Firewall test
bool FirewallTest(
	const uint16_t Protocol, 
	ssize_t &ErrorCode)
{
//Initialization
	std::uniform_int_distribution<uint16_t> RandomDistribution(0, 0);
	SOCKET_VALUE_TABLE SocketValue_FirewallTest;
	size_t Index = 0;
	ErrorCode = 0;

//IPv6
	if (Protocol == AF_INET6)
	{
	//Socket value initialization
		if (!SocketValue_FirewallTest.SocketValueInit(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, 0, nullptr, &ErrorCode))
			return false;
		reinterpret_cast<sockaddr_in6 *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin6_addr = in6addr_any;
		GenerateRandomBuffer(&reinterpret_cast<sockaddr_in6 *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin6_port, sizeof(reinterpret_cast<const sockaddr_in6 *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin6_port), &RandomDistribution, 0, 0);

	//Bind local socket.
		while (bind(SocketValue_FirewallTest.ValueSet.front().Socket, reinterpret_cast<const sockaddr *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr), SocketValue_FirewallTest.ValueSet.front().AddrLen) == SOCKET_ERROR)
		{
			if (Index < LOOP_MAX_TIMES && WSAGetLastError() == WSAEADDRINUSE)
			{
				GenerateRandomBuffer(&reinterpret_cast<sockaddr_in6 *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin6_port, sizeof(reinterpret_cast<const sockaddr_in6 *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin6_port), &RandomDistribution, 0, 0);
				++Index;
			}
			else {
				ErrorCode = WSAGetLastError();
				return false;
			}
		}
	}
//IPv4
	else if (Protocol == AF_INET)
	{
	//Socket value initialization
		if (!SocketValue_FirewallTest.SocketValueInit(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, nullptr, &ErrorCode))
			return false;
		reinterpret_cast<sockaddr_in *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin_addr.s_addr = INADDR_ANY;
		GenerateRandomBuffer(&reinterpret_cast<sockaddr_in *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin_port, sizeof(reinterpret_cast<const sockaddr_in *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin_port), &RandomDistribution, 0, 0);

	//Bind local socket.
		while (bind(SocketValue_FirewallTest.ValueSet.front().Socket, reinterpret_cast<const sockaddr *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr), SocketValue_FirewallTest.ValueSet.front().AddrLen) == SOCKET_ERROR)
		{
			if (Index < LOOP_MAX_TIMES && WSAGetLastError() == WSAEADDRINUSE)
			{
				GenerateRandomBuffer(&reinterpret_cast<sockaddr_in *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin_port, sizeof(reinterpret_cast<const sockaddr_in *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin_port), &RandomDistribution, 0, 0);
				++Index;
			}
			else {
				ErrorCode = WSAGetLastError();
				return false;
			}
		}
	}
	else {
		return false;
	}

	return true;
}
#endif
