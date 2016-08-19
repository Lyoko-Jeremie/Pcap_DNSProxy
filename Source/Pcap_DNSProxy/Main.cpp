// This code is part of Pcap_DNSProxy
// A local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2016 Chengr28
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


#include "Main.h"

//The Main function of program
#if defined(PLATFORM_WIN)
int wmain(
	int argc, 
	wchar_t* argv[])
{
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
int main(
	int argc, 
	char *argv[])
{
#endif
//Get commands.
	if (argc > 0)
	{
		if (!ReadCommands(argc, argv))
			return EXIT_SUCCESS;
	}
	else {
		return EXIT_FAILURE;
	}

//Read configuration file.
	if (!ReadParameter(true))
		return EXIT_FAILURE;

//DNSCurve initialization
#if defined(ENABLE_LIBSODIUM)
	if (Parameter.IsDNSCurve)
	{
		DNSCurveParameterModificating.SetToMonitorItem();

	//Encryption mode initialization
		if (DNSCurveParameter.IsEncryption)
			DNSCurveInit();
	}
#endif

//Mark Local DNS address to PTR Records, read Parameter(Monitor mode), IPFilter and Hosts.
	ParameterModificating.SetToMonitorItem();
	std::thread NetworkInformationMonitorThread(std::bind(NetworkInformationMonitor));
	NetworkInformationMonitorThread.detach();
	if (!GlobalRunningStatus.FileList_IPFilter->empty())
	{
		std::thread ReadParameterThread(std::bind(ReadParameter, false));
		ReadParameterThread.detach();
	}
	if (!GlobalRunningStatus.FileList_Hosts->empty())
	{
		std::thread ReadHostsThread(std::bind(ReadHosts));
		ReadHostsThread.detach();
	}
	if (Parameter.OperationMode == LISTEN_MODE_CUSTOM || Parameter.DataCheck_Blacklist || Parameter.LocalRouting)
	{
		std::thread ReadIPFilterThread(std::bind(ReadIPFilter));
		ReadIPFilterThread.detach();
	}

#if defined(PLATFORM_WIN)
//Service initialization and start service.
	SERVICE_TABLE_ENTRYW ServiceTable[]{{SYSTEM_SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain}, {nullptr, nullptr}};
	if (!StartServiceCtrlDispatcherW(ServiceTable))
	{
		auto ErrorCode = GetLastError();
		
	//Print to screen.
		std::unique_lock<std::mutex> ScreenMutex(ScreenLock);
		PrintToScreen(false, L"System Error: Service start error, error code is %lu.\n", ErrorCode);
		PrintToScreen(false, L"System Error: Program will continue to run in console mode.\n");
		PrintToScreen(false, L"Please ignore these error messages if you want to run in console mode.\n\n");
		ScreenMutex.unlock();

	//Handle the system signal and start all monitors.
		SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE);
		if (!MonitorInit())
			return EXIT_FAILURE;
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (!MonitorInit())
		return EXIT_FAILURE;
#endif

	return EXIT_SUCCESS;
}

//Read commands from main program
#if defined(PLATFORM_WIN)
bool ReadCommands(
	int argc, 
	wchar_t *argv[])
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
bool ReadCommands(
	int argc, 
	char *argv[])
#endif
{
//Path initialization
#if defined(PLATFORM_WIN)
	if (!FileNameInit(argv[0]))
		return false;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	char FileName[PATH_MAX + 1U] = {0};
	if (getcwd(FileName, PATH_MAX) == nullptr)
	{
		PrintToScreen(true, L"Path initialization error.\n");
		return false;
	}
	if (!FileNameInit(FileName))
		return false;
#endif

//Screen output buffer setting
	_set_errno(0);
	if (setvbuf(stderr, NULL, _IONBF, 0) != 0)
	{
		auto ErrorCode = errno;
		PrintToScreen(true, L"Screen output buffer setting error, error code is %d.\n", ErrorCode);
		PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Screen output buffer setting error", ErrorCode, nullptr, 0);

		return false;
	}

//Winsock initialization
#if defined(PLATFORM_WIN)
	WSAData WSAInitialization;
	memset(&WSAInitialization, 0, sizeof(WSAInitialization));
	if (WSAStartup(MAKEWORD(WINSOCK_VERSION_HIGH, WINSOCK_VERSION_LOW), &WSAInitialization) != 0 || //WinSock 2.2
		LOBYTE(WSAInitialization.wVersion) != WINSOCK_VERSION_LOW || HIBYTE(WSAInitialization.wVersion) != WINSOCK_VERSION_HIGH)
	{
		auto ErrorCode = WSAGetLastError();
		PrintToScreen(true, L"Winsock initialization error, error code is %d.\n", ErrorCode);
		PrintError(LOG_LEVEL_1, LOG_ERROR_NETWORK, L"Winsock initialization error", ErrorCode, nullptr, 0);

		return false;
	}
	else {
		GlobalRunningStatus.Initialization_WinSock = true;
	}

//Read commands.
	std::wstring Commands;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::string Commands;
#endif
	for (size_t Index = 1U;(int)Index < argc;++Index)
	{
		Commands = argv[Index];

	//Flush DNS Cache from user.
		if (Commands == COMMAND_FLUSH_DNS)
		{
		//Remove single domain cache.
			if (argc > 2)
			{
			#if defined(PLATFORM_WIN)
				if (wcsnlen_s(argv[2U], FILE_BUFFER_SIZE) <= DOMAIN_MINSIZE && wcsnlen_s(argv[2U], FILE_BUFFER_SIZE) >= DOMAIN_MAXSIZE)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (strnlen(argv[2U], FILE_BUFFER_SIZE) <= DOMAIN_MINSIZE && strnlen(argv[2U], FILE_BUFFER_SIZE) >= DOMAIN_MAXSIZE)
			#endif
				{
					PrintToScreen(true, L"Domain name parameter is too long.\n");
				}
				else {
				#if defined(PLATFORM_WIN)
					FlushDNSMailSlotSender(argv[2U]);
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					FlushDNSFIFOSender((const uint8_t *)argv[2U]);
				#endif
				}
			}
		//Flush all DNS cache.
			else {
			#if defined(PLATFORM_WIN)
				FlushDNSMailSlotSender(nullptr);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				FlushDNSFIFOSender(nullptr);
			#endif
			}

			return false;
		}
	//Windows Firewall Test in first start.
	#if defined(PLATFORM_WIN)
		else if (Commands == COMMAND_FIREWALL_TEST)
		{
			if (!FirewallTest(AF_INET6) && !FirewallTest(AF_INET))
			{
				auto ErrorCode = WSAGetLastError();
				PrintToScreen(true, L"Windows Firewall Test error, error code is %d.\n", ErrorCode);
				PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Windows Firewall Test error", ErrorCode, nullptr, 0);
			}
			else {
				PrintToScreen(true, L"Windows Firewall was tested successfully.\n");
			}

			return false;
		}
	#endif
	//Set system daemon.
	#if defined(PLATFORM_LINUX)
		else if (Commands == COMMAND_DISABLE_DAEMON)
		{
			GlobalRunningStatus.IsDaemon = false;
		}
	#endif
	//Print current version.
		else if (Commands == COMMAND_LONG_PRINT_VERSION || Commands == COMMAND_SHORT_PRINT_VERSION)
		{
			std::lock_guard<std::mutex> ScreenMutex(ScreenLock);
			PrintToScreen(false, L"Pcap_DNSProxy ");
			PrintToScreen(false, FULL_VERSION);
			PrintToScreen(false, L"\n");

			return false;
		}
	//Print library version.
		else if (Commands == COMMAND_LIB_VERSION)
		{
		#if (defined(ENABLE_LIBSODIUM) || defined(ENABLE_PCAP))
			std::wstring LibVersion;

			//LibSodium version
			#if defined(ENABLE_LIBSODIUM)
				if (MBSToWCSString((const uint8_t *)SODIUM_VERSION_STRING, strlen(SODIUM_VERSION_STRING), LibVersion))
					PrintToScreen(true, L"LibSodium version %ls\n", LibVersion.c_str());
				else 
					PrintToScreen(true, L"Convert multiple byte or wide char string error.\n");
			#endif

			//WinPcap or LibPcap version
			#if defined(ENABLE_PCAP)
				if (MBSToWCSString((const uint8_t *)pcap_lib_version(), strlen(pcap_lib_version()), LibVersion))
					PrintToScreen(true, L"%ls\n", LibVersion.c_str());
				else 
					PrintToScreen(true, L"Convert multiple byte or wide char string error.\n");
			#endif
		#else
			PrintToScreen(true, L"No any available libraries.\n");
		#endif

			return false;
		}
	//Print help messages.
		else if (Commands == COMMAND_LONG_HELP || Commands == COMMAND_SHORT_HELP)
		{
			std::lock_guard<std::mutex> ScreenMutex(ScreenLock);
			PrintToScreen(false, L"Pcap_DNSProxy ");
			PrintToScreen(false, FULL_VERSION);
		#if defined(PLATFORM_WIN)
			PrintToScreen(false, L"(Windows)\n");
		#elif defined(PLATFORM_OPENWRT)
			PrintToScreen(false, L"(OpenWrt)\n");
		#elif defined(PLATFORM_LINUX)
			PrintToScreen(false, L"(Linux)\n");
		#elif defined(PLATFORM_MACX)
			PrintToScreen(false, L"(Mac)\n");
		#endif
			PrintToScreen(false, COPYRIGHT_MESSAGE);
			PrintToScreen(false, L"\nUsage: Please visit ReadMe... files in Documents folder.\n");
			PrintToScreen(false, L"   -v/--version:          Print current version on screen.\n");
			PrintToScreen(false, L"   --lib-version:         Print current version of libraries on screen.\n");
			PrintToScreen(false, L"   -h/--help:             Print help messages on screen.\n");
			PrintToScreen(false, L"   --flush-dns:           Flush all DNS cache in program and system immediately.\n");
			PrintToScreen(false, L"   --flush-dns Domain:    Flush cache of Domain in program and all in system immediately.\n");
		#if defined(PLATFORM_WIN)
			PrintToScreen(false, L"   --first-setup:         Test local firewall.\n");
		#endif
			PrintToScreen(false, L"   -c/--config-file Path: Set path of configuration file.\n");
			PrintToScreen(false, L"   --keypair-generator:   Generate a DNSCurve/DNSCrypt keypair.\n");
		#if defined(PLATFORM_LINUX)
			PrintToScreen(false, L"   --disable-daemon:      Disable daemon mode.\n");
		#endif

			return false;
		}
	//Set working directory from commands.
		else if (Commands == COMMAND_LONG_SET_PATH || Commands == COMMAND_SHORT_SET_PATH)
		{
		//Commands check
			if ((int)Index + 1 >= argc)
			{
				PrintToScreen(true, L"Commands error.\n");
				PrintError(LOG_LEVEL_1, LOG_ERROR_SYSTEM, L"Commands error", 0, nullptr, 0);

				return false;
			}
			else {
				++Index;
				Commands = argv[Index];

			//Path check.
				if (Commands.length() > MAX_PATH)
				{
					PrintToScreen(true, L"Commands error.\n");
					PrintError(LOG_LEVEL_1, LOG_ERROR_SYSTEM, L"Commands error", 0, nullptr, 0);

					return false;
				}
				else {
					if (!FileNameInit(Commands.c_str()))
						return false;
				}
			}
		}
	//DNSCurve/DNSCrypt KeyPairGenerator
		else if (Commands == COMMAND_KEYPAIR_GENERATOR)
		{
		//File handle initialization
		#if defined(ENABLE_LIBSODIUM)
			FILE *FileHandle = nullptr;
			#if defined(PLATFORM_WIN)
				_wfopen_s(&FileHandle, L"KeyPair.txt", L"w+,ccs=UTF-8");
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				FileHandle = fopen("KeyPair.txt", "w+");
			#endif
			
		//Print keypair to file.
			if (FileHandle != nullptr)
			{
			//Initialization and make keypair.
				std::shared_ptr<uint8_t> Buffer(new uint8_t[DNSCRYPT_KEYPAIR_MESSAGE_LEN]());
				sodium_memzero(Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN);
				DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> SecretKey(crypto_box_SECRETKEYBYTES);
				uint8_t PublicKey[crypto_box_PUBLICKEYBYTES] = {0};
				size_t InnerIndex = 0;

			//Generator a ramdon keypair and write public key.
				if (crypto_box_keypair(PublicKey, SecretKey.Buffer) != 0 || 
					sodium_bin2hex((char *)Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN, PublicKey, crypto_box_PUBLICKEYBYTES) == nullptr)
				{
					fclose(FileHandle);
					PrintToScreen(true, L"Create ramdom key pair failed, please try again.\n");

					return false;
				}
				CaseConvert(true, Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN);
				fwprintf_s(FileHandle, L"Client Public Key = ");
				for (InnerIndex = 0;InnerIndex < strnlen_s((const char *)Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN);++InnerIndex)
				{
					if (InnerIndex > 0 && InnerIndex % DNSCRYPT_KEYPAIR_INTERVAL == 0 && 
						InnerIndex + 1U < strnlen_s((const char *)Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN))
							fwprintf_s(FileHandle, L":");

					fwprintf_s(FileHandle, L"%c", Buffer.get()[InnerIndex]);
				}
				sodium_memzero(Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN);
				fwprintf_s(FileHandle, L"\n");

			//Write secret key.
				if (sodium_bin2hex((char *)Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN, SecretKey.Buffer, crypto_box_SECRETKEYBYTES) == nullptr)
				{
					fclose(FileHandle);
					PrintToScreen(true, L"Create ramdom key pair failed, please try again.\n");

					return false;
				}
				CaseConvert(true, Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN);
				fwprintf_s(FileHandle, L"Client Secret Key = ");
				for (InnerIndex = 0;InnerIndex < strnlen_s((const char *)Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN);++InnerIndex)
				{
					if (InnerIndex > 0 && InnerIndex % DNSCRYPT_KEYPAIR_INTERVAL == 0 && 
						InnerIndex + 1U < strnlen_s((const char *)Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN))
							fwprintf_s(FileHandle, L":");

					fwprintf_s(FileHandle, L"%c", Buffer.get()[InnerIndex]);
				}
				fwprintf_s(FileHandle, L"\n");

			//Close file.
				fclose(FileHandle);
				PrintToScreen(true, L"DNSCurve/DNSCrypt keypair was generated successfully.\n");
			}
			else {
				PrintToScreen(true, L"Cannot create target file(KeyPair.txt).\n");
			}
		#else
			PrintToScreen(true, L"LibSodium is disable.\n");
		#endif

			return false;
		}
	}

//Set system daemon.
#if defined(PLATFORM_LINUX)
	if (GlobalRunningStatus.IsDaemon && daemon(0, 0) == RETURN_ERROR)
	{
		PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Set system daemon error", 0, nullptr, 0);
		return false;
	}
#endif

	return true;
}

//Get path of program from the main function parameter and Winsock initialization
#if defined(PLATFORM_WIN)
bool FileNameInit(
	const wchar_t *OriginalPath)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
bool FileNameInit(
	const char *OriginalPath)
#endif
{
//Path process
#if defined(PLATFORM_WIN)
	GlobalRunningStatus.Path_Global->clear();
	GlobalRunningStatus.Path_Global->push_back(OriginalPath);
	GlobalRunningStatus.Path_Global->front().erase(GlobalRunningStatus.Path_Global->front().rfind(L"\\") + 1U);
	for (size_t Index = 0;Index < GlobalRunningStatus.Path_Global->front().length();++Index)
	{
		if ((GlobalRunningStatus.Path_Global->front()).at(Index) == L'\\')
		{
			GlobalRunningStatus.Path_Global->front().insert(Index, L"\\");
			++Index;
		}
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	GlobalRunningStatus.sPath_Global->clear();
	GlobalRunningStatus.sPath_Global->push_back(OriginalPath);
	GlobalRunningStatus.sPath_Global->front().append("/");
	std::wstring StringTemp;
	if (!MBSToWCSString((const uint8_t *)OriginalPath, PATH_MAX + 1U, StringTemp))
		return false;
	StringTemp.append(L"/");
	GlobalRunningStatus.Path_Global->clear();
	GlobalRunningStatus.Path_Global->push_back(StringTemp);
	StringTemp.clear();
#endif

//Get path of error/running status log file and mark start time.
	GlobalRunningStatus.Path_ErrorLog->clear();
	*GlobalRunningStatus.Path_ErrorLog = GlobalRunningStatus.Path_Global->front();
	GlobalRunningStatus.Path_ErrorLog->append(ERROR_LOG_FILE_NAME);
#if defined(PLATFORM_WIN)
	GlobalRunningStatus.IsConsole = true;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	GlobalRunningStatus.sPath_ErrorLog->clear();
	*GlobalRunningStatus.sPath_ErrorLog = GlobalRunningStatus.sPath_Global->front();
	GlobalRunningStatus.sPath_ErrorLog->append(ERROR_LOG_FILE_NAME_STRING);
#endif
	GlobalRunningStatus.StartupTime = time(nullptr);

	return true;
}

#if defined(PLATFORM_WIN)
//Windows Firewall Test
bool FirewallTest(
	const uint16_t Protocol)
{
//Ramdom number distribution initialization
	std::uniform_int_distribution<uint16_t> RamdomDistribution(DYNAMIC_MIN_PORT, UINT16_MAX - 1U);
	sockaddr_storage SockAddr;
	memset(&SockAddr, 0, sizeof(SockAddr));
	SYSTEM_SOCKET FirewallSocket = 0;
	size_t Index = 0;

//IPv6
	if (Protocol == AF_INET6)
	{
		((PSOCKADDR_IN6)&SockAddr)->sin6_addr = in6addr_any;
		((PSOCKADDR_IN6)&SockAddr)->sin6_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
		SockAddr.ss_family = AF_INET6;
		FirewallSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	//Bind local socket.
		if (!SocketSetting(FirewallSocket, SOCKET_SETTING_INVALID_CHECK, true, nullptr))
		{
			return false;
		}
		else if (bind(FirewallSocket, (PSOCKADDR)&SockAddr, sizeof(sockaddr_in6)) == SOCKET_ERROR)
		{
			((PSOCKADDR_IN6)&SockAddr)->sin6_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
			while (bind(FirewallSocket, (PSOCKADDR)&SockAddr, sizeof(sockaddr_in6)) == SOCKET_ERROR)
			{
				if (Index < LOOP_MAX_TIMES && WSAGetLastError() == WSAEADDRINUSE)
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
					++Index;
				}
				else {
					SocketSetting(FirewallSocket, SOCKET_SETTING_CLOSE, false, nullptr);
					return false;
				}
			}
		}
	}
//IPv4
	else if (Protocol == AF_INET)
	{
		((PSOCKADDR_IN)&SockAddr)->sin_addr.s_addr = INADDR_ANY;
		((PSOCKADDR_IN)&SockAddr)->sin_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
		SockAddr.ss_family = AF_INET;
		FirewallSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	//Bind local socket.
		if (!SocketSetting(FirewallSocket, SOCKET_SETTING_INVALID_CHECK, true, nullptr))
		{
			return false;
		}
		else if (bind(FirewallSocket, (PSOCKADDR)&SockAddr, sizeof(sockaddr_in)) == SOCKET_ERROR)
		{
			((PSOCKADDR_IN)&SockAddr)->sin_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
			while (bind(FirewallSocket, (PSOCKADDR)&SockAddr, sizeof(sockaddr_in)) == SOCKET_ERROR)
			{
				if (Index < LOOP_MAX_TIMES && WSAGetLastError() == WSAEADDRINUSE)
				{
					((PSOCKADDR_IN)&SockAddr)->sin_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
					++Index;
				}
				else {
					SocketSetting(FirewallSocket, SOCKET_SETTING_CLOSE, false, nullptr);
					return false;
				}
			}
		}
	}
	else {
		return false;
	}

//Close socket.
	SocketSetting(FirewallSocket, SOCKET_SETTING_CLOSE, false, nullptr);
	return true;
}
#endif
