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

//Read commands from main process
#if defined(PLATFORM_WIN)
bool ReadCommands(
	int argc, 
	wchar_t *argv[])
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
bool ReadCommands(
	int argc, 
	char *argv[])
#endif
{
//Path initialization
#if defined(PLATFORM_WIN)
	if (!FileNameInit(argv[0]))
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	char FileName[PATH_MAX + 1U]{0};
	if (getcwd(FileName, PATH_MAX) == nullptr)
	{
		PrintToScreen(true, L"[System Error] Path initialization error.\n");
		return false;
	}
	if (!FileNameInit(FileName))
#endif
		return false;

//Screen output buffer settings
	_set_errno(0);
	if (setvbuf(stderr, nullptr, _IONBF, 0) != 0)
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_SYSTEM, L"Screen output buffer setting error", errno, nullptr, 0);
		return false;
	}

//Winsock initialization
#if defined(PLATFORM_WIN)
	WSAData WSAInitialization;
	memset(&WSAInitialization, 0, sizeof(WSAInitialization));
	if (WSAStartup(
			MAKEWORD(WINSOCK_VERSION_HIGH, WINSOCK_VERSION_LOW), //WinSock 2.2
			&WSAInitialization) != 0 || 
		LOBYTE(WSAInitialization.wVersion) != WINSOCK_VERSION_LOW || HIBYTE(WSAInitialization.wVersion) != WINSOCK_VERSION_HIGH)
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_NETWORK, L"Winsock initialization error", WSAGetLastError(), nullptr, 0);
		return false;
	}
	else {
		GlobalRunningStatus.IsWinSockInitialized = true;
	}

//Read commands.
	std::wstring Commands;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	std::string Commands;
#endif
	for (size_t Index = 1U;(int)Index < argc;++Index)
	{
		Commands = argv[Index];

	//Set working directory from commands.
		if (Commands == COMMAND_LONG_SET_PATH || Commands == COMMAND_SHORT_SET_PATH)
		{
		//Commands check
			if ((int)Index + 1 >= argc)
			{
				PrintError(LOG_LEVEL_1, LOG_ERROR_SYSTEM, L"Commands error", 0, nullptr, 0);
				return false;
			}
			else {
				++Index;
				Commands = argv[Index];

			//Path check.
				if (Commands.length() > MAX_PATH)
				{
					PrintError(LOG_LEVEL_1, LOG_ERROR_SYSTEM, L"Commands error", 0, nullptr, 0);
					return false;
				}
				else {
					if (!FileNameInit(Commands.c_str()))
						return false;
				}
			}
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
		#elif defined(PLATFORM_MACOS)
			PrintToScreen(false, L"(macOS)\n");
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
	//Print current version.
		else if (Commands == COMMAND_LONG_PRINT_VERSION || Commands == COMMAND_SHORT_PRINT_VERSION)
		{
			std::lock_guard<std::mutex> ScreenMutex(ScreenLock);
			PrintToScreen(false, L"Pcap_DNSProxy ");
			PrintToScreen(false, FULL_VERSION);
			PrintToScreen(false, L"\n");

			return false;
		}
	//Flush DNS Cache from user.
		else if (Commands == COMMAND_FLUSH_DNS)
		{
		//Remove single domain cache.
			if (argc > 2)
			{
			#if defined(PLATFORM_WIN)
				if (wcsnlen_s(argv[2U], FILE_BUFFER_SIZE) <= DOMAIN_MINSIZE && wcsnlen_s(argv[2U], FILE_BUFFER_SIZE) >= DOMAIN_MAXSIZE)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (strnlen(argv[2U], FILE_BUFFER_SIZE) <= DOMAIN_MINSIZE && strnlen(argv[2U], FILE_BUFFER_SIZE) >= DOMAIN_MAXSIZE)
			#endif
				{
					PrintToScreen(true, L"[Parameter Error] Domain name parameter error.\n");
				}
				else {
				#if defined(PLATFORM_WIN)
					Flush_DNS_MailSlotSender(argv[2U]);
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
					Flush_DNS_FIFO_Sender((const uint8_t *)argv[2U]);
				#endif
				}
			}
		//Flush all DNS cache.
			else {
			#if defined(PLATFORM_WIN)
				Flush_DNS_MailSlotSender(nullptr);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				Flush_DNS_FIFO_Sender(nullptr);
			#endif
			}

			return false;
		}
	//DNSCurve/DNSCrypt KeyPairGenerator
		else if (Commands == COMMAND_KEYPAIR_GENERATOR)
		{
		//File handle initialization
		#if defined(ENABLE_LIBSODIUM)
			FILE *FileHandle = nullptr;
			#if defined(PLATFORM_WIN)
				_wfopen_s(&FileHandle, L"KeyPair.txt", L"w+,ccs=UTF-8");
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				FileHandle = fopen("KeyPair.txt", "w+");
			#endif

		//Print keypair to file.
			if (FileHandle != nullptr)
			{
			//Initialization and make keypair.
				std::shared_ptr<uint8_t> Buffer(new uint8_t[DNSCRYPT_KEYPAIR_MESSAGE_LEN]());
				sodium_memzero(Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN);
				DNSCURVE_HEAP_BUFFER_TABLE<uint8_t> SecretKey(crypto_box_SECRETKEYBYTES);
				uint8_t PublicKey[crypto_box_PUBLICKEYBYTES]{0};
				size_t InnerIndex = 0;

			//Generator a ramdon keypair and write public key.
				if (crypto_box_keypair(
						PublicKey, 
						SecretKey.Buffer) != 0 || 
					sodium_bin2hex((char *)Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN, PublicKey, crypto_box_PUBLICKEYBYTES) == nullptr)
				{
					fclose(FileHandle);
					PrintToScreen(true, L"[System Error] Create ramdom key pair failed, please try again.\n");

					return false;
				}
				CaseConvert(Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN, true);
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
					PrintToScreen(true, L"[System Error] Create ramdom key pair failed, please try again.\n");

					return false;
				}
				CaseConvert(Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN, true);
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
				PrintToScreen(true, L"[Notice] DNSCurve/DNSCrypt keypair was generated successfully.\n");
			}
			else {
				PrintToScreen(true, L"[System Error] Cannot create target file(KeyPair.txt).\n");
			}
		#else
			PrintToScreen(true, L"[Notice] LibSodium is disable.\n");
		#endif

			return false;
		}
	//Print library version.
		else if (Commands == COMMAND_LIB_VERSION)
		{
		#if (defined(ENABLE_LIBSODIUM) || defined(ENABLE_PCAP) || defined(ENABLE_TLS))
			std::wstring LibVersion;

			//LibSodium version
			#if defined(ENABLE_LIBSODIUM)
				if (MBS_To_WCS_String((const uint8_t *)sodium_version_string(), strlen(sodium_version_string()), LibVersion))
					PrintToScreen(true, L"LibSodium version %ls\n", LibVersion.c_str());
				else 
					PrintToScreen(true, L"[System Error] Convert multiple byte or wide char string error.\n");
			#endif

			//WinPcap or LibPcap version
			#if defined(ENABLE_PCAP)
				if (MBS_To_WCS_String((const uint8_t *)pcap_lib_version(), strlen(pcap_lib_version()), LibVersion))
					PrintToScreen(true, L"%ls\n", LibVersion.c_str());
				else 
					PrintToScreen(true, L"[System Error] Convert multiple byte or wide char string error.\n");
			#endif

			//OpenSSL version
			#if defined(ENABLE_TLS)
				#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1_0 //OpenSSL version after 1.1.0
					if (MBS_To_WCS_String((const uint8_t *)OpenSSL_version(OPENSSL_VERSION), strnlen(OpenSSL_version(OPENSSL_VERSION), OPENSSL_STATIC_BUFFER_SIZE), LibVersion))
				#else //OpenSSL version before 1.1.0
					if (MBS_To_WCS_String((const uint8_t *)SSLeay_version(SSLEAY_VERSION), strnlen(SSLeay_version(SSLEAY_VERSION), OPENSSL_STATIC_BUFFER_SIZE), LibVersion))
				#endif
						PrintToScreen(true, L"%ls\n", LibVersion.c_str());
					else 
						PrintToScreen(true, L"[System Error] Convert multiple byte or wide char string error.\n");
				#endif
			#endif
		#else
			PrintToScreen(true, L"[Notice] No any available libraries.\n");
		#endif

			return false;
		}
	#if defined(PLATFORM_LINUX)
	//Set system daemon.
		else if (Commands == COMMAND_DISABLE_DAEMON)
		{
			GlobalRunningStatus.IsDaemon = false;
		}
	#elif defined(PLATFORM_WIN)
	//Windows Firewall Test in first start.
		else if (Commands == COMMAND_FIREWALL_TEST)
		{
			ssize_t ErrorCode = 0;
			if (!FirewallTest(AF_INET6, ErrorCode) && !FirewallTest(AF_INET, ErrorCode))
				PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Windows Firewall Test error", ErrorCode, nullptr, 0);
			else 
				PrintToScreen(true, L"[Notice] Windows Firewall was tested successfully.\n");

			return false;
		}
	#endif
	}

//Set system daemon.
#if defined(PLATFORM_LINUX)
	if (GlobalRunningStatus.IsDaemon && daemon(0, 0) == RETURN_ERROR)
	{
		PrintError(LOG_LEVEL_1, LOG_ERROR_SYSTEM, L"Set system daemon error", 0, nullptr, 0);
		return false;
	}
#endif

	return true;
}

//Get path of program from the main function parameter and Winsock initialization
#if defined(PLATFORM_WIN)
bool FileNameInit(
	const wchar_t * const OriginalPath)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
bool FileNameInit(
	const char * const OriginalPath)
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
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	GlobalRunningStatus.sPath_Global->clear();
	GlobalRunningStatus.sPath_Global->push_back(OriginalPath);
	GlobalRunningStatus.sPath_Global->front().append("/");
	std::wstring StringTemp;
	if (!MBS_To_WCS_String((const uint8_t *)OriginalPath, PATH_MAX + 1U, StringTemp))
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
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	GlobalRunningStatus.sPath_ErrorLog->clear();
	*GlobalRunningStatus.sPath_ErrorLog = GlobalRunningStatus.sPath_Global->front();
	GlobalRunningStatus.sPath_ErrorLog->append(ERROR_LOG_FILE_NAME_STRING);
#endif
	GlobalRunningStatus.StartupTime = time(nullptr);

	return true;
}
