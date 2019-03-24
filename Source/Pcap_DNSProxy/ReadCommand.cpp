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


#include "ReadCommand.h"

//Read commands
#if defined(PLATFORM_WIN)
bool ReadCommand(
	int argc, 
	wchar_t * argv[])
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
bool ReadCommand(
	int argc, 
	char * argv[])
#endif
{
#if defined(PLATFORM_WIN)
	std::wstring Commands, InsensitiveString;
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	std::string Commands, InsensitiveString;
#endif
	auto IsRewriteLogFile = false;

//Read commands.
	for (size_t Index = 1U;static_cast<const int>(Index) < argc;++Index)
	{
	//Case insensitive
	#if defined(PLATFORM_WIN)
		Commands = argv[Index];
		InsensitiveString = argv[Index];
	#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		Commands = argv[Index];
		InsensitiveString = argv[Index];
	#endif
		CaseConvert(InsensitiveString, false);

	//Set working directory from commands.
		if (InsensitiveString == COMMAND_LONG_SET_PATH || InsensitiveString == COMMAND_SHORT_SET_PATH)
		{
		//Commands check
			if (static_cast<const int>(Index) + 1 >= argc || 
			#if defined(PLATFORM_WIN)
				wcsnlen_s(argv[Index], PATH_FILE_NAME_MAXSIZE) >= PATH_FILE_NAME_MAXSIZE
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				strnlen_s(argv[Index], PATH_FILE_NAME_MAXSIZE) >= PATH_MAX
			#endif
				)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SYSTEM, L"Commands error", 0, nullptr, 0);
				return false;
			}
			else {
				++Index;
				Commands = argv[Index];

			//Path, file name check, and add backslash or slash to the end.
			#if defined(PLATFORM_WIN)
				if (Commands.empty() || Commands.find(L"\\\\") != std::wstring::npos)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SYSTEM, L"Commands error", 0, nullptr, 0);
					return false;
				}
				else if (Commands.back() != ASCII_BACKSLASH)
				{
					Commands.append(L"\\");
				}
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (Commands.empty() || Commands.find("//") != std::string::npos)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SYSTEM, L"Commands error", 0, nullptr, 0);
					return false;
				}
				else if (Commands.back() != ASCII_SLASH)
				{
					Commands.append("/");
				}
			#endif

			//Mark path and file name.
				if (!FileNameInit(Commands, false, IsRewriteLogFile))
				{
					PrintToScreen(true, false, L"[System Error] Path initialization error.\n");
					return false;
				}
			}
		}
	//Print help messages.
		else if (InsensitiveString == COMMAND_LONG_HELP || InsensitiveString == COMMAND_SHORT_HELP)
		{
			std::lock_guard<std::mutex> ScreenMutex((*GlobalRunningStatus.ScreenLock));
			PrintToScreen(false, false, L"Pcap_DNSProxy ");
			PrintToScreen(false, false, VERSION_FULL);
		#if defined(PLATFORM_FREEBSD)
			PrintToScreen(false, false, L"(FreeBSD)\n");
		#elif defined(PLATFORM_OPENWRT)
			PrintToScreen(false, false, L"(OpenWrt)\n");
		#elif defined(PLATFORM_LINUX)
			PrintToScreen(false, false, L"(Linux)\n");
		#elif defined(PLATFORM_MACOS)
			PrintToScreen(false, false, L"(macOS)\n");
		#elif defined(PLATFORM_WIN)
			PrintToScreen(false, false, L"(Windows)\n");
		#endif
			PrintToScreen(false, false, COPYRIGHT_MESSAGE);
			PrintToScreen(false, false, L"\nUsage: Please visit ReadMe.. files in Documents folder.\n");
			PrintToScreen(false, false, L"   --version:             Print current version on screen.\n");
			PrintToScreen(false, false, L"   --lib-version:         Print current version of libraries on screen.\n");
			PrintToScreen(false, false, L"   --help:                Print help messages on screen.\n");
			PrintToScreen(false, false, L"   --log-file Path+Name:  Set path and name of log file.\n");
			PrintToScreen(false, false, L"   --log-file stderr/out: Set output log to stderr or stdout.\n");
			PrintToScreen(false, false, L"   --flush-dns:           Flush all domain cache in program and system immediately.\n");
			PrintToScreen(false, false, L"   --flush-dns Domain:    Flush cache of Domain in program and all in system immediately.\n");
		#if defined(PLATFORM_WIN)
			PrintToScreen(false, false, L"   --firewall-test:       Test system firewall.\n");
		#endif
			PrintToScreen(false, false, L"   --config-path Path:    Set path of configuration file.\n");
		#if defined(ENABLE_LIBSODIUM)
			PrintToScreen(false, false, L"   --keypair-generator:   Generate a DNSCrypt keypair.\n");
		#endif
		#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX))
			PrintToScreen(false, false, L"   --disable-daemon:      Disable daemon mode.\n");
		#endif

			return false;
		}
	//Set log file location from commands.
		else if (InsensitiveString == COMMAND_LONG_LOG_FILE || InsensitiveString == COMMAND_SHORT_LOG_FILE)
		{
		//Commands check
			if (static_cast<const int>(Index) + 1 >= argc || 
			#if defined(PLATFORM_WIN)
				wcsnlen_s(argv[Index], PATH_FILE_NAME_MAXSIZE) >= PATH_FILE_NAME_MAXSIZE
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				strnlen_s(argv[Index], PATH_FILE_NAME_MAXSIZE) >= PATH_MAX + NAME_MAX
			#endif
				)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SYSTEM, L"Commands error", 0, nullptr, 0);
				return false;
			}
			else {
				++Index;
				Commands = argv[Index];

			//Path, file name check and ddd backslash or slash to the end.
			#if defined(PLATFORM_WIN)
				if (Commands.empty() || Commands.find(L"\\\\") != std::wstring::npos)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SYSTEM, L"Commands error", 0, nullptr, 0);
					return false;
				}
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (Commands.empty() || Commands.find("//") != std::string::npos)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SYSTEM, L"Commands error", 0, nullptr, 0);
					return false;
				}
			#endif

			//Mark log path and name.
			#if defined(PLATFORM_WIN)
				*GlobalRunningStatus.Path_ErrorLog_WCS = Commands;
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				*GlobalRunningStatus.Path_ErrorLog_MBS = Commands;
				std::wstring StringTemp;
				if (!MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(Commands.c_str()), PATH_MAX + NAME_MAX + NULL_TERMINATE_LENGTH, StringTemp))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::SYSTEM, L"Commands error", 0, nullptr, 0);
					return false;
				}
				else {
					*GlobalRunningStatus.Path_ErrorLog_WCS = StringTemp;
					StringTemp.clear();
				}
			#endif
				IsRewriteLogFile = true;
			}
		}
	//Print current version.
		else if (InsensitiveString == COMMAND_LONG_PRINT_VERSION || InsensitiveString == COMMAND_SHORT_PRINT_VERSION)
		{
			std::lock_guard<std::mutex> ScreenMutex((*GlobalRunningStatus.ScreenLock));
			PrintToScreen(false, false, L"Pcap_DNSProxy ");
			PrintToScreen(false, false, VERSION_FULL);
			PrintToScreen(false, false, L"\n");

			return false;
		}
	//Flush domain cache from user.
		else if (InsensitiveString == COMMAND_FLUSH_DOMAIN_CACHE)
		{
		//Remove single domain cache.
			if (argc > 2)
			{
			//Domain format check
			#if defined(PLATFORM_WIN)
				if (wcsnlen_s(argv[2U], FILE_BUFFER_SIZE) == 0 || 
					wcsnlen_s(argv[2U], FILE_BUFFER_SIZE) + wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_SPECIFIC) >= FILE_BUFFER_SIZE)
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (strnlen(argv[2U], FILE_BUFFER_SIZE) == 0 || 
					strnlen(argv[2U], FILE_BUFFER_SIZE) + strlen(FLUSH_DOMAIN_PIPE_MESSAGE_SPECIFIC) >= FILE_BUFFER_SIZE)
			#endif
				{
					PrintToScreen(true, false, L"[Parameter Error] Domain name parameter error.\n");
					return false;
				}
				else {
				#if defined(PLATFORM_WIN)
					std::vector<std::wstring> ItemData;
					std::wstring WholeString(argv[2U]);
				#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
					std::vector<std::string> ItemData;
					std::string WholeString(argv[2U]);
				#endif

				//Whole string format check
				#if defined(PLATFORM_WIN)
					if (WholeString.find(L"||") != std::wstring::npos)
				#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
					if (WholeString.find("||") != std::string::npos)
				#endif
					{
						PrintToScreen(true, false, L"[Parameter Error] Domain name parameter error.\n");
						return false;
					}

				//Check all items domain acceptable.
					GetItemFromString(ItemData, WholeString, 0, WholeString.length(), ASCII_VERTICAL, false, false);
					for (const auto &StringItem:ItemData)
					{
						if (!CheckDomainAcceptable(StringItem))
						{
							PrintToScreen(true, false, L"[Parameter Error] Domain name parameter error.\n");
							return false;
						}
					}
				}

			//Send to monitor.
			#if defined(PLATFORM_WIN)
				FlushDomainCache_MailslotSender(argv[2U]);
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				FlushDomainCache_PipeSender(reinterpret_cast<const uint8_t *>(argv[2U]));
			#endif
			}
		//Flush all domain cache.
			else {
			#if defined(PLATFORM_WIN)
				FlushDomainCache_MailslotSender(nullptr);
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				FlushDomainCache_PipeSender(nullptr);
			#endif
			}

			return false;
		}
	//DNSCrypt KeyPairGenerator
	#if defined(ENABLE_LIBSODIUM)
		else if (InsensitiveString == COMMAND_KEYPAIR_GENERATOR)
		{
		//File handle initialization
			FILE *FileHandle = nullptr;
		#if defined(PLATFORM_WIN)
			_wfopen_s(&FileHandle, DNSCRYPT_KEY_PAIR_FILE_NAME, L"w+,ccs=UTF-8");
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			FileHandle = fopen(DNSCRYPT_KEY_PAIR_FILE_NAME, "w+");
		#endif

		//Print keypair to file.
			if (FileHandle != nullptr)
			{
			//Initialization and make keypair.
				const auto Buffer = std::make_unique<uint8_t[]>(DNSCRYPT_KEYPAIR_MESSAGE_LEN + MEMORY_RESERVED_BYTES);
				memset(Buffer.get(), 0, DNSCRYPT_KEYPAIR_MESSAGE_LEN + MEMORY_RESERVED_BYTES);
				DNSCRYPT_HEAP_BUFFER_TABLE<uint8_t> SecretKey(crypto_box_SECRETKEYBYTES);
				std::array<uint8_t, crypto_box_PUBLICKEYBYTES> PublicKey{};
				size_t KeyIndex = 0;

			//Generate a random keypair.
				if (crypto_box_keypair(
						PublicKey.data(), 
						SecretKey.Buffer) != 0 || 
					sodium_bin2hex(
						reinterpret_cast<char *>(Buffer.get()), 
						DNSCRYPT_KEYPAIR_MESSAGE_LEN, 
						PublicKey.data(), 
						crypto_box_PUBLICKEYBYTES) == nullptr)
				{
					fclose(FileHandle);
					PrintToScreen(true, false, L"[System Error] Create random key pair failed, please try again.\n");

					return false;
				}
				else {
					CaseConvert(Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN, true);
					fwprintf_s(FileHandle, L"Client Public Key = ");
				}

			//Write public key.
				for (KeyIndex = 0;KeyIndex < strnlen_s(reinterpret_cast<const char *>(Buffer.get()), DNSCRYPT_KEYPAIR_MESSAGE_LEN);++KeyIndex)
				{
					if (KeyIndex > 0 && KeyIndex % DNSCRYPT_KEYPAIR_INTERVAL == 0 && 
						KeyIndex + 1U < strnlen_s(reinterpret_cast<const char *>(Buffer.get()), DNSCRYPT_KEYPAIR_MESSAGE_LEN))
							fwprintf_s(FileHandle, L":");

					fwprintf_s(FileHandle, L"%c", Buffer.get()[KeyIndex]);
				}

			//Reset buffer.
				memset(Buffer.get(), 0, DNSCRYPT_KEYPAIR_MESSAGE_LEN);
				fwprintf_s(FileHandle, L"\n");

			//Convert secret key.
				if (sodium_bin2hex(
						reinterpret_cast<char *>(Buffer.get()), 
						DNSCRYPT_KEYPAIR_MESSAGE_LEN, 
						SecretKey.Buffer, 
						crypto_box_SECRETKEYBYTES) == nullptr)
				{
					fclose(FileHandle);
					PrintToScreen(true, false, L"[System Error] Create random key pair failed, please try again.\n");

					return false;
				}
				else {
					CaseConvert(Buffer.get(), DNSCRYPT_KEYPAIR_MESSAGE_LEN, true);
					fwprintf_s(FileHandle, L"Client Secret Key = ");
				}

			//Write secret key.
				for (KeyIndex = 0;KeyIndex < strnlen_s(reinterpret_cast<const char *>(Buffer.get()), DNSCRYPT_KEYPAIR_MESSAGE_LEN);++KeyIndex)
				{
					if (KeyIndex > 0 && KeyIndex % DNSCRYPT_KEYPAIR_INTERVAL == 0 && 
						KeyIndex + 1U < strnlen_s(reinterpret_cast<const char *>(Buffer.get()), DNSCRYPT_KEYPAIR_MESSAGE_LEN))
							fwprintf_s(FileHandle, L":");

					fwprintf_s(FileHandle, L"%c", Buffer.get()[KeyIndex]);
				}
				fwprintf_s(FileHandle, L"\n");

			//Close file.
				fclose(FileHandle);
				PrintToScreen(true, false, L"[Notice] DNSCrypt keypair generation is successful.\n");
			}
			else {
				PrintToScreen(true, false, L"[System Error] Cannot create target file(KeyPair.txt).\n");
			}

			return false;
		}
	#endif
	//Print library version.
		else if (InsensitiveString == COMMAND_LIB_VERSION)
		{
		//Initialization
			std::wstring LibVersion;
			char *VersionString = nullptr;

		//LibEvent version
			VersionString = const_cast<char *>(event_get_version());
			if (VersionString != nullptr && MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(VersionString), strlen(VersionString), LibVersion))
				PrintToScreen(true, false, L"LibEvent version %ls\n", LibVersion.c_str());
			else 
				PrintToScreen(true, false, L"[System Error] Convert multiple or wide character string error.\n");

		//LibSodium version
		#if defined(ENABLE_LIBSODIUM)
			VersionString = const_cast<char *>(sodium_version_string());
			if (VersionString != nullptr && MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(VersionString), strlen(VersionString), LibVersion))
				PrintToScreen(true, false, L"LibSodium version %ls\n", LibVersion.c_str());
			else 
				PrintToScreen(true, false, L"[System Error] Convert multiple or wide character string error.\n");
		#endif

		//Npcap or LibPcap version
		#if defined(ENABLE_PCAP)
			VersionString = const_cast<char *>(pcap_lib_version());
			if (VersionString != nullptr && MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(VersionString), strlen(VersionString), LibVersion))
				PrintToScreen(true, false, L"%ls\n", LibVersion.c_str());
			else 
				PrintToScreen(true, false, L"[System Error] Convert multiple or wide character string error.\n");
		#endif

		//OpenSSL version
		#if defined(ENABLE_TLS)
		#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_1_0 //OpenSSL version 1.1.0 and above
			VersionString = const_cast<char *>(OpenSSL_version(OPENSSL_VERSION));
		#else //OpenSSL version below 1.1.0
			VersionString = const_cast<char *>(SSLeay_version(SSLEAY_VERSION));
		#endif
			if (VersionString != nullptr && MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(VersionString), strnlen(VersionString, OPENSSL_STATIC_BUFFER_SIZE), LibVersion))
				PrintToScreen(true, false, L"%ls\n", LibVersion.c_str());
			else 
				PrintToScreen(true, false, L"[System Error] Convert multiple or wide character string error.\n");
		#endif
		#endif

			return false;
		}
	#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX))
	//Set program to daemon mode.
		else if (InsensitiveString == COMMAND_DISABLE_DAEMON)
		{
			GlobalRunningStatus.IsDaemon = false;
		}
	#elif defined(PLATFORM_WIN)
	//Firewall Test
		else if (InsensitiveString == COMMAND_FIREWALL_TEST)
		{
			ssize_t ErrorCode = 0;
			if (!FirewallTest(AF_INET6, ErrorCode) && !FirewallTest(AF_INET, ErrorCode))
				PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::NETWORK, L"Firewall test error", ErrorCode, nullptr, 0);
			else 
				PrintToScreen(true, false, L"[Notice] Firewall test is successful.\n");

			return false;
		}
	#endif
	}

	return true;
}
