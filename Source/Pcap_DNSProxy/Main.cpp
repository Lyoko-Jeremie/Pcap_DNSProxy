// This code is part of Pcap_DNSProxy
// A local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2015 Chengr28
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
	int wmain(int argc, wchar_t* argv[])
{
//Windows XP with SP3 support
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
		GetFunctionPointer(FUNCTION_GETTICKCOUNT64);
		GetFunctionPointer(FUNCTION_INET_NTOP);
	#endif
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	int main(int argc, char *argv[])
{
#endif

//Get parameter.
#if defined(PLATFORM_WIN)
	if (argc > 0)
	{
	//Path initialization and Winsock initialization.
		if (FileNameInit(argv[0]) == EXIT_FAILURE)
			return EXIT_FAILURE;

	//Read parameters.
		if (argc > 1)
		{
			Parameter.Console = true;

		//Windows Firewall Test in first start.
			if (wcsnlen_s(argv[1U], STRING_BUFFER_MAXSIZE) == wcslen(MESSAGE_FIREWALL_TEST) && wcsncmp(argv[1U], MESSAGE_FIREWALL_TEST, wcslen(MESSAGE_FIREWALL_TEST)) == 0 && 
				FirewallTest(AF_INET6) == EXIT_FAILURE && FirewallTest(AF_INET) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_NETWORK, L"Windows Firewall Test error", 0, nullptr, 0);

				WSACleanup();
				return EXIT_FAILURE;
			}

		//Flush DNS Cache from user.
			else if (wcsnlen_s(argv[1U], STRING_BUFFER_MAXSIZE) == wcslen(MESSAGE_FLUSH_DNS) && wcsncmp(argv[1U], MESSAGE_FLUSH_DNS, wcslen(MESSAGE_FLUSH_DNS)) == 0)
			{
				FlushDNSMailSlotSender();
			}

			WSACleanup();
			return EXIT_SUCCESS;
		}
	}
	else {
		return EXIT_FAILURE;
	}

//Set MailSlot Monitor.
	std::thread FlushDNSMailSlotMonitorThread(FlushDNSMailSlotMonitor);
	FlushDNSMailSlotMonitorThread.detach();
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Path initialization
	std::shared_ptr<char> FileName(new char[PATH_MAX + 1U]());
	memset(FileName.get(), 0, PATH_MAX + 1U);
	if (getcwd(FileName.get(), PATH_MAX) == nullptr)
	{
		PrintError(LOG_ERROR_SYSTEM, L"Path initialization error", 0, nullptr, 0);
		return EXIT_FAILURE;
	}
	if (FileNameInit(FileName.get()) == EXIT_FAILURE)
		return EXIT_FAILURE;
	FileName.reset();

	#if defined(PLATFORM_LINUX)
	//Set Daemon
		if (daemon(0, 0) == RETURN_ERROR)
		{
			PrintError(LOG_ERROR_SYSTEM, L"Set system daemon error", 0, nullptr, 0);
			return EXIT_FAILURE;
		}
	#endif

	if (argc > 1 && strnlen(argv[1U], STRING_BUFFER_MAXSIZE) == strlen(MESSAGE_FLUSH_DNS) && 
		memcmp(argv[1U], MESSAGE_FLUSH_DNS, strlen(MESSAGE_FLUSH_DNS)) == 0)
	{
		FlushDNSFIFOSender();
		return EXIT_SUCCESS;
	}

//Set FIFO Monitor.
	std::thread FlushDNSFIFOMonitorThread(FlushDNSFIFOMonitor);
	FlushDNSFIFOMonitorThread.detach();
#endif

//Read configuration file and WinPcap or LibPcap initialization.
	if (ReadParameter() == EXIT_FAILURE)
	{
		WSACleanup();
		return EXIT_FAILURE;
	}

//Mark Local DNS address to PTR Records.
	std::thread GetNetworkingInformationThread(GetNetworkingInformation);
	GetNetworkingInformationThread.detach();

//Read IPFilter and Hosts.
	if (Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.Blacklist || Parameter.LocalRouting)
	{
		std::thread IPFilterThread(ReadIPFilter);
		IPFilterThread.detach();
	}

	std::thread HostsThread(ReadHosts);
	HostsThread.detach();

//DNSCurve initialization
#if defined(ENABLE_LIBSODIUM)
	if (Parameter.DNSCurve && DNSCurveParameter.IsEncryption)
	{
		randombytes_set_implementation(&randombytes_salsa20_implementation);
		randombytes_stir();
		DNSCurveInit();
	}
#endif

#if defined(PLATFORM_WIN)
//Service initialization and start service.
	SERVICE_TABLE_ENTRYW ServiceTable[] = {{DEFAULT_LOCAL_SERVICENAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain}, {nullptr, nullptr}};
	if (!StartServiceCtrlDispatcherW(ServiceTable))
	{
		Parameter.Console = true;
		PrintError(LOG_ERROR_SYSTEM, L"Service start error", GetLastError(), nullptr, 0);
		PrintError(LOG_ERROR_SYSTEM, L"Pcap_DNSProxy will continue to run in console mode", 0, nullptr, 0);

	//Handle the system signal.
		SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE);

	//Switch to run as a program.
		MonitorInit();

	//Exit.
		WSACleanup();
		return EXIT_SUCCESS;
	}

	WSACleanup();
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	MonitorInit();
#endif

	return EXIT_SUCCESS;
}

//Get path of program from the main function parameter and Winsock initialization
#if defined(PLATFORM_WIN)
	size_t __fastcall FileNameInit(const wchar_t *OriginalPath)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	size_t FileNameInit(const char *OriginalPath)
#endif
{
//Path process.
#if defined(PLATFORM_WIN)
	Parameter.Path->push_back(OriginalPath);
	Parameter.Path->front().erase(Parameter.Path->front().rfind(L"\\") + 1U);
	for (size_t Index = 0;Index < Parameter.Path->front().length();++Index)
	{
		if ((Parameter.Path->front())[Index] == L'\\')
		{
			Parameter.Path->front().insert(Index, L"\\");
			++Index;
		}
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Parameter.sPath->push_back(OriginalPath);
	Parameter.sPath->front().append("/");
	std::wstring StringTemp;
	MBSToWCSString(StringTemp, OriginalPath);
	StringTemp.append(L"/");
	Parameter.Path->push_back(StringTemp);
	StringTemp.clear();
#endif

//Get path of error/running status log file and mark start time.
	*Parameter.ErrorLogPath = Parameter.Path->front();
	Parameter.ErrorLogPath->append(L"Error.log");
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	*Parameter.sErrorLogPath = Parameter.sPath->front();
	Parameter.sErrorLogPath->append("Error.log");
#endif
	Parameter.PrintError = true;
	*Parameter.RunningLogPath = Parameter.Path->front();
	Parameter.RunningLogPath->append(L"Running.log");
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	*Parameter.sRunningLogPath = Parameter.sPath->front();
	Parameter.sRunningLogPath->append("Running.log");
#endif
	time(&StartTime);
	time(&RunningLogStartTime);

#if defined(PLATFORM_WIN)
//Winsock initialization
	WSAData WSAInitialization = {0};
	if (WSAStartup(MAKEWORD(WINSOCK_VERSION_HIGH, WINSOCK_VERSION_LOW), &WSAInitialization) != 0 || LOBYTE(WSAInitialization.wVersion) != WINSOCK_VERSION_LOW || HIBYTE(WSAInitialization.wVersion) != WINSOCK_VERSION_HIGH)
	{
		PrintError(LOG_ERROR_NETWORK, L"Winsock initialization error", WSAGetLastError(), nullptr, 0);

		WSACleanup();
		return EXIT_FAILURE;
	}
#endif

	return EXIT_SUCCESS;
}

#if defined(PLATFORM_WIN)
//Windows Firewall Test
	size_t __fastcall FirewallTest(const uint16_t Protocol)
	{
	//Initialization
		std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
		memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
		SYSTEM_SOCKET FirewallSocket = 0;

	//Ramdom number distribution initialization
		std::uniform_int_distribution<int> RamdomDistribution(DYNAMIC_MIN_PORT, UINT16_MAX - 1U);

	//Socket initialization
		if (Protocol == AF_INET6) //IPv6
		{
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = in6addr_any;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = htons((uint16_t)RamdomDistribution(*Parameter.RamdomEngine));
			SockAddr->ss_family = AF_INET6;
			FirewallSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

		//Bind local socket.
			if (FirewallSocket == INVALID_SOCKET)
			{
				return EXIT_FAILURE;
			}
			else if (bind(FirewallSocket, (PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6)) == SOCKET_ERROR)
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = htons((uint16_t)RamdomDistribution(*Parameter.RamdomEngine));
				size_t Index = 0;
				while (bind(FirewallSocket, (PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6)) == SOCKET_ERROR)
				{
					if (Index < LOOP_MAX_TIMES && WSAGetLastError() == WSAEADDRINUSE)
					{
						((PSOCKADDR_IN6)SockAddr.get())->sin6_port = htons((uint16_t)RamdomDistribution(*Parameter.RamdomEngine));

						++Index;
						continue;
					}
					else {
						closesocket(FirewallSocket);
						return EXIT_FAILURE;
					}
				}
			}
		}
		else { //IPv4
			((PSOCKADDR_IN)SockAddr.get())->sin_addr.s_addr = INADDR_ANY;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = htons((uint16_t)RamdomDistribution(*Parameter.RamdomEngine));
			SockAddr->ss_family = AF_INET;
			FirewallSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

		//Bind local socket.
			if (FirewallSocket == INVALID_SOCKET)
			{
				return EXIT_FAILURE;
			}
			else if (bind(FirewallSocket, (PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in)) == SOCKET_ERROR)
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_port = htons((uint16_t)RamdomDistribution(*Parameter.RamdomEngine));
				size_t Index = 0;
				while (bind(FirewallSocket, (PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in)) == SOCKET_ERROR)
				{
					if (Index < LOOP_MAX_TIMES && WSAGetLastError() == WSAEADDRINUSE)
					{
						((PSOCKADDR_IN)SockAddr.get())->sin_port = htons((uint16_t)RamdomDistribution(*Parameter.RamdomEngine));

						++Index;
						continue;
					}
					else {
						closesocket(FirewallSocket);
						return EXIT_FAILURE;
					}
				}
			}
		}

		closesocket(FirewallSocket);
		return EXIT_SUCCESS;
	}
#endif
