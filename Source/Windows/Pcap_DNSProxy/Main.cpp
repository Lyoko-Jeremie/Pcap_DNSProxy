// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
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
int wmain(int argc, wchar_t* argv[])
{
//Windows XP with SP3 support
#ifdef _WIN64
#else //x86
	GetFunctionPointer(FUNCTION_GETTICKCOUNT64);
	GetFunctionPointer(FUNCTION_INET_NTOP);
#endif

//Get parameter.
	if (argc > 0)
	{
	//Path initialization and Winsock initialization.
		if (FileNameInit(argv[0]) == EXIT_FAILURE)
			return EXIT_FAILURE;

	//Windows Firewall Test in first start.
		if (argc > 1 && wcsnlen_s(argv[1U], STRING_BUFFER_MAXSIZE) == wcslen(L"--FirstStart") && wcsncmp(argv[1U], L"--FirstStart", wcslen(L"--FirstStart")) == 0)
		{
			if (FirewallTest(AF_INET6) == EXIT_FAILURE && FirewallTest(AF_INET) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Windows Firewall Test error", 0, nullptr, 0);

				WSACleanup();
				return EXIT_FAILURE;
			}
			else {
				WSACleanup();
				return EXIT_SUCCESS;
			}
		}
	}
	else {
		return EXIT_FAILURE;
	}

//Read configuration file and WinPcap initialization.
	if (ReadParameter() == EXIT_FAILURE)
	{
		WSACleanup();
		return EXIT_FAILURE;
	}

//Mark Local DNS address to PTR Records.
	std::thread GetNetworkingInformationThread(GetNetworkingInformation);
	GetNetworkingInformationThread.detach();

//Read IPFilter, start DNS Cache monitor(Timer type) and read Hosts.
	if (Parameter.CacheType > 0)
	{
		std::thread DNSCacheTimerThread(DNSCacheTimerMonitor);
		DNSCacheTimerThread.detach();
	}

	if (Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.Blacklist || Parameter.LocalRouting)
	{
		std::thread IPFilterThread(ReadIPFilter);
		IPFilterThread.detach();
	}

	std::thread HostsThread(ReadHosts);
	HostsThread.detach();

//DNSCurve initialization
	if (Parameter.DNSCurve && DNSCurveParameter.IsEncryption)
	{
		randombytes_set_implementation(&randombytes_salsa20_implementation);
		randombytes_stir();
		DNSCurveInit();
	}

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
//	TerminateService();
	return EXIT_SUCCESS;
}

//Get path of program from the main function parameter and Winsock initialization
size_t __fastcall FileNameInit(const PWSTR OriginalPath)
{
//Path process.
	Parameter.Path->push_back(OriginalPath);
	Parameter.Path->front().erase(Parameter.Path->front().rfind(L"\\") + 1U);
	for (size_t Index = 0;Index < Parameter.Path->front().length();Index++)
	{
		if ((Parameter.Path->front())[Index] == L'\\')
		{
			Parameter.Path->front().insert(Index, L"\\");
			Index++;
		}
	}

//Get path of error/running status log file and mark start time.
	*Parameter.ErrorLogPath = Parameter.Path->front();
	Parameter.ErrorLogPath->append(L"Error.log");
//	DeleteFileW(Parameter.ErrorLogPath->c_str());
	Parameter.PrintError = true;
	*Parameter.RunningLogPath = Parameter.Path->front();
	Parameter.RunningLogPath->append(L"Running.log");
//	DeleteFileW(Parameter.RunningLogPath->c_str());
	time(&StartTime);
	time(&RunningLogStartTime);

//Winsock initialization
	WSAData WSAInitialization = {0};
	if (WSAStartup(MAKEWORD(WINSOCK_VERSION_HIGH, WINSOCK_VERSION_LOW), &WSAInitialization) != 0 || LOBYTE(WSAInitialization.wVersion) != WINSOCK_VERSION_LOW || HIBYTE(WSAInitialization.wVersion) != WINSOCK_VERSION_HIGH)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Winsock initialization error", WSAGetLastError(), nullptr, 0);

		WSACleanup();
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

//Windows Firewall Test
size_t __fastcall FirewallTest(const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	SYSTEM_SOCKET FirewallSocket = 0;

//Ramdom number distribution initialization
	std::uniform_int_distribution<int> RamdomDistribution(DYNAMIC_MIN_PORT, U16_MAXNUM - 1U);

//Socket initialization
	if (Protocol == AF_INET6) //IPv6
	{
		FirewallSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr->ss_family = AF_INET6;
		((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = in6addr_any;
		((PSOCKADDR_IN6)SockAddr.get())->sin6_port = htons((uint16_t)RamdomDistribution(*Parameter.RamdomEngine));

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
					Index++;
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
		FirewallSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr->ss_family = AF_INET;
		((PSOCKADDR_IN)SockAddr.get())->sin_addr.S_un.S_addr = INADDR_ANY;
		((PSOCKADDR_IN)SockAddr.get())->sin_port = htons((uint16_t)RamdomDistribution(*Parameter.RamdomEngine));

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
					Index++;
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
