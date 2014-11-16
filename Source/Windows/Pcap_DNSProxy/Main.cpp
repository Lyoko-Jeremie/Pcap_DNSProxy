// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
// Copyright (C) 2012-2014 Chengr28
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


#include "Pcap_DNSProxy.h"

extern Configuration Parameter;
extern DNSCurveConfiguration DNSCurveParameter;

//The Main function of program
int wmain(int argc, _TCHAR* argv[])
{
//Get parameter.
	if (argc > 0)
	{
/* Change parameters of main function from characters to wide characters(2014-11-02).
		std::shared_ptr<wchar_t> wPath(new wchar_t[MAX_PATH]());
		if (MultiByteToWideChar(CP_ACP, NULL, argv[0], MBSTOWCS_NULLTERMINATE, wPath.get(), MAX_PATH) <= 0)
		{
			PrintError(LOG_ERROR_SYSTEM, L"Multi byte(s) to wide char(s) error", NULL, nullptr, NULL);
			return EXIT_FAILURE;
		}
*/

	//Path initialization and Winsock initialization.
		if (FileInit(argv[0]) == EXIT_FAILURE)
			return EXIT_FAILURE;
//		wPath.reset();

	//Windows Firewall Test in first start.
		if (argc > 1 && lstrlenW(argv[1U]) == lstrlenW(L"--FirstStart") && wcsncmp(argv[1U], L"--FirstStart", lstrlenW(L"--FirstStart")) == 0)
		{
			if (FirewallTest(AF_INET6) == EXIT_FAILURE && FirewallTest(AF_INET) == EXIT_FAILURE)
			{
				PrintError(LOG_ERROR_WINSOCK, L"Windows Firewall Test error", NULL, nullptr, NULL);

				WSACleanup();
				return EXIT_FAILURE;
			}
			else {
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
	std::thread GetLocalAddressInformationThread_IPv6(GetLocalAddressInformation, AF_INET6);
	std::thread GetLocalAddressInformationThread_IPv4(GetLocalAddressInformation, AF_INET);
	GetLocalAddressInformationThread_IPv6.detach();
	GetLocalAddressInformationThread_IPv4.detach();
	
//Read IPFilter, start DNS Cache monitor(Timer type) and read Hosts.
	if (Parameter.FileRefreshTime > 0)
	{
		if (Parameter.CacheType != 0)
		{
			std::thread DNSCacheTimerThread(DNSCacheTimerMonitor, Parameter.CacheType);
			DNSCacheTimerThread.detach();
		}

		if (Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.Blacklist)
		{
			std::thread IPFilterThread(ReadIPFilter);
			IPFilterThread.detach();
		}

		std::thread HostsThread(ReadHosts);
		HostsThread.detach();
	}

//DNSCurve initialization
	if (Parameter.DNSCurve && DNSCurveParameter.Encryption)
	{
		randombytes_set_implementation(&randombytes_salsa20_implementation);
		randombytes_stir();
		DNSCurveInit();
	}

//Service initialization and start service.
	SERVICE_TABLE_ENTRYW ServiceTable[] = {{DEFAULT_LOCAL_SERVICENAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain}, {nullptr, NULL}};
	if (!StartServiceCtrlDispatcherW(ServiceTable))
	{
		Parameter.Console = true;
		PrintError(LOG_ERROR_SYSTEM, L"Service start error", GetLastError(), nullptr, NULL);
		PrintError(LOG_ERROR_SYSTEM, L"Pcap_DNSProxy will continue to run in console mode", NULL, nullptr, NULL);

	//Handle the system signal.
		SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE);

	//Switch to run as a program.
		MonitorInit();

		WSACleanup();
		return EXIT_FAILURE;
	}

	WSACleanup();
	return EXIT_SUCCESS;
}

//Get path of program from the main function parameter and Winsock initialization
inline size_t __fastcall FileInit(const PWSTR wPath)
{
/* Get path of program from server information.
//Prepare
	SC_HANDLE SCM = nullptr, Service = nullptr;
	DWORD nResumeHandle = 0;

	if ((SCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS)) == nullptr)
		return EXIT_FAILURE;
 
	Service = OpenService(SCM, DEFAULT_LOCAL_SERVICENAME, SERVICE_ALL_ACCESS);
	if (Service == nullptr)
		return EXIT_FAILURE;

	LPQUERY_SERVICE_CONFIG ServicesInfo = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, QUERY_SERVICE_CONFIG_BUFFER_MAXSIZE);
	if (ServicesInfo == nullptr)
		return EXIT_FAILURE;

	if (QueryServiceConfig(Service, ServicesInfo, QUERY_SERVICE_CONFIG_BUFFER_MAXSIZE, &nResumeHandle) == FALSE)
	{
		LocalFree(ServicesInfo);
		return EXIT_FAILURE;
	}
	Path = ServicesInfo->lpBinaryPathName;
	LocalFree(ServicesInfo);
*/

//Path process.
	*Parameter.Path = wPath;
	Parameter.Path->erase(Parameter.Path->rfind(L"\\") + 1U);

	for (size_t Index = 0;Index < Parameter.Path->length();Index++)
	{
		if ((*Parameter.Path)[Index] == L'\\')
		{
			Parameter.Path->insert(Index, L"\\");
			Index++;
		}
	}

//Get path of error log file and delete the old one.
	*Parameter.ErrorLogPath = *Parameter.Path;
	Parameter.ErrorLogPath->append(L"Error.log");
	DeleteFileW(Parameter.ErrorLogPath->c_str());
	Parameter.PrintError = true;

//Winsock initialization
	WSAData WSAInitialization = {0};
	if (WSAStartup(MAKEWORD(WINSOCK_VERSION_HIGH, WINSOCK_VERSION_LOW), &WSAInitialization) != 0 || LOBYTE(WSAInitialization.wVersion) != WINSOCK_VERSION_LOW || HIBYTE(WSAInitialization.wVersion) != WINSOCK_VERSION_HIGH)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Winsock initialization error", WSAGetLastError(), nullptr, NULL);

		WSACleanup();
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

//Windows Firewall Test
inline size_t __fastcall FirewallTest(const uint16_t Protocol)
{
	SYSTEM_SOCKET FirewallSocket = 0;
	sockaddr_storage SockAddr = {0};

//Ramdom number generator initialization
	std::random_device RamdomDevice;
	std::mt19937 RamdomEngine(RamdomDevice()); //Mersenne Twister Engine
	std::uniform_int_distribution<int> Distribution(1, U16_MAXNUM);
	auto RamdomGenerator = std::bind(Distribution, RamdomEngine);

//Socket initialization
	if (Protocol == AF_INET6) //IPv6
	{
		FirewallSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr.ss_family = AF_INET6;
		((PSOCKADDR_IN6)&SockAddr)->sin6_addr = in6addr_any;
		((PSOCKADDR_IN6)&SockAddr)->sin6_port = htons((uint16_t)RamdomGenerator());

	//Bind local socket.
		if (FirewallSocket == INVALID_SOCKET)
		{
			return EXIT_FAILURE;
		}
		else if (bind(FirewallSocket, (PSOCKADDR)&SockAddr, sizeof(sockaddr_in6)) == SOCKET_ERROR)
		{
			closesocket(FirewallSocket);
			return EXIT_FAILURE;
		}
	}
	else { //IPv4
		FirewallSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr.ss_family = AF_INET;
		((PSOCKADDR_IN)&SockAddr)->sin_addr.S_un.S_addr = INADDR_ANY;
		((PSOCKADDR_IN)&SockAddr)->sin_port = htons((uint16_t)RamdomGenerator());

	//Bind local socket.
		if (FirewallSocket == INVALID_SOCKET)
		{
			return EXIT_FAILURE;
		}
		else if (bind(FirewallSocket, (PSOCKADDR)&SockAddr, sizeof(sockaddr_in)) == SOCKET_ERROR)
		{
			closesocket(FirewallSocket);
			return EXIT_FAILURE;
		}
	}

	closesocket(FirewallSocket);
	return EXIT_SUCCESS;
}
