// This code is part of Pcap_DNSProxy
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

Configuration Parameter;
std::string ErrorLogPath, ParameterPath, HostsPath;

//The Main function of program
int main(int argc, char *argv[])
{
//Some Regular Expression initialization and get path
	RegexInitialization();
	if (FileInitialization() == EXIT_FAILURE)
		return EXIT_FAILURE;

//Set Daemon
	if (daemon(0, 0) == RETURN_ERROR)
	{
		PrintError(System_Error, L"Set system daemon failed", 0, 0);
		return EXIT_FAILURE;
	}


//Read configuration file 
	if (Parameter.ReadParameter() == EXIT_FAILURE || CaptureInitialization() == EXIT_FAILURE)
		return EXIT_FAILURE;

//Get Localhost DNS PTR Records
	std::thread IPv6LocalAddressThread(LocalAddressToPTR, AF_INET6);
	std::thread IPv4LocalAddressThread(LocalAddressToPTR, AF_INET);
	IPv6LocalAddressThread.detach();
	IPv4LocalAddressThread.detach();

//Read Hosts
	std::thread HostsThread(&Configuration::ReadHosts, std::ref(Parameter));
	HostsThread.detach();

//Start Monitor
	if (MonitorInitialization() == EXIT_FAILURE)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

//File initialization(Linux)
size_t FileInitialization()
{
//Initialization
	char *Path = nullptr;
	try {
		Path = new char[PATH_MAX]();
	}
	catch (std::bad_alloc)
	{
		return EXIT_FAILURE;
	}
	memset(Path, 0, PATH_MAX);

//Get path
	if (getcwd(Path, PATH_MAX) == nullptr)
	{
		delete[] Path;
		return EXIT_FAILURE;
	}

	ErrorLogPath.append(Path);
	ParameterPath.append(Path);
	HostsPath.append(Path);
	ErrorLogPath.append("/Error.log");
	ParameterPath.append("/Config.conf");
	HostsPath.append("/Hosts.conf");

//Delete old log file
	remove(ErrorLogPath.c_str());
	Parameter.PrintError = true;

	delete[] Path;
	return EXIT_SUCCESS;
}
