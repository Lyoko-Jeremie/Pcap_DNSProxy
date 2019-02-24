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


#include "File.h"

//Compare file size
ARITHMETIC_COMPARE_TYPE CompareFileSize(
#if defined(PLATFORM_WIN)
	const std::wstring &PathFileName, 
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	const std::string &PathFileName, 
#endif
	const uint64_t TargetSize)
{
//Path file name and target size check
	if (PathFileName.empty() || TargetSize == 0)
		return ARITHMETIC_COMPARE_TYPE::NONE;

#if defined(PLATFORM_WIN)
//Initialization
	WIN32_FILE_ATTRIBUTE_DATA FileAttribute;
	memset(&FileAttribute, 0, sizeof(FileAttribute));

//Get file size information.
	if (GetFileAttributesExW(
			PathFileName.c_str(), 
			GetFileExInfoStandard, 
			&FileAttribute) != 0)
	{
	//Copy size information from large intrger to 64-bit size.
		LARGE_INTEGER ErrorFileSize;
		memset(&ErrorFileSize, 0, sizeof(ErrorFileSize));
		ErrorFileSize.HighPart = FileAttribute.nFileSizeHigh;
		ErrorFileSize.LowPart = FileAttribute.nFileSizeLow;

	//Compare file size.
		if (ErrorFileSize.QuadPart <= 0)
			return ARITHMETIC_COMPARE_TYPE::NONE;
		else if (static_cast<uint64_t>(ErrorFileSize.QuadPart) == TargetSize)
			return ARITHMETIC_COMPARE_TYPE::EQUAL;
		else if (static_cast<uint64_t>(ErrorFileSize.QuadPart) > TargetSize)
			return ARITHMETIC_COMPARE_TYPE::GREATER;
		else if (static_cast<uint64_t>(ErrorFileSize.QuadPart) < TargetSize)
			return ARITHMETIC_COMPARE_TYPE::LESS;
	}
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//Initialization
	struct stat FileAttribute;
	memset(&FileAttribute, 0, sizeof(FileAttribute));

//Get file size information.
	if (stat(PathFileName.c_str(), &FileAttribute) == 0)
	{
	//Compare file size.
		if (FileAttribute.st_size <= 0)
			return ARITHMETIC_COMPARE_TYPE::NONE;
		else if (static_cast<uint64_t>(FileAttribute.st_size) == TargetSize)
			return ARITHMETIC_COMPARE_TYPE::EQUAL;
		else if (static_cast<uint64_t>(FileAttribute.st_size) > TargetSize)
			return ARITHMETIC_COMPARE_TYPE::GREATER;
		else if (static_cast<uint64_t>(FileAttribute.st_size) < TargetSize)
			return ARITHMETIC_COMPARE_TYPE::LESS;
	}
#endif

	return ARITHMETIC_COMPARE_TYPE::NONE;
}

//Delete full size file
ssize_t DeleteFullSizeFile(
#if defined(PLATFORM_WIN)
	const std::wstring &PathFileName, 
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	const std::string &PathFileName, 
#endif
	const uint64_t FullSize, 
	bool * const IsFileDeleted)
{
	if (CompareFileSize(PathFileName, FullSize) == ARITHMETIC_COMPARE_TYPE::GREATER)
	{
	#if defined(PLATFORM_WIN)
		if (DeleteFileW(
				PathFileName.c_str()) == 0)
		{
			if (GetLastError() != EXIT_SUCCESS)
				return GetLastError();
			else 
				return EXIT_FAILURE;
		}
	#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		if (remove(PathFileName.c_str()) != 0)
		{
			if (errno != EXIT_SUCCESS)
				return errno;
			else 
				return EXIT_FAILURE;
		}
	#endif
		else if (IsFileDeleted != nullptr)
		{
			*IsFileDeleted = true;
		}
	}

	return EXIT_SUCCESS;
}
