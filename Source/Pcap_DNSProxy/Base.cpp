// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2018 Chengr28
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


#include "Base.h"

//Check empty buffer
bool CheckEmptyBuffer(
	const void * const Buffer, 
	const size_t Length)
{
//Null pointer
	if (Buffer == nullptr)
	{
		return false;
	}
//Scan all data.
	else {
		for (size_t Index = 0;Index < Length;++Index)
		{
			if (*(reinterpret_cast<const uint8_t *>(Buffer) + Index) != 0)
				return false;
		}
	}

	return true;
}

//Convert multiple bytes to wide char string
bool MBS_To_WCS_String(
	const uint8_t * const Buffer, 
	const size_t BufferSize, 
	std::wstring &Target)
{
//Check buffer.
	Target.clear();
	if (Buffer == nullptr || BufferSize == 0)
		return false;
	const auto DataLength = strnlen_s(reinterpret_cast<const char *>(Buffer), BufferSize);
	if (DataLength == 0 || CheckEmptyBuffer(Buffer, DataLength))
		return false;

//Initialization
	const auto TargetBuffer = std::make_unique<wchar_t[]>(DataLength + PADDING_RESERVED_BYTES);
	wmemset(TargetBuffer.get(), 0, DataLength + PADDING_RESERVED_BYTES);

//Convert string.
#if defined(PLATFORM_WIN)
	if (MultiByteToWideChar(
			CP_ACP, 
			0, 
			reinterpret_cast<const LPCCH>(Buffer), 
			MBSTOWCS_NULL_TERMINATE, 
			TargetBuffer.get(), 
			static_cast<int>(DataLength + NULL_TERMINATE_LENGTH)) == 0)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (mbstowcs(TargetBuffer.get(), reinterpret_cast<const char *>(Buffer), DataLength + NULL_TERMINATE_LENGTH) == static_cast<size_t>(RETURN_ERROR))
#endif
	{
		return false;
	}
	else {
		if (wcsnlen_s(TargetBuffer.get(), DataLength + NULL_TERMINATE_LENGTH) == 0)
			return false;
		else 
			Target = TargetBuffer.get();
	}

	return true;
}

//Convert wide char string to multiple bytes
bool WCS_To_MBS_String(
	const wchar_t * const Buffer, 
	const size_t BufferSize, 
	std::string &Target)
{
//Check buffer pointer.
	Target.clear();
	if (Buffer == nullptr || BufferSize == 0)
		return false;
	const auto DataLength = wcsnlen_s(Buffer, BufferSize);
	if (DataLength == 0 || CheckEmptyBuffer(Buffer, sizeof(wchar_t) * DataLength))
		return false;

//Initialization
	const auto TargetBuffer = std::make_unique<wchar_t[]>(DataLength + PADDING_RESERVED_BYTES);
	memset(TargetBuffer.get(), 0, DataLength + PADDING_RESERVED_BYTES);

//Convert string.
#if defined(PLATFORM_WIN)
	if (WideCharToMultiByte(
			CP_ACP, 
			0, 
			Buffer, 
			WCSTOMBS_NULL_TERMINATE, 
			reinterpret_cast<LPSTR>(TargetBuffer.get()), 
			static_cast<int>(DataLength + NULL_TERMINATE_LENGTH), 
			nullptr, 
			nullptr) == 0)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (wcstombs(reinterpret_cast<char *>(TargetBuffer.get()), Buffer, DataLength + NULL_TERMINATE_LENGTH) == static_cast<size_t>(RETURN_ERROR))
#endif
	{
		return false;
	}
	else {
		if (strnlen_s(reinterpret_cast<const char *>(TargetBuffer.get()), DataLength + NULL_TERMINATE_LENGTH) == 0)
			return false;
		else 
			Target = reinterpret_cast<const char *>(TargetBuffer.get());
	}

	return true;
}

//Convert lowercase/uppercase words to uppercase/lowercase words(C-Style version)
void CaseConvert(
	uint8_t * const Buffer, 
	const size_t Length, 
	const bool IsLowerToUpper)
{
	if (Buffer != nullptr)
	{
	//Convert words.
		for (size_t Index = 0;Index < Length;++Index)
		{
		//Lowercase to uppercase
			if (IsLowerToUpper)
				Buffer[Index] = static_cast<uint8_t>(toupper(Buffer[Index]));
		//Uppercase to lowercase
			else 
				Buffer[Index] = static_cast<uint8_t>(tolower(Buffer[Index]));
		}
	}

	return;
}

//Convert lowercase/uppercase words to uppercase/lowercase words(C++ string version)
void CaseConvert(
	std::string &Buffer, 
	const bool IsLowerToUpper)
{
	for (auto &StringIter:Buffer)
	{
	//Lowercase to uppercase
		if (IsLowerToUpper)
			StringIter = static_cast<char>(toupper(StringIter));
	//Uppercase to lowercase
		else 
			StringIter = static_cast<char>(tolower(StringIter));
	}

	return;
}

//Convert lowercase/uppercase words to uppercase/lowercase words(C++ wstring version)
void CaseConvert(
	std::wstring &Buffer, 
	const bool IsLowerToUpper)
{
	for (auto &StringIter:Buffer)
	{
	//Lowercase to uppercase
		if (IsLowerToUpper)
			StringIter = static_cast<wchar_t>(toupper(StringIter));
	//Uppercase to lowercase
		else 
			StringIter = static_cast<wchar_t>(tolower(StringIter));
	}

	return;
}

//Make string reversed
void MakeStringReversed(
	std::string &String)
{
	if (String.length() > 1U)
	{
	//Make string reversed
		for (size_t Index = 0;Index < String.length() / 2U;++Index)
		{
			uint8_t StringIter = String.at(String.length() - 1U - Index);
			String.at(String.length() - 1U - Index) = String.at(Index);
			String.at(Index) = StringIter;
		}
	}

	return;
}

//Make string reversed
void MakeStringReversed(
	std::wstring &String)
{
	if (String.length() > 1U)
	{
	//Make string reversed
		for (size_t Index = 0;Index < String.length() / 2U;++Index)
		{
			wchar_t StringIter = String.at(String.length() - 1U - Index);
			String.at(String.length() - 1U - Index) = String.at(Index);
			String.at(Index) = StringIter;
		}
	}

	return;
}

//Reversed string comparing
bool CompareStringReversed(
	const std::string &RuleItem, 
	const std::string &TestItem)
{
	if (!RuleItem.empty() && !TestItem.empty() && 
		TestItem.length() >= RuleItem.length() && 
		TestItem.compare(0, RuleItem.length(), RuleItem) == 0)
			return true;

	return false;
}

//Reversed string comparing
bool CompareStringReversed(
	const wchar_t * const RuleItem, 
	const wchar_t * const TestItem)
{
//Buffer and length check
	if (RuleItem != nullptr && TestItem != nullptr)
	{
		std::wstring InnerRuleItem(RuleItem), InnerTestItem(TestItem);
		if (!InnerRuleItem.empty() && !InnerTestItem.empty() && InnerTestItem.length() >= InnerRuleItem.length())
		{
		//Make string reversed to compare.
			MakeStringReversed(InnerRuleItem);
			MakeStringReversed(InnerTestItem);

		//Compare each other.
			if (InnerTestItem.compare(0, InnerRuleItem.length(), InnerRuleItem) == 0)
				return true;
		}
	}

	return false;
}

//Sort compare(IPFilter)
bool SortCompare_IPFilter(
	const DIFFERNET_FILE_SET_IPFILTER &Begin, 
	const DIFFERNET_FILE_SET_IPFILTER &End)
{
	return Begin.FileIndex < End.FileIndex;
}

//Sort compare(Hosts)
bool SortCompare_Hosts(
	const DIFFERNET_FILE_SET_HOSTS &Begin, 
	const DIFFERNET_FILE_SET_HOSTS &End)
{
	return Begin.FileIndex < End.FileIndex;
}

#if !defined(ENABLE_LIBSODIUM)
//Base64 encoding
//Base64 encoding and decoding, please visit https://github.com/zhicheng/base64.
size_t Base64_Encode(
	uint8_t * const Input, 
	const size_t Length, 
	uint8_t * const Output, 
	const size_t OutputSize)
{
//Length check
	if (Length == 0)
		return 0;

//Convert from binary to Base64.
	size_t Index[]{0, 0, 0};
	memset(Output, 0, OutputSize);
	for (Index[0] = Index[1U] = 0;Index[0] < Length;++Index[0])
	{
	//From 6/gcd(6, 8)
		Index[2U] = Index[0] % 3U;
		switch (Index[2U])
		{
			case 0:
			{
				Output[Index[1U]++] = GlobalRunningStatus.Base64_EncodeTable[(Input[Index[0]] >> 2U) & 0x3F];
				continue;
			}
			case 1U:
			{
				Output[Index[1U]++] = GlobalRunningStatus.Base64_EncodeTable[((Input[Index[0] - 1U] & 0x3) << 4U) + ((Input[Index[0]] >> 4U) & 0xF)];
				continue;
			}
			case 2U:
			{
				Output[Index[1U]++] = GlobalRunningStatus.Base64_EncodeTable[((Input[Index[0] - 1U] & 0xF) << 2U) + ((Input[Index[0]] >> 6U) & 0x3)];
				Output[Index[1U]++] = GlobalRunningStatus.Base64_EncodeTable[Input[Index[0]] & 0x3F];
			}
		}
	}

//Move back.
	Index[0] -= 1U;

//Check the last and add padding.
	if ((Index[0] % 3U) == 0)
	{
		Output[Index[1U]++] = GlobalRunningStatus.Base64_EncodeTable[(Input[Index[0]] & 0x3) << 4U];
		Output[Index[1U]++] = BASE64_PAD;
		Output[Index[1U]++] = BASE64_PAD;
	}
	else if ((Index[0] % 3U) == 1U)
	{
		Output[Index[1U]++] = GlobalRunningStatus.Base64_EncodeTable[(Input[Index[0]] & 0xF) << 2U];
		Output[Index[1U]++] = BASE64_PAD;
	}

	return strnlen_s(reinterpret_cast<const char *>(Output), OutputSize);
}

//Base64 decoding
//Base64 encoding and decoding, please visit https://github.com/zhicheng/base64.
size_t Base64_Decode(
	uint8_t *Input, 
	const size_t Length, 
	uint8_t *Output, 
	const size_t OutputSize)
{
//Initialization
	if (Length == 0)
		return 0;
	size_t Index[]{0, 0, 0};
	memset(Output, 0, OutputSize);

//Convert from Base64 to binary.
	for (Index[0] = Index[1U] = 0;Index[0] < Length;++Index[0])
	{
		int StringIter = 0;
		Index[2U] = Index[0] % 4U;
		if (Input[Index[0]] == static_cast<uint8_t>(BASE64_PAD))
			return strnlen_s(reinterpret_cast<const char *>(Output), OutputSize);
		if (Input[Index[0]] < BASE64_DECODE_FIRST || Input[Index[0]] > BASE64_DECODE_LAST || 
			(StringIter = GlobalRunningStatus.Base64_DecodeTable[Input[Index[0]] - BASE64_DECODE_FIRST]) == (-1))
				return 0;
		switch (Index[2U])
		{
			case 0:
			{
				Output[Index[1U]] = static_cast<uint8_t>(StringIter << 2U);
				continue;
			}
			case 1U:
			{
				Output[Index[1U]++] += (StringIter >> 4U) & 0x3;

			//If not last char with padding
				if (Index[0] < (Length - 3U) || Input[Length - 2U] != static_cast<uint8_t>(BASE64_PAD))
					Output[Index[1U]] = (StringIter & 0xF) << 4U;

				continue;
			}
			case 2U:
			{
				Output[Index[1U]++] += (StringIter >> 2U) & 0xF;

			//If not last char with padding
				if (Index[0] < (Length - 2U) || Input[Length - 1U] != static_cast<uint8_t>(BASE64_PAD))
					Output[Index[1U]] = (StringIter & 0x3) << 6U;

				continue;
			}
			case 3U:
			{
				Output[Index[1U]++] += static_cast<uint8_t>(StringIter);
			}
		}
	}

	return strnlen_s(reinterpret_cast<const char *>(Output), OutputSize);
}
#endif

//HTTP version 2 HPACK Header Compression static huffman encoding
//HPACK huffman encoding and decoding, please visit https://github.com/phluid61/mk-hpack.
HUFFMAN_RETURN_TYPE HPACK_HuffmanEncoding(
	uint8_t *String, 
	size_t ByteSize, 
	size_t *Consumed, 
	uint8_t *Buffer, 
	size_t Length, 
	size_t *Produced)
{
	uint8_t Shift = 0, BitLength = 0;
	uint64_t Mask = 0, Value = 0, BitQueue = 0;
	HUFFMAN_NODE Huffman_Node;
	size_t _Produced = 0, _Consumed = 0;
	if (!Produced)
		Produced = &_Produced;
	if (!Consumed)
		Consumed = &_Consumed;
	*Produced = *Consumed = 0;
	while (ByteSize > 0)
	{
		if (Buffer && Length < 1U)
			return HUFFMAN_RETURN_TYPE::ERROR_OVERFLOW;
		Huffman_Node = HuffmanCodes[*String];
		++String;
		++(*Consumed);
		--ByteSize;
		BitQueue = ((BitQueue << Huffman_Node.BitSize) | Huffman_Node.Bits); //Max 33 bits wide
		BitLength += Huffman_Node.BitSize;

	//Canibalise the top bytes.
		while (BitLength >= BYTES_TO_BITS)
		{
			if (Buffer)
			{
				Shift = BitLength - BYTES_TO_BITS;
				Mask = static_cast<uint64_t>(0xFF) << Shift;
				Value = (BitQueue & Mask);
				*Buffer = static_cast<uint8_t>(Value >> Shift);
				++Buffer;
				--Length;
				BitQueue ^= Value;
			}

			++(*Produced);
			BitLength -= BYTES_TO_BITS;
		}
	}

//Pad with EOS(incidentally all 1s).
	if (BitLength > 0)
	{
		if (Buffer)
		{
			Shift = BYTES_TO_BITS - BitLength;
			Mask = (1U << Shift) - 1U;
			*Buffer = static_cast<uint8_t>((BitQueue << Shift) | Mask);
			++Buffer;
			--Length;
		}

		++(*Produced);
	}

	return HUFFMAN_RETURN_TYPE::NONE;
}

//HTTP version 2 HPACK Header Compression huffman decoding
//HPACK huffman encoding and decoding, please visit https://github.com/phluid61/mk-hpack.
HUFFMAN_RETURN_TYPE HPACK_HuffmanDecoding(
	uint8_t *HuffmanBuffer, 
	size_t ByteSize, 
	size_t *Consumed, 
	uint8_t *TargetBuffer, 
	size_t Length, 
	size_t *Produced)
{
	auto TC = *HuffmanDecodes;
	uint16_t Temp = 0;
	uint8_t ByteIter = 0, BC = 0, Mask = 0;
	size_t _Produced = 0, _Consumed = 0;
	if (!Produced)
		Produced = &_Produced;
	if (!Consumed)
		Consumed = &_Consumed;
	*Produced = *Consumed = 0;
	if (ByteSize < 1U)
		return HUFFMAN_RETURN_TYPE::NONE;
	else if (TargetBuffer && Length < 1U)
		return HUFFMAN_RETURN_TYPE::ERROR_OVERFLOW;

#define ZERO(TC)      static_cast<uint16_t>((TC) >> 16U)
#define ONE(TC)       static_cast<uint16_t>((TC) & 0xFFFF)
#define IS_INT(x)     (((x) & 0x8000) == 0x8000)
#define VALUE_OF(x)   ((x) & 0x7FFF)

	while (ByteSize > 0)
	{
		ByteIter = *HuffmanBuffer;
		++HuffmanBuffer;
		++(*Consumed);
		--ByteSize;
		BC = 0x80; //Bit cursor
		Mask = 0x7F; //Padding mask
		while (BC > 0)
		{
			if ((ByteIter & BC) == BC)
				Temp = ONE(TC);
			else 
				Temp = ZERO(TC);
			if (IS_INT(Temp))
			{
				Temp = VALUE_OF(Temp);
				if (Temp > 0xFF)
				{
					return HUFFMAN_RETURN_TYPE::ERROR_EOS;
				}
				else {
					if (TargetBuffer)
					{
						*TargetBuffer = static_cast<uint8_t>(Temp);
						++TargetBuffer;
						--Length;
					}
					++(*Produced);
					if (ByteSize < 1 && (ByteIter & Mask) == Mask)
					{
						TC = 0;
						goto Done;
					}
					else if (TargetBuffer && Length < 1U)
					{
						return HUFFMAN_RETURN_TYPE::ERROR_OVERFLOW;
					}
					else {
						TC = *HuffmanDecodes;
					}
				}
			}
			else {
				if (Temp < sizeof(HuffmanDecodes) / sizeof(uint32_t))
					TC = HuffmanDecodes[Temp];
				else 
					return HUFFMAN_RETURN_TYPE::ERROR_TRUNCATED;
			}

			BC >>= 1U;
			Mask >>= 1U;
		}
	}

#undef ZERO
#undef ONE
#undef IS_INT
#undef VALUE_OF

Done:
	if (TC)
		return HUFFMAN_RETURN_TYPE::ERROR_TRUNCATED;

	return HUFFMAN_RETURN_TYPE::NONE;
}

#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
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
	timeval CurrentTime;
	memset(&CurrentTime, 0, sizeof(CurrentTime));
	if (gettimeofday(&CurrentTime, nullptr) == 0)
		return IncreaseMillisecondTime(0, CurrentTime);

	return 0;
}
#endif
