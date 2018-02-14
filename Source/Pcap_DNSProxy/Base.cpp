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

//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;

//HTTP version 2 HPACK Header Compression static huffman coding node
static HUFFMAN_NODE HuffmanCodes[] = 
{
	{0x1FF8, 13}, {0x7FFFD8, 23}, 
	{0xFFFFFE2, 28}, {0xFFFFFE3, 28}, 
	{0xFFFFFE4, 28}, {0xFFFFFE5, 28}, 
	{0xFFFFFE6, 28}, {0xFFFFFE7, 28}, 
	{0xFFFFFE8, 28}, {0xFFFFEA, 24}, 
	{0x3FFFFFFC, 30}, {0xFFFFFE9, 28}, 
	{0xFFFFFEA, 28}, {0x3FFFFFFD, 30}, 
	{0xFFFFFEB, 28}, {0xFFFFFEC, 28}, 
	{0xFFFFFED, 28}, {0xFFFFFEE, 28}, 
	{0xFFFFFEF, 28}, {0xFFFFFF0, 28}, 
	{0xFFFFFF1, 28}, {0xFFFFFF2, 28}, 
	{0x3FFFFFFE, 30}, {0xFFFFFF3, 28}, 
	{0xFFFFFF4, 28}, {0xFFFFFF5, 28}, 
	{0xFFFFFF6, 28}, {0xFFFFFF7, 28}, 
	{0xFFFFFF8, 28}, {0xFFFFFF9, 28}, 
	{0xFFFFFFA, 28}, {0xFFFFFFB, 28}, 
	{0x14, 6}, {0x3F8, 10}, {0x3F9, 10}, 
	{0xFFA, 12}, {0x1FF9, 13}, {0x15, 6}, 
	{0xF8, 8}, {0x7FA, 11}, {0x3FA, 10}, 
	{0x3FB, 10}, {0xF9, 8}, {0x7FB, 11}, 
	{0xFA, 8}, {0x16, 6}, {0x17, 6}, 
	{0x18, 6}, {0x0, 5}, {0x1, 5}, 
	{0x2, 5}, {0x19, 6}, {0x1A, 6}, 
	{0x1B, 6}, {0x1C, 6}, {0x1D, 6}, 
	{0x1E, 6}, {0x1F, 6}, {0x5C, 7}, 
	{0xFB, 8}, {0x7FFC, 15}, {0x20, 6}, 
	{0xFFB, 12}, {0x3FC, 10}, {0x1FFA, 13}, 
	{0x21, 6}, {0x5D, 7}, {0x5E, 7}, 
	{0x5F, 7}, {0x60, 7}, {0x61, 7}, 
	{0x62, 7}, {0x63, 7}, {0x64, 7}, 
	{0x65, 7}, {0x66, 7}, {0x67, 7}, 
	{0x68, 7}, {0x69, 7}, {0x6A, 7}, 
	{0x6B, 7}, {0x6C, 7}, {0x6D, 7}, 
	{0x6E, 7}, {0x6F, 7}, {0x70, 7}, 
	{0x71, 7}, {0x72, 7}, {0xFC, 8}, 
	{0x73, 7}, {0xFD, 8}, {0x1FFB, 13}, 
	{0x7FFF0, 19}, {0x1FFC, 13}, 
	{0x3FFC, 14}, {0x22, 6}, {0x7FFD, 15}, 
	{0x3, 5}, {0x23, 6}, {0x4, 5}, 
	{0x24, 6}, {0x5, 5}, {0x25, 6}, 
	{0x26, 6}, {0x27, 6}, {0x6, 5}, 
	{0x74, 7}, {0x75, 7}, {0x28, 6}, 
	{0x29, 6}, {0x2A, 6}, {0x7, 5}, 
	{0x2B, 6}, {0x76, 7}, {0x2C, 6}, 
	{0x8, 5}, {0x9, 5}, {0x2D, 6}, 
	{0x77, 7}, {0x78, 7}, {0x79, 7}, 
	{0x7A, 7}, {0x7B, 7}, {0x7FFE, 15}, 
	{0x7FC, 11}, {0x3FFD, 14}, {0x1FFD, 13}, 
	{0xFFFFFFC, 28}, {0xFFFE6, 20}, 
	{0x3FFFD2, 22}, {0xFFFE7, 20}, 
	{0xFFFE8, 20}, {0x3FFFD3, 22}, 
	{0x3FFFD4, 22}, {0x3FFFD5, 22}, 
	{0x7FFFD9, 23}, {0x3FFFD6, 22}, 
	{0x7FFFDA, 23}, {0x7FFFDB, 23}, 
	{0x7FFFDC, 23}, {0x7FFFDD, 23}, 
	{0x7FFFDE, 23}, {0xFFFFEB, 24}, 
	{0x7FFFDF, 23}, {0xFFFFEC, 24}, 
	{0xFFFFED, 24}, {0x3FFFD7, 22}, 
	{0x7FFFE0, 23}, {0xFFFFEE, 24}, 
	{0x7FFFE1, 23}, {0x7FFFE2, 23}, 
	{0x7FFFE3, 23}, {0x7FFFE4, 23}, 
	{0x1FFFDC, 21}, {0x3FFFD8, 22}, 
	{0x7FFFE5, 23}, {0x3FFFD9, 22}, 
	{0x7FFFE6, 23}, {0x7FFFE7, 23}, 
	{0xFFFFEF, 24}, {0x3FFFDA, 22}, 
	{0x1FFFDD, 21}, {0xFFFE9, 20}, 
	{0x3FFFDB, 22}, {0x3FFFDC, 22}, 
	{0x7FFFE8, 23}, {0x7FFFE9, 23}, 
	{0x1FFFDE, 21}, {0x7FFFEA, 23}, 
	{0x3FFFDD, 22}, {0x3FFFDE, 22}, 
	{0xFFFFF0, 24}, {0x1FFFDF, 21}, 
	{0x3FFFDF, 22}, {0x7FFFEB, 23}, 
	{0x7FFFEC, 23}, {0x1FFFE0, 21}, 
	{0x1FFFE1, 21}, {0x3FFFE0, 22}, 
	{0x1FFFE2, 21}, {0x7FFFED, 23}, 
	{0x3FFFE1, 22}, {0x7FFFEE, 23}, 
	{0x7FFFEF, 23}, {0xFFFEA, 20}, 
	{0x3FFFE2, 22}, {0x3FFFE3, 22}, 
	{0x3FFFE4, 22}, {0x7FFFF0, 23}, 
	{0x3FFFE5, 22}, {0x3FFFE6, 22}, 
	{0x7FFFF1, 23}, {0x3FFFFE0, 26}, 
	{0x3FFFFE1, 26}, {0xFFFEB, 20}, 
	{0x7FFF1, 19}, {0x3FFFE7, 22}, 
	{0x7FFFF2, 23}, {0x3FFFE8, 22}, 
	{0x1FFFFEC, 25}, {0x3FFFFE2, 26}, 
	{0x3FFFFE3, 26}, {0x3FFFFE4, 26}, 
	{0x7FFFFDE, 27}, {0x7FFFFDF, 27}, 
	{0x3FFFFE5, 26}, {0xFFFFF1, 24}, 
	{0x1FFFFED, 25}, {0x7FFF2, 19}, 
	{0x1FFFE3, 21}, {0x3FFFFE6, 26}, 
	{0x7FFFFE0, 27}, {0x7FFFFE1, 27}, 
	{0x3FFFFE7, 26}, {0x7FFFFE2, 27}, 
	{0xFFFFF2, 24}, {0x1FFFE4, 21}, 
	{0x1FFFE5, 21}, {0x3FFFFE8, 26}, 
	{0x3FFFFE9, 26}, {0xFFFFFFD, 28}, 
	{0x7FFFFE3, 27}, {0x7FFFFE4, 27}, 
	{0x7FFFFE5, 27}, {0xFFFEC, 20}, 
	{0xFFFFF3, 24}, {0xFFFED, 20}, 
	{0x1FFFE6, 21}, {0x3FFFE9, 22}, 
	{0x1FFFE7, 21}, {0x1FFFE8, 21}, 
	{0x7FFFF3, 23}, {0x3FFFEA, 22}, 
	{0x3FFFEB, 22}, {0x1FFFFEE, 25}, 
	{0x1FFFFEF, 25}, {0xFFFFF4, 24}, 
	{0xFFFFF5, 24}, {0x3FFFFEA, 26}, 
	{0x7FFFF4, 23}, {0x3FFFFEB, 26}, 
	{0x7FFFFE6, 27}, {0x3FFFFEC, 26}, 
	{0x3FFFFED, 26}, {0x7FFFFE7, 27}, 
	{0x7FFFFE8, 27}, {0x7FFFFE9, 27}, 
	{0x7FFFFEA, 27}, {0x7FFFFEB, 27}, 
	{0xFFFFFFE, 28}, {0x7FFFFEC, 27}, 
	{0x7FFFFED, 27}, {0x7FFFFEE, 27}, 
	{0x7FFFFEF, 27}, {0x7FFFFF0, 27}, 
	{0x3FFFFEE, 26}, {0x3FFFFFFF, 30}
};

//HTTP version 2 HPACK Header Compression static huffman decoding array
static uint32_t HuffmanDecodes[256U] = 
{
	static_cast<uint32_t>(65538U), 
	static_cast<uint32_t>(196612U), 
	static_cast<uint32_t>(1507352U), 
	static_cast<uint32_t>(327686U), 
	static_cast<uint32_t>(720908U), 
	static_cast<uint32_t>(458760U), 
	static_cast<uint32_t>(589834U), 
	static_cast<uint32_t>(2150662193U), 
	static_cast<uint32_t>(2150793313U), 
	static_cast<uint32_t>(2154004581U), 
	static_cast<uint32_t>(2154397807U), 
	static_cast<uint32_t>(851982U), 
	static_cast<uint32_t>(1114130U), 
	static_cast<uint32_t>(2155053172U), 
	static_cast<uint32_t>(983056U), 
	static_cast<uint32_t>(2149613605U), 
	static_cast<uint32_t>(2150465582U), 
	static_cast<uint32_t>(1245204U), 
	static_cast<uint32_t>(1376278U), 
	static_cast<uint32_t>(2150596659U), 
	static_cast<uint32_t>(2150924341U), 
	static_cast<uint32_t>(2151055415U), 
	static_cast<uint32_t>(2151186489U), 
	static_cast<uint32_t>(1638426U), 
	static_cast<uint32_t>(2687018U), 
	static_cast<uint32_t>(1769500U), 
	static_cast<uint32_t>(2162722U), 
	static_cast<uint32_t>(1900574U), 
	static_cast<uint32_t>(2031648U), 
	static_cast<uint32_t>(2151514177U), 
	static_cast<uint32_t>(2153742434U), 
	static_cast<uint32_t>(2154070118U), 
	static_cast<uint32_t>(2154266728U), 
	static_cast<uint32_t>(2293796U), 
	static_cast<uint32_t>(2424870U), 
	static_cast<uint32_t>(2154594413U), 
	static_cast<uint32_t>(2154725488U), 
	static_cast<uint32_t>(2154987637U), 
	static_cast<uint32_t>(2555944U), 
	static_cast<uint32_t>(2151317570U), 
	static_cast<uint32_t>(2151907396U), 
	static_cast<uint32_t>(2818092U), 
	static_cast<uint32_t>(3735610U), 
	static_cast<uint32_t>(2949166U), 
	static_cast<uint32_t>(3342388U), 
	static_cast<uint32_t>(3080240U), 
	static_cast<uint32_t>(3211314U), 
	static_cast<uint32_t>(2152038470U), 
	static_cast<uint32_t>(2152169544U), 
	static_cast<uint32_t>(2152300618U), 
	static_cast<uint32_t>(2152431692U), 
	static_cast<uint32_t>(3473462U), 
	static_cast<uint32_t>(3604536U), 
	static_cast<uint32_t>(2152562766U), 
	static_cast<uint32_t>(2152693840U), 
	static_cast<uint32_t>(2152824914U), 
	static_cast<uint32_t>(2152955988U), 
	static_cast<uint32_t>(3866684U), 
	static_cast<uint32_t>(4259906U), 
	static_cast<uint32_t>(3997758U), 
	static_cast<uint32_t>(4128832U), 
	static_cast<uint32_t>(2153087062U), 
	static_cast<uint32_t>(2153218137U), 
	static_cast<uint32_t>(2154463339U), 
	static_cast<uint32_t>(2154922102U), 
	static_cast<uint32_t>(4390980U), 
	static_cast<uint32_t>(4522054U), 
	static_cast<uint32_t>(2155315320U), 
	static_cast<uint32_t>(2155446394U), 
	static_cast<uint32_t>(4653128U), 
	static_cast<uint32_t>(4784202U), 
	static_cast<uint32_t>(2150006826U), 
	static_cast<uint32_t>(2150400059U), 
	static_cast<uint32_t>(2153283674U), 
	static_cast<uint32_t>(4915276U), 
	static_cast<uint32_t>(5046350U), 
	static_cast<uint32_t>(5177424U), 
	static_cast<uint32_t>(2149679138U), 
	static_cast<uint32_t>(2150137897U), 
	static_cast<uint32_t>(2151612497U), 
	static_cast<uint32_t>(5374035U), 
	static_cast<uint32_t>(2150072363U), 
	static_cast<uint32_t>(2155610196U), 
	static_cast<uint32_t>(5570646U), 
	static_cast<uint32_t>(2149810238U), 
	static_cast<uint32_t>(5701720U), 
	static_cast<uint32_t>(5832794U), 
	static_cast<uint32_t>(2147516452U), 
	static_cast<uint32_t>(2151710811U), 
	static_cast<uint32_t>(2153611390U), 
	static_cast<uint32_t>(5963868U), 
	static_cast<uint32_t>(2153676925U), 
	static_cast<uint32_t>(6094942U), 
	static_cast<uint32_t>(2151448672U), 
	static_cast<uint32_t>(2155544671U), 
	static_cast<uint32_t>(6291553U), 
	static_cast<uint32_t>(6422627U), 
	static_cast<uint32_t>(7274608U), 
	static_cast<uint32_t>(6553701U), 
	static_cast<uint32_t>(6750312U), 
	static_cast<uint32_t>(2153545923U), 
	static_cast<uint32_t>(2161115238U), 
	static_cast<uint32_t>(2155905154U), 
	static_cast<uint32_t>(6881386U), 
	static_cast<uint32_t>(7012460U), 
	static_cast<uint32_t>(2156101794U), 
	static_cast<uint32_t>(2159575234U), 
	static_cast<uint32_t>(2162196706U), 
	static_cast<uint32_t>(7143534U), 
	static_cast<uint32_t>(2157543585U), 
	static_cast<uint32_t>(2158461100U), 
	static_cast<uint32_t>(7405682U), 
	static_cast<uint32_t>(8781959U), 
	static_cast<uint32_t>(7536756U), 
	static_cast<uint32_t>(7929978U), 
	static_cast<uint32_t>(7667830U), 
	static_cast<uint32_t>(7798904U), 
	static_cast<uint32_t>(2159050929U), 
	static_cast<uint32_t>(2159247569U), 
	static_cast<uint32_t>(2161672409U), 
	static_cast<uint32_t>(2162393317U), 
	static_cast<uint32_t>(8061052U), 
	static_cast<uint32_t>(8388737U), 
	static_cast<uint32_t>(2162557053U), 
	static_cast<uint32_t>(8257663U), 
	static_cast<uint32_t>(2155970692U), 
	static_cast<uint32_t>(2156232838U), 
	static_cast<uint32_t>(2156429458U), 
	static_cast<uint32_t>(8519811U), 
	static_cast<uint32_t>(8650885U), 
	static_cast<uint32_t>(2157609116U), 
	static_cast<uint32_t>(2158002339U), 
	static_cast<uint32_t>(2158264489U), 
	static_cast<uint32_t>(2158657709U), 
	static_cast<uint32_t>(8913033U), 
	static_cast<uint32_t>(10092699U), 
	static_cast<uint32_t>(9044107U), 
	static_cast<uint32_t>(9437329U), 
	static_cast<uint32_t>(9175181U), 
	static_cast<uint32_t>(9306255U), 
	static_cast<uint32_t>(2159182005U), 
	static_cast<uint32_t>(2159640762U), 
	static_cast<uint32_t>(2159771837U), 
	static_cast<uint32_t>(2159968452U), 
	static_cast<uint32_t>(9568403U), 
	static_cast<uint32_t>(9699477U), 
	static_cast<uint32_t>(2160492772U), 
	static_cast<uint32_t>(2162721001U), 
	static_cast<uint32_t>(9830551U), 
	static_cast<uint32_t>(9961625U), 
	static_cast<uint32_t>(2147582087U), 
	static_cast<uint32_t>(2156494986U), 
	static_cast<uint32_t>(2156626060U), 
	static_cast<uint32_t>(2156757135U), 
	static_cast<uint32_t>(10223773U), 
	static_cast<uint32_t>(11141291U), 
	static_cast<uint32_t>(10354847U), 
	static_cast<uint32_t>(10748069U), 
	static_cast<uint32_t>(10485921U), 
	static_cast<uint32_t>(10616995U), 
	static_cast<uint32_t>(2157150357U), 
	static_cast<uint32_t>(2157346967U), 
	static_cast<uint32_t>(2157478043U), 
	static_cast<uint32_t>(2157805726U), 
	static_cast<uint32_t>(10879143U), 
	static_cast<uint32_t>(11010217U), 
	static_cast<uint32_t>(2158330022U), 
	static_cast<uint32_t>(2158526638U), 
	static_cast<uint32_t>(2158985396U), 
	static_cast<uint32_t>(2159444151U), 
	static_cast<uint32_t>(11272365U), 
	static_cast<uint32_t>(11862198U), 
	static_cast<uint32_t>(11403439U), 
	static_cast<uint32_t>(11534513U), 
	static_cast<uint32_t>(2159837375U), 
	static_cast<uint32_t>(2160427239U), 
	static_cast<uint32_t>(2163146930U), 
	static_cast<uint32_t>(11731124U), 
	static_cast<uint32_t>(2148106382U), 
	static_cast<uint32_t>(2156953745U), 
	static_cast<uint32_t>(2157215903U), 
	static_cast<uint32_t>(11993272U), 
	static_cast<uint32_t>(12517568U), 
	static_cast<uint32_t>(12124346U), 
	static_cast<uint32_t>(12255420U), 
	static_cast<uint32_t>(2158723278U), 
	static_cast<uint32_t>(2161606881U), 
	static_cast<uint32_t>(2162983149U), 
	static_cast<uint32_t>(12386494U), 
	static_cast<uint32_t>(2160558287U), 
	static_cast<uint32_t>(2162852075U), 
	static_cast<uint32_t>(12648642U), 
	static_cast<uint32_t>(13631697U), 
	static_cast<uint32_t>(12779716U), 
	static_cast<uint32_t>(13172938U), 
	static_cast<uint32_t>(12910790U), 
	static_cast<uint32_t>(13041864U), 
	static_cast<uint32_t>(2160099521U), 
	static_cast<uint32_t>(2160623817U), 
	static_cast<uint32_t>(2160754893U), 
	static_cast<uint32_t>(2161279189U), 
	static_cast<uint32_t>(13304012U), 
	static_cast<uint32_t>(13435086U), 
	static_cast<uint32_t>(2161803483U), 
	static_cast<uint32_t>(2163114224U), 
	static_cast<uint32_t>(2163376371U), 
	static_cast<uint32_t>(2164195535U), 
	static_cast<uint32_t>(2160820428U), 
	static_cast<uint32_t>(13762771U), 
	static_cast<uint32_t>(14680289U), 
	static_cast<uint32_t>(13893845U), 
	static_cast<uint32_t>(14287067U), 
	static_cast<uint32_t>(14024919U), 
	static_cast<uint32_t>(14155993U), 
	static_cast<uint32_t>(2161344724U), 
	static_cast<uint32_t>(2161541341U), 
	static_cast<uint32_t>(2162065631U), 
	static_cast<uint32_t>(2163310836U), 
	static_cast<uint32_t>(14418141U), 
	static_cast<uint32_t>(14549215U), 
	static_cast<uint32_t>(2163572982U), 
	static_cast<uint32_t>(2163704056U), 
	static_cast<uint32_t>(2163900667U), 
	static_cast<uint32_t>(2164031741U), 
	static_cast<uint32_t>(14811363U), 
	static_cast<uint32_t>(15663344U), 
	static_cast<uint32_t>(14942437U), 
	static_cast<uint32_t>(15270122U), 
	static_cast<uint32_t>(2164130022U), 
	static_cast<uint32_t>(15139048U), 
	static_cast<uint32_t>(2147647491U), 
	static_cast<uint32_t>(2147778565U), 
	static_cast<uint32_t>(2147909639U), 
	static_cast<uint32_t>(15401196U), 
	static_cast<uint32_t>(15532270U), 
	static_cast<uint32_t>(2148040715U), 
	static_cast<uint32_t>(2148302862U), 
	static_cast<uint32_t>(2148499472U), 
	static_cast<uint32_t>(2148630546U), 
	static_cast<uint32_t>(15794418U), 
	static_cast<uint32_t>(16187640U), 
	static_cast<uint32_t>(15925492U), 
	static_cast<uint32_t>(16056566U), 
	static_cast<uint32_t>(2148761620U), 
	static_cast<uint32_t>(2148892695U), 
	static_cast<uint32_t>(2149089305U), 
	static_cast<uint32_t>(2149220379U), 
	static_cast<uint32_t>(16318714U), 
	static_cast<uint32_t>(16449788U), 
	static_cast<uint32_t>(2149351453U), 
	static_cast<uint32_t>(2149482527U), 
	static_cast<uint32_t>(2155839708U), 
	static_cast<uint32_t>(2163802365U), 
	static_cast<uint32_t>(16646399U), 
	static_cast<uint32_t>(2148171789U), 
	static_cast<uint32_t>(2148958464U)
};

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
	else {
	//Scan all data.
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
	const size_t MaxLen, 
	std::wstring &Target)
{
//Check buffer.
	Target.clear();
	if (Buffer == nullptr || MaxLen == 0)
		return false;
	const auto Length = strnlen_s(reinterpret_cast<const char *>(Buffer), MaxLen);
	if (Length == 0 || CheckEmptyBuffer(Buffer, Length))
		return false;

//Initialization
	const auto TargetBuffer = std::make_unique<wchar_t[]>(Length + PADDING_RESERVED_BYTES);
	wmemset(TargetBuffer.get(), 0, Length + PADDING_RESERVED_BYTES);

//Convert string.
#if defined(PLATFORM_WIN)
	if (MultiByteToWideChar(
			CP_ACP, 
			0, 
			reinterpret_cast<const LPCCH>(Buffer), 
			MBSTOWCS_NULL_TERMINATE, 
			TargetBuffer.get(), 
			static_cast<int>(Length + NULL_TERMINATE_LENGTH)) == 0)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (mbstowcs(TargetBuffer.get(), reinterpret_cast<const char *>(Buffer), Length + NULL_TERMINATE_LENGTH) == static_cast<size_t>(RETURN_ERROR))
#endif
	{
		return false;
	}
	else {
		if (wcsnlen_s(TargetBuffer.get(), Length + NULL_TERMINATE_LENGTH) == 0)
			return false;
		else 
			Target = TargetBuffer.get();
	}

	return true;
}

//Convert wide char string to multiple bytes
bool WCS_To_MBS_String(
	const wchar_t * const Buffer, 
	const size_t MaxLen, 
	std::string &Target)
{
//Check buffer pointer.
	Target.clear();
	if (Buffer == nullptr || MaxLen == 0)
		return false;
	const auto Length = wcsnlen_s(Buffer, MaxLen);
	if (Length == 0 || CheckEmptyBuffer(Buffer, sizeof(wchar_t) * Length))
		return false;

//Initialization
	const auto TargetBuffer = std::make_unique<wchar_t[]>(Length + PADDING_RESERVED_BYTES);
	memset(TargetBuffer.get(), 0, Length + PADDING_RESERVED_BYTES);

//Convert string.
#if defined(PLATFORM_WIN)
	if (WideCharToMultiByte(
			CP_ACP, 
			0, 
			Buffer, 
			WCSTOMBS_NULL_TERMINATE, 
			reinterpret_cast<LPSTR>(TargetBuffer.get()), 
			static_cast<int>(Length + NULL_TERMINATE_LENGTH), 
			nullptr, 
			nullptr) == 0)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (wcstombs(reinterpret_cast<char *>(TargetBuffer.get()), Buffer, Length + NULL_TERMINATE_LENGTH) == static_cast<size_t>(RETURN_ERROR))
#endif
	{
		return false;
	}
	else {
		if (strnlen_s(reinterpret_cast<const char *>(TargetBuffer.get()), Length + NULL_TERMINATE_LENGTH) == 0)
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
	if (!RuleItem.empty() && !TestItem.empty() && TestItem.length() >= RuleItem.length() && TestItem.compare(0, RuleItem.length(), RuleItem) == 0)
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
