using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ABI.System;
using ABI.System.ComponentModel;
using ABI.System.Windows.Input;

namespace WinRT.RikaNET_WinUIGenericHelpers;

internal static class GlobalVtableLookup
{
	[ModuleInitializer]
	internal static void InitializeGlobalVtableLookup()
	{
		_0025__005E_002D_005E_002D_0026_0026((Func<System.Type, ComWrappers.ComInterfaceEntry[]>)LookupVtableEntries);
		while (true)
		{
			int num = 77825623;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)((~(((~(num2 - ~(~(~(~((-1627376742 - 461870638) * 639178695) * 1363761759) * -1572527961 + -889247625 * ((1954302502 - (73381886 + 1184076210)) * -582363849 - -(1348940122 - -351084039 - ~1075739692) + ~(0xF7814B2 ^ 0x12A619D2))))) - (-(~(444890935 * --688131639) ^ -(-237154639 * 194606613)) + (-904618259 - -(-938162090 ^ 0x6D3823FD) - (-880441245 ^ -796577509))) + (~((-451500882 ^ 0x6A7B28C4) * 1883929643) + (-1742212890 + (-1701026328 ^ -1383758262)) + ((-(-1983259828 - -139124362) - --1955300185 - -(--192429839) * 1818517453) ^ 0x4EE48983))) * 1623902951 + (0x39867323 ^ -(-2135362121 - 1850462843 + (0x4D0EE2C5 ^ 0x411A3B42)))) ^ -1841230097) - (0x250B92FC ^ 0x635A26C2)) ^ -2054186407)) % 3;
				int num5 = -1714408721;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 -= -1714408721;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -110800510;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = ~num7 * 1927274035;
					num7 = -num7 - -671915145;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1117636017;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = num9 * -1050084505 - -1424593719;
						num9 = num9 ^ 0x439DE7DB ^ -516230206;
					}
					if (num3 == (uint)num9)
					{
					}
					return;
				}
				_003C_005E_003C_003E_005E_003E_002D_0026((Func<System.Type, string>)LookupRuntimeClassName);
				int[,] array = new int[4, 4];
				array[0, 0] = -1716803840;
				array[0, 1] = 143983871;
				array[0, 2] = -581619281;
				array[0, 3] = 1106640478;
				array[1, 0] = 151241091;
				array[1, 1] = -1452630928;
				array[1, 2] = 1914131775;
				array[1, 3] = 307481782;
				array[2, 0] = 844065485;
				array[2, 1] = 391278928;
				array[2, 2] = 1790118419;
				array[2, 3] = 764525445;
				array[3, 0] = -159303478;
				array[3, 1] = 508745536;
				array[3, 2] = -1769064482;
				array[3, 3] = 1338149589;
				array[2, 1] = array[3, 2] ^ -1139539283;
				array[3, 2] = array[3, 1] ^ 0x36AE80B3;
				array[0, 1] ^= -249329704;
				array[1, 2] = array[2, 0] ^ -827413368;
				int num11 = array[1, 2] ^ -387429486;
				num = ((int)num4 * -1743270161) ^ 0x609E78CB ^ num11;
			}
		}
	}

	private unsafe static ComWrappers.ComInterfaceEntry[] LookupVtableEntries(System.Type type)
	{
		string text = _0023_0024_005E_0028_0024_0040_0029_002D((object)type);
		while (true)
		{
			int num = -840577031;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(((589982115 - (~num2 - (-(-798700139 * (1227974385 * (-928743937 ^ -991308338))) + 625053353 * (0x4E943E9D ^ ((~1403290137 - 623807653 - -487222863 - (-(-67831315 - 1087316849) ^ -509942677)) ^ (-1227835459 + -(--1558669698) + ((-1501136936 ^ 0x44FA060D) + (0x6FDB32D5 ^ 0x240CFD4F)))))) + (-((791357939 - ~(--1232186928 ^ 0x134085E8)) * 1792625597) + (-2128007200 - (-809212664 ^ -178464462) + -806328611 * (625670301 * -244562501))) - (21155208 + (~((-413712707 - (-280323118 ^ 0x5776E6B8)) * 2080077845) - ~-29800233)))) ^ (-(-215276146 + 460771751) * -1706000901 + -(~(-1086403354 + 684955065)))) * -2040245197 * -760395433) ^ -520112284)) % 6;
				int num5 = -1;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 = ~num5;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -1;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 = -num7;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -1098260824;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 -= -1098260829;
					}
					if (num3 == (uint)num9)
					{
						return new ComWrappers.ComInterfaceEntry[2]
						{
							new ComWrappers.ComInterfaceEntry
							{
								IID = _0028_0026_0024_002D_005E_002F_002D_003E(),
								Vtable = _003E_0029_0026_002D_0029_0021_002A_005E()
							},
							new ComWrappers.ComInterfaceEntry
							{
								IID = _0023_0026_002D_003F_0023_003C_002A_0024(),
								Vtable = _0021_0026_003D_005E_002B_002A_0024_0040()
							}
						};
					}
					int num11 = -709695249;
					_ = 0;
					for (int num12 = 0; num12 < 2; num12++)
					{
						num11 = -(~num11);
						num11 = num11 * -1349170457 * 320050805;
					}
					if (num3 != (uint)num11)
					{
						int num13 = -463282428;
						_ = 0;
						for (int num14 = 0; num14 < 2; num14++)
						{
							num13 = num13 * -400508181 + -188336225;
							num13 = (num13 ^ 0x60E3E9DE) + 1780507375;
						}
						if (num3 != (uint)num13)
						{
							int num15 = 758922266;
							_ = 0;
							for (int num16 = 0; num16 < 2; num16++)
							{
								num15 = ~num15;
								num15 = ~(num15 + 1051803313 * -951649844);
							}
							if (num3 != (uint)num15)
							{
							}
							return null;
						}
						return new ComWrappers.ComInterfaceEntry[2]
						{
							new ComWrappers.ComInterfaceEntry
							{
								IID = __0040_0026_0024_003E_0024_0040_005E(),
								Vtable = _002A_0024_002D_0029_003C_002F_0023_0024()
							},
							new ComWrappers.ComInterfaceEntry
							{
								IID = _005E_0023_003E_0021_0021_002B__003C(),
								Vtable = _005E_003F_002B_0024_0025_003D_0025_002A()
							}
						};
					}
					int num17;
					if (_0024_0026_0021_005E_0026_003D_002A_003D(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(13 + sizeof(int)) ^ sizeof(Guid)]))
					{
						num = -510671888;
						num17 = num;
					}
					else
					{
						num = 503425774;
						num17 = num;
					}
				}
				else
				{
					bool num18 = _0024_0026_0021_005E_0026_003D_002A_003D(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(12 + sizeof(int)) ^ sizeof(Guid)]);
					int[] array = new int[5] { -1695277975, 651020471, -1224788654, -2011831981, 1431268999 };
					array[3] ^= -110028782;
					array[0] = array[2] ^ -1546113750;
					array[3] = array[2] ^ -1771352685;
					int[] array2 = new int[4] { -137487748, -808300621, -1486182543, -2099307581 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][1] ^ -1033782841;
					array2[2] = array2[3] ^ 0x5F15A389;
					array2[3] = array2[1] ^ 0x67A5BF8E;
					array2[3] ^= -105620412;
					int num19 = array3[1][0] ^ 0x73EFCD4F;
					int[] array4 = new int[4];
					array4[0] = -2046985731;
					array4[1] = -783614466;
					array4[2] = 1062143479;
					array4[3] = -1213574343;
					array4[1] = array4[2] ^ -1511853878;
					array4[2] = array4[0] ^ -1257929904;
					array4[2] ^= -1735694874;
					int[] array5 = new int[4] { 1512996357, -1562115374, 461850103, -197683188 };
					int[][] array6 = new int[2][] { array4, array5 };
					array5[2] = array6[0][0] ^ -1886150678;
					array5[3] = array5[1] ^ 0x61DE22B1;
					array5[0] ^= 2123597230;
					int num20 = array6[1][2] ^ 0x4A9FD876;
					int num21 = (int)(num4 * 1843734241) ^ -1955558381;
					num19 ^= num21;
					num20 ^= num21;
					int num22;
					int num23;
					if (num18)
					{
						num22 = num20;
						num23 = num22;
					}
					else
					{
						num22 = num19;
						num23 = num22;
					}
					num = num22 ^ num21;
				}
			}
		}
	}

	private unsafe static string LookupRuntimeClassName(System.Type type)
	{
		string text = _0023_0024_005E_0028_0024_0040_0029_002D((object)type);
		if (_0024_0026_0021_005E_0026_003D_002A_003D(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0xC414 ^ 0xC414))]))
		{
			goto IL_002e;
		}
		goto IL_054b;
		IL_002e:
		int num = 1802900123;
		goto IL_0033;
		IL_0033:
		int num2 = num;
		uint num4;
		uint num3 = (num4 = (uint)(~(-(~783377804 + 138692502 - -2068641180 + -1989657115 + -206065000 - ((((num2 - -(-(-(~-1530516876)) - (-(~(-600312757 * 298810005)) - (~((0x7C86FA6D ^ -672879884) - (-533622342 ^ -1304576000)) * -704305175 - -(-1252740327 * -290598687 + -574610016 * -120689681 - -258394975 - ((-877094413 ^ -1266343076) + (905463391 - -1523224056) - (652356531 * -1619618087 - -1023159798))))))) ^ (~(753294701 * -(-245449705 * 1678098222 * 351945363 - (~-658446672 - (2100584137 - 2007306575))) + 1734269379 * (-737647213 * -875322559 + -151030117 - (324981750 - -476995914 * 111003945 + (-1758881338 ^ 0x4618604E)))) * 975359489)) * 1001383499) ^ 0x5F8953CD))) ^ 0x3B37C239)) % 5;
		int num5 = 1186988160;
		_ = 0;
		for (int num6 = 0; num6 < 2; num6++)
		{
			num5 = ~num5 - 683229260;
			num5 = ~(num5 ^ -593627763);
		}
		if (num3 == (uint)num5)
		{
			goto IL_002e;
		}
		int num7 = 2;
		_ = 0;
		for (int num8 = 0; num8 < 2; num8++)
		{
			num7 = -(num7 - ~1874433622);
			num7 = -(-num7);
		}
		if (num3 != (uint)num7)
		{
			int num9 = 1549427657;
			_ = 0;
			for (int num10 = 0; num10 < 1; num10++)
			{
				num9 ^= 0x5C5A63CD;
			}
			if (num3 != (uint)num9)
			{
				int num11 = 691794473;
				_ = 0;
				for (int num12 = 0; num12 < 1; num12++)
				{
					num11 = 691794474 - num11;
				}
				if (num3 != (uint)num11)
				{
					int num13 = 722230919;
					_ = 0;
					for (int num14 = 0; num14 < 2; num14++)
					{
						num13 = -1489277579 - ~num13;
						num13 = -(num13 * 1802642707);
					}
					if (num3 != (uint)num13)
					{
					}
					return null;
				}
				return _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x17B3C ^ 0x17B3F))];
			}
			goto IL_054b;
		}
		return _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(14 + sizeof(int)) ^ sizeof(Guid)];
		IL_054b:
		int num15;
		if (_0024_0026_0021_005E_0026_003D_002A_003D(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x866 ^ 0x867]))
		{
			num = 1564787059;
			num15 = num;
		}
		else
		{
			num = -1546567297;
			num15 = num;
		}
		goto IL_0033;
	}

	static void _0025__005E_002D_005E_002D_0026_0026(Func<System.Type, ComWrappers.ComInterfaceEntry[]> P_0)
	{
		try
		{
			throw new System.Exception();
		}
		catch (System.Exception)
		{
			while (true)
			{
				int num = -416983194;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(((num2 ^ -(-(-1747377746 ^ ((-2129113067 * 1845761803 + (-(508109835 - 7953656) - (876566595 - -1879144089 - 788946321)) - (-1945579361 * -115963467 - -(-1523934329 - 1478781683) * -620165799)) ^ ~((--1272439221 ^ 0x631F018D) * 1835036645))))) * -1684870445) ^ ~(~((~(~(1679716389 + 67875920)) + -(-1741919155 * -1711136318)) * -646948877)))) * 466558565 * -1688684791)) % 3;
					int num5 = -1734523388;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 * -2043965663;
						num5 = -num5 * -1178867483;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1597649413;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 1265186099;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= 398477759;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					ComWrappersSupport.RegisterTypeComInterfaceEntriesLookup(P_0);
					int[,] array = new int[4, 4];
					array[0, 0] = 826511983;
					array[0, 1] = 2070434612;
					array[0, 2] = -501761985;
					array[0, 3] = -1481000558;
					array[1, 0] = -1812658921;
					array[1, 1] = 1400238261;
					array[1, 2] = -1907439099;
					array[1, 3] = 1568527284;
					array[2, 0] = -228259643;
					array[2, 1] = 1374748015;
					array[2, 2] = 1457385348;
					array[2, 3] = 1015110719;
					array[3, 0] = -804986027;
					array[3, 1] = 108891689;
					array[3, 2] = 1662896855;
					array[3, 3] = -892558835;
					array[0, 0] = array[3, 1] ^ -570230577;
					array[1, 3] = array[3, 3] ^ -1764026523;
					array[3, 2] = array[3, 0] ^ 0x75EB4EFA;
					array[0, 0] = array[0, 3] ^ -65705343;
					int num11 = array[0, 0] ^ 0x6743CA91;
					num = (int)((num4 * 764369011) ^ 0xA74D9169u) ^ num11;
				}
			}
		}
	}

	static void _003C_005E_003C_003E_005E_003E_002D_0026(Func<System.Type, string> P_0)
	{
		try
		{
			throw new System.Exception();
		}
		catch (System.Exception)
		{
			while (true)
			{
				int num = 557206707;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(~(~(~num2 - -1982781731 * ((~(315010345 + -930140990 + -1572435238 * 1298383195) + ((-2112081114 ^ -623910645) - ((0x7D9C6328 ^ 0x7503861E) - -977642121)) + -177706664) ^ 0x582CA7A8)) - 2010313029 * -1040815366) - (--701252550 - ~(-952225555 * 2094174353) + ~(591812613 + (-1942413462 + 1954914694))) - (-1389781793 * 817676287 - (472509635 * 1891444348 + --1345771035))) - (-88628349 ^ -1456213230)))) % 3;
					int num5 = 1444571298;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 ^ --434742550) * -1998093259;
						num5 *= 1064310253;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1436507597;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -259205371;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 229072189;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 += -229072189;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					ComWrappersSupport.RegisterTypeRuntimeClassNameLookup(P_0);
					int[] array = new int[4] { -1481953246, 54671891, -2108814436, -1832717837 };
					array[0] ^= 1650874036;
					array[0] = array[1] ^ -432148373;
					int[] array2 = new int[7] { 1410490491, 1831390473, -929634123, -1834625793, -1448876549, 196664584, 1132249106 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][3] ^ -698395898;
					array2[6] = array2[5] ^ -17601532;
					array2[4] = array2[0] ^ 0x1F2B9C0E;
					array2[4] = array2[0] ^ -1813749068;
					int num11 = array3[1][2] ^ -1621242034;
					num = (int)((num4 * 237603952) ^ 0x79057560) ^ num11;
				}
			}
		}
	}

	static string _0023_0024_005E_0028_0024_0040_0029_002D(object P_0)
	{
		string result = default(string);
		try
		{
			throw new System.Exception();
		}
		catch (System.Exception)
		{
			while (true)
			{
				int num = 1644077655;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(-(-(~(--1052993338 ^ -1982215898)) - num2 - (-(1605967205 - -2138057966 - --583559985 - ~(354876190 - -1461425892)) + ((0x173CABFF ^ -632859826) - (-744183600 - -860133250) - (-2021115290 * -360177891 - ~1622883049) - (584277912 + (-1152577366 + 135974455) + ((0x87CD5BE ^ -836961140) + (1858107786 + -539201740)))) + (-((--173728851 + (587631014 - -933355575)) * -1964761171) ^ -830317489) - -1093250634) * 973815229)) - -(-(-1477063957 ^ 0x60BCD1EB))) * -1157716307 + ~(~(--1936170083)))) % 3;
					int num5 = -169370944;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * 1545587087 - -1979092063;
						num5 = ~num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1862107092;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 += -2075935344 - 747952549;
						num7 = ~(num7 ^ --1540180439);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1401194115;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= 277903403;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.ToString();
					int[,] array = new int[4, 4];
					array[0, 0] = 1954771220;
					array[0, 1] = 1210742868;
					array[0, 2] = 1308413746;
					array[0, 3] = 1155745965;
					array[1, 0] = -1059552329;
					array[1, 1] = -360345387;
					array[1, 2] = -1543799109;
					array[1, 3] = -644619677;
					array[2, 0] = 2036602045;
					array[2, 1] = 102952389;
					array[2, 2] = -999875572;
					array[2, 3] = 956070374;
					array[3, 0] = -419444045;
					array[3, 1] = 1474403007;
					array[3, 2] = -978129190;
					array[3, 3] = -669129702;
					array[2, 1] = array[3, 1] ^ 0x276B558F;
					array[1, 3] = array[0, 3] ^ 0x11703940;
					array[1, 3] = array[0, 0] ^ 0x7F6BC9C8;
					int num11 = array[1, 3] ^ 0x27E32BC0;
					num = (int)((num4 * 1096374274) ^ 0x14D8D07E) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static bool _0024_0026_0021_005E_0026_003D_002A_003D(string P_0, string P_1)
	{
		try
		{
			throw new System.Exception();
		}
		catch (System.Exception)
		{
			return P_0 == P_1;
		}
	}

	static Guid _0028_0026_0024_002D_005E_002F_002D_003E()
	{
		Guid ıID = default(Guid);
		try
		{
			throw new System.Exception();
		}
		catch (System.Exception)
		{
			while (true)
			{
				int num = 1406575775;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-((~num2 * 1096020535) ^ (-1903117915 ^ (972346074 + -(0x4DF9E398 ^ -1532135814) + ~-1358902965)))) * 1867756857)) % 3;
					int num5 = 1530360722;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 *= 1366995037;
						num5 = -(~num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -184290053;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += 184290054;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -1853921650 - num9;
							num9 = ~(~num9);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ıID = IServiceProviderMethods.IID;
					int[,] array = new int[4, 3];
					array[0, 0] = 699739280;
					array[0, 1] = 1637302289;
					array[0, 2] = -149920085;
					array[1, 0] = 495537234;
					array[1, 1] = 241127896;
					array[1, 2] = 426165815;
					array[2, 0] = 1993789967;
					array[2, 1] = -1931292690;
					array[2, 2] = -799100132;
					array[3, 0] = -1190036679;
					array[3, 1] = 280162887;
					array[3, 2] = -60907146;
					array[0, 2] = array[0, 1] ^ 0x61FF0C40;
					array[2, 0] = array[0, 0] ^ 0x41E22D3F;
					array[3, 1] = array[2, 1] ^ 0x5BC5E46A;
					int num11 = array[3, 1] ^ 0x2046FE92;
					num = ((int)num4 * -574404086) ^ -844753904 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ıID;
	}

	static nint _003E_0029_0026_002D_0029_0021_002A_005E()
	{
		nint abiToProjectionVftablePtr = default(nint);
		try
		{
			throw new System.Exception();
		}
		catch (System.Exception)
		{
			while (true)
			{
				int num = 205325356;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((~(-(-(~num2 ^ ((~(~((-1345128935 + -1088678056) ^ -885412172)) - (-2052488809 * 549211553 - (((0x1618FFF4 ^ 0x44A85167) + --790137140) ^ -116219465) * 2038765811)) ^ (-1455387221 * -(~(~-520794289)) * -429753261 * 193157631) ^ (~(~(1679791855 + 393901249) + 2047351199 - 1402288800 * 1274697699) * -1397774979 + -(-592785096 * 581189109 - (1225647317 - ((--1883659491 * 1776632479) ^ -(--1696670907))))))) - -(~(~(~-2049208064)) + ~(0x504781D3 ^ -2111138919))) * -1292463535) ^ -(1228172770 + -1803273218)) - 34502797 * 862660289))) % 3;
					int num5 = -2;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 744378177;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 ^ -1111374453) + -2141786692;
						num7 = (num7 - ~1985066460) * 530657339;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -970499154;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9 - 2056634725;
							num9 = num9 * -1047041005 + -1636842250;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					abiToProjectionVftablePtr = IServiceProviderMethods.AbiToProjectionVftablePtr;
					int[] array = new int[7];
					array[0] = -893671133;
					array[1] = -1897178599;
					array[2] = -1743128432;
					array[3] = 619674352;
					array[4] = 1292804575;
					array[5] = -1935971097;
					array[6] = 518222984;
					array[0] = array[3] ^ 0x4F98A0F0;
					array[0] = array[5] ^ 0x1A96FE00;
					array[3] = array[0] ^ 0x5B6658F8;
					int[] array2 = new int[6];
					array2[0] = 448801421;
					array2[1] = -695526553;
					array2[2] = -1082808029;
					array2[3] = 509534498;
					array2[4] = 2131444724;
					array2[5] = -1751099809;
					array2[5] = array[2] ^ 0x3A75EF27;
					array2[1] = array2[2] ^ -1717986457;
					array2[1] = array2[4] ^ 0x11E76CBE;
					int num11 = array2[5] ^ -1355765723;
					num = ((int)num4 * -501285132) ^ 0x1868A9C8 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return abiToProjectionVftablePtr;
	}

	static Guid _0023_0026_002D_003F_0023_003C_002A_0024()
	{
		Guid ıID = default(Guid);
		try
		{
			throw new System.Exception();
		}
		catch (System.Exception)
		{
			while (true)
			{
				int num = -1812718265;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(-(-(-307683050 + ~(0x42A0DF9F ^ 0x1601DCB2) * 1773877751) - ~(-(~(-num2)))) ^ ~(--1214583476 ^ 0x270F46D7)) ^ 0x786D7869))) % 3;
					int num5 = -1177560490;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= 128018819;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= 404409001;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ıID = IDisposableMethods.IID;
					int[] array = new int[4];
					array[0] = -1361460295;
					array[1] = 1530733843;
					array[2] = 868506884;
					array[3] = 825110062;
					array[2] = array[3] ^ 0x7B9F203A;
					array[0] = array[1] ^ -1981472021;
					array[2] ^= -2096599157;
					int[] array2 = new int[5];
					array2[0] = -1824701456;
					array2[1] = 1477360091;
					array2[2] = 768243304;
					array2[3] = 783083236;
					array2[4] = -251037977;
					array2[1] = array[3] ^ 0x57B1A958;
					array2[0] = array2[1] ^ 0x4FE066DA;
					array2[3] = array2[1] ^ 0x7C3DAF11;
					int num11 = array2[1] ^ -1011819552;
					num = (int)((num4 * 453080048) ^ 0x43031330) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ıID;
	}

	static nint _0021_0026_003D_005E_002B_002A_0024_0040()
	{
		nint abiToProjectionVftablePtr = default(nint);
		try
		{
			throw new System.Exception();
		}
		catch (System.Exception)
		{
			while (true)
			{
				int num = -1272062142;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((((-(~num2) - (-(851916641 * ~(1893328634 - --513246932 * 1062819483)) + (-549701284 ^ 0x6C2C7895)) - 442374662 - -(~-1261079470)) * 1392760425 - -(-8680310 - -868209992 - --1584542398)) * 51063621 - ~-888239100) ^ 0x69C1ABFC)) % 3;
					int num5 = -1074728377;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= -1074728377;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 870137430;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 870137429;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -553509367;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -553509369;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					abiToProjectionVftablePtr = IDisposableMethods.AbiToProjectionVftablePtr;
					int[,] array = new int[3, 3];
					array[0, 0] = 621004770;
					array[0, 1] = -538116211;
					array[0, 2] = -470057826;
					array[1, 0] = 1435214600;
					array[1, 1] = -500386311;
					array[1, 2] = 607900583;
					array[2, 0] = 1746441982;
					array[2, 1] = -899416738;
					array[2, 2] = 335219970;
					array[1, 2] = array[0, 0] ^ 0x129B919E;
					array[0, 2] = array[1, 2] ^ -894043345;
					array[2, 2] = array[1, 1] ^ -432400792;
					int num11 = array[2, 2] ^ 0x3A6E374B;
					num = (int)((num4 * 101309549) ^ 0xB4CD7BB3u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return abiToProjectionVftablePtr;
	}

	static Guid __0040_0026_0024_003E_0024_0040_005E()
	{
		Guid ıID = default(Guid);
		try
		{
			throw new System.Exception();
		}
		catch (System.Exception)
		{
			while (true)
			{
				int num = -1746429575;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(~(-((-(num2 * 128322645) ^ 0x6BF58D8) + -(-859559813 * (~1056348705 - ~(1944470310 * 1944824619)) + -1341362839)) + ((-1459438049 ^ -422557031) - ((-2081498250 ^ 0x38F245FE) - -1702310859))))) + -557625832)) % 3;
					int num5 = -1;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = ~num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 981562401;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 * 1325560559) ^ -412463446;
						num7 = ~(num7 - (0x4BDA1066 ^ -582051849));
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 + (1718109059 + -1877364637));
							num9 = -((-481374758 ^ -1073970384) - num9);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ıID = ICommandMethods.IID;
					int[] array = new int[5];
					array[0] = 203118665;
					array[1] = -1535424256;
					array[2] = -319654270;
					array[3] = 1094962989;
					array[4] = -614126447;
					array[0] = array[4] ^ -1028944825;
					array[2] = array[1] ^ 0x2921D523;
					int[] array2 = new int[7] { -1626007172, 1660420492, 1235056088, -133126134, -567660177, -905774078, -1201650656 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][3] ^ -592013237;
					array2[6] ^= -1110234588;
					array2[4] = array2[5] ^ 0x1A98562E;
					array2[6] = array2[3] ^ 0x3843FC03;
					int num11 = array3[1][2] ^ -1240851701;
					num = ((int)num4 * -486969925) ^ 0x4441BDC9 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ıID;
	}

	static nint _002A_0024_002D_0029_003C_002F_0023_0024()
	{
		nint abiToProjectionVftablePtr = default(nint);
		try
		{
			throw new System.Exception();
		}
		catch (System.Exception)
		{
			while (true)
			{
				int num = -352337619;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((0x203BDB66 ^ -456006733) - ((num2 ^ (-2123926787 * -((0x6AD214F5 ^ (-(-757463336 + (294257299 - -972399292)) ^ (-(~-242290610) ^ 0x5F6C6E67))) - (-266934929 ^ (0x490C19EF ^ (1888344192 + -995678407 + (1985180536 - 716892677) - -(-767207339 ^ -902987175))))) + 1659953429 * ((-(-706590087 ^ (-89334335 ^ (486739009 * -1988155228))) ^ 0x4EFEC3E1) + (-839256982 ^ ((-1468372416 ^ (-2054719688 - -766821524)) + (0xD2F9323 ^ -(1719553650 - -1297297249))) ^ (-((-1016976329 + -222221628) * -537148919 - (-1050359856 ^ 0x50E17B21)) * -283366935))))) * 1536420283 * 575809083 - -(0x7A17594 ^ -1455210431) - (-1294538679 ^ (-(631553654 - -334102705) + (0x53BF4AF9 ^ 0x63D7D2DF) + (-2050060663 ^ -1999486485)))) * -411298647 - -452131111 - (0x8CEECCC ^ -1073548160)))) % 3;
					int num5 = 1488070810;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 1488070810;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1614030504;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 * -1216969183 - 1948524755;
						num7 = ~(1547191161 * -813719905 - num7);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -940771402;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= -940771401;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					abiToProjectionVftablePtr = ICommandMethods.AbiToProjectionVftablePtr;
					int[] array = new int[7];
					array[0] = -1883150722;
					array[1] = 1334929924;
					array[2] = 1261120764;
					array[3] = -678310086;
					array[4] = -40112021;
					array[5] = 1276036792;
					array[6] = 684841074;
					array[5] = array[3] ^ -227783550;
					array[0] = array[5] ^ 0x64CCBB87;
					array[5] = array[1] ^ 0x2E97AF3A;
					int[] array2 = new int[7] { 1951379065, -91335731, -495221430, 595445752, -650170735, 430919629, 1139399073 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[5] = array3[0][6] ^ 0x2CA85BE5;
					array2[0] ^= 568849466;
					array2[1] ^= -1118043791;
					int num11 = array3[1][5] ^ 0x3B38D8DE;
					num = ((int)num4 * -1417323052) ^ 0x7F28B7BC ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return abiToProjectionVftablePtr;
	}

	static Guid _005E_0023_003E_0021_0021_002B__003C()
	{
		Guid ıID = default(Guid);
		try
		{
			throw new System.Exception();
		}
		catch (System.Exception)
		{
			while (true)
			{
				int num = 1118688389;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(~(-(-(-(~((~(-(--1370714037 + -1333417915)) ^ ((-(--1614436986 ^ 0x6D02C5) ^ 0x1D1F720A) * -2143560829 * -40141951 - (~(787326843 * (~(-1563522321 ^ --1432959219) - (964427907 + -848636361 - (1360488485 - -883866163) - ~(-1218010615 + -1430700544)))) ^ (-891733575 - ((-(0x28423256 ^ -421341425) + (0x19155327 ^ -1443575107)) ^ 0x79DAC624) * 942827057)))) - num2)))))) - (0xB4FD431 ^ 0x1F4B62E5)) * -2050385035)) % 3;
					int num5 = 2;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(num5 ^ 0x634CC39C);
						num5 = ~(-num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 15;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7;
						num7 = ~num7 ^ 0xC86CC16;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1627071868;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 1627071868;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ıID = INotifyPropertyChangedMethods.IID;
					int[] array = new int[7];
					array[0] = 60419415;
					array[1] = 1302406565;
					array[2] = -2105590588;
					array[3] = 2103664917;
					array[4] = 1824348809;
					array[5] = -615627975;
					array[6] = 134729304;
					array[5] = array[0] ^ -969025269;
					array[2] = array[5] ^ -1793309904;
					array[1] = array[0] ^ -693331293;
					int[] array2 = new int[6] { 1103964795, -2022201776, 1708993312, -1572623918, -604705466, -1675395570 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][6] ^ 0x5DED063E;
					array2[2] = array2[0] ^ 0x5245E05D;
					array2[2] = array2[0] ^ -191908498;
					int num11 = array3[1][4] ^ 0x6E59E7A;
					num = ((int)num4 * -8892825) ^ 0x3D045421 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ıID;
	}

	static nint _005E_003F_002B_0024_0025_003D_0025_002A()
	{
		nint abiToProjectionVftablePtr = default(nint);
		try
		{
			throw new System.Exception();
		}
		catch (System.Exception)
		{
			while (true)
			{
				int num = -1867833379;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(~num2 * -623106633)))) % 3;
					int num5 = -1870020588;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -num5 + -970666108;
						num5 = ~(num5 ^ -2042945611);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 837283057;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -465730543;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = -num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					abiToProjectionVftablePtr = INotifyPropertyChangedMethods.AbiToProjectionVftablePtr;
					int[,] array = new int[4, 4];
					array[0, 0] = -1299580494;
					array[0, 1] = -1937033808;
					array[0, 2] = 2098110654;
					array[0, 3] = 1329996916;
					array[1, 0] = 807359976;
					array[1, 1] = -360981309;
					array[1, 2] = 1509377369;
					array[1, 3] = -362344339;
					array[2, 0] = -108260283;
					array[2, 1] = -1332898923;
					array[2, 2] = 162606997;
					array[2, 3] = 233735295;
					array[3, 0] = 319206886;
					array[3, 1] = 1007756962;
					array[3, 2] = -1664428579;
					array[3, 3] = 663756529;
					array[1, 0] = array[3, 1] ^ 0x28593945;
					array[1, 3] = array[2, 2] ^ 0x7863F3C;
					array[2, 1] = array[3, 0] ^ 0x7649A378;
					int num11 = array[2, 1] ^ 0x34375A2A;
					num = (int)((num4 * 1276001499) ^ 0xF3DEA0BAu) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return abiToProjectionVftablePtr;
	}
}
