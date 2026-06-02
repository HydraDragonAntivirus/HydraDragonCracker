using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using dnlib.DotNet;
using dnlib.DotNet.Writer;
using RikaNET.Core.Models;
using RikaNET.Core.Services;
using RikaNET.WinUI.Services;

namespace wkj_003D;

public sealed class cma_003D : IAssemblyWorkspaceService
{
	[Serializable]
	[CompilerGenerated]
	private sealed class _003C_003Ec
	{
		public static readonly _003C_003Ec _003C_003E9 = new _003C_003Ec();

		public static Func<TypeDef, bool> _003C_003E9__12_0;

		public static Func<TypeDef, bool> _003C_003E9__12_1;

		public static Func<TypeDef, bool> _003C_003E9__12_2;

		public static Func<TypeDef, bool> _003C_003E9__12_3;

		public static Func<TypeDef, bool> _003C_003E9__12_4;

		public static Func<TypeDef, string> _003C_003E9__12_5;

		public static Func<IGrouping<string, TypeDef>, string> _003C_003E9__12_6;

		public static Func<TypeDef, string> _003C_003E9__12_7;

		public static Func<MethodDef, bool> _003C_003E9__12_8;

		public static Func<TypeDef, bool> _003C_003E9__12_9;

		public static Func<TypeDef, bool> _003C_003E9__15_0;

		public static Func<List<MethodItem>, IEnumerable<MethodItem>> _003C_003E9__15_1;

		public static Func<CustomAttribute, bool> _003C_003E9__15_2;

		public static Func<Parameter, bool> _003C_003E9__16_0;

		public static Func<Parameter, string> _003C_003E9__16_1;

		public static Func<CustomAttribute, bool> _003C_003E9__20_0;

		internal bool _003CBuildDnlibProfile_003Eb__12_0(TypeDef type)
		{
			return !_0024_0040_0040_0023_0029_0029_002B_003E(type);
		}

		internal bool _003CBuildDnlibProfile_003Eb__12_1(TypeDef type)
		{
			return !ejJ_003D(_0028_003E__0023_0028_0029_0024_003D(_0028_005E_005E_003C_003D_003E_0026_0040(type)));
		}

		internal bool _003CBuildDnlibProfile_003Eb__12_2(TypeDef type)
		{
			return !WRp_003D(type);
		}

		internal bool _003CBuildDnlibProfile_003Eb__12_3(TypeDef type)
		{
			return !__002D_005E_0024_003E_0040_002F_0021(type);
		}

		internal bool _003CBuildDnlibProfile_003Eb__12_4(TypeDef type)
		{
			return !_002F_002A_002D_003C_002A_002F_0026_005E(_0028_003E__0023_0028_0029_0024_003D(_005E_002B_0024_0029_002A_005E__002A(type)), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x1157 ^ 0x109B], StringComparison.Ordinal);
		}

		internal string _003CBuildDnlibProfile_003Eb__12_5(TypeDef type)
		{
			UTF8String uTF8String = _005E_002B_0024_0029_002A_005E__002A(type);
			string text = (((object)uTF8String != null) ? _0025_0028_002B_0029_002F_0029_003E_003D((object)uTF8String) : null);
			while (true)
			{
				int num = -1777776416;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(-(~(-num2)) - -2130386884) + (-771487814 ^ -(--169893434 - --1739361835))))) % 4;
					int num5 = -1338058301;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= 1387896001;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1938125525;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= -1938125527;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 580522533;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= 807516589;
						}
						if (num3 != (uint)num9)
						{
							int num11 = 1838727770;
							_ = 0;
							for (int num12 = 0; num12 < 2; num12++)
							{
								num11 = -(~num11);
								num11 = -(num11 * -1399677485);
							}
							if (num3 != (uint)num11)
							{
							}
							return _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[2653 - 2232 + 40];
						}
						return text;
					}
					bool num13 = _005E_002A_002D_002F_002B_002A_0024_0026(text);
					int[] array = new int[7];
					array[0] = -1386419182;
					array[1] = 561851624;
					array[2] = 767191887;
					array[3] = -388758078;
					array[4] = 442673621;
					array[5] = -539022441;
					array[6] = -1335238714;
					array[5] = array[3] ^ -789682439;
					array[5] = array[6] ^ 0x2F6EDED9;
					int[] array2 = new int[6] { -224989696, 1226962000, 1527775721, 1504518215, -1567343099, -678090992 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][2] ^ 0x9A575C5;
					array2[2] ^= 848763098;
					array2[0] = array2[3] ^ 0x65B1F484;
					int num14 = array3[1][3] ^ -1536924884;
					int[,] array4 = new int[3, 4];
					array4[0, 0] = 713546477;
					array4[0, 1] = -16005922;
					array4[0, 2] = 1292053475;
					array4[0, 3] = 2039162611;
					array4[1, 0] = -286686656;
					array4[1, 1] = -879551081;
					array4[1, 2] = -1973018872;
					array4[1, 3] = -987943318;
					array4[2, 0] = -863706480;
					array4[2, 1] = 1068756075;
					array4[2, 2] = -543681848;
					array4[2, 3] = -1280263914;
					array4[0, 2] = array4[2, 2] ^ -1091667140;
					array4[0, 3] = array4[1, 2] ^ -1742631953;
					array4[1, 3] = array4[0, 3] ^ 0x4F53651C;
					array4[0, 0] = array4[0, 1] ^ 0x48A100C;
					int num15 = array4[0, 0] ^ 0x791F8CC3;
					int num16 = (int)(num4 * 1742798317) ^ -182135150;
					num14 ^= num16;
					num15 ^= num16;
					int num17;
					int num18;
					if (!num13)
					{
						num17 = num15;
						num18 = num17;
					}
					else
					{
						num17 = num14;
						num18 = num17;
					}
					num = num17 ^ num16;
				}
			}
		}

		internal string _003CBuildDnlibProfile_003Eb__12_6(IGrouping<string, TypeDef> group)
		{
			return group.Key;
		}

		internal string _003CBuildDnlibProfile_003Eb__12_7(TypeDef item)
		{
			UTF8String uTF8String = _0028_005E_005E_003C_003D_003E_0026_0040(item);
			if ((object)uTF8String == null)
			{
				return null;
			}
			return _0025_0028_002B_0029_002F_0029_003E_003D((object)uTF8String);
		}

		internal bool _003CBuildDnlibProfile_003Eb__12_8(MethodDef method)
		{
			if (@_005E_003F_0040_002B_003F_003D_0023(method))
			{
				uint num2;
				int num4;
				do
				{
					int num = 371385121;
					uint num3;
					num2 = (num3 = (uint)(~(~(num + ((~(-1093253086 + ~(-319882414) - ((0x141E4958 ^ -1504660309) + -534804648)) - (-(-(799099151 + 773389566) - ~(~682240761)) ^ -238373503) + ~(395744439 * --1906079765) * -1010715037) ^ ((((~-1330749903 - (0x6F5165B1 ^ 0x4519F1FE)) * -426723347 - (-1698139829 ^ -1034677039) - (((--1871375512 + 110558407 * -199948479) ^ 0x9F4592) - -1096614058)) * -1374319491) ^ ((-(-1499292031 ^ -(-186934032 - -890126169)) + (-1072442215 ^ -(~(-1023914365 + -1881136821)))) ^ --627464231)) ^ (~(((--70771140 ^ 0x16A2AE5C) - -470576005) ^ (~(188718341 * -2111180787 * 520746161) - -(0x6D62AE60 ^ 0x7DD29F94))) + 2035166131 + (-((0x53C576ED ^ 0x788ECD9E) + (0x58AF890B ^ -1825119697)) - ~(-1773637429 * 591707135 - -1490333250) - (~788291466 + ((0x7C2CF5EC ^ 0x3216548F) - 884351458)) + -2142500516 - --252222019))))) * 2056866191)) % 3;
					num4 = 42002338;
					_ = 0;
					for (int num5 = 0; num5 < 1; num5++)
					{
						num4 -= 42002336;
					}
				}
				while (num2 == (uint)num4);
				int num6 = -2058263367;
				_ = 0;
				for (int num7 = 0; num7 < 2; num7++)
				{
					num6 = (num6 * 883972629) ^ 0x54C30D98;
					num6 = num6 * 1974117429 * 1574804613;
				}
				if (num2 == (uint)num6)
				{
					return !_002F_002A_002D_003C_002A_002F_0026_005E(_0028_003E__0023_0028_0029_0024_003D(_0025_0024_005E_0040_003F_0029_005E_003D(method)), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x1B9E ^ 0x1A50))], StringComparison.Ordinal);
				}
				int num8 = 0;
				_ = 0;
				for (int num9 = 0; num9 < 2; num9++)
				{
					num8 = ~num8 - -129565977;
					num8 = num8 - --258493905 + -1751531323;
				}
				if (num2 == (uint)num8)
				{
				}
			}
			return false;
		}

		internal bool _003CBuildDnlibProfile_003Eb__12_9(TypeDef type)
		{
			return _002F_002A_002D_003C_002A_002F_0026_005E(_0026_002D_0024_0026_0029_002A_0023_0029(type), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-692 + 228)], StringComparison.Ordinal);
		}

		internal bool _003CPrepareAssemblyForProtection_003Eb__15_0(TypeDef type)
		{
			return _002F_002A_002D_003C_002A_002F_0026_005E(_0026_002D_0024_0026_0029_002A_0023_0029(type), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-769 + 305)], StringComparison.Ordinal);
		}

		internal IEnumerable<MethodItem> _003CPrepareAssemblyForProtection_003Eb__15_1(List<MethodItem> items)
		{
			return items;
		}

		internal bool _003CPrepareAssemblyForProtection_003Eb__15_2(CustomAttribute attribute)
		{
			return _002F_002A_002D_003C_002A_002F_0026_005E(_003F_002B_002F_005E_003F_0021_0023_0023((IFullName)_0024_0029_0025_003E_002A_0024_002D_0025(attribute)), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[553 - 28 - 28 - 34], StringComparison.Ordinal);
		}

		internal bool _003CBuildSignature_003Eb__16_0(Parameter parameter)
		{
			return !_005E_003D_005E_002A_0024_003C_0024_003C(parameter);
		}

		internal string _003CBuildSignature_003Eb__16_1(Parameter parameter)
		{
			return _0024_003E_003E_0025_002A_0024_0026_002B(idi_003D(_0021_0029_0040__0025_005E_0024_002B(parameter)), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x1EDB ^ 0x1F0B], _005E_0025_0021_003E_0024_0021_002F_0025(parameter));
		}

		internal unsafe bool _003CHasVirtualizationAttribute_003Eb__20_0(CustomAttribute attribute)
		{
			return _002F_002A_002D_003C_002A_002F_0026_005E(_003F_002B_002F_005E_003F_0021_0023_0023((IFullName)_0024_0029_0025_003E_002A_0024_002D_0025(attribute)), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(475 + sizeof(int)) ^ sizeof(Guid)], StringComparison.Ordinal);
		}

		static bool _0024_0040_0040_0023_0029_0029_002B_003E(TypeDef P_0)
		{
			bool ısGlobalModuleType = default(bool);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1439260551;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((-(~(~((num2 ^ (~(-(-(-1011357235 + (~(29494953 - 984175821) - (-1058525312 + ~539332017))) + -(-(1737631088 + -600175798 + (387421081 - 1002267728)) ^ -(743511927 + -2115813302)))) ^ (~((-2134028689 ^ 0x41967321) - (0x48579D26 ^ 0xF67298C) - (-707098543 - --508066924 - ((0x296E8C8 ^ 0x3DC5ED38) - (-1716146369 - -1604537241)) + 391342302)) + ~(-(-1330993517 * -1627706619)) + (0x511BBFAE ^ (~(-(-653026946 + -638010808 + (-175479003 ^ -1438402413))) + 987567082) ^ 0x7714815C)))) - -((0x155D7993 ^ -401172831) + (-1474339339 * -(-2068625909 * -1033821761) - (-231073731 ^ -804980017 ^ -165184631) + (-(0x44585F00 ^ 0x6E3F79CA) - (-8599222 + (1428094207 - 2109218176) * 572176233))) - (-(0x55A1FB6A ^ 0x6BE12211) - -130787308 - (((-(-476454924 - 2053328823) * 1654653951) ^ (--659281107 + --1629039812 + (-1799918346 + (-720479491 - 1521261740)))) - (1443454363 + -2085561633 + (-191586205 - -713233145) + ((-1155313827 ^ 0x7FFA7D1A) + -1948298035) - ~(--1204592989 - -1845733843 * 1573305715)))))) ^ (1323334595 * --1236064049 + -1012911070 * -1733506223 + (-(778485253 - (734980012 * -501477245 + (-938583222 ^ -1090252035))) + -1357188331 * 70527564))) * -1256342261 * -1157026319) - ~581733089) ^ 0xA29E32B)) % 3;
						int num5 = 1243992370;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 ^= 0x4A25D132;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 311511359;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 -= 311511358;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 409437886;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 ^= 0x186786BC;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						ısGlobalModuleType = P_0.IsGlobalModuleType;
						int[] array = new int[7];
						array[0] = 1782141255;
						array[1] = 2117050980;
						array[2] = -1463838942;
						array[3] = -125516400;
						array[4] = -560721724;
						array[5] = -359399064;
						array[6] = -1078237094;
						array[0] = array[4] ^ 0x27D7120;
						array[1] = array[4] ^ -1621314687;
						int[] array2 = new int[5] { -1077578996, 1546663361, 865377127, -1364632289, -1544573861 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[3] = array3[0][4] ^ -954667004;
						array2[0] = array2[2] ^ -2039440617;
						array2[4] = array2[1] ^ -514822791;
						array2[0] ^= -1876819870;
						int num11 = array3[1][3] ^ 0x7D298618;
						num = (int)((num4 * 463860634) ^ 0xACE077E6u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return ısGlobalModuleType;
		}

		static UTF8String _0028_005E_005E_003C_003D_003E_0026_0040(TypeDef P_0)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				return P_0.Name;
			}
		}

		static string _0028_003E__0023_0028_0029_0024_003D(UTF8String P_0)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				return P_0;
			}
		}

		static bool __002D_005E_0024_003E_0040_002F_0021(TypeDef P_0)
		{
			bool ısEnum = default(bool);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -617487500;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(~(-(-(-((num2 + (~(1758518585 + -920506838 + (1175574019 * (115721473 * (~(~133809414) + --649951262)) - ((-610710280 ^ -503596689) + -(~1282885152)))) ^ ((~(681116445 * ~-1532665305) + ((0x4A7C7203 ^ -530836807) + -1065453717 + (137480142 - 1874249435 + (-1742597430 - -845999780))) + 1538978081 * ((0x3D8D162A ^ -962200289) * 950242955) + ~(-649301360 - ((-225380251 ^ 0x8CA5431) - ~610121802) * -1541360095) - (1133140269 * ((125359430 - 902309061 + 1751279444) * -1682496101) * 1101066127 + (1812558623 + (~(~(--2038469972)) - ~-1423919479)))) ^ (-((-2048339401 ^ 0x130B5FD7) + (-(~2010807579) - (-352762287 ^ 0x4FA03E84))) + -451865893 * 1042719629)))) * -1068197529) * -540636153)) + ~(-899303177 ^ -1215270089))) * -1836073681)) % 3;
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
						int num7 = 3;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~num7;
							num7 = -(num7 ^ -1554629006);
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1613574624;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -num9 * 119830623;
								num9 ^= -1326215769;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						ısEnum = P_0.IsEnum;
						int[] array = new int[7];
						array[0] = -1157466247;
						array[1] = 1107401832;
						array[2] = 1854462116;
						array[3] = 1710486048;
						array[4] = 1986360094;
						array[5] = 1943236761;
						array[6] = 1615039374;
						array[2] = array[3] ^ 0x66025B5C;
						array[1] = array[3] ^ 0xD5E5A6F;
						int[] array2 = new int[4];
						array2[0] = -1634473476;
						array2[1] = 946388240;
						array2[2] = 388981323;
						array2[3] = -210922850;
						array2[1] = array[4] ^ -1212238500;
						array2[2] = array2[0] ^ 0x289A355;
						array2[2] = array2[1] ^ -224761045;
						int num11 = array2[1] ^ -1166733266;
						num = (int)((num4 * 891747027) ^ 0x5E9032AC) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return ısEnum;
		}

		static UTF8String _005E_002B_0024_0029_002A_005E__002A(TypeDef P_0)
		{
			UTF8String result = default(UTF8String);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1972304360;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(-(~(-(~(num2 * -1918034435)) - 1289639299 * (-956834189 + (-208827637 * (0x7451522 ^ --173071623) - (-50598247 * -1340840144 * -1675440977 + (-636064254 ^ -1537040496)))) - -328205233) ^ ~(~(--207532165))) + (0x69467F87 ^ -1110051652)))) % 3;
						int num5 = -1832121952;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 ^= -1783202020;
							num5 *= 1216871785;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -3;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 = ~num7;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1008550093;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 *= 192195589;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.Namespace;
						int[,] array = new int[3, 3]
						{
							{ -1436539471, 854815244, -1312873389 },
							{ 52452254, 1881432520, -1981942782 },
							{ 810105176, 1106501198, 15295385 }
						};
						array[1, 2] ^= -955850480;
						array[1, 1] = array[2, 2] ^ 0x8C37B91;
						array[2, 2] = array[1, 1] ^ -550231233;
						array[2, 0] = array[0, 1] ^ -1042680585;
						int num11 = array[2, 0] ^ -1293751680;
						num = (int)((num4 * 334154071) ^ 0x4B354F2B) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static bool _002F_002A_002D_003C_002A_002F_0026_005E(string P_0, string P_1, StringComparison P_2)
		{
			bool result = default(bool);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -191190334;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((((((num2 ^ (((0x7CA86ABE ^ -(-(-2092259917 * (--1086254940 + (38672795 + -947672439))))) + --9964080 - (802508021 + ((-1352087316 ^ 0x6A9B609B) + 2064815921)) * -1698756597) ^ ~(~(~((-176454738 ^ -1837812571) * 1158549113) - --274148564) - (-1989019264 + (~(~-1887821582 - 1498471183 * 11456989 - -(-1101021378 - -1493899950)) + (-118131930 + (-917152263 + 1568644489) - ~(1985822433 * 364915155)) * 970789729)))) ^ -700568967) * 1126072981) ^ (-1353352989 ^ (~(0x5430A59B ^ -2060998132) - (-403075308 ^ (-(--700119916) ^ 0x20B2D594))))) + (~(-2094222909 - 1702626255 - (1694110665 - -1561345920) - (632040330 - (0x6FFE83F4 ^ -439964692))) + (~(1293796363 * (1638323732 - -197285406)) - (-1204364161 + ~(-266810461 ^ 0x6E9D1FC9)))) - (-114225091 - (~(-557530185 - -291152931) + 66217651 * ~-1912281967))) ^ -1210890249) - (768487779 * 416825517 - (-357016311 + 714058228)) - (-879347742 + 1766843182))) % 3;
						int num5 = -2033751488;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -1824042324 - (num5 ^ 0x4E6F6938);
							num5 = num5 * 587065163 - 715979329;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1757955233;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 *= -1161912479;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 605708040;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = (num9 ^ -1696519409) + -636458930;
								num9 = (num9 * 1639124045) ^ -181961870;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = string.Equals(P_0, P_1, P_2);
						int[,] array = new int[4, 3];
						array[0, 0] = -976374916;
						array[0, 1] = -381020944;
						array[0, 2] = 1994452824;
						array[1, 0] = 1467243148;
						array[1, 1] = 1709827987;
						array[1, 2] = -412506575;
						array[2, 0] = -2074028949;
						array[2, 1] = 535883977;
						array[2, 2] = 1989948688;
						array[3, 0] = 558679850;
						array[3, 1] = 1127769150;
						array[3, 2] = -815763548;
						array[1, 2] = array[0, 1] ^ -188307328;
						array[2, 0] = array[0, 1] ^ -649744925;
						array[1, 0] = array[0, 0] ^ -2131338423;
						int num11 = array[1, 0] ^ -50811862;
						num = ((int)num4 * -871117047) ^ -1707458154 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static string _0025_0028_002B_0029_002F_0029_003E_003D(object P_0)
		{
			string result = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -804000822;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(~(-1134373666 - (-(-(-(~(num2 + (-(1139791370 * 850232335) + (-(--1623602521) + (-2000211686 + -389696969) - (~(~(-259304645 + (0x2D779178 ^ 0x542F01C5))) + -223980722 + -1106504374))))) - (--1725383136 * -360874177 * -393018973 - (-1298269666 + -537877477 - ~(~650752732)) + (-1353160671 ^ -1933120222) - ((0x1E88FF70 ^ -(1760175769 * (-1334134225 - -1951047427))) + ((-1319041689 - 1729103851) * 1379918865 - ~(-18122468 + 763861018) + (0x515BE806 ^ (0x2601DE52 ^ --1193948714))))))) ^ 0x7B64F7E9))))) % 3;
						int num5 = 402661378;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = ~num5 - 336065536;
							num5 = num5 ^ 0x6CC6DFA4 ^ 0x2097E793;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -2;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 = ~num7;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 0;
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
						result = P_0.ToString();
						int[] array = new int[5] { 1383852106, -1419342242, -616189242, 201135481, 1136079523 };
						array[2] ^= 1033835488;
						array[0] ^= -681257617;
						array[4] = array[3] ^ -1281487350;
						int[] array2 = new int[4];
						array2[0] = 336932952;
						array2[1] = -1647429766;
						array2[2] = -75363690;
						array2[3] = 354906020;
						array2[2] = array[3] ^ 0x1A7587A2;
						array2[1] = array2[3] ^ 0x1D77DB93;
						array2[0] = array2[2] ^ -1245437770;
						int num11 = array2[2] ^ -635830278;
						num = ((int)num4 * -1138122952) ^ -403559936 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static bool _005E_002A_002D_002F_002B_002A_0024_0026(string P_0)
		{
			bool result = default(bool);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1079263905;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(num2 - (~(-71438763 + 2145436250) - (-(-(0x65881E3C ^ --586089872 ^ -1750827876)) + -1064348874) - ~(-(~(0x6E26E977 ^ 0x77316896) + (-1354776501 + -833426030 + ~1458808732) + -((-1958663709 - 1270856175) * -1556359277) - ~(-(~2052883428)) * -953170409))) * -902090147) * -139127877 * -1321404345 - -(-(-1934478990 * -2101802903) ^ 0x777099F9) * 98721261)) % 3;
						int num5 = -1073742000;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = --487245389 - num5 + -2122919978;
							num5 = (num5 ^ -257863747) + -1298418052;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -1026297863;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = (num7 + ~618199601) ^ 0x65EA0C6D;
							num7 = ~(num7 + 1048928072);
						}
						if (num3 != (uint)num7)
						{
							int num9 = -147897974;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = num9 * -1045024887 - -1683391237;
								num9 = (num9 - (523402142 + -239341751)) * -1591292629;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = string.IsNullOrWhiteSpace(P_0);
						int[] array = new int[5];
						array[0] = -958629104;
						array[1] = 296277207;
						array[2] = -522230208;
						array[3] = -1235890849;
						array[4] = -512978212;
						array[4] = array[1] ^ -1044746547;
						array[4] = array[3] ^ -373939639;
						array[0] ^= 1209433198;
						int[] array2 = new int[7];
						array2[0] = 606365164;
						array2[1] = -1285007555;
						array2[2] = 677500488;
						array2[3] = 478591826;
						array2[4] = -1856356936;
						array2[5] = 1195169237;
						array2[6] = -63756051;
						array2[4] = array[1] ^ 0x60C2D8E2;
						array2[2] ^= 902830388;
						array2[0] = array2[6] ^ -2010842907;
						array2[2] = array2[3] ^ -618786807;
						int num11 = array2[4] ^ -1781901027;
						num = (int)((num4 * 1417792960) ^ 0xD877F780u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static bool @_005E_003F_0040_002B_003F_003D_0023(MethodDef P_0)
		{
			bool hasBody = default(bool);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -2070027188;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(((-num2 - -(~(-448578224 - ~(833615301 * 1978180788) * 194925307 - ((-((-707656646 ^ 0x67DB29F) - (0x364D9CB2 ^ 0x7C3271E0)) ^ 0x62472383) - -536267951 * (-1521808189 * 547202178))))) * -2055992879 - -(2110006267 - 1537705990 - --1128907455 - ~780668116 + (-27804696 + -45432732 - (-1114578321 + 360659994) - ~(0x296C6B70 ^ 0x18CF4A68)) - 53645964)) * -820537611)) % 3;
						int num5 = 125736784;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -1041060220 - num5;
							num5 = -(num5 + 1103928612);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 2138125086;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 += -2138125085;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1265449050;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 += -1265449048;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						hasBody = P_0.HasBody;
						int[,] array = new int[4, 3];
						array[0, 0] = 42367806;
						array[0, 1] = -913106441;
						array[0, 2] = 1178896574;
						array[1, 0] = 867159017;
						array[1, 1] = 11513284;
						array[1, 2] = 1984582040;
						array[2, 0] = 1504194774;
						array[2, 1] = 1504363967;
						array[2, 2] = -131843356;
						array[3, 0] = -1923478085;
						array[3, 1] = -1281283662;
						array[3, 2] = -367736554;
						array[3, 2] = array[0, 0] ^ 0x58D1A7AA;
						array[0, 2] ^= -1392783799;
						array[3, 2] = array[0, 2] ^ 0x64793A3;
						array[3, 0] = array[2, 0] ^ -1158734678;
						int num11 = array[3, 0] ^ -1041461810;
						num = (int)((num4 * 759694088) ^ 0x57253458) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return hasBody;
		}

		static UTF8String _0025_0024_005E_0040_003F_0029_005E_003D(MethodDef P_0)
		{
			UTF8String name = default(UTF8String);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 984895945;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(-1336289374 - ((~(~(~(540937783 + (-290531111 * -336206128 - 239623628 * -1899978199 - 200497495 * ~-31595941)) - -(~(--1732221603)) - (-(-(2141869383 * (1733414449 * (1368365127 * ~(~2039237933 - ~1404034465))))) - num2))) ^ 0x1A8D2049) + (1234759413 + ((-1127871660 ^ -2064730898) - (-182228631 ^ -100555550))) - (~1456750589 - (-42283478 + 269580953) + ~(1603929347 * 1731201995)) + (1802703838 - -2089452492) * -1275881393)))) % 3;
						int num5 = -1656365312;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 += 1656365314;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -584454111;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -num7;
							num7 = ~(num7 + (-640890400 ^ -1218956817));
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1355297154;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = (num9 ^ -2041581735) - -695794749;
								num9 = (num9 ^ 0x61E4D0ED) * -96287903;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						name = P_0.Name;
						int[] array = new int[7];
						array[0] = -2089503022;
						array[1] = -1520324194;
						array[2] = 497875155;
						array[3] = -595304659;
						array[4] = -490002098;
						array[5] = 665148253;
						array[6] = 686396544;
						array[1] = array[5] ^ -1229403382;
						array[0] = array[5] ^ 0x10F78C07;
						int[] array2 = new int[4] { 1996615678, 463220801, 1249560517, -1064360059 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[0] = array3[0][4] ^ -2021153429;
						array2[3] = array2[2] ^ 0x1F5DC296;
						array2[1] = array2[0] ^ -1505007826;
						array2[2] = array2[0] ^ 0x5A350813;
						int num11 = array3[1][0] ^ 0x6BDAE38B;
						num = ((int)num4 * -477006387) ^ 0xB2D0956 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return name;
		}

		static string _0026_002D_0024_0026_0029_002A_0023_0029(TypeDef P_0)
		{
			string fullName = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 2500217;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(-(~(-(~(~(num2 * 513983259))))) + (-1190522663 - (-1028016306 ^ --534221915))) * -1959368013)) % 3;
						int num5 = -831262501;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 -= -831262501;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -89774219;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = num7 * -1656268541 + 2096045686;
							num7 = -num7 - 1911347196;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1081349118;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~(~num9);
								num9 = (num9 - ~-305772919) ^ 0x1EC1D4A8;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						fullName = P_0.FullName;
						int[] array = new int[5];
						array[0] = -2101565218;
						array[1] = -570565595;
						array[2] = -1558757820;
						array[3] = 1182660973;
						array[4] = -2011340211;
						array[2] = array[4] ^ 0x49B92BB7;
						array[2] = array[1] ^ 0x361458E6;
						array[0] = array[1] ^ 0x5F6ED90F;
						int[] array2 = new int[7] { -1402212537, -729707599, 594490829, 1101958480, 1271245757, 2001808640, 2087285631 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[3] = array3[0][4] ^ -1531969556;
						array2[5] = array2[3] ^ -1358538942;
						array2[1] = array2[0] ^ -925144369;
						int num11 = array3[1][3] ^ 0xFC298E;
						num = (int)((num4 * 771843579) ^ 0xF3CD967Du) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return fullName;
		}

		static ITypeDefOrRef _0024_0029_0025_003E_002A_0024_002D_0025(CustomAttribute P_0)
		{
			ITypeDefOrRef attributeType = default(ITypeDefOrRef);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 43538879;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((~(-(-256463055 * (0x6516E48B ^ -1697658607)) - 248042535) - -(num2 ^ ((((~(~((-1228226943 ^ 0x442566CF) + (~1961179583 - 2076922601))) - ((0x50744940 ^ -1336266531) - --658580673 - (--638780404 + (-926929016 - 1108708399)) - ~((0x6046F0DB ^ 0x5FB44789) + 636876508 * -336798941) - (-428822329 - (0x46A938FC ^ 0x53B25AA4)))) ^ (-375598761 ^ ((-182310397 ^ 0x1850B17F) + -1021824273))) * -287511023) ^ (-(-48160085) ^ ~(-(566208489 - 1149214411 - 1102516034 + 1446571191 * 1516424445 - (0x63B3FEDC ^ 0x4CE2794B) * 727890185 + -(-(-494895488 + -135801329) + ~-148299929 * 1420181813))))))) * 1196639407)) % 3;
						int num5 = 781506458;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = num5 * 1376257715 * 804989423;
							num5 = ~num5 - 502362249;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -2;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 = ~num7;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1408971603;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 = 1408971603 - num9;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						attributeType = P_0.AttributeType;
						int[] array = new int[5] { -1453597507, 1173359797, -1202679368, 1843459364, 964794543 };
						array[4] ^= -579157397;
						array[2] = array[4] ^ -1867300549;
						int[] array2 = new int[7];
						array2[0] = -1793518364;
						array2[1] = 1998470121;
						array2[2] = -1377619970;
						array2[3] = 536565886;
						array2[4] = -1820284118;
						array2[5] = -1131823988;
						array2[6] = -1977008235;
						array2[2] = array[0] ^ 0x540DF517;
						array2[3] = array2[0] ^ -1557873269;
						array2[0] ^= -1722828540;
						array2[4] = array2[6] ^ 0x6136C7D8;
						int num11 = array2[2] ^ -412825610;
						num = ((int)num4 * -1498397963) ^ -729655886 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return attributeType;
		}

		static string _003F_002B_002F_005E_003F_0021_0023_0023(IFullName P_0)
		{
			string fullName = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 826646100;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((-((-(-num2 ^ (-(~(~((--463394763 * -715144535) ^ -998744461)) - -191448357) - (-983360972 * 1810143545 - -(~(-335690619 * -1621690167))))) + -(-(-1092141818 + ~1646430638 + (-808008873 - 1422131444))) * 164421639) * -1208649517) * 1966680231 * -679509271) ^ 0x21802151 ^ 0x526ECAC)) % 3;
						int num5 = 496829476;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = (num5 - -1232999118) * 788118427;
							num5 = ~num5;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 204472353;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~num7 - -76599089;
							num7 = -num7 ^ 0x61C77BE4;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 117866366;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~(~num9);
								num9 = -1387474316 - (num9 ^ -1899634485);
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						fullName = P_0.FullName;
						int[] array = new int[6];
						array[0] = -1987811765;
						array[1] = 1912503802;
						array[2] = -1880709743;
						array[3] = -988167916;
						array[4] = -734011118;
						array[5] = -688382816;
						array[5] = array[2] ^ -1767088978;
						array[1] = array[3] ^ 0x7DC6BB6F;
						int[] array2 = new int[5];
						array2[0] = -962853320;
						array2[1] = 1006861590;
						array2[2] = 158843159;
						array2[3] = 211804016;
						array2[4] = 730916360;
						array2[3] = array[3] ^ -1506199592;
						array2[4] = array2[0] ^ -302329138;
						array2[2] = array2[3] ^ 0x4681EE8C;
						array2[1] = array2[2] ^ 0x191590EB;
						int num11 = array2[3] ^ -202779821;
						num = ((int)num4 * -348351978) ^ -1468946404 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return fullName;
		}

		static bool _005E_003D_005E_002A_0024_003C_0024_003C(Parameter P_0)
		{
			bool ısHiddenThisParameter = default(bool);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -536250645;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(((-(-(1625960539 * 724987759 + --122573892)) - -(-(-1470052036 + -746484075 + -(2132991328 - -1100807664 - -1861051625)) - ((~(953141677 * -705858702) - num2) ^ (-(-1569251521 * -510626675) - (-1632097854 ^ -(713678367 * (483864285 - 1445114537) * 1647248271) ^ 0x66B888E6 ^ -1394331835)))) * 36165037 - (0x7B618701 ^ -2067732640) * -1707509071 - (1836921211 * 1420472437 + (-1367386236 - 1273439551))) ^ 0x39675848) - -1562062562)) % 3;
						int num5 = -176714164;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = num5 * -947058097 - 445289257;
							num5 = 1234539882 - num5;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 139000039;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~(1293701933 - num7);
							num7 += --1224201915;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 0;
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
						ısHiddenThisParameter = P_0.IsHiddenThisParameter;
						int[] array = new int[4];
						array[0] = 978788504;
						array[1] = -2118056695;
						array[2] = -1458678157;
						array[3] = -1718655862;
						array[1] = array[2] ^ -2026266079;
						array[0] = array[3] ^ 0x8F4E7F2;
						int[] array2 = new int[7];
						array2[0] = -738640586;
						array2[1] = 1116907934;
						array2[2] = 708176992;
						array2[3] = -114990157;
						array2[4] = 1598892670;
						array2[5] = -1917955603;
						array2[6] = 1517052986;
						array2[1] = array[2] ^ 0x151274BC;
						array2[4] = array2[0] ^ -2073826325;
						array2[3] = array2[1] ^ 0x5CC3C122;
						array2[3] = array2[4] ^ 0x2AB92372;
						int num11 = array2[1] ^ -1608356560;
						num = ((int)num4 * -1501751784) ^ 0x13FF33A0 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return ısHiddenThisParameter;
		}

		static TypeSig _0021_0029_0040__0025_005E_0024_002B(Parameter P_0)
		{
			TypeSig type = default(TypeSig);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -44289688;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(-(((-1142717332 ^ -1742793166) - (-(num2 ^ (-(~(-(-801184154 ^ 0x5AC48DD2)) + -(-(0x507E0352 ^ 0x7E46744E))) - ~(0x673EFDE3 ^ 0x5A01A0FA)) ^ ~(714947451 * (--63531939 * 796149599))) + -(-102577429 * (1388034072 * 1019255329) - (~(-125229178) + 733508162 - ~(0x4E671C3A ^ -1481574438))))) ^ 0x2939B1F9)))) % 3;
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
						int num7 = 755699243;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 *= -1243135869;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 2;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~num9 ^ 0x5836FCBC;
								num9 = ~(~num9);
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						type = P_0.Type;
						int[] array = new int[4];
						array[0] = 1566386426;
						array[1] = -1588376414;
						array[2] = -394806716;
						array[3] = 113155764;
						array[1] = array[3] ^ 0x40F6FDD8;
						array[2] = array[3] ^ -1644236227;
						array[0] = array[1] ^ -632835033;
						int[] array2 = new int[4] { -1050477559, 96336016, -82173707, 2007923524 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[3] = array3[0][3] ^ -370321428;
						array2[0] = array2[3] ^ -993239028;
						array2[2] = array2[3] ^ 0x64AC447C;
						int num11 = array3[1][3] ^ 0x92F66FE;
						num = ((int)num4 * -701010019) ^ -2034857388 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return type;
		}

		static string _005E_0025_0021_003E_0024_0021_002F_0025(Parameter P_0)
		{
			string name = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 1312442159;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((~-1182862918 + -(-1241418449 ^ --181285355) - -((~num2 * 810149007 * 654824317) ^ (-(~(-(-1115010425 + -1469424375)) * 688096159) ^ 0x1E800650))) * -200760037)) % 3;
						int num5 = 651221613;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 += -651221613;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1030128346;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = num7 * -1949565501 * 1130595641;
							num7 = (num7 ^ -1583843508) - 1957400972;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1688422127;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -num9 - -326275656;
								num9 = 373196777 - num9 * 755864335;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						name = P_0.Name;
						int[] array = new int[6];
						array[0] = 763606701;
						array[1] = 1022626935;
						array[2] = 953074886;
						array[3] = 1575869252;
						array[4] = -834943003;
						array[5] = 1865755296;
						array[2] = array[4] ^ -1694473288;
						array[4] ^= 1174336519;
						array[0] = array[2] ^ -1911195714;
						int[] array2 = new int[4] { 223665906, 1695531896, 137143761, 177415167 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][3] ^ -879035874;
						array2[2] = array2[1] ^ 0x5EBB3D12;
						array2[2] = array2[3] ^ -763493595;
						array2[0] = array2[1] ^ 0x6DB964BB;
						int num11 = array3[1][1] ^ 0x2E4C506F;
						num = (int)((num4 * 2025829176) ^ 0x7E88AA80) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return name;
		}

		static string _0024_003E_003E_0025_002A_0024_0026_002B(string P_0, string P_1, string P_2)
		{
			string result = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -945935027;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(((num2 ^ (-551004677 * (~-1853834934 - ((~(-431418517 - (-1854824152 ^ 0x78B76BF7) + -1841402865) ^ (-(113637934 * 1411767575) + -976117457 * -(1115872514 * -1461593575))) - --39938330)) * 516043923) ^ (~(~(-(~(--1830330157) - 55380924) ^ -1871566336)) + (-715731108 ^ ((-520207680 - (-198189841 * ~(-1155706448) + -(831209629 - -771240045 + 78598664))) ^ (-1279535635 * (1610589079 * (0x38985D8F ^ -1079152558) - ~(-1697461070)) * 594820709))))) + -(((-734505032 + (~-622368479 - (-1700218951 - 2139194775)) - -(1416205783 * -1149521083)) * -1449695811) ^ -1571742805)) * 658438513 * -1991951957 * 694674099))) % 3;
						int num5 = -610920168;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = num5 * 1934237625 * -1337126961;
							num5 = (num5 + -437858281 * -1876058748) * 935858719;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -2;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 = ~num7;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 2142412020;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = 1076277638 - ~num9;
								num9 = -(-num9);
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0 + P_1 + P_2;
						int[,] array = new int[4, 4];
						array[0, 0] = -1896349852;
						array[0, 1] = -151664775;
						array[0, 2] = 1609920491;
						array[0, 3] = 127257145;
						array[1, 0] = 558823027;
						array[1, 1] = 435451665;
						array[1, 2] = 1751281997;
						array[1, 3] = 2060174137;
						array[2, 0] = 644512163;
						array[2, 1] = -1702209761;
						array[2, 2] = 1729458554;
						array[2, 3] = -1206636014;
						array[3, 0] = 1328512941;
						array[3, 1] = 2045890786;
						array[3, 2] = 790479375;
						array[3, 3] = -194923482;
						array[0, 1] = array[2, 2] ^ -707607389;
						array[0, 3] = array[3, 0] ^ -156197698;
						array[0, 1] ^= -1411265223;
						array[0, 1] = array[1, 2] ^ 0x144C9118;
						int num11 = array[0, 1] ^ -1706246876;
						num = (int)((num4 * 1418543997) ^ 0x1D897D4) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}
	}

	[CompilerGenerated]
	private sealed class _003C_003Ec__DisplayClass14_0
	{
		public int token;

		public Func<MethodItem, bool> _003C_003E9__0;

		internal bool _003CSetMethodSelection_003Eb__0(MethodItem item)
		{
			return @_002A_005E_003C_005E_002D_0029_005E(item) == token;
		}

		static int @_002A_005E_003C_005E_002D_0029_005E(MethodItem P_0)
		{
			int result = default(int);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 2117491944;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((((~num2 ^ (-(~-2008426433 * -476806235) * -1349915909 * -1076384645)) * -916688363) ^ ((~(-1783857253 * 629435296 - -1769498790) - (-1014391150 ^ 0x69D1D082)) * -1802958743 - --874458944)) * 1573675959)) % 3;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 = -num5;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 269310479;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -(-num7);
							num7 = -(--134655239 - num7);
						}
						if (num3 != (uint)num7)
						{
							int num9 = 397127868;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~num9;
								num9 = num9 * -1310117529 + -1211061130;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.Token;
						int[,] array = new int[4, 4];
						array[0, 0] = -1137914952;
						array[0, 1] = -1642648684;
						array[0, 2] = -991875768;
						array[0, 3] = 2061147227;
						array[1, 0] = 700669447;
						array[1, 1] = -333145672;
						array[1, 2] = 364563487;
						array[1, 3] = 908424505;
						array[2, 0] = -1259329176;
						array[2, 1] = -377256219;
						array[2, 2] = -1733440930;
						array[2, 3] = -860642389;
						array[3, 0] = 1136912871;
						array[3, 1] = 778497016;
						array[3, 2] = -660159177;
						array[3, 3] = 2000660627;
						array[0, 1] = array[3, 0] ^ -1689906023;
						array[3, 1] = array[0, 1] ^ -185268797;
						array[1, 0] = array[0, 0] ^ -1437565498;
						int num11 = array[1, 0] ^ 0x30606819;
						num = ((int)num4 * -1488520824) ^ 0x19D40CF0 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}
	}

	private readonly Dictionary<string, List<MethodItem>> gQj_003D = new Dictionary<string, List<MethodItem>>(_002B_0024_005E_002A_002D__0023_0025());

	private readonly Dictionary<int, MethodDef> RyF_003D = new Dictionary<int, MethodDef>();

	private ModuleDefMD? BAB_003D;

	private byte[]? eJt_003D;

	[CompilerGenerated]
	private AssemblyProfile? pME_003D;

	public AssemblyProfile? Woj_003D
	{
		[CompilerGenerated]
		get
		{
			return pME_003D;
		}
		[CompilerGenerated]
		private set
		{
			pME_003D = value;
		}
	}

	public bool rBc_003D
	{
		get
		{
			if (Woj_003D != null)
			{
				uint num2;
				int num4;
				do
				{
					int num = -1649753238;
					uint num3;
					num2 = (num3 = (uint)(~(-(-(~(((num - -(-919694671 ^ ~(-(1731916481 * -1860250732 + ~-1252849923)))) ^ -1152546403) - (~(~(-916131643 * -(1405926200 * 1504283657)) - ~(-(188081577 * --1035186021))) - 477927514)) * -1025289869 * 784829679 * -1661292963))))) % 3;
					num4 = 1954450694;
					_ = 0;
					for (int num5 = 0; num5 < 2; num5++)
					{
						num4 = (num4 ^ 0x30BE107D) - -1173268817;
						num4 = -(-num4);
					}
				}
				while (num2 == (uint)num4);
				int num6 = -852149193;
				_ = 0;
				for (int num7 = 0; num7 < 1; num7++)
				{
					num6 *= 1696807303;
				}
				if (num2 == (uint)num6)
				{
					return eJt_003D != null;
				}
				int num8 = -1538391408;
				_ = 0;
				for (int num9 = 0; num9 < 2; num9++)
				{
					num8 = (num8 * 1151006915) ^ 0x66A3B688;
					num8 = -(num8 ^ -1585498524);
				}
				if (num2 == (uint)num8)
				{
				}
			}
			return false;
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[AsyncStateMachine(typeof(_003CLoadAssemblyAsync_003Ed__10))]
	public Task<AssemblyProfile> LoadAssemblyAsync(string voa_003D, CancellationToken UsV_003D)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { this, voa_003D, UsV_003D };
		return (Task<AssemblyProfile>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MTAxMGBsMGVUVReHUlRQJ1Q=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static ModuleDefMD jUf_003D(string XDR_003D, byte[] qKn_003D)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { XDR_003D, qKn_003D };
		return (ModuleDefMD)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Njc2NzJnMmVTUhb7VVNXJ1M=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	private AssemblyProfile Fre_003D(string cqh_003D, ModuleDefMD JtE_003D)
	{
		List<NamespaceItem> list = new List<NamespaceItem>();
		List<TypeItem> list2 = default(List<TypeItem>);
		TypeDef current2 = default(TypeDef);
		bool flag = default(bool);
		List<MethodItem> list3 = default(List<MethodItem>);
		int num78 = default(int);
		int num80 = default(int);
		MethodDef current3 = default(MethodDef);
		bool flag2 = default(bool);
		MDToken mDToken = default(MDToken);
		int num114 = default(int);
		while (true)
		{
			int num = 47261486;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(-(~((num2 + (~(~(0x2448B0E3 ^ -1919463063)) + ~(-414088917 - (-(-(~-4134046) - (0x48D75166 ^ 0x6AE08BF2)) * 2126682415 + ~((-(-616329568 + 404628899) ^ 0x703FC963) + ((-920349549 - (1453725652 - -1780166395)) ^ -(~-1021271567))))))) ^ ~(--1631230525 + -(-((--1949672878 ^ -53203045) * 1674312067) ^ (-1450543751 ^ -(-1780312011 ^ -975863894))))))) ^ (-(156339451 * -1770006268) ^ (-(-437457236 - 1992361704) ^ -601138316)))) % 4;
				uint num5 = num3;
				int num6 = 190429816;
				_ = 0;
				for (int num7 = 0; num7 < 1; num7++)
				{
					num6 ^= 0xB59BA7B;
				}
				if (num5 == (uint)num6)
				{
					break;
				}
				uint num8 = num3;
				int num9 = -1437245871;
				_ = 0;
				for (int num10 = 0; num10 < 2; num10++)
				{
					num9 = -(num9 * 697834727);
					num9 = ~(num9 * -1026638023);
				}
				if (num8 != (uint)num9)
				{
					uint num11 = num3;
					int num12 = 670097634;
					_ = 0;
					for (int num13 = 0; num13 < 2; num13++)
					{
						num12 = -(-num12);
						num12 = (num12 ^ --1250386211) - -637726354;
					}
					if (num11 != (uint)num12)
					{
						uint num14 = num3;
						int num15 = -1251299388;
						_ = 0;
						for (int num16 = 0; num16 < 2; num16++)
						{
							num15 -= ~625649693;
							num15 = ~(~num15);
						}
						if (num14 != (uint)num15)
						{
						}
						IEnumerator<IGrouping<string, TypeDef>> enumerator = (from type in _002A_0026_003E_003F_003D_0025_002D_0025((ModuleDef)JtE_003D)
							where !_003C_003Ec._0024_0040_0040_0023_0029_0029_002B_003E(type)
							where !ejJ_003D(_003C_003Ec._0028_003E__0023_0028_0029_0024_003D(_003C_003Ec._0028_005E_005E_003C_003D_003E_0026_0040(type)))
							where !WRp_003D(type)
							where !_003C_003Ec.__002D_005E_0024_003E_0040_002F_0021(type)
							where !_003C_003Ec._002F_002A_002D_003C_002A_002F_0026_005E(_003C_003Ec._0028_003E__0023_0028_0029_0024_003D(_003C_003Ec._005E_002B_0024_0029_002A_005E__002A(type)), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x1157 ^ 0x109B], StringComparison.Ordinal)
							select type).GroupBy(delegate(TypeDef type)
						{
							UTF8String uTF8String = _003C_003Ec._005E_002B_0024_0029_002A_005E__002A(type);
							string text = (((object)uTF8String != null) ? _003C_003Ec._0025_0028_002B_0029_002F_0029_003E_003D((object)uTF8String) : null);
							while (true)
							{
								int num157 = -1777776416;
								while (true)
								{
									int num158 = num157;
									uint num160;
									uint num159 = (num160 = (uint)(-(-(-(~(-num158)) - -2130386884) + (-771487814 ^ -(--169893434 - --1739361835))))) % 4;
									int num161 = -1338058301;
									_ = 0;
									for (int num162 = 0; num162 < 1; num162++)
									{
										num161 *= 1387896001;
									}
									if (num159 == (uint)num161)
									{
										break;
									}
									int num163 = -1938125525;
									_ = 0;
									for (int num164 = 0; num164 < 1; num164++)
									{
										num163 ^= -1938125527;
									}
									if (num159 != (uint)num163)
									{
										int num165 = 580522533;
										_ = 0;
										for (int num166 = 0; num166 < 1; num166++)
										{
											num165 *= 807516589;
										}
										if (num159 == (uint)num165)
										{
											return text;
										}
										int num167 = 1838727770;
										_ = 0;
										for (int num168 = 0; num168 < 2; num168++)
										{
											num167 = -(~num167);
											num167 = -(num167 * -1399677485);
										}
										if (num159 != (uint)num167)
										{
										}
										return _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[2653 - 2232 + 40];
									}
									bool num169 = _003C_003Ec._005E_002A_002D_002F_002B_002A_0024_0026(text);
									int[] array32 = new int[7];
									array32[0] = -1386419182;
									array32[1] = 561851624;
									array32[2] = 767191887;
									array32[3] = -388758078;
									array32[4] = 442673621;
									array32[5] = -539022441;
									array32[6] = -1335238714;
									array32[5] = array32[3] ^ -789682439;
									array32[5] = array32[6] ^ 0x2F6EDED9;
									int[] array33 = new int[6] { -224989696, 1226962000, 1527775721, 1504518215, -1567343099, -678090992 };
									int[][] array34 = new int[2][] { array32, array33 };
									array33[3] = array34[0][2] ^ 0x9A575C5;
									array33[2] ^= 848763098;
									array33[0] = array33[3] ^ 0x65B1F484;
									int num170 = array34[1][3] ^ -1536924884;
									int[,] array35 = new int[3, 4];
									array35[0, 0] = 713546477;
									array35[0, 1] = -16005922;
									array35[0, 2] = 1292053475;
									array35[0, 3] = 2039162611;
									array35[1, 0] = -286686656;
									array35[1, 1] = -879551081;
									array35[1, 2] = -1973018872;
									array35[1, 3] = -987943318;
									array35[2, 0] = -863706480;
									array35[2, 1] = 1068756075;
									array35[2, 2] = -543681848;
									array35[2, 3] = -1280263914;
									array35[0, 2] = array35[2, 2] ^ -1091667140;
									array35[0, 3] = array35[1, 2] ^ -1742631953;
									array35[1, 3] = array35[0, 3] ^ 0x4F53651C;
									array35[0, 0] = array35[0, 1] ^ 0x48A100C;
									int num171 = array35[0, 0] ^ 0x791F8CC3;
									int num172 = (int)(num160 * 1742798317) ^ -182135150;
									num170 ^= num172;
									num171 ^= num172;
									int num173;
									int num174;
									if (!num169)
									{
										num173 = num171;
										num174 = num173;
									}
									else
									{
										num173 = num170;
										num174 = num173;
									}
									num157 = num173 ^ num172;
								}
							}
						}).OrderBy<IGrouping<string, TypeDef>, string>((IGrouping<string, TypeDef> group) => group.Key, _002B_0024_005E_002A_002D__0023_0025()).GetEnumerator();
						try
						{
							while (true)
							{
								if (_003C_003C_0024_0025_0029_005E_0029_003E((IEnumerator)enumerator))
								{
									IGrouping<string, TypeDef> current;
									while (true)
									{
										current = enumerator.Current;
										int num17 = 585505070;
										while (true)
										{
											num2 = num17;
											num3 = (num4 = (uint)(~(-(~((num2 + (~(~(0x2448B0E3 ^ -1919463063)) + ~(-414088917 - (-(-(~-4134046) - (0x48D75166 ^ 0x6AE08BF2)) * 2126682415 + ~((-(-616329568 + 404628899) ^ 0x703FC963) + ((-920349549 - (1453725652 - -1780166395)) ^ -(~-1021271567))))))) ^ ~(--1631230525 + -(-((--1949672878 ^ -53203045) * 1674312067) ^ (-1450543751 ^ -(-1780312011 ^ -975863894))))))) ^ (-(156339451 * -1770006268) ^ (-(-437457236 - 1992361704) ^ -601138316)))) % 4;
											uint num18 = num3;
											int num19 = -538814164;
											_ = 0;
											for (int num20 = 0; num20 < 2; num20++)
											{
												num19 = num19 * 1757886655 - -1805233101;
												num19 = -num19 ^ 0x7C0F29;
											}
											if (num18 == (uint)num19)
											{
												num17 = 112815072;
												continue;
											}
											uint num21 = num3;
											int num22 = 1871738246;
											_ = 0;
											for (int num23 = 0; num23 < 1; num23++)
											{
												num22 = 1871738249 - num22;
											}
											if (num21 == (uint)num22)
											{
												break;
											}
											uint num24 = num3;
											int num25 = 18611713;
											_ = 0;
											for (int num26 = 0; num26 < 2; num26++)
											{
												num25 = (num25 ^ -429857166) - -2100455165;
												num25 = -(~num25);
											}
											if (num24 != (uint)num25)
											{
												goto end_IL_09c4;
											}
											list2 = new List<TypeItem>();
											int[] array = new int[6];
											array[0] = 939492401;
											array[1] = 1981907307;
											array[2] = 765930784;
											array[3] = 822015086;
											array[4] = 1195270027;
											array[5] = -1180954982;
											array[4] = array[1] ^ 0x721A2F05;
											array[3] = array[1] ^ -1291915907;
											array[5] = array[0] ^ 0x4A368A8C;
											int[] array2 = new int[6] { -559824997, 860482096, 1784638477, -1333413780, 1908625435, -46733049 };
											int[][] array3 = new int[2][] { array, array2 };
											array2[5] = array3[0][1] ^ -2058480911;
											array2[2] = array2[4] ^ -1311294662;
											array2[1] = array2[0] ^ 0x5C6040CF;
											int num27 = array3[1][5] ^ -758027755;
											num17 = (int)((num4 * 1675230197) ^ 0x771EA151) ^ num27;
										}
										continue;
										end_IL_09c4:
										break;
									}
									uint num28 = num3;
									int num29 = 1563898226;
									_ = 0;
									for (int num30 = 0; num30 < 2; num30++)
									{
										num29 = num29 + -1196071791 * -1196233888 + -1737822124;
										num29 = num29 - 922900251 - 2083324753;
									}
									if (num28 != (uint)num29)
									{
									}
									IEnumerator<TypeDef> enumerator2 = current.OrderBy<TypeDef, string>(delegate(TypeDef item)
									{
										UTF8String uTF8String = _003C_003Ec._0028_005E_005E_003C_003D_003E_0026_0040(item);
										return ((object)uTF8String == null) ? null : _003C_003Ec._0025_0028_002B_0029_002F_0029_003E_003D((object)uTF8String);
									}, _002B_0024_005E_002A_002D__0023_0025()).GetEnumerator();
									try
									{
										uint num117;
										int num118;
										do
										{
											if (_003C_003C_0024_0025_0029_005E_0029_003E((IEnumerator)enumerator2))
											{
												while (true)
												{
													current2 = enumerator2.Current;
													int num31 = -794787457;
													while (true)
													{
														num2 = num31;
														num3 = (num4 = (uint)(~(-(~((num2 + (~(~(0x2448B0E3 ^ -1919463063)) + ~(-414088917 - (-(-(~-4134046) - (0x48D75166 ^ 0x6AE08BF2)) * 2126682415 + ~((-(-616329568 + 404628899) ^ 0x703FC963) + ((-920349549 - (1453725652 - -1780166395)) ^ -(~-1021271567))))))) ^ ~(--1631230525 + -(-((--1949672878 ^ -53203045) * 1674312067) ^ (-1450543751 ^ -(-1780312011 ^ -975863894))))))) ^ (-(156339451 * -1770006268) ^ (-(-437457236 - 1992361704) ^ -601138316)))) % 5;
														uint num32 = num3;
														int num33 = -1;
														_ = 0;
														for (int num34 = 0; num34 < 1; num34++)
														{
															num33 = ~num33;
														}
														if (num32 == (uint)num33)
														{
															num31 = 344989103;
															continue;
														}
														uint num35 = num3;
														int num36 = -544023480;
														_ = 0;
														for (int num37 = 0; num37 < 2; num37++)
														{
															num36 = --1626493560 - num36 - 1997107649;
															num36 = num36 * 11502303 - 107741660;
														}
														if (num35 == (uint)num36)
														{
															break;
														}
														uint num38 = num3;
														int num39 = 1065410949;
														_ = 0;
														for (int num40 = 0; num40 < 2; num40++)
														{
															num39 = (num39 ^ -1471425687) + -716957961;
															num39 = -2127669073 - (num39 - ~1202632187);
														}
														if (num38 != (uint)num39)
														{
															uint num41 = num3;
															int num42 = -1;
															_ = 0;
															for (int num43 = 0; num43 < 1; num43++)
															{
																num42 = -num42;
															}
															if (num41 != (uint)num42)
															{
																goto end_IL_0ee5;
															}
															flag = XkQ_003D(current2);
															int[,] array4 = new int[4, 3];
															array4[0, 0] = 1091458634;
															array4[0, 1] = 1849869006;
															array4[0, 2] = -324005033;
															array4[1, 0] = 977070624;
															array4[1, 1] = -722214782;
															array4[1, 2] = -2054522716;
															array4[2, 0] = -1176224064;
															array4[2, 1] = 281442199;
															array4[2, 2] = 1307105046;
															array4[3, 0] = -1628861754;
															array4[3, 1] = -2035795365;
															array4[3, 2] = -1845555632;
															array4[0, 1] = array4[0, 0] ^ -112299625;
															array4[2, 0] = array4[3, 2] ^ 0x50488C5A;
															array4[2, 0] = array4[2, 1] ^ 0x26FA2004;
															int num44 = array4[2, 0] ^ -1039049011;
															num31 = ((int)num4 * -656256372) ^ 0x22AE0F44 ^ num44;
														}
														else
														{
															list3 = new List<MethodItem>();
															int[] array5 = new int[7];
															array5[0] = -1338075061;
															array5[1] = 1233557588;
															array5[2] = 1652418165;
															array5[3] = -1856552896;
															array5[4] = 1237397031;
															array5[5] = 476043224;
															array5[6] = -935302650;
															array5[1] = array5[2] ^ 0x2F8730C7;
															array5[0] = array5[4] ^ -1483650933;
															int[] array6 = new int[4];
															array6[0] = -1753380542;
															array6[1] = -169125135;
															array6[2] = 1125044438;
															array6[3] = -1722992881;
															array6[3] = array5[4] ^ 0x4F58EE59;
															array6[0] = array6[1] ^ 0x5944E57A;
															array6[1] = array6[3] ^ -617547723;
															array6[2] = array6[0] ^ -1986738287;
															int num45 = array6[3] ^ -1029098534;
															num31 = ((int)num4 * -390227423) ^ -614657378 ^ num45;
														}
													}
													continue;
													end_IL_0ee5:
													break;
												}
												uint num46 = num3;
												int num47 = 639238132;
												_ = 0;
												for (int num48 = 0; num48 < 2; num48++)
												{
													num47 = -num47 ^ -1122129400;
													num47 = num47 - ~-1683388341 - 1828209712;
												}
												if (num46 != (uint)num47)
												{
												}
												IEnumerator<MethodDef> enumerator3 = _003C_002A_005E_0021_0026_0040__003D(current2).Where(delegate(MethodDef method)
												{
													if (_003C_003Ec.@_005E_003F_0040_002B_003F_003D_0023(method))
													{
														uint num158;
														int num160;
														do
														{
															int num157 = 371385121;
															uint num159;
															num158 = (num159 = (uint)(~(~(num157 + ((~(-1093253086 + ~(-319882414) - ((0x141E4958 ^ -1504660309) + -534804648)) - (-(-(799099151 + 773389566) - ~(~682240761)) ^ -238373503) + ~(395744439 * --1906079765) * -1010715037) ^ ((((~-1330749903 - (0x6F5165B1 ^ 0x4519F1FE)) * -426723347 - (-1698139829 ^ -1034677039) - (((--1871375512 + 110558407 * -199948479) ^ 0x9F4592) - -1096614058)) * -1374319491) ^ ((-(-1499292031 ^ -(-186934032 - -890126169)) + (-1072442215 ^ -(~(-1023914365 + -1881136821)))) ^ --627464231)) ^ (~(((--70771140 ^ 0x16A2AE5C) - -470576005) ^ (~(188718341 * -2111180787 * 520746161) - -(0x6D62AE60 ^ 0x7DD29F94))) + 2035166131 + (-((0x53C576ED ^ 0x788ECD9E) + (0x58AF890B ^ -1825119697)) - ~(-1773637429 * 591707135 - -1490333250) - (~788291466 + ((0x7C2CF5EC ^ 0x3216548F) - 884351458)) + -2142500516 - --252222019))))) * 2056866191)) % 3;
															num160 = 42002338;
															_ = 0;
															for (int num161 = 0; num161 < 1; num161++)
															{
																num160 -= 42002336;
															}
														}
														while (num158 == (uint)num160);
														int num162 = -2058263367;
														_ = 0;
														for (int num163 = 0; num163 < 2; num163++)
														{
															num162 = (num162 * 883972629) ^ 0x54C30D98;
															num162 = num162 * 1974117429 * 1574804613;
														}
														if (num158 == (uint)num162)
														{
															return !_003C_003Ec._002F_002A_002D_003C_002A_002F_0026_005E(_003C_003Ec._0028_003E__0023_0028_0029_0024_003D(_003C_003Ec._0025_0024_005E_0040_003F_0029_005E_003D(method)), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x1B9E ^ 0x1A50))], StringComparison.Ordinal);
														}
														int num164 = 0;
														_ = 0;
														for (int num165 = 0; num165 < 2; num165++)
														{
															num164 = ~num164 - -129565977;
															num164 = num164 - --258493905 + -1751531323;
														}
														if (num158 == (uint)num164)
														{
														}
													}
													return false;
												}).GetEnumerator();
												try
												{
													uint num87;
													int num88;
													do
													{
														int num49;
														int num50;
														if (!_003C_003C_0024_0025_0029_005E_0029_003E((IEnumerator)enumerator3))
														{
															num49 = 2855960;
															num50 = num49;
														}
														else
														{
															num49 = 132092130;
															num50 = num49;
														}
														while (true)
														{
															num2 = num49;
															num3 = (num4 = (uint)(~(-(~((num2 + (~(~(0x2448B0E3 ^ -1919463063)) + ~(-414088917 - (-(-(~-4134046) - (0x48D75166 ^ 0x6AE08BF2)) * 2126682415 + ~((-(-616329568 + 404628899) ^ 0x703FC963) + ((-920349549 - (1453725652 - -1780166395)) ^ -(~-1021271567))))))) ^ ~(--1631230525 + -(-((--1949672878 ^ -53203045) * 1674312067) ^ (-1450543751 ^ -(-1780312011 ^ -975863894))))))) ^ (-(156339451 * -1770006268) ^ (-(-437457236 - 1992361704) ^ -601138316)))) % 11;
															uint num51 = num3;
															int num52 = -3;
															_ = 0;
															for (int num53 = 0; num53 < 1; num53++)
															{
																num52 = -num52;
															}
															if (num51 == (uint)num52)
															{
																num49 = 132092130;
																continue;
															}
															uint num54 = num3;
															int num55 = 2107016233;
															_ = 0;
															for (int num56 = 0; num56 < 1; num56++)
															{
																num55 -= 2107016232;
															}
															if (num54 != (uint)num55)
															{
																uint num57 = num3;
																int num58 = -326111998;
																_ = 0;
																for (int num59 = 0; num59 < 1; num59++)
																{
																	num58 ^= -326111993;
																}
																if (num57 != (uint)num58)
																{
																	uint num60 = num3;
																	int num61 = -8;
																	_ = 0;
																	for (int num62 = 0; num62 < 1; num62++)
																	{
																		num61 = -num61;
																	}
																	if (num60 != (uint)num61)
																	{
																		uint num63 = num3;
																		int num64 = 633362619;
																		_ = 0;
																		for (int num65 = 0; num65 < 1; num65++)
																		{
																			num64 = 633362623 - num64;
																		}
																		int num83;
																		if (num63 != (uint)num64)
																		{
																			uint num66 = num3;
																			int num67 = 2072584729;
																			_ = 0;
																			for (int num68 = 0; num68 < 1; num68++)
																			{
																				num67 -= 2072584719;
																			}
																			if (num66 != (uint)num67)
																			{
																				uint num69 = num3;
																				int num70 = 2122992774;
																				_ = 0;
																				for (int num71 = 0; num71 < 2; num71++)
																				{
																					num70 = num70 * 1924868825 * 1613883351;
																					num70 = -num70 ^ 0x5CB38A72;
																				}
																				if (num69 != (uint)num70)
																				{
																					uint num72 = num3;
																					int num73 = 1197866715;
																					_ = 0;
																					for (int num74 = 0; num74 < 2; num74++)
																					{
																						num73 = (num73 - ~971143299) * 1697714435;
																						num73 = -(num73 - 894305367 * 97524615);
																					}
																					if (num72 != (uint)num73)
																					{
																						uint num75 = num3;
																						int num76 = -1833745684;
																						_ = 0;
																						for (int num77 = 0; num77 < 2; num77++)
																						{
																							num76 = ~num76 - 133110768;
																							num76 = num76 * 2061041543 + 1837077449;
																						}
																						if (num75 != (uint)num76)
																						{
																							break;
																						}
																						num78++;
																						int[,] array7 = new int[4, 3];
																						array7[0, 0] = 235665453;
																						array7[0, 1] = -416369424;
																						array7[0, 2] = -1824525465;
																						array7[1, 0] = 1324810853;
																						array7[1, 1] = -542713475;
																						array7[1, 2] = -973179403;
																						array7[2, 0] = 1296717162;
																						array7[2, 1] = 925119315;
																						array7[2, 2] = -384399092;
																						array7[3, 0] = -1038790339;
																						array7[3, 1] = 1929078674;
																						array7[3, 2] = 1966981937;
																						array7[1, 0] = array7[0, 0] ^ 0x7EAA1CED;
																						array7[3, 2] = array7[0, 2] ^ -958424191;
																						array7[2, 1] = array7[2, 0] ^ 0x8BA9210;
																						int num79 = array7[2, 1] ^ 0x65FC865C;
																						num49 = ((int)num4 * -642172838) ^ -599834168 ^ num79;
																					}
																					else
																					{
																						RyF_003D[num80] = current3;
																						int[,] array8 = new int[4, 3];
																						array8[0, 0] = 1951838747;
																						array8[0, 1] = -252608654;
																						array8[0, 2] = -1780138348;
																						array8[1, 0] = -208389372;
																						array8[1, 1] = 811240152;
																						array8[1, 2] = 1999659840;
																						array8[2, 0] = 894286446;
																						array8[2, 1] = -459659481;
																						array8[2, 2] = -30732332;
																						array8[3, 0] = 1482735779;
																						array8[3, 1] = 853945683;
																						array8[3, 2] = -762503774;
																						array8[2, 2] = array8[2, 1] ^ -1464319915;
																						array8[1, 1] ^= -457103518;
																						array8[3, 2] = array8[3, 1] ^ -641897441;
																						int num81 = array8[3, 2] ^ 0x55C3ACE9;
																						num49 = (int)((num4 * 2102700899) ^ 0x2411490C) ^ num81;
																					}
																				}
																				else
																				{
																					List<MethodItem> list4 = list3;
																					MethodItem methodItem = new MethodItem();
																					_002F_003D_0028__0024_003E_003D_0028(methodItem, num80);
																					_003E_0023_0026_0025_0028_0029_0040_003D(methodItem, _002B_0024_003D_002F_003C_0029_005E_005E(_0021_005E_005E__005E_002A_0028_005E(current3)));
																					__0040_0029_005E_0040_002D_0025_005E(methodItem, VCT_003D(current3));
																					_0021_005E__0024_0025_003E_0040_002A(methodItem, _003C_0029_0024_002A_003F_0021_003C_0023(current2));
																					_002A_0023_003C_003F_0028_0029_0021_(methodItem, flag2);
																					_002F_002B_0024_002F_002F_0029_003F_0024(methodItem, flag2);
																					list4.Add(methodItem);
																					int[,] array9 = new int[4, 4];
																					array9[0, 0] = -721149665;
																					array9[0, 1] = -239706370;
																					array9[0, 2] = 452625881;
																					array9[0, 3] = 778221738;
																					array9[1, 0] = -860656950;
																					array9[1, 1] = 2068046356;
																					array9[1, 2] = -329960457;
																					array9[1, 3] = -694695483;
																					array9[2, 0] = 1573944926;
																					array9[2, 1] = 1380098641;
																					array9[2, 2] = -1834608986;
																					array9[2, 3] = 264984138;
																					array9[3, 0] = -1800642696;
																					array9[3, 1] = 408754486;
																					array9[3, 2] = 1479111583;
																					array9[3, 3] = -734262951;
																					array9[0, 1] = array9[3, 2] ^ 0x48159D9E;
																					array9[1, 0] = array9[1, 1] ^ -1998060967;
																					array9[0, 0] = array9[2, 1] ^ -116733898;
																					int num82 = array9[0, 0] ^ 0x4DF7B732;
																					num49 = (int)((num4 * 2016821940) ^ 0xA42BC354u) ^ num82;
																				}
																				continue;
																			}
																			num83 = (XkQ_003D(current3) ? 1 : 0);
																		}
																		else
																		{
																			if (!flag)
																			{
																				int[,] array10 = new int[4, 4];
																				array10[0, 0] = 806359661;
																				array10[0, 1] = -1309710935;
																				array10[0, 2] = 1001054366;
																				array10[0, 3] = -1611919648;
																				array10[1, 0] = -1502172533;
																				array10[1, 1] = -209506280;
																				array10[1, 2] = -1781254681;
																				array10[1, 3] = -1170755821;
																				array10[2, 0] = 332717273;
																				array10[2, 1] = -1841678528;
																				array10[2, 2] = -913616063;
																				array10[2, 3] = -1038444263;
																				array10[3, 0] = 1050054478;
																				array10[3, 1] = 2137940632;
																				array10[3, 2] = 1299979675;
																				array10[3, 3] = -620110907;
																				array10[2, 0] = array10[0, 0] ^ -318985851;
																				array10[1, 0] = array10[0, 3] ^ -1853368489;
																				array10[1, 2] = array10[0, 2] ^ 0x6EC9BD1E;
																				array10[3, 0] = array10[0, 3] ^ -1212290893;
																				int num84 = array10[3, 0] ^ -162383071;
																				num49 = ((int)num4 * -293478521) ^ 0xBB57A8E ^ num84;
																				continue;
																			}
																			num83 = 1;
																		}
																		flag2 = (byte)num83 != 0;
																		num49 = 238104202;
																	}
																	else
																	{
																		num80 = mDToken.ToInt32();
																		int[] array11 = new int[5] { -635822725, 1494916566, -1324071700, -633897802, -1496358850 };
																		array11[4] ^= -90990557;
																		array11[1] = array11[2] ^ -25738877;
																		array11[4] = array11[3] ^ -607781222;
																		int[] array12 = new int[6] { -1194066239, 961682920, -1720682431, 330221035, -1595985496, 142475460 };
																		int[][] array13 = new int[2][] { array11, array12 };
																		array12[2] = array13[0][0] ^ -1349690328;
																		array12[4] ^= -1460553252;
																		array12[3] = array12[0] ^ 0x7501B0B9;
																		array12[4] = array12[2] ^ 0x28505703;
																		int num85 = array13[1][2] ^ -1453596160;
																		num49 = ((int)num4 * -1143513068) ^ -1406341404 ^ num85;
																	}
																}
																else
																{
																	mDToken = _0029_0029_003F_0023_0024_005E_003D_003F(current3);
																	int[] array14 = new int[6];
																	array14[0] = 417999956;
																	array14[1] = 1933656147;
																	array14[2] = -1869079296;
																	array14[3] = -1454045029;
																	array14[4] = 1202667817;
																	array14[5] = 1446283661;
																	array14[3] = array14[4] ^ 0x16F7D2EF;
																	array14[3] = array14[5] ^ -1109787654;
																	array14[3] = array14[1] ^ -1479853560;
																	int[] array15 = new int[4] { -229291989, 1065161216, 138567294, 1334853538 };
																	int[][] array16 = new int[2][] { array14, array15 };
																	array15[0] = array16[0][4] ^ -1481475277;
																	array15[3] = array15[2] ^ -809270710;
																	array15[3] = array15[2] ^ 0x3954248E;
																	int num86 = array16[1][0] ^ -442566164;
																	num49 = ((int)num4 * -1759010072) ^ 0x2EFE1480 ^ num86;
																}
															}
															else
															{
																current3 = enumerator3.Current;
																num49 = -1105065855;
															}
														}
														num87 = num3;
														num88 = 948159615;
														_ = 0;
														for (int num89 = 0; num89 < 2; num89++)
														{
															num88 = -(~num88);
															num88 = -82042027 - (-1755445870 - num88);
														}
													}
													while (num87 == (uint)num88);
													uint num90 = num3;
													int num91 = -1264626948;
													_ = 0;
													for (int num92 = 0; num92 < 2; num92++)
													{
														num91 = num91 + -1576621143 + 576849906;
														num91 = num91 * -1043173055 * -177224943;
													}
													if (num90 == (uint)num91)
													{
													}
												}
												finally
												{
													if (enumerator3 != null)
													{
														while (true)
														{
															int num93 = -295658929;
															while (true)
															{
																num2 = num93;
																num3 = (num4 = (uint)(~(-(~((num2 + (~(~(0x2448B0E3 ^ -1919463063)) + ~(-414088917 - (-(-(~-4134046) - (0x48D75166 ^ 0x6AE08BF2)) * 2126682415 + ~((-(-616329568 + 404628899) ^ 0x703FC963) + ((-920349549 - (1453725652 - -1780166395)) ^ -(~-1021271567))))))) ^ ~(--1631230525 + -(-((--1949672878 ^ -53203045) * 1674312067) ^ (-1450543751 ^ -(-1780312011 ^ -975863894))))))) ^ (-(156339451 * -1770006268) ^ (-(-437457236 - 1992361704) ^ -601138316)))) % 3;
																uint num94 = num3;
																int num95 = -3;
																_ = 0;
																for (int num96 = 0; num96 < 1; num96++)
																{
																	num95 = ~num95;
																}
																if (num94 == (uint)num95)
																{
																	break;
																}
																uint num97 = num3;
																int num98 = -1;
																_ = 0;
																for (int num99 = 0; num99 < 1; num99++)
																{
																	num98 = -num98;
																}
																if (num97 != (uint)num98)
																{
																	uint num100 = num3;
																	int num101 = -934970540;
																	_ = 0;
																	for (int num102 = 0; num102 < 1; num102++)
																	{
																		num101 -= -934970540;
																	}
																	if (num100 == (uint)num101)
																	{
																	}
																	goto end_IL_251f;
																}
																_003D_002D_0024_003F_003D_003F_003C_0021((IDisposable)enumerator3);
																int[] array17 = new int[5];
																array17[0] = -960158404;
																array17[1] = 1130801937;
																array17[2] = -41942035;
																array17[3] = -447514113;
																array17[4] = 236393060;
																array17[4] = array17[1] ^ -1009756078;
																array17[4] = array17[0] ^ -992219741;
																int[] array18 = new int[7] { 734958761, 1638758937, -888603621, -314791950, 448746260, 55583339, 1603066640 };
																int[][] array19 = new int[2][] { array17, array18 };
																array18[6] = array19[0][1] ^ -1308754940;
																array18[1] = array18[2] ^ 0x3E8B520;
																array18[2] = array18[3] ^ 0x604E4211;
																array18[4] = array18[5] ^ -1595717196;
																int num103 = array19[1][6] ^ -1050481339;
																num93 = ((int)num4 * -249777956) ^ 0x71243608 ^ num103;
															}
															continue;
															end_IL_251f:
															break;
														}
													}
												}
												gQj_003D[_003C_0029_0024_002A_003F_0021_003C_0023(current2)] = list3;
												goto IL_2909;
											}
											int num104 = -135303105;
											goto IL_290e;
											IL_290e:
											while (true)
											{
												num2 = num104;
												num3 = (num4 = (uint)(~(-(~((num2 + (~(~(0x2448B0E3 ^ -1919463063)) + ~(-414088917 - (-(-(~-4134046) - (0x48D75166 ^ 0x6AE08BF2)) * 2126682415 + ~((-(-616329568 + 404628899) ^ 0x703FC963) + ((-920349549 - (1453725652 - -1780166395)) ^ -(~-1021271567))))))) ^ ~(--1631230525 + -(-((--1949672878 ^ -53203045) * 1674312067) ^ (-1450543751 ^ -(-1780312011 ^ -975863894))))))) ^ (-(156339451 * -1770006268) ^ (-(-437457236 - 1992361704) ^ -601138316)))) % 5;
												uint num105 = num3;
												int num106 = 0;
												_ = 0;
												for (int num107 = 0; num107 < 2; num107++)
												{
													num106 = -410507141 - num106 + 211768740;
													num106 = num106 - -1759700606 * -557765035 + -1717241216;
												}
												if (num105 == (uint)num106)
												{
													break;
												}
												uint num108 = num3;
												int num109 = -1202032949;
												_ = 0;
												for (int num110 = 0; num110 < 2; num110++)
												{
													num109 = ~num109 * -1266935625;
													num109 = ~num109 + 1105071721;
												}
												if (num108 != (uint)num109)
												{
													uint num111 = num3;
													int num112 = -5;
													_ = 0;
													for (int num113 = 0; num113 < 1; num113++)
													{
														num112 = ~num112;
													}
													if (num111 == (uint)num112)
													{
														num114++;
														int[,] array20 = new int[3, 3]
														{
															{ -1044893450, 1475642378, -549568830 },
															{ -920553023, 852792008, -455190662 },
															{ -1743721690, -1125146842, -1316128022 }
														};
														array20[1, 2] ^= -718078866;
														array20[2, 2] = array20[1, 2] ^ -1116137576;
														array20[0, 0] = array20[1, 0] ^ -1737146313;
														int num115 = array20[0, 0] ^ 0x7D939E0F;
														num104 = (int)((num4 * 242309258) ^ 0xA80A1996u) ^ num115;
														continue;
													}
													goto IL_2b2e;
												}
												List<TypeItem> list5 = list2;
												TypeItem typeItem = new TypeItem();
												_0028_0025_0024__0024_002F_0028_003C(typeItem, _003C_0029_0024_002A_003F_0021_003C_0023(current2));
												_0029_0029__0025_0021_003F_005E_002B(typeItem, _002B_0024_003D_002F_003C_0029_005E_005E(_0024_0023_002B_0024_002F_0028_0029_0025(current2)));
												@__0029__002D_002F_002F_0029(typeItem, list3.Count);
												_0024_005E_002F_003E_005E_002F_0023_005E(typeItem, _003D_0024_002A_0025_005E___0021(current2));
												_0024_002B_0028_0029_002A_005E_0023_0023(typeItem, _0025_005E_003E_0021_0028_005E_003C_002B(current2));
												_005E_0029_0021_003E_0024_0029_003D_0024(typeItem, _0025_0023_005E_005E_0040_005E_0024_0024(current2));
												list5.Add(typeItem);
												int[] array21 = new int[6];
												array21[0] = -287168781;
												array21[1] = 1184213728;
												array21[2] = -1941636640;
												array21[3] = -206975188;
												array21[4] = -1240079816;
												array21[5] = 2015544036;
												array21[5] = array21[3] ^ -1018101885;
												array21[3] = array21[0] ^ 0x55EBF887;
												int[] array22 = new int[4] { 1592013206, 800326555, 99135992, 1296862534 };
												int[][] array23 = new int[2][] { array21, array22 };
												array22[1] = array23[0][4] ^ -419360946;
												array22[0] = array22[2] ^ -1015649835;
												array22[3] = array22[1] ^ -1208584428;
												int num116 = array23[1][1] ^ -1236306946;
												num104 = (int)((num4 * 1909714447) ^ 0x3512609E) ^ num116;
											}
											goto IL_2909;
											IL_2909:
											num104 = -805889965;
											goto IL_290e;
											IL_2b2e:
											num117 = num3;
											num118 = 1;
											_ = 0;
											for (int num119 = 0; num119 < 2; num119++)
											{
												num118 = num118 - (-1321427844 ^ -289261422) - 224589877;
												num118 = ~num118;
											}
										}
										while (num117 == (uint)num118);
										uint num120 = num3;
										int num121 = -1558099897;
										_ = 0;
										for (int num122 = 0; num122 < 1; num122++)
										{
											num121 ^= -1558099899;
										}
										if (num120 == (uint)num121)
										{
										}
									}
									finally
									{
										if (enumerator2 != null)
										{
											while (true)
											{
												int num123 = 159738065;
												while (true)
												{
													num2 = num123;
													num3 = (num4 = (uint)(~(-(~((num2 + (~(~(0x2448B0E3 ^ -1919463063)) + ~(-414088917 - (-(-(~-4134046) - (0x48D75166 ^ 0x6AE08BF2)) * 2126682415 + ~((-(-616329568 + 404628899) ^ 0x703FC963) + ((-920349549 - (1453725652 - -1780166395)) ^ -(~-1021271567))))))) ^ ~(--1631230525 + -(-((--1949672878 ^ -53203045) * 1674312067) ^ (-1450543751 ^ -(-1780312011 ^ -975863894))))))) ^ (-(156339451 * -1770006268) ^ (-(-437457236 - 1992361704) ^ -601138316)))) % 3;
													uint num124 = num3;
													int num125 = 0;
													_ = 0;
													for (int num126 = 0; num126 < 1; num126++)
													{
														num125 = -num125;
													}
													if (num124 == (uint)num125)
													{
														break;
													}
													uint num127 = num3;
													int num128 = -503294665;
													_ = 0;
													for (int num129 = 0; num129 < 1; num129++)
													{
														num128 ^= -503294667;
													}
													if (num127 != (uint)num128)
													{
														uint num130 = num3;
														int num131 = -890570281;
														_ = 0;
														for (int num132 = 0; num132 < 2; num132++)
														{
															num131 = ~(-num131);
															num131 = num131 - ~-1618135857 - 84062650;
														}
														if (num130 == (uint)num131)
														{
														}
														goto end_IL_2fd3;
													}
													_003D_002D_0024_003F_003D_003F_003C_0021((IDisposable)enumerator2);
													int[,] array24 = new int[3, 4];
													array24[0, 0] = 370848393;
													array24[0, 1] = 1611764748;
													array24[0, 2] = -594937346;
													array24[0, 3] = 1138663929;
													array24[1, 0] = -434737542;
													array24[1, 1] = -1061353532;
													array24[1, 2] = -10430984;
													array24[1, 3] = 768799103;
													array24[2, 0] = -1938418453;
													array24[2, 1] = -861634403;
													array24[2, 2] = -836064145;
													array24[2, 3] = -661458957;
													array24[2, 2] = array24[2, 1] ^ 0x1087FA77;
													array24[0, 0] = array24[1, 2] ^ 0x4043260F;
													array24[1, 0] = array24[1, 3] ^ 0x10A39BE0;
													array24[2, 2] = array24[2, 3] ^ 0x5E6B5B87;
													int num133 = array24[2, 2] ^ 0x7BA77CEF;
													num123 = (int)((num4 * 1045716745) ^ 0xB7D1200) ^ num133;
												}
												continue;
												end_IL_2fd3:
												break;
											}
										}
									}
									NamespaceItem namespaceItem = new NamespaceItem();
									_002A_0024_005E_003D_0040_002F_0021_0028(namespaceItem, current.Key);
									_0025_003E_005E_003D_0040_0021_002D_005E(namespaceItem, (IReadOnlyList<TypeItem>)list2);
									list.Add(namespaceItem);
									goto IL_3429;
								}
								int num134 = 267291010;
								goto IL_342e;
								IL_3429:
								num134 = 830535835;
								goto IL_342e;
								IL_342e:
								num2 = num134;
								num3 = (num4 = (uint)(~(-(~((num2 + (~(~(0x2448B0E3 ^ -1919463063)) + ~(-414088917 - (-(-(~-4134046) - (0x48D75166 ^ 0x6AE08BF2)) * 2126682415 + ~((-(-616329568 + 404628899) ^ 0x703FC963) + ((-920349549 - (1453725652 - -1780166395)) ^ -(~-1021271567))))))) ^ ~(--1631230525 + -(-((--1949672878 ^ -53203045) * 1674312067) ^ (-1450543751 ^ -(-1780312011 ^ -975863894))))))) ^ (-(156339451 * -1770006268) ^ (-(-437457236 - 1992361704) ^ -601138316)))) % 3;
								uint num135 = num3;
								int num136 = 0;
								_ = 0;
								for (int num137 = 0; num137 < 1; num137++)
								{
									num136 *= -500391041;
								}
								if (num135 != (uint)num136)
								{
									uint num138 = num3;
									int num139 = 1932705587;
									_ = 0;
									for (int num140 = 0; num140 < 2; num140++)
									{
										num139 = ~(num139 + ~-1048407194);
										num139 = (num139 - (-1290902029 ^ -707904382)) * -1137735433;
									}
									if (num138 != (uint)num139)
									{
										break;
									}
									continue;
								}
								goto IL_3429;
							}
							uint num141 = num3;
							int num142 = -1874764680;
							_ = 0;
							for (int num143 = 0; num143 < 1; num143++)
							{
								num142 = -1874764678 - num142;
							}
							if (num141 == (uint)num142)
							{
							}
						}
						finally
						{
							if (enumerator != null)
							{
								while (true)
								{
									int num144 = -794210388;
									while (true)
									{
										num2 = num144;
										num3 = (num4 = (uint)(~(-(~((num2 + (~(~(0x2448B0E3 ^ -1919463063)) + ~(-414088917 - (-(-(~-4134046) - (0x48D75166 ^ 0x6AE08BF2)) * 2126682415 + ~((-(-616329568 + 404628899) ^ 0x703FC963) + ((-920349549 - (1453725652 - -1780166395)) ^ -(~-1021271567))))))) ^ ~(--1631230525 + -(-((--1949672878 ^ -53203045) * 1674312067) ^ (-1450543751 ^ -(-1780312011 ^ -975863894))))))) ^ (-(156339451 * -1770006268) ^ (-(-437457236 - 1992361704) ^ -601138316)))) % 3;
										uint num145 = num3;
										int num146 = -2;
										_ = 0;
										for (int num147 = 0; num147 < 1; num147++)
										{
											num146 = -num146;
										}
										if (num145 == (uint)num146)
										{
											break;
										}
										uint num148 = num3;
										int num149 = -1;
										_ = 0;
										for (int num150 = 0; num150 < 1; num150++)
										{
											num149 = -num149;
										}
										if (num148 != (uint)num149)
										{
											uint num151 = num3;
											int num152 = 0;
											_ = 0;
											for (int num153 = 0; num153 < 1; num153++)
											{
												num152 *= -1905633203;
											}
											if (num151 == (uint)num152)
											{
											}
											goto end_IL_366a;
										}
										_003D_002D_0024_003F_003D_003F_003C_0021((IDisposable)enumerator);
										int[] array25 = new int[4];
										array25[0] = 170185932;
										array25[1] = -1841573639;
										array25[2] = -1278732621;
										array25[3] = -322616032;
										array25[3] = array25[1] ^ 0x26C12B7A;
										array25[1] ^= 909115293;
										array25[1] = array25[0] ^ 0x6841C7D1;
										int[] array26 = new int[6];
										array26[0] = 1858306328;
										array26[1] = 957361928;
										array26[2] = -1802982322;
										array26[3] = 260334454;
										array26[4] = 431242584;
										array26[5] = -762335048;
										array26[4] = array25[2] ^ -888708321;
										array26[1] ^= -1271506497;
										array26[5] ^= -925504349;
										int num154 = array26[4] ^ 0x6E694486;
										num144 = ((int)num4 * -628525402) ^ 0x30F90792 ^ num154;
									}
									continue;
									end_IL_366a:
									break;
								}
							}
						}
						AssemblyProfile assemblyProfile = new AssemblyProfile();
						_0024_003C__003E_002B_0024_0025_0024(assemblyProfile, cqh_003D);
						_005E_005E_0040_0025_002D_0028_0040_002A(assemblyProfile, _0024_003F_0040_005E_0025_005E_002D_0029(cqh_003D));
						_002F_003E_002D_005E_005E_002F_002D_0025(assemblyProfile, @_002F_003D_005E_0024_005E_002F_002F(cqh_003D));
						_0024_003F_003E_003F_0024_0028_003D_003C(assemblyProfile, _0024_0026_003C_005E_003E_0023_0024_0026(new FileInfo(cqh_003D)));
						_003D_0024_003C_003C__005E_0024_003C(assemblyProfile, CpM_003D(_0024_0026_003C_005E_003E_0023_0024_0026(new FileInfo(cqh_003D))));
						AssemblyDef assemblyDef = _005E_0025_0021_0029_0026_002A__0040((ModuleDef)JtE_003D);
						_002A_0021_002A_002B_0040_003C_0024_003E(assemblyProfile, _002B_0024_003D_002F_003C_0029_005E_005E(((assemblyDef != null) ? _003D_002F_0025_005E_003C_003E_002B_005E(assemblyDef) : null) ?? @_002F_002B_003E_0023_002F_003C_0021(_003D_002A_0023_0024_0029_0040_005E_0028(cqh_003D))));
						_005E_002B_002A_0029_003E_003E_005E_003E(assemblyProfile, _002B_003F_0021_0023_003F_003F_0025_003F(_0026_003C_0024_0040_0024_002A_0021_002F((ModuleDef)JtE_003D)) ? _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x814 ^ 0x988] : _0026_003C_0024_0040_0024_002A_0021_002F((ModuleDef)JtE_003D));
						_002D_003E_0021_002A_0023_0024_0028_0024(assemblyProfile, _002A_0026_003E_003F_003D_0025_002D_0025((ModuleDef)JtE_003D).Any((TypeDef type) => _003C_003Ec._002F_002A_002D_003C_002A_002F_0026_005E(_003C_003Ec._0026_002D_0024_0026_0029_002A_0023_0029(type), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-692 + 228)], StringComparison.Ordinal)));
						_003F_003D_0040_003E_003F_003C_005E_0023(assemblyProfile, num114);
						_0024_003E_002F_0025_0040_003E_0029_0023(assemblyProfile, num78);
						_0028_0024_0026_002D_003F_0021_0025_0026(assemblyProfile, (IReadOnlyList<NamespaceItem>)list);
						return assemblyProfile;
					}
					num78 = 0;
					int[] array27 = new int[5];
					array27[0] = -334630754;
					array27[1] = 500328020;
					array27[2] = -1523561068;
					array27[3] = -480438173;
					array27[4] = 2033733814;
					array27[3] = array27[0] ^ 0x2E4A3755;
					array27[3] = array27[1] ^ -1804050355;
					array27[3] ^= -454781349;
					int[] array28 = new int[5];
					array28[0] = 661080796;
					array28[1] = 579477258;
					array28[2] = -1840440142;
					array28[3] = 1948682698;
					array28[4] = -731267941;
					array28[3] = array27[2] ^ -1341568336;
					array28[2] = array28[3] ^ -1659806502;
					array28[4] = array28[1] ^ 0x12F9804D;
					int num155 = array28[3] ^ -886369043;
					num = (int)((num4 * 238303964) ^ 0xFD1594B8u) ^ num155;
				}
				else
				{
					num114 = 0;
					int[] array29 = new int[7];
					array29[0] = 1716208797;
					array29[1] = 1011065739;
					array29[2] = 377288255;
					array29[3] = -250747366;
					array29[4] = -741105395;
					array29[5] = 453195755;
					array29[6] = -784870335;
					array29[6] = array29[0] ^ 0x4593E97C;
					array29[6] = array29[2] ^ -1258846930;
					int[] array30 = new int[6] { -176361080, -606749334, -322470942, -1434441267, -414540952, 1433654513 };
					int[][] array31 = new int[2][] { array29, array30 };
					array30[2] = array31[0][1] ^ -1217456453;
					array30[5] = array30[1] ^ -931557678;
					array30[0] ^= 648925771;
					array30[5] = array30[2] ^ 0x12049CA9;
					int num156 = array31[1][2] ^ -1302519773;
					num = ((int)num4 * -355029631) ^ -877026323 ^ num156;
				}
			}
		}
	}

	public IReadOnlyList<MethodItem> GetMethodsForType(string bYQ_003D)
	{
		if (!gQj_003D.TryGetValue(bYQ_003D, out List<MethodItem> value))
		{
			uint num2;
			int num4;
			do
			{
				int num = -1033441939;
				uint num3;
				num2 = (num3 = (uint)((~(-(~(num - -(-((-(~(--1512515769 ^ --286711982) + -4601624) ^ -1098816848) + (~-1839799601 + -(~(-1903489306 + 1753156148 + (-1395349625 ^ -481679084))) * -726248579)))) ^ (~(-1271281319 - (~(881593283 * -2015300365) - -979183578)) - ~(-106305827 ^ 0x3C2EE5A3) - (-1753502891 ^ ((-1063317655 * (1976062738 * -2056980105) + (1623692840 + -711407261 + -905124503 * -462570219)) * -1583655509 + (((-654939201 - 222675979 + -1034287612) ^ --1802827283) + -1927086234))))) * -531714755 - ~((0x68C7970A ^ --1453321362) * 369969137)) - ~(--792254151)) * 1898499291 + -1942238660)) % 3;
				num4 = -3;
				_ = 0;
				for (int num5 = 0; num5 < 1; num5++)
				{
					num4 = ~num4;
				}
			}
			while (num2 == (uint)num4);
			int num6 = -2;
			_ = 0;
			for (int num7 = 0; num7 < 1; num7++)
			{
				num6 = ~num6;
			}
			if (num2 == (uint)num6)
			{
				return new List<MethodItem>();
			}
			int num8 = 0;
			_ = 0;
			for (int num9 = 0; num9 < 2; num9++)
			{
				num8 = -(num8 - (-863960568 ^ 0x753902F5));
				num8 = ~(~num8);
			}
			if (num2 == (uint)num8)
			{
			}
		}
		return value.Select(wpa_003D).ToList();
	}

	public void SetMethodSelection(int ihU_003D, bool eYk_003D)
	{
		MethodItem methodItem = default(MethodItem);
		int token = default(int);
		while (true)
		{
			int num = -1436957082;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(~((num2 + (-(-(604241081 * (-(~-986931774) ^ -71190593))) - (-(-(~(-1141569271 * 1898827809 + -464330743) + ((0x26E939B2 ^ 0x13E9FD0C) + 1947681710))) - (-(767086977 * (-2094897992 + -43082397 - ~-1022979838) * -1527573331) + ~(-(~(-2064275159) ^ (-1013519958 * -1585665067)))) - ~(~634375682 + -(-(0x37C1C4DE ^ -1702232232)))))) ^ ~((-(-2136297517 * ~-549288002) - ((-264190345 ^ 0x133F792) + ~974697136 + (--883443966 + (-1728171332 - 264327779)) - ~(~(-1505440979 + 2052909513)) + (-2070706352 + -781959772 * -1584767497))) ^ ((-1651813128 - ((~(--558338077) ^ -(-719728482 ^ 0x54BEB309)) - ((-828769360 * -1079444075 + -2031166649) ^ (-98442064 - --1054041129)))) ^ ((-1170716682 + -((1391772921 + 2005465789) * 682124017)) ^ 0x376BB23D))) ^ -(~(-((2115534938 * -679566521 - --2092716037 - (62973341 - -1016781207) * -1945522647) * 423140751)))) ^ -1800304775))) % 3;
				uint num5 = num3;
				int num6 = 1688115967;
				_ = 0;
				for (int num7 = 0; num7 < 1; num7++)
				{
					num6 ^= 0x649E9AFD;
				}
				if (num5 == (uint)num6)
				{
					break;
				}
				uint num8 = num3;
				int num9 = 1;
				_ = 0;
				for (int num10 = 0; num10 < 2; num10++)
				{
					num9 = -(~num9);
					num9 = ~(-num9);
				}
				if (num8 != (uint)num9)
				{
					uint num11 = num3;
					int num12 = -1815831324;
					_ = 0;
					for (int num13 = 0; num13 < 2; num13++)
					{
						num12 += -1570024021 + -2043107492;
						num12 = 392275719 - num12 * 454917951;
					}
					if (num11 != (uint)num12)
					{
					}
					using Dictionary<string, List<MethodItem>>.ValueCollection.Enumerator enumerator = gQj_003D.Values.GetEnumerator();
					while (true)
					{
						int num14;
						int num15;
						if (!enumerator.MoveNext())
						{
							num14 = 2018663955;
							num15 = num14;
						}
						else
						{
							num14 = -2090122421;
							num15 = num14;
						}
						while (true)
						{
							num2 = num14;
							num3 = (num4 = (uint)(-(~((num2 + (-(-(604241081 * (-(~-986931774) ^ -71190593))) - (-(-(~(-1141569271 * 1898827809 + -464330743) + ((0x26E939B2 ^ 0x13E9FD0C) + 1947681710))) - (-(767086977 * (-2094897992 + -43082397 - ~-1022979838) * -1527573331) + ~(-(~(-2064275159) ^ (-1013519958 * -1585665067)))) - ~(~634375682 + -(-(0x37C1C4DE ^ -1702232232)))))) ^ ~((-(-2136297517 * ~-549288002) - ((-264190345 ^ 0x133F792) + ~974697136 + (--883443966 + (-1728171332 - 264327779)) - ~(~(-1505440979 + 2052909513)) + (-2070706352 + -781959772 * -1584767497))) ^ ((-1651813128 - ((~(--558338077) ^ -(-719728482 ^ 0x54BEB309)) - ((-828769360 * -1079444075 + -2031166649) ^ (-98442064 - --1054041129)))) ^ ((-1170716682 + -((1391772921 + 2005465789) * 682124017)) ^ 0x376BB23D))) ^ -(~(-((2115534938 * -679566521 - --2092716037 - (62973341 - -1016781207) * -1945522647) * 423140751)))) ^ -1800304775))) % 7;
							uint num16 = num3;
							int num17 = 1850033216;
							_ = 0;
							for (int num18 = 0; num18 < 2; num18++)
							{
								num17 = -num17 * 118900475;
								num17 = 1490680221 + 196353522 - num17 - -535621377;
							}
							if (num16 == (uint)num17)
							{
								num14 = -2090122421;
								continue;
							}
							uint num19 = num3;
							int num20 = 4;
							_ = 0;
							for (int num21 = 0; num21 < 2; num21++)
							{
								num20 = ~num20 ^ 0x3C324EF8;
								num20 = ~(-num20);
							}
							if (num19 != (uint)num20)
							{
								uint num22 = num3;
								int num23 = 3;
								_ = 0;
								for (int num24 = 0; num24 < 2; num24++)
								{
									num23 = ~num23;
									num23 = -1373345134 - (-567222017 * -177757065 - num23);
								}
								if (num22 != (uint)num23)
								{
									uint num25 = num3;
									int num26 = 523789;
									_ = 0;
									for (int num27 = 0; num27 < 2; num27++)
									{
										num26 = (num26 - -2113796693 * 1669502395) ^ 0x248C3FC4;
										num26 = ~num26 + 1971940308;
									}
									if (num25 != (uint)num26)
									{
										break;
									}
									_002A_0023_003C_003F_0028_0029_0021_(methodItem, eYk_003D);
									int[,] array = new int[4, 3];
									array[0, 0] = -1728667279;
									array[0, 1] = -1799448277;
									array[0, 2] = -1833932295;
									array[1, 0] = 1316683711;
									array[1, 1] = 265804605;
									array[1, 2] = -2116676751;
									array[2, 0] = 527304475;
									array[2, 1] = -2021056448;
									array[2, 2] = 466364340;
									array[3, 0] = -1397097;
									array[3, 1] = -2084712126;
									array[3, 2] = -1630698505;
									array[3, 0] = array[3, 2] ^ 0x5871DB5A;
									array[1, 2] = array[1, 0] ^ 0x7ECCE8B;
									array[1, 0] = array[3, 2] ^ 0x28B6AE87;
									array[1, 2] = array[3, 1] ^ 0x3924B3F6;
									int num28 = array[1, 2] ^ 0x9FFDA23;
									num14 = (int)((num4 * 1809628178) ^ 0x7FE0F86E) ^ num28;
									continue;
								}
								MethodItem methodItem2 = methodItem;
								int[] array2 = new int[4];
								array2[0] = 1512857470;
								array2[1] = 1190048225;
								array2[2] = 291048907;
								array2[3] = 139397039;
								array2[1] = array2[0] ^ -1050603782;
								array2[1] = array2[2] ^ 0x4F174646;
								int[] array3 = new int[5] { 900758815, -717640508, -1188041553, 1712402910, 1936344174 };
								int[][] array4 = new int[2][] { array2, array3 };
								array3[0] = array4[0][2] ^ -1227332755;
								array3[4] ^= -1890190207;
								array3[2] = array3[3] ^ -974868191;
								array3[3] = array3[2] ^ -303367116;
								int num29 = array4[1][0] ^ 0x15611770;
								int[] array5 = new int[4];
								array5[0] = -614812344;
								array5[1] = -45732126;
								array5[2] = -2093760718;
								array5[3] = -328229478;
								array5[0] = array5[2] ^ 0x7B1A03BB;
								array5[3] ^= 1290165522;
								array5[0] = array5[1] ^ 0xF73EABE;
								int[] array6 = new int[4] { 157905215, 731793306, -1357123713, -1147513023 };
								int[][] array7 = new int[2][] { array5, array6 };
								array6[1] = array7[0][1] ^ -2124961284;
								array6[3] ^= 1749703017;
								array6[0] = array6[2] ^ -1122028497;
								int num30 = array7[1][1] ^ -118361504;
								int num31 = (int)((num4 * 1260882589) ^ 0x351D59CE);
								num29 ^= num31;
								num30 ^= num31;
								int num32;
								int num33;
								if (methodItem2 != null)
								{
									num32 = num30;
									num33 = num32;
								}
								else
								{
									num32 = num29;
									num33 = num32;
								}
								num14 = num32 ^ num31;
							}
							else
							{
								methodItem = enumerator.Current.FirstOrDefault((MethodItem item) => _003C_003Ec__DisplayClass14_0.@_002A_005E_003C_005E_002D_0029_005E(item) == token);
								num14 = 1791603941;
							}
						}
						uint num34 = num3;
						int num35 = 1598796157;
						_ = 0;
						for (int num36 = 0; num36 < 1; num36++)
						{
							num35 ^= 0x5F4BB17B;
						}
						if (num34 == (uint)num35)
						{
							break;
						}
						uint num37 = num3;
						int num38 = -529929755;
						_ = 0;
						for (int num39 = 0; num39 < 1; num39++)
						{
							num38 ^= -529929753;
						}
						if (num37 != (uint)num38)
						{
							uint num40 = num3;
							int num41 = 1625566351;
							_ = 0;
							for (int num42 = 0; num42 < 1; num42++)
							{
								num41 *= -1984466321;
							}
							if (num40 == (uint)num41)
							{
							}
							break;
						}
					}
					return;
				}
				token = ihU_003D;
				int[,] array8 = new int[3, 3];
				array8[0, 0] = -678714836;
				array8[0, 1] = -384079467;
				array8[0, 2] = -86849492;
				array8[1, 0] = 90044593;
				array8[1, 1] = 2137561185;
				array8[1, 2] = -1011405765;
				array8[2, 0] = -2104866308;
				array8[2, 1] = -318176040;
				array8[2, 2] = -995289506;
				array8[1, 1] = array8[2, 1] ^ 0x226C9DE2;
				array8[0, 0] = array8[2, 2] ^ 0x3E12C463;
				array8[1, 1] = array8[2, 2] ^ -1715240103;
				int num43 = array8[1, 1] ^ -1663819199;
				num = ((int)num4 * -1475243425) ^ 0x7BE6B579 ^ num43;
			}
		}
	}

	public unsafe byte[] PrepareAssemblyForProtection(bool IGZ_003D)
	{
		if (rBc_003D)
		{
			TypeDef typeDef2 = default(TypeDef);
			MethodDef value = default(MethodDef);
			CustomAttribute current2 = default(CustomAttribute);
			MethodDef methodDef = default(MethodDef);
			byte[] result = default(byte[]);
			while (true)
			{
				int num = 1894030335;
				uint num3;
				while (true)
				{
					int num2 = num;
					uint num4;
					num3 = (num4 = (uint)((-(num2 ^ (1551471731 * ((1070208689 - ((-(-1495188905 * -697025867 * -585389751) ^ -(~(1326082766 * -1505494605))) + 2124870537)) * 1216555299))) ^ --1391065644) - -557097407 * ((0x633A7A81 ^ (~(--42275944) ^ -921670812)) + (910297659 * ~(1635927187 * 692731121) - (--1945236030 - ~904243865) * -132174971)) + (-256960992 + ((-333973326 + -(-1480023944 - 1718314855)) ^ (-(740646262 - -42489751) - -1372934575 * (1722866110 + 1508079211)))) - ((-2004511064 ^ 0x4F4A7292) - -782489533 * (-896863515 * 1721792031 - ~1774106493)))) % 11;
					uint num5 = num3;
					int num6 = -7;
					_ = 0;
					for (int num7 = 0; num7 < 1; num7++)
					{
						num6 = -num6;
					}
					if (num5 == (uint)num6)
					{
						break;
					}
					uint num8 = num3;
					int num9 = -8;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 = -num9;
					}
					if (num8 != (uint)num9)
					{
						uint num11 = num3;
						int num12 = -1721710994;
						_ = 0;
						for (int num13 = 0; num13 < 1; num13++)
						{
							num12 = -1721710985 - num12;
						}
						if (num11 == (uint)num12)
						{
							goto end_IL_000e;
						}
						uint num14 = num3;
						int num15 = -191310772;
						_ = 0;
						for (int num16 = 0; num16 < 2; num16++)
						{
							num15 = 1331655139 - num15 * -1417628609;
							num15 ^= -85046796;
						}
						if (num14 != (uint)num15)
						{
							uint num17 = num3;
							int num18 = 528949217;
							_ = 0;
							for (int num19 = 0; num19 < 2; num19++)
							{
								num18 ^= -281383954;
								num18 = num18 + (0x2C4C38EE ^ 0xA894431) - -1263459239;
							}
							if (num17 != (uint)num18)
							{
								uint num20 = num3;
								int num21 = -2025468490;
								_ = 0;
								for (int num22 = 0; num22 < 2; num22++)
								{
									num21 = (--1373922948 - num21) * 721787763;
									num21 = 1134985561 - (num21 - 1789132427);
								}
								if (num20 != (uint)num21)
								{
									uint num23 = num3;
									int num24 = -1005832372;
									_ = 0;
									for (int num25 = 0; num25 < 2; num25++)
									{
										num24 = -(-num24);
										num24 = num24 - -1339395368 - -1311004468;
									}
									if (num23 != (uint)num24)
									{
										uint num26 = num3;
										int num27 = 1427856655;
										_ = 0;
										for (int num28 = 0; num28 < 1; num28++)
										{
											num27 -= 1427856652;
										}
										if (num26 != (uint)num27)
										{
											uint num29 = num3;
											int num30 = 1192996831;
											_ = 0;
											for (int num31 = 0; num31 < 2; num31++)
											{
												num30 = ~(~num30);
												num30 = ~(~1550985235 - num30);
											}
											if (num29 == (uint)num30)
											{
												TypeDef typeDef = typeDef2;
												int[,] array = new int[4, 4];
												array[0, 0] = 651365657;
												array[0, 1] = 336701273;
												array[0, 2] = -750220584;
												array[0, 3] = 459850759;
												array[1, 0] = 510640379;
												array[1, 1] = 773479407;
												array[1, 2] = -1761143070;
												array[1, 3] = 1398773021;
												array[2, 0] = -1123799516;
												array[2, 1] = 1239670210;
												array[2, 2] = -310209059;
												array[2, 3] = -418052309;
												array[3, 0] = 471072448;
												array[3, 1] = 1938124950;
												array[3, 2] = 1254673851;
												array[3, 3] = -455704298;
												array[3, 0] = array[1, 2] ^ -936867364;
												array[1, 1] = array[0, 2] ^ -505706447;
												array[1, 3] = array[2, 1] ^ 0x5E4B31F4;
												array[0, 0] = array[1, 2] ^ -1672652096;
												int num32 = array[0, 0] ^ 0x7C4DCA2A;
												int[] array2 = new int[5];
												array2[0] = 1050605939;
												array2[1] = -272790315;
												array2[2] = 763398018;
												array2[3] = 804656997;
												array2[4] = 1670384505;
												array2[3] = array2[2] ^ 0x681AC190;
												array2[1] ^= -691523364;
												array2[3] = array2[2] ^ 0x10AE52E;
												int[] array3 = new int[7];
												array3[0] = 406672551;
												array3[1] = 2127598556;
												array3[2] = -588590289;
												array3[3] = 407217382;
												array3[4] = 1894948181;
												array3[5] = -135837422;
												array3[6] = -40139227;
												array3[3] = array2[0] ^ 0x67AE0944;
												array3[2] = array3[3] ^ 0x5F40E1A0;
												array3[6] = array3[2] ^ 0x3C396B86;
												int num33 = array3[3] ^ -1732224252;
												int num34 = (int)((num4 * 1219428841) ^ 0x23A7955A);
												num32 ^= num34;
												num33 ^= num34;
												int num35;
												int num36;
												if (typeDef == null)
												{
													num35 = num33;
													num36 = num35;
												}
												else
												{
													num35 = num32;
													num36 = num35;
												}
												num = num35 ^ num34;
												continue;
											}
											goto IL_0486;
										}
										typeDef2 = _002A_0026_003E_003F_003D_0025_002D_0025((ModuleDef)BAB_003D).FirstOrDefault((TypeDef type) => _003C_003Ec._002F_002A_002D_003C_002A_002F_0026_005E(_003C_003Ec._0026_002D_0024_0026_0029_002A_0023_0029(type), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-769 + 305)], StringComparison.Ordinal));
										num = -598073590;
										continue;
									}
									throw new InvalidOperationException(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[3042 - 2651 + 23]);
								}
								int num37;
								if (BAB_003D == null)
								{
									num = -1015518393;
									num37 = num;
								}
								else
								{
									num = 1677057089;
									num37 = num;
								}
								continue;
							}
							return eJt_003D;
						}
						int num38;
						if (!IGZ_003D)
						{
							num = 2036875660;
							num38 = num;
						}
						else
						{
							num = 2041428707;
							num38 = num;
						}
						continue;
					}
					byte[]? array4 = eJt_003D;
					int[] array5 = new int[4];
					array5[0] = 1779736319;
					array5[1] = 5794559;
					array5[2] = -638011090;
					array5[3] = 990713615;
					array5[0] = array5[1] ^ 0x23CCD193;
					array5[0] = array5[2] ^ 0x2FD5F7D8;
					int[] array6 = new int[6];
					array6[0] = 333539287;
					array6[1] = 603429924;
					array6[2] = 354630288;
					array6[3] = 1235869896;
					array6[4] = 1395775273;
					array6[5] = -916863113;
					array6[4] = array5[1] ^ 0x14AE8B1C;
					array6[5] = array6[4] ^ -359736115;
					array6[3] ^= -2100197048;
					int num39 = array6[4] ^ 0x2BC5CE2E;
					int[] array7 = new int[5];
					array7[0] = -186178213;
					array7[1] = -1996902334;
					array7[2] = 1736195039;
					array7[3] = 1064925417;
					array7[4] = 8892058;
					array7[3] = array7[2] ^ -1548256068;
					array7[1] = array7[3] ^ -2133002363;
					array7[0] = array7[3] ^ 0x860F1F9;
					int[] array8 = new int[6];
					array8[0] = -691498805;
					array8[1] = -646656952;
					array8[2] = -306299501;
					array8[3] = 1734505456;
					array8[4] = 1060431521;
					array8[5] = -1934339314;
					array8[2] = array7[2] ^ -422541751;
					array8[0] = array8[2] ^ 0xE4F08DD;
					array8[4] = array8[3] ^ -1729135035;
					array8[4] = array8[1] ^ 0x61551FB4;
					int num40 = array8[2] ^ -1846322296;
					int num41 = (int)((num4 * 45458404) ^ 0x48B9F174);
					num39 ^= num41;
					num40 ^= num41;
					int num42;
					int num43;
					if (array4 == null)
					{
						num42 = num40;
						num43 = num42;
					}
					else
					{
						num42 = num39;
						num43 = num42;
					}
					num = num42 ^ num41;
				}
				continue;
				IL_0486:
				uint num44 = num3;
				int num45 = 1998757072;
				_ = 0;
				for (int num46 = 0; num46 < 2; num46++)
				{
					num45 = ~num45 - 1157225335;
					num45 = -(num45 - -97222721 * 777921055);
				}
				if (num44 != (uint)num45)
				{
					uint num47 = num3;
					int num48 = -460589788;
					_ = 0;
					for (int num49 = 0; num49 < 2; num49++)
					{
						num48 = ~(num48 + (1752419327 - 235408787));
						num48 = (num48 * -188449291) ^ -182302196;
					}
					if (num47 != (uint)num48)
					{
					}
					IEnumerator<MethodItem> enumerator = gQj_003D.Values.SelectMany((List<MethodItem> items) => items).GetEnumerator();
					try
					{
						while (_003C_003C_0024_0025_0029_005E_0029_003E((IEnumerator)enumerator))
						{
							while (true)
							{
								MethodItem current = enumerator.Current;
								int num50 = 43016215;
								while (true)
								{
									int num2 = num50;
									uint num4;
									num3 = (num4 = (uint)((-(num2 ^ (1551471731 * ((1070208689 - ((-(-1495188905 * -697025867 * -585389751) ^ -(~(1326082766 * -1505494605))) + 2124870537)) * 1216555299))) ^ --1391065644) - -557097407 * ((0x633A7A81 ^ (~(--42275944) ^ -921670812)) + (910297659 * ~(1635927187 * 692731121) - (--1945236030 - ~904243865) * -132174971)) + (-256960992 + ((-333973326 + -(-1480023944 - 1718314855)) ^ (-(740646262 - -42489751) - -1372934575 * (1722866110 + 1508079211)))) - ((-2004511064 ^ 0x4F4A7292) - -782489533 * (-896863515 * 1721792031 - ~1774106493)))) % 11;
									uint num51 = num3;
									int num52 = -37597910;
									_ = 0;
									for (int num53 = 0; num53 < 1; num53++)
									{
										num52 -= -37597912;
									}
									if (num51 == (uint)num52)
									{
										num50 = -769029511;
										continue;
									}
									uint num54 = num3;
									int num55 = -514240129;
									_ = 0;
									for (int num56 = 0; num56 < 2; num56++)
									{
										num55 = ~num55 + 666501459;
										num55 = ~(num55 * 1907283673);
									}
									if (num54 == (uint)num55)
									{
										break;
									}
									uint num57 = num3;
									int num58 = -2147454936;
									_ = 0;
									for (int num59 = 0; num59 < 2; num59++)
									{
										num58 = -(-num58);
										num58 = (num58 ^ 0x37FB36CC) - -736022841;
									}
									if (num57 != (uint)num58)
									{
										uint num60 = num3;
										int num61 = -385723292;
										_ = 0;
										for (int num62 = 0; num62 < 2; num62++)
										{
											num61 = (564857634 - -238292983 - num61) ^ 0x2376818A;
											num61 = ~(num61 * 825335603);
										}
										if (num60 != (uint)num61)
										{
											uint num63 = num3;
											int num64 = 9;
											_ = 0;
											for (int num65 = 0; num65 < 2; num65++)
											{
												num64 = -1279914293 - (num64 - ~-29260009);
												num64 = num64 - 1455747505 - -965702441;
											}
											if (num63 != (uint)num64)
											{
												uint num66 = num3;
												int num67 = -6;
												_ = 0;
												for (int num68 = 0; num68 < 1; num68++)
												{
													num67 = -num67;
												}
												if (num66 != (uint)num67)
												{
													uint num69 = num3;
													int num70 = -1532956453;
													_ = 0;
													for (int num71 = 0; num71 < 2; num71++)
													{
														num70 = -(num70 * -1106851685);
														num70 = ~num70;
													}
													if (num69 != (uint)num70)
													{
														uint num72 = num3;
														int num73 = 240525381;
														_ = 0;
														for (int num74 = 0; num74 < 2; num74++)
														{
															num73 *= 1807413837;
															num73 = (num73 - 1302693826 * 167375695) * 2087900263;
														}
														if (num72 != (uint)num73)
														{
															uint num75 = num3;
															int num76 = 2085838848;
															_ = 0;
															for (int num77 = 0; num77 < 2; num77++)
															{
																num76 = ~num76 + -1786852100;
																num76 = (num76 * -557754319) ^ 0x563E7143;
															}
															if (num75 != (uint)num76)
															{
																uint num78 = num3;
																int num79 = 1596281260;
																_ = 0;
																for (int num80 = 0; num80 < 1; num80++)
																{
																	num79 *= -1922647997;
																}
																if (num78 == (uint)num79)
																{
																	goto end_IL_269e;
																}
																uint num81 = num3;
																int num82 = -1624188321;
																_ = 0;
																for (int num83 = 0; num83 < 2; num83++)
																{
																	num82 = num82 * -1828278067 + -1440258803;
																	num82 = -(--1283775843 - num82);
																}
																if (num81 != (uint)num82)
																{
																}
																using (List<CustomAttribute>.Enumerator enumerator2 = (from attribute in _0028_003C_0025_0021_005E_003E_0028_0040(value)
																	where _003C_003Ec._002F_002A_002D_003C_002A_002F_0026_005E(_003C_003Ec._003F_002B_002F_005E_003F_0021_0023_0023((IFullName)_003C_003Ec._0024_0029_0025_003E_002A_0024_002D_0025(attribute)), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[553 - 28 - 28 - 34], StringComparison.Ordinal)
																	select attribute).ToList().GetEnumerator())
																{
																	uint num96;
																	int num97;
																	do
																	{
																		int num84;
																		int num85;
																		if (!enumerator2.MoveNext())
																		{
																			num84 = -764208562;
																			num85 = num84;
																		}
																		else
																		{
																			num84 = -551339350;
																			num85 = num84;
																		}
																		while (true)
																		{
																			num2 = num84;
																			num3 = (num4 = (uint)((-(num2 ^ (1551471731 * ((1070208689 - ((-(-1495188905 * -697025867 * -585389751) ^ -(~(1326082766 * -1505494605))) + 2124870537)) * 1216555299))) ^ --1391065644) - -557097407 * ((0x633A7A81 ^ (~(--42275944) ^ -921670812)) + (910297659 * ~(1635927187 * 692731121) - (--1945236030 - ~904243865) * -132174971)) + (-256960992 + ((-333973326 + -(-1480023944 - 1718314855)) ^ (-(740646262 - -42489751) - -1372934575 * (1722866110 + 1508079211)))) - ((-2004511064 ^ 0x4F4A7292) - -782489533 * (-896863515 * 1721792031 - ~1774106493)))) % 5;
																			uint num86 = num3;
																			int num87 = -372035498;
																			_ = 0;
																			for (int num88 = 0; num88 < 2; num88++)
																			{
																				num87 = 458390450 - num87 * -1380042191;
																				num87 = (num87 * 407363495) ^ -1880562659;
																			}
																			if (num86 == (uint)num87)
																			{
																				num84 = -551339350;
																				continue;
																			}
																			uint num89 = num3;
																			int num90 = 1963542600;
																			_ = 0;
																			for (int num91 = 0; num91 < 1; num91++)
																			{
																				num90 += -1963542599;
																			}
																			if (num89 != (uint)num90)
																			{
																				uint num92 = num3;
																				int num93 = -1874596568;
																				_ = 0;
																				for (int num94 = 0; num94 < 1; num94++)
																				{
																					num93 -= -1874596568;
																				}
																				if (num92 != (uint)num93)
																				{
																					break;
																				}
																				_0028_003C_0025_0021_005E_003E_0028_0040(value).Remove(current2);
																				int[] array9 = new int[4];
																				array9[0] = 1544004717;
																				array9[1] = 614370540;
																				array9[2] = 1419035088;
																				array9[3] = 321062982;
																				array9[0] = array9[3] ^ -1985507689;
																				array9[2] = array9[3] ^ -94999952;
																				array9[2] = array9[1] ^ -1568999822;
																				int[] array10 = new int[7];
																				array10[0] = -2096997522;
																				array10[1] = -1471916018;
																				array10[2] = 776782938;
																				array10[3] = 1883043200;
																				array10[4] = -244941262;
																				array10[5] = 2016583418;
																				array10[6] = -137674809;
																				array10[1] = array9[1] ^ 0x48DC00F5;
																				array10[2] = array10[5] ^ 0x6ED5C85F;
																				array10[3] = array10[5] ^ -1864678462;
																				int num95 = array10[1] ^ 0x4EB7AD31;
																				num84 = (int)((num4 * 2112545742) ^ 0xFE40988) ^ num95;
																			}
																			else
																			{
																				current2 = enumerator2.Current;
																				num84 = 1073693412;
																			}
																		}
																		num96 = num3;
																		num97 = -2034917560;
																		_ = 0;
																		for (int num98 = 0; num98 < 2; num98++)
																		{
																			num97 = (num97 * -964072637) ^ 0x4E2E55F3;
																			num97 = (num97 ^ -1980224775) * -116128739;
																		}
																	}
																	while (num96 == (uint)num97);
																	uint num99 = num3;
																	int num100 = -353206702;
																	_ = 0;
																	for (int num101 = 0; num101 < 1; num101++)
																	{
																		num100 ^= -353206703;
																	}
																	if (num99 == (uint)num100)
																	{
																	}
																}
																goto end_IL_269e;
															}
															_0028_003C_0025_0021_005E_003E_0028_0040(value).Add(new CustomAttribute(methodDef));
															int[,] array11 = new int[3, 3]
															{
																{ -1542100759, 910345617, 619489369 },
																{ 1112533755, -847953776, -1073937606 },
																{ 67706497, 2054366552, -1025395130 }
															};
															array11[1, 1] ^= 1565528544;
															array11[0, 2] = array11[0, 0] ^ 0x6EF5B548;
															array11[2, 0] ^= -1510901455;
															array11[1, 2] = array11[2, 2] ^ 0x5195A760;
															int num102 = array11[1, 2] ^ -534062590;
															num50 = (int)((num4 * 1336398402) ^ 0x28F4F560) ^ num102;
														}
														else
														{
															if (methodDef == null)
															{
																goto end_IL_269e;
															}
															int[,] array12 = new int[3, 3];
															array12[0, 0] = -1233953;
															array12[0, 1] = 879780495;
															array12[0, 2] = -1482959838;
															array12[1, 0] = -502056176;
															array12[1, 1] = -327130241;
															array12[1, 2] = -2074989691;
															array12[2, 0] = 1670249731;
															array12[2, 1] = -762868313;
															array12[2, 2] = -500268371;
															array12[0, 0] = array12[1, 0] ^ 0x2EC2C967;
															array12[1, 2] = array12[2, 0] ^ -683488426;
															array12[2, 2] = array12[0, 1] ^ -1958930954;
															int num103 = array12[2, 2] ^ 0x6B3285B1;
															num50 = ((int)num4 * -615423279) ^ -1443433317 ^ num103;
														}
													}
													else
													{
														methodDef = _005E_002F_005E_0024_003D_003F_002A_003E(typeDef2, @_002F_002B_003E_0023_002F_003C_0021(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x4CD ^ 0x56D]));
														int[] array13 = new int[4];
														array13[0] = 716429328;
														array13[1] = -1207109673;
														array13[2] = 637932233;
														array13[3] = 1909770013;
														array13[2] = array13[1] ^ -196312101;
														array13[3] = array13[2] ^ 0x24AE8D90;
														array13[1] ^= -190326280;
														int[] array14 = new int[4];
														array14[0] = -606057851;
														array14[1] = -660065402;
														array14[2] = -739730257;
														array14[3] = -1481484880;
														array14[3] = array13[0] ^ 0x255D35C8;
														array14[1] = array14[2] ^ -394612565;
														array14[0] = array14[1] ^ 0x6B232D62;
														int num104 = array14[3] ^ 0x1B572E0D;
														num50 = (int)((num4 * 1760234455) ^ 0x2CE443B6) ^ num104;
													}
												}
												else
												{
													if (XkQ_003D(__0025_0040__005E_0026_0025_002F(value)))
													{
														goto end_IL_269e;
													}
													int[,] array15 = new int[3, 3];
													array15[0, 0] = -2004771540;
													array15[0, 1] = 1610754156;
													array15[0, 2] = 110858530;
													array15[1, 0] = 715290215;
													array15[1, 1] = 376870529;
													array15[1, 2] = -63714839;
													array15[2, 0] = 666435716;
													array15[2, 1] = -1651594342;
													array15[2, 2] = -250057558;
													array15[0, 0] = array15[1, 0] ^ -686332720;
													array15[2, 2] = array15[0, 0] ^ 0x50E19818;
													array15[1, 0] = array15[1, 1] ^ -834552515;
													array15[0, 2] = array15[1, 1] ^ 0x15F68FF4;
													int num105 = array15[0, 2] ^ 0xAFCA92F;
													num50 = (int)((num4 * 433282010) ^ 0x15AA8BA4) ^ num105;
												}
											}
											else
											{
												if (XkQ_003D(value))
												{
													goto end_IL_269e;
												}
												int[] array16 = new int[6];
												array16[0] = 763283949;
												array16[1] = 822021776;
												array16[2] = -1973953307;
												array16[3] = 534064931;
												array16[4] = -370810516;
												array16[5] = 1042209215;
												array16[3] = array16[5] ^ 0x63619D41;
												array16[5] = array16[0] ^ -1564663884;
												int[] array17 = new int[4] { -1550375281, 1011789111, 235290898, -47606945 };
												int[][] array18 = new int[2][] { array16, array17 };
												array17[0] = array18[0][4] ^ 0x2A6609D1;
												array17[3] = array17[1] ^ 0x7DCF39EB;
												array17[1] = array17[3] ^ 0x65F7546B;
												int num106 = array18[1][0] ^ -679528441;
												num50 = (int)((num4 * 1923612795) ^ 0x43877F7B) ^ num106;
											}
										}
										else
										{
											bool num107 = _005E_0026_002D_002A_005E_002F_002F_0026(current);
											int[] array19 = new int[5];
											array19[0] = -76352954;
											array19[1] = -598528353;
											array19[2] = -1991924066;
											array19[3] = -1760081403;
											array19[4] = -1089631181;
											array19[3] = array19[1] ^ 0x2DF94EB6;
											array19[0] ^= -1979708410;
											int[] array20 = new int[5] { 2019936094, 542927536, -190100290, 1405311933, -2027260529 };
											int[][] array21 = new int[2][] { array19, array20 };
											array20[1] = array21[0][4] ^ 0x1EF65D14;
											array20[0] = array20[2] ^ 0x631DB564;
											array20[3] = array20[4] ^ 0x7D367E9F;
											int num108 = array21[1][1] ^ 0x73708166;
											int[,] array22 = new int[3, 4];
											array22[0, 0] = 1396717520;
											array22[0, 1] = -42850136;
											array22[0, 2] = 239879155;
											array22[0, 3] = -2043593285;
											array22[1, 0] = -1643233290;
											array22[1, 1] = 1522221222;
											array22[1, 2] = -106309319;
											array22[1, 3] = -1900802317;
											array22[2, 0] = 2077065704;
											array22[2, 1] = -1900472649;
											array22[2, 2] = -294523963;
											array22[2, 3] = -870129988;
											array22[1, 0] = array22[0, 3] ^ 0x250EF099;
											array22[0, 2] = array22[0, 3] ^ -109021214;
											array22[0, 1] = array22[0, 2] ^ -1135636797;
											array22[2, 0] = array22[2, 2] ^ 0x7D6A7BD;
											int num109 = array22[2, 0] ^ 0x36A15603;
											int num110 = ((int)num4 * -162120524) ^ 0x43391320;
											num108 ^= num110;
											num109 ^= num110;
											int num111;
											int num112;
											if (num107)
											{
												num111 = num109;
												num112 = num111;
											}
											else
											{
												num111 = num108;
												num112 = num111;
											}
											num50 = num111 ^ num110;
										}
									}
									else
									{
										if (!RyF_003D.TryGetValue(__003F_0029_0023_003C_0023_0023_0023(current), out value))
										{
											goto end_IL_269e;
										}
										int[] array23 = new int[5];
										array23[0] = 654308439;
										array23[1] = 1293651759;
										array23[2] = 320685217;
										array23[3] = -551078466;
										array23[4] = -1935638463;
										array23[3] = array23[4] ^ -1566480953;
										array23[4] = array23[0] ^ 0x82D6327;
										array23[1] ^= 1674376528;
										int[] array24 = new int[6];
										array24[0] = 924838045;
										array24[1] = -977777596;
										array24[2] = -716532793;
										array24[3] = 1217315696;
										array24[4] = -1340427857;
										array24[5] = 29081982;
										array24[0] = array23[0] ^ 0x92EF9BB;
										array24[3] = array24[0] ^ -1680244180;
										array24[4] = array24[2] ^ -1426424524;
										array24[2] = array24[1] ^ 0x7E87030D;
										int num113 = array24[0] ^ 0x6385F7C;
										num50 = (int)((num4 * 1068441804) ^ 0xEE64DADCu) ^ num113;
									}
								}
								continue;
								end_IL_269e:
								break;
							}
						}
					}
					finally
					{
						if (enumerator != null)
						{
							while (true)
							{
								int num114 = -789729112;
								while (true)
								{
									int num2 = num114;
									uint num4;
									num3 = (num4 = (uint)((-(num2 ^ (1551471731 * ((1070208689 - ((-(-1495188905 * -697025867 * -585389751) ^ -(~(1326082766 * -1505494605))) + 2124870537)) * 1216555299))) ^ --1391065644) - -557097407 * ((0x633A7A81 ^ (~(--42275944) ^ -921670812)) + (910297659 * ~(1635927187 * 692731121) - (--1945236030 - ~904243865) * -132174971)) + (-256960992 + ((-333973326 + -(-1480023944 - 1718314855)) ^ (-(740646262 - -42489751) - -1372934575 * (1722866110 + 1508079211)))) - ((-2004511064 ^ 0x4F4A7292) - -782489533 * (-896863515 * 1721792031 - ~1774106493)))) % 3;
									uint num115 = num3;
									int num116 = 2015987584;
									_ = 0;
									for (int num117 = 0; num117 < 2; num117++)
									{
										num116 = -(-num116);
										num116 = 1139489856 - ~num116;
									}
									if (num115 == (uint)num116)
									{
										break;
									}
									uint num118 = num3;
									int num119 = 1;
									_ = 0;
									for (int num120 = 0; num120 < 2; num120++)
									{
										num119 = ~num119 + -1583517645;
										num119 = num119 - --1204028009 - -983568885;
									}
									if (num118 != (uint)num119)
									{
										uint num121 = num3;
										int num122 = 0;
										_ = 0;
										for (int num123 = 0; num123 < 1; num123++)
										{
											num122 *= -166979783;
										}
										if (num121 == (uint)num122)
										{
										}
										goto end_IL_2dea;
									}
									_003D_002D_0024_003F_003D_003F_003C_0021((IDisposable)enumerator);
									int[,] array25 = new int[4, 3];
									array25[0, 0] = -128015633;
									array25[0, 1] = 129046913;
									array25[0, 2] = -745233817;
									array25[1, 0] = -200352605;
									array25[1, 1] = -337328500;
									array25[1, 2] = 1178342605;
									array25[2, 0] = 1902916580;
									array25[2, 1] = -577989975;
									array25[2, 2] = -244093014;
									array25[3, 0] = -11013531;
									array25[3, 1] = 1175552372;
									array25[3, 2] = 31872350;
									array25[2, 0] = array25[2, 2] ^ 0x115C4FBF;
									array25[0, 1] = array25[2, 1] ^ -421803483;
									array25[1, 0] = array25[1, 2] ^ 0x6CBCC8FC;
									array25[1, 2] = array25[0, 0] ^ -410348907;
									int num124 = array25[1, 2] ^ -763542840;
									num114 = (int)((num4 * 618927992) ^ 0xB8DE8180u) ^ num124;
								}
								continue;
								end_IL_2dea:
								break;
							}
						}
					}
					MemoryStream memoryStream = new MemoryStream();
					try
					{
						ModuleWriterOptions moduleWriterOptions = new ModuleWriterOptions(BAB_003D);
						_002D_003C_005E_003C_0024_0040_0024_002B((ModuleWriterOptionsBase)moduleWriterOptions, (ILogger)DummyLogger.NoThrowInstance);
						_005E_0024_0040_002B_0024_003C_0040_0024((ModuleWriterOptionsBase)moduleWriterOptions, (ILogger)DummyLogger.NoThrowInstance);
						ModuleWriterOptions moduleWriterOptions2 = moduleWriterOptions;
						while (true)
						{
							int num125 = 543364249;
							while (true)
							{
								int num2 = num125;
								uint num4;
								num3 = (num4 = (uint)((-(num2 ^ (1551471731 * ((1070208689 - ((-(-1495188905 * -697025867 * -585389751) ^ -(~(1326082766 * -1505494605))) + 2124870537)) * 1216555299))) ^ --1391065644) - -557097407 * ((0x633A7A81 ^ (~(--42275944) ^ -921670812)) + (910297659 * ~(1635927187 * 692731121) - (--1945236030 - ~904243865) * -132174971)) + (-256960992 + ((-333973326 + -(-1480023944 - 1718314855)) ^ (-(740646262 - -42489751) - -1372934575 * (1722866110 + 1508079211)))) - ((-2004511064 ^ 0x4F4A7292) - -782489533 * (-896863515 * 1721792031 - ~1774106493)))) % 5;
								uint num126 = num3;
								int num127 = -555898259;
								_ = 0;
								for (int num128 = 0; num128 < 2; num128++)
								{
									num127 = ~num127 - -2074904870;
									num127 = ~(num127 - 205370353);
								}
								if (num126 == (uint)num127)
								{
									break;
								}
								uint num129 = num3;
								int num130 = 403641289;
								_ = 0;
								for (int num131 = 0; num131 < 2; num131++)
								{
									num130 = (num130 - (0x432CADED ^ -1727114897)) ^ -202087357;
									num130 = 1387926446 - (-187760432 - num130);
								}
								if (num129 != (uint)num130)
								{
									uint num132 = num3;
									int num133 = 944253361;
									_ = 0;
									for (int num134 = 0; num134 < 1; num134++)
									{
										num133 -= 944253359;
									}
									if (num132 != (uint)num133)
									{
										uint num135 = num3;
										int num136 = -399480764;
										_ = 0;
										for (int num137 = 0; num137 < 2; num137++)
										{
											num136 = -(num136 * -399253055);
											num136 = num136 - -359116107 + 1743403476;
										}
										if (num135 != (uint)num136)
										{
											uint num138 = num3;
											int num139 = 0;
											_ = 0;
											for (int num140 = 0; num140 < 2; num140++)
											{
												num139 = num139 - 190408375 * 1023760481 + -641570642;
												num139 = ~num139;
											}
											if (num138 == (uint)num139)
											{
											}
											goto end_IL_327c;
										}
										result = _003F_0021_002F__0040__003C_0024(memoryStream);
										int[,] array26 = new int[4, 3];
										array26[0, 0] = -984874400;
										array26[0, 1] = -1641265192;
										array26[0, 2] = 178899241;
										array26[1, 0] = -897397278;
										array26[1, 1] = 262252549;
										array26[1, 2] = -462774036;
										array26[2, 0] = -2063469717;
										array26[2, 1] = -557472580;
										array26[2, 2] = -2025428862;
										array26[3, 0] = -1662691963;
										array26[3, 1] = 1204964332;
										array26[3, 2] = 715820091;
										array26[3, 2] = array26[0, 2] ^ 0xE93D12F;
										array26[3, 1] = array26[2, 0] ^ 0x7C75C471;
										array26[1, 0] = array26[1, 2] ^ 0x62EE0517;
										int num141 = array26[1, 0] ^ -2122306286;
										num125 = (int)((num4 * 1387023939) ^ 0x8B841A59u) ^ num141;
									}
									else
									{
										_0024_003F_0024_0025_002D_002F_0040_003C((ModuleDef)BAB_003D, (Stream)memoryStream, moduleWriterOptions2);
										int[] array27 = new int[4];
										array27[0] = 1530681470;
										array27[1] = 122553174;
										array27[2] = 821329460;
										array27[3] = -258537718;
										array27[3] = array27[2] ^ -192456484;
										array27[1] ^= -943966544;
										array27[1] ^= 1575596252;
										int[] array28 = new int[6];
										array28[0] = -1097389448;
										array28[1] = 1696995056;
										array28[2] = -1920257619;
										array28[3] = 214526941;
										array28[4] = 1125045776;
										array28[5] = 895592368;
										array28[4] = array27[2] ^ -221344654;
										array28[1] = array28[4] ^ -140709914;
										array28[1] = array28[2] ^ 0x1E62B26C;
										int num142 = array28[4] ^ 0x126BF40B;
										num125 = (int)((num4 * 1280481463) ^ 0x954FF66Eu) ^ num142;
									}
								}
								else
								{
									_002B_002B_003F_003F_0024_0024_0029_0040((ModuleWriterOptionsBase)moduleWriterOptions2).Flags = MetadataFlags.PreserveAll;
									int[] array29 = new int[5] { 1786407192, 1499703687, 731038854, -1613097747, -639136390 };
									array29[4] ^= 50081370;
									array29[3] = array29[1] ^ 0x8234545;
									array29[4] = array29[2] ^ -2075231955;
									int[] array30 = new int[5] { 1096537412, -141190741, -198406928, -1083697737, 239668261 };
									int[][] array31 = new int[2][] { array29, array30 };
									array30[3] = array31[0][2] ^ 0xA658C17;
									array30[4] ^= 491777580;
									array30[1] = array30[3] ^ 0x3944783C;
									int num143 = array31[1][3] ^ 0x36D5E8E3;
									num125 = (int)((num4 * 1033872508) ^ 0xCD641004u) ^ num143;
								}
							}
							continue;
							end_IL_327c:
							break;
						}
					}
					finally
					{
						if (memoryStream != null)
						{
							while (true)
							{
								int num144 = 463797151;
								while (true)
								{
									int num2 = num144;
									uint num4;
									num3 = (num4 = (uint)((-(num2 ^ (1551471731 * ((1070208689 - ((-(-1495188905 * -697025867 * -585389751) ^ -(~(1326082766 * -1505494605))) + 2124870537)) * 1216555299))) ^ --1391065644) - -557097407 * ((0x633A7A81 ^ (~(--42275944) ^ -921670812)) + (910297659 * ~(1635927187 * 692731121) - (--1945236030 - ~904243865) * -132174971)) + (-256960992 + ((-333973326 + -(-1480023944 - 1718314855)) ^ (-(740646262 - -42489751) - -1372934575 * (1722866110 + 1508079211)))) - ((-2004511064 ^ 0x4F4A7292) - -782489533 * (-896863515 * 1721792031 - ~1774106493)))) % 3;
									uint num145 = num3;
									int num146 = -247067505;
									_ = 0;
									for (int num147 = 0; num147 < 1; num147++)
									{
										num146 -= -247067505;
									}
									if (num145 == (uint)num146)
									{
										break;
									}
									uint num148 = num3;
									int num149 = -1071641591;
									_ = 0;
									for (int num150 = 0; num150 < 2; num150++)
									{
										num149 = ~(num149 + (0x55A9C736 ^ -61014672));
										num149 ^= -185067900;
									}
									if (num148 != (uint)num149)
									{
										uint num151 = num3;
										int num152 = 1415925912;
										_ = 0;
										for (int num153 = 0; num153 < 1; num153++)
										{
											num152 -= 1415925910;
										}
										if (num151 == (uint)num152)
										{
										}
										goto end_IL_3afe;
									}
									_003D_002D_0024_003F_003D_003F_003C_0021((IDisposable)memoryStream);
									int[] array32 = new int[4];
									array32[0] = -473011443;
									array32[1] = 420781641;
									array32[2] = -1898883299;
									array32[3] = 1384914429;
									array32[0] = array32[2] ^ -1070444014;
									array32[0] = array32[1] ^ -801172664;
									array32[2] = array32[3] ^ 0x6DBBB618;
									int[] array33 = new int[7] { -1040370776, 1088127176, -2022724211, -1685543129, -2006252899, 501522082, -455491528 };
									int[][] array34 = new int[2][] { array32, array33 };
									array33[5] = array34[0][3] ^ 0x307BE836;
									array33[0] = array33[1] ^ 0x2B6DA1A7;
									array33[6] = array33[1] ^ -1718645992;
									array33[3] = array33[2] ^ 0x45B71E28;
									int num154 = array34[1][5] ^ 0x4E62513B;
									num144 = (int)((num4 * 1579034944) ^ 0x7E08A640) ^ num154;
								}
								continue;
								end_IL_3afe:
								break;
							}
						}
					}
					return result;
				}
				throw new InvalidOperationException(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(395 + sizeof(int)) ^ sizeof(Guid)]);
				continue;
				end_IL_000e:
				break;
			}
		}
		throw new InvalidOperationException(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-562 + 148)]);
	}

	private static string VCT_003D(MethodDef Zna_003D)
	{
		string value = _003D_0040_0029_003D_0024_002D_002F_0029(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x624 ^ 0x785], from parameter in _003C_0026_003D_003D_003C_003F_003F_003C(Zna_003D)
			where !_003C_003Ec._005E_003D_005E_002A_0024_003C_0024_003C(parameter)
			select _003C_003Ec._0024_003E_003E_0025_002A_0024_0026_002B(idi_003D(_003C_003Ec._0021_0029_0040__0025_005E_0024_002B(parameter)), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x1EDB ^ 0x1F0B], _003C_003Ec._005E_0025_0021_003E_0024_0021_002F_0025(parameter)));
		DefaultInterpolatedStringHandler defaultInterpolatedStringHandler = default(DefaultInterpolatedStringHandler);
		while (true)
		{
			int num = -797984470;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~((num2 - ((-((-1013431799 - 462305739 - -1230824782) * 1490581113) + (349527689 * ~(-96580716 ^ -1470550743) * -2072417613 - (((0x7FF9F358 ^ -2101053730) - (448692975 + -813108887 - -1608672899)) ^ 0x1612D62) * -1845249773)) ^ ~(-(~((0x51AED401 ^ -943644703) * 1652883033))) ^ (2129103079 * -(-(-(~(--1101094648)) ^ (-1890128489 ^ -(-129031128 ^ -1862054582))) ^ 0x60179FB3)))) * 611889587 * 960015741 - -113201005))) % 7;
				int num5 = 1146328786;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~(num5 - -68861317);
					num5 = -(num5 - (-2080956736 - 708552623));
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -6;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 = -num7;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -40161853;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = -820551333 - ~num9;
						num9 = (num9 * -976084409) ^ -418051390;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 1106474657;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 += -1106474656;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -2128920902;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 *= 1421126901;
							}
							if (num3 != (uint)num13)
							{
								int num15 = -392443453;
								_ = 0;
								for (int num16 = 0; num16 < 1; num16++)
								{
									num15 *= -589944169;
								}
								if (num3 != (uint)num15)
								{
									int num17 = -6288422;
									_ = 0;
									for (int num18 = 0; num18 < 2; num18++)
									{
										num17 = (num17 - 1428565117) * -917440615;
										num17 = -num17 * 720546515;
									}
									if (num3 != (uint)num17)
									{
									}
									return defaultInterpolatedStringHandler.ToStringAndClear();
								}
								defaultInterpolatedStringHandler.AppendFormatted(idi_003D(_005E_0025_003E_0026_0023_0024_0024_0028(Zna_003D)));
								int[] array = new int[6];
								array[0] = 1485922659;
								array[1] = -1722225907;
								array[2] = 250975142;
								array[3] = -1679592512;
								array[4] = 2032369609;
								array[5] = 769950550;
								array[2] = array[5] ^ -152391360;
								array[0] = array[5] ^ -1239372287;
								array[2] ^= -1442533017;
								int[] array2 = new int[5];
								array2[0] = 1331563536;
								array2[1] = -1081692998;
								array2[2] = 1894953037;
								array2[3] = -1581197728;
								array2[4] = 1000412257;
								array2[1] = array[3] ^ -821119315;
								array2[2] ^= 1078916680;
								array2[4] = array2[0] ^ 0x3C8BD004;
								array2[0] = array2[4] ^ 0x471263CE;
								int num19 = array2[1] ^ -1751033167;
								num = ((int)num4 * -218878881) ^ -1537574318 ^ num19;
							}
							else
							{
								defaultInterpolatedStringHandler.AppendLiteral(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[501 - 40 - 18 - 24]);
								int[,] array3 = new int[3, 3];
								array3[0, 0] = 1543029638;
								array3[0, 1] = -1198367638;
								array3[0, 2] = 1130641593;
								array3[1, 0] = -1432713083;
								array3[1, 1] = -24280713;
								array3[1, 2] = -754655658;
								array3[2, 0] = 126156677;
								array3[2, 1] = 1102807243;
								array3[2, 2] = 1480518308;
								array3[1, 2] = array3[2, 1] ^ -904778630;
								array3[0, 2] = array3[2, 0] ^ -759241774;
								array3[0, 2] = array3[0, 0] ^ 0x2AADEF71;
								int num20 = array3[0, 2] ^ -2014395791;
								num = (int)((num4 * 1434674605) ^ 0x22C572B) ^ num20;
							}
						}
						else
						{
							defaultInterpolatedStringHandler.AppendLiteral(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xBFD8 ^ 0xBE7A]);
							defaultInterpolatedStringHandler.AppendFormatted(value);
							int[] array4 = new int[4];
							array4[0] = 1725012973;
							array4[1] = 185168923;
							array4[2] = 714050696;
							array4[3] = -1963410983;
							array4[0] = array4[3] ^ -655452135;
							array4[2] ^= -1158689203;
							array4[3] ^= 1386788477;
							int[] array5 = new int[6] { -749903182, 1241526240, -782853624, -156281482, -51479851, -1372152677 };
							int[][] array6 = new int[2][] { array4, array5 };
							array5[4] = array6[0][1] ^ -1000214147;
							array5[2] = array5[1] ^ 0x3D57ABD3;
							array5[5] = array5[1] ^ 0x77D64CB9;
							array5[3] = array5[2] ^ 0x732F3CF5;
							int num21 = array6[1][4] ^ 0x52521CD1;
							num = ((int)num4 * -1667410793) ^ -1321747126 ^ num21;
						}
					}
					else
					{
						defaultInterpolatedStringHandler.AppendFormatted(_0021_005E_005E__005E_002A_0028_005E(Zna_003D));
						int[,] array7 = new int[4, 3];
						array7[0, 0] = 611201981;
						array7[0, 1] = -1594718107;
						array7[0, 2] = -910227472;
						array7[1, 0] = -1349876965;
						array7[1, 1] = -125658949;
						array7[1, 2] = 442959819;
						array7[2, 0] = -280173052;
						array7[2, 1] = 1658739930;
						array7[2, 2] = -1206534820;
						array7[3, 0] = 106574179;
						array7[3, 1] = 509526573;
						array7[3, 2] = -201700541;
						array7[1, 0] = array7[3, 0] ^ -1088215891;
						array7[3, 0] = array7[1, 1] ^ -1729561050;
						array7[0, 2] = array7[1, 1] ^ -393583301;
						int num22 = array7[0, 2] ^ -1234966498;
						num = ((int)num4 * -948672059) ^ -1933838850 ^ num22;
					}
				}
				else
				{
					defaultInterpolatedStringHandler = new DefaultInterpolatedStringHandler(5, 3);
					int[] array8 = new int[5];
					array8[0] = -2110251993;
					array8[1] = 394624456;
					array8[2] = -885790507;
					array8[3] = 563061590;
					array8[4] = 421091333;
					array8[4] = array8[3] ^ 0x1C6FC52C;
					array8[3] = array8[1] ^ 0x8030E0B;
					int[] array9 = new int[7];
					array9[0] = -162956695;
					array9[1] = -432019686;
					array9[2] = 98082006;
					array9[3] = 1276226661;
					array9[4] = 1175137372;
					array9[5] = -1166664064;
					array9[6] = 1724474482;
					array9[5] = array8[2] ^ -1875084774;
					array9[6] = array9[2] ^ 0x688E0C0C;
					array9[6] = array9[4] ^ 0x6D9EE5FA;
					array9[6] = array9[2] ^ -277244331;
					int num23 = array9[5] ^ -1051589391;
					num = (int)((num4 * 647887896) ^ 0x6F00FEB0) ^ num23;
				}
			}
		}
	}

	private static MethodItem wpa_003D(MethodItem xLU_003D)
	{
		MethodItem methodItem = new MethodItem();
		_002F_003D_0028__0024_003E_003D_0028(methodItem, __003F_0029_0023_003C_0023_0023_0023(xLU_003D));
		_003E_0023_0026_0025_0028_0029_0040_003D(methodItem, _005E_002A_003C_0024_003F__0023_0021(xLU_003D));
		__0040_0029_005E_0040_002D_0025_005E(methodItem, _002F_002D_0040_003F__003E_002A_0024(xLU_003D));
		_0021_005E__0024_0025_003E_0040_002A(methodItem, _0021_005E___002A_0028_003E_0025(xLU_003D));
		_002A_0023_003C_003F_0028_0029_0021_(methodItem, _005E_0026_002D_002A_005E_002F_002F_0026(xLU_003D));
		_002F_002B_0024_002F_002F_0029_003F_0024(methodItem, _0023_0028_005E_003F_003E_002A_0040_003C(xLU_003D));
		return methodItem;
	}

	private static string CpM_003D(long ROG_003D)
	{
		if (ROG_003D < 1024)
		{
			goto IL_000f;
		}
		goto IL_0ba5;
		IL_000f:
		int num = -713138115;
		goto IL_0014;
		IL_0014:
		DefaultInterpolatedStringHandler defaultInterpolatedStringHandler = default(DefaultInterpolatedStringHandler);
		DefaultInterpolatedStringHandler defaultInterpolatedStringHandler2 = default(DefaultInterpolatedStringHandler);
		DefaultInterpolatedStringHandler defaultInterpolatedStringHandler3 = default(DefaultInterpolatedStringHandler);
		DefaultInterpolatedStringHandler defaultInterpolatedStringHandler4 = default(DefaultInterpolatedStringHandler);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)(~(-(~(~(~(-num2) - 1691187535 * ~(1225391608 - (-240059732 + 403544224) * -2089300529 * 1947835637 + -1892380854) - -((0x75F80212 ^ -118588022) - ~(0x73A88A88 ^ 0x6084286F))))) - (-1863383826 ^ 0x4FB37DA1)) ^ -376439596)) % 19;
			int num5 = 570443934;
			_ = 0;
			for (int num6 = 0; num6 < 1; num6++)
			{
				num5 *= 965564429;
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = -713374192;
			_ = 0;
			for (int num8 = 0; num8 < 1; num8++)
			{
				num7 = -713374178 - num7;
			}
			if (num3 != (uint)num7)
			{
				int num9 = 1267804288;
				_ = 0;
				for (int num10 = 0; num10 < 2; num10++)
				{
					num9 = ~num9 * -993351795;
					num9 = ~num9 * -420395841;
				}
				if (num3 != (uint)num9)
				{
					int num11 = 5;
					_ = 0;
					for (int num12 = 0; num12 < 2; num12++)
					{
						num11 = ~num11;
						num11 = -(num11 ^ -790713876);
					}
					if (num3 != (uint)num11)
					{
						int num13 = -581396751;
						_ = 0;
						for (int num14 = 0; num14 < 2; num14++)
						{
							num13 = -(num13 * -526910211);
							num13 = -num13 + -1589226956;
						}
						if (num3 != (uint)num13)
						{
							int num15 = -1029154667;
							_ = 0;
							for (int num16 = 0; num16 < 2; num16++)
							{
								num15 = ~num15 - -1361066240;
								num15 = ~num15 - 271840073;
							}
							if (num3 != (uint)num15)
							{
								int num17 = -9;
								_ = 0;
								for (int num18 = 0; num18 < 1; num18++)
								{
									num17 = -num17;
								}
								if (num3 != (uint)num17)
								{
									int num19 = -13;
									_ = 0;
									for (int num20 = 0; num20 < 1; num20++)
									{
										num19 = ~num19;
									}
									if (num3 != (uint)num19)
									{
										int num21 = -16;
										_ = 0;
										for (int num22 = 0; num22 < 1; num22++)
										{
											num21 = ~num21;
										}
										if (num3 != (uint)num21)
										{
											int num23 = 254583813;
											_ = 0;
											for (int num24 = 0; num24 < 2; num24++)
											{
												num23 = num23 * -388608029 * -1511678005;
												num23 = -(-num23);
											}
											if (num3 == (uint)num23)
											{
												return defaultInterpolatedStringHandler.ToStringAndClear();
											}
											int num25 = -333034856;
											_ = 0;
											for (int num26 = 0; num26 < 1; num26++)
											{
												num25 -= -333034864;
											}
											int num48;
											if (num3 != (uint)num25)
											{
												int num27 = 424253300;
												_ = 0;
												for (int num28 = 0; num28 < 1; num28++)
												{
													num27 += -424253300;
												}
												if (num3 != (uint)num27)
												{
													int num29 = 1529606020;
													_ = 0;
													for (int num30 = 0; num30 < 2; num30++)
													{
														num29 = -num29 * 1664381633;
														num29 = -num29 * -315866321;
													}
													if (num3 != (uint)num29)
													{
														int num31 = 1366738186;
														_ = 0;
														for (int num32 = 0; num32 < 1; num32++)
														{
															num31 -= 1366738184;
														}
														if (num3 != (uint)num31)
														{
															int num33 = -1915611911;
															_ = 0;
															for (int num34 = 0; num34 < 2; num34++)
															{
																num33 *= 1916824567;
																num33 = ~(-560147162 - num33);
															}
															if (num3 == (uint)num33)
															{
																return defaultInterpolatedStringHandler2.ToStringAndClear();
															}
															int num35 = -1737266805;
															_ = 0;
															for (int num36 = 0; num36 < 2; num36++)
															{
																num35 = -713134985 * 1567928907 - num35;
																num35 = -(num35 - (0xA5B9487 ^ -2105719654));
															}
															if (num3 != (uint)num35)
															{
																int num37 = -469772231;
																_ = 0;
																for (int num38 = 0; num38 < 2; num38++)
																{
																	num37 = (num37 ^ 0x6CEFCBE4) - 1977591290;
																	num37 = -(-num37);
																}
																if (num3 != (uint)num37)
																{
																	int num39 = 1977567370;
																	_ = 0;
																	for (int num40 = 0; num40 < 2; num40++)
																	{
																		num39 = (~588228822 - num39) * 1667252297;
																		num39 = (~-986085520 - num39) * 1025752611;
																	}
																	if (num3 != (uint)num39)
																	{
																		int num41 = -1055920114;
																		_ = 0;
																		for (int num42 = 0; num42 < 2; num42++)
																		{
																			num41 = ~(-num41);
																			num41 = (num41 ^ 0x5E3074F0) - 850893921;
																		}
																		if (num3 != (uint)num41)
																		{
																		}
																		return defaultInterpolatedStringHandler3.ToStringAndClear();
																	}
																	defaultInterpolatedStringHandler3.AppendLiteral(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x17B27 ^ 0x17A8F))]);
																	int[] array = new int[4];
																	array[0] = 647140283;
																	array[1] = -2130558482;
																	array[2] = -1358781521;
																	array[3] = -1695781526;
																	array[1] = array[2] ^ 0x1B07CE2A;
																	array[2] = array[1] ^ 0x1E8AA54B;
																	int[] array2 = new int[6];
																	array2[0] = -1313808313;
																	array2[1] = 214357186;
																	array2[2] = 377790186;
																	array2[3] = 1503089825;
																	array2[4] = 1792288345;
																	array2[5] = 1442600180;
																	array2[0] = array[0] ^ -1467919175;
																	array2[1] = array2[2] ^ -319820391;
																	array2[2] = array2[1] ^ 0x216211FE;
																	array2[2] = array2[1] ^ 0x6952A844;
																	int num43 = array2[0] ^ -1440248329;
																	num = ((int)num4 * -754849875) ^ -456395250 ^ num43;
																}
																else
																{
																	defaultInterpolatedStringHandler3.AppendFormatted((double)ROG_003D / 1073741824.0, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x11C6 ^ 0x1063]);
																	int[,] array3 = new int[4, 3];
																	array3[0, 0] = 968699746;
																	array3[0, 1] = -91668065;
																	array3[0, 2] = 697957814;
																	array3[1, 0] = -1816311705;
																	array3[1, 1] = 1578718701;
																	array3[1, 2] = -20792892;
																	array3[2, 0] = 1936411045;
																	array3[2, 1] = 429894995;
																	array3[2, 2] = 1357620891;
																	array3[3, 0] = -833814614;
																	array3[3, 1] = -131908070;
																	array3[3, 2] = 2131097959;
																	array3[2, 0] = array3[2, 1] ^ -2001285162;
																	array3[0, 2] = array3[2, 1] ^ 0x224CC0F5;
																	array3[2, 2] = array3[1, 2] ^ 0x39C98E07;
																	array3[1, 0] = array3[1, 1] ^ -612793511;
																	int num44 = array3[1, 0] ^ 0x72DB0820;
																	num = (int)((num4 * 2041388753) ^ 0x58FE6232) ^ num44;
																}
															}
															else
															{
																defaultInterpolatedStringHandler3 = new DefaultInterpolatedStringHandler(3, 1);
																num = -568333048;
															}
														}
														else
														{
															defaultInterpolatedStringHandler2.AppendLiteral(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[1851 - 1459 + 31]);
															int[,] array4 = new int[4, 3];
															array4[0, 0] = -1135561572;
															array4[0, 1] = -724698781;
															array4[0, 2] = 865767765;
															array4[1, 0] = 1524100548;
															array4[1, 1] = 47410653;
															array4[1, 2] = -172944100;
															array4[2, 0] = 116024438;
															array4[2, 1] = -1330515119;
															array4[2, 2] = 2069204295;
															array4[3, 0] = 545305388;
															array4[3, 1] = 1978954356;
															array4[3, 2] = -1869523380;
															array4[1, 2] = array4[2, 1] ^ 0x2BC2488;
															array4[2, 1] = array4[3, 2] ^ 0x42ADE62E;
															array4[2, 2] = array4[0, 2] ^ -1346298822;
															array4[1, 0] = array4[1, 1] ^ 0x20B60BDC;
															int num45 = array4[1, 0] ^ -966190367;
															num = (int)((num4 * 1401833285) ^ 0xE1BB0C43u) ^ num45;
														}
													}
													else
													{
														defaultInterpolatedStringHandler2.AppendFormatted((double)ROG_003D / 1048576.0, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-765 + 343)]);
														int[] array5 = new int[6];
														array5[0] = -1159824888;
														array5[1] = 1055511368;
														array5[2] = -1013571134;
														array5[3] = 1088209821;
														array5[4] = 2052037639;
														array5[5] = -1384868541;
														array5[0] = array5[4] ^ -1627786905;
														array5[4] = array5[1] ^ -803117914;
														array5[4] = array5[0] ^ 0x31322C2A;
														int[] array6 = new int[5] { -1295824164, -1456920587, -1878544101, -359517630, -2057110897 };
														int[][] array7 = new int[2][] { array5, array6 };
														array6[3] = array7[0][3] ^ 0x6513B855;
														array6[0] = array6[2] ^ -664275314;
														array6[4] = array6[2] ^ 0xB7F3877;
														int num46 = array7[1][3] ^ 0x507153D;
														num = ((int)num4 * -344492440) ^ -2005467680 ^ num46;
													}
												}
												else
												{
													defaultInterpolatedStringHandler2 = new DefaultInterpolatedStringHandler(3, 1);
													int[,] array8 = new int[4, 4];
													array8[0, 0] = 204593601;
													array8[0, 1] = 837277717;
													array8[0, 2] = 982862252;
													array8[0, 3] = -1923120654;
													array8[1, 0] = -2139987332;
													array8[1, 1] = -709789237;
													array8[1, 2] = -859699561;
													array8[1, 3] = -558216709;
													array8[2, 0] = -501579545;
													array8[2, 1] = -1858419247;
													array8[2, 2] = 1374278187;
													array8[2, 3] = 754356691;
													array8[3, 0] = -30445459;
													array8[3, 1] = -423524770;
													array8[3, 2] = 762387926;
													array8[3, 3] = 316983723;
													array8[3, 0] = array8[1, 3] ^ 0x135E2720;
													array8[2, 1] = array8[1, 3] ^ 0x317FA4FB;
													array8[0, 2] = array8[0, 3] ^ -1889657699;
													array8[0, 2] = array8[1, 0] ^ 0x370C5620;
													int num47 = array8[0, 2] ^ 0x7BD55066;
													num = ((int)num4 * -1960785146) ^ -958107898 ^ num47;
												}
											}
											else if (ROG_003D < 1073741824)
											{
												num = -525384553;
												num48 = num;
											}
											else
											{
												num = 340977024;
												num48 = num;
											}
										}
										else
										{
											defaultInterpolatedStringHandler.AppendLiteral(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4035 - 3707 + 94]);
											int[] array9 = new int[4] { -1739599392, -2024045996, -1220569592, -712046012 };
											array9[1] ^= 712983421;
											array9[3] = array9[1] ^ -242315593;
											array9[1] ^= -232765101;
											int[] array10 = new int[6];
											array10[0] = -1701376459;
											array10[1] = 1405595449;
											array10[2] = -83722910;
											array10[3] = 1391850322;
											array10[4] = 631915340;
											array10[5] = -2071875907;
											array10[4] = array9[2] ^ 0x182478C6;
											array10[2] = array10[4] ^ 0x2018599C;
											array10[3] = array10[4] ^ -1227838294;
											array10[0] = array10[2] ^ 0x16AA6982;
											int num49 = array10[4] ^ 0x430A603A;
											num = (int)((num4 * 1801797745) ^ 0xC1062C35u) ^ num49;
										}
									}
									else
									{
										defaultInterpolatedStringHandler.AppendFormatted((double)ROG_003D / 1024.0, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[529 - 45 - 39 - 24]);
										int[] array11 = new int[6];
										array11[0] = -444526026;
										array11[1] = 432091158;
										array11[2] = -1113359623;
										array11[3] = 1600777709;
										array11[4] = 1396561814;
										array11[5] = 1356382487;
										array11[3] = array11[2] ^ 0x225389A8;
										array11[2] = array11[0] ^ -1017642035;
										int[] array12 = new int[4];
										array12[0] = -1579439496;
										array12[1] = -1828218054;
										array12[2] = -448854947;
										array12[3] = 1207428021;
										array12[1] = array11[1] ^ 0x3FB307EC;
										array12[0] = array12[2] ^ -1131500985;
										array12[3] = array12[2] ^ -972194063;
										array12[3] = array12[2] ^ 0x79B85639;
										int num50 = array12[1] ^ -1786628247;
										num = (int)((num4 * 1877268468) ^ 0xFDA13664u) ^ num50;
									}
								}
								else
								{
									defaultInterpolatedStringHandler = new DefaultInterpolatedStringHandler(3, 1);
									int[,] array13 = new int[4, 3]
									{
										{ 1840992022, 751568624, 1642226799 },
										{ -133801275, 931033083, -1384264169 },
										{ -1285068264, 2086052209, 427636160 },
										{ -1539822017, 854279389, 1657440978 }
									};
									array13[1, 0] ^= 1827491509;
									array13[3, 1] = array13[2, 1] ^ -714605175;
									array13[3, 0] = array13[1, 0] ^ 0x34D9AB28;
									array13[1, 2] = array13[2, 0] ^ -1995513124;
									int num51 = array13[1, 2] ^ 0x18EA071F;
									num = ((int)num4 * -552575467) ^ -212386307 ^ num51;
								}
								continue;
							}
							goto IL_0ba5;
						}
						return defaultInterpolatedStringHandler4.ToStringAndClear();
					}
					defaultInterpolatedStringHandler4.AppendLiteral(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x10B9A ^ 0x10A3E))]);
					int[] array14 = new int[6];
					array14[0] = 407067027;
					array14[1] = 1676974035;
					array14[2] = 2041822483;
					array14[3] = 1246078967;
					array14[4] = 739256276;
					array14[5] = -759948766;
					array14[0] = array14[1] ^ -1008493011;
					array14[3] ^= 115645617;
					array14[3] = array14[2] ^ -2131059448;
					int[] array15 = new int[7] { -753364450, 1822869199, -566232504, -1194179085, 922693607, 1061795205, -1143183626 };
					int[][] array16 = new int[2][] { array14, array15 };
					array15[0] = array16[0][2] ^ -362337545;
					array15[3] = array15[2] ^ -846022737;
					array15[3] = array15[0] ^ 0x28E3BA00;
					array15[4] = array15[1] ^ -1040967858;
					int num52 = array16[1][0] ^ -1918321413;
					num = (int)((num4 * 1021110087) ^ 0x25AE8168) ^ num52;
					continue;
				}
				defaultInterpolatedStringHandler4.AppendFormatted(ROG_003D);
				int[] array17 = new int[5];
				array17[0] = 1969568300;
				array17[1] = -211337489;
				array17[2] = -1439737644;
				array17[3] = -1519718120;
				array17[4] = -86683457;
				array17[4] = array17[3] ^ -1352383621;
				array17[4] = array17[2] ^ 0x502A11E0;
				array17[0] = array17[2] ^ 0x4443F756;
				int[] array18 = new int[6] { -525054940, 1994551334, 1674584590, 237284192, 1073362607, -2004335762 };
				int[][] array19 = new int[2][] { array17, array18 };
				array18[2] = array19[0][2] ^ -40408395;
				array18[4] ^= 976171842;
				array18[5] = array18[4] ^ -1615460639;
				array18[5] ^= -1317031333;
				int num53 = array19[1][2] ^ 0x442C272F;
				num = (int)((num4 * 101651663) ^ 0x87E5C245u) ^ num53;
				continue;
			}
			defaultInterpolatedStringHandler4 = new DefaultInterpolatedStringHandler(2, 1);
			int[,] array20 = new int[4, 3];
			array20[0, 0] = 1325274239;
			array20[0, 1] = 476743262;
			array20[0, 2] = 62858504;
			array20[1, 0] = 590915167;
			array20[1, 1] = -748034625;
			array20[1, 2] = 1340852117;
			array20[2, 0] = 1582451880;
			array20[2, 1] = 1256471218;
			array20[2, 2] = 158601217;
			array20[3, 0] = -1813787273;
			array20[3, 1] = 1168706723;
			array20[3, 2] = -1915915198;
			array20[1, 1] = array20[0, 1] ^ 0x13C62143;
			array20[2, 2] = array20[3, 2] ^ -1126873566;
			array20[3, 0] ^= -1921187466;
			array20[3, 2] = array20[0, 1] ^ -2092535603;
			int num54 = array20[3, 2] ^ -1093806894;
			num = ((int)num4 * -1878675554) ^ 0x23F0F902 ^ num54;
		}
		goto IL_000f;
		IL_0ba5:
		int num55;
		if (ROG_003D < 1048576)
		{
			num = -1129297825;
			num55 = num;
		}
		else
		{
			num = -861212834;
			num55 = num;
		}
		goto IL_0014;
	}

	private unsafe static string idi_003D(TypeSig? xUT_003D)
	{
		if (xUT_003D == null)
		{
			goto IL_0009;
		}
		goto IL_aa00;
		IL_0009:
		int num = -1387612610;
		goto IL_000e;
		IL_000e:
		string result = default(string);
		string text = default(string);
		char c = default(char);
		int num349 = default(int);
		SZArraySig sZArraySig = default(SZArraySig);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)(-(~num2 ^ ~(0x313FB512 ^ (1598323395 * (0x5B09E3D9 ^ 0x791C891) - (-1686336961 * (393207487 * -63161462 - (-868784090 + -1321009594) + --1687477895) - (~(0x345ECEBE ^ -1966017513) + (~1107759779 - (-2004895843 + -1227486236)) + ~1098717404))))) ^ ((0x6B7C03B1 ^ -563237034) - 1997213302 - -864690461 * 508014115 + -91259503 - (~(-1501978634 - --1171567529) + ~(885469012 + (246159577 + -1825049077)) - (-(2111566533 * 1701019692 + (-463952699 + 1623486493)) + (-1224917475 * -1531921247 + (1927600904 + 320144413) + -(-114173538 + 399479174))))))) % 100;
			int num5 = 3344427;
			_ = 0;
			for (int num6 = 0; num6 < 2; num6++)
			{
				num5 -= 236528657;
				num5 = -num5 ^ -2072142464;
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = 5;
			_ = 0;
			for (int num8 = 0; num8 < 2; num8++)
			{
				num7 = -num7;
				num7 = ~num7;
			}
			if (num3 != (uint)num7)
			{
				int num9 = 52;
				_ = 0;
				for (int num10 = 0; num10 < 2; num10++)
				{
					num9 = -(~num9);
					num9 = -389926308 - (num9 - (539959085 + 937717516));
				}
				if (num3 != (uint)num9)
				{
					int num11 = 79;
					_ = 0;
					for (int num12 = 0; num12 < 2; num12++)
					{
						num11 = num11 ^ -503192981 ^ 0x542FAC59;
						num11 ^= 0x198F6482;
					}
					if (num3 != (uint)num11)
					{
						int num13 = 829426665;
						_ = 0;
						for (int num14 = 0; num14 < 1; num14++)
						{
							num13 *= 1991212121;
						}
						if (num3 != (uint)num13)
						{
							int num15 = 1750160829;
							_ = 0;
							for (int num16 = 0; num16 < 2; num16++)
							{
								num15 = (num15 - (0x6A66660A ^ 0x55EEEA3F)) * -1983328163;
								num15 = (-343777011 - 2136846698 - num15) ^ -2115066102;
							}
							if (num3 != (uint)num15)
							{
								int num17 = 647709375;
								_ = 0;
								for (int num18 = 0; num18 < 1; num18++)
								{
									num17 -= 647709353;
								}
								if (num3 != (uint)num17)
								{
									int num19 = 184557695;
									_ = 0;
									for (int num20 = 0; num20 < 2; num20++)
									{
										num19 = ~num19;
										num19 = (num19 - (0x2F2E157F ^ -1414625264)) ^ 0x458F1254;
									}
									if (num3 != (uint)num19)
									{
										int num21 = -268927014;
										_ = 0;
										for (int num22 = 0; num22 < 2; num22++)
										{
											num21 = -num21 ^ 0x67EAB752;
											num21 = ~-1943456090 - num21 - 621610798;
										}
										if (num3 != (uint)num21)
										{
											int num23 = -641530753;
											_ = 0;
											for (int num24 = 0; num24 < 1; num24++)
											{
												num23 ^= -641530845;
											}
											if (num3 != (uint)num23)
											{
												int num25 = 44;
												_ = 0;
												for (int num26 = 0; num26 < 2; num26++)
												{
													num25 = -(num25 + (200918127 + 23935449));
													num25 = ~((0x2B798E8 ^ 0x3B56B4A7) - num25);
												}
												if (num3 == (uint)num25)
												{
													goto IL_9644;
												}
												int num27 = -762034713;
												_ = 0;
												for (int num28 = 0; num28 < 2; num28++)
												{
													num27 = 116258400 + 748256005 - num27;
													num27 = ~(num27 * -867165693);
												}
												if (num3 != (uint)num27)
												{
													int num29 = -1702850580;
													_ = 0;
													for (int num30 = 0; num30 < 2; num30++)
													{
														num29 = (num29 * 1602767021) ^ -406718703;
														num29 = -((-795085665 ^ 0x6A5BA140) - num29);
													}
													if (num3 != (uint)num29)
													{
														int num31 = -100;
														_ = 0;
														for (int num32 = 0; num32 < 1; num32++)
														{
															num31 = ~num31;
														}
														if (num3 != (uint)num31)
														{
															int num33 = 73;
															_ = 0;
															for (int num34 = 0; num34 < 2; num34++)
															{
																num33 = -(863103870 + -1222733265 - num33);
																num33 = -num33 - 2114048221;
															}
															if (num3 == (uint)num33)
															{
																goto IL_a14c;
															}
															int num35 = 1705263419;
															_ = 0;
															for (int num36 = 0; num36 < 1; num36++)
															{
																num35 -= 1705263343;
															}
															if (num3 != (uint)num35)
															{
																int num37 = 939936853;
																_ = 0;
																for (int num38 = 0; num38 < 2; num38++)
																{
																	num37 = (num37 ^ -799903039) - 201909709;
																	num37 = ~(num37 ^ 0x2EB558C3);
																}
																if (num3 != (uint)num37)
																{
																	int num39 = -67;
																	_ = 0;
																	for (int num40 = 0; num40 < 1; num40++)
																	{
																		num39 = -num39;
																	}
																	if (num3 != (uint)num39)
																	{
																		int num41 = -1903011258;
																		_ = 0;
																		for (int num42 = 0; num42 < 1; num42++)
																		{
																			num41 *= -998764097;
																		}
																		if (num3 != (uint)num41)
																		{
																			int num43 = -1841906969;
																			_ = 0;
																			for (int num44 = 0; num44 < 1; num44++)
																			{
																				num43 -= -1841907051;
																			}
																			if (num3 == (uint)num43)
																			{
																				goto IL_5971;
																			}
																			int num45 = 328891256;
																			_ = 0;
																			for (int num46 = 0; num46 < 1; num46++)
																			{
																				num45 *= 542690989;
																			}
																			if (num3 != (uint)num45)
																			{
																				int num47 = -1176990795;
																				_ = 0;
																				for (int num48 = 0; num48 < 2; num48++)
																				{
																					num47 = 592489586 - (3994166 - num47);
																					num47 = ~(~num47);
																				}
																				if (num3 != (uint)num47)
																				{
																					int num49 = 1779430995;
																					_ = 0;
																					for (int num50 = 0; num50 < 2; num50++)
																					{
																						num49 = num49 ^ 0x6DBDF037 ^ -1843012160;
																						num49 = 597677998 - num49 + 658418983;
																					}
																					if (num3 != (uint)num49)
																					{
																						int num51 = -774903798;
																						_ = 0;
																						for (int num52 = 0; num52 < 1; num52++)
																						{
																							num51 = -774903777 - num51;
																						}
																						if (num3 != (uint)num51)
																						{
																							int num53 = -2038307600;
																							_ = 0;
																							for (int num54 = 0; num54 < 2; num54++)
																							{
																								num53 = ~num53 * 642221171;
																								num53 = num53 * -1145537321 - 1826828663;
																							}
																							if (num3 != (uint)num53)
																							{
																								int num55 = -375451470;
																								_ = 0;
																								for (int num56 = 0; num56 < 1; num56++)
																								{
																									num55 = -375451460 - num55;
																								}
																								if (num3 != (uint)num55)
																								{
																									int num57 = 268512271;
																									_ = 0;
																									for (int num58 = 0; num58 < 2; num58++)
																									{
																										num57 = -(-num57);
																										num57 = (num57 - --128160908) ^ 0x55FF69E4;
																									}
																									if (num3 != (uint)num57)
																									{
																										int num59 = 2014117541;
																										_ = 0;
																										for (int num60 = 0; num60 < 2; num60++)
																										{
																											num59 ^= --2135721204;
																											num59 = (num59 ^ 0x67B9FAD3) - 1007839041;
																										}
																										if (num3 != (uint)num59)
																										{
																											int num61 = -1263132661;
																											_ = 0;
																											for (int num62 = 0; num62 < 1; num62++)
																											{
																												num61 += 1263132673;
																											}
																											if (num3 != (uint)num61)
																											{
																												int num63 = 707309447;
																												_ = 0;
																												for (int num64 = 0; num64 < 2; num64++)
																												{
																													num63 = (num63 ^ --1272757972) * -1648651173;
																													num63 = -num63;
																												}
																												if (num3 != (uint)num63)
																												{
																													int num65 = 862617211;
																													_ = 0;
																													for (int num66 = 0; num66 < 2; num66++)
																													{
																														num65 = (1569792733 * -970764139 - num65) * 1637390443;
																														num65 -= -2014538663 + 401929297;
																													}
																													if (num3 != (uint)num65)
																													{
																														int num67 = -465304513;
																														_ = 0;
																														for (int num68 = 0; num68 < 2; num68++)
																														{
																															num67 = -num67 * 1525527695;
																															num67 = (num67 - ~1787192262) * 1541193463;
																														}
																														if (num3 != (uint)num67)
																														{
																															int num69 = 1282882550;
																															_ = 0;
																															for (int num70 = 0; num70 < 2; num70++)
																															{
																																num69 = 422522013 - (num69 ^ 0x75180F0C);
																																num69 = 1768560324 - num69 * -313537679;
																															}
																															int num269;
																															if (num3 != (uint)num69)
																															{
																																int num71 = 1851405559;
																																_ = 0;
																																for (int num72 = 0; num72 < 2; num72++)
																																{
																																	num71 = (num71 + -584086251 * -385968725) ^ 0x1B3322D0;
																																	num71 = num71 * 142214659 * -1331420679;
																																}
																																if (num3 != (uint)num71)
																																{
																																	int num73 = -1313633206;
																																	_ = 0;
																																	for (int num74 = 0; num74 < 2; num74++)
																																	{
																																		num73 = ~(num73 ^ 0x1A39343F);
																																		num73 = (num73 ^ -91701130) * 447368407;
																																	}
																																	if (num3 != (uint)num73)
																																	{
																																		int num75 = -943602062;
																																		_ = 0;
																																		for (int num76 = 0; num76 < 1; num76++)
																																		{
																																			num75 *= 1006257687;
																																		}
																																		if (num3 != (uint)num75)
																																		{
																																			int num77 = -1321653887;
																																			_ = 0;
																																			for (int num78 = 0; num78 < 2; num78++)
																																			{
																																				num77 = (-1161864064 - -432833227 - num77) * -1291337487;
																																				num77 = num77 - (0x4D750C57 ^ 0x10686466) + 912509142;
																																			}
																																			int num255;
																																			if (num3 != (uint)num77)
																																			{
																																				int num79 = -42;
																																				_ = 0;
																																				for (int num80 = 0; num80 < 1; num80++)
																																				{
																																					num79 = -num79;
																																				}
																																				if (num3 != (uint)num79)
																																				{
																																					int num81 = -73;
																																					_ = 0;
																																					for (int num82 = 0; num82 < 1; num82++)
																																					{
																																						num81 = ~num81;
																																					}
																																					int num253;
																																					if (num3 != (uint)num81)
																																					{
																																						int num83 = 898914197;
																																						_ = 0;
																																						for (int num84 = 0; num84 < 1; num84++)
																																						{
																																							num83 -= 898914151;
																																						}
																																						if (num3 != (uint)num83)
																																						{
																																							int num85 = 471399348;
																																							_ = 0;
																																							for (int num86 = 0; num86 < 2; num86++)
																																							{
																																								num85 = ~num85 ^ 0x121EBF6E;
																																								num85 = ~(1449598913 + -1798939155 - num85);
																																							}
																																							int num251;
																																							if (num3 != (uint)num85)
																																							{
																																								int num87 = -1269507065;
																																								_ = 0;
																																								for (int num88 = 0; num88 < 2; num88++)
																																								{
																																									num87 = num87 * 1815886603 + -1695803041;
																																									num87 = -(num87 * 562567767);
																																								}
																																								if (num3 != (uint)num87)
																																								{
																																									int num89 = 1491172937;
																																									_ = 0;
																																									for (int num90 = 0; num90 < 1; num90++)
																																									{
																																										num89 = 1491173001 - num89;
																																									}
																																									int num249;
																																									if (num3 != (uint)num89)
																																									{
																																										int num91 = 1017080459;
																																										_ = 0;
																																										for (int num92 = 0; num92 < 1; num92++)
																																										{
																																											num91 += -1017080439;
																																										}
																																										if (num3 != (uint)num91)
																																										{
																																											int num93 = -1446639302;
																																											_ = 0;
																																											for (int num94 = 0; num94 < 1; num94++)
																																											{
																																												num93 *= -1288185771;
																																											}
																																											int num247;
																																											if (num3 != (uint)num93)
																																											{
																																												int num95 = 1766347039;
																																												_ = 0;
																																												for (int num96 = 0; num96 < 2; num96++)
																																												{
																																													num95 = -num95 * 285444627;
																																													num95 += 1519145323 * 1699606661;
																																												}
																																												if (num3 != (uint)num95)
																																												{
																																													int num97 = 691070867;
																																													_ = 0;
																																													for (int num98 = 0; num98 < 2; num98++)
																																													{
																																														num97 ^= -1360974792;
																																														num97 = -(num97 * -107859849);
																																													}
																																													int num245;
																																													if (num3 != (uint)num97)
																																													{
																																														int num99 = -980784921;
																																														_ = 0;
																																														for (int num100 = 0; num100 < 2; num100++)
																																														{
																																															num99 = -num99;
																																															num99 = -(num99 * 912633503);
																																														}
																																														if (num3 != (uint)num99)
																																														{
																																															int num101 = -1971287855;
																																															_ = 0;
																																															for (int num102 = 0; num102 < 2; num102++)
																																															{
																																																num101 = ~(num101 * 621799039);
																																																num101 ^= 0x5C9DEDB4;
																																															}
																																															int num243;
																																															if (num3 != (uint)num101)
																																															{
																																																int num103 = -1718582706;
																																																_ = 0;
																																																for (int num104 = 0; num104 < 1; num104++)
																																																{
																																																	num103 = -1718582657 - num103;
																																																}
																																																if (num3 != (uint)num103)
																																																{
																																																	int num105 = 925386176;
																																																	_ = 0;
																																																	for (int num106 = 0; num106 < 1; num106++)
																																																	{
																																																		num105 -= 925386158;
																																																	}
																																																	int num241;
																																																	if (num3 != (uint)num105)
																																																	{
																																																		int num107 = 930062968;
																																																		_ = 0;
																																																		for (int num108 = 0; num108 < 1; num108++)
																																																		{
																																																			num107 *= 1419193707;
																																																		}
																																																		if (num3 != (uint)num107)
																																																		{
																																																			int num109 = -1886577195;
																																																			_ = 0;
																																																			for (int num110 = 0; num110 < 1; num110++)
																																																			{
																																																				num109 = -1886577106 - num109;
																																																			}
																																																			int num239;
																																																			if (num3 != (uint)num109)
																																																			{
																																																				int num111 = -1252643819;
																																																				_ = 0;
																																																				for (int num112 = 0; num112 < 1; num112++)
																																																				{
																																																					num111 ^= -1252643757;
																																																				}
																																																				if (num3 != (uint)num111)
																																																				{
																																																					int num113 = 1715350610;
																																																					_ = 0;
																																																					for (int num114 = 0; num114 < 1; num114++)
																																																					{
																																																						num113 -= 1715350522;
																																																					}
																																																					int num237;
																																																					if (num3 != (uint)num113)
																																																					{
																																																						int num115 = 1404506757;
																																																						_ = 0;
																																																						for (int num116 = 0; num116 < 2; num116++)
																																																						{
																																																							num115 = ~(num115 * 1204026037);
																																																							num115 = 1162053279 - (num115 - (1558841396 + 1568015069));
																																																						}
																																																						if (num3 != (uint)num115)
																																																						{
																																																							int num117 = 0;
																																																							_ = 0;
																																																							for (int num118 = 0; num118 < 2; num118++)
																																																							{
																																																								num117 = -num117 * 270527809;
																																																								num117 = -num117;
																																																							}
																																																							int num235;
																																																							if (num3 != (uint)num117)
																																																							{
																																																								int num119 = 84;
																																																								_ = 0;
																																																								for (int num120 = 0; num120 < 2; num120++)
																																																								{
																																																									num119 = ~(-num119);
																																																									num119 = -num119 ^ 0x1F484EF7;
																																																								}
																																																								if (num3 != (uint)num119)
																																																								{
																																																									int num121 = -1741588559;
																																																									_ = 0;
																																																									for (int num122 = 0; num122 < 1; num122++)
																																																									{
																																																										num121 += 1741588652;
																																																									}
																																																									int num233;
																																																									if (num3 != (uint)num121)
																																																									{
																																																										int num123 = 588402454;
																																																										_ = 0;
																																																										for (int num124 = 0; num124 < 1; num124++)
																																																										{
																																																											num123 *= -620749903;
																																																										}
																																																										if (num3 != (uint)num123)
																																																										{
																																																											int num125 = 1834916634;
																																																											_ = 0;
																																																											for (int num126 = 0; num126 < 1; num126++)
																																																											{
																																																												num125 = 1834916667 - num125;
																																																											}
																																																											int num231;
																																																											if (num3 != (uint)num125)
																																																											{
																																																												int num127 = 620305903;
																																																												_ = 0;
																																																												for (int num128 = 0; num128 < 2; num128++)
																																																												{
																																																													num127 = (~-1371415161 - num127) * -1756163669;
																																																													num127 = ~(-1007594850 - num127);
																																																												}
																																																												if (num3 != (uint)num127)
																																																												{
																																																													int num129 = -559793386;
																																																													_ = 0;
																																																													for (int num130 = 0; num130 < 1; num130++)
																																																													{
																																																														num129 ^= -559793389;
																																																													}
																																																													if (num3 != (uint)num129)
																																																													{
																																																														int num131 = -59;
																																																														_ = 0;
																																																														for (int num132 = 0; num132 < 1; num132++)
																																																														{
																																																															num131 = -num131;
																																																														}
																																																														int num223;
																																																														if (num3 != (uint)num131)
																																																														{
																																																															int num133 = -1241051098;
																																																															_ = 0;
																																																															for (int num134 = 0; num134 < 2; num134++)
																																																															{
																																																																num133 = -388125869 - (num133 + --196863778);
																																																																num133 = (-2109840847 - num133) ^ 0x206877D9;
																																																															}
																																																															if (num3 != (uint)num133)
																																																															{
																																																																int num135 = -14;
																																																																_ = 0;
																																																																for (int num136 = 0; num136 < 1; num136++)
																																																																{
																																																																	num135 = ~num135;
																																																																}
																																																																int num221;
																																																																if (num3 != (uint)num135)
																																																																{
																																																																	int num137 = -1750422680;
																																																																	_ = 0;
																																																																	for (int num138 = 0; num138 < 1; num138++)
																																																																	{
																																																																		num137 = -1750422633 - num137;
																																																																	}
																																																																	if (num3 != (uint)num137)
																																																																	{
																																																																		int num139 = 411008897;
																																																																		_ = 0;
																																																																		for (int num140 = 0; num140 < 2; num140++)
																																																																		{
																																																																			num139 = num139 - 1046091670 + -1306896409;
																																																																			num139 = ~(~num139);
																																																																		}
																																																																		if (num3 != (uint)num139)
																																																																		{
																																																																			int num141 = -69;
																																																																			_ = 0;
																																																																			for (int num142 = 0; num142 < 1; num142++)
																																																																			{
																																																																				num141 = -num141;
																																																																			}
																																																																			if (num3 != (uint)num141)
																																																																			{
																																																																				int num143 = 74;
																																																																				_ = 0;
																																																																				for (int num144 = 0; num144 < 2; num144++)
																																																																				{
																																																																					num143 = -(-num143);
																																																																					num143 ^= 0x4F43FE0A;
																																																																				}
																																																																				if (num3 != (uint)num143)
																																																																				{
																																																																					int num145 = -1331817497;
																																																																					_ = 0;
																																																																					for (int num146 = 0; num146 < 2; num146++)
																																																																					{
																																																																						num145 = num145 + -879771522 + -2146507269;
																																																																						num145 = num145 - ~-888258514 + -1862004871;
																																																																					}
																																																																					if (num3 != (uint)num145)
																																																																					{
																																																																						int num147 = 812301114;
																																																																						_ = 0;
																																																																						for (int num148 = 0; num148 < 1; num148++)
																																																																						{
																																																																							num147 *= 1727345183;
																																																																						}
																																																																						if (num3 != (uint)num147)
																																																																						{
																																																																							int num149 = -738607163;
																																																																							_ = 0;
																																																																							for (int num150 = 0; num150 < 1; num150++)
																																																																							{
																																																																								num149 += 738607241;
																																																																							}
																																																																							if (num3 != (uint)num149)
																																																																							{
																																																																								int num151 = -803492401;
																																																																								_ = 0;
																																																																								for (int num152 = 0; num152 < 2; num152++)
																																																																								{
																																																																									num151 = -(num151 * -1352975329);
																																																																									num151 = ~(num151 * 1243593723);
																																																																								}
																																																																								if (num3 != (uint)num151)
																																																																								{
																																																																									int num153 = 647219514;
																																																																									_ = 0;
																																																																									for (int num154 = 0; num154 < 1; num154++)
																																																																									{
																																																																										num153 -= 647219437;
																																																																									}
																																																																									if (num3 != (uint)num153)
																																																																									{
																																																																										int num155 = -84;
																																																																										_ = 0;
																																																																										for (int num156 = 0; num156 < 1; num156++)
																																																																										{
																																																																											num155 = -num155;
																																																																										}
																																																																										if (num3 != (uint)num155)
																																																																										{
																																																																											int num157 = 1090545724;
																																																																											_ = 0;
																																																																											for (int num158 = 0; num158 < 2; num158++)
																																																																											{
																																																																												num157 = ~num157 + -1774900283;
																																																																												num157 = -num157 ^ -815855516;
																																																																											}
																																																																											if (num3 != (uint)num157)
																																																																											{
																																																																												int num159 = -694400442;
																																																																												_ = 0;
																																																																												for (int num160 = 0; num160 < 1; num160++)
																																																																												{
																																																																													num159 += 694400495;
																																																																												}
																																																																												if (num3 != (uint)num159)
																																																																												{
																																																																													int num161 = 68;
																																																																													_ = 0;
																																																																													for (int num162 = 0; num162 < 2; num162++)
																																																																													{
																																																																														num161 = -(~num161);
																																																																														num161 = ~(num161 - -309327810);
																																																																													}
																																																																													if (num3 != (uint)num161)
																																																																													{
																																																																														int num163 = -178756348;
																																																																														_ = 0;
																																																																														for (int num164 = 0; num164 < 1; num164++)
																																																																														{
																																																																															num163 += 178756380;
																																																																														}
																																																																														if (num3 != (uint)num163)
																																																																														{
																																																																															int num165 = 318579034;
																																																																															_ = 0;
																																																																															for (int num166 = 0; num166 < 1; num166++)
																																																																															{
																																																																																num165 -= 318578948;
																																																																															}
																																																																															if (num3 != (uint)num165)
																																																																															{
																																																																																int num167 = 1195314045;
																																																																																_ = 0;
																																																																																for (int num168 = 0; num168 < 2; num168++)
																																																																																{
																																																																																	num167 = -num167 * -373464801;
																																																																																	num167 = (num167 - 1344468819 * -302101938) ^ -1252324351;
																																																																																}
																																																																																if (num3 != (uint)num167)
																																																																																{
																																																																																	int num169 = -1186727760;
																																																																																	_ = 0;
																																																																																	for (int num170 = 0; num170 < 2; num170++)
																																																																																	{
																																																																																		num169 = ~num169;
																																																																																		num169 = ~num169 * 1120275091;
																																																																																	}
																																																																																	if (num3 != (uint)num169)
																																																																																	{
																																																																																		int num171 = 26;
																																																																																		_ = 0;
																																																																																		for (int num172 = 0; num172 < 2; num172++)
																																																																																		{
																																																																																			num171 = -(~num171);
																																																																																			num171 = -num171 - 1845079525;
																																																																																		}
																																																																																		if (num3 != (uint)num171)
																																																																																		{
																																																																																			int num173 = 1019503082;
																																																																																			_ = 0;
																																																																																			for (int num174 = 0; num174 < 1; num174++)
																																																																																			{
																																																																																				num173 -= 1019502984;
																																																																																			}
																																																																																			if (num3 != (uint)num173)
																																																																																			{
																																																																																				int num175 = -1284099494;
																																																																																				_ = 0;
																																																																																				for (int num176 = 0; num176 < 1; num176++)
																																																																																				{
																																																																																					num175 -= -1284099501;
																																																																																				}
																																																																																				if (num3 != (uint)num175)
																																																																																				{
																																																																																					int num177 = 36;
																																																																																					_ = 0;
																																																																																					for (int num178 = 0; num178 < 2; num178++)
																																																																																					{
																																																																																						num177 = -(-num177);
																																																																																						num177 = ~(~num177);
																																																																																					}
																																																																																					if (num3 != (uint)num177)
																																																																																					{
																																																																																						int num179 = 28;
																																																																																						_ = 0;
																																																																																						for (int num180 = 0; num180 < 2; num180++)
																																																																																						{
																																																																																							num179 = num179 ^ -2018284942 ^ 0x4B9A337B;
																																																																																							num179 = ~(num179 ^ 0x33BC3228);
																																																																																						}
																																																																																						if (num3 != (uint)num179)
																																																																																						{
																																																																																							int num181 = -1364268355;
																																																																																							_ = 0;
																																																																																							for (int num182 = 0; num182 < 2; num182++)
																																																																																							{
																																																																																								num181 = 1781324729 - (1178799097 * 690161449 - num181);
																																																																																								num181 = (359482563 * -1708329836 - num181) * 1541653679;
																																																																																							}
																																																																																							if (num3 != (uint)num181)
																																																																																							{
																																																																																								int num183 = -1784077742;
																																																																																								_ = 0;
																																																																																								for (int num184 = 0; num184 < 1; num184++)
																																																																																								{
																																																																																									num183 -= -1784077807;
																																																																																								}
																																																																																								if (num3 != (uint)num183)
																																																																																								{
																																																																																									int num185 = -1531240238;
																																																																																									_ = 0;
																																																																																									for (int num186 = 0; num186 < 2; num186++)
																																																																																									{
																																																																																										num185 = ~(num185 + -2120466353);
																																																																																										num185 *= -1290282389;
																																																																																									}
																																																																																									if (num3 != (uint)num185)
																																																																																									{
																																																																																										int num187 = 71;
																																																																																										_ = 0;
																																																																																										for (int num188 = 0; num188 < 2; num188++)
																																																																																										{
																																																																																											num187 = -num187 ^ 0x4594A499;
																																																																																											num187 ^= -989977943;
																																																																																										}
																																																																																										if (num3 != (uint)num187)
																																																																																										{
																																																																																											int num189 = -1560785059;
																																																																																											_ = 0;
																																																																																											for (int num190 = 0; num190 < 1; num190++)
																																																																																											{
																																																																																												num189 -= -1560785149;
																																																																																											}
																																																																																											if (num3 != (uint)num189)
																																																																																											{
																																																																																												int num191 = 83;
																																																																																												_ = 0;
																																																																																												for (int num192 = 0; num192 < 2; num192++)
																																																																																												{
																																																																																													num191 = num191 - (643053926 - -1526229358) + 1121102613;
																																																																																													num191 = ~(num191 + 1208066622 * 929502595);
																																																																																												}
																																																																																												if (num3 != (uint)num191)
																																																																																												{
																																																																																													int num193 = 94;
																																																																																													_ = 0;
																																																																																													for (int num194 = 0; num194 < 2; num194++)
																																																																																													{
																																																																																														num193 = 1317037736 - (num193 - 699453297);
																																																																																														num193 = num193 - (1455809433 + -2115792225) - -1245115476;
																																																																																													}
																																																																																													if (num3 != (uint)num193)
																																																																																													{
																																																																																														int num195 = -76;
																																																																																														_ = 0;
																																																																																														for (int num196 = 0; num196 < 1; num196++)
																																																																																														{
																																																																																															num195 = ~num195;
																																																																																														}
																																																																																														if (num3 != (uint)num195)
																																																																																														{
																																																																																															int num197 = -297276722;
																																																																																															_ = 0;
																																																																																															for (int num198 = 0; num198 < 1; num198++)
																																																																																															{
																																																																																																num197 = -297276711 - num197;
																																																																																															}
																																																																																															if (num3 != (uint)num197)
																																																																																															{
																																																																																																int num199 = -50;
																																																																																																_ = 0;
																																																																																																for (int num200 = 0; num200 < 1; num200++)
																																																																																																{
																																																																																																	num199 = -num199;
																																																																																																}
																																																																																																if (num3 != (uint)num199)
																																																																																																{
																																																																																																	int num201 = 404751626;
																																																																																																	_ = 0;
																																																																																																	for (int num202 = 0; num202 < 2; num202++)
																																																																																																	{
																																																																																																		num201 = -1506633377 - (num201 + -1881554670);
																																																																																																		num201 = (-501480335 - 1418905229 - num201) ^ -211063427;
																																																																																																	}
																																																																																																	if (num3 != (uint)num201)
																																																																																																	{
																																																																																																		int num203 = -2;
																																																																																																		_ = 0;
																																																																																																		for (int num204 = 0; num204 < 1; num204++)
																																																																																																		{
																																																																																																			num203 = -num203;
																																																																																																		}
																																																																																																		if (num3 != (uint)num203)
																																																																																																		{
																																																																																																		}
																																																																																																		return result;
																																																																																																	}
																																																																																																	result = _002F_002B_005E_002F_0028_0028_0021_0029(xUT_003D);
																																																																																																	num = -2127977219;
																																																																																																}
																																																																																																else
																																																																																																{
																																																																																																	int[] array = new int[6];
																																																																																																	array[0] = 1670954373;
																																																																																																	array[1] = 920340305;
																																																																																																	array[2] = -672356375;
																																																																																																	array[3] = -2038270980;
																																																																																																	array[4] = -1631169627;
																																																																																																	array[5] = 1528116656;
																																																																																																	array[3] = array[0] ^ -393325787;
																																																																																																	array[1] = array[3] ^ -1725416115;
																																																																																																	array[3] = array[1] ^ 0x501B574;
																																																																																																	int[] array2 = new int[5] { -1379995127, -469147101, -1118056744, 1282587731, 1995123303 };
																																																																																																	int[][] array3 = new int[2][] { array, array2 };
																																																																																																	array2[0] = array3[0][0] ^ -2006318916;
																																																																																																	array2[3] = array2[4] ^ -1418274915;
																																																																																																	array2[4] = array2[0] ^ -145027303;
																																																																																																	array2[4] = array2[1] ^ -218985254;
																																																																																																	int num205 = array3[1][0] ^ 0x6ADB19C4;
																																																																																																	num = (int)((num4 * 289011033) ^ 0xBBEC8536u) ^ num205;
																																																																																																}
																																																																																															}
																																																																																															else
																																																																																															{
																																																																																																result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x571 ^ 0x4D8];
																																																																																																num = -273376715;
																																																																																															}
																																																																																														}
																																																																																														else
																																																																																														{
																																																																																															int[] array4 = new int[6];
																																																																																															array4[0] = 428434474;
																																																																																															array4[1] = 672578237;
																																																																																															array4[2] = -536600965;
																																																																																															array4[3] = -1385547405;
																																																																																															array4[4] = 419621504;
																																																																																															array4[5] = -1785814444;
																																																																																															array4[1] = array4[2] ^ 0x52880C0E;
																																																																																															array4[2] = array4[0] ^ -295358587;
																																																																																															array4[0] = array4[2] ^ -1929191633;
																																																																																															int[] array5 = new int[4] { 1608588971, 1998870914, 3832049, 878170618 };
																																																																																															int[][] array6 = new int[2][] { array4, array5 };
																																																																																															array5[0] = array6[0][3] ^ 0xC366652;
																																																																																															array5[2] = array5[3] ^ 0x5F0DFB9E;
																																																																																															array5[3] = array5[0] ^ -784915209;
																																																																																															array5[2] = array5[0] ^ -1152243848;
																																																																																															int num206 = array6[1][0] ^ 0x2075FBDC;
																																																																																															num = (int)((num4 * 2121674206) ^ 0xB90183A) ^ num206;
																																																																																														}
																																																																																													}
																																																																																													else
																																																																																													{
																																																																																														result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[3219 - 2816 + 49];
																																																																																														num = -1193796190;
																																																																																													}
																																																																																												}
																																																																																												else
																																																																																												{
																																																																																													result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[557 - 38 - 44 - 24];
																																																																																													num = -2127977219;
																																																																																												}
																																																																																											}
																																																																																											else
																																																																																											{
																																																																																												int[,] array7 = new int[3, 3];
																																																																																												array7[0, 0] = -342604906;
																																																																																												array7[0, 1] = -1882970174;
																																																																																												array7[0, 2] = 1385691353;
																																																																																												array7[1, 0] = 1465415669;
																																																																																												array7[1, 1] = 754168711;
																																																																																												array7[1, 2] = 1954796587;
																																																																																												array7[2, 0] = -94332783;
																																																																																												array7[2, 1] = -862981498;
																																																																																												array7[2, 2] = -1134487336;
																																																																																												array7[1, 1] = array7[2, 2] ^ -1341917575;
																																																																																												array7[0, 2] = array7[2, 1] ^ 0x6E7E5B99;
																																																																																												array7[0, 0] = array7[1, 0] ^ 0x6778D32E;
																																																																																												int num207 = array7[0, 0] ^ -1324810202;
																																																																																												num = (int)((num4 * 2088056479) ^ 0x9050448Eu) ^ num207;
																																																																																											}
																																																																																										}
																																																																																										else
																																																																																										{
																																																																																											result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0xF467 ^ 0xF5A5))];
																																																																																											num = -1776007519;
																																																																																										}
																																																																																									}
																																																																																									else
																																																																																									{
																																																																																										int[] array8 = new int[7];
																																																																																										array8[0] = -374575323;
																																																																																										array8[1] = -690730291;
																																																																																										array8[2] = 954113849;
																																																																																										array8[3] = -501731334;
																																																																																										array8[4] = -244723142;
																																																																																										array8[5] = 895584459;
																																																																																										array8[6] = 1966312480;
																																																																																										array8[4] = array8[0] ^ 0x58534D08;
																																																																																										array8[5] ^= 1604939335;
																																																																																										array8[5] = array8[0] ^ -1204640008;
																																																																																										int[] array9 = new int[5];
																																																																																										array9[0] = -99945643;
																																																																																										array9[1] = -1932906285;
																																																																																										array9[2] = -1941719578;
																																																																																										array9[3] = -1694391355;
																																																																																										array9[4] = -1772517927;
																																																																																										array9[4] = array8[6] ^ -482409575;
																																																																																										array9[1] ^= -1750840158;
																																																																																										array9[3] = array9[4] ^ -2143635884;
																																																																																										array9[3] ^= 559331040;
																																																																																										int num208 = array9[4] ^ 0x17252B44;
																																																																																										num = ((int)num4 * -1458850) ^ -1213577252 ^ num208;
																																																																																									}
																																																																																								}
																																																																																								else
																																																																																								{
																																																																																									result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x7914 ^ 0x78D5))];
																																																																																									num = -1185081759;
																																																																																								}
																																																																																							}
																																																																																							else
																																																																																							{
																																																																																								int[,] array10 = new int[3, 3]
																																																																																								{
																																																																																									{ -1003921802, 1087367258, -1376333181 },
																																																																																									{ 321333828, -1439637537, 1793292790 },
																																																																																									{ 516813224, 1480618531, -1502040963 }
																																																																																								};
																																																																																								array10[1, 0] ^= 1902686002;
																																																																																								array10[1, 2] = array10[2, 1] ^ 0x42D152CC;
																																																																																								array10[2, 0] = array10[2, 1] ^ -1667751159;
																																																																																								int num209 = array10[2, 0] ^ 0x45F1F5D7;
																																																																																								num = (int)((num4 * 976074615) ^ 0x42CE607B) ^ num209;
																																																																																							}
																																																																																						}
																																																																																						else
																																																																																						{
																																																																																							result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[1524 - 1134 + 58];
																																																																																							num = -2140989428;
																																																																																						}
																																																																																					}
																																																																																					else
																																																																																					{
																																																																																						int[] array11 = new int[4] { 1700729869, -869269122, 260548615, -1303840095 };
																																																																																						array11[3] ^= 1817188310;
																																																																																						array11[3] = array11[1] ^ -2144617673;
																																																																																						int[] array12 = new int[4];
																																																																																						array12[0] = 122976819;
																																																																																						array12[1] = 778815945;
																																																																																						array12[2] = -2022415254;
																																																																																						array12[3] = 318461876;
																																																																																						array12[2] = array11[2] ^ -1440522109;
																																																																																						array12[1] = array12[0] ^ -1493470174;
																																																																																						array12[0] = array12[3] ^ 0x535E3740;
																																																																																						array12[3] = array12[1] ^ -1787018802;
																																																																																						int num210 = array12[2] ^ 0x248D6C79;
																																																																																						num = ((int)num4 * -1597949101) ^ -804382592 ^ num210;
																																																																																					}
																																																																																				}
																																																																																				else
																																																																																				{
																																																																																					result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[512 - 48 - 8 - 9];
																																																																																					num = -700988049;
																																																																																				}
																																																																																			}
																																																																																			else
																																																																																			{
																																																																																				int[] array13 = new int[6];
																																																																																				array13[0] = 1632315927;
																																																																																				array13[1] = 1543175287;
																																																																																				array13[2] = -1544131811;
																																																																																				array13[3] = -1459683292;
																																																																																				array13[4] = 1519000796;
																																																																																				array13[5] = 1943746126;
																																																																																				array13[5] = array13[3] ^ 0x44D80B21;
																																																																																				array13[5] = array13[2] ^ 0x4D57230C;
																																																																																				int[] array14 = new int[4] { -346758183, -1031100903, -670106398, 156620732 };
																																																																																				int[][] array15 = new int[2][] { array13, array14 };
																																																																																				array14[3] = array15[0][3] ^ 0x24816619;
																																																																																				array14[2] = array14[3] ^ 0x4A06C817;
																																																																																				array14[1] = array14[2] ^ -1409769461;
																																																																																				int num211 = array15[1][3] ^ 0xD57C2C0;
																																																																																				num = ((int)num4 * -1508911786) ^ 0x69399C44 ^ num211;
																																																																																			}
																																																																																		}
																																																																																		else
																																																																																		{
																																																																																			result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-769 + 322)];
																																																																																			num = -762914187;
																																																																																		}
																																																																																	}
																																																																																	else
																																																																																	{
																																																																																		int[,] array16 = new int[4, 3];
																																																																																		array16[0, 0] = 1888205515;
																																																																																		array16[0, 1] = 372811775;
																																																																																		array16[0, 2] = 521449374;
																																																																																		array16[1, 0] = -750692061;
																																																																																		array16[1, 1] = -1623057840;
																																																																																		array16[1, 2] = 2089500199;
																																																																																		array16[2, 0] = 524651693;
																																																																																		array16[2, 1] = 312387055;
																																																																																		array16[2, 2] = -579118102;
																																																																																		array16[3, 0] = 672307181;
																																																																																		array16[3, 1] = -3222327;
																																																																																		array16[3, 2] = -2076631895;
																																																																																		array16[2, 0] = array16[3, 1] ^ 0x63EA8F21;
																																																																																		array16[2, 2] = array16[0, 0] ^ -1391646919;
																																																																																		array16[0, 0] = array16[3, 0] ^ -1052374563;
																																																																																		int num212 = array16[0, 0] ^ 0x687D3ACD;
																																																																																		num = ((int)num4 * -49956859) ^ -2075561360 ^ num212;
																																																																																	}
																																																																																}
																																																																																else
																																																																																{
																																																																																	result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(425 + sizeof(int)) ^ sizeof(Guid)];
																																																																																	num = -144419905;
																																																																																}
																																																																															}
																																																																															else
																																																																															{
																																																																																int[] array17 = new int[6];
																																																																																array17[0] = -1498639008;
																																																																																array17[1] = -1398270547;
																																																																																array17[2] = 1966730359;
																																																																																array17[3] = -2118829002;
																																																																																array17[4] = 123644471;
																																																																																array17[5] = 349837218;
																																																																																array17[0] = array17[4] ^ -1546807208;
																																																																																array17[4] ^= 2052943049;
																																																																																array17[4] ^= -117380031;
																																																																																int[] array18 = new int[6];
																																																																																array18[0] = 1343632341;
																																																																																array18[1] = 1817944703;
																																																																																array18[2] = 1951595352;
																																																																																array18[3] = -1750918396;
																																																																																array18[4] = -94118269;
																																																																																array18[5] = 1059230256;
																																																																																array18[1] = array17[3] ^ 0x1DB7A658;
																																																																																array18[4] = array18[1] ^ -366359823;
																																																																																array18[3] = array18[5] ^ 0x2A496C89;
																																																																																array18[5] ^= 1313870811;
																																																																																int num213 = array18[1] ^ 0x1D2B3E93;
																																																																																num = ((int)num4 * -1866344636) ^ -1858509624 ^ num213;
																																																																															}
																																																																														}
																																																																														else
																																																																														{
																																																																															result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xB48 ^ 0xAF4];
																																																																															num = -1738303359;
																																																																														}
																																																																													}
																																																																													else
																																																																													{
																																																																														int[] array19 = new int[4] { -1060343080, 1340364438, -1328904385, 517533497 };
																																																																														array19[0] ^= -602886254;
																																																																														array19[0] = array19[2] ^ 0x3B548BD4;
																																																																														array19[3] = array19[2] ^ -1456753193;
																																																																														int[] array20 = new int[4] { -154163311, -1180078976, 1483231236, -2135748314 };
																																																																														int[][] array21 = new int[2][] { array19, array20 };
																																																																														array20[3] = array21[0][2] ^ 0x3B0F78D9;
																																																																														array20[2] = array20[1] ^ 0x5F2EA785;
																																																																														array20[0] = array20[3] ^ -359741767;
																																																																														int num214 = array21[1][3] ^ 0xAEC5B1B;
																																																																														num = (int)((num4 * 1861212560) ^ 0x545D4BC0) ^ num214;
																																																																													}
																																																																												}
																																																																												else
																																																																												{
																																																																													result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xE76 ^ 0xFCD];
																																																																													num = -599201781;
																																																																												}
																																																																											}
																																																																											else
																																																																											{
																																																																												int[,] array22 = new int[4, 4];
																																																																												array22[0, 0] = 1943331413;
																																																																												array22[0, 1] = -1937845169;
																																																																												array22[0, 2] = -1677989884;
																																																																												array22[0, 3] = -753370426;
																																																																												array22[1, 0] = -1579583052;
																																																																												array22[1, 1] = 1882047555;
																																																																												array22[1, 2] = 837704518;
																																																																												array22[1, 3] = 1278800922;
																																																																												array22[2, 0] = -980395762;
																																																																												array22[2, 1] = -404029053;
																																																																												array22[2, 2] = -1517239820;
																																																																												array22[2, 3] = -867307866;
																																																																												array22[3, 0] = 563815506;
																																																																												array22[3, 1] = 634616978;
																																																																												array22[3, 2] = -146605753;
																																																																												array22[3, 3] = -526852037;
																																																																												array22[2, 3] = array22[1, 0] ^ -866260438;
																																																																												array22[0, 1] = array22[0, 3] ^ 0x57CBF3BB;
																																																																												array22[2, 1] = array22[2, 0] ^ -468906430;
																																																																												int num215 = array22[2, 1] ^ -1598753871;
																																																																												num = (int)((num4 * 1680720735) ^ 0x6A6DE718) ^ num215;
																																																																											}
																																																																										}
																																																																										else
																																																																										{
																																																																											result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4396 - 4007 + 53];
																																																																											num = -168560649;
																																																																										}
																																																																									}
																																																																									else
																																																																									{
																																																																										int[,] array23 = new int[4, 4];
																																																																										array23[0, 0] = 433661935;
																																																																										array23[0, 1] = 1427208518;
																																																																										array23[0, 2] = 139757122;
																																																																										array23[0, 3] = -81837977;
																																																																										array23[1, 0] = 73551248;
																																																																										array23[1, 1] = -119849955;
																																																																										array23[1, 2] = 461263650;
																																																																										array23[1, 3] = 1541695396;
																																																																										array23[2, 0] = 748436892;
																																																																										array23[2, 1] = 117522845;
																																																																										array23[2, 2] = 15886852;
																																																																										array23[2, 3] = -896940920;
																																																																										array23[3, 0] = 1241099377;
																																																																										array23[3, 1] = -147000616;
																																																																										array23[3, 2] = 2111498574;
																																																																										array23[3, 3] = -540024401;
																																																																										array23[3, 0] = array23[2, 2] ^ -1425190453;
																																																																										array23[1, 3] = array23[3, 2] ^ 0x23C3F908;
																																																																										array23[2, 1] = array23[2, 3] ^ -317189960;
																																																																										array23[2, 1] = array23[1, 0] ^ 0x2A31DAC0;
																																																																										int num216 = array23[2, 1] ^ -1350945875;
																																																																										num = ((int)num4 * -1043006792) ^ -411373128 ^ num216;
																																																																									}
																																																																								}
																																																																								else
																																																																								{
																																																																									result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[3217 - 2831 + 55];
																																																																									num = -1879278544;
																																																																								}
																																																																							}
																																																																							else
																																																																							{
																																																																								int[,] array24 = new int[4, 3];
																																																																								array24[0, 0] = 1690591943;
																																																																								array24[0, 1] = 298809403;
																																																																								array24[0, 2] = 1544399976;
																																																																								array24[1, 0] = -1751177090;
																																																																								array24[1, 1] = 676190357;
																																																																								array24[1, 2] = 187028353;
																																																																								array24[2, 0] = -268193780;
																																																																								array24[2, 1] = -276140408;
																																																																								array24[2, 2] = 1569338581;
																																																																								array24[3, 0] = -181605007;
																																																																								array24[3, 1] = 1441523307;
																																																																								array24[3, 2] = -2141211781;
																																																																								array24[1, 0] = array24[0, 0] ^ 0x4367197;
																																																																								array24[3, 0] = array24[0, 0] ^ -392032702;
																																																																								array24[0, 1] = array24[1, 2] ^ -955813229;
																																																																								array24[2, 0] = array24[2, 1] ^ -1053413871;
																																																																								int num217 = array24[2, 0] ^ -1349131164;
																																																																								num = (int)((num4 * 340335220) ^ 0xF1816E98u) ^ num217;
																																																																							}
																																																																						}
																																																																						else
																																																																						{
																																																																							result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-573 + 132)];
																																																																							num = -144116147;
																																																																						}
																																																																					}
																																																																					else
																																																																					{
																																																																						int[] array25 = new int[5];
																																																																						array25[0] = 1610956668;
																																																																						array25[1] = -400766982;
																																																																						array25[2] = 1188032901;
																																																																						array25[3] = -487508378;
																																																																						array25[4] = 610273905;
																																																																						array25[4] = array25[1] ^ -1076326934;
																																																																						array25[4] = array25[1] ^ 0x419B6F72;
																																																																						int[] array26 = new int[6] { 1344546700, 1454998051, 1805350280, -1828101960, -755744727, -1521365589 };
																																																																						int[][] array27 = new int[2][] { array25, array26 };
																																																																						array26[1] = array27[0][3] ^ -569470425;
																																																																						array26[4] = array26[3] ^ -633571548;
																																																																						array26[0] ^= -1142850062;
																																																																						int num218 = array27[1][1] ^ -1110048580;
																																																																						num = (int)((num4 * 728137986) ^ 0xC7A89A9Au) ^ num218;
																																																																					}
																																																																				}
																																																																				else
																																																																				{
																																																																					result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[1442 - 1021 + 18];
																																																																					num = -1238395172;
																																																																				}
																																																																			}
																																																																			else
																																																																			{
																																																																				int[,] array28 = new int[3, 3];
																																																																				array28[0, 0] = 299668053;
																																																																				array28[0, 1] = -898418271;
																																																																				array28[0, 2] = -442383892;
																																																																				array28[1, 0] = -1234752908;
																																																																				array28[1, 1] = -1900853386;
																																																																				array28[1, 2] = 253709511;
																																																																				array28[2, 0] = -184373410;
																																																																				array28[2, 1] = 1407985384;
																																																																				array28[2, 2] = -1401049568;
																																																																				array28[0, 1] = array28[2, 0] ^ 0x21BA146F;
																																																																				array28[1, 0] ^= 1106305647;
																																																																				array28[1, 2] = array28[1, 0] ^ 0x1BD39526;
																																																																				array28[0, 2] = array28[2, 1] ^ 0x334E431;
																																																																				int num219 = array28[0, 2] ^ -772708828;
																																																																				num = ((int)num4 * -2017736363) ^ -19676987 ^ num219;
																																																																			}
																																																																		}
																																																																		else
																																																																		{
																																																																			result = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x134F ^ 0x12F9];
																																																																			num = -950376032;
																																																																		}
																																																																	}
																																																																	else
																																																																	{
																																																																		int[] array29 = new int[5];
																																																																		array29[0] = 1243149630;
																																																																		array29[1] = 769882901;
																																																																		array29[2] = 251969580;
																																																																		array29[3] = 128084639;
																																																																		array29[4] = 1024140758;
																																																																		array29[2] = array29[0] ^ 0x3CCAF217;
																																																																		array29[2] = array29[3] ^ 0x33FD65A0;
																																																																		array29[4] ^= -1329875673;
																																																																		int[] array30 = new int[5] { 1028636587, 1016077548, -1832852474, 821185156, -1856342210 };
																																																																		int[][] array31 = new int[2][] { array29, array30 };
																																																																		array30[4] = array31[0][0] ^ 0x5258AE78;
																																																																		array30[1] = array30[4] ^ -943756044;
																																																																		array30[3] = array30[0] ^ 0x7A027F6F;
																																																																		int num220 = array31[1][4] ^ -2057935369;
																																																																		num = (int)((num4 * 1229907987) ^ 0xBD0D9D69u) ^ num220;
																																																																	}
																																																																}
																																																																else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xD11 ^ 0xD04]))
																																																																{
																																																																	num = -993936382;
																																																																	num221 = num;
																																																																}
																																																																else
																																																																{
																																																																	num = -1241424295;
																																																																	num221 = num;
																																																																}
																																																															}
																																																															else
																																																															{
																																																																int[,] array32 = new int[4, 4];
																																																																array32[0, 0] = -2065362669;
																																																																array32[0, 1] = -1259747455;
																																																																array32[0, 2] = 588132067;
																																																																array32[0, 3] = 1599067883;
																																																																array32[1, 0] = -1932573955;
																																																																array32[1, 1] = -1861976318;
																																																																array32[1, 2] = 1107110149;
																																																																array32[1, 3] = 927580256;
																																																																array32[2, 0] = 1332394514;
																																																																array32[2, 1] = -2057552551;
																																																																array32[2, 2] = -1460240880;
																																																																array32[2, 3] = -1267267258;
																																																																array32[3, 0] = -8886332;
																																																																array32[3, 1] = 1390515564;
																																																																array32[3, 2] = -1352513208;
																																																																array32[3, 3] = 1078132799;
																																																																array32[1, 3] = array32[1, 0] ^ -2010502504;
																																																																array32[0, 1] = array32[1, 3] ^ 0x493ECC2F;
																																																																array32[0, 1] = array32[1, 2] ^ 0x75FDD649;
																																																																array32[1, 3] = array32[0, 2] ^ 0x9D95D71;
																																																																int num222 = array32[1, 3] ^ -1212068573;
																																																																num = (int)((num4 * 118225490) ^ 0xB2023514u) ^ num222;
																																																															}
																																																														}
																																																														else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0xFB6A ^ 0xFB45))]))
																																																														{
																																																															num = -526033559;
																																																															num223 = num;
																																																														}
																																																														else
																																																														{
																																																															num = -123453310;
																																																															num223 = num;
																																																														}
																																																													}
																																																													else
																																																													{
																																																														int[] array33 = new int[7];
																																																														array33[0] = 706050577;
																																																														array33[1] = -1953215710;
																																																														array33[2] = -2016980347;
																																																														array33[3] = -1292689658;
																																																														array33[4] = 77945435;
																																																														array33[5] = -5599036;
																																																														array33[6] = -1424920331;
																																																														array33[3] = array33[4] ^ -620535567;
																																																														array33[0] = array33[1] ^ 0x48C20A59;
																																																														int[] array34 = new int[6] { -723004923, -343075994, 1975892825, 952385227, 1720412651, 888414107 };
																																																														int[][] array35 = new int[2][] { array33, array34 };
																																																														array34[5] = array35[0][5] ^ 0x4A9CABF1;
																																																														array34[3] = array34[2] ^ -822713578;
																																																														array34[4] = array34[2] ^ 0x3A982C81;
																																																														int num224 = array35[1][5] ^ 0x28200584;
																																																														num = ((int)num4 * -556966210) ^ 0x781AB356 ^ num224;
																																																													}
																																																												}
																																																												else
																																																												{
																																																													bool num225 = _002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x148E0 ^ 0x148C8))]);
																																																													int[] array36 = new int[4] { 2062617022, 605611900, 545639476, 766364492 };
																																																													array36[2] ^= -1549044112;
																																																													array36[3] = array36[0] ^ 0x7E6868DA;
																																																													int[] array37 = new int[4] { 623073900, -103859648, 1382755097, 1090674328 };
																																																													int[][] array38 = new int[2][] { array36, array37 };
																																																													array37[0] = array38[0][1] ^ -583826858;
																																																													array37[3] = array37[0] ^ 0x1DE466AD;
																																																													array37[1] = array37[3] ^ -744657912;
																																																													int num226 = array38[1][0] ^ 0x65A24AF9;
																																																													int[] array39 = new int[5];
																																																													array39[0] = 799826094;
																																																													array39[1] = -1968446531;
																																																													array39[2] = -381758033;
																																																													array39[3] = 240263349;
																																																													array39[4] = -1093041853;
																																																													array39[0] = array39[2] ^ -661745783;
																																																													array39[2] = array39[4] ^ -1539023879;
																																																													int[] array40 = new int[6];
																																																													array40[0] = -1175664729;
																																																													array40[1] = 1830736491;
																																																													array40[2] = 1426919884;
																																																													array40[3] = -952285752;
																																																													array40[4] = -641019479;
																																																													array40[5] = -1344414506;
																																																													array40[2] = array39[4] ^ -1608237849;
																																																													array40[4] ^= -465035976;
																																																													array40[4] = array40[2] ^ -134783310;
																																																													array40[0] = array40[2] ^ -1986594906;
																																																													int num227 = array40[2] ^ -1206167424;
																																																													int num228 = ((int)num4 * -1348967047) ^ -627513235;
																																																													num226 ^= num228;
																																																													num227 ^= num228;
																																																													int num229;
																																																													int num230;
																																																													if (!num225)
																																																													{
																																																														num229 = num227;
																																																														num230 = num229;
																																																													}
																																																													else
																																																													{
																																																														num229 = num226;
																																																														num230 = num229;
																																																													}
																																																													num = num229 ^ num228;
																																																												}
																																																											}
																																																											else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x8A5D ^ 0x8BE8]))
																																																											{
																																																												num = -1542303356;
																																																												num231 = num;
																																																											}
																																																											else
																																																											{
																																																												num = -1123307722;
																																																												num231 = num;
																																																											}
																																																										}
																																																										else
																																																										{
																																																											int[] array41 = new int[7];
																																																											array41[0] = 717832115;
																																																											array41[1] = 1813724854;
																																																											array41[2] = -670409711;
																																																											array41[3] = -1969787707;
																																																											array41[4] = -1632532090;
																																																											array41[5] = 2093754333;
																																																											array41[6] = 681854867;
																																																											array41[0] = array41[4] ^ -471350528;
																																																											array41[0] = array41[5] ^ -1356342169;
																																																											array41[4] = array41[6] ^ -439804910;
																																																											int[] array42 = new int[4] { 178836449, 304930898, -2102031880, -1754108424 };
																																																											int[][] array43 = new int[2][] { array41, array42 };
																																																											array42[0] = array43[0][6] ^ 0x36C3E751;
																																																											array42[3] = array42[1] ^ 0x60573BF;
																																																											array42[1] ^= -1661488126;
																																																											array42[1] = array42[0] ^ -964442701;
																																																											int num232 = array43[1][0] ^ -2089705869;
																																																											num = (int)((num4 * 230387736) ^ 0x1DF15F50) ^ num232;
																																																										}
																																																									}
																																																									else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-608 + 171)]))
																																																									{
																																																										num = -1197949603;
																																																										num233 = num;
																																																									}
																																																									else
																																																									{
																																																										num = -795290095;
																																																										num233 = num;
																																																									}
																																																								}
																																																								else
																																																								{
																																																									int[,] array44 = new int[4, 3];
																																																									array44[0, 0] = 1765808409;
																																																									array44[0, 1] = 602835253;
																																																									array44[0, 2] = 1205847569;
																																																									array44[1, 0] = -1072887870;
																																																									array44[1, 1] = -773164072;
																																																									array44[1, 2] = -229352382;
																																																									array44[2, 0] = -612208086;
																																																									array44[2, 1] = -377421215;
																																																									array44[2, 2] = -861082169;
																																																									array44[3, 0] = 946568847;
																																																									array44[3, 1] = 336948285;
																																																									array44[3, 2] = 1849341598;
																																																									array44[1, 1] = array44[2, 2] ^ 0xED060AC;
																																																									array44[2, 2] = array44[1, 2] ^ 0x79FA8C8D;
																																																									array44[0, 2] = array44[2, 0] ^ -792522307;
																																																									array44[2, 2] = array44[2, 0] ^ -1492954500;
																																																									int num234 = array44[2, 2] ^ -510189849;
																																																									num = (int)((num4 * 1155730548) ^ 0x3DF84C40) ^ num234;
																																																								}
																																																							}
																																																							else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xA2CE ^ 0xA37D]))
																																																							{
																																																								num = -1207348641;
																																																								num235 = num;
																																																							}
																																																							else
																																																							{
																																																								num = -2118398553;
																																																								num235 = num;
																																																							}
																																																						}
																																																						else
																																																						{
																																																							int[] array45 = new int[5];
																																																							array45[0] = 1505367898;
																																																							array45[1] = -1405292027;
																																																							array45[2] = 744428555;
																																																							array45[3] = 1224359979;
																																																							array45[4] = -1290085798;
																																																							array45[1] = array45[2] ^ 0x5E4522D5;
																																																							array45[1] = array45[0] ^ -526553231;
																																																							array45[3] = array45[0] ^ 0x29D45F2A;
																																																							int[] array46 = new int[5];
																																																							array46[0] = -1846131445;
																																																							array46[1] = 1029702609;
																																																							array46[2] = 1481696332;
																																																							array46[3] = -1614179749;
																																																							array46[4] = 223038522;
																																																							array46[4] = array45[4] ^ -432010474;
																																																							array46[0] = array46[3] ^ 0x52660F61;
																																																							array46[0] = array46[3] ^ 0x3AABD1C4;
																																																							array46[3] = array46[4] ^ -178678644;
																																																							int num236 = array46[4] ^ -934481923;
																																																							num = (int)((num4 * 949872750) ^ 0xAC9C6022u) ^ num236;
																																																						}
																																																					}
																																																					else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x8FE5 ^ 0x8E57]))
																																																					{
																																																						num = -689743386;
																																																						num237 = num;
																																																					}
																																																					else
																																																					{
																																																						num = -1291020801;
																																																						num237 = num;
																																																					}
																																																				}
																																																				else
																																																				{
																																																					int[,] array47 = new int[3, 4];
																																																					array47[0, 0] = -1384634844;
																																																					array47[0, 1] = 1010226971;
																																																					array47[0, 2] = 1710053036;
																																																					array47[0, 3] = -1021852949;
																																																					array47[1, 0] = 1716012763;
																																																					array47[1, 1] = -2143131399;
																																																					array47[1, 2] = 2081629399;
																																																					array47[1, 3] = -1781319071;
																																																					array47[2, 0] = 842484507;
																																																					array47[2, 1] = 1822829844;
																																																					array47[2, 2] = 409592067;
																																																					array47[2, 3] = -1987687616;
																																																					array47[2, 3] = array47[0, 1] ^ -426732947;
																																																					array47[1, 1] = array47[2, 3] ^ 0x5E6DD576;
																																																					array47[1, 2] = array47[2, 1] ^ -418092088;
																																																					array47[2, 0] = array47[2, 2] ^ 0xDF1767C;
																																																					int num238 = array47[2, 0] ^ -2003916338;
																																																					num = (int)((num4 * 2064701478) ^ 0xBD14DE44u) ^ num238;
																																																				}
																																																			}
																																																			else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x11FF ^ 0x104E]))
																																																			{
																																																				num = -344275835;
																																																				num239 = num;
																																																			}
																																																			else
																																																			{
																																																				num = -499874136;
																																																				num239 = num;
																																																			}
																																																		}
																																																		else
																																																		{
																																																			int[] array48 = new int[4];
																																																			array48[0] = 1676944904;
																																																			array48[1] = 637730020;
																																																			array48[2] = 839421480;
																																																			array48[3] = -1890585484;
																																																			array48[3] = array48[2] ^ -1695229863;
																																																			array48[0] = array48[1] ^ -1394923038;
																																																			int[] array49 = new int[6] { 1622152438, 447725623, 674953545, 1761367136, 411691766, -132309815 };
																																																			int[][] array50 = new int[2][] { array48, array49 };
																																																			array49[2] = array50[0][1] ^ -1504944981;
																																																			array49[1] = array49[4] ^ -1543684439;
																																																			array49[4] ^= -1107617443;
																																																			int num240 = array50[1][2] ^ 0x1D589EFE;
																																																			num = (int)((num4 * 1180042480) ^ 0x21BCECC0) ^ num240;
																																																		}
																																																	}
																																																	else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-287 + 198)]))
																																																	{
																																																		num = -577088157;
																																																		num241 = num;
																																																	}
																																																	else
																																																	{
																																																		num = -1112450692;
																																																		num241 = num;
																																																	}
																																																}
																																																else
																																																{
																																																	int[,] array51 = new int[3, 3];
																																																	array51[0, 0] = -643558496;
																																																	array51[0, 1] = -771338612;
																																																	array51[0, 2] = -1389211759;
																																																	array51[1, 0] = 729210983;
																																																	array51[1, 1] = 2109973907;
																																																	array51[1, 2] = -812636819;
																																																	array51[2, 0] = 9093580;
																																																	array51[2, 1] = 862809819;
																																																	array51[2, 2] = 988284933;
																																																	array51[1, 0] = array51[1, 1] ^ -380284440;
																																																	array51[2, 0] = array51[2, 1] ^ -1068496213;
																																																	array51[2, 0] = array51[0, 0] ^ -1907967232;
																																																	int num242 = array51[2, 0] ^ -889940463;
																																																	num = ((int)num4 * -1074112281) ^ 0x53C04E7 ^ num242;
																																																}
																																															}
																																															else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x9034 ^ 0x9184))]))
																																															{
																																																num = -45726704;
																																																num243 = num;
																																															}
																																															else
																																															{
																																																num = -1119873076;
																																																num243 = num;
																																															}
																																														}
																																														else
																																														{
																																															int[,] array52 = new int[4, 3];
																																															array52[0, 0] = 2040189967;
																																															array52[0, 1] = -1698251148;
																																															array52[0, 2] = 1237164740;
																																															array52[1, 0] = -1951797521;
																																															array52[1, 1] = -1540516846;
																																															array52[1, 2] = -1817247429;
																																															array52[2, 0] = 1409592904;
																																															array52[2, 1] = -1283054436;
																																															array52[2, 2] = -1352086526;
																																															array52[3, 0] = -766972066;
																																															array52[3, 1] = 281046465;
																																															array52[3, 2] = -1593403936;
																																															array52[2, 2] = array52[0, 2] ^ -1696794823;
																																															array52[0, 0] = array52[2, 1] ^ -1076481833;
																																															array52[3, 0] = array52[2, 0] ^ 0x6E6E01EA;
																																															array52[1, 1] = array52[1, 0] ^ 0x358FF63F;
																																															int num244 = array52[1, 1] ^ 0x23302661;
																																															num = ((int)num4 * -1890580808) ^ -780703448 ^ num244;
																																														}
																																													}
																																													else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(443 + sizeof(int)) ^ sizeof(Guid)]))
																																													{
																																														num = -2101885326;
																																														num245 = num;
																																													}
																																													else
																																													{
																																														num = -971856747;
																																														num245 = num;
																																													}
																																												}
																																												else
																																												{
																																													int[,] array53 = new int[4, 4];
																																													array53[0, 0] = 922069085;
																																													array53[0, 1] = -250705802;
																																													array53[0, 2] = 663741719;
																																													array53[0, 3] = 658841882;
																																													array53[1, 0] = -1431170469;
																																													array53[1, 1] = -925762005;
																																													array53[1, 2] = 1323998819;
																																													array53[1, 3] = -1339983803;
																																													array53[2, 0] = 673528909;
																																													array53[2, 1] = -898824990;
																																													array53[2, 2] = 1221344112;
																																													array53[2, 3] = 2038988739;
																																													array53[3, 0] = 1886204491;
																																													array53[3, 1] = 1116395497;
																																													array53[3, 2] = -1457383732;
																																													array53[3, 3] = 300753843;
																																													array53[0, 2] = array53[3, 0] ^ -219167030;
																																													array53[0, 0] = array53[3, 0] ^ -1493916820;
																																													array53[2, 3] = array53[1, 2] ^ -1343252820;
																																													array53[2, 1] = array53[0, 3] ^ 0x45A83548;
																																													int num246 = array53[2, 1] ^ -316701;
																																													num = (int)((num4 * 910166096) ^ 0x317883D0) ^ num246;
																																												}
																																											}
																																											else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x52E2 ^ 0x534C]))
																																											{
																																												num = -1793383864;
																																												num247 = num;
																																											}
																																											else
																																											{
																																												num = -1703042450;
																																												num247 = num;
																																											}
																																										}
																																										else
																																										{
																																											int[] array54 = new int[5];
																																											array54[0] = 1322552690;
																																											array54[1] = 1763033938;
																																											array54[2] = -85981038;
																																											array54[3] = -1302183748;
																																											array54[4] = 2105887013;
																																											array54[1] = array54[4] ^ -1019659795;
																																											array54[2] = array54[3] ^ -1095359452;
																																											int[] array55 = new int[4];
																																											array55[0] = 878472827;
																																											array55[1] = -1325945573;
																																											array55[2] = -1466467292;
																																											array55[3] = -1759934258;
																																											array55[0] = array54[3] ^ -658582791;
																																											array55[1] = array55[3] ^ 0x562FF61E;
																																											array55[2] = array55[0] ^ 0x58CF0571;
																																											array55[1] = array55[2] ^ 0x5C4F555A;
																																											int num248 = array55[0] ^ -137712396;
																																											num = ((int)num4 * -2089069260) ^ -1998820688 ^ num248;
																																										}
																																									}
																																									else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x11E4 ^ 0x1049]))
																																									{
																																										num = -2018537653;
																																										num249 = num;
																																									}
																																									else
																																									{
																																										num = -1191557454;
																																										num249 = num;
																																									}
																																								}
																																								else
																																								{
																																									int[,] array56 = new int[4, 4];
																																									array56[0, 0] = 543395234;
																																									array56[0, 1] = 570284789;
																																									array56[0, 2] = -1074590004;
																																									array56[0, 3] = 1847321791;
																																									array56[1, 0] = 1676153890;
																																									array56[1, 1] = 397264058;
																																									array56[1, 2] = -1132355774;
																																									array56[1, 3] = -2000500906;
																																									array56[2, 0] = 307330698;
																																									array56[2, 1] = -2092750790;
																																									array56[2, 2] = -892081978;
																																									array56[2, 3] = -1747542026;
																																									array56[3, 0] = 897457277;
																																									array56[3, 1] = 917018455;
																																									array56[3, 2] = 1482371266;
																																									array56[3, 3] = -1806309107;
																																									array56[0, 0] = array56[0, 2] ^ -244044251;
																																									array56[1, 1] ^= -1913666142;
																																									array56[1, 2] = array56[0, 2] ^ 0x212D9F7;
																																									int num250 = array56[1, 2] ^ 0x20F7E98A;
																																									num = ((int)num4 * -1124160548) ^ -985810972 ^ num250;
																																								}
																																							}
																																							else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xA3B ^ 0xB97]))
																																							{
																																								num = -389664098;
																																								num251 = num;
																																							}
																																							else
																																							{
																																								num = -1472602507;
																																								num251 = num;
																																							}
																																						}
																																						else
																																						{
																																							int[] array57 = new int[4];
																																							array57[0] = 224963573;
																																							array57[1] = 1215253777;
																																							array57[2] = 2028448958;
																																							array57[3] = 1101850002;
																																							array57[0] = array57[1] ^ 0x11F8BD07;
																																							array57[2] = array57[0] ^ -561185580;
																																							array57[3] = array57[0] ^ -707922553;
																																							int[] array58 = new int[6];
																																							array58[0] = -645755132;
																																							array58[1] = -1053876633;
																																							array58[2] = 1074937413;
																																							array58[3] = 976273271;
																																							array58[4] = -445610346;
																																							array58[5] = -546277766;
																																							array58[3] = array57[1] ^ 0x724B2C22;
																																							array58[0] = array58[2] ^ 0x58027D95;
																																							array58[0] = array58[5] ^ -288918026;
																																							array58[1] = array58[0] ^ -1325120194;
																																							int num252 = array58[3] ^ -1489870974;
																																							num = (int)((num4 * 1569999758) ^ 0x92D0A2DCu) ^ num252;
																																						}
																																					}
																																					else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x6E3 ^ 0x748]))
																																					{
																																						num = -120882383;
																																						num253 = num;
																																					}
																																					else
																																					{
																																						num = -1643327780;
																																						num253 = num;
																																					}
																																				}
																																				else
																																				{
																																					int[] array59 = new int[7];
																																					array59[0] = 656473327;
																																					array59[1] = -37345706;
																																					array59[2] = -1139517832;
																																					array59[3] = -341338940;
																																					array59[4] = -1291862191;
																																					array59[5] = 126932412;
																																					array59[6] = -1954802636;
																																					array59[1] = array59[4] ^ -757409920;
																																					array59[1] = array59[4] ^ 0x2BFA00A7;
																																					int[] array60 = new int[6] { 1928751182, -297498736, -1229303838, 1548549592, -778075695, -2126871255 };
																																					int[][] array61 = new int[2][] { array59, array60 };
																																					array60[4] = array61[0][6] ^ 0x8B7F952;
																																					array60[1] = array60[0] ^ 0xF478659;
																																					array60[5] ^= 50520234;
																																					int num254 = array61[1][4] ^ 0x1EDDD3D7;
																																					num = ((int)num4 * -638260775) ^ -1845158410 ^ num254;
																																				}
																																			}
																																			else if (!_002A_0028_002B_0024_003D_0028_003C_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xBA3 ^ 0xBB5]))
																																			{
																																				num = -951435787;
																																				num255 = num;
																																			}
																																			else
																																			{
																																				num = -2006336862;
																																				num255 = num;
																																			}
																																		}
																																		else
																																		{
																																			int[] array62 = new int[7];
																																			array62[0] = -900062397;
																																			array62[1] = 26169515;
																																			array62[2] = 904793568;
																																			array62[3] = 1390559785;
																																			array62[4] = 2125567615;
																																			array62[5] = 1253731779;
																																			array62[6] = 749819494;
																																			array62[5] = array62[1] ^ 0x1E623DF3;
																																			array62[2] = array62[1] ^ -1556162518;
																																			int[] array63 = new int[6];
																																			array63[0] = -1815167428;
																																			array63[1] = -854993304;
																																			array63[2] = 625515206;
																																			array63[3] = 1144409218;
																																			array63[4] = -767180620;
																																			array63[5] = -1046996968;
																																			array63[0] = array62[6] ^ -444765234;
																																			array63[2] = array63[5] ^ 0x57699F4;
																																			array63[4] = array63[2] ^ 0x15B9B672;
																																			int num256 = array63[0] ^ 0x54DA0319;
																																			num = (int)((num4 * 804606152) ^ 0xC4B15C90u) ^ num256;
																																		}
																																	}
																																	else
																																	{
																																		char num257 = c;
																																		int[,] array64 = new int[4, 3];
																																		array64[0, 0] = 1365747822;
																																		array64[0, 1] = -1397032290;
																																		array64[0, 2] = 1890703825;
																																		array64[1, 0] = 1714101509;
																																		array64[1, 1] = -1333348123;
																																		array64[1, 2] = 1061607191;
																																		array64[2, 0] = -480196122;
																																		array64[2, 1] = 963330987;
																																		array64[2, 2] = 1247808566;
																																		array64[3, 0] = 1664621227;
																																		array64[3, 1] = -592822386;
																																		array64[3, 2] = 31296379;
																																		array64[3, 1] = array64[1, 2] ^ -2141214676;
																																		array64[3, 2] ^= 1044850004;
																																		array64[1, 0] = array64[0, 2] ^ -1264283148;
																																		int num258 = array64[1, 0] ^ 0x1585DB67;
																																		int[,] array65 = new int[3, 4];
																																		array65[0, 0] = 1008931834;
																																		array65[0, 1] = 441794328;
																																		array65[0, 2] = -400035524;
																																		array65[0, 3] = 1895083389;
																																		array65[1, 0] = 717142095;
																																		array65[1, 1] = 145689818;
																																		array65[1, 2] = -1867017463;
																																		array65[1, 3] = 683509835;
																																		array65[2, 0] = 1263593942;
																																		array65[2, 1] = -310672336;
																																		array65[2, 2] = -1503744763;
																																		array65[2, 3] = 1641329554;
																																		array65[2, 1] = array65[0, 1] ^ -1145677948;
																																		array65[2, 2] = array65[0, 3] ^ -947243237;
																																		array65[0, 1] = array65[2, 3] ^ -1219637953;
																																		int num259 = array65[0, 1] ^ 0x553F70DC;
																																		int num260 = ((int)num4 * -26619531) ^ 0x7EC4C852;
																																		num258 ^= num260;
																																		num259 ^= num260;
																																		int num261;
																																		int num262;
																																		if (num257 != 'n')
																																		{
																																			num261 = num259;
																																			num262 = num261;
																																		}
																																		else
																																		{
																																			num261 = num258;
																																			num262 = num261;
																																		}
																																		num = num261 ^ num260;
																																	}
																																}
																																else
																																{
																																	char num263 = c;
																																	int[,] array66 = new int[3, 3];
																																	array66[0, 0] = 1241859058;
																																	array66[0, 1] = -1550213694;
																																	array66[0, 2] = 1326918023;
																																	array66[1, 0] = 1461516086;
																																	array66[1, 1] = 1246608874;
																																	array66[1, 2] = -473134624;
																																	array66[2, 0] = 1970843204;
																																	array66[2, 1] = -2076154364;
																																	array66[2, 2] = -90260688;
																																	array66[2, 1] = array66[1, 1] ^ -650851796;
																																	array66[0, 2] = array66[0, 1] ^ -1948590293;
																																	array66[2, 0] = array66[1, 2] ^ -784879171;
																																	int num264 = array66[2, 0] ^ -643579863;
																																	int[,] array67 = new int[3, 3];
																																	array67[0, 0] = 1759235099;
																																	array67[0, 1] = -483284566;
																																	array67[0, 2] = 1693065406;
																																	array67[1, 0] = 1864401842;
																																	array67[1, 1] = 231941155;
																																	array67[1, 2] = -2046257453;
																																	array67[2, 0] = -671479764;
																																	array67[2, 1] = -1426009660;
																																	array67[2, 2] = -1879393437;
																																	array67[0, 2] = array67[0, 1] ^ 0x51D3238E;
																																	array67[1, 1] = array67[2, 0] ^ -1091220760;
																																	array67[1, 1] = array67[1, 0] ^ 0x4C02F89A;
																																	array67[1, 2] = array67[2, 2] ^ -1908828317;
																																	int num265 = array67[1, 2] ^ -520673575;
																																	int num266 = (int)(num4 * 1031000682) ^ -408503114;
																																	num264 ^= num266;
																																	num265 ^= num266;
																																	int num267;
																																	int num268;
																																	if (num263 != 'l')
																																	{
																																		num267 = num265;
																																		num268 = num267;
																																	}
																																	else
																																	{
																																		num267 = num264;
																																		num268 = num267;
																																	}
																																	num = num267 ^ num266;
																																}
																															}
																															else if (c != 'c')
																															{
																																num = -51405986;
																																num269 = num;
																															}
																															else
																															{
																																num = -1668037548;
																																num269 = num;
																															}
																														}
																														else
																														{
																															int[] array68 = new int[5] { 693386556, -24543349, -494802769, 1728867006, -1445188054 };
																															array68[3] ^= 995061981;
																															array68[0] = array68[2] ^ 0x724D371;
																															int[] array69 = new int[7];
																															array69[0] = -1237723003;
																															array69[1] = 1105581314;
																															array69[2] = 491064943;
																															array69[3] = 1244185100;
																															array69[4] = -1184138317;
																															array69[5] = -1373952539;
																															array69[6] = 671265798;
																															array69[0] = array68[1] ^ -1805739150;
																															array69[3] = array69[6] ^ -648587843;
																															array69[5] = array69[0] ^ 0x331D3D05;
																															int num270 = array69[0] ^ -138290616;
																															num = (int)((num4 * 995027453) ^ 0x303698BF) ^ num270;
																														}
																													}
																													else
																													{
																														char num271 = c;
																														int[] array70 = new int[4];
																														array70[0] = 2005936892;
																														array70[1] = -836235486;
																														array70[2] = -41323429;
																														array70[3] = -675179893;
																														array70[3] = array70[1] ^ 0xD330F97;
																														array70[2] = array70[1] ^ -972428167;
																														int[] array71 = new int[7] { 814802042, -664342767, 1402033737, 1752890458, 1398229878, -1890868291, 2029055664 };
																														int[][] array72 = new int[2][] { array70, array71 };
																														array71[3] = array72[0][0] ^ 0xCCA5CDA;
																														array71[1] = array71[6] ^ 0x60E54720;
																														array71[5] = array71[1] ^ -1373899521;
																														int num272 = array72[1][3] ^ -1777109942;
																														int[] array73 = new int[6] { -649114563, -1838963100, -797186986, -319358522, -1660660038, -479788722 };
																														array73[0] ^= 1359516672;
																														array73[3] = array73[2] ^ -2088663794;
																														int[] array74 = new int[6];
																														array74[0] = -2145279503;
																														array74[1] = -2126722080;
																														array74[2] = -1013430168;
																														array74[3] = -1487709825;
																														array74[4] = 841698977;
																														array74[5] = 1207281385;
																														array74[2] = array73[5] ^ -1762604249;
																														array74[4] = array74[1] ^ 0x403D14C4;
																														array74[3] ^= 2017199555;
																														array74[5] ^= -1382302820;
																														int num273 = array74[2] ^ -1924708845;
																														int num274 = (int)((num4 * 1141128796) ^ 0x5F4E755C);
																														num272 ^= num274;
																														num273 ^= num274;
																														int num275;
																														int num276;
																														if (num271 != '6')
																														{
																															num275 = num273;
																															num276 = num275;
																														}
																														else
																														{
																															num275 = num272;
																															num276 = num275;
																														}
																														num = num275 ^ num274;
																													}
																												}
																												else
																												{
																													char num277 = c;
																													int[] array75 = new int[6] { 1903700870, 1459459776, -871243826, -1566601716, 287169316, 1122489291 };
																													array75[4] ^= -1688035077;
																													array75[5] ^= -756170856;
																													int[] array76 = new int[4];
																													array76[0] = -1350980407;
																													array76[1] = 1097803766;
																													array76[2] = 807914556;
																													array76[3] = -980104845;
																													array76[0] = array75[0] ^ -921659960;
																													array76[3] = array76[1] ^ -1477921411;
																													array76[2] = array76[3] ^ -413544565;
																													array76[2] = array76[3] ^ 0x57FA6F54;
																													int num278 = array76[0] ^ 0x43F7D965;
																													int[] array77 = new int[5];
																													array77[0] = -1762793530;
																													array77[1] = 1436675338;
																													array77[2] = -610396581;
																													array77[3] = 1337730808;
																													array77[4] = -1235463831;
																													array77[4] = array77[2] ^ 0x435D96FE;
																													array77[0] = array77[2] ^ 0x16845A2;
																													array77[1] = array77[4] ^ 0x5ECCA5DD;
																													int[] array78 = new int[6];
																													array78[0] = -116774955;
																													array78[1] = -1134074131;
																													array78[2] = -161773208;
																													array78[3] = 91737725;
																													array78[4] = 979829552;
																													array78[5] = -801031137;
																													array78[0] = array77[3] ^ -1266625238;
																													array78[1] ^= -1111763176;
																													array78[4] = array78[0] ^ 0x1DF57B55;
																													array78[4] = array78[3] ^ 0x6FDDAAA3;
																													int num279 = array78[0] ^ 0xFDE5B82;
																													int num280 = ((int)num4 * -1280586852) ^ 0x1A617D14;
																													num278 ^= num280;
																													num279 ^= num280;
																													int num281;
																													int num282;
																													if (num277 != '3')
																													{
																														num281 = num279;
																														num282 = num281;
																													}
																													else
																													{
																														num281 = num278;
																														num282 = num281;
																													}
																													num = num281 ^ num280;
																												}
																											}
																											else
																											{
																												char num283 = c;
																												int[,] array79 = new int[4, 4];
																												array79[0, 0] = -819260526;
																												array79[0, 1] = -829680187;
																												array79[0, 2] = -2135204745;
																												array79[0, 3] = -756313476;
																												array79[1, 0] = 2015894666;
																												array79[1, 1] = -295653722;
																												array79[1, 2] = -1839636178;
																												array79[1, 3] = 1511571883;
																												array79[2, 0] = 567291253;
																												array79[2, 1] = 1590985352;
																												array79[2, 2] = 1988755797;
																												array79[2, 3] = 350790052;
																												array79[3, 0] = 422677415;
																												array79[3, 1] = 98412280;
																												array79[3, 2] = -875860607;
																												array79[3, 3] = -201990453;
																												array79[0, 0] = array79[3, 2] ^ -242823873;
																												array79[3, 1] = array79[1, 3] ^ -1323246038;
																												array79[0, 1] = array79[1, 0] ^ -1650313613;
																												array79[0, 0] = array79[1, 0] ^ -1499747744;
																												int num284 = array79[0, 0] ^ 0x53705D99;
																												int[] array80 = new int[5];
																												array80[0] = 1887497175;
																												array80[1] = -746027340;
																												array80[2] = 1533692122;
																												array80[3] = 616894224;
																												array80[4] = -822150358;
																												array80[2] = array80[1] ^ -464352773;
																												array80[0] ^= 269422193;
																												array80[3] = array80[1] ^ -738367637;
																												int[] array81 = new int[7] { 456889958, -736011507, -1972023978, -512898340, -581069272, 616498983, -216229656 };
																												int[][] array82 = new int[2][] { array80, array81 };
																												array81[0] = array82[0][1] ^ -1321253650;
																												array81[6] = array81[3] ^ 0x3A0B66EC;
																												array81[3] = array81[5] ^ -213804527;
																												int num285 = array82[1][0] ^ -439553864;
																												int num286 = ((int)num4 * -860823692) ^ 0x234C3800;
																												num284 ^= num286;
																												num285 ^= num286;
																												int num287;
																												int num288;
																												if (num283 != '1')
																												{
																													num287 = num285;
																													num288 = num287;
																												}
																												else
																												{
																													num287 = num284;
																													num288 = num287;
																												}
																												num = num287 ^ num286;
																											}
																											continue;
																										}
																										goto IL_a9c9;
																									}
																									int[] array83 = new int[4];
																									array83[0] = -1195583521;
																									array83[1] = 1671929845;
																									array83[2] = -1092083135;
																									array83[3] = -75489990;
																									array83[2] = array83[0] ^ 0x756D82DD;
																									array83[2] ^= -465837908;
																									int[] array84 = new int[4];
																									array84[0] = -310227904;
																									array84[1] = -1138906199;
																									array84[2] = -1285637692;
																									array84[3] = 517637025;
																									array84[3] = array83[0] ^ 0x5552C123;
																									array84[0] = array84[2] ^ -1585305767;
																									array84[1] = array84[0] ^ 0x2AA0A5EA;
																									array84[0] ^= 1904318308;
																									int num289 = array84[3] ^ 0x70F8284D;
																									num = (int)((num4 * 157420113) ^ 0x48123C0F) ^ num289;
																									continue;
																								}
																								char num290 = c;
																								int[] array85 = new int[6];
																								array85[0] = 1745749327;
																								array85[1] = 1066578295;
																								array85[2] = 1197342788;
																								array85[3] = 844096807;
																								array85[4] = -174700201;
																								array85[5] = -186885855;
																								array85[3] = array85[4] ^ 0x4DAD1FB2;
																								array85[3] = array85[2] ^ -575010055;
																								int[] array86 = new int[6] { -1412260492, -349654196, -849889596, 293974344, -1903556353, -144896758 };
																								int[][] array87 = new int[2][] { array85, array86 };
																								array86[0] = array87[0][2] ^ -1016489171;
																								array86[5] = array86[0] ^ -914328193;
																								array86[2] = array86[1] ^ -1161397240;
																								array86[4] ^= -1542777395;
																								int num291 = array87[1][0] ^ 0x29B3BD7;
																								int[] array88 = new int[7];
																								array88[0] = 777044545;
																								array88[1] = -285397294;
																								array88[2] = -423647835;
																								array88[3] = -1747335582;
																								array88[4] = 1768720287;
																								array88[5] = -1551103329;
																								array88[6] = 1710745452;
																								array88[2] = array88[5] ^ -2134782043;
																								array88[1] = array88[2] ^ 0x62B1E4B3;
																								int[] array89 = new int[5];
																								array89[0] = 215551046;
																								array89[1] = 881669158;
																								array89[2] = 1166131041;
																								array89[3] = 331945555;
																								array89[4] = 1351540678;
																								array89[1] = array88[0] ^ -1186824784;
																								array89[2] = array89[1] ^ 0x27491B5A;
																								array89[2] = array89[0] ^ 0x548D068C;
																								int num292 = array89[1] ^ 0x3C6C67BF;
																								int num293 = ((int)num4 * -332945465) ^ 0x49A6C702;
																								num291 ^= num293;
																								num292 ^= num293;
																								int num294;
																								int num295;
																								if (num290 != 't')
																								{
																									num294 = num292;
																									num295 = num294;
																								}
																								else
																								{
																									num294 = num291;
																									num295 = num294;
																								}
																								num = num294 ^ num293;
																								continue;
																							}
																							int num296;
																							if (c != '6')
																							{
																								num = -516823811;
																								num296 = num;
																							}
																							else
																							{
																								num = -1862921700;
																								num296 = num;
																							}
																							continue;
																						}
																						int[] array90 = new int[6];
																						array90[0] = 1136322044;
																						array90[1] = 1693525297;
																						array90[2] = 633196627;
																						array90[3] = 2108591306;
																						array90[4] = 305320878;
																						array90[5] = 1975741099;
																						array90[1] = array90[5] ^ -1191451005;
																						array90[1] ^= -100121075;
																						int[] array91 = new int[5];
																						array91[0] = 1541710608;
																						array91[1] = 200954936;
																						array91[2] = -1226576815;
																						array91[3] = 910674091;
																						array91[4] = -1553276670;
																						array91[1] = array90[3] ^ -1791568168;
																						array91[3] ^= 335844877;
																						array91[4] = array91[2] ^ -202007829;
																						int num297 = array91[1] ^ 0x758E64A3;
																						num = ((int)num4 * -87247019) ^ 0x3BB8C4F1 ^ num297;
																						continue;
																					}
																					char num298 = c;
																					int[] array92 = new int[7];
																					array92[0] = -1823478670;
																					array92[1] = -1489475400;
																					array92[2] = -201755122;
																					array92[3] = 1822208871;
																					array92[4] = 1616722917;
																					array92[5] = -1391110266;
																					array92[6] = -1262572997;
																					array92[1] = array92[2] ^ -791528808;
																					array92[5] = array92[4] ^ 0x33D832E2;
																					int[] array93 = new int[6];
																					array93[0] = 1174089958;
																					array93[1] = -128419275;
																					array93[2] = 792553868;
																					array93[3] = -442610275;
																					array93[4] = 1531480113;
																					array93[5] = 358917898;
																					array93[0] = array92[2] ^ -237863151;
																					array93[4] ^= -1969412791;
																					array93[1] = array93[0] ^ -2029874370;
																					array93[3] = array93[1] ^ -1741463795;
																					int num299 = array93[0] ^ -11172546;
																					int[] array94 = new int[6] { 952879902, -357484072, 1286591926, 2147412078, 6856111, 1393912742 };
																					array94[1] ^= -388648545;
																					array94[2] = array94[1] ^ -831727880;
																					array94[0] = array94[3] ^ -1994809723;
																					int[] array95 = new int[4];
																					array95[0] = -30462813;
																					array95[1] = -93527313;
																					array95[2] = -422947950;
																					array95[3] = -2050426208;
																					array95[2] = array94[3] ^ -1564787880;
																					array95[1] ^= 2095976617;
																					array95[3] = array95[1] ^ -1694610698;
																					array95[0] ^= -166224158;
																					int num300 = array95[2] ^ 0x29F8BC0A;
																					int num301 = ((int)num4 * -2121339301) ^ 0x25904789;
																					num299 ^= num301;
																					num300 ^= num301;
																					int num302;
																					int num303;
																					if (num298 != '3')
																					{
																						num302 = num300;
																						num303 = num302;
																					}
																					else
																					{
																						num302 = num299;
																						num303 = num302;
																					}
																					num = num302 ^ num301;
																					continue;
																				}
																				char num304 = c;
																				int[] array96 = new int[4];
																				array96[0] = -309821740;
																				array96[1] = -1032630728;
																				array96[2] = 2132073348;
																				array96[3] = -1042529379;
																				array96[3] = array96[0] ^ 0xF0DE927;
																				array96[2] = array96[0] ^ -1765045080;
																				array96[3] = array96[1] ^ -1256415240;
																				int[] array97 = new int[4] { -439074023, 693163253, 2089105504, -153101382 };
																				int[][] array98 = new int[2][] { array96, array97 };
																				array97[0] = array98[0][0] ^ -1734916597;
																				array97[2] = array97[3] ^ -1816274302;
																				array97[1] = array97[0] ^ 0x28207572;
																				int num305 = array98[1][0] ^ -759978251;
																				int[] array99 = new int[6] { -1494025123, 1504132649, 488421135, -1048520374, -1832091065, 479363835 };
																				array99[5] ^= 594016678;
																				array99[5] = array99[2] ^ 0x20A2A7AF;
																				int[] array100 = new int[4] { -995464135, 1016238774, -1069227170, -1827171741 };
																				int[][] array101 = new int[2][] { array99, array100 };
																				array100[3] = array101[0][0] ^ -1689613995;
																				array100[1] = array100[3] ^ 0x7B5B6E18;
																				array100[1] = array100[2] ^ -934505995;
																				int num306 = array101[1][3] ^ -1751200782;
																				int num307 = ((int)num4 * -1570595747) ^ 0x6BF74AF1;
																				num305 ^= num307;
																				num306 ^= num307;
																				int num308;
																				int num309;
																				if (num304 != '1')
																				{
																					num308 = num306;
																					num309 = num308;
																				}
																				else
																				{
																					num308 = num305;
																					num309 = num308;
																				}
																				num = num308 ^ num307;
																				continue;
																			}
																			char num310 = c;
																			int[,] array102 = new int[3, 4];
																			array102[0, 0] = -1011621839;
																			array102[0, 1] = -1019172399;
																			array102[0, 2] = -830588520;
																			array102[0, 3] = 323696760;
																			array102[1, 0] = 1724665516;
																			array102[1, 1] = -927657082;
																			array102[1, 2] = -1411312435;
																			array102[1, 3] = 464301456;
																			array102[2, 0] = -1138011603;
																			array102[2, 1] = 1278676883;
																			array102[2, 2] = -103737965;
																			array102[2, 3] = 364370505;
																			array102[0, 2] = array102[0, 0] ^ -382604136;
																			array102[0, 1] = array102[1, 1] ^ -863835730;
																			array102[1, 1] = array102[0, 0] ^ -537629545;
																			int num311 = array102[1, 1] ^ -1343315403;
																			int[] array103 = new int[4] { 2141381594, 1344568260, 526217254, -1369809189 };
																			array103[1] ^= 877976214;
																			array103[3] ^= -73843169;
																			array103[2] = array103[0] ^ 0x44493EAE;
																			int[] array104 = new int[5] { -2001617811, -2025051657, -1994567667, -1449598990, 1763414586 };
																			int[][] array105 = new int[2][] { array103, array104 };
																			array104[2] = array105[0][0] ^ -929656408;
																			array104[1] = array104[4] ^ 0x15C642DC;
																			array104[3] = array104[4] ^ -1880200306;
																			array104[3] ^= 562942455;
																			int num312 = array105[1][2] ^ 0x50A71DC6;
																			int num313 = ((int)num4 * -1566201139) ^ -179123160;
																			num311 ^= num313;
																			num312 ^= num313;
																			int num314;
																			int num315;
																			if ((uint)num310 <= 51u)
																			{
																				num314 = num312;
																				num315 = num314;
																			}
																			else
																			{
																				num314 = num311;
																				num315 = num314;
																			}
																			num = num314 ^ num313;
																			continue;
																		}
																		int[] array106 = new int[7];
																		array106[0] = -2129820717;
																		array106[1] = 832857249;
																		array106[2] = -1881015283;
																		array106[3] = 1391743036;
																		array106[4] = -355398878;
																		array106[5] = 1622232696;
																		array106[6] = 1744762958;
																		array106[5] = array106[4] ^ 0x37DB34CC;
																		array106[5] = array106[2] ^ 0x2856AA1;
																		array106[2] = array106[5] ^ 0x6E2579B0;
																		int[] array107 = new int[5];
																		array107[0] = 1531084213;
																		array107[1] = 1062719260;
																		array107[2] = -1304284772;
																		array107[3] = -1699804312;
																		array107[4] = 1836986636;
																		array107[2] = array106[3] ^ -936540296;
																		array107[3] = array107[0] ^ 0x8963055;
																		array107[1] = array107[4] ^ -1784333335;
																		int num316 = array107[2] ^ 0x7CFE9F5;
																		num = (int)((num4 * 968734471) ^ 0x70C55C9E) ^ num316;
																		continue;
																	}
																	char num317 = c;
																	int[,] array108 = new int[4, 4];
																	array108[0, 0] = 1051602245;
																	array108[0, 1] = 1996071321;
																	array108[0, 2] = -445672007;
																	array108[0, 3] = -1487667103;
																	array108[1, 0] = 1015022563;
																	array108[1, 1] = 422958181;
																	array108[1, 2] = 396452916;
																	array108[1, 3] = -813956115;
																	array108[2, 0] = 382026634;
																	array108[2, 1] = 1068009140;
																	array108[2, 2] = -103926471;
																	array108[2, 3] = -1287648096;
																	array108[3, 0] = -385708660;
																	array108[3, 1] = 675982199;
																	array108[3, 2] = 999170529;
																	array108[3, 3] = 2000218453;
																	array108[3, 3] = array108[3, 2] ^ -545244261;
																	array108[1, 2] = array108[2, 3] ^ -1144598672;
																	array108[2, 0] = array108[2, 3] ^ -145084893;
																	int num318 = array108[2, 0] ^ -1490317418;
																	int[] array109 = new int[4];
																	array109[0] = -1470792310;
																	array109[1] = -589536834;
																	array109[2] = 1521574860;
																	array109[3] = -1847895841;
																	array109[3] = array109[0] ^ -1101422707;
																	array109[3] = array109[0] ^ -865998176;
																	int[] array110 = new int[5];
																	array110[0] = -1652678375;
																	array110[1] = 1346019107;
																	array110[2] = 691740213;
																	array110[3] = -865300302;
																	array110[4] = 734301260;
																	array110[0] = array109[1] ^ -262748414;
																	array110[2] ^= 1191809892;
																	array110[4] = array110[0] ^ 0x49A177EA;
																	int num319 = array110[0] ^ -1490846115;
																	int num320 = ((int)num4 * -2119859116) ^ 0x2B68A50C;
																	num318 ^= num320;
																	num319 ^= num320;
																	int num321;
																	int num322;
																	if (num317 != 'V')
																	{
																		num321 = num319;
																		num322 = num321;
																	}
																	else
																	{
																		num321 = num318;
																		num322 = num321;
																	}
																	num = num321 ^ num320;
																	continue;
																}
																char num323 = c;
																int[] array111 = new int[4] { -361052825, -1324349210, -1288600441, -1458506047 };
																array111[3] ^= -704881002;
																array111[3] ^= 58153458;
																array111[2] ^= 1015333176;
																int[] array112 = new int[7] { 1132786811, -1023921461, 2121003227, -1131979639, -1809707066, 2073634724, -1366667139 };
																int[][] array113 = new int[2][] { array111, array112 };
																array112[6] = array113[0][0] ^ 0x1A6085F0;
																array112[3] = array112[5] ^ -500601715;
																array112[5] = array112[2] ^ -391098082;
																int num324 = array113[1][6] ^ 0x62CBBDA8;
																int[,] array114 = new int[4, 3];
																array114[0, 0] = -114822215;
																array114[0, 1] = -1391865965;
																array114[0, 2] = -1840329829;
																array114[1, 0] = -318171054;
																array114[1, 1] = -831943649;
																array114[1, 2] = 1343275520;
																array114[2, 0] = 1505860849;
																array114[2, 1] = -1416983994;
																array114[2, 2] = -1552593102;
																array114[3, 0] = 932068538;
																array114[3, 1] = 924144117;
																array114[3, 2] = 866850698;
																array114[0, 1] = array114[2, 2] ^ 0x494C1AC9;
																array114[3, 2] = array114[3, 1] ^ -392483812;
																array114[0, 1] = array114[2, 0] ^ 0x461C0C4F;
																int num325 = array114[0, 1] ^ -124803496;
																int num326 = (int)((num4 * 387652975) ^ 0x429B152B);
																num324 ^= num326;
																num325 ^= num326;
																int num327;
																int num328;
																if (num323 != 'C')
																{
																	num327 = num325;
																	num328 = num327;
																}
																else
																{
																	num327 = num324;
																	num328 = num327;
																}
																num = num327 ^ num326;
																continue;
															}
															char num329 = c;
															int[] array115 = new int[5];
															array115[0] = 1662043566;
															array115[1] = -1379105800;
															array115[2] = 1788659128;
															array115[3] = -297311546;
															array115[4] = 1142106078;
															array115[1] = array115[3] ^ -418284719;
															array115[4] ^= 91872013;
															array115[2] = array115[3] ^ 0x5B5F7F29;
															int[] array116 = new int[6] { -1386770085, 5178942, 451915721, -48047936, 1998353338, 850261029 };
															int[][] array117 = new int[2][] { array115, array116 };
															array116[1] = array117[0][0] ^ -1118061771;
															array116[2] = array116[4] ^ -353906326;
															array116[3] = array116[2] ^ -771011724;
															int num330 = array117[1][1] ^ 0x6DC84DD4;
															int[] array118 = new int[5];
															array118[0] = 816994827;
															array118[1] = -1750171357;
															array118[2] = -1677415107;
															array118[3] = 1071569166;
															array118[4] = 1029311739;
															array118[0] = array118[3] ^ -731989635;
															array118[1] = array118[2] ^ 0x6350C0A2;
															array118[3] = array118[0] ^ 0x37A647AD;
															int[] array119 = new int[6] { -1774484598, 754847844, -2118343371, 1369744945, 808862124, -317453109 };
															int[][] array120 = new int[2][] { array118, array119 };
															array119[1] = array120[0][2] ^ -712257434;
															array119[4] = array119[1] ^ 0x7A7FCB04;
															array119[3] ^= 1508914160;
															int num331 = array120[1][1] ^ -1426992305;
															int num332 = (int)((num4 * 2006783994) ^ 0x12359B38);
															num330 ^= num332;
															num331 ^= num332;
															int num333;
															int num334;
															if (num329 != 'B')
															{
																num333 = num331;
																num334 = num333;
															}
															else
															{
																num333 = num330;
																num334 = num333;
															}
															num = num333 ^ num332;
															continue;
														}
														int[] array121 = new int[7] { 1250371826, 217503620, 1903714546, 45889102, 1535564394, -1570840842, 572256512 };
														array121[6] ^= -775386547;
														array121[5] = array121[4] ^ 0x1DDE2612;
														array121[0] = array121[2] ^ -1166920696;
														int[] array122 = new int[4];
														array122[0] = -1250550314;
														array122[1] = 419525099;
														array122[2] = -856506546;
														array122[3] = 212195705;
														array122[3] = array121[2] ^ 0x3E44FD9A;
														array122[0] = array122[3] ^ 0xF6236E5;
														array122[2] = array122[1] ^ -2048970690;
														int num335 = array122[3] ^ -768957479;
														num = ((int)num4 * -977231609) ^ -694880947 ^ num335;
														continue;
													}
													char num336 = c;
													int[] array123 = new int[6] { -1623297767, 1083058430, -1289127006, -114144651, 1815366390, -1587421812 };
													array123[3] ^= 1126789846;
													array123[1] = array123[0] ^ -2144785324;
													int[] array124 = new int[5];
													array124[0] = -48200782;
													array124[1] = 940338555;
													array124[2] = -2038036614;
													array124[3] = 1281769347;
													array124[4] = 1926157098;
													array124[0] = array123[0] ^ -833666438;
													array124[2] = array124[3] ^ -1286987207;
													array124[1] = array124[4] ^ 0x4D5CB3C0;
													int num337 = array124[0] ^ -1802245376;
													int[] array125 = new int[7];
													array125[0] = 1455220798;
													array125[1] = -1883825990;
													array125[2] = -368367666;
													array125[3] = 1275053525;
													array125[4] = -1742098031;
													array125[5] = -919074776;
													array125[6] = 840298979;
													array125[3] = array125[1] ^ -493925271;
													array125[2] = array125[6] ^ 0x4789F5E5;
													array125[2] = array125[0] ^ -1286366944;
													int[] array126 = new int[5];
													array126[0] = 785522548;
													array126[1] = -48642463;
													array126[2] = -1080773136;
													array126[3] = -1413713906;
													array126[4] = -960563618;
													array126[3] = array125[1] ^ 0xF5B2BA6;
													array126[2] = array126[3] ^ -1871779149;
													array126[1] = array126[3] ^ 0x151A908E;
													int num338 = array126[3] ^ 0xC142506;
													int num339 = (int)(num4 * 712673984) ^ -1789733888;
													num337 ^= num339;
													num338 ^= num339;
													int num340;
													int num341;
													if (num336 != 'D')
													{
														num340 = num338;
														num341 = num340;
													}
													else
													{
														num340 = num337;
														num341 = num340;
													}
													num = num340 ^ num339;
													continue;
												}
												char num342 = c;
												int[,] array127 = new int[4, 3];
												array127[0, 0] = 51475343;
												array127[0, 1] = -2005500207;
												array127[0, 2] = -340722811;
												array127[1, 0] = -1107716517;
												array127[1, 1] = 193261074;
												array127[1, 2] = -475155655;
												array127[2, 0] = -194379393;
												array127[2, 1] = -7735190;
												array127[2, 2] = -2137553239;
												array127[3, 0] = -2084297669;
												array127[3, 1] = -1208409942;
												array127[3, 2] = -447453671;
												array127[2, 2] = array127[2, 1] ^ -739549832;
												array127[1, 0] = array127[0, 0] ^ -1511326341;
												array127[1, 0] = array127[3, 2] ^ 0x4B971213;
												array127[1, 2] = array127[3, 2] ^ -1136117044;
												int num343 = array127[1, 2] ^ -914256711;
												int[] array128 = new int[4];
												array128[0] = -2012653455;
												array128[1] = 230903698;
												array128[2] = 857819567;
												array128[3] = 2130532608;
												array128[2] = array128[0] ^ 0x48444CA5;
												array128[2] = array128[0] ^ 0x39CFBB0;
												int[] array129 = new int[6] { -726548599, -1526026567, 839768899, -1578471566, 801559575, 312653843 };
												int[][] array130 = new int[2][] { array128, array129 };
												array129[1] = array130[0][3] ^ 0x4DA9DB03;
												array129[2] = array129[4] ^ 0x69E10D43;
												array129[0] ^= 415395403;
												int num344 = array130[1][1] ^ -2138604548;
												int num345 = (int)((num4 * 1963354982) ^ 0x263F2ABA);
												num343 ^= num345;
												num344 ^= num345;
												int num346;
												int num347;
												if (num342 != 'B')
												{
													num346 = num344;
													num347 = num346;
												}
												else
												{
													num346 = num343;
													num347 = num346;
												}
												num = num346 ^ num345;
												continue;
											}
											int[] array131 = new int[5] { -125331869, 2065297576, -1045956191, -345575712, -999774681 };
											array131[3] ^= -761971654;
											array131[4] = array131[2] ^ 0x3B5BA111;
											int[] array132 = new int[5];
											array132[0] = 117262818;
											array132[1] = 1740118725;
											array132[2] = -837559934;
											array132[3] = -1083275842;
											array132[4] = -1216325969;
											array132[1] = array131[1] ^ -1141935966;
											array132[3] ^= -44060497;
											array132[2] ^= -318574407;
											array132[4] ^= 1986137431;
											int num348 = array132[1] ^ 0x5DE0BEBB;
											num = (int)((num4 * 512872962) ^ 0x3E5D1528) ^ num348;
											continue;
										}
										switch (num349)
										{
										case 5:
											goto IL_5971;
										case 7:
											goto IL_9644;
										case 4:
											goto IL_a14c;
										case 6:
											goto IL_a9c9;
										}
										int[,] array133 = new int[4, 4];
										array133[0, 0] = -1466880869;
										array133[0, 1] = -374700328;
										array133[0, 2] = -1814018569;
										array133[0, 3] = -376386236;
										array133[1, 0] = 451221921;
										array133[1, 1] = -1601029884;
										array133[1, 2] = 853801457;
										array133[1, 3] = 1372135445;
										array133[2, 0] = 956004079;
										array133[2, 1] = 2070657064;
										array133[2, 2] = -1494100451;
										array133[2, 3] = 1730598174;
										array133[3, 0] = -1378277556;
										array133[3, 1] = -1576039550;
										array133[3, 2] = -50133400;
										array133[3, 3] = -1294292342;
										array133[1, 1] = array133[0, 0] ^ -1229945733;
										array133[1, 0] = array133[2, 3] ^ -1551270169;
										array133[2, 0] = array133[1, 2] ^ -2003413588;
										int num350 = array133[2, 0] ^ 0x2D6D4ADE;
										num = ((int)num4 * -537194025) ^ 0xC8AE4F4 ^ num350;
										continue;
									}
									num349 = _002D_0029_003F_002A_0025_005E_005E_(text);
									int[] array134 = new int[6];
									array134[0] = 947421656;
									array134[1] = -1451268967;
									array134[2] = -1498464104;
									array134[3] = -135959513;
									array134[4] = -122049437;
									array134[5] = -1822320712;
									array134[0] = array134[1] ^ -1478358372;
									array134[3] ^= -1396932715;
									array134[5] = array134[3] ^ -327901306;
									int[] array135 = new int[5];
									array135[0] = 1994834416;
									array135[1] = 2031117916;
									array135[2] = 425425909;
									array135[3] = -1791467491;
									array135[4] = -1602045707;
									array135[3] = array134[2] ^ 0x6658A5AD;
									array135[0] = array135[4] ^ 0x5B6280D7;
									array135[1] = array135[0] ^ -1309249836;
									int num351 = array135[3] ^ 0x3306990E;
									num = (int)((num4 * 426788232) ^ 0xD09A8878u) ^ num351;
									continue;
								}
								string text2 = text;
								int[,] array136 = new int[3, 3];
								array136[0, 0] = -1919859408;
								array136[0, 1] = 20157464;
								array136[0, 2] = 1366978308;
								array136[1, 0] = 1824211755;
								array136[1, 1] = -1857551163;
								array136[1, 2] = -1243030497;
								array136[2, 0] = -2068273464;
								array136[2, 1] = 737612818;
								array136[2, 2] = -948977529;
								array136[1, 0] = array136[1, 2] ^ 0x474EF94A;
								array136[1, 2] = array136[0, 1] ^ -1799449659;
								array136[1, 1] = array136[0, 0] ^ -1469304496;
								array136[2, 1] = array136[2, 0] ^ -1798195516;
								int num352 = array136[2, 1] ^ -1921044803;
								int[,] array137 = new int[4, 3];
								array137[0, 0] = 1615236705;
								array137[0, 1] = 1343940030;
								array137[0, 2] = -1485414056;
								array137[1, 0] = 1913047929;
								array137[1, 1] = 1888896384;
								array137[1, 2] = -605433213;
								array137[2, 0] = -1009334780;
								array137[2, 1] = 1831428353;
								array137[2, 2] = -1407009882;
								array137[3, 0] = -828092729;
								array137[3, 1] = -1679354165;
								array137[3, 2] = -48291802;
								array137[1, 1] = array137[3, 2] ^ -2092986982;
								array137[2, 2] = array137[0, 2] ^ -1686137405;
								array137[3, 2] = array137[2, 1] ^ 0x465FDC84;
								int num353 = array137[3, 2] ^ -395122645;
								int num354 = ((int)num4 * -597892295) ^ 0x33129C1A;
								num352 ^= num354;
								num353 ^= num354;
								int num355;
								int num356;
								if (text2 != null)
								{
									num355 = num353;
									num356 = num355;
								}
								else
								{
									num355 = num352;
									num356 = num355;
								}
								num = num355 ^ num354;
								continue;
							}
							text = _002F_002B_005E_002F_0028_0028_0021_0029(xUT_003D);
							num = -1704391943;
							continue;
						}
						return _0024_0028_003E_0026__0021_005E_0029(idi_003D(_002A_0025_003E_002A_0040_002F_002F_0023((TypeSig)sZArraySig)), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[534 - 49 - 32 - 27]);
					}
					SZArraySig sZArraySig2 = sZArraySig;
					int[] array138 = new int[7];
					array138[0] = 280816384;
					array138[1] = 388341158;
					array138[2] = 1375288206;
					array138[3] = -1707751224;
					array138[4] = -811283302;
					array138[5] = 2059317957;
					array138[6] = 505555372;
					array138[5] = array138[3] ^ 0x2968EC60;
					array138[5] ^= 767082576;
					array138[2] = array138[4] ^ 0x22C85DEF;
					int[] array139 = new int[7];
					array139[0] = 369999267;
					array139[1] = 2030406555;
					array139[2] = -1105379421;
					array139[3] = 624007865;
					array139[4] = -92470222;
					array139[5] = -972138236;
					array139[6] = -979642664;
					array139[0] = array138[1] ^ 0x10C43C92;
					array139[3] = array139[1] ^ -1951250017;
					array139[3] = array139[5] ^ -471157864;
					int num357 = array139[0] ^ -1579658676;
					int[] array140 = new int[7];
					array140[0] = 392903921;
					array140[1] = -44335872;
					array140[2] = 376207620;
					array140[3] = -186551000;
					array140[4] = 26265714;
					array140[5] = 947736910;
					array140[6] = 460351166;
					array140[4] = array140[3] ^ 0x289F7E00;
					array140[0] = array140[5] ^ 0x6D696E47;
					int[] array141 = new int[6] { -1951823842, -1922188988, -1319257320, 204956052, 260721890, 1011617241 };
					int[][] array142 = new int[2][] { array140, array141 };
					array141[1] = array142[0][3] ^ 0x359DA252;
					array141[0] = array141[4] ^ -2110605248;
					array141[3] = array141[2] ^ 0x4C471E92;
					array141[3] = array141[0] ^ 0xAA75F8D;
					int num358 = array142[1][1] ^ 0x79BF4C92;
					int num359 = ((int)num4 * -569760283) ^ 0x5CB2FE6B;
					num357 ^= num359;
					num358 ^= num359;
					int num360;
					int num361;
					if (sZArraySig2 != null)
					{
						num360 = num358;
						num361 = num360;
					}
					else
					{
						num360 = num357;
						num361 = num360;
					}
					num = num360 ^ num359;
					continue;
				}
				goto IL_aa00;
			}
			return _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0xCC7E ^ 0xCDD7))];
			IL_5971:
			c = _002B_002A_0029_005E_0021_0024_0040_0024(text, 3);
			num = -1465123625;
			continue;
			IL_a9c9:
			c = _002B_002A_0029_005E_0021_0024_0040_0024(text, 4);
			int num362;
			if ((uint)c <= 54u)
			{
				num = -165914641;
				num362 = num;
			}
			else
			{
				num = -1766912525;
				num362 = num;
			}
			continue;
			IL_a14c:
			c = _002B_002A_0029_005E_0021_0024_0040_0024(text, 0);
			num = -1433571109;
			continue;
			IL_9644:
			c = _002B_002A_0029_005E_0021_0024_0040_0024(text, 0);
			num = -906784578;
		}
		goto IL_0009;
		IL_aa00:
		sZArraySig = xUT_003D as SZArraySig;
		num = -986022370;
		goto IL_000e;
	}

	private unsafe static bool XkQ_003D(IHasCustomAttribute? xXs_003D)
	{
		if (xXs_003D == null)
		{
			uint num2;
			int num4;
			do
			{
				int num = 1300016541;
				uint num3;
				num2 = (num3 = (uint)((-(-(~(-(-1785922253 * 1399171377 + (-1414669624 + 923791973))) - ((((~num + (1721780998 * 2135255515 + -931203749 * ~-237904997 - (-(-880841243 + 868869267) * -1866925879 - (-(-781963755 - -1961801999) ^ -1647655013) - -(-(-843621868 - (2030585278 + -606371092))) - (-(-1690356288 + (--1145569872 ^ 0x4B651D1C)) - ~-314068847)) - (~(0x2981C78C ^ -934175363) + (-(-311103753) ^ -(~(-(1645210719 * -819411560)) + ~(1702622887 - -1700281601 - (-2119516833 + -467058604))))))) * -1830830915) ^ (-226194661 * ~(-918886269 * --1833595908 + -1017464136 + 385244686))) - 771827732))) - ~1001689235) ^ -2002488848)) % 3;
				num4 = -1074913304;
				_ = 0;
				for (int num5 = 0; num5 < 2; num5++)
				{
					num4 = -num4 ^ -1956204693;
					num4 = ~-973976300 - num4 - -1744642425;
				}
			}
			while (num2 == (uint)num4);
			int num6 = -1;
			_ = 0;
			for (int num7 = 0; num7 < 1; num7++)
			{
				num6 = -num6;
			}
			if (num2 == (uint)num6)
			{
				return false;
			}
			int num8 = -1042688375;
			_ = 0;
			for (int num9 = 0; num9 < 1; num9++)
			{
				num8 ^= -1042688373;
			}
			if (num2 == (uint)num8)
			{
			}
		}
		return _0029_003F_0024_0024_0040_0025_0026_0024(xXs_003D).Any((CustomAttribute attribute) => _003C_003Ec._002F_002A_002D_003C_002A_002F_0026_005E(_003C_003Ec._003F_002B_002F_005E_003F_0021_0023_0023((IFullName)_003C_003Ec._0024_0029_0025_003E_002A_0024_002D_0025(attribute)), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(475 + sizeof(int)) ^ sizeof(Guid)], StringComparison.Ordinal));
	}

	private static bool ejJ_003D(string NWL_003D)
	{
		if (!_0025_005E_003C_002B_0021_0029_002F_003C(NWL_003D, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x7A97 ^ 0x7B52], StringComparison.Ordinal))
		{
			uint num3;
			while (true)
			{
				int num = -423256548;
				while (true)
				{
					int num2 = num;
					uint num4;
					num3 = (num4 = (uint)(((983194075 - 1854127452 - -213269935 * 1423330597) * -406679051 - ((((~(~1446288009) - ((0x30400E6C ^ (-770130434 ^ --1409998820)) - -(~-1049624993 - 2001423441))) ^ (-(0x15ED82D ^ 0x53C2D356) ^ (((-376863347 + (1180789413 + 1476301807)) ^ 0x1E944B87) + (-408154232 + -720442321 * 1918781898) + (-(0x72DC9D51 ^ 0x447646F9) - (0x5042F70 ^ 0x1DC5D481) + ~(-1313027005 * --2036073405))))) - (num2 - ~((-(~(-(~(2080613766 - 231748767))) + ~(0x2EACD2B3 ^ 0x454BDCFF)) ^ (-(1614316635 * (~(-523053005 - 778219512) * -304131769)) - -1185246632)) - (400399392 + (~(-283375417 * -1374967959) + 1321810641 * (-213086731 * (-53118228 + -2023010275)) - (0x3D5A5F26 ^ ((-2086296190 ^ 0x7675EE91) - (-1207224525 - 1495328547 - --1164800491))) - ((-(~-1249131202) ^ ~(-919843702)) - -1953004217 * 2096695787 - (-2033966998 ^ -((-1744132285 - -916629734) * -1940163697)))))) - (-798957143 + ~(~(-(979080100 - -806822534) + --1675693451 * 2189051) + -1225485390)) * -218701277)) * -1567196377 + ~(0x251F2855 ^ 0x2E5134D7) - (-73468381 ^ 0x5174CC))) * -415021639 * -856103705 - -625093497)) % 4;
					int num5 = 1409425836;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0x540221AE;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -2053897119;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 - 1765165529;
						num7 = ~(num7 ^ --1006763276);
					}
					if (num3 != (uint)num7)
					{
						goto end_IL_0036;
					}
					bool num9 = _0025_005E_003C_002B_0021_0029_002F_003C(NWL_003D, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[526 - 46 - 3 - 23], StringComparison.Ordinal);
					int[] array = new int[5];
					array[0] = 1839644563;
					array[1] = 1700563728;
					array[2] = -1950628715;
					array[3] = 1925018922;
					array[4] = -682242498;
					array[0] = array[2] ^ 0x40BC514;
					array[2] = array[0] ^ 0x16C16E63;
					int[] array2 = new int[7];
					array2[0] = -1293666977;
					array2[1] = 25416239;
					array2[2] = 439469053;
					array2[3] = -1185330494;
					array2[4] = 640540759;
					array2[5] = -2084150774;
					array2[6] = -2063020618;
					array2[6] = array[1] ^ -1000184848;
					array2[5] = array2[0] ^ -2126705723;
					array2[2] = array2[4] ^ -1944260485;
					array2[3] = array2[6] ^ 0xC78829D;
					int num10 = array2[6] ^ -752861373;
					int[] array3 = new int[6];
					array3[0] = 361210891;
					array3[1] = -579732505;
					array3[2] = -209636541;
					array3[3] = -2099873893;
					array3[4] = 579734770;
					array3[5] = -1956256249;
					array3[4] = array3[0] ^ 0x3401DAF6;
					array3[3] = array3[2] ^ 0x1EBCE21A;
					int[] array4 = new int[6] { -1264292253, 1720754482, 1205626129, -741550132, 1275600592, 1874259657 };
					int[][] array5 = new int[2][] { array3, array4 };
					array4[0] = array5[0][5] ^ -1615773940;
					array4[4] = array4[3] ^ 0x2346148F;
					array4[2] = array4[5] ^ -1513324646;
					array4[5] = array4[4] ^ 0x60C23E73;
					int num11 = array5[1][0] ^ -1164382243;
					int num12 = ((int)num4 * -726167461) ^ 0x18DC227;
					num10 ^= num12;
					num11 ^= num12;
					int num13;
					int num14;
					if (!num9)
					{
						num13 = num11;
						num14 = num13;
					}
					else
					{
						num13 = num10;
						num14 = num13;
					}
					num = num13 ^ num12;
				}
				continue;
				end_IL_0036:
				break;
			}
			int num15 = -466980733;
			_ = 0;
			for (int num16 = 0; num16 < 1; num16++)
			{
				num15 ^= -466980736;
			}
			if (num3 == (uint)num15)
			{
				return _0024_005E_003E_0024_002B_003D_0028_002F(NWL_003D, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x6BA ^ 0x77D], StringComparison.Ordinal);
			}
			int num17 = -277945994;
			_ = 0;
			for (int num18 = 0; num18 < 2; num18++)
			{
				num17 = (num17 - 267423707 * -1732272691) * 2081349457;
				num17 = num17 - (0x14ED966A ^ -496901189) + 1597881149;
			}
			if (num3 == (uint)num17)
			{
			}
		}
		return true;
	}

	private static bool WRp_003D(TypeDef ofv_003D)
	{
		ITypeDefOrRef typeDefOrRef = __0023_0029_0021_002F_0040_003F_0025(ofv_003D);
		return _0021__0040_003C_005E_0029_0023_005E((typeDefOrRef != null) ? _003E_003C_005E_0028_005E_0023_0028_0026((IFullName)typeDefOrRef) : null, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-789 + 332)], StringComparison.Ordinal);
	}

	private static void EWo_003D(string bMR_003D, Exception Tnk_003D)
	{
		try
		{
			string text = _002A_0023_002D_005E_003E_005E_0040_0023(__002F_003F_002A_002D_002B_002B_003F(Environment.SpecialFolder.LocalApplicationData), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4890 - 4495 + 62]);
			_0029__003F_0026_002B_0028_0028_0021(text);
			string text2 = _002A_0023_002D_005E_003E_005E_0040_0023(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[499 - 20 - 17 - 4]);
			DefaultInterpolatedStringHandler defaultInterpolatedStringHandler = new DefaultInterpolatedStringHandler(6, 4);
			defaultInterpolatedStringHandler.AppendLiteral(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xAB06 ^ 0xAACD]);
			defaultInterpolatedStringHandler.AppendFormatted(bMR_003D);
			defaultInterpolatedStringHandler.AppendFormatted(_003F_0029_0023_0040_002D_003D_002D_0021());
			defaultInterpolatedStringHandler.AppendFormatted(_003F_0029_0023_0040_002D_003D_002D_0021());
			defaultInterpolatedStringHandler.AppendFormatted(Tnk_003D);
			_0021_002B__0021_005E_0028_002D_0025(text2, defaultInterpolatedStringHandler.ToStringAndClear());
		}
		catch
		{
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static ModuleDefMD _0024_005E_003D_002D_002D_0029_005E_0025(string P_0, ModuleCreationOptions P_1)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
		return (ModuleDefMD)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZGloMDVnaDVRUBrOV1FV01E=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static ModuleDefMD __0025_0029_0025_003F_002A_005E_005E(byte[] P_0, ModuleCreationOptions P_1)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
		return (ModuleDefMD)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NWFlZWUxZjUAAUzZBgAEgwA=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static ModuleDefMD _0029_002A_005E_003E_002F_003E_002B_0026(Stream P_0)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
		return (ModuleDefMD)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MDJrYGY1ZmNTUh0jVVNX11M=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static void _003D_002D_0024_003F_003D_003F_003C_0021(IDisposable P_0)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
		_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OGE/OGw9a2FZWBY2X1ld3Fk=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static string _0028_003C_0024_002A_005E_003D_0029_002D(string P_0, string P_1, string P_2)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { P_0, P_1, P_2 };
		return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OGU4ZGU2NDgAAVAfBgAEhgA=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	static IEnumerable<TypeDef> _002A_0026_003E_003F_003D_0025_002D_0025(ModuleDef P_0)
	{
		IEnumerable<TypeDef> types = default(IEnumerable<TypeDef>);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -526355315;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(((~(~num2 * -1596909417 * 782716275) ^ 0x6274369D) - 48842304) * 710383129 * -688310657) ^ 0x12F38FAB)) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * -391309315 * 905223815;
						num5 = -(num5 * -405553381);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -2;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1272801381;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x4BDD6864;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					types = P_0.GetTypes();
					int[,] array = new int[4, 3];
					array[0, 0] = -903801337;
					array[0, 1] = -1851715881;
					array[0, 2] = 346741533;
					array[1, 0] = 228304824;
					array[1, 1] = 900134085;
					array[1, 2] = 712219693;
					array[2, 0] = 1338370391;
					array[2, 1] = 1982313881;
					array[2, 2] = 1098026514;
					array[3, 0] = -642715518;
					array[3, 1] = 1240783858;
					array[3, 2] = 2145651563;
					array[1, 1] = array[0, 0] ^ -1028914791;
					array[2, 1] = array[3, 2] ^ 0x60DCAB8A;
					array[3, 1] = array[2, 2] ^ 0x2E1A261E;
					int num11 = array[3, 1] ^ -748117355;
					num = ((int)num4 * -331513877) ^ 0x48DA871 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return types;
	}

	static StringComparer _002B_0024_005E_002A_002D__0023_0025()
	{
		StringComparer ordinal = default(StringComparer);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1906729197;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(((~(-(num2 * -709755981) - ~67085561) * -887411397) ^ ((~(~-1878944422) - ~(-220557298)) * 859139989)) * -852770577 - (0x5CF4AE41 ^ 0x1132D415)) + -1732917790)) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -2;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = ~num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1002749772;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -1002749774;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ordinal = StringComparer.Ordinal;
					int[] array = new int[7];
					array[0] = 967190335;
					array[1] = -1158280012;
					array[2] = 1558217323;
					array[3] = 631686289;
					array[4] = -582329529;
					array[5] = -1584155949;
					array[6] = -1852413876;
					array[0] = array[5] ^ 0x3F176C7E;
					array[4] = array[1] ^ -845232179;
					array[5] = array[0] ^ 0x4D0F787D;
					int[] array2 = new int[5] { 1448673659, 584958639, -1631170207, 1047874243, 886074502 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][6] ^ 0x3BC17BB3;
					array2[3] = array2[4] ^ -456659974;
					array2[3] = array2[1] ^ 0x10D1A16A;
					int num11 = array3[1][4] ^ 0x79FEA50E;
					num = ((int)num4 * -135444424) ^ 0x5B439EA0 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ordinal;
	}

	static IList<MethodDef> _003C_002A_005E_0021_0026_0040__003D(TypeDef P_0)
	{
		IList<MethodDef> methods = default(IList<MethodDef>);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -991057634;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((num2 + ~(-(-280780681 ^ (~(-(-533195081 - -742869298) + ~(1285236403 * -1433109915)) + -637551505 * 1890470541)) - ~(1711265449 - ~-805194780)) - ((-880057315 - (-173597180 ^ (221316939 * -(-(185916793 + -1199644354) - (0x4B3D9CE8 ^ -1691639346))))) ^ (-921233519 * ((-((-1951142047 * -1348473837 - ~-1359156005) * -1417622823) * 845246093) ^ (0x50E95C ^ -(-(-2000201779 ^ -676366832) + (-288028625 * 704907488 + (-1113270934 ^ 0x5335D51E))))))) + -((~(-1551091536 ^ -(526030957 - -597921349)) ^ (~(-(1608848709 * -1399921875)) * 110238897)) - 1397743969)) ^ 0x3BA2B10F ^ 0x417ECE09 ^ (--2051515399 - ~(~(--128699320))))) % 3;
					int num5 = 429688287;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = 429688287 - num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(~num7);
						num7 = ~(num7 ^ 0x3811B55D);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 757090292;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ -1249398558) * 1965515025;
							num9 = (num9 - 1684082979) * -76609163;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					methods = P_0.Methods;
					int[,] array = new int[3, 3];
					array[0, 0] = 1162978473;
					array[0, 1] = 1584840188;
					array[0, 2] = -320862946;
					array[1, 0] = -444143589;
					array[1, 1] = -1679758529;
					array[1, 2] = 168140268;
					array[2, 0] = 1765114983;
					array[2, 1] = 1066268228;
					array[2, 2] = 1224549766;
					array[0, 2] = array[1, 1] ^ -1118127184;
					array[2, 0] = array[0, 1] ^ 0x11540F30;
					array[0, 0] = array[2, 2] ^ 0x19FB6DB9;
					array[2, 1] = array[1, 1] ^ 0x53FB8EFE;
					int num11 = array[2, 1] ^ 0x24727DB3;
					num = (int)((num4 * 1767526773) ^ 0xB339EA15u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return methods;
	}

	static MDToken _0029_0029_003F_0023_0024_005E_003D_003F(MethodDef P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return P_0.MDToken;
		}
	}

	static void _002F_003D_0028__0024_003E_003D_0028(MethodItem P_0, int P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -264034375;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((~(-809579953 - (~(num2 * 2134034823) - ((0x67D821EC ^ -(44281845 * 628805329)) + -1930450414)) - (~-1097083685 + -(-(-1599080764) - -(2027706693 + -2083751848)))) * -2084279665 - -1443209695 * (-956559932 + 736320385)) ^ 0xAB94842))) % 3;
					int num5 = -3;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = ~num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1190206929;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 1572840655;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 732413288;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 * -1214047543 * -220454977;
							num9 = -434555733 - num9 * 1295472591;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Token = P_1;
					int[,] array = new int[3, 3];
					array[0, 0] = 229221715;
					array[0, 1] = 1145537300;
					array[0, 2] = 338231728;
					array[1, 0] = -459844909;
					array[1, 1] = -1124776168;
					array[1, 2] = -1868464122;
					array[2, 0] = -430913853;
					array[2, 1] = 1434640050;
					array[2, 2] = -1051342990;
					array[1, 1] = array[0, 1] ^ -1791673127;
					array[1, 1] = array[2, 1] ^ -8714018;
					array[0, 1] = array[2, 0] ^ 0x3FCE489C;
					int num11 = array[0, 1] ^ -1967800133;
					num = (int)((num4 * 278432391) ^ 0x9C362FDCu) ^ num11;
				}
			}
		}
	}

	static UTF8String _0021_005E_005E__005E_002A_0028_005E(MethodDef P_0)
	{
		UTF8String name = default(UTF8String);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 50041283;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(-(~num2 * -1493614059) * 1448383321 * 745901211 + -2097878569) * -1377867285 + ~1219691520))) % 3;
					int num5 = 551710894;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 551710892;
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
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(num9 - --1902510643);
							num9 = -2004303507 - (~1370320547 - num9);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					name = P_0.Name;
					int[] array = new int[7];
					array[0] = 1229865376;
					array[1] = -730535063;
					array[2] = -1629941966;
					array[3] = 938872187;
					array[4] = 1193768235;
					array[5] = 320566477;
					array[6] = 799159691;
					array[5] = array[3] ^ 0x491C5DF;
					array[4] = array[0] ^ -1306222309;
					int[] array2 = new int[7];
					array2[0] = 1901396876;
					array2[1] = -1301689539;
					array2[2] = 1169405021;
					array2[3] = -172356751;
					array2[4] = 404472975;
					array2[5] = -447676296;
					array2[6] = 2066873323;
					array2[1] = array[3] ^ -434788718;
					array2[2] = array2[5] ^ 0x16415C86;
					array2[0] = array2[2] ^ 0x1B9D2D25;
					array2[2] = array2[6] ^ 0x161CBFD8;
					int num11 = array2[1] ^ -1037885594;
					num = (int)((num4 * 1108657494) ^ 0x88B313E8u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return name;
	}

	static string _002B_0024_003D_002F_003C_0029_005E_005E(UTF8String P_0)
	{
		string result = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 2099848192;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-((~(~(-116651445 * (-42260047 * -(-1528916315 ^ 0x2607072) * -1436050933)) - (num2 ^ ((((-1221990658 ^ (-2146004629 * -1428463628) ^ ((-2025564505 ^ 0x742255F6) - (0x1B504BA5 ^ -210125177))) + -1784312609 * ((-930779261 * 1837973407 + (-1606462664 - -1298528041)) * 1003388647) + -(2136901391 * (0x7EF61B2E ^ 0x46A7FB22))) * 456569227 + (-329092409 - -495203373)) ^ -(-(~(212488789 * -1543433100 + ((-1084316364 ^ 0x5D99E004) - --484527299)) + (-(1251275302 + -353547243 - -1774156127 * 1686509319) - (~-2104313502 + 1310736213 + --1748254642)) - -(-272092439 * 1581218094 - --740129448)))) ^ -175055866)) ^ (-471251487 * ((~237616902 * 37438327 + -(~-431756147)) * -690444385))) - (0x6EC59355 ^ 0x72560762))) - (0x75A2AA9F ^ 0x1AF73C2A) + -13274460)) % 3;
					int num5 = 577265045;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0x22685D95;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 687576022;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 742332099;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2101715421;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= -200819083;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0;
					int[] array = new int[4];
					array[0] = 685323780;
					array[1] = -862043654;
					array[2] = -1006858584;
					array[3] = 387144548;
					array[2] = array[1] ^ 0x76483919;
					array[0] = array[3] ^ 0x49CDEB5D;
					int[] array2 = new int[4] { 1944477700, 905027994, 910046097, -1725984156 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][1] ^ -1323190334;
					array2[2] ^= 662601052;
					array2[0] = array2[1] ^ 0x174C4C65;
					array2[2] = array2[0] ^ 0x72CE589F;
					int num11 = array3[1][1] ^ -857780452;
					num = (int)((num4 * 626267620) ^ 0x5637F1D8) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _003E_0023_0026_0025_0028_0029_0040_003D(MethodItem P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 136652124;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(((~(num2 ^ (-(-(-(~(2000646138 * 808647317 + (-285656681 + -409180271))) - 1581950755)) + (--834344470 + (-(0x644DE2EB ^ -884517363) + -(-(~(-294814756 - 2107590796)))) + -94836457) - -522014973 * -((-1071261402 ^ (1461541016 + (1141859997 - --1493147011)) ^ (-1962948465 ^ (1414581216 - -651935815 - -1705503763) ^ 0x1E7EACAE)) + (600046101 + 1838980317)))) ^ (((-(-(-1001473522 - -1703953140 - (1133695684 - -213406805))) - (-(-37437267 + -1838650116) + (-1433925516 ^ -802039068)) * -1685624611) ^ 0x1330CDAC) * 405969961)) - (0xB4186C5 ^ -(-1492830241 ^ -1532602524)) * 1948335259) * -1411349549) + -543927360)) % 3;
					int num5 = 1464787074;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 ^ 0x255F4B93) * 1479792385;
						num5 += -768072467 * 592258288;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1948364223;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 * -1302359183 - 1903668609;
						num7 = ~(num7 - --10013806);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2114469576;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 + (1457255456 - -1577978777) + 1071848441;
							num9 = -854118511 - (596185768 + 1599543607 - num9);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Name = P_1;
					int[] array = new int[7];
					array[0] = 1320604110;
					array[1] = 703408954;
					array[2] = 902329448;
					array[3] = 52989609;
					array[4] = -1566346195;
					array[5] = -375442554;
					array[6] = -1520044273;
					array[0] = array[1] ^ -387566675;
					array[1] = array[5] ^ 0x78696F81;
					int[] array2 = new int[4] { -1798240657, 12679124, -2095122120, 1208747490 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][3] ^ 0x4700D846;
					array2[0] ^= 981893614;
					array2[1] = array2[2] ^ -1527982865;
					array2[1] ^= -43982744;
					int num11 = array3[1][2] ^ -1202193746;
					num = ((int)num4 * -1141064020) ^ -1968634796 ^ num11;
				}
			}
		}
	}

	static void __0040_0029_005E_0040_002D_0025_005E(MethodItem P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 466680165;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(((-358536204 ^ 0x65039649) - (-161132947 ^ -12162958) * -179180655 - (-(~963941726 - -374343077 * -15232038 + (0x3F272D45 ^ -1026874398)) + --289809010)) * 663876951 - (num2 * 1890326547 + (--256190739 ^ ~((((-1271885311 ^ -396918426) + ((0x786B6405 ^ -1313010191) + (-406845516 ^ -1727778190))) ^ (-(~1700249113) ^ -1307347239)) - -(-(-1634760330 + 772155767) * -1431404753) + -88648537)))))) % 3;
					int num5 = 801845295;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = 801845295 - num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1767166495;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 1767166494;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -300591588;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 - 601700345 * 612409140 - -1028227573;
							num9 = -(num9 * 224324035);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Signature = P_1;
					int[,] array = new int[3, 3];
					array[0, 0] = 1155376374;
					array[0, 1] = -1696840235;
					array[0, 2] = 1475495279;
					array[1, 0] = 1950341918;
					array[1, 1] = -419034857;
					array[1, 2] = -297283850;
					array[2, 0] = 582665434;
					array[2, 1] = 1126498797;
					array[2, 2] = -1514536407;
					array[2, 2] = array[0, 0] ^ -906271704;
					array[2, 2] = array[0, 2] ^ -289252985;
					array[1, 1] = array[0, 1] ^ 0x57572A5E;
					array[0, 0] = array[1, 0] ^ -1423760860;
					int num11 = array[0, 0] ^ -992080181;
					num = (int)((num4 * 593799313) ^ 0xF28E544Fu) ^ num11;
				}
			}
		}
	}

	static string _003C_0029_0024_002A_003F_0021_003C_0023(TypeDef P_0)
	{
		string fullName = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 644133599;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(((~num2 - (-1505513367 * -(-((150807564 * 1069188581 - --1141790315) ^ 0x9BD6B6B) ^ (0x5BF6FDF7 ^ -(-1428212943) ^ -(--1472538728 + (914273689 + 2034516685)))) - (0x7CA03FD9 ^ 0x59E1BEF6) * -2142769351)) ^ (-1403546909 * 1995600777)) - -1257604288) ^ -732497639 ^ -474476734)) % 3;
					int num5 = -1341655038;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 ^= 0x68144649;
						num5 = ~num5 - -595399522;
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
						int num9 = -65929210;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 ^ -331157892 ^ -733570068;
							num9 = num9 + 1888408065 * 1839908462 - -1552001167;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					fullName = P_0.FullName;
					int[] array = new int[6];
					array[0] = -391585560;
					array[1] = 708978222;
					array[2] = 751683703;
					array[3] = 861754946;
					array[4] = -1741576939;
					array[5] = -1354457138;
					array[2] = array[1] ^ 0x7FA9EE6D;
					array[4] ^= -1957792558;
					array[3] = array[4] ^ 0x3BFA35C4;
					int[] array2 = new int[4] { 919947222, -1283659610, -201642410, -2082871284 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][1] ^ -246087190;
					array2[1] ^= 217844906;
					array2[1] = array2[2] ^ -327764269;
					int num11 = array3[1][2] ^ 0x2DCE4B50;
					num = (int)((num4 * 216454035) ^ 0xF8012ED4u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return fullName;
	}

	static void _0021_005E__0024_0025_003E_0040_002A(MethodItem P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -477287990;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-((num2 + (-(~(-((--454127955 ^ -84778815) + ~(-584202769 * 1682511377 + (0x597C10E3 ^ -1411005293))) - (-1997079481 * 1676576980 + (0x143DA9F2 ^ -1318678573) - (-1354687078 ^ -(1071026517 - 1776988395))) * 2049763323)) + ~(~(-(~(--705654736 ^ 0x7762B0CD)) - --2032557196 + (775903994 + -564204515 + (-1075328409 * 993144621 + (-1012699312 + 1789135628)) + 1530674167 - ~1957102616)))) + (~1832860632 + -(~(1642629721 * ~(~(-1846811867)) * -822734475)))) * -112586453 * 1156718731)))) % 3;
					int num5 = 1328044079;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 += -1328044079;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(~num7);
						num7 = -num7 - 713785595;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 6;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 ^ -1134093436 ^ -661028018;
							num9 = -num9 ^ 0x4F301450;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.TypeFullName = P_1;
					int[] array = new int[4];
					array[0] = -2006011643;
					array[1] = 706424271;
					array[2] = -1922397481;
					array[3] = -1433293125;
					array[2] = array[1] ^ -944794739;
					array[1] = array[0] ^ -932809315;
					array[2] = array[1] ^ 0x457459CC;
					int[] array2 = new int[5];
					array2[0] = 762483732;
					array2[1] = -982440480;
					array2[2] = -100922424;
					array2[3] = 1134927145;
					array2[4] = -1912238390;
					array2[0] = array[0] ^ -162012138;
					array2[2] = array2[0] ^ -1735992295;
					array2[4] = array2[1] ^ -1444166094;
					int num11 = array2[0] ^ -330959786;
					num = (int)((num4 * 310291676) ^ 0x4D003D88) ^ num11;
				}
			}
		}
	}

	static void _002A_0023_003C_003F_0028_0029_0021_(MethodItem P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -903837466;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((-(~((((~(-((0x39919184 ^ 0x56D99D8C) + -460713270)) - -1069805897 * -121077624 * -366897131) ^ -1301579064) - (-(894422335 - -550034463 - (-238889273 - -840497306) - --2119691979) * -1519603665 * 1421690569 - (1558821047 + -991647537) * 800960293) + -1868590367 * ~530900437 - num2) * -1494969909)) ^ (1426131871 * -(1100765780 - 100130469 - --1938723572) + -1206784955)) + ((-(-2112534198) ^ -1291574651) - -(--1635997266) * -325089339)))) % 3;
					int num5 = -1409130202;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 ^ 0x59A7FE56 ^ -1560945665;
						num5 = num5 * 272848855 - 532204376;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 385443676;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += -385443675;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1711918325;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 1711918323;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.IsSelected = P_1;
					int[,] array = new int[4, 3];
					array[0, 0] = -1561360321;
					array[0, 1] = 1449879997;
					array[0, 2] = -790966004;
					array[1, 0] = 445409687;
					array[1, 1] = -96700618;
					array[1, 2] = -1319022626;
					array[2, 0] = -1405283183;
					array[2, 1] = 415160359;
					array[2, 2] = -1165249243;
					array[3, 0] = -1718912201;
					array[3, 1] = -696175986;
					array[3, 2] = 567438356;
					array[2, 1] = array[0, 1] ^ 0x4AB12DFA;
					array[1, 1] = array[3, 1] ^ -1376290763;
					array[2, 1] = array[3, 2] ^ -1572582015;
					int num11 = array[2, 1] ^ -1198295165;
					num = ((int)num4 * -425951323) ^ -1973469133 ^ num11;
				}
			}
		}
	}

	static void _002F_002B_0024_002F_002F_0029_003F_0024(MethodItem P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -2142294403;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~((((((-(-784695159 ^ ~(-(1709323901 * -1109233601 * 2003818047) + ((-203526093 ^ 0x6A588FF7) + (-386901701 + 626305446) + (0x6AA36E2D ^ -1146358755)))) ^ 0x77D7C88E ^ ((~(1190189187 * (((0x690A8E33 ^ 0x1FD71E9B) + ~(~2137811641)) * -612086815)) + (~((~(--2058117095) - ~(-512878038 - -130523026)) ^ 0x5C64A9D) ^ -965376433)) ^ -(~(-1617413811 * (0x6E59CC09 ^ 0x74DB5259))))) - num2 + (-(~(-(0x22878D54 ^ -1396453510))) - ((~(-(((-1365134104 ^ 0x43DCECBA) - (-1138234245 + 1930652458)) * -1068499897)) - -(~(~(0x29DD672F ^ -189908419)))) ^ (-(~1908564718 * 1898224429 + -(--302837875)) ^ -(1819001179 * 1083201469 * -1480353457) ^ 0xB630A58)))) * -135826067 - (0x1289D643 ^ -1110948065)) ^ 0x159D1ABD) - ~(-1700530251 + -665666059 * --1234986510)) ^ 0x5E782986)) * -1821745357)) % 3;
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
					int num7 = -1370938311;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~-1095606285 - num7 - 1781075441;
						num7 = ~num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -470058670;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 - ~787778347);
							num9 = (num9 ^ 0x3EA24FAC) + -553568130;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.IsPreselected = P_1;
					int[] array = new int[7];
					array[0] = 1879420875;
					array[1] = -772533501;
					array[2] = 187796782;
					array[3] = -730306160;
					array[4] = -838544716;
					array[5] = 1707137348;
					array[6] = 258118203;
					array[5] = array[0] ^ -908177086;
					array[3] = array[0] ^ -510672828;
					int[] array2 = new int[6];
					array2[0] = -778368940;
					array2[1] = 1273731665;
					array2[2] = -2087245680;
					array2[3] = 877196443;
					array2[4] = 870628682;
					array2[5] = 2009885393;
					array2[2] = array[0] ^ -1299238936;
					array2[1] = array2[2] ^ -1216542320;
					array2[5] = array2[1] ^ -270762414;
					array2[5] = array2[1] ^ -725228073;
					int num11 = array2[2] ^ -980351763;
					num = (int)((num4 * 1787971025) ^ 0x13D6261B) ^ num11;
				}
			}
		}
	}

	static bool _003C_003C_0024_0025_0029_005E_0029_003E(IEnumerator P_0)
	{
		bool result = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 290864973;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(((1863374213 * ((-2138830588 + (489990209 * (-1024382393 ^ 0xF2D477F) + (0x3F39C7A ^ 0x2F8DB1A1)) - 438473021) * -1384500875) - ((num2 - (~(-(-(-658571377 - -1832530404)) + ~(-277991308 - (0x4ECBB82E ^ 0xE5069CE)) + (2138278923 * 1680809284 - (2016956371 + 33616563) - (~-1698783389 - -1835978041) - --310169317)) ^ -1070621410 ^ (((-135136315 * ~(-701434092 ^ -1574506289) - (~(--969003586 - ~107852457) + (~(1093244704 - 53544144) + (-1273508474 ^ --1781121346)))) ^ (-(-2077749515 * (-103539128 * 888339985)) - (-2089932510 ^ --569530170))) + (--1534036499 + (--1394604849 - 642191795))) ^ -(((-1076975587 * (-1410672048 ^ -416770534) - ~(853440743 + -1303514521) - -((0xA3CB5AE ^ -1637666154) + (1120062038 + 1405843362)) + ~((0x3906E58B ^ -344189968) - -2104134649 + (-979266861 + -1986731507))) * -1159887837) ^ (-520484767 * (269188537 * (-396505757 + -1873262454 - (-26243447 - -863267166)) * 468946337) + (~(-(-1132639689 * -919598481 * -97777767)) ^ 0x6E7532E3))))) ^ -(~(593369826 - (-(402309234 - 725385288 - (-364093960 + -139076608)) - (--291980336 ^ (-597389026 + (0x48B41213 ^ -615471888)))) - ~(~114526994))))) ^ -260157227) * -305260589)) - ((-641705635 ^ 0x623FC0D9) + -1170411205))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= 1951143569;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1166038612;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -1051097366 - num7 + 884810314;
						num7 = -(num7 - (-673999832 + -1056751561));
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2090042067;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 -= -1275440712 ^ 0x1D097CD5;
							num9 += -1036759450 + 779427230;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.MoveNext();
					int[,] array = new int[4, 4];
					array[0, 0] = 1278746025;
					array[0, 1] = 2113328523;
					array[0, 2] = 746808448;
					array[0, 3] = 1474890477;
					array[1, 0] = 1023639558;
					array[1, 1] = 665534282;
					array[1, 2] = 2062197111;
					array[1, 3] = 1590913649;
					array[2, 0] = 1201214357;
					array[2, 1] = -27848283;
					array[2, 2] = -557213151;
					array[2, 3] = 299410632;
					array[3, 0] = -956393152;
					array[3, 1] = -1103620718;
					array[3, 2] = -791839538;
					array[3, 3] = -164404383;
					array[3, 1] = array[3, 3] ^ -858930680;
					array[2, 3] = array[3, 0] ^ -1133744701;
					array[1, 0] = array[3, 2] ^ 0x4164C8AA;
					array[2, 3] = array[1, 1] ^ -1696937009;
					int num11 = array[2, 3] ^ -310795377;
					num = (int)((num4 * 2131419653) ^ 0x6F50D11D) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _0028_0025_0024__0024_002F_0028_003C(TypeItem P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 943631466;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((num2 ^ 0x6EC68FDC) * -1684631699 - (-(-824550673) - 836085343 * (-(574744058 + 1328607536) - (-672083518 ^ -1454300557)) - ~(-(2042689671 * -102178925 + (-47933350 + 457823084)) ^ 0x27726590) + 1998035323 * -1884304899 * 2054536105 * 1772223401)) ^ -(~(-1400616938 ^ -1491137081)))) % 3;
					int num5 = -2069075769;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= -2069075769;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -271306774;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 913087581;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = -num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.FullName = P_1;
					int[,] array = new int[3, 4]
					{
						{ -1042702946, 979280533, -1088201946, -1542384947 },
						{ -1273158394, 78493277, 2009955878, 2074651553 },
						{ 656995707, 1135512673, 2113998117, 714819481 }
					};
					array[0, 0] ^= 1404095565;
					array[0, 1] ^= 1331374507;
					array[1, 3] = array[1, 2] ^ 0x5E506E21;
					array[2, 0] = array[2, 3] ^ 0x40F649F3;
					int num11 = array[2, 0] ^ 0x321FE5E2;
					num = (int)((num4 * 188070103) ^ 0xB96FBE79u) ^ num11;
				}
			}
		}
	}

	static UTF8String _0024_0023_002B_0024_002F_0028_0029_0025(TypeDef P_0)
	{
		UTF8String name = default(UTF8String);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 305933485;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~((num2 ^ -(-(~(~(--1270150836 * 58354591 * 1258511471))))) * 95379559)) ^ ((-751352093 + -1277456073 * 198314635) * 706785939 + (-(782680280 - 1147487454) + -2080765833 * 1993021068) - ~(-(-212292485))))) % 3;
					int num5 = -2146977792;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 ^ 0x3ABF2BA0 ^ -507820360;
						num5 = ~num5 - 1144708644;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1624298879;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -180415103;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -3;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = ~num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					name = P_0.Name;
					int[] array = new int[6] { -996004864, 334189419, -1221493177, 1826428034, -1507195758, 1615812095 };
					array[2] ^= -1434132187;
					array[2] = array[1] ^ -1644241096;
					array[1] = array[5] ^ 0x2B6F3B4C;
					int[] array2 = new int[6];
					array2[0] = -725988825;
					array2[1] = 73337511;
					array2[2] = 626457379;
					array2[3] = 1309916607;
					array2[4] = -2086585291;
					array2[5] = -1537377879;
					array2[5] = array[3] ^ 0x55D8E7B2;
					array2[0] = array2[1] ^ 0x1440F639;
					array2[2] = array2[4] ^ 0x2F20087A;
					int num11 = array2[5] ^ 0x33A4AC7D;
					num = ((int)num4 * -338413498) ^ 0x2406EA20 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return name;
	}

	static void _0029_0029__0025_0021_003F_005E_002B(TypeItem P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -2018465769;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(-(-(801197621 * (0x6576A1FA ^ --885413308) - (-(-997970400 + 404838707) + ~(-675744294 ^ 0x8881A12))) - ((num2 ^ (-201997917 * ~(~((--179137153 * 342106835 + 1347850253 * ~-542596647) * 863789201))) ^ (-1996759541 * ~(~(702843051 + -(~(-861397502 + -1879199780) * 1881202839))))) - ~(-((-1916473185 ^ -2117375348) - (-224462191 ^ 0x359F920A) - (-928226261 + (-939043215 - 1494385927))) + 1395472924 + -(0xC96AEBB ^ (1946792191 - -1974460085 - (-949429946 - -195174810 + -1720916055 * 1766589367)))) - -615794977)) * 659172609 + -965450590)))) % 3;
					int num5 = 1984277019;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 1984277017;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 297995153;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(-num7);
						num7 = num7 * 1935174889 * -393968335;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = -num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.DisplayName = P_1;
					int[] array = new int[4];
					array[0] = 1736138191;
					array[1] = -867919658;
					array[2] = 1368250052;
					array[3] = 1947453972;
					array[2] = array[3] ^ -254103678;
					array[2] = array[0] ^ 0x395E7B5D;
					int[] array2 = new int[7] { -924310018, -938547541, 1787193801, -259165804, 1259858423, -369084409, 1420540149 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][3] ^ -1999462846;
					array2[0] ^= -817808209;
					array2[1] = array2[5] ^ -297443974;
					int num11 = array3[1][3] ^ -154333694;
					num = (int)((num4 * 1689640322) ^ 0xE17FFFA2u) ^ num11;
				}
			}
		}
	}

	static void @__0029__002D_002F_002F_0029(TypeItem P_0, int P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -415027053;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(~(num2 - -(0x338894C9 ^ (-422168956 ^ (-178774647 * ~(-(-691702989 - 1544467275 - ~-250090885)))) ^ (((-1407588355 ^ 0x592E970E) * 1675866519 - -(-547894360 ^ -(-172881442 - ~-1195949687))) ^ (0x6B8B7F13 ^ (-(0x52216C5E ^ 0x59BFF5E4) - (-930899581 * -561600641 - -633507283 * --923040030 - 34526753 * -(-1433772763 * -1832106058)))))) - (~(-(-(~(--1158182302)) * -515646287) + ~(0x3D995B47 ^ (-1341743672 - (--1515812614 ^ 0x70C826F4)))) - ~(-1008932228 - (~1979933547 + -1379528907 + (-(-1879125143 * -1458693151 + (0x19802244 ^ 0xF22C055)) + -1438188056)))))) ^ -1569759098))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -116406989;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(num7 - (843215749 - -1369267910));
						num7 = 1656997485 - (num7 - -1533793979);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 447327464;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x1AA9ACEA;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.MethodCount = P_1;
					int[] array = new int[5];
					array[0] = -861499212;
					array[1] = -1234897291;
					array[2] = 1949437937;
					array[3] = 416951214;
					array[4] = 2094141744;
					array[2] = array[1] ^ -733590573;
					array[0] = array[3] ^ -1640987263;
					array[0] = array[1] ^ -1477866735;
					int[] array2 = new int[7] { 147839465, -2106616902, 1564069661, 418569000, 366429760, 1318617614, 313903359 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[5] = array3[0][1] ^ -1546142310;
					array2[6] = array2[3] ^ 0x3EE3E2EB;
					array2[3] = array2[5] ^ -279347934;
					array2[0] = array2[6] ^ -1319978704;
					int num11 = array3[1][5] ^ 0x1061D586;
					num = ((int)num4 * -1909072585) ^ -509425958 ^ num11;
				}
			}
		}
	}

	static bool _003D_0024_002A_0025_005E___0021(TypeDef P_0)
	{
		bool ısAbstract = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -482354564;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(((~(~(--1719573575 - --1260094181) + (~(0x3B346A18 ^ 0x416B86AB) + --1466739603)) ^ (-(~(-475837031 - 751239256) + -(0x5EC19395 ^ 0x16935E51)) + (-128935340 ^ -606639656))) * 1407032711 - num2 * 1352066521 * -513257535) * 293355089))) % 3;
					int num5 = -1005354720;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 *= -722126481;
						num5 = ~(~-337092222 - num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1973539522;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 1973539520;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = ~num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ısAbstract = P_0.IsAbstract;
					int[] array = new int[4];
					array[0] = 1199223916;
					array[1] = -91927797;
					array[2] = 2028487462;
					array[3] = -517482605;
					array[1] = array[2] ^ 0x1B61DF6C;
					array[1] = array[0] ^ -413456748;
					array[1] = array[0] ^ -1275904174;
					int[] array2 = new int[7] { -1473038525, -1818542137, 727576400, 1206067235, -1061835929, -44653258, -1920397931 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][2] ^ 0x2E4C4EF9;
					array2[3] = array2[2] ^ -1523516012;
					array2[5] = array2[0] ^ 0x27E5E20B;
					int num11 = array3[1][4] ^ 0x67E20870;
					num = (int)((num4 * 736074294) ^ 0x61E3A22E) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ısAbstract;
	}

	static void _0024_005E_002F_003E_005E_002F_0023_005E(TypeItem P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			P_0.IsAbstract = P_1;
		}
	}

	static bool _0025_005E_003E_0021_0028_005E_003C_002B(TypeDef P_0)
	{
		bool ısInterface = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -731362192;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~num2 - -(0x6128FA79 ^ -1390868788)) ^ ((-(-622086199 ^ 0x46B2DC6D) ^ -1255057282 ^ (~(-1820612753 ^ (-678803587 ^ -326955795)) + -1233782593 * -(~-997871348) * 1774285085)) - 497449772) ^ 0x699D9ED1)) % 3;
					int num5 = 646019893;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 646019891;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1290022900;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 1290022899;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 598021984;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 * -310997791 * 2038303325;
							num9 = (num9 - (-689370505 ^ 0x42546027)) * -1651259887;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ısInterface = P_0.IsInterface;
					int[] array = new int[4];
					array[0] = 123943222;
					array[1] = 1708009070;
					array[2] = 485863803;
					array[3] = 1518833094;
					array[0] = array[2] ^ 0x18236FC4;
					array[0] = array[2] ^ 0x4DF9B8AD;
					array[0] = array[3] ^ -1353041619;
					int[] array2 = new int[5] { 18894964, 842221538, 36074296, -606567318, -1296548581 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][3] ^ 0x7572329F;
					array2[1] = array2[0] ^ -422011311;
					array2[2] = array2[1] ^ -1161452549;
					array2[4] ^= 1274715561;
					int num11 = array3[1][0] ^ -100899336;
					num = (int)((num4 * 563572133) ^ 0x13C013DC) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ısInterface;
	}

	static void _0024_002B_0028_0029_002A_005E_0023_0023(TypeItem P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -490777018;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~num2 * -847359181 - -(-(58597549 - -428387712) + (-94048275 * 2021685115 - (0x7775AF1 ^ -1536009713)) - (-1826361064 + -1008349524 + (1475202523 - -712571932) - (0x16BD4BE9 ^ -1051017351))) * 1635197491 * 979535075))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1207690206;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 ^ -1485271686) - 281915716;
						num7 = (-491293223 - -1098400397 - num7) ^ -1009611168;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1054658505;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9;
							num9 = 1313379519 - -306774876 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.IsInterface = P_1;
					int[] array = new int[4];
					array[0] = 764468585;
					array[1] = -1253093907;
					array[2] = 1987329178;
					array[3] = -814548619;
					array[2] = array[0] ^ 0x709CD2EB;
					array[2] = array[0] ^ -322030245;
					int[] array2 = new int[6] { -1933013793, -1776074911, 654674220, -1030801599, -985003952, -2060882765 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[5] = array3[0][3] ^ 0x2D9BC950;
					array2[3] = array2[5] ^ -1431259025;
					array2[4] = array2[2] ^ -1579561581;
					array2[0] = array2[4] ^ -2007805669;
					int num11 = array3[1][5] ^ -419922337;
					num = (int)((num4 * 1370889761) ^ 0x7AF3A724) ^ num11;
				}
			}
		}
	}

	static bool _0025_0023_005E_005E_0040_005E_0024_0024(TypeDef P_0)
	{
		bool ısValueType = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1756941750;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-562523162 - ~(-(((~num2 ^ (1564900305 * ~(2016887229 * (~(-1005252867 * 866608649) - (-350421032 + -251311354))) - (~(-((-1297796454 - -1801262000 - 1637860300 * -1979018043) * 688667937)) ^ (-((-1272477941 ^ --344343426) + -1836243395) ^ (934601837 * -(480610568 - -1746223111 - (-1199158134 + 2122085942))))) - (-726439885 ^ (~((0x7AF4E34B ^ 0x12EB1F16) + -1678140906) - (-(-135206310 ^ 0x3A2D05AF) - (2066434204 * -953561551 + (0x168A946 ^ 0x164BCA24)) * 1563437355))))) * -1114882209) ^ -1195008650))))) % 3;
					int num5 = -1731678702;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * -1837073335 - 1108889742;
						num5 += -363610775;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 176271436;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += -176271434;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 759696313;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9;
							num9 = -num9 * -477292995;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ısValueType = P_0.IsValueType;
					int[] array = new int[7];
					array[0] = -1391690498;
					array[1] = -1119662043;
					array[2] = 628067620;
					array[3] = -1325538204;
					array[4] = -1667429991;
					array[5] = 1800542764;
					array[6] = 136479237;
					array[4] = array[1] ^ -428605176;
					array[1] = array[3] ^ -1980120544;
					array[6] = array[4] ^ 0x72E1CD6A;
					int[] array2 = new int[6];
					array2[0] = 1020464911;
					array2[1] = -966485001;
					array2[2] = -472154301;
					array2[3] = 1364481188;
					array2[4] = 1284791471;
					array2[5] = -858120594;
					array2[3] = array[2] ^ 0x68AFFC5;
					array2[5] ^= -1103161762;
					array2[0] = array2[5] ^ 0x52A4647B;
					array2[2] ^= -1118226198;
					int num11 = array2[3] ^ 0x73BA8312;
					num = ((int)num4 * -119888600) ^ 0x3B33F8F0 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ısValueType;
	}

	static void _005E_0029_0021_003E_0024_0029_003D_0024(TypeItem P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			P_0.IsValueType = P_1;
		}
	}

	static void _002A_0024_005E_003D_0040_002F_0021_0028(NamespaceItem P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1699005414;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(((((-(~num2 ^ (-872351338 ^ (-846407453 * 454242413) ^ (~(-(--1596953427 ^ -1025673823)) * 1538418133 - 1400859843 * 1145238437 + (0x1759E2F6 ^ ~(-(2001110351 * 298407493 - (-1490103848 ^ -1646736409))))))) - ((-775156804 ^ 0x219DE7A0) + ((-1272610916 ^ -1111805994) - (-1207512415 ^ -903348136)) + -1224468513 * 2057438525 + ~(~(-(0xFCF299B ^ -1552515225))))) * 329413361) ^ (-1781949851 - (0x1FA27CA5 ^ -26603376) - ((-256444821 + (1270123378 - -999674700)) ^ 0x6067ECFA))) * -449106183 + (-220032206 - -1792793040 - (1377164796 + 217750775))) ^ -891080509))) % 3;
					int num5 = 1552808756;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * -1794746243 - -2020026115;
						num5 = -1471559705 - -num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -716391123;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 * 2059438537 + 454283050;
						num7 ^= -1639706832;
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
						return;
					}
					P_0.Name = P_1;
					int[] array = new int[4];
					array[0] = -2008518406;
					array[1] = 2095976666;
					array[2] = 1981385821;
					array[3] = -1073722979;
					array[1] = array[2] ^ -1168927362;
					array[2] = array[3] ^ 0x1EF024A4;
					int[] array2 = new int[4];
					array2[0] = -1058946034;
					array2[1] = 612665936;
					array2[2] = -219057153;
					array2[3] = 931737521;
					array2[2] = array[3] ^ -114913789;
					array2[3] = array2[0] ^ -1951731759;
					array2[0] ^= -1708708325;
					int num11 = array2[2] ^ 0x73E6EF9E;
					num = ((int)num4 * -1798160744) ^ -1768560096 ^ num11;
				}
			}
		}
	}

	static void _0025_003E_005E_003D_0040_0021_002D_005E(NamespaceItem P_0, IReadOnlyList<TypeItem> P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -639774671;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(((-294855419 - (-(1152036819 * -400589205) - (-1979075154 + (1147829900 + -1836044938) + -591823311 * ~-1278332753 - (-2118730114 ^ -309777537)) - -777920384 - (num2 ^ (((909291851 * (--2372776 + ((-1922683527 ^ --1115504111) - (0x50E4DDAC ^ -194528901) - (-1281974747 * (1782482123 + -895431747) - -1565725595 * (0x53FDBCAB ^ 0x243238E3))))) ^ 0x194FF5A2) + (-((-1815380676 + 42745313 * -1833574006 + -(-1193449079 - -2031520780)) * -760056455 - (0x2DC2E001 ^ -148465482)) - ((~((-1474402670 ^ -780877380) - (-1067172597 ^ -884649103)) - ((0x27E1F0F ^ -1221963130) - (-1392531259 + -698557645 + 1045966219))) ^ -2023230207)) - ((-(~((2051387917 - 2116775428) * -1180860265) - (0x20556C88 ^ -682059973)) * -594881575) ^ -1362391260) * -238702689)) * -628324479 * -365044899) * -285865147) ^ (-(204526115 * -280171313) - ((0x7FCF1999 ^ -368591349) + ~-1896947418))) + ((-1358631011 ^ 0x758B51B9) - (-1433072444 - 508485022))) ^ -1183635623)) % 3;
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
					int num7 = 2;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 - 2131355603;
						num7 = 1341336338 - (1860981687 - num7);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -967278839;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= -1335574727;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Types = P_1;
					int[] array = new int[5] { -1259668230, 1454978201, -593284417, 992620568, -101093009 };
					array[0] ^= -1739363514;
					array[1] = array[2] ^ -1673629900;
					int[] array2 = new int[4] { 63685129, 1996426385, 903683546, 964189448 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][2] ^ -668002187;
					array2[2] = array2[1] ^ 0x271A235C;
					array2[0] = array2[2] ^ 0x472CBBDA;
					int num11 = array3[1][1] ^ -928408643;
					num = (int)((num4 * 1894028110) ^ 0xC3803DBCu) ^ num11;
				}
			}
		}
	}

	static void _0024_003C__003E_002B_0024_0025_0024(AssemblyProfile P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1324693534;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(~(~(num2 - ~(-(-(~(-(0x267DD992 ^ (1208020034 + --1357090543 + (-763634937 ^ -453470440)))))))) * 30346993 - (-1333060578 + -(~(~1312109966 + (-370856742 - -520078776) + (--1882879303 ^ -452475740))))))))) % 3;
					int num5 = -105655202;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 - 1244684950);
						num5 = ~num5 - -1297512551;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 536743906;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 ^ -733217767) - -446990174;
						num7 = ~(num7 - (0x4DFA1625 ^ 0x585F94F5));
					}
					if (num3 != (uint)num7)
					{
						int num9 = 52891439;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ -1523830178) * -583604989;
							num9 = 327632552 - (num9 + 1514488883);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.FilePath = P_1;
					int[] array = new int[6] { 1005227305, 233006356, 1494277918, 1041596552, 581686132, -611111149 };
					array[5] ^= -1815325829;
					array[2] = array[3] ^ 0x6072B725;
					int[] array2 = new int[5];
					array2[0] = -1280059672;
					array2[1] = -1865707699;
					array2[2] = 763060480;
					array2[3] = -974301528;
					array2[4] = -1374503906;
					array2[1] = array[3] ^ 0x3E51CD53;
					array2[0] = array2[4] ^ 0x14298BEC;
					array2[2] ^= -243111691;
					array2[2] ^= -1281529517;
					int num11 = array2[1] ^ 0x7ECF1C80;
					num = (int)((num4 * 208376992) ^ 0x48DDEBA0) ^ num11;
				}
			}
		}
	}

	static string _0024_003F_0040_005E_0025_005E_002D_0029(string P_0)
	{
		string fileName = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -626843043;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(((-(~(num2 * -2079199229) * -2072308107 + ((-(0x6150EB4D ^ -1120594404) + 563713435 * (851459839 * -1362217248)) ^ ~(997965789 - -(-1670977570 ^ -1388197831)))) * -1712159775) ^ (0x5A3B4B13 ^ -(0x27C81B7F ^ -1548196602))) - (175006973 + 2024342828 - (-897039416 ^ -207214706))) ^ 0x279509E8)) % 3;
					int num5 = 246650238;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= 1598465343;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 54508727;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x33FBCB6;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1516714892;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 * 1828180403 * -89595521;
							num9 = -num9 - 67444295;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					fileName = Path.GetFileName(P_0);
					int[,] array = new int[4, 3];
					array[0, 0] = -398904371;
					array[0, 1] = -1044460606;
					array[0, 2] = -251360173;
					array[1, 0] = -2109727278;
					array[1, 1] = 1497590078;
					array[1, 2] = -339127018;
					array[2, 0] = 2085931587;
					array[2, 1] = 91122548;
					array[2, 2] = -1850677043;
					array[3, 0] = 1259380655;
					array[3, 1] = -217344547;
					array[3, 2] = 160069852;
					array[2, 1] = array[2, 2] ^ -1148312250;
					array[3, 1] = array[0, 1] ^ 0x456AA0E3;
					array[2, 1] = array[3, 1] ^ -1693695817;
					array[3, 1] = array[2, 2] ^ 0x288AF8DA;
					int num11 = array[3, 1] ^ -2020529122;
					num = ((int)num4 * -1734580216) ^ 0x3EF62FD8 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return fileName;
	}

	static void _005E_005E_0040_0025_002D_0028_0040_002A(AssemblyProfile P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1383568897;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((~num2 ^ ((-1653181763 - -(-(1034366077 + 205798172 + -2069625180 * -1013465001) + 741822251 * 1878538386 - ~(1694289637 * 1185849857))) ^ -((-1031377360 ^ -1031764689) - (910272199 * (-1153486947 ^ -1951452501) - (~(-1845064181 * -1266653529) + -(983289382 * 2002535855)) - --946117438)))) * -1298500229))) % 3;
					int num5 = 1859068261;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0x6ECF2165;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1847769280;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = 1847769282 - num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 408953601;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 + 1634472892 - 947687106;
							num9 = (1922575959 - num9) ^ 0x3C709791;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.FileName = P_1;
					int[] array = new int[7];
					array[0] = 1755371891;
					array[1] = 801763456;
					array[2] = 258521154;
					array[3] = -835691836;
					array[4] = -1012511287;
					array[5] = -1833092949;
					array[6] = -1451151091;
					array[2] = array[0] ^ 0x6127EDF1;
					array[0] = array[4] ^ -1875094805;
					int[] array2 = new int[7] { 834546350, 653050072, -1564204875, 1942811552, 1053574115, 1278777031, -212851182 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][1] ^ 0x42BA2788;
					array2[1] ^= -134481885;
					array2[4] = array2[2] ^ 0x7D7ED3FB;
					array2[5] = array2[3] ^ -2042674172;
					int num11 = array3[1][3] ^ 0x58E47E0A;
					num = ((int)num4 * -172941721) ^ -1143450394 ^ num11;
				}
			}
		}
	}

	static string @_002F_003D_005E_0024_005E_002F_002F(string P_0)
	{
		string extension = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -689459965;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~((-(-(-(-(-num2))) * -351848377) + -(-35492053 + 1069461657)) ^ -244410108)))) % 3;
					int num5 = -870350576;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 * -1579756191) ^ -1869326744;
						num5 = -num5 ^ -1318498448;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 33712161;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(~num7);
						num7 = (num7 - (2031043347 + -948836323)) ^ -560985874;
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
					extension = Path.GetExtension(P_0);
					int[] array = new int[6] { 981062615, -954392111, -2113669411, 144241211, -1776937067, 1323838791 };
					array[4] ^= 1958921432;
					array[3] = array[1] ^ -694337083;
					array[4] ^= -457514961;
					int[] array2 = new int[4] { 40621100, 1956505151, -1642229749, -1051525054 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][5] ^ -1803662321;
					array2[1] ^= -323483297;
					array2[1] = array2[2] ^ 0x5244EC6;
					int num11 = array3[1][0] ^ 0x1C2BB63F;
					num = (int)((num4 * 234993370) ^ 0x6F90384E) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return extension;
	}

	static void _002F_003E_002D_005E_005E_002F_002D_0025(AssemblyProfile P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 45109632;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(~num2) * -790933193) ^ -(1780039473 * -227207559))) % 3;
					int num5 = -344813752;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= -344813752;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1560045991;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += -1560045990;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1897400348;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -1897400350;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.FileExtension = P_1;
					int[] array = new int[4] { -996936458, 1904303541, -654866701, -1508470592 };
					array[1] ^= -726638650;
					array[1] = array[2] ^ 0x76C40E67;
					int[] array2 = new int[7];
					array2[0] = 588111320;
					array2[1] = 843163288;
					array2[2] = 1276539844;
					array2[3] = 463383371;
					array2[4] = -1135735173;
					array2[5] = -1396607823;
					array2[6] = -440318286;
					array2[4] = array[0] ^ 0x6B5D8EB6;
					array2[2] ^= -1204462457;
					array2[1] = array2[6] ^ 0x53BD0F1;
					int num11 = array2[4] ^ -1383084170;
					num = ((int)num4 * -28472536) ^ -42880360 ^ num11;
				}
			}
		}
	}

	static long _0024_0026_003C_005E_003E_0023_0024_0026(FileInfo P_0)
	{
		long length = default(long);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 759303426;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(-(~num2) - -((226635643 * -(~(-432840232 - -14961112)) + (~(1925982101 * -1964674652) + 1388479672 + ~(~-867240461 - -623454283 * 242927416))) ^ -(~(~((-1473219579 ^ -245302979) - (1183504045 + 674859063)))))) ^ (-(~561428839) ^ -(~(-1078360277)))) - (-1037425240 ^ -873531547) - (-145592621 ^ -(-1946405505 * -919321050)))) % 3;
					int num5 = -901369180;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -901369180 - num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1671367449;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = 1671367451 - num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = ~num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					length = P_0.Length;
					int[] array = new int[5];
					array[0] = 108734239;
					array[1] = -1923130902;
					array[2] = 663846515;
					array[3] = 291371749;
					array[4] = -123152797;
					array[1] = array[3] ^ -1864977562;
					array[1] = array[0] ^ 0x235EADEA;
					array[1] = array[3] ^ 0xD48DF06;
					int[] array2 = new int[6];
					array2[0] = 1173417325;
					array2[1] = -1027576914;
					array2[2] = 637502616;
					array2[3] = -1223492125;
					array2[4] = -828513146;
					array2[5] = -1098786590;
					array2[0] = array[0] ^ -1342797702;
					array2[1] = array2[3] ^ -494464129;
					array2[5] ^= 957932022;
					array2[5] = array2[0] ^ -1219991427;
					int num11 = array2[0] ^ 0x5C1DD6DE;
					num = (int)((num4 * 508693065) ^ 0x485BE049) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return length;
	}

	static void _0024_003F_003E_003F_0024_0028_003D_003C(AssemblyProfile P_0, long P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			P_0.FileSizeBytes = P_1;
		}
	}

	static void _003D_0024_003C_003C__005E_0024_003C(AssemblyProfile P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1753899215;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((((num2 * -2004317195 - (-(0x3FFA9234 ^ 0x7D893F71) ^ ((~174944148 + (434694713 + -(~1334028396 - (-1071591775 ^ 0x405F3379))) + ~(~(--2053450572))) ^ (802961543 * -(~(0x3BC831D4 ^ 0x267E3E23) * -2111013417))))) ^ 0x727E4B1D ^ 0x41B8EE20) * 750267501) ^ (-1219153809 * (-1393973580 - -(0x45FF6025 ^ -991961753))))) % 3;
					int num5 = -246694357;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= -246694357;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -2;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 428343287;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(~num9);
							num9 = (num9 ^ 0xABAAF3A) - -1931913988;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.FileSizeDisplay = P_1;
					int[] array = new int[7] { -241259237, -385735845, -1721326386, 124283148, -1032442256, 1041927736, -867814512 };
					array[4] ^= 358945211;
					array[5] = array[1] ^ 0x5E97016B;
					array[5] = array[0] ^ 0x6BA3187B;
					int[] array2 = new int[6];
					array2[0] = 243687328;
					array2[1] = 1704061267;
					array2[2] = -380020596;
					array2[3] = 922200034;
					array2[4] = -1713474313;
					array2[5] = -1276057717;
					array2[2] = array[0] ^ -1889031476;
					array2[0] ^= -1047149359;
					array2[3] = array2[4] ^ -258586470;
					int num11 = array2[2] ^ 0x46137F14;
					num = (int)((num4 * 1050037522) ^ 0x8923A880u) ^ num11;
				}
			}
		}
	}

	static AssemblyDef _005E_0025_0021_0029_0026_002A__0040(ModuleDef P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return P_0.Assembly;
		}
	}

	static UTF8String _003D_002F_0025_005E_003C_003E_002B_005E(AssemblyDef P_0)
	{
		UTF8String name = default(UTF8String);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -479137305;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(((0x7CC18B2C ^ -706301510) - (-(~num2) + ~-1199400583 - (1432315523 * (~-2094269567 * -452549209 * -1040410837) + (~811016415 - (~(-1629319065 ^ 0x30454D05) + -(1286575425 - -1519247373)))) * -577474187)) ^ -841851659) * 1288653303 - --10852536))) % 3;
					int num5 = -1506138532;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= -1506138532;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1826230155;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -1826230156;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 ^= -645567731;
							num9 ^= 0x7E6EDAF0;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					name = P_0.Name;
					int[] array = new int[7];
					array[0] = 1006019532;
					array[1] = 1187229868;
					array[2] = 8080717;
					array[3] = -1607657803;
					array[4] = -125515660;
					array[5] = 241701001;
					array[6] = 1297122125;
					array[1] = array[0] ^ -1331279746;
					array[0] ^= -1229162204;
					int[] array2 = new int[6];
					array2[0] = 1251579937;
					array2[1] = 747365901;
					array2[2] = -606214198;
					array2[3] = -1265577068;
					array2[4] = 36346621;
					array2[5] = 1170160571;
					array2[4] = array[2] ^ -1572199845;
					array2[0] = array2[2] ^ 0x465008C3;
					array2[2] = array2[1] ^ -2006793258;
					array2[5] ^= 391221324;
					int num11 = array2[4] ^ 0x5293B02;
					num = (int)((num4 * 1778220816) ^ 0xC3E6DEC0u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return name;
	}

	static string _003D_002A_0023_0024_0029_0040_005E_0028(string P_0)
	{
		string fileNameWithoutExtension = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1119003511;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(num2 + -(771506117 * (-1872326373 * (-1797582273 * (1903017278 - -1946535547 - ~1264020538 - -1922073541 * -1292266215) - -(-(1937517060 - ~-187879139))) - -16679309)) - (-(-1705651759 * ~(-1921422794 * 994915065 + ~567248157) - ~(-(-(--403626325)))) - ((-(-(-1136913348) ^ -1838132458) ^ -599534023) - ~(--991420273 ^ (-1354322901 - 1512462663 * 1522011179 + (0xCA0E4B7 ^ 0x1EAC8075)))) + (-(~(~(-1498727815 + 2095849336 + (0xD988F45 ^ 0x6F7E346E) + (-1228990207 ^ 0x70B9844B)))) + -(1065503453 * (769360423 * (-1838561968 ^ 0x5EF29207))))) + (-1759612394 - ((~(-830399183 ^ 0x4C01F6E) + -432077165) ^ 0x124E3E7A) * -424378697)) ^ -598438971 ^ (~(304597948 - -1765193373) + (-456136633 * 42679453 + -987257593) - (-2036684138 + -1617501419))))) % 3;
					int num5 = 298290990;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 * -1095781735);
						num5 = ~num5 + 749088317;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -2;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = ~num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -317290730;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= -70661085;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					fileNameWithoutExtension = Path.GetFileNameWithoutExtension(P_0);
					int[] array = new int[6];
					array[0] = 646145580;
					array[1] = -448114323;
					array[2] = -1551162282;
					array[3] = 1715792216;
					array[4] = 64019315;
					array[5] = 569794162;
					array[0] = array[2] ^ -439933899;
					array[2] = array[4] ^ 0x314396BB;
					int[] array2 = new int[4];
					array2[0] = -1148672874;
					array2[1] = -1202911751;
					array2[2] = -87891069;
					array2[3] = -1691186883;
					array2[1] = array[3] ^ 0x273E2163;
					array2[0] = array2[3] ^ 0x50B58EC1;
					array2[3] ^= -1681748780;
					int num11 = array2[1] ^ -724907945;
					num = ((int)num4 * -750820964) ^ -1524120728 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return fileNameWithoutExtension;
	}

	static UTF8String @_002F_002B_003E_0023_002F_003C_0021(string P_0)
	{
		UTF8String result = default(UTF8String);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -249802784;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(~((num2 - -(-(-132852597 * (-1093442956 - (--497274252 + -715787462))))) * 1864050543))))) % 3;
					int num5 = 1959929152;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(num5 * -826477107);
						num5 = -num5 ^ 0x34BAC0F0;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 385479690;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 385479689;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1609567226;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= 1595670357;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0;
					int[] array = new int[5];
					array[0] = 1143766973;
					array[1] = 1339914303;
					array[2] = 1647273206;
					array[3] = 1374085654;
					array[4] = 242389294;
					array[2] = array[1] ^ -312768983;
					array[0] = array[4] ^ -23885867;
					int[] array2 = new int[7] { 258799241, -221474855, 1202116473, -1446213117, 1281511406, -1697385506, 1915139428 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][4] ^ 0x3FFE1312;
					array2[5] = array2[6] ^ 0x5E89C96C;
					array2[0] = array2[3] ^ -123335523;
					int num11 = array3[1][4] ^ -2010330183;
					num = ((int)num4 * -1726772604) ^ 0x1F417394 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _002A_0021_002A_002B_0040_003C_0024_003E(AssemblyProfile P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -458697403;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(num2 - ~(46723369 * (-(((--798013601 - --868953936) ^ -(-792248640)) * -349537627) ^ -1196811570 ^ -1751420613))) - ~(-1761610885 * (-150724559 * (-(1464255779 * --684351242) * -1669917059))) + -570064819 * ~(-(--238443824) - ~(--2096918295) + (-1224251241 + 6107529))))) % 3;
					int num5 = 133699600;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 ^ -403024118;
						num5 = (num5 + (-234209525 ^ 0x160C0B81)) ^ -521158377;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 254355581;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(num7 * 943347567);
						num7 = num7 + (-831810056 - -2088996126) + 1190811725;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1014060318;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 * 585314867);
							num9 = ~num9 * -208406451;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.AssemblyName = P_1;
					int[,] array = new int[3, 4];
					array[0, 0] = 1954242042;
					array[0, 1] = 960601985;
					array[0, 2] = 742006799;
					array[0, 3] = -1255819501;
					array[1, 0] = 432836838;
					array[1, 1] = -954460882;
					array[1, 2] = -319334382;
					array[1, 3] = -1281463412;
					array[2, 0] = 22014779;
					array[2, 1] = 373589057;
					array[2, 2] = 215226740;
					array[2, 3] = -566901924;
					array[0, 1] = array[2, 0] ^ 0x37311BEB;
					array[2, 2] = array[2, 3] ^ 0x79D0EE24;
					array[0, 2] = array[1, 3] ^ 0x334310AD;
					int num11 = array[0, 2] ^ 0x3AF7E4AA;
					num = (int)((num4 * 1715194791) ^ 0x49AA065F) ^ num11;
				}
			}
		}
	}

	static string _0026_003C_0024_0040_0024_002A_0021_002F(ModuleDef P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return P_0.RuntimeVersion;
		}
	}

	static bool _002B_003F_0021_0023_003F_003F_0025_003F(string P_0)
	{
		bool result = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1832208579;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(-(-(~(((num2 - ~(-((~(-(592657938 - -690213769)) ^ ~(--1121533510 - -960811682) ^ ((-653088917 ^ 0x134C3382) * -1944836317 - (-1776556327 * (-582601936 ^ 0x44E989D7) - --1997130149))) - -1956536639) + ((609759523 * (~1764950015 + -1384466019 * (-26644179 * --2128680095)) - -(-(~1084059444 - (-213796953 ^ -360771137))) * -1309132199) ^ (~(-(--1534639694 - (-1068374284 - -2145964925)) ^ ((--1619503211 ^ 0x363F9824) * 1459102993)) + -(-(-535549895 * -1239958911) + -(~1352844837) + (0x4D007B71 ^ 0x51185D13)))))) * 904583407) ^ (448973471 * --1654811373 - -1245485696 + (155493531 * (~(0x49DF7C8B ^ -544524509) + ~(-1811921009 - 1458075059)) - (--1749643390 * -509634677 + -(-685898760 ^ 0x75242144)) * -1170177665) - -296851824)))) ^ (~75145041 - (-584201025 + -1396582892) - (--1748944284 + 2058530162))) ^ -1029483947))) % 3;
					int num5 = -141918592;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= -141918592;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1295048215;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ((-50948039 ^ -1412444257) - num7) ^ -508037606;
						num7 = -(num7 * 1151803405);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -743617006;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= -743617008;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = string.IsNullOrWhiteSpace(P_0);
					int[,] array = new int[4, 3];
					array[0, 0] = -187484484;
					array[0, 1] = -972850074;
					array[0, 2] = 2071949018;
					array[1, 0] = -839073782;
					array[1, 1] = 1790245269;
					array[1, 2] = 552584157;
					array[2, 0] = 1808635243;
					array[2, 1] = -786478289;
					array[2, 2] = -604519805;
					array[3, 0] = -2046853111;
					array[3, 1] = -1797542827;
					array[3, 2] = 1635527582;
					array[3, 2] = array[0, 2] ^ -1255678565;
					array[2, 2] = array[0, 2] ^ -1259724974;
					array[2, 2] = array[1, 0] ^ -186114227;
					array[3, 2] = array[0, 2] ^ -1793957044;
					int num11 = array[3, 2] ^ -1961047325;
					num = ((int)num4 * -658930863) ^ -1273494971 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _005E_002B_002A_0029_003E_003E_005E_003E(AssemblyProfile P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			P_0.RuntimeDisplay = P_1;
		}
	}

	static void _002D_003E_0021_002A_0023_0024_0028_0024(AssemblyProfile P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -559490887;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((((~(~num2) - (~(536292411 * -(1371806786 - (-1017432175 ^ -422191794))) ^ -1353223442 ^ ((-(0x7A259290 ^ -(0x2B08D21B ^ 0xBF76405)) - ((~-205759661 - --1199331908) * -2095431869 + (0x4631F406 ^ -937871305))) ^ -944121359))) * -1587030357 * -788684951 * -17829697) ^ --667369769) * 467260677)) % 3;
					int num5 = -833153726;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * -127191913 - 554049925;
						num5 = (num5 - 315601347) * -330834839;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 631860653;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7 * -1534839099;
						num7 = num7 - -1203468281 * 2103970629 - 1564691119;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1389033184;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 * 635615325 + 704897948;
							num9 = (num9 + (964982565 - -169174886)) ^ 0x602CB5DF;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.HasSdkReference = P_1;
					int[] array = new int[4];
					array[0] = -698300087;
					array[1] = 1631188266;
					array[2] = 1414022490;
					array[3] = -1286357122;
					array[1] = array[3] ^ -1858583477;
					array[0] = array[2] ^ 0x139536B;
					int[] array2 = new int[4] { 2138273515, -1166812565, -172481445, 1511147850 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][3] ^ -1176663950;
					array2[1] = array2[0] ^ 0xB5A80A3;
					array2[1] = array2[0] ^ 0x6C0A434D;
					int num11 = array3[1][0] ^ -1493343150;
					num = ((int)num4 * -2049586485) ^ -12815914 ^ num11;
				}
			}
		}
	}

	static void _003F_003D_0040_003E_003F_003C_005E_0023(AssemblyProfile P_0, int P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -293741213;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(((num2 + (~(-1021035129 * (-72400451 ^ -164043096)) + (-2094059542 ^ -1652245466) + (2107398987 * ((-(--742849555 * 1591116515 - (78204981 * -172668193 + 1138715495 * 1558488228)) - 1795830433) ^ ~(~(1404365807 * -(-1325870336 - -1018068711)))) + ~-900936595))) * 688356649 * -36767943 - 993638755 * -(-((0x6B6FEBE8 ^ 0xC4FD26C) - (505217685 - -470379688 - -857895848 * 177171041))) - 841870557) ^ -((--1281065940 * 1857276065) ^ 0x213EF9C9)) + ((0x38A9ACE8 ^ -1863916993) - (-1312588364 - -1950742991))) ^ -1608496503 ^ -1458751647)) % 3;
					int num5 = 2;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = 2126803891 * -339472255 - num5;
						num5 = ~(-num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 199059953;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 * 1460535323 * 484571055;
						num7 = num7 * -1868179955 - 2035433128;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1182793888;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = 1623867960 - ~num9;
							num9 = -num9 ^ 0x73F12D56;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.TypeCount = P_1;
					int[,] array = new int[4, 4];
					array[0, 0] = -1371523450;
					array[0, 1] = -381053791;
					array[0, 2] = -1538579493;
					array[0, 3] = -281989893;
					array[1, 0] = 3915152;
					array[1, 1] = 1146026098;
					array[1, 2] = 278918596;
					array[1, 3] = 1956376546;
					array[2, 0] = 1609431928;
					array[2, 1] = 809212687;
					array[2, 2] = -1326593859;
					array[2, 3] = -1964158758;
					array[3, 0] = -1987740998;
					array[3, 1] = -1687088774;
					array[3, 2] = 129768666;
					array[3, 3] = -1931385996;
					array[1, 2] = array[0, 2] ^ -1777522538;
					array[0, 3] = array[2, 3] ^ -21439941;
					array[1, 2] = array[1, 3] ^ 0x629B7994;
					int num11 = array[1, 2] ^ 0x2778223E;
					num = ((int)num4 * -1561086745) ^ -1108058113 ^ num11;
				}
			}
		}
	}

	static void _0024_003E_002F_0025_0040_003E_0029_0023(AssemblyProfile P_0, int P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1174290850;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(~((~(-(num2 + 1080099465 * ~(-766616099 ^ (657243655 * -1088807101 * 970708761 - (1125441689 * -(-960644085 ^ -1356899913) - 1802950708))))) - (-1239995138 - (-1568796123 + (--1062486877 + 438041011 * -270214211) - 392019823 * (761306093 - -339795614 - (0x38143931 ^ 0x73BF08B5))) - (~((0x10926D27 ^ 0x2CFA1B2D) + -270248139 + (-1178395737 ^ 0x68617C8)) - -(-179783275 + 332368919 * (-202801548 - 1593027350))))) * 934317821 * 1302378107) * 522491255)))) % 3;
					int num5 = 268435196;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 ^ -710934924);
						num5 = -num5 - 40208255;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 190591551;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += -190591550;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1610473138;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9 - -1393573942;
							num9 = -num9 - -588337374;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.MethodCount = P_1;
					int[,] array = new int[4, 3];
					array[0, 0] = 1908594615;
					array[0, 1] = -1681855860;
					array[0, 2] = -1555490738;
					array[1, 0] = 1233172216;
					array[1, 1] = 1230051544;
					array[1, 2] = 402625692;
					array[2, 0] = 1557688913;
					array[2, 1] = 1132334854;
					array[2, 2] = -1730341065;
					array[3, 0] = 268675521;
					array[3, 1] = 1305511591;
					array[3, 2] = 1200899214;
					array[2, 0] = array[3, 0] ^ 0x298EF778;
					array[3, 0] = array[0, 1] ^ 0x10F3C02A;
					array[3, 1] = array[0, 2] ^ -972074980;
					array[0, 1] = array[0, 0] ^ 0x67BA8AB8;
					int num11 = array[0, 1] ^ 0xCD7B174;
					num = ((int)num4 * -1696095472) ^ 0x554B1D70 ^ num11;
				}
			}
		}
	}

	static void _0028_0024_0026_002D_003F_0021_0025_0026(AssemblyProfile P_0, IReadOnlyList<NamespaceItem> P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 328468508;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((-1435003342 - ((-(-(-1938358916 * -1582713437 + (-1250743721 + -272952283)) + -(-1262594376 ^ -1242917201)) + 1165764816 - ((num2 + (-666591067 + (-1781766985 * (0x28E02B9C ^ -(1394672959 * -970383621)) + 373391000 - 133811894) - -1157788075 * (-94106341 * (--197321457 ^ (-1919496909 * (-201865863 * --274682273 * -661628481)))) + ((-265058757 * (-1118021215 ^ 0x11D247F4) + (-1082495595 + (0x4B7A5C39 ^ -1225543332)) + ((~(946395762 - -2084848364 - ~1373559357) + 427875331 * (1708153191 + -1526274455 - -373502093)) ^ -1024681316)) * 176364493 + (2030097844 + (~(-596260329) - ~(~1421524674 + (1723043413 - 2122991378 - (889557469 - -244420709)) + ~1890256880)))))) ^ (-2012246967 ^ ~((-(86210446 - ~-1125171623 * 918275623) ^ 0x583353DD) + -(-700560789 * ~(0x25FD6BF9 ^ 0x4E04150)))) ^ --1525154831)) ^ (((--1574710535 + (917551337 + 158042768)) ^ (-1074075110 + 1482845688) ^ 0x7E17577C) * -1143650339))) ^ ~(~(--1707694764))))) % 3;
					int num5 = 1067251026;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 - -1959944275) * -1852176859;
						num5 = -(num5 ^ -1463735585);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 - 378709988;
						num7 = 1213513533 - -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = -num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Namespaces = P_1;
					int[] array = new int[6];
					array[0] = -1638972323;
					array[1] = 436759106;
					array[2] = -957192779;
					array[3] = 593166725;
					array[4] = 965306822;
					array[5] = 1493744504;
					array[3] = array[2] ^ -767812620;
					array[1] = array[0] ^ -1694502228;
					int[] array2 = new int[7];
					array2[0] = 495436087;
					array2[1] = 1778522013;
					array2[2] = 1511697248;
					array2[3] = -2074893678;
					array2[4] = 1120548354;
					array2[5] = 1423415468;
					array2[6] = 927855844;
					array2[4] = array[2] ^ -223631967;
					array2[0] = array2[2] ^ 0x39114DDC;
					array2[0] = array2[2] ^ 0x7DBB6EEA;
					array2[2] = array2[0] ^ 0x4E2360E2;
					int num11 = array2[4] ^ 0x3387490A;
					num = (int)((num4 * 1202493646) ^ 0xFA00E1FAu) ^ num11;
				}
			}
		}
	}

	static int __003F_0029_0023_003C_0023_0023_0023(MethodItem P_0)
	{
		int token = default(int);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1448886759;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-((-(-(-((-(-1350697369 - 235777055) + ~(0x338E1A0A ^ 0x642E5397) + -(-(-1117293150)) + (~(-516652712 ^ 0x15BBC749) + -1670510427 * -1417955772) * 500306255 - (0x3F859200 ^ -(-2074284750 - 257227136 - 916173676) ^ ((-(-2103931626 + 1416694373) - (--720840988 - (-765032558 - -1698573106))) ^ (-1372686909 + ~1543052365 + --1450658146)))) * 597436667 * 254300811 - (num2 + (-(-1728279964 ^ -1060600807) + (866624903 * -(~(-1194130594 - -1169816888)) - ((1118682262 + -2028392781) * 1417240137 * 1054171693 * 1176842275 + (-920593469 ^ 0x4B8EB9DC) - (0x29492BD3 ^ ((-(1133174381 + 1310092814) - (~-1405196255 + (1104626697 + 717136832))) ^ -957626999))) - (-(-(~(-1722627652) - -1827699696 + ~728861552)) ^ (1861151697 * -(-1721408096 ^ 0x438A19E3))))))))) - -(1708180221 - -328376700 + (1132080362 - -528627390) - -(-291891567 ^ 0x3E40D73B))) * -314663009)) - -661159787)) % 3;
					int num5 = 1507102820;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = 1507102822 - num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -640538669;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -105527205;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9;
							num9 ^= 0x56FA26D3;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					token = P_0.Token;
					int[] array = new int[5];
					array[0] = 1778710036;
					array[1] = -1591929658;
					array[2] = -1497776393;
					array[3] = -1531237303;
					array[4] = 540598979;
					array[3] = array[1] ^ -1084682887;
					array[0] ^= 1403436411;
					array[3] = array[4] ^ 0x65B64AF4;
					int[] array2 = new int[4] { -1996254209, -1175509542, -712232139, -337384979 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][1] ^ 0x746319B5;
					array2[3] = array2[0] ^ 0x48361147;
					array2[1] = array2[0] ^ -1104923749;
					array2[3] = array2[2] ^ 0x7D415C69;
					int num11 = array3[1][2] ^ -1043628738;
					num = (int)((num4 * 2001426707) ^ 0xA9140F4Du) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return token;
	}

	static bool _005E_0026_002D_002A_005E_002F_002F_0026(MethodItem P_0)
	{
		bool ısSelected = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1761849525;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(1471123709 * -(-862726425 * -434091815 + -1107407597) - (~(0xF2B7B96 ^ ((-1470171745 ^ -1967525705) - (--741490813 - --362907900))) + (0x250011FC ^ ((0x463193A4 ^ ((-747063625 ^ -2115437001) - -1211755052)) * -202052685)) - (~num2 - (~(~369108396) + 1599768488 - (1554184611 * (624781080 * 280780227 * -2063933899 + ~(-39467275) - ~(0x183CD277 ^ -1964698051) + 1201900495 * -((-803113292 ^ -1144955984) - ~1036627488)) - -(-((0x1AE75334 ^ -(0x5C659526 ^ -1889321353)) - (0x14116684 ^ (-1013178894 - --719994382)))))) - (2132115942 + (-1871340236 ^ -(~(1094618352 - -955229862) * 2082827485 * 668495865))))) * 509080173) ^ -(1912666255 * 1019325918)) + (520364735 - 1587992485) - 1678607750)) % 3;
					int num5 = -31091788;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -num5 * 296391989;
						num5 = -54765032 - ~num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 487905365;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = 1553430358 - (num7 + (-1929124158 ^ 0x5917E73));
						num7 = -(num7 + -877023701 * 1421445903);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -629084602;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -629084604;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ısSelected = P_0.IsSelected;
					int[] array = new int[7];
					array[0] = -318455234;
					array[1] = -864004320;
					array[2] = 1038144187;
					array[3] = -293888682;
					array[4] = -643188339;
					array[5] = 481808750;
					array[6] = 1503816899;
					array[1] = array[3] ^ -1441809928;
					array[1] = array[2] ^ -1467031638;
					array[0] = array[6] ^ -1018917978;
					int[] array2 = new int[5] { -1821121143, -2067564702, -1993619948, -457969765, 1427072623 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][2] ^ 0x30DB9FA5;
					array2[4] = array2[1] ^ 0x667F2B77;
					array2[4] = array2[3] ^ 0x2DF16800;
					int num11 = array3[1][1] ^ 0x30814F98;
					num = (int)((num4 * 1907367456) ^ 0x70195240) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ısSelected;
	}

	static TypeDef __0025_0040__005E_0026_0025_002F(MethodDef P_0)
	{
		TypeDef declaringType = default(TypeDef);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -203988988;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((((-(~(-num2 - 863569509 * ~(--1870718127 ^ 0x29E0AFB5)) * 689359965) - (-1978861753 + ~(~-1201633496)) - -2146081408) ^ 0x346EECB0) + 1896299000) * -241524189)) % 3;
					int num5 = -1330979922;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -1330979920 - num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 -= 1827022714 - -1573759657;
						num7 = -num7 - -1212480369;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
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
					declaringType = P_0.DeclaringType;
					int[] array = new int[6];
					array[0] = -1705738835;
					array[1] = -250114336;
					array[2] = -1061717070;
					array[3] = -1532209707;
					array[4] = -892219835;
					array[5] = 2031377746;
					array[1] = array[0] ^ -231976715;
					array[2] = array[5] ^ -801852756;
					int[] array2 = new int[4] { -694350730, -2098368132, -1556695456, -1474230742 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][0] ^ -1169677999;
					array2[0] ^= -1691792721;
					array2[2] = array2[0] ^ -1676351700;
					array2[1] = array2[2] ^ -1785781918;
					int num11 = array3[1][3] ^ -798149751;
					num = ((int)num4 * -974303970) ^ 0xA759452 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return declaringType;
	}

	static MethodDef _005E_002F_005E_0024_003D_003F_002A_003E(TypeDef P_0, UTF8String P_1)
	{
		MethodDef result = default(MethodDef);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1100623396;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((num2 * 308225733 + ~(-(-724969021 ^ ~(-2035807570 ^ -(-1160968614)))) * -1633007551) ^ (~((~1973502815 - -1623770609) * -1086414997 + -(-(~-1694805706)) + ((-409985931 - 1292347659 - --748545192 + (~-1654227311 + -2029810324)) ^ (1818871487 * -(-789816435 * -1276792845)))) ^ ~((~(0x7FC9734F ^ --1521922291) + -(1318823485 + 189326213 * 487064396)) ^ -1332921127))))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(num7 ^ 0x654F15A8);
						num7 = ~(-num7);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 497025000;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = --1965133226 - num9;
							num9 = ~(num9 - ~430862919);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.FindMethod(P_1);
					int[,] array = new int[3, 3];
					array[0, 0] = 245899088;
					array[0, 1] = -513260264;
					array[0, 2] = 786218034;
					array[1, 0] = 443923129;
					array[1, 1] = 1233173933;
					array[1, 2] = -1082164811;
					array[2, 0] = 1132210960;
					array[2, 1] = 1886451452;
					array[2, 2] = 1344544499;
					array[0, 1] = array[2, 2] ^ 0x2DD6F118;
					array[2, 2] = array[0, 2] ^ -1731325158;
					array[1, 2] = array[1, 1] ^ -2004867102;
					array[2, 2] = array[0, 2] ^ -1073372967;
					int num11 = array[2, 2] ^ 0x13144161;
					num = ((int)num4 * -601423113) ^ -1213484173 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static CustomAttributeCollection _0028_003C_0025_0021_005E_003E_0028_0040(MethodDef P_0)
	{
		CustomAttributeCollection customAttributes = default(CustomAttributeCollection);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1849887068;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-641591117 ^ -1981455019) - ~(~((~num2 - ~(((~(1738112824 + 141417368 - ~1313825949) - -(0x532EA0F5 ^ -928470064) - (-(-1591473892 * -597615843) ^ -1197757514)) ^ -1847285645) * -1727332273)) ^ ((((1322744345 * -(1532069475 - 1790575862)) ^ ~(754015076 + -1356736089 - -1906196450)) + -1617065884) * 1937955707 * -681147613) ^ ((-((-1131484150 ^ -1448947130) * 1243750161) ^ (-(-62974521 ^ 0x706447D8) + (-2072992019 - (--1681305912 ^ 0x70C2E7D4)))) * -1904848595) ^ ~(-1867213082 ^ (--38095224 + -489505422) ^ --1650411646))))) % 3;
					int num5 = -1297482477;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= -1297482477;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2030988391;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x790E6C65;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1409103247;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~29775059 - num9;
							num9 = -1504790598 - num9 - 1377019733;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					customAttributes = P_0.CustomAttributes;
					int[,] array = new int[4, 3];
					array[0, 0] = 1498593279;
					array[0, 1] = 637441077;
					array[0, 2] = 1410805917;
					array[1, 0] = 2095163188;
					array[1, 1] = 976520082;
					array[1, 2] = -1989763839;
					array[2, 0] = 57294422;
					array[2, 1] = -1986120768;
					array[2, 2] = 2083286108;
					array[3, 0] = -470244567;
					array[3, 1] = 1748432735;
					array[3, 2] = 421229150;
					array[1, 0] = array[2, 1] ^ 0x40D33327;
					array[0, 1] = array[0, 2] ^ 0x567F027;
					array[0, 2] = array[2, 2] ^ -1061909979;
					array[1, 1] = array[0, 0] ^ 0x3708D09;
					int num11 = array[1, 1] ^ -535722446;
					num = (int)((num4 * 146598695) ^ 0x45845D) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return customAttributes;
	}

	static void _002D_003C_005E_003C_0024_0040_0024_002B(ModuleWriterOptionsBase P_0, ILogger P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 82002840;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(~(--779035441 ^ -1878578537)) - (-471239215 * (907276694 + (-555626099 - -2013322925) * 1605296113 - -((-140274930 - -363838485) * -1701824895)) - ((-(~(209508679 * 1970104292) + ~(314621512 * 2093959265) + ((-45242594 ^ 0x3F7702D3) * -98649083 + 444826093)) + -(-484919191 * (-681977407 * (1801842568 - 674339047))) * -1526692381) * 2056592801 - ~(num2 + ~(-(-552436359 ^ ~(~(-(~1902198861)) - (~(~1167854700 + --1699584369) - (~(918409730 * -1018491177) + -(-2087785274 * 1132368685))))))) - ~(~(~(~(-1561394448 * -1883221757))))))) * -299559481)) % 3;
					int num5 = -992814518;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= -992814520;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -517566015;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(num7 * -1804868897);
						num7 = -(~num7);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = ~num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.MetadataLogger = P_1;
					int[] array = new int[4];
					array[0] = -64551678;
					array[1] = 966609396;
					array[2] = 610145662;
					array[3] = 533278392;
					array[0] = array[3] ^ -351143740;
					array[2] ^= -128616283;
					int[] array2 = new int[6];
					array2[0] = 765587067;
					array2[1] = -1683060364;
					array2[2] = 949855151;
					array2[3] = 1486739364;
					array2[4] = -495513312;
					array2[5] = -637512862;
					array2[5] = array[3] ^ 0x140261F8;
					array2[2] = array2[5] ^ 0x360F762B;
					array2[4] = array2[3] ^ 0x3D22A6C2;
					array2[3] = array2[1] ^ 0x3C0BCB52;
					int num11 = array2[5] ^ 0xE8735BD;
					num = ((int)num4 * -1060567167) ^ -1162076783 ^ num11;
				}
			}
		}
	}

	static void _005E_0024_0040_002B_0024_003C_0040_0024(ModuleWriterOptionsBase P_0, ILogger P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1138570022;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(-283591707 * -898438375 - -1051601701)) + -(((-2099814515 ^ -1390300480) + -(-413275873 * -860456183)) * -457522021 + 748124207 * 727713039) - (~num2 ^ 0x1CBA869B) - ((1482270905 * -507068191 + ((~784092668 - (331247108 - -1988168609) + (--1900603520 - ~-1237269423)) ^ -1781947385)) ^ (-958644911 * ~(0x734B6D3 ^ --1022972414))) - ~(--1041151631 - ~-569782854 - (266794988 - -711937744) * -515423661 - (-1116143555 + --131793869 - -(0x44ADCA24 ^ -1527691363))) - 448226657 * 784076509 - (-(--1589434519) ^ -(~-804848113)))) % 3;
					int num5 = -41389092;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 ^ 0x308011C1) - 1313089966;
						num5 = ~(~num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1986930223;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 *= 1534422871;
						num7 = ~num7 * 532465669;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 116819298;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9 ^ -1808178566;
							num9 = num9 * 82543377 + 1529338239;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Logger = P_1;
					int[] array = new int[6];
					array[0] = -2111377324;
					array[1] = 213358666;
					array[2] = 1611164144;
					array[3] = -1817357533;
					array[4] = 1690402919;
					array[5] = -5489751;
					array[1] = array[0] ^ 0x36BB40A5;
					array[0] ^= 1843988132;
					array[4] = array[1] ^ 0x5AA5E39E;
					int[] array2 = new int[4] { -1694955369, 163400820, -267646287, -116808183 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][2] ^ 0x7E7D2366;
					array2[2] ^= 1609967943;
					array2[3] = array2[1] ^ 0x3CBD4B0E;
					int num11 = array3[1][1] ^ -916226465;
					num = (int)((num4 * 880278267) ^ 0xE451B0BAu) ^ num11;
				}
			}
		}
	}

	static MetadataOptions _002B_002B_003F_003F_0024_0024_0029_0040(ModuleWriterOptionsBase P_0)
	{
		MetadataOptions metadataOptions = default(MetadataOptions);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1039984183;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((-1219004209 ^ -(-1854135134 - (-(~-210317974 - -1900536722) - ((0x5AB4E7D5 ^ 0x19204956) + (-634189656 ^ -1291100324))))) + (-2065058440 ^ ~(-((-886202943 ^ --1235402255 ^ -1472931372) * 56399353))) - (num2 - ~(~(-(~(202332531 + (-262152724 - 518257098)) * -952422727 - -((-1765196860 ^ 0x12AB8B89) - (1925792174 - -627591676)) * -810388315)) ^ ((0x5F1DAF36 ^ -(-((--916100326 * 921508625) ^ -1372712357))) - -((((-560600901 ^ 0x3553A659) + (-1703942191 + --1644691657)) ^ -(~(0x42C112E3 ^ -1257795624))) - -(-460118592 ^ 0x245DBB16)))))) * 886108815 + (0x4A83DD4B ^ (((-(~1288896389) + ~-466992355 * 184941229) ^ -(-1906956238 ^ -1049372520)) - 346390175 * (203807384 - (-641339659 - (-1710761500 + 1844680557))))))) % 3;
					int num5 = 19244036;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 + -1668468071) ^ -1029768671;
						num5 = ~num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2029277049;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 * 1139401987) ^ 0x16D1F285;
						num7 = (num7 ^ -1775974819) * 1984924065;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 ^ 0x4EB3872);
							num9 = -(num9 ^ 0x2BC0DA30);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					metadataOptions = P_0.MetadataOptions;
					int[,] array = new int[3, 3]
					{
						{ 1604738978, -1957404931, 545104820 },
						{ -1101197344, -81449370, -696038718 },
						{ -2017659939, 967433022, -874760176 }
					};
					array[2, 2] ^= -1495871482;
					array[1, 1] = array[2, 2] ^ -1394577360;
					array[2, 2] ^= -1889366616;
					array[2, 0] = array[2, 1] ^ -76218881;
					int num11 = array[2, 0] ^ -2116258657;
					num = (int)((num4 * 814938717) ^ 0x85A6378Au) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return metadataOptions;
	}

	static void _0024_003F_0024_0025_002D_002F_0040_003C(ModuleDef P_0, Stream P_1, ModuleWriterOptions P_2)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 432632697;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(525695933 + 1954311137 + (0x617DC498 ^ -1881999302))) - ((~(-num2 - (~(~(-(~(1175408245 * (656971772 * -1140055281))))) + ((-1106746514 ^ -896464144) + ((0x2A98BAC0 ^ 0x554F05A2) - (~184413463 + (-1538680346 ^ 0x169CECA0)) - -(-(~-455169129))) + (1542879011 - 509917375 * -(-815425079 - (-997883988 + -1041352721)))) - ~1516810016 * -1134510843)) * -1529698229) ^ -(1606087391 * -332165474 - (-1562113287 - -1312322919) + -(649529456 + 1079275655 - (826272777 + -1093042174)))))) % 3;
					int num5 = 1067039975;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0x3F99BCE7;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7;
						num7 = ~(~num7);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = ~num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Write(P_1, P_2);
					int[] array = new int[7];
					array[0] = -120396916;
					array[1] = 1999790711;
					array[2] = 252134746;
					array[3] = -902819474;
					array[4] = 1277166911;
					array[5] = 660464368;
					array[6] = 998402349;
					array[2] = array[5] ^ 0x3C657570;
					array[1] = array[6] ^ -521815902;
					int[] array2 = new int[5] { -1091244579, -958234854, -1102035199, -244942567, 1293506712 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][4] ^ -1444450490;
					array2[1] = array2[0] ^ 0x4733C10C;
					array2[1] = array2[4] ^ 0x2A838EB5;
					array2[3] = array2[2] ^ 0x5B9A3728;
					int num11 = array3[1][4] ^ -1416659062;
					num = (int)((num4 * 305689181) ^ 0x5BED5A53) ^ num11;
				}
			}
		}
	}

	static byte[] _003F_0021_002F__0040__003C_0024(MemoryStream P_0)
	{
		byte[] result = default(byte[]);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1925906762;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(~((~(~(((num2 ^ (-822288035 * (-1198943171 ^ (-228905979 * -(~(-1778073343 * (-1644603410 - 113619564) - ~(-841329247 + -1672356151) + -(0x1AC3D719 ^ -1361743818))))))) + ((-46493555 * ~(1274530024 - -1366692079 + --543772114 - -434353315 * (1521552412 - -707386075) - (-1873920848 ^ -1835062511) - (-1159447775 * -832749223 - 1943160677 * (-1931311286 - 481243922 + 1373873051 * -1777104209)))) ^ -570260429)) * -350167707)) - ((-(0x2162A8BE ^ 0x32B32933) ^ 0x3C18DEED) + ~(~(1216775296 * -1426269399)))) * -364325355))))) % 3;
					int num5 = 42052702;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0x281AC5E;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 665019422;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7 * 893252539;
						num7 = (num7 - ~20667340) * 277853205;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 479819789;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 * -1705851739) ^ 0x13F9ECB9;
							num9 = -1919311648 - -num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.ToArray();
					int[,] array = new int[3, 4];
					array[0, 0] = 1660151364;
					array[0, 1] = -113406827;
					array[0, 2] = 873717721;
					array[0, 3] = 783937735;
					array[1, 0] = 1382960525;
					array[1, 1] = 1583947015;
					array[1, 2] = -1847998477;
					array[1, 3] = 1925235788;
					array[2, 0] = -2035085764;
					array[2, 1] = 258280391;
					array[2, 2] = -499351794;
					array[2, 3] = -6871210;
					array[1, 2] = array[1, 1] ^ -838076939;
					array[2, 2] = array[2, 1] ^ 0x7B410DEA;
					array[2, 2] = array[2, 0] ^ 0x47866D72;
					int num11 = array[2, 2] ^ 0x66DBF8A0;
					num = ((int)num4 * -525691172) ^ 0x5C26D70 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static ParameterList _003C_0026_003D_003D_003C_003F_003F_003C(MethodDef P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return P_0.Parameters;
		}
	}

	static string _003D_0040_0029_003D_0024_002D_002F_0029(string P_0, IEnumerable<string> P_1)
	{
		string result = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -2047220233;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(~(-(~(-((num2 + ~(~(-(-(1818194995 * (~1363117518 - (-1900370236 - 877576812)) + ~-1941550757) - ~((122988365 + -2018985264 + 1083097902 * -823023753) * 1464220219 * -1247620111))))) ^ (~(~(-244809290 - --1648417127) * 1595523287) ^ (1190874327 * (-(--423146337) - ~(-1257448086 ^ 0x4168AE01)) * 514431041) ^ -(-((~1458399729 - 1369917914) * -1544642047 * 1243378423)) ^ (-804311667 ^ ~(0x2E3FD96A ^ (424077059 * -447508141 - -455230929 * -1675964642 - -(-761061802 + 313386262) + (--1520349703 + -1879742102)))))))) ^ 0x38BDCC93))) - -336645855)) % 3;
					int num5 = 354996986;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 * -1270629687) ^ -836473436;
						num5 = ~(-345171601 - 38188055 - num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 30;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 ^= 0x39C61724;
						num7 = -num7 ^ 0x32D0112;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1878880317;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(~num9);
							num9 = (num9 ^ 0x2140345A) - 1208050681;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = string.Join(P_0, P_1);
					int[] array = new int[4];
					array[0] = -780370262;
					array[1] = 1499757656;
					array[2] = 822558809;
					array[3] = -417622291;
					array[3] = array[1] ^ -1917350186;
					array[3] ^= -851610422;
					array[3] = array[1] ^ 0x2157C956;
					int[] array2 = new int[5];
					array2[0] = 2128401378;
					array2[1] = 1594064743;
					array2[2] = 1178413263;
					array2[3] = -1383607830;
					array2[4] = 196904839;
					array2[3] = array[0] ^ -185631331;
					array2[1] = array2[4] ^ 0x15FF4B62;
					array2[4] = array2[3] ^ -1349180649;
					int num11 = array2[3] ^ -399423865;
					num = ((int)num4 * -1138528454) ^ 0x3FF5F6EE ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static TypeSig _005E_0025_003E_0026_0023_0024_0024_0028(MethodDef P_0)
	{
		TypeSig returnType = default(TypeSig);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1054317483;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(1234853644 - -(~(~((num2 ^ ((-(~(~(0x2881B7D6 ^ -1076379277) + -413542129 * 1250999650) * -1218898007 * -441167797) - -1411206553 * (804297163 * -(0x2DF008D5 ^ -163947361))) * 1272157711)) * 1114719995) ^ (-1987523034 + (0x49DDEFD2 ^ (-(-1682711848 ^ -1353047566) + -937441983 * ~(~435168515)))))))) % 3;
					int num5 = 327602881;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 += -327602881;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -2003575290;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= -2003575292;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1;
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
					returnType = P_0.ReturnType;
					int[] array = new int[6] { 273033568, -397553096, 1694585939, 693743540, -334099660, 930388459 };
					array[0] ^= 1299951980;
					array[0] = array[5] ^ -2096337164;
					int[] array2 = new int[5];
					array2[0] = 1139821559;
					array2[1] = 1531545454;
					array2[2] = 1580826176;
					array2[3] = -1274292190;
					array2[4] = 119833756;
					array2[1] = array[5] ^ 0x606F3751;
					array2[4] = array2[1] ^ -88723105;
					array2[4] = array2[2] ^ -750569323;
					array2[0] = array2[2] ^ -1847352262;
					int num11 = array2[1] ^ 0x3350D3;
					num = ((int)num4 * -582832472) ^ 0x6B5921C8 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return returnType;
	}

	static string _005E_002A_003C_0024_003F__0023_0021(MethodItem P_0)
	{
		string name = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1494769762;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-1369917827 - (~(num2 * -424243381 * -1640876585 - ((-2106015437 ^ -2068939118) + -((-1154923569 ^ 0x5B979963) - 1517489085 * --518135545 + (-263676878 + -1041233497 * (-712501709 * 1580736233)) + 549881555))) ^ (1261579563 * ((-476357933 * 1908998172 + -1425904715 + -(~1941642330)) ^ -819739663)))))) % 3;
					int num5 = -1615848954;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 ^= -731080921;
						num5 = -(num5 + ~984003195);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1812942048;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x6C0F4CE2;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1;
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
					name = P_0.Name;
					int[] array = new int[7];
					array[0] = 551298855;
					array[1] = -1179889382;
					array[2] = 463232840;
					array[3] = 1982451029;
					array[4] = -1047262809;
					array[5] = 783258445;
					array[6] = 1541920713;
					array[1] = array[4] ^ 0x4C62DBC4;
					array[6] = array[4] ^ -288779620;
					int[] array2 = new int[7];
					array2[0] = 1943435554;
					array2[1] = -735226072;
					array2[2] = -1016845988;
					array2[3] = -1894794329;
					array2[4] = -882824442;
					array2[5] = 268898311;
					array2[6] = 819669857;
					array2[4] = array[3] ^ -2129635443;
					array2[5] = array2[3] ^ 0x4F96FA8A;
					array2[0] = array2[4] ^ -436279959;
					array2[5] = array2[2] ^ -2111808952;
					int num11 = array2[4] ^ 0x480CE223;
					num = ((int)num4 * -311878562) ^ -1282291768 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return name;
	}

	static string _002F_002D_0040_003F__003E_002A_0024(MethodItem P_0)
	{
		string signature = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1987379104;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~((((((num2 ^ (-(-(1327973801 * ~(~-1076171104 * -101548805 - (0x5599ABFA ^ 0x548A2925))) + ~(-1926381650 ^ -1254453285)) + (~(-(~(1988823734 - -1427053526))) + ((-1761289469 ^ --141770551) + (-686714605 + -1727304102) + (1496447176 * -1261082741 * -837813591 - (-1859063868 - 850876080 + ~1464824622)) + ~((--2147234355 ^ -990584525) - -820322651 * (0x650520C1 ^ 0x1E7F1391))) - (0x30AA6BDA ^ -143884266) * -2044095671 + ((~((0x10A1F83A ^ 0x7BB1621B) + (-1995893426 ^ -1694651040) + ((-2136428564 ^ -1789699791) + -1205112299)) ^ -(-(-61281055 * (1302020939 * -1106217780) - -(2141778089 - 623537288)))) + -(--1002395917 + -(11132117 + 1413248479 + (-487619030 + 1512065084) - (1570264969 * 657170246 - (0x6EB89187 ^ 0x52DB50B0)))))))) * -1857134601) ^ -(-1278141612 + (--1571462674 - -140140793 * -210555491 * -513113163) * -1649796597 - ((-530468376 ^ -899820433) - (-986539542 - -505209472 - (-1213158843 - -822102481) + (-1112850512 ^ -1963491230) + -1602613860))) ^ (-((-(1485829121 * 92024796) ^ -325643652) - (0x331A70A2 ^ -1809979076)) - ~-1375527835) ^ ~(((-192087174 ^ 0x6DBE4C98) + --1446414375) ^ -(1791809683 + -229885190 + 1696921070))) + (0x558AC10A ^ -((0x591B568D ^ -145285188) - -2002026721))) ^ 0x2C037EC3) * -1248892219)))) % 3;
					int num5 = -1396416434;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 *= 2069709645;
						num5 = (num5 + (-467353424 - -501497138)) ^ 0x7A57880F;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -288584629;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 1706810723;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 976061617;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = 976061617 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					signature = P_0.Signature;
					int[] array = new int[4];
					array[0] = -1090542339;
					array[1] = 1283104723;
					array[2] = -116542139;
					array[3] = 434750225;
					array[2] = array[1] ^ 0x6FFE1E81;
					array[2] ^= -2145459563;
					array[1] = array[2] ^ 0x4097DCBB;
					int[] array2 = new int[7];
					array2[0] = 1362379965;
					array2[1] = -1082313693;
					array2[2] = 1808043863;
					array2[3] = -1118995796;
					array2[4] = -1813407315;
					array2[5] = 360334302;
					array2[6] = 1367989963;
					array2[0] = array[3] ^ -374452787;
					array2[6] = array2[4] ^ 0x39D0D22E;
					array2[5] = array2[2] ^ 0x67478869;
					int num11 = array2[0] ^ 0x5B08F135;
					num = (int)((num4 * 221183924) ^ 0xFB4CF1F0u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return signature;
	}

	static string _0021_005E___002A_0028_003E_0025(MethodItem P_0)
	{
		string typeFullName = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 316500009;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((~(~(-1843092695 ^ 0x88F271) * 1720279089) - (~(~(num2 + ~(-(((((-(~685429541) + --1361949116) ^ ((-827404485 ^ 0x60DD4E81) + -534092049 * -774379165)) - ~(-288368263 * -752111364)) ^ ((0x38AB2B83 ^ (-1587524804 ^ ~(-1864181988))) - ((-226550010 - -1593140878) * -1109750731 - --1031279852 * 1113994151) * -1919722201)) - (-1184458997 ^ -(~(~(1085453047 - 1927909860) + -(~1707266354)))))))) ^ (881742345 * ((~(-935313554 ^ -1280224392) + (--153250936 + (1442380364 + 1966130000))) ^ -1543709787) * -565491855)) + (~-53165656 + -1823337932 - -578685171) * 348667871) ^ 0x3FF655D6))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= -1125676367;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1891149041;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = -1891149039 - num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1171411480;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 1171411479;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					typeFullName = P_0.TypeFullName;
					int[] array = new int[5] { -545655767, 1526737449, 1384752399, 1273420559, -1758660713 };
					array[3] ^= 1014208349;
					array[3] = array[0] ^ -1888418077;
					array[4] = array[2] ^ 0x1236A79E;
					int[] array2 = new int[6];
					array2[0] = -2045438916;
					array2[1] = 2006217402;
					array2[2] = 115489607;
					array2[3] = 1898577700;
					array2[4] = -1794248539;
					array2[5] = 1628904668;
					array2[5] = array[1] ^ 0x2F72BE48;
					array2[2] = array2[0] ^ 0x2A356D93;
					array2[4] = array2[1] ^ -1931851511;
					int num11 = array2[5] ^ -2026740310;
					num = ((int)num4 * -1878078333) ^ 0x24F6DF7D ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return typeFullName;
	}

	static bool _0023_0028_005E_003F_003E_002A_0040_003C(MethodItem P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return P_0.IsPreselected;
		}
	}

	static TypeSig _002A_0025_003E_002A_0040_002F_002F_0023(TypeSig P_0)
	{
		TypeSig next = default(TypeSig);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1989287267;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(num2 + ~(~(1723023307 * ~1305836826 * 376898231) + -(1681052505 * ~(~(-(-2069008177 * --2138417285)))))) + ~(-160990937 - ~((0x21020604 ^ 0x54A820C6) - (2057302336 + 1460175940)) * -925915051 - (-(0x74CA9D14 ^ (-1474111390 ^ -559705126)) ^ (-(1216145329 * -1132714498 * -616140795) ^ --881818856)))))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = 1529233016 - ~num5;
						num5 = -num5 + 770790377;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 235143154;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 ^ 0x4D2F114C) - -465522450;
						num7 = ~(num7 - (-1689789320 - 80322750));
					}
					if (num3 != (uint)num7)
					{
						int num9 = -536639551;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = 1994166304 - (num9 ^ 0x26F5BA5F);
							num9 = -(num9 + -38254142);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					next = P_0.Next;
					int[,] array = new int[4, 3];
					array[0, 0] = -690732654;
					array[0, 1] = -385566041;
					array[0, 2] = -1175829164;
					array[1, 0] = 1935737715;
					array[1, 1] = -2012476785;
					array[1, 2] = 1355140681;
					array[2, 0] = -1466133577;
					array[2, 1] = -299027169;
					array[2, 2] = 813675540;
					array[3, 0] = -514293934;
					array[3, 1] = 1807174635;
					array[3, 2] = -1983533731;
					array[1, 2] = array[2, 2] ^ -1207645030;
					array[3, 1] = array[3, 0] ^ -1679474117;
					array[3, 2] = array[1, 2] ^ 0x29E45FD7;
					array[1, 2] = array[3, 0] ^ 0x7118670F;
					int num11 = array[1, 2] ^ -337840790;
					num = ((int)num4 * -1539338813) ^ 0x4CAD84F7 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return next;
	}

	static string _0024_0028_003E_0026__0021_005E_0029(string P_0, string P_1)
	{
		string result = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1080320926;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(~(-num2) ^ ((1814760581 * -538604239 * 424750121) ^ ~(~(-(-1556069508 - (911894560 - 1222785471 - --781438627)))))) ^ ~(1504069741 * ((2074856841 - -1715244641) * -452860597 - -(-1503695007 ^ 0x782C9F4C)))) - -370781338)) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 ^= 0x3048B55;
						num5 = ~(-num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 716063422;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 ^ 0x5EBDBC5E) * 932135751;
						num7 = ~num7 * -241751897;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -456493823;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9 * 1160721927;
							num9 = ~(num9 - (-332399916 + 562002567));
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0 + P_1;
					int[] array = new int[4];
					array[0] = 955934415;
					array[1] = 1367907943;
					array[2] = 370881787;
					array[3] = -1059364083;
					array[3] = array[1] ^ -1302715940;
					array[2] = array[0] ^ -1616322530;
					int[] array2 = new int[7];
					array2[0] = -1859660610;
					array2[1] = 343774375;
					array2[2] = -994068481;
					array2[3] = 257163293;
					array2[4] = 2119054573;
					array2[5] = 190379385;
					array2[6] = -244958524;
					array2[5] = array[1] ^ -1891077504;
					array2[6] = array2[4] ^ 0x3C4F4B3F;
					array2[2] ^= 1477636515;
					array2[2] = array2[3] ^ 0x61772B13;
					int num11 = array2[5] ^ -1987302387;
					num = ((int)num4 * -955013904) ^ -689881776 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string _002F_002B_005E_002F_0028_0028_0021_0029(TypeSig P_0)
	{
		string typeName = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 2084713652;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-((num2 * 1936322301) ^ (((~(-1803144737 * 1347288163 - -(-1157682450 + 2116691053) * 1517482413) - ((-888339135 * -2104929033 + (1833695918 + -1156074793)) * -439927089 + ~(~1878880412 + 809962281 * 431741585) + (124812524 - ~(-1058230558 - --1119699310)))) ^ ~((-2010045645 + -1219566665 * -(123546996 * -621609435)) * 2080447137)) + ((--1619424525 - -(915228859 * (-1870620124 - -42546194) - -(~1862922593))) ^ (1566660501 * (-(-1531980791 ^ 0x3CFFBB8) - (0x5711CC87 ^ -1844913087)) + (-(-(-914032217 * 914453355)) ^ ((0x4A3128D6 ^ 0x43990BEB) + ~(-768279846))))) * 583089891)) - 1185269347 * 2104438554) * 1570229639 * 482785793 * -1532939911)) % 3;
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
					int num7 = -3;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = ~num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1534749163;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 * -1345672941);
							num9 = 456190315 - num9 * 1741607947;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					typeName = P_0.TypeName;
					int[] array = new int[6] { 969217716, -315155974, -17841179, -605014890, 1047635049, 83449223 };
					array[2] ^= 967540377;
					array[4] = array[0] ^ -961541442;
					array[2] = array[3] ^ -2029040823;
					int[] array2 = new int[6];
					array2[0] = 2110604226;
					array2[1] = 1791731462;
					array2[2] = -567810757;
					array2[3] = -1731999392;
					array2[4] = -1718227059;
					array2[5] = 640462900;
					array2[0] = array[3] ^ -1611936928;
					array2[3] = array2[5] ^ 0x442599C;
					array2[2] = array2[0] ^ -1079191066;
					array2[2] ^= -723203674;
					int num11 = array2[0] ^ -1839214883;
					num = (int)((num4 * 1995385272) ^ 0x6373F980) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return typeName;
	}

	static int _002D_0029_003F_002A_0025_005E_005E_(string P_0)
	{
		int length = default(int);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1325541455;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-188456458 - ((-(1430251953 - 735013191) ^ -1165818474) - ((~(num2 * 1650713859) ^ 0x2F87620F) - -850765997 - (--1993469765 + (0x419FAFC ^ 0x76F1C8F6) + 923347643 + --371747598) - ~(-804446275 * -(--1221998181)))))) % 3;
					int num5 = 582875582;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (1754645862 - -21057341 - num5) * 1827192787;
						num5 = num5 - (-1738816021 + -224771716) - -1714846957;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 - -756169178 + 860690946;
						num7 = ~num7 + 1084883816;
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
					length = P_0.Length;
					int[] array = new int[7];
					array[0] = -403601185;
					array[1] = -1003782056;
					array[2] = -91532003;
					array[3] = -1974888767;
					array[4] = -476021637;
					array[5] = 644449763;
					array[6] = 742629700;
					array[5] = array[0] ^ -1985518576;
					array[0] = array[1] ^ 0x134394E5;
					array[0] = array[5] ^ 0x4841696;
					int[] array2 = new int[4];
					array2[0] = 22818213;
					array2[1] = 2100389272;
					array2[2] = -380742484;
					array2[3] = 445414429;
					array2[3] = array[6] ^ 0x78B58532;
					array2[0] = array2[1] ^ -1647780810;
					array2[0] = array2[2] ^ 0x24ED39DE;
					int num11 = array2[3] ^ 0x2B7D5BE5;
					num = (int)((num4 * 166795116) ^ 0xFDF02220u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return length;
	}

	static char _002B_002A_0029_005E_0021_0024_0040_0024(string P_0, int P_1)
	{
		char result = default(char);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1505997088;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(-((~(-(0x1C1012D6 ^ 0x543685A7)) ^ 0x630C655C ^ (-(~(-660558872 * 159729037)) + (-1508073369 * ~(~-1156527545) + (-843885999 ^ -(-68270675 - 45593528))) + (1390473445 * (~(129567336 - 950092613) + -429313537 * -1503288776) + ((1926980241 * 1582348313 - (-2063798207 + --1077684903)) ^ 0x77A29878)) + ((-1092017841 * (((0x252D632D ^ -874211310) + -868332842) ^ 0xA8A88B ^ (-32006320 ^ -2041804830 ^ -(-2061893392 + -2049645442)))) ^ -(~(~-856328780 - 837164427) * 746887699)))) - -num2))) ^ (-(-1651358873 + 1603968379 + (2040203479 - 582773970)) + -(416878716 + --986627414)))) % 3;
					int num5 = 1815810113;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 += -1815810111;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1359006947;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -253044533;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1596671530;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -1596671530;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0[P_1];
					int[] array = new int[5] { 81681395, 1163992720, 2103128097, 1333400517, -134214437 };
					array[1] ^= -249634570;
					array[1] ^= -681646118;
					int[] array2 = new int[5] { 766260086, 667107963, -1462804815, 1673982578, -1513293172 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][3] ^ 0x50322B8F;
					array2[2] = array2[0] ^ -1808959774;
					array2[0] = array2[4] ^ 0x18D4BD43;
					int num11 = array3[1][1] ^ 0x2E4652A9;
					num = (int)((num4 * 423904338) ^ 0xE953CA08u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static bool _002A_0028_002B_0024_003D_0028_003C_0023(string P_0, string P_1)
	{
		bool result = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -890362549;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-((-((num2 ^ (-151179597 * (-(((956403221 * 841557536 + (-1848714688 ^ -1193211266) - ~(-1381305909 ^ 0x4A3AB938) + (735584027 * (-31343339 * -1176655204) + (-1350766158 ^ --1778819904))) ^ 0x31111D63) - 816524922) - (-(~(-354721301 + 389168289) * -2049302155 + (-145033490 ^ -2141701807) - (-(-765271019 * -519171482) ^ -2100693975)) + 1455610622))) ^ (-1367586761 * ((-(~(-(-1552602230 ^ -733909581))) ^ -490481570) * 1629036191))) - (-((0x1A5D52C ^ (-150653881 * 646976463)) * -925775801 + -(-(~(190671900 - -528380515)))) ^ (-319716199 * ~(-660838876 * 269002785)))) - (~(0x8C09A3F ^ --283919395) - ~(~(-1951100933)) - ~((-1069976396 + 1498569767 + --1632484841) * 599496713)) - 1207493451 + -890789918) * 1096192541)))) % 3;
					int num5 = -3;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = ~num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 932110683;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 * -667604883) ^ -332080648;
						num7 = (num7 ^ 0x75A685AB) * 1349759879;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= 602887765;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0 == P_1;
					int[] array = new int[7];
					array[0] = 479093900;
					array[1] = -1741362278;
					array[2] = 1684629946;
					array[3] = 1837928268;
					array[4] = -1272205211;
					array[5] = 1157304835;
					array[6] = 1883430089;
					array[4] = array[2] ^ -1505172958;
					array[0] = array[6] ^ -1824047007;
					int[] array2 = new int[4] { 524568934, -1871706145, -131291978, -900246854 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][3] ^ 0x1F7D0BB4;
					array2[0] = array2[1] ^ -941637411;
					array2[1] = array2[3] ^ -299216385;
					array2[0] = array2[2] ^ -1327231512;
					int num11 = array3[1][3] ^ -629479804;
					num = ((int)num4 * -1567957089) ^ -128467866 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static CustomAttributeCollection _0029_003F_0024_0024_0040_0025_0026_0024(IHasCustomAttribute P_0)
	{
		CustomAttributeCollection customAttributes = default(CustomAttributeCollection);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 515720932;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(228740728 - -350383297 - ((-((1711628073 - 1372228619) * 1012069053) - (-((num2 * 688264851) ^ ((((-841792249 ^ -1787029683) - (~(--1693681090) + -767926894 + -(0x41F5E173 ^ 0x6DCD71B3) + 1965101187 * (-2073068597 + ~1986727720 - (244782750 + 2023017336) * 1575851839))) ^ (-(~1841937105) - -(~-2010459908) - ~(2095999902 + 1756369184 - 1970958876 * -398565629) - 1216147174 - ~806604869)) * -606422721) ^ (0x61E9DBDA ^ (~(-637380973 * --845559455 - (-1007848554 - 2003995513) * 1659140957) ^ -2145590649 ^ (1247224268 + (-(-1501475179 * -1212348527) - (519883639 * -2062643166 + (-410820301 - 1562185588)) - -(--2143714133 ^ -1983418321)))))) - (0x322EF41 ^ 0x78C165AB) - ((0x45B0CEB0 ^ -1699638201) - 1658484446 + (--1514984203 ^ -1741147912) + (-1891090582 + 1861438503 + 1738182105 - -477653310)))) ^ -933072746))) % 3;
					int num5 = 120823000;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(-num5);
						num5 = (num5 - (1770831945 - 324750072)) * 1346596131;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7 ^ -1404675187;
						num7 = ~(num7 ^ -911093980);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 111407992;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 111407990;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					customAttributes = P_0.CustomAttributes;
					int[] array = new int[4] { 1809358398, -272220874, -1824093780, 1333256327 };
					array[2] ^= 608145711;
					array[0] = array[1] ^ 0x7314853A;
					array[2] ^= -625950026;
					int[] array2 = new int[4];
					array2[0] = 1018869186;
					array2[1] = -358055376;
					array2[2] = 473292782;
					array2[3] = 1941648412;
					array2[1] = array[3] ^ 0x2E9FE7C3;
					array2[0] = array2[1] ^ -2067623885;
					array2[2] = array2[1] ^ -700164722;
					int num11 = array2[1] ^ -1772624907;
					num = ((int)num4 * -444833395) ^ -1853343956 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return customAttributes;
	}

	static bool _0025_005E_003C_002B_0021_0029_002F_003C(string P_0, string P_1, StringComparison P_2)
	{
		bool result = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1177337793;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((~num2 ^ (1926691177 * ~(-205292243 - ((-968963407 ^ -1081957466) + ~(-1076191985 ^ -311501549) - (1266539480 + (-1068310635 + 1482153873 - (-182430169 + 1750456171))))) + ((-(~-759767029) ^ 0x4DC98B35) + ~(~(-383424456 * 811877405)) + (0x2E258D19 ^ 0x3FF0C5DB) + -1720227945 + ((170110164 - -(~-1768813993 + --1186556274) + 383464611 * (0x6E53A35D ^ 0x7907919F)) ^ (0x57DA5DFA ^ (0x6B6F9AFD ^ (0x3B771D5A ^ ((0x4984B12A ^ 0x419470E2) + -806585932)))))))) * -1071587431))) % 3;
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
					int num7 = -2;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = ~num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(-num9);
							num9 = ~num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.StartsWith(P_1, P_2);
					int[] array = new int[4];
					array[0] = -1709189538;
					array[1] = -1719069128;
					array[2] = -747972086;
					array[3] = 1829448898;
					array[3] = array[0] ^ 0x31FBC10E;
					array[3] = array[0] ^ -1526907911;
					array[3] = array[0] ^ 0x665146F3;
					int[] array2 = new int[4];
					array2[0] = 911821996;
					array2[1] = -245407862;
					array2[2] = 916701989;
					array2[3] = -2022763099;
					array2[1] = array[1] ^ 0x7A1D7476;
					array2[3] = array2[2] ^ -1192501397;
					array2[2] = array2[0] ^ 0x2EB89EF3;
					int num11 = array2[1] ^ 0x2EC29368;
					num = ((int)num4 * -954874269) ^ 0x72DA43A8 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static bool _0024_005E_003E_0024_002B_003D_0028_002F(string P_0, string P_1, StringComparison P_2)
	{
		bool result = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1815208504;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((-(-num2) * -2058647437) ^ (-875728179 * (-667009173 - ~(-(~-1279095625))) + -1982929231 * ~(-1526967878 ^ -531017632))) - --769651516 - (~(-1458504514 - 1328023817) * 588163915 - -1185141837))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 += -846985583;
						num5 = ~(num5 - -858040547);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1731147046;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 - ~1624996871) * 997753657;
						num7 = num7 + -729949621 - 1933329309;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = ~num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.EndsWith(P_1, P_2);
					int[] array = new int[5];
					array[0] = -1610714213;
					array[1] = 1472654352;
					array[2] = 1030234421;
					array[3] = 1061556384;
					array[4] = -1306586933;
					array[4] = array[1] ^ 0x2D906FBA;
					array[1] ^= 1344369603;
					int[] array2 = new int[5];
					array2[0] = 866482948;
					array2[1] = 1013840386;
					array2[2] = -55823656;
					array2[3] = 1974347622;
					array2[4] = 17001777;
					array2[4] = array[2] ^ 0x1F74D7A;
					array2[3] = array2[4] ^ -1035245369;
					array2[1] = array2[2] ^ -1708585241;
					int num11 = array2[4] ^ -1727415675;
					num = (int)((num4 * 435929674) ^ 0x370A9D44) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static ITypeDefOrRef __0023_0029_0021_002F_0040_003F_0025(TypeDef P_0)
	{
		ITypeDefOrRef baseType = default(ITypeDefOrRef);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1463183585;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(~(-(-(-(num2 * -493408733 - (~(~(1716898667 * (-(-600425073 ^ -77366513) - (1694508501 + -1052681463 + --1643131655)) * -330307645)) + -328591884 * -414352163)))) + ~(-(-895703530 - -754712241) * -1165933937))) - -1940496641 * -1780004495))) % 3;
					int num5 = 1377343466;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0x521897E8;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1956525457;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += -1956525456;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -261115280;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -261115280;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					baseType = P_0.BaseType;
					int[,] array = new int[4, 3];
					array[0, 0] = 1674377324;
					array[0, 1] = -494715413;
					array[0, 2] = 887954641;
					array[1, 0] = 1006149365;
					array[1, 1] = -59293910;
					array[1, 2] = 1096519563;
					array[2, 0] = 1879286953;
					array[2, 1] = -717512108;
					array[2, 2] = -1654768129;
					array[3, 0] = -414483750;
					array[3, 1] = -1397484990;
					array[3, 2] = -375649622;
					array[0, 1] = array[3, 2] ^ 0x4938BD86;
					array[1, 2] = array[0, 1] ^ -10067919;
					array[3, 2] = array[2, 0] ^ 0x7764031C;
					int num11 = array[3, 2] ^ -1925205503;
					num = (int)((num4 * 1453689708) ^ 0xC2F116B8u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return baseType;
	}

	static string _003E_003C_005E_0028_005E_0023_0028_0026(IFullName P_0)
	{
		string fullName = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1789201158;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(-(-(((-(num2 ^ (-1847395417 * ~(((-500757545 ^ 0x146420C2) - -1742247131 * -(-2074051811 ^ -1943646048)) ^ (-(973526477 * -1458693047) * -1675122725 - ((-1397605103 ^ 0xB5FA020) * -1632377451 - (0x4E54D369 ^ 0x3958186)) - (~-2096548011 - (-644970956 - 995165445) + (-1128396863 ^ -1381763503)) * 1925871919) ^ ((~(-1555833979 + 811573388 - (0x55A2FC8 ^ 0x28F0AEC7)) - (1198196770 + --1074963953 - ~1155738489) - 2103843650) ^ (1104591697 - (-(2055080705 * (96163062 * 1515023899)) - ~(-(~638603589)))))))) - (~-555691014 + (~(-(~(--893095065 ^ -2037991545))) + ~(~((0x2E27AA33 ^ 0x62A92F64) - (-194580262 + -335610499 + ~1426776168))))) + ~(-(~(2056820823 - 1989130520) * -1855902191) - -(0x7984C386 ^ -577840566))) ^ ((~(~-317511180) + (611709204 + -996664814)) * 415157385 + 1150062434)) * -1514757329)))))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(~num7);
						num7 = -(num7 - (0x2BEE083E ^ 0x6EBCDE1D));
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1927831558;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x72E86007;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					fullName = P_0.FullName;
					int[,] array = new int[3, 3];
					array[0, 0] = -2090732623;
					array[0, 1] = -506733723;
					array[0, 2] = -805356229;
					array[1, 0] = -2032751739;
					array[1, 1] = -1297886670;
					array[1, 2] = 1595519698;
					array[2, 0] = -491192127;
					array[2, 1] = 489432297;
					array[2, 2] = 1082197440;
					array[0, 2] = array[0, 0] ^ -2051834797;
					array[0, 1] = array[2, 1] ^ 0x65AA7F1B;
					array[1, 1] = array[0, 0] ^ 0x739F0856;
					array[2, 1] = array[1, 0] ^ -693919496;
					int num11 = array[2, 1] ^ 0x61A03F4A;
					num = ((int)num4 * -506229134) ^ 0x76DBEEC0 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return fullName;
	}

	static bool _0021__0040_003C_005E_0029_0023_005E(string P_0, string P_1, StringComparison P_2)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return string.Equals(P_0, P_1, P_2);
		}
	}

	static string __002F_003F_002A_002D_002B_002B_003F(Environment.SpecialFolder P_0)
	{
		string folderPath = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -447869639;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(1956751107 - -(-((-(~(num2 - ((2056713575 * ~-1029584004 + -(-(-(-(1325182549 + 731809608)) + --880018538)) + (-506651715 * ~(-(~((0x779960BF ^ 0x292232F2) + (2043535706 - -751496674)))) - (-1023786368 ^ 0x2C525596))) ^ (0x3146478A ^ ~(-(-((--493396506 ^ -1892546152) - -(~21701494))) ^ 0x79AC1061)))) - (-1107736237 + (--1620029269 * -514126269 - (~((0x23A23A3D ^ -1638500954) + 1517966070) + (~(1746883851 * -706295737 + (-1449745051 + -1074531966)) - (~(--1708929362) - ~(~-709086898))))))) * 604533787) ^ ((-420206129 * ~(--1142832874)) ^ ~(--1762451137)))) * -258130073)) % 3;
					int num5 = 549133672;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 * -2064470689) ^ -496734954;
						num5 = num5 + (-1102577244 ^ -561635021) + -252790321;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1770584085;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x6988F814;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1179740860;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 - --678593057 - -1268463487;
							num9 = -(~num9);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					folderPath = Environment.GetFolderPath(P_0);
					int[] array = new int[4];
					array[0] = -2113358332;
					array[1] = -1725582819;
					array[2] = 2064099314;
					array[3] = 1015263084;
					array[0] = array[2] ^ 0x5BB05757;
					array[1] ^= -1838446474;
					int[] array2 = new int[7] { -1956738718, -941043138, 1545842031, -641725006, -1228749495, -1630794976, -1285357098 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][2] ^ 0x3F758393;
					array2[6] = array2[3] ^ 0x66456C4;
					array2[2] = array2[1] ^ -2015593593;
					array2[6] = array2[0] ^ 0x69DEFA5F;
					int num11 = array3[1][0] ^ 0x342BEE3A;
					num = (int)((num4 * 1342971577) ^ 0xBC804C56u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return folderPath;
	}

	static string _002A_0023_002D_005E_003E_005E_0040_0023(string P_0, string P_1)
	{
		string result = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -697603360;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(~(2056541255 * (--1202978847 * 698448783 - (--24434593 + -1749815489)) * -322781367) - (~(~(--1894342816 + 1169568161 * (0x52F8D69C ^ -1944961381) - ~(-1645418257 * -1362936245 + (-1111991505 - 2262322)))) + ~(-(~(~-722575141 - (-1466281807 ^ -2026692747))) * -812893039) - -(~num2))) - -(-1942156709)) ^ (-71813484 + (-1049160172 ^ -1381133230) + (0x7580AE7D ^ -268304098)))) % 3;
					int num5 = 1166917846;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 -= ~1760517745;
						num5 = -(num5 * -946852069);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1094452485;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= -1094452486;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = ~num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = Path.Combine(P_0, P_1);
					int[] array = new int[5] { 1823019774, -2072733018, -591413992, -1926155171, -1498784997 };
					array[0] ^= -1754214211;
					array[3] = array[2] ^ 0x554DB01E;
					int[] array2 = new int[5] { -1339197443, -1320731013, -230413855, -1944105973, -1696198586 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][4] ^ -1440119296;
					array2[4] ^= 457897447;
					array2[1] = array2[0] ^ 0x5B4F2465;
					int num11 = array3[1][3] ^ -450606989;
					num = (int)((num4 * 638458630) ^ 0x3FCDD53A) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static DirectoryInfo _0029__003F_0026_002B_0028_0028_0021(string P_0)
	{
		DirectoryInfo result = default(DirectoryInfo);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 371553354;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((368997931 - ~(-420271369 * (-1363066681 + -(207326206 * 119265051 - -1120998024 - (0x22DC0725 ^ -1636600744) + -(-431417428 - 1201515437 * 63974954) + ~(~(-(-1730885880)))) - (-1549205688 * -1264964095 - ~((-888077643 - (0x8614759 ^ 0x16B0E5E1)) * -2011783195 + ~(-(-711250 * -231766977))) + -(-1248904432 * -2104863427 - (~(-(-1263965657)) ^ 0x371AC1FA)))) - num2) * -889680511 - ((0x7B9E1D49 ^ 0x2E105EBA) + ~1383026833 - (~-1784779651 + -1429940749) + -1240842854) * -96370143) * -2131472007)) % 3;
					int num5 = 1780105464;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = 913612487 - (num5 - ~-633422004);
						num5 = ~(num5 * -286633657);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1026101235;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7;
						num7 *= -688607619;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1217987018;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ((0x7EBAFF2E ^ -764569852) - num9) * -322898569;
							num9 = ~num9 ^ -50885772;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = Directory.CreateDirectory(P_0);
					int[,] array = new int[4, 3];
					array[0, 0] = 21200138;
					array[0, 1] = 309554029;
					array[0, 2] = 1529430928;
					array[1, 0] = 1658225456;
					array[1, 1] = -1280989879;
					array[1, 2] = 1784558408;
					array[2, 0] = 1277733004;
					array[2, 1] = 567807481;
					array[2, 2] = -685047593;
					array[3, 0] = -1029312069;
					array[3, 1] = -1299317474;
					array[3, 2] = -781832381;
					array[1, 0] = array[0, 2] ^ -1448104932;
					array[2, 0] = array[3, 2] ^ -1817046777;
					array[3, 1] = array[3, 0] ^ -892034519;
					int num11 = array[3, 1] ^ 0x59ECAF27;
					num = ((int)num4 * -1812793873) ^ 0x7AA74A61 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string _003F_0029_0023_0040_002D_003D_002D_0021()
	{
		string newLine = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1451504172;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((~((~(num2 + ((560617312 - ~(-55373121 ^ -1061597150) + (--1141033681 + (454627410 + (((-1938573847 ^ -2089106380) + -(-230845930 + 1955582133)) ^ 0x6178D895)))) ^ -492516568) * 1745848927) - -(((-137377931 ^ -2070130125) + ~(~(~784486748)) - 1241098701 * 1780267325) * -119113603)) * 258551795) + (~(-1981578295 * 214142241 * -717418049) + -(-727865118 - -327288980 - 1885323829))) * 1556762003))) % 3;
					int num5 = 1043145400;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * 1321153953 - -163584150;
						num5 = ~(-num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1689208320;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += -1689208319;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
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
					newLine = Environment.NewLine;
					int[] array = new int[7];
					array[0] = 135260384;
					array[1] = 1287127802;
					array[2] = 1934213829;
					array[3] = -602810817;
					array[4] = 1820517166;
					array[5] = -141165848;
					array[6] = -585099896;
					array[0] = array[5] ^ 0x620457E4;
					array[0] ^= -2132286268;
					array[6] = array[1] ^ -1460533553;
					int[] array2 = new int[5] { -355702316, -1045039316, -1795940536, 1424632025, 216121450 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][4] ^ 0x40D5C3A2;
					array2[2] = array2[4] ^ -2032618842;
					array2[2] = array2[0] ^ 0xCC8D5D1;
					array2[0] = array2[2] ^ 0x4B7DCF1;
					int num11 = array3[1][4] ^ -444724572;
					num = (int)((num4 * 787066055) ^ 0x91DE3607u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return newLine;
	}

	static void _0021_002B__0021_005E_0028_002D_0025(string P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -913294234;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(-(-(((302424133 * (((1071301524 + -256666778 + (-492605504 - 513523709) + 588838527 - -433820391 * (-928946767 + -967573410) - -((-584935679 ^ --187942209) - -(-537590661 * -322577269))) ^ ~(-1085899176 ^ (364169695 * (-1333801631 - --581591385)))) * 1082650529)) ^ (((-((~(-1934165635) + (2094356193 - 1495044641)) ^ ~(-756610120 ^ 0x75E1BF0B)) ^ 0x4F25D60F) * -932487881) ^ -1885139218)) - num2)))))) % 3;
					int num5 = -601748840;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 * 1908250995;
						num5 = ~(-num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -398633824;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += 398633826;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 421089873;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = 42741121 - (num9 + (1758759046 + 240069685));
							num9 = ~(num9 - 1181445513 * -304156185);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					File.WriteAllText(P_0, P_1);
					int[,] array = new int[4, 3];
					array[0, 0] = -1188499073;
					array[0, 1] = -1055038895;
					array[0, 2] = -823849703;
					array[1, 0] = 421515882;
					array[1, 1] = 1993664037;
					array[1, 2] = -1502313966;
					array[2, 0] = -730901014;
					array[2, 1] = 68982959;
					array[2, 2] = 359911911;
					array[3, 0] = -378733404;
					array[3, 1] = -908641274;
					array[3, 2] = 807755550;
					array[0, 1] = array[0, 0] ^ 0x48E0C0BB;
					array[1, 1] = array[3, 0] ^ 0x6407DD8D;
					array[2, 0] ^= 1879567066;
					array[0, 1] = array[1, 2] ^ 0x66017057;
					int num11 = array[0, 1] ^ -1116983433;
					num = ((int)num4 * -868105048) ^ 0x5CE44C68 ^ num11;
				}
			}
		}
	}
}
