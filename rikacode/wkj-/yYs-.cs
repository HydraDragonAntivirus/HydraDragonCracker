using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using RikaNET.Core.Services;

namespace wkj_003D;

public sealed class yYs_003D : ISettingsStore
{
	private readonly object UyW_003D = new object();

	private readonly string NTm_003D;

	private readonly string YmR_003D;

	private Dictionary<string, string> uSn_003D;

	public yYs_003D()
	{
		while (true)
		{
			int num = -1651783767;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(~(~num2)) * 1057234635 - -(1260833496 - ~((0x5945D246 ^ 0x52D89A03) - 363020835)))) % 5;
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
				int num7 = 142663693;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = ~num7 - 371541727;
					num7 = (num7 - -1345599206) ^ -2050327218;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -634187536;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 ^= -634187533;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 26;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = ~(num11 ^ -1536218294);
							num11 = -num11 ^ -34026412;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -1127979390;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = (num13 - (0x463FA121 ^ 0x2C1A34F2)) ^ -1656032156;
								num13 = ~(num13 * 602528619);
							}
							if (num3 == (uint)num13)
							{
							}
							return;
						}
						uSn_003D = cVD_003D();
						int[] array = new int[4];
						array[0] = 907851886;
						array[1] = 466786665;
						array[2] = 588473635;
						array[3] = 1682176533;
						array[0] = array[1] ^ -1606437148;
						array[1] = array[0] ^ -953268335;
						int[] array2 = new int[7] { -876611371, -2136790036, 342413100, 338730216, -892408084, -823251830, -698700039 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[4] = array3[0][2] ^ -1969507745;
						array2[1] = array2[0] ^ 0x1301A729;
						array2[3] = array2[0] ^ -1982393900;
						int num15 = array3[1][4] ^ -1427756706;
						num = ((int)num4 * -1197441977) ^ 0x73FE6F17 ^ num15;
					}
					else
					{
						YmR_003D = _003F_003E_005E_002A_0024_0040_005E_0029(NTm_003D, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x7B1B ^ 0x790C]);
						int[,] array4 = new int[3, 4];
						array4[0, 0] = 1630557428;
						array4[0, 1] = 1246146379;
						array4[0, 2] = -836969219;
						array4[0, 3] = -504478483;
						array4[1, 0] = 696676533;
						array4[1, 1] = 170889967;
						array4[1, 2] = 662435017;
						array4[1, 3] = -1297545369;
						array4[2, 0] = -2118710407;
						array4[2, 1] = 1534016951;
						array4[2, 2] = 2006743556;
						array4[2, 3] = -1751006275;
						array4[0, 0] = array4[1, 3] ^ 0x3420F867;
						array4[1, 3] = array4[0, 1] ^ 0x69105B2E;
						array4[2, 2] = array4[2, 0] ^ -475511463;
						int num16 = array4[2, 2] ^ 0xF7E4DBE;
						num = (int)((num4 * 860164692) ^ 0x8FB36D10u) ^ num16;
					}
				}
				else
				{
					NTm_003D = _003F_003E_005E_002A_0024_0040_005E_0029(_0023_002D_0040_002D_0026_002B_0040_002B(Environment.SpecialFolder.LocalApplicationData), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x10F2 ^ 0x113B]);
					int[,] array5 = new int[3, 4];
					array5[0, 0] = -1332063541;
					array5[0, 1] = -802889172;
					array5[0, 2] = -597359017;
					array5[0, 3] = 1440254765;
					array5[1, 0] = 1818982882;
					array5[1, 1] = 266627604;
					array5[1, 2] = -1040035355;
					array5[1, 3] = -286647069;
					array5[2, 0] = -1326662202;
					array5[2, 1] = 183148304;
					array5[2, 2] = -1258816972;
					array5[2, 3] = -902504146;
					array5[1, 3] = array5[2, 0] ^ -944614634;
					array5[1, 2] = array5[2, 0] ^ -205822526;
					array5[0, 2] = array5[1, 2] ^ -452713689;
					array5[0, 1] = array5[2, 1] ^ -1940836686;
					int num17 = array5[0, 1] ^ -1398661417;
					num = (int)((num4 * 891381452) ^ 0x69D509A0) ^ num17;
				}
			}
		}
	}

	public bool GetBoolean(string vhT_003D, bool RXB_003D = false)
	{
		object uyW_003D = UyW_003D;
		bool flag = false;
		bool result = default(bool);
		try
		{
			_005E_0040_002B_0023_003C_0023_0025_003E(uyW_003D, ref flag);
			if (uSn_003D.TryGetValue(vhT_003D, out string value))
			{
				goto IL_003e;
			}
			goto IL_03dc;
			IL_003e:
			int num = -85747818;
			goto IL_0043;
			IL_0043:
			uint num3;
			bool flag2 = default(bool);
			while (true)
			{
				int num2 = num;
				uint num4;
				num3 = (num4 = (uint)(((-(~(-(-(1405294658 - -551557382) + (1639063279 * 1813657317 + ~1555573224))) - ~(~(-(~num2)))) * 1833569689 * 1098102681) ^ 0x3615C4B3) * -851876737)) % 4;
				uint num5 = num3;
				int num6 = -849795536;
				_ = 0;
				for (int num7 = 0; num7 < 2; num7++)
				{
					num6 *= -637991889;
					num6 = ~(-num6);
				}
				if (num5 == (uint)num6)
				{
					break;
				}
				uint num8 = num3;
				int num9 = 3;
				_ = 0;
				for (int num10 = 0; num10 < 2; num10++)
				{
					num9 = -(num9 - -1799808531 * 1936351933);
					num9 -= 1143446430 + -544136917;
				}
				if (num8 != (uint)num9)
				{
					goto IL_0170;
				}
				if (!_0028_003C_003E_005E_002F_0024_005E_0024(value, ref flag2))
				{
					int[] array = new int[7];
					array[0] = -136826110;
					array[1] = 2002886573;
					array[2] = 490878943;
					array[3] = 1334010658;
					array[4] = 498668172;
					array[5] = 558393207;
					array[6] = -1497606544;
					array[6] = array[3] ^ -953942251;
					array[0] = array[2] ^ 0x10C3ADDE;
					int[] array2 = new int[6];
					array2[0] = -1712835675;
					array2[1] = 1164733345;
					array2[2] = 836619936;
					array2[3] = -6731190;
					array2[4] = 299629234;
					array2[5] = -654219463;
					array2[2] = array[4] ^ -1487559477;
					array2[1] = array2[2] ^ 0xB0D124E;
					array2[1] ^= 1909437089;
					array2[5] ^= 110407218;
					int num11 = array2[2] ^ -1569654121;
					num = (int)((num4 * 1391316145) ^ 0x8086A4E3u) ^ num11;
					continue;
				}
				goto IL_03e5;
			}
			goto IL_003e;
			IL_0170:
			uint num12 = num3;
			int num13 = 214772117;
			_ = 0;
			for (int num14 = 0; num14 < 1; num14++)
			{
				num13 ^= 0xCCD2994;
			}
			if (num12 == (uint)num13)
			{
				goto IL_03dc;
			}
			uint num15 = num3;
			int num16 = 2058090054;
			_ = 0;
			for (int num17 = 0; num17 < 1; num17++)
			{
				num16 = 2058090056 - num16;
			}
			if (num15 == (uint)num16)
			{
			}
			goto end_IL_0016;
			IL_03dc:
			bool num18 = RXB_003D;
			goto IL_03e9;
			IL_03e5:
			num18 = flag2;
			goto IL_03e9;
			IL_03e9:
			result = num18;
			num = -1972555803;
			goto IL_0043;
			end_IL_0016:;
		}
		finally
		{
			if (flag)
			{
				while (true)
				{
					int num19 = -1343625051;
					while (true)
					{
						int num2 = num19;
						uint num4;
						uint num3 = (num4 = (uint)(((-(~(-(-(1405294658 - -551557382) + (1639063279 * 1813657317 + ~1555573224))) - ~(~(-(~num2)))) * 1833569689 * 1098102681) ^ 0x3615C4B3) * -851876737)) % 3;
						uint num20 = num3;
						int num21 = 234497040;
						_ = 0;
						for (int num22 = 0; num22 < 2; num22++)
						{
							num21 = (-1534972765 + 1251040404 - num21) ^ -335597000;
							num21 += 1286719637 - -526691992;
						}
						if (num20 == (uint)num21)
						{
							break;
						}
						uint num23 = num3;
						int num24 = -1312810487;
						_ = 0;
						for (int num25 = 0; num25 < 2; num25++)
						{
							num24 = (num24 ^ -842606866) - 547486059;
							num24 = (num24 + (0x4D3129A3 ^ -2075375729)) ^ -847237459;
						}
						if (num23 != (uint)num24)
						{
							uint num26 = num3;
							int num27 = 231652655;
							_ = 0;
							for (int num28 = 0; num28 < 1; num28++)
							{
								num27 -= 231652653;
							}
							if (num26 == (uint)num27)
							{
							}
							goto end_IL_0405;
						}
						_005E_0023_0026_0024_0026_0026_002A_003E(uyW_003D);
						int[] array3 = new int[6];
						array3[0] = -1050465730;
						array3[1] = -603391294;
						array3[2] = -1804222181;
						array3[3] = -847236651;
						array3[4] = 1770958911;
						array3[5] = -1950223936;
						array3[0] = array3[5] ^ -469802220;
						array3[0] = array3[2] ^ -471552007;
						array3[0] = array3[1] ^ -1286298080;
						int[] array4 = new int[6];
						array4[0] = -1681856229;
						array4[1] = 1626103976;
						array4[2] = -559111122;
						array4[3] = -1215749520;
						array4[4] = -172321657;
						array4[5] = -1240803390;
						array4[5] = array3[5] ^ 0x1792AE7E;
						array4[1] = array4[5] ^ -2076518279;
						array4[0] = array4[4] ^ 0x19E0623C;
						array4[0] = array4[4] ^ -1705634918;
						int num29 = array4[5] ^ -4154635;
						num19 = (int)((num4 * 530347254) ^ 0x8887B88Cu) ^ num29;
					}
					continue;
					end_IL_0405:
					break;
				}
			}
		}
		return result;
	}

	public string? GetString(string cxP_003D)
	{
		object uyW_003D = UyW_003D;
		bool flag = false;
		string result = default(string);
		try
		{
			_005E_0040_002B_0023_003C_0023_0025_003E(uyW_003D, ref flag);
			while (true)
			{
				int num = -1409774798;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(((-(~(-(num2 - (((0x6C8EE0F3 ^ -(~((0x17A859A6 ^ -1654976092) - (-2134564245 ^ --725003221)) * 1915498445)) * 4802101) ^ ~(~(-(~(0x7FCA6778 ^ (-143515573 * 1017536781 + -(72918043 + -692236039))))))))) ^ -1998826181) ^ (-(-2141137374 * -649569831) - -(1294837897 * -1901919901) + -(1190748154 - -1975361759 - --1783582967))) + (0x28D610EA ^ -755681666)) * 1563361471 - (-504274630 ^ -1044814141)))) % 4;
					uint num5 = num3;
					int num6 = 204559705;
					_ = 0;
					for (int num7 = 0; num7 < 1; num7++)
					{
						num6 = 204559705 - num6;
					}
					if (num5 == (uint)num6)
					{
						break;
					}
					uint num8 = num3;
					int num9 = -2015577717;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = 2094484390 - num9 * 1133559705;
						num9 = -1877447357 - (num9 - 496229127);
					}
					object obj;
					if (num8 != (uint)num9)
					{
						uint num11 = num3;
						int num12 = -122399352;
						_ = 0;
						for (int num13 = 0; num13 < 1; num13++)
						{
							num12 = -122399351 - num12;
						}
						if (num11 != (uint)num12)
						{
							uint num14 = num3;
							int num15 = -2;
							_ = 0;
							for (int num16 = 0; num16 < 1; num16++)
							{
								num15 = -num15;
							}
							if (num14 == (uint)num15)
							{
							}
							goto end_IL_0023;
						}
						obj = null;
					}
					else
					{
						if (!uSn_003D.TryGetValue(cxP_003D, out string value))
						{
							int[,] array = new int[4, 4];
							array[0, 0] = -285471795;
							array[0, 1] = -2048834760;
							array[0, 2] = -25831170;
							array[0, 3] = 358300591;
							array[1, 0] = -110997406;
							array[1, 1] = 1981895565;
							array[1, 2] = -1340262279;
							array[1, 3] = -728236477;
							array[2, 0] = 1490087546;
							array[2, 1] = 1865202793;
							array[2, 2] = -951533623;
							array[2, 3] = 1071031370;
							array[3, 0] = 795673019;
							array[3, 1] = 2116704224;
							array[3, 2] = 6890008;
							array[3, 3] = -1641497820;
							array[1, 2] = array[1, 0] ^ -796942577;
							array[3, 0] = array[1, 2] ^ 0x41AD5FAE;
							array[3, 2] = array[3, 0] ^ 0x3A7D2BAF;
							array[2, 1] = array[0, 1] ^ -409712282;
							int num17 = array[2, 1] ^ -1726586790;
							num = (int)((num4 * 528918837) ^ 0xF9ACD1A7u) ^ num17;
							continue;
						}
						obj = value;
					}
					result = (string)obj;
					num = 1543377099;
				}
				continue;
				end_IL_0023:
				break;
			}
		}
		finally
		{
			if (flag)
			{
				while (true)
				{
					int num18 = -1709828045;
					while (true)
					{
						int num2 = num18;
						uint num4;
						uint num3 = (num4 = (uint)(~(((-(~(-(num2 - (((0x6C8EE0F3 ^ -(~((0x17A859A6 ^ -1654976092) - (-2134564245 ^ --725003221)) * 1915498445)) * 4802101) ^ ~(~(-(~(0x7FCA6778 ^ (-143515573 * 1017536781 + -(72918043 + -692236039))))))))) ^ -1998826181) ^ (-(-2141137374 * -649569831) - -(1294837897 * -1901919901) + -(1190748154 - -1975361759 - --1783582967))) + (0x28D610EA ^ -755681666)) * 1563361471 - (-504274630 ^ -1044814141)))) % 3;
						uint num19 = num3;
						int num20 = 1788306448;
						_ = 0;
						for (int num21 = 0; num21 < 2; num21++)
						{
							num20 = 2060110317 - num20 * -2117841401;
							num20 = -(num20 - (1975791606 - -1640974485));
						}
						if (num19 == (uint)num20)
						{
							break;
						}
						uint num22 = num3;
						int num23 = 1040742519;
						_ = 0;
						for (int num24 = 0; num24 < 2; num24++)
						{
							num23 = num23 * 1227846197 - 1273050506;
							num23 = (num23 ^ -989051442) + 1802348657;
						}
						if (num22 != (uint)num23)
						{
							uint num25 = num3;
							int num26 = -3;
							_ = 0;
							for (int num27 = 0; num27 < 1; num27++)
							{
								num26 = ~num26;
							}
							if (num25 == (uint)num26)
							{
							}
							goto end_IL_0599;
						}
						_005E_0023_0026_0024_0026_0026_002A_003E(uyW_003D);
						int[] array2 = new int[5];
						array2[0] = -1196462779;
						array2[1] = -1596475393;
						array2[2] = -1061072475;
						array2[3] = -947737430;
						array2[4] = -1927571944;
						array2[0] = array2[2] ^ 0x1272309F;
						array2[1] = array2[4] ^ 0x61D04FE0;
						array2[4] = array2[0] ^ 0x798BD659;
						int[] array3 = new int[4] { 864204419, 1474056421, 913727434, -1869228707 };
						int[][] array4 = new int[2][] { array2, array3 };
						array3[3] = array4[0][2] ^ -985018006;
						array3[1] = array3[0] ^ 0x35E82EEE;
						array3[0] ^= 471941556;
						array3[2] = array3[1] ^ 0x1634D24C;
						int num28 = array4[1][3] ^ -847461246;
						num18 = (int)((num4 * 949208574) ^ 0xC6645ABCu) ^ num28;
					}
					continue;
					end_IL_0599:
					break;
				}
			}
		}
		return result;
	}

	public void Remove(string IuO_003D)
	{
		object uyW_003D = UyW_003D;
		bool flag = false;
		try
		{
			_005E_0040_002B_0023_003C_0023_0025_003E(uyW_003D, ref flag);
			while (true)
			{
				int num = 1680792564;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(-(~(~num2 + (-(~(-(236268344 + (-294385935 + 429186804) * 1151789577)) - ~719271586) ^ ((0x1359500B ^ 0x47F24390) + ((721429155 * 710150647 + -1803470907 - -562091973 * --724722263) ^ 0x60D45688 ^ (~(~(~967534440)) + (-(1697899989 - -1406420380) ^ 0x63013D7))) - -(1285552025 * (-(-1523553042 - -585593267) ^ -1457838403)))))) + (-(-542099630 + 516692854) - -(~2076413067) + ((--2139011945 + -2001035109) ^ (--526144846 ^ 0x1169AAB2)) + (344355126 - -1623127698))) ^ -84549357))) % 4;
					uint num5 = num3;
					int num6 = 0;
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
					int num9 = 2;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = -(num9 - -202340696);
						num9 = ~(-num9);
					}
					if (num8 != (uint)num9)
					{
						uint num11 = num3;
						int num12 = -1213110799;
						_ = 0;
						for (int num13 = 0; num13 < 2; num13++)
						{
							num12 = ~num12 * -1036816567;
							num12 = -(~num12);
						}
						if (num11 != (uint)num12)
						{
							uint num14 = num3;
							int num15 = -1758559369;
							_ = 0;
							for (int num16 = 0; num16 < 1; num16++)
							{
								num15 ^= -1758559372;
							}
							if (num14 == (uint)num15)
							{
							}
							return;
						}
						WHO_003D();
						int[,] array = new int[4, 4];
						array[0, 0] = -111935858;
						array[0, 1] = 848700751;
						array[0, 2] = -666961485;
						array[0, 3] = 1644445767;
						array[1, 0] = 1527520209;
						array[1, 1] = 390821235;
						array[1, 2] = 939643119;
						array[1, 3] = 551641033;
						array[2, 0] = -1302106493;
						array[2, 1] = 1854279816;
						array[2, 2] = 1883863621;
						array[2, 3] = -1558572672;
						array[3, 0] = 128250537;
						array[3, 1] = -2000020218;
						array[3, 2] = -539918862;
						array[3, 3] = -1620355191;
						array[3, 1] = array[1, 1] ^ -358609214;
						array[2, 1] = array[0, 3] ^ 0x564E8D28;
						array[1, 1] = array[1, 0] ^ 0x3E6981B6;
						array[3, 3] = array[3, 0] ^ 0x36CC1AC8;
						int num17 = array[3, 3] ^ 0x67EAAEBC;
						num = (int)((num4 * 1550261963) ^ 0x827FBECBu) ^ num17;
						continue;
					}
					bool num18 = uSn_003D.Remove(IuO_003D);
					int[] array2 = new int[5];
					array2[0] = -1846380593;
					array2[1] = -392562593;
					array2[2] = 1281384578;
					array2[3] = 1771649173;
					array2[4] = 1318268367;
					array2[1] = array2[4] ^ 0x5A45C5C1;
					array2[1] ^= -898256475;
					array2[4] ^= -1993270210;
					int[] array3 = new int[5];
					array3[0] = -770866407;
					array3[1] = -595414954;
					array3[2] = -1504694961;
					array3[3] = 1578098162;
					array3[4] = 1500519155;
					array3[2] = array2[0] ^ -2124623616;
					array3[4] = array3[1] ^ -849016343;
					array3[4] = array3[0] ^ -1484767486;
					int num19 = array3[2] ^ 0x462CE012;
					int[] array4 = new int[5];
					array4[0] = -638764098;
					array4[1] = 114263735;
					array4[2] = -1899823442;
					array4[3] = 1762213109;
					array4[4] = 130401985;
					array4[0] = array4[2] ^ -1436943618;
					array4[4] = array4[1] ^ -1943152314;
					array4[0] ^= 564375010;
					int[] array5 = new int[7] { 1681285435, 189465869, -1735967533, 1225608789, -1386584170, -1460926782, 78467898 };
					int[][] array6 = new int[2][] { array4, array5 };
					array5[1] = array6[0][1] ^ -1264941846;
					array5[3] = array5[2] ^ 0x5561AFD4;
					array5[2] = array5[4] ^ -79863335;
					array5[6] = array5[5] ^ 0x6587C383;
					int num20 = array6[1][1] ^ -131986710;
					int num21 = (int)(num4 * 1885947824) ^ -1317162464;
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
		finally
		{
			if (flag)
			{
				while (true)
				{
					int num24 = 1585678641;
					while (true)
					{
						int num2 = num24;
						uint num4;
						uint num3 = (num4 = (uint)(~(-(-(~(~num2 + (-(~(-(236268344 + (-294385935 + 429186804) * 1151789577)) - ~719271586) ^ ((0x1359500B ^ 0x47F24390) + ((721429155 * 710150647 + -1803470907 - -562091973 * --724722263) ^ 0x60D45688 ^ (~(~(~967534440)) + (-(1697899989 - -1406420380) ^ 0x63013D7))) - -(1285552025 * (-(-1523553042 - -585593267) ^ -1457838403)))))) + (-(-542099630 + 516692854) - -(~2076413067) + ((--2139011945 + -2001035109) ^ (--526144846 ^ 0x1169AAB2)) + (344355126 - -1623127698))) ^ -84549357))) % 3;
						uint num25 = num3;
						int num26 = -1669288761;
						_ = 0;
						for (int num27 = 0; num27 < 1; num27++)
						{
							num26 ^= -1669288761;
						}
						if (num25 == (uint)num26)
						{
							break;
						}
						uint num28 = num3;
						int num29 = -2;
						_ = 0;
						for (int num30 = 0; num30 < 1; num30++)
						{
							num29 = -num29;
						}
						if (num28 != (uint)num29)
						{
							uint num31 = num3;
							int num32 = 144629409;
							_ = 0;
							for (int num33 = 0; num33 < 2; num33++)
							{
								num32 = (num32 - ~1704680266) * -1918663697;
								num32 = (num32 - 200604353 * 1544921593) * -1084961407;
							}
							if (num31 == (uint)num32)
							{
							}
							goto end_IL_08d9;
						}
						_005E_0023_0026_0024_0026_0026_002A_003E(uyW_003D);
						int[,] array7 = new int[4, 3];
						array7[0, 0] = -731700059;
						array7[0, 1] = 1425450692;
						array7[0, 2] = 879546593;
						array7[1, 0] = -1891829709;
						array7[1, 1] = -1326058695;
						array7[1, 2] = -656889405;
						array7[2, 0] = -806562642;
						array7[2, 1] = -1234697684;
						array7[2, 2] = 1638535725;
						array7[3, 0] = -996928194;
						array7[3, 1] = -1345686556;
						array7[3, 2] = -494073586;
						array7[1, 1] = array7[3, 0] ^ -394714574;
						array7[1, 1] = array7[0, 2] ^ -1213354503;
						array7[2, 0] = array7[1, 0] ^ 0x50ED60A4;
						int num34 = array7[2, 0] ^ 0x7717E2D8;
						num24 = ((int)num4 * -793309137) ^ -1241409403 ^ num34;
					}
					continue;
					end_IL_08d9:
					break;
				}
			}
		}
	}

	public void SetBoolean(string jqy_003D, bool YJt_003D)
	{
		object uyW_003D = UyW_003D;
		bool flag = false;
		try
		{
			_005E_0040_002B_0023_003C_0023_0025_003E(uyW_003D, ref flag);
			while (true)
			{
				int num = -1229309334;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-2054048741 - -(-(-(-(-(-564897831) - (~(num2 ^ (((-28872810 * 243329311) ^ -323865477) - -(~(1555286281 * -1674158931 * -2011430239 - ((0x579D99F7 ^ 0x279349A2) * -1300912369 - (1498930356 * 395698453 - (-1125555794 ^ 0x3DA9ED56)))) ^ ((1660073182 + 886462042) * 555458137 - -13892960 + (-1894885932 ^ (-1248097541 + 365098759)) + (-1020727612 - -854940435 * 1046991281 * -205170881)) ^ -(~((-279570223 * (-2096362939 * 1264302793) - -(-846325824)) ^ 0x35EF66B1))))) + ((466709681 + ((0x32D376DD ^ 0x2ED5E008) + -(726445493 * (0x44AC27CC ^ 0x788CCA3C)))) ^ (-1376273299 ^ ((-269200728 ^ 0x23E65F3E) + ~-871521787 + (-764968772 + ~80554801) - -(-350270508 ^ -96048686) - ((0x198132C ^ -1680208936) + ~(--1930798220) - -1258330033)))))) - 590971927 * (-1601341178 * -920457243)))))) % 4;
					uint num5 = num3;
					int num6 = -4;
					_ = 0;
					for (int num7 = 0; num7 < 1; num7++)
					{
						num6 = ~num6;
					}
					if (num5 == (uint)num6)
					{
						break;
					}
					uint num8 = num3;
					int num9 = 750712460;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 -= 750712458;
					}
					if (num8 != (uint)num9)
					{
						uint num11 = num3;
						int num12 = -70549519;
						_ = 0;
						for (int num13 = 0; num13 < 2; num13++)
						{
							num12 = (1950409122 - 798691735 - num12) ^ 0x716499E4;
							num12 = -num12 - 1226796841;
						}
						if (num11 != (uint)num12)
						{
							uint num14 = num3;
							int num15 = 0;
							_ = 0;
							for (int num16 = 0; num16 < 1; num16++)
							{
								num15 = -num15;
							}
							if (num14 == (uint)num15)
							{
							}
							return;
						}
						WHO_003D();
						int[,] array = new int[3, 3];
						array[0, 0] = -380849878;
						array[0, 1] = -1725943544;
						array[0, 2] = -1109226537;
						array[1, 0] = -1796078361;
						array[1, 1] = -583294401;
						array[1, 2] = 1726214153;
						array[2, 0] = 240400165;
						array[2, 1] = -2134548102;
						array[2, 2] = 1323839687;
						array[1, 0] = array[2, 1] ^ -1882430212;
						array[2, 0] = array[1, 2] ^ -324906923;
						array[2, 2] = array[1, 1] ^ 0x7C8BCC78;
						array[1, 1] = array[0, 0] ^ -1916167653;
						int num17 = array[1, 1] ^ -1889302047;
						num = (int)((num4 * 2095990549) ^ 0xDA663CD9u) ^ num17;
					}
					else
					{
						uSn_003D[jqy_003D] = YJt_003D.ToString();
						int[,] array2 = new int[4, 4];
						array2[0, 0] = 1366103947;
						array2[0, 1] = 1266436196;
						array2[0, 2] = -2089435103;
						array2[0, 3] = 207582409;
						array2[1, 0] = -988714885;
						array2[1, 1] = -423706303;
						array2[1, 2] = 855076926;
						array2[1, 3] = 1774795671;
						array2[2, 0] = -1314542158;
						array2[2, 1] = 1861211532;
						array2[2, 2] = -1575979090;
						array2[2, 3] = -799883663;
						array2[3, 0] = -488044922;
						array2[3, 1] = 79231428;
						array2[3, 2] = -1385585168;
						array2[3, 3] = -109682248;
						array2[1, 2] = array2[3, 2] ^ 0x66120417;
						array2[3, 3] = array2[0, 3] ^ -1312218371;
						array2[0, 3] = array2[1, 0] ^ 0x64D5099D;
						array2[0, 1] = array2[0, 0] ^ 0x7F50E376;
						int num18 = array2[0, 1] ^ -1944279026;
						num = (int)((num4 * 2086049534) ^ 0x5A94A764) ^ num18;
					}
				}
			}
		}
		finally
		{
			if (flag)
			{
				while (true)
				{
					int num19 = 1597793567;
					while (true)
					{
						int num2 = num19;
						uint num4;
						uint num3 = (num4 = (uint)(-2054048741 - -(-(-(-(-(-564897831) - (~(num2 ^ (((-28872810 * 243329311) ^ -323865477) - -(~(1555286281 * -1674158931 * -2011430239 - ((0x579D99F7 ^ 0x279349A2) * -1300912369 - (1498930356 * 395698453 - (-1125555794 ^ 0x3DA9ED56)))) ^ ((1660073182 + 886462042) * 555458137 - -13892960 + (-1894885932 ^ (-1248097541 + 365098759)) + (-1020727612 - -854940435 * 1046991281 * -205170881)) ^ -(~((-279570223 * (-2096362939 * 1264302793) - -(-846325824)) ^ 0x35EF66B1))))) + ((466709681 + ((0x32D376DD ^ 0x2ED5E008) + -(726445493 * (0x44AC27CC ^ 0x788CCA3C)))) ^ (-1376273299 ^ ((-269200728 ^ 0x23E65F3E) + ~-871521787 + (-764968772 + ~80554801) - -(-350270508 ^ -96048686) - ((0x198132C ^ -1680208936) + ~(--1930798220) - -1258330033)))))) - 590971927 * (-1601341178 * -920457243)))))) % 3;
						uint num20 = num3;
						int num21 = -3;
						_ = 0;
						for (int num22 = 0; num22 < 1; num22++)
						{
							num21 = ~num21;
						}
						if (num20 == (uint)num21)
						{
							break;
						}
						uint num23 = num3;
						int num24 = 1099829485;
						_ = 0;
						for (int num25 = 0; num25 < 1; num25++)
						{
							num24 *= 140954853;
						}
						if (num23 != (uint)num24)
						{
							uint num26 = num3;
							int num27 = -506708628;
							_ = 0;
							for (int num28 = 0; num28 < 1; num28++)
							{
								num27 ^= -506708628;
							}
							if (num26 == (uint)num27)
							{
							}
							goto end_IL_0806;
						}
						_005E_0023_0026_0024_0026_0026_002A_003E(uyW_003D);
						int[,] array3 = new int[4, 3]
						{
							{ 158427211, -1410100293, -18483128 },
							{ -877318715, -1243493643, 872065681 },
							{ -1021335916, 1110702296, 80292781 },
							{ 556754988, 722165775, -1600136636 }
						};
						array3[2, 2] ^= 99565890;
						array3[3, 1] = array3[2, 2] ^ 0xBE32059;
						array3[1, 1] = array3[2, 1] ^ 0x7D1DBDD6;
						int num29 = array3[1, 1] ^ -1466836671;
						num19 = ((int)num4 * -1633269171) ^ -1993899411 ^ num29;
					}
					continue;
					end_IL_0806:
					break;
				}
			}
		}
	}

	public void SetString(string IaX_003D, string? Cgh_003D)
	{
		object uyW_003D = UyW_003D;
		bool flag = false;
		try
		{
			_005E_0040_002B_0023_003C_0023_0025_003E(uyW_003D, ref flag);
			while (true)
			{
				int num = -584367303;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((num2 - ~(849856431 * (-2064012219 ^ (1645365583 * ((~(1359348757 * (-372724813 ^ -19725521)) - -940596073 * (469867833 * 260146250 + --1859791133)) ^ -(-69794891 ^ -(--1253928270)))))) + (0x7E6C7DAD ^ ((0x6839A812 ^ -1395124581) + (794207691 - -404051750 + -949523599) + (~(-1246042055 + 1992707133) + -1484274208) + ((-1006531509 ^ 0x186BD2A8) + (-(~-1114153447) ^ -(1714558137 + -1249368878)))) ^ (-(769062207 * ~-1166595090) - 499443743 * (~(-(-1546438608)) + 1066503401 * (--409628782 - -1859601256))) ^ -(733079852 + 296807416))) * 243973893) ^ ((-1066206047 ^ 0x4454067E) - ((~(-1063699997) ^ -(83743615 * 1045699662) ^ 0x2C07AB81) - 586333859 * ((-1542470514 ^ 0x123422CE) - -(--691815847)))) ^ (~(-(~467523087 + -1587814192)) ^ (0x57F06A35 ^ (-(1873753803 + -979673791) + (-1359781962 + 957483664 - (-544001741 + 1857049402))))))) % 8;
					uint num5 = num3;
					int num6 = 2;
					_ = 0;
					for (int num7 = 0; num7 < 2; num7++)
					{
						num6 = ~(num6 ^ 0x5B46DFD7);
						num6 = -(-num6);
					}
					if (num5 == (uint)num6)
					{
						break;
					}
					uint num8 = num3;
					int num9 = 1610776513;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = (num9 - ~180681076) ^ 0x2BA28D09;
						num9 = ~(-1959120467 + -1893071961 - num9);
					}
					if (num8 != (uint)num9)
					{
						uint num11 = num3;
						int num12 = 2040781832;
						_ = 0;
						for (int num13 = 0; num13 < 2; num13++)
						{
							num12 = num12 - ~972174557 - -154918174;
							num12 = -(-num12);
						}
						if (num11 != (uint)num12)
						{
							uint num14 = num3;
							int num15 = -1561312339;
							_ = 0;
							for (int num16 = 0; num16 < 2; num16++)
							{
								num15 = -(num15 ^ 0x19063096);
								num15 = -1307028501 - num15 * 2103760063;
							}
							if (num14 != (uint)num15)
							{
								uint num17 = num3;
								int num18 = 598813763;
								_ = 0;
								for (int num19 = 0; num19 < 1; num19++)
								{
									num18 ^= 0x23B12C44;
								}
								if (num17 == (uint)num18)
								{
									return;
								}
								uint num20 = num3;
								int num21 = 2147420035;
								_ = 0;
								for (int num22 = 0; num22 < 2; num22++)
								{
									num21 = num21 ^ -1739627025 ^ -1491071915;
									num21 = -((0x46B24974 ^ 0x6600C324) - num21);
								}
								if (num20 != (uint)num21)
								{
									uint num23 = num3;
									int num24 = 326644101;
									_ = 0;
									for (int num25 = 0; num25 < 1; num25++)
									{
										num24 ^= 0x13783183;
									}
									if (num23 != (uint)num24)
									{
										uint num26 = num3;
										int num27 = 562106438;
										_ = 0;
										for (int num28 = 0; num28 < 2; num28++)
										{
											num27 = ~(~num27);
											num27 = ((0x7E167732 ^ -139725546) - num27) ^ -1325619031;
										}
										if (num26 == (uint)num27)
										{
										}
										return;
									}
									WHO_003D();
									int[] array = new int[7];
									array[0] = -1891091324;
									array[1] = -2040379948;
									array[2] = -53722145;
									array[3] = -161225636;
									array[4] = 988949122;
									array[5] = 1655422211;
									array[6] = 204360654;
									array[0] = array[4] ^ -78535873;
									array[0] ^= -107817378;
									array[5] = array[2] ^ -818994192;
									int[] array2 = new int[4] { -1033383126, -1835544100, -1341377219, -1097316338 };
									int[][] array3 = new int[2][] { array, array2 };
									array2[1] = array3[0][1] ^ -1496791779;
									array2[3] = array2[2] ^ -1695534805;
									array2[3] = array2[1] ^ -116432795;
									array2[2] ^= -68750877;
									int num29 = array3[1][1] ^ -1084054191;
									num = ((int)num4 * -1198291661) ^ 0x69B09AE2 ^ num29;
								}
								else
								{
									uSn_003D[IaX_003D] = Cgh_003D;
									num = 915020814;
								}
							}
							else
							{
								WHO_003D();
								int[] array4 = new int[7];
								array4[0] = -175572954;
								array4[1] = 987974519;
								array4[2] = 1831596871;
								array4[3] = 632408390;
								array4[4] = -1028389965;
								array4[5] = -2120487558;
								array4[6] = -870526479;
								array4[0] = array4[4] ^ 0x19039F14;
								array4[1] = array4[0] ^ 0x52EC9159;
								array4[2] ^= -1923220737;
								int[] array5 = new int[4];
								array5[0] = 1004974160;
								array5[1] = 1875666625;
								array5[2] = -1109698817;
								array5[3] = 1112737467;
								array5[0] = array4[5] ^ 0x63ABB93A;
								array5[1] = array5[2] ^ 0x4E035D6B;
								array5[1] = array5[2] ^ -891579960;
								array5[2] = array5[1] ^ -363311318;
								int num30 = array5[0] ^ 0x327B50A3;
								num = ((int)num4 * -194189100) ^ 0x7A9643C4 ^ num30;
							}
						}
						else
						{
							bool num31 = uSn_003D.Remove(IaX_003D);
							int[] array6 = new int[7];
							array6[0] = 734246922;
							array6[1] = 1594830700;
							array6[2] = -1250039497;
							array6[3] = 911757685;
							array6[4] = 1609364684;
							array6[5] = -270438992;
							array6[6] = 819846839;
							array6[2] = array6[4] ^ -851164315;
							array6[4] ^= -74101176;
							array6[3] = array6[5] ^ -219731792;
							int[] array7 = new int[6];
							array7[0] = 1363174083;
							array7[1] = -1876647920;
							array7[2] = -783490678;
							array7[3] = 772834011;
							array7[4] = 1658566305;
							array7[5] = 1797751757;
							array7[1] = array6[6] ^ -828027552;
							array7[4] ^= 458586274;
							array7[4] = array7[2] ^ -1692982352;
							int num32 = array7[1] ^ 0x2E339734;
							int[] array8 = new int[7] { -1187911459, -848587680, -1206494228, -967363945, -126587512, -929413533, 162767647 };
							array8[3] ^= -1763108378;
							array8[4] = array8[5] ^ 0x598D26E0;
							int[] array9 = new int[6];
							array9[0] = -1039884157;
							array9[1] = -2115891683;
							array9[2] = -555071865;
							array9[3] = 1775121768;
							array9[4] = 173046156;
							array9[5] = -403629565;
							array9[4] = array8[5] ^ 0x3EE00251;
							array9[0] = array9[2] ^ 0x13C92989;
							array9[3] = array9[5] ^ 0x79093159;
							int num33 = array9[4] ^ 0xD87237F;
							int num34 = ((int)num4 * -1356923425) ^ 0x516B15A0;
							num32 ^= num34;
							num33 ^= num34;
							int num35;
							int num36;
							if (num31)
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
						}
					}
					else
					{
						bool num37 = _0023_0028_003F_003F_003E_002D_002A_0021(Cgh_003D);
						int[] array10 = new int[6];
						array10[0] = 1968957223;
						array10[1] = -1775402496;
						array10[2] = 724092428;
						array10[3] = 1425374757;
						array10[4] = -1909022072;
						array10[5] = 1859851667;
						array10[2] = array10[0] ^ 0x400C6ED7;
						array10[0] ^= 1733366542;
						int[] array11 = new int[6];
						array11[0] = 582749008;
						array11[1] = -1114238371;
						array11[2] = 141804581;
						array11[3] = 1846375536;
						array11[4] = 1701975939;
						array11[5] = 453521631;
						array11[2] = array10[1] ^ -1309305017;
						array11[1] = array11[0] ^ 0x505F2D6C;
						array11[1] = array11[2] ^ -182211981;
						array11[5] = array11[4] ^ -688439795;
						int num38 = array11[2] ^ -686814576;
						int[] array12 = new int[4];
						array12[0] = -1116633806;
						array12[1] = -721886207;
						array12[2] = 1574533153;
						array12[3] = -446826368;
						array12[3] = array12[2] ^ -312690227;
						array12[3] = array12[0] ^ -1288274238;
						int[] array13 = new int[6] { -1372209578, -740744519, 844476728, -1072217851, -1465702564, -1217492495 };
						int[][] array14 = new int[2][] { array12, array13 };
						array13[3] = array14[0][1] ^ 0x44A57FC1;
						array13[1] = array13[0] ^ 0x196B2985;
						array13[1] ^= -1961732138;
						int num39 = array14[1][3] ^ 0x3751026C;
						int num40 = ((int)num4 * -806138687) ^ 0x15012161;
						num38 ^= num40;
						num39 ^= num40;
						int num41;
						int num42;
						if (num37)
						{
							num41 = num39;
							num42 = num41;
						}
						else
						{
							num41 = num38;
							num42 = num41;
						}
						num = num41 ^ num40;
					}
				}
			}
		}
		finally
		{
			if (flag)
			{
				while (true)
				{
					int num43 = 1443693945;
					while (true)
					{
						int num2 = num43;
						uint num4;
						uint num3 = (num4 = (uint)(((num2 - ~(849856431 * (-2064012219 ^ (1645365583 * ((~(1359348757 * (-372724813 ^ -19725521)) - -940596073 * (469867833 * 260146250 + --1859791133)) ^ -(-69794891 ^ -(--1253928270)))))) + (0x7E6C7DAD ^ ((0x6839A812 ^ -1395124581) + (794207691 - -404051750 + -949523599) + (~(-1246042055 + 1992707133) + -1484274208) + ((-1006531509 ^ 0x186BD2A8) + (-(~-1114153447) ^ -(1714558137 + -1249368878)))) ^ (-(769062207 * ~-1166595090) - 499443743 * (~(-(-1546438608)) + 1066503401 * (--409628782 - -1859601256))) ^ -(733079852 + 296807416))) * 243973893) ^ ((-1066206047 ^ 0x4454067E) - ((~(-1063699997) ^ -(83743615 * 1045699662) ^ 0x2C07AB81) - 586333859 * ((-1542470514 ^ 0x123422CE) - -(--691815847)))) ^ (~(-(~467523087 + -1587814192)) ^ (0x57F06A35 ^ (-(1873753803 + -979673791) + (-1359781962 + 957483664 - (-544001741 + 1857049402))))))) % 3;
						uint num44 = num3;
						int num45 = -402076791;
						_ = 0;
						for (int num46 = 0; num46 < 1; num46++)
						{
							num45 += 402076791;
						}
						if (num44 == (uint)num45)
						{
							break;
						}
						uint num47 = num3;
						int num48 = 2;
						_ = 0;
						for (int num49 = 0; num49 < 2; num49++)
						{
							num48 = ~num48;
							num48 = ~num48 ^ 0x74698667;
						}
						if (num47 != (uint)num48)
						{
							uint num50 = num3;
							int num51 = 17290285;
							_ = 0;
							for (int num52 = 0; num52 < 1; num52++)
							{
								num51 += -17290284;
							}
							if (num50 == (uint)num51)
							{
							}
							goto end_IL_1008;
						}
						_005E_0023_0026_0024_0026_0026_002A_003E(uyW_003D);
						int[] array15 = new int[6];
						array15[0] = -2061532823;
						array15[1] = -572088438;
						array15[2] = -1378811556;
						array15[3] = 831263995;
						array15[4] = -548165705;
						array15[5] = 954327573;
						array15[2] = array15[5] ^ -1717621550;
						array15[5] ^= -341370545;
						int[] array16 = new int[4];
						array16[0] = 1388074051;
						array16[1] = -1582417120;
						array16[2] = 1465577734;
						array16[3] = -1654824642;
						array16[0] = array15[3] ^ -810651839;
						array16[2] = array16[0] ^ -414374031;
						array16[2] = array16[1] ^ -554418816;
						array16[1] = array16[0] ^ 0x48AB4A26;
						int num53 = array16[0] ^ -1061862831;
						num43 = (int)((num4 * 2008906487) ^ 0xC4F2AF97u) ^ num53;
					}
					continue;
					end_IL_1008:
					break;
				}
			}
		}
	}

	private Dictionary<string, string> cVD_003D()
	{
		if (!_003E_0024_002D_003E_0028_002A_0024_0021(YmR_003D))
		{
			uint num2;
			uint num4;
			int num5;
			do
			{
				int num = 174624214;
				uint num3;
				num2 = (num3 = (uint)(-1490084590 - (~(~(~(-1851354195 + -1767008243 * -1353408416))) + (-1707710281 - 824835271)) - ~(num ^ (~(-527356797 * (1341150377 * -1056502151 - (-33703129 - -632747102) - --113332792 * 1374053821 - (-1044076035 * -917891079 + 1020439003 * -1816331009 - ((-321411625 ^ 0x791D4980) + --793802630)))) * -235023321 + (-1509319084 - -1689505309 + (-(-(~1740406285)) ^ (~(--941877518) ^ (-1179294461 ^ --705101127)) ^ (0x12321F29 ^ (0x3F39FA07 ^ -(927003330 - -1878896668)))) + ~(-1568115081)) - (-(-((-1609902841 * -(-1057919455 - 1653019855) - 838200767) ^ -471291426)) + -(-279784923 * (-1928110073 * (((--1564285807 ^ -194353330) - (--1351117524 - --28244427)) * -1094026111)))))) - ((807899451 + (--2094863597 + 663317490 + ((-1217987396 ^ 0x2DC22A06) - (0x6C3CB129 ^ -1306032294)) - (~(454192212 + 994864461) + ~(987621865 - 1669594120)))) ^ (-1785050587 + ~(~(1454379936 + 1275969215) - (428810727 - -663098969 + -175696180)))))) % 3;
				num4 = num2;
				num5 = 0;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = -(-num5);
					num5 = 1072967237 - (num5 + -1392502555);
				}
			}
			while (num4 == (uint)num5);
			uint num7 = num2;
			int num8 = 458387113;
			_ = 0;
			for (int num9 = 0; num9 < 1; num9++)
			{
				num8 *= -731376231;
			}
			if (num7 == (uint)num8)
			{
				return new Dictionary<string, string>(_0028_0026_0024_002D_003E_0023_003C_002F());
			}
			uint num10 = num2;
			int num11 = -322518050;
			_ = 0;
			for (int num12 = 0; num12 < 1; num12++)
			{
				num11 *= 548269327;
			}
			if (num10 == (uint)num11)
			{
			}
		}
		Dictionary<string, string> result = default(Dictionary<string, string>);
		try
		{
			result = JsonSerializer.Deserialize<Dictionary<string, string>>(_0029_005E_0040_003F_003E_005E_0024_002B(YmR_003D)) ?? new Dictionary<string, string>(_0028_0026_0024_002D_003E_0023_003C_002F());
		}
		catch
		{
			while (true)
			{
				int num13 = 549556853;
				while (true)
				{
					int num = num13;
					uint num3;
					uint num2 = (num3 = (uint)(-1490084590 - (~(~(~(-1851354195 + -1767008243 * -1353408416))) + (-1707710281 - 824835271)) - ~(num ^ (~(-527356797 * (1341150377 * -1056502151 - (-33703129 - -632747102) - --113332792 * 1374053821 - (-1044076035 * -917891079 + 1020439003 * -1816331009 - ((-321411625 ^ 0x791D4980) + --793802630)))) * -235023321 + (-1509319084 - -1689505309 + (-(-(~1740406285)) ^ (~(--941877518) ^ (-1179294461 ^ --705101127)) ^ (0x12321F29 ^ (0x3F39FA07 ^ -(927003330 - -1878896668)))) + ~(-1568115081)) - (-(-((-1609902841 * -(-1057919455 - 1653019855) - 838200767) ^ -471291426)) + -(-279784923 * (-1928110073 * (((--1564285807 ^ -194353330) - (--1351117524 - --28244427)) * -1094026111)))))) - ((807899451 + (--2094863597 + 663317490 + ((-1217987396 ^ 0x2DC22A06) - (0x6C3CB129 ^ -1306032294)) - (~(454192212 + 994864461) + ~(987621865 - 1669594120)))) ^ (-1785050587 + ~(~(1454379936 + 1275969215) - (428810727 - -663098969 + -175696180)))))) % 3;
					uint num14 = num2;
					int num15 = 6;
					_ = 0;
					for (int num16 = 0; num16 < 2; num16++)
					{
						num15 = ~num15 ^ -1425749363;
						num15 = -num15 ^ 0x1EE9C92B;
					}
					if (num14 == (uint)num15)
					{
						break;
					}
					uint num17 = num2;
					int num18 = -694495100;
					_ = 0;
					for (int num19 = 0; num19 < 1; num19++)
					{
						num18 ^= -694495098;
					}
					if (num17 != (uint)num18)
					{
						uint num20 = num2;
						int num21 = -127;
						_ = 0;
						for (int num22 = 0; num22 < 2; num22++)
						{
							num21 = -(-398207191 - num21);
							num21 = (num21 ^ -307495116) - -636118633;
						}
						if (num20 == (uint)num21)
						{
						}
						goto end_IL_050e;
					}
					result = new Dictionary<string, string>(_0028_0026_0024_002D_003E_0023_003C_002F());
					int[] array = new int[5];
					array[0] = -379338755;
					array[1] = 898929675;
					array[2] = 285570137;
					array[3] = 575826254;
					array[4] = -1795297381;
					array[0] = array[2] ^ 0x34AB167;
					array[0] = array[4] ^ 0x7AD0F92F;
					int[] array2 = new int[4] { 344508537, 1302368112, 1167287519, -79820127 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][1] ^ -878447425;
					array2[2] ^= 1144027618;
					array2[2] = array2[3] ^ 0x6249D9C0;
					array2[2] = array2[1] ^ -667119348;
					int num23 = array3[1][0] ^ -13863898;
					num13 = (int)((num3 * 840165089) ^ 0x59EADD7C) ^ num23;
				}
				continue;
				end_IL_050e:
				break;
			}
		}
		return result;
	}

	private void WHO_003D()
	{
		_003C_003E_0024_0026_0026_002A_0024_003F(NTm_003D);
		while (true)
		{
			int num = -1256692183;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)((~(--187057550 * 1092776147 - (-(1399747461 * -(-(-1917032207 * ~-1059567955))) + -455757136 + -(0x398752E1 ^ -342956189 ^ (-1924842855 * (-777572411 * (235377310 + -315098701) - -(1116625807 - 1028401630) - (~538568573 - ~(~406701346)))))) - num2) + (-(((0x68250027 ^ -66852598) - (0x62FC4CA4 ^ 0x382A3398)) * -1571465573 - -261686673) + ~(-186672207 * 1023189587 + (-969745332 - 158933011 * 929321843 - ~(1580053449 * 1100158950))) - -631937337)) ^ (~(25416591 - (0x3DE7A7B0 ^ -1618252264)) * 1665753969 + ((-(-(~1852944661)) - -1065385193) ^ 0x37B9B31A)))) % 3;
				int num5 = 1531414076;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~num5 * -700144849;
					num5 = -(~num5);
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = ~num7 - -1731533190;
					num7 = -(-num7);
				}
				if (num3 != (uint)num7)
				{
					int num9 = -987568386;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = -(~num9);
						num9 = -(358160956 + 1295538499 - num9);
					}
					if (num3 == (uint)num9)
					{
					}
					return;
				}
				string ymR_003D = YmR_003D;
				Dictionary<string, string> value = uSn_003D;
				JsonSerializerOptions jsonSerializerOptions = new JsonSerializerOptions();
				_0026_003E_0023_005E_002A_0029_002B_005E(jsonSerializerOptions, true);
				_0024_005E__0024_0024_003C_0021_0024(ymR_003D, JsonSerializer.Serialize(value, jsonSerializerOptions));
				int[,] array = new int[4, 4];
				array[0, 0] = -1594609190;
				array[0, 1] = -386173054;
				array[0, 2] = 1774537830;
				array[0, 3] = -169919133;
				array[1, 0] = 1881355526;
				array[1, 1] = 1637894375;
				array[1, 2] = -217616142;
				array[1, 3] = 723452925;
				array[2, 0] = -147307517;
				array[2, 1] = -368286490;
				array[2, 2] = -1723927325;
				array[2, 3] = 1460257460;
				array[3, 0] = 1152259704;
				array[3, 1] = 1531431796;
				array[3, 2] = 1523532288;
				array[3, 3] = -1043028521;
				array[1, 0] = array[1, 1] ^ 0x1D98D4C9;
				array[2, 2] = array[0, 0] ^ 0x7149D2E3;
				array[0, 3] = array[3, 1] ^ -132355862;
				array[1, 3] = array[3, 3] ^ -1461443916;
				int num11 = array[1, 3] ^ -1454566442;
				num = (int)((num4 * 1027147626) ^ 0xA78A222Cu) ^ num11;
			}
		}
	}

	static string _0023_002D_0040_002D_0026_002B_0040_002B(Environment.SpecialFolder P_0)
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
				int num = -1882615441;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((num2 - (~(-(311727323 * (--902414365 ^ -892944405 ^ -55195456 ^ 0x492F2580)) ^ (-851097185 * (-1510130125 * ~(-1486244318 + 337278492 * 858767641)) - ~(0x127F12A5 ^ (-(-1067743728 - -617618640) * 265489101)))) ^ -(--1806641619)) - -(--386337953)) * -442942955) ^ 0x5B4D306B)) % 3;
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
					int num7 = -2051633576;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += 2051633577;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2136945571;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 2136945569;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					folderPath = Environment.GetFolderPath(P_0);
					int[,] array = new int[4, 3];
					array[0, 0] = 1954404441;
					array[0, 1] = -1442570156;
					array[0, 2] = -966486612;
					array[1, 0] = -249982617;
					array[1, 1] = -1347428416;
					array[1, 2] = -195406309;
					array[2, 0] = -1987277470;
					array[2, 1] = 55452291;
					array[2, 2] = 172618931;
					array[3, 0] = -773506645;
					array[3, 1] = 568624789;
					array[3, 2] = 736981521;
					array[3, 1] = array[2, 2] ^ 0x4D91BD8;
					array[2, 0] = array[2, 1] ^ -720296079;
					array[0, 1] ^= -1251587949;
					array[2, 2] = array[3, 2] ^ -914795585;
					int num11 = array[2, 2] ^ -596876159;
					num = (int)((num4 * 1807572594) ^ 0xD19F879Cu) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return folderPath;
	}

	static string _003F_003E_005E_002A_0024_0040_005E_0029(string P_0, string P_1)
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
				int num = 267173136;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(~(0x13498B39 ^ (-(-843471698 - -804999473) ^ (2041361401 - -(-1327777138))))) - (-104903119 * (-39138471 * ~(0x482A2C8B ^ -639716635)) + (2059380499 - (0x747ABF8A ^ 0x5981845D)) * -1237116119 - num2 * 1331707377)) * 937183273)) % 3;
					int num5 = 1248613792;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = 390948420 - num5 + -1930162629;
						num5 = ~num5 + -16037456;
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
						int num9 = 1823248948;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9;
							num9 = -num9 * 1264273141;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = Path.Combine(P_0, P_1);
					int[,] array = new int[3, 4];
					array[0, 0] = 897079445;
					array[0, 1] = -1889712741;
					array[0, 2] = 605051034;
					array[0, 3] = -906155880;
					array[1, 0] = -541346964;
					array[1, 1] = -1985084769;
					array[1, 2] = -1269896116;
					array[1, 3] = 676605932;
					array[2, 0] = 1613238530;
					array[2, 1] = 1780175049;
					array[2, 2] = -367120584;
					array[2, 3] = -1348977829;
					array[0, 1] = array[1, 2] ^ -1597916627;
					array[1, 2] = array[2, 0] ^ -1107979722;
					array[1, 1] = array[1, 3] ^ 0x7B8B1C12;
					array[1, 2] = array[1, 3] ^ -40799277;
					int num11 = array[1, 2] ^ 0x7FE80D08;
					num = (int)((num4 * 1360141132) ^ 0x3E0488F8) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _005E_0040_002B_0023_003C_0023_0025_003E(object P_0, ref bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1303651440;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(~num2) - (0x50069C01 ^ (-1465025621 * (-(-1229963987 * (--959532647 ^ 0x3B656214)) - ((-1785510497 ^ (0x4E9593AF ^ --1494092500)) + (-(-482019502) ^ -(~409445479))))))) ^ ((-(~-1683064289 + (-1045417635 + -1720076310 - ~-528276991)) * 1453702617) ^ ~(-(-594667517 - (-1132584313 ^ -2005768610) + (0x13DD0496 ^ 0x42AADDEF)))) ^ (((0x78047634 ^ -95887953) - ((-280472992 ^ 0x1ED69207) - --12001996)) * -836756857 * 945848805))) % 3;
					int num5 = -1717630538;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 -= -845832245;
						num5 = num5 * -1833372269 - -1796361308;
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
						int num9 = 1807152338;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 - -1930245118);
							num9 = ~(num9 - 1461146009);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					Monitor.Enter(P_0, ref P_1);
					int[] array = new int[6];
					array[0] = 572823399;
					array[1] = -871931664;
					array[2] = -777149588;
					array[3] = 38400438;
					array[4] = 1474325291;
					array[5] = 791480806;
					array[5] = array[3] ^ -1828553082;
					array[5] = array[0] ^ 0x4527B4C1;
					array[3] = array[0] ^ -1607686870;
					int[] array2 = new int[5] { -725751224, 2008637037, -921080197, -1950812867, -1783023843 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][4] ^ -1804411627;
					array2[4] = array2[1] ^ -273081838;
					array2[3] = array2[1] ^ 0x7DE497BA;
					array2[1] = array2[4] ^ 0x6E80A8B9;
					int num11 = array3[1][2] ^ -72289985;
					num = (int)((num4 * 646746528) ^ 0xD54D3400u) ^ num11;
				}
			}
		}
	}

	static bool _0028_003C_003E_005E_002F_0024_005E_0024(string P_0, ref bool P_1)
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
				int num = 1370752167;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(num2 * -1454199029) * 1979945687 + 72003932))) % 3;
					int num5 = 584100144;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 - (0x46B65351 ^ 0x6BF387D1)) ^ -1111927315;
						num5 = (0x43A712D9 ^ 0x3AFE2C2F) - num5 - -1652605170;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1520048001;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x5A9A1780;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 242391996;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 += -242391996;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = bool.TryParse(P_0, out P_1);
					int[,] array = new int[4, 4];
					array[0, 0] = -1557920862;
					array[0, 1] = 1519386575;
					array[0, 2] = 1657325317;
					array[0, 3] = -89792877;
					array[1, 0] = -1332367644;
					array[1, 1] = 276983224;
					array[1, 2] = -2128880093;
					array[1, 3] = 2024231772;
					array[2, 0] = -621706386;
					array[2, 1] = -2081475741;
					array[2, 2] = 1130133863;
					array[2, 3] = 531659764;
					array[3, 0] = 754481573;
					array[3, 1] = 52489770;
					array[3, 2] = -1872835489;
					array[3, 3] = 276533878;
					array[1, 1] = array[2, 2] ^ -958597411;
					array[0, 1] = array[1, 2] ^ -834163390;
					array[1, 1] = array[2, 1] ^ 0x22DDBEEB;
					array[2, 0] = array[3, 1] ^ -316637542;
					int num11 = array[2, 0] ^ -384485221;
					num = ((int)num4 * -201596515) ^ -1742730378 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _005E_0023_0026_0024_0026_0026_002A_003E(object P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1751963908;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((355926068 + (-299301638 - (0x1AB71069 ^ 0x69799A25))) * 1760130693 * -2130335473 - (-(~num2) + -1474428329 * (-1648589902 + -((0x43F9D3EC ^ 0x7DF415B7) - (~1740565540 + (-347829297 + 1289683399)))) * -1698552581))) % 3;
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
					int num7 = -800825297;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -800825299;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -460178217;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(num9 * -1093476781);
							num9 = ~(-num9);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					Monitor.Exit(P_0);
					int[] array = new int[6];
					array[0] = -804612483;
					array[1] = -1810677510;
					array[2] = 1032968064;
					array[3] = -1144807580;
					array[4] = -1348027989;
					array[5] = 2034803899;
					array[3] = array[2] ^ -1085744998;
					array[4] = array[1] ^ -875087230;
					array[2] = array[1] ^ -2027172805;
					int[] array2 = new int[7];
					array2[0] = 1298879812;
					array2[1] = 1597126731;
					array2[2] = 19828690;
					array2[3] = -1753182437;
					array2[4] = -1358068798;
					array2[5] = -1110978791;
					array2[6] = -1566254858;
					array2[6] = array[0] ^ 0x3DB9B0C0;
					array2[3] ^= -335128675;
					array2[4] = array2[1] ^ -1621861848;
					int num11 = array2[6] ^ 0x1D468CCF;
					num = ((int)num4 * -2063674510) ^ 0x13016292 ^ num11;
				}
			}
		}
	}

	static bool _0023_0028_003F_003F_003E_002D_002A_0021(string P_0)
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
				int num = 522966133;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(1771897253 * ~(-(1428082468 + 1617568026))) - ((~(num2 ^ (((599079177 * (~(~(~651790424) * 58404539) * 1437429985 - (952935966 + (-(-1953023848 ^ -625743545) - (0x136BD3FD ^ 0x3964044D)) + ((-1290548003 ^ -1416690757) + ~(0xBF8EE46 ^ -1344583691) + (~(0x53ADA2EE ^ -1693581039) + (1589286337 * 864466587 - -972650947)))))) ^ -956754124) + ~(-(1798366966 - ~(-819182139 * (-420828307 * -1163655669 + ~-765444013)))) * 1527634393)) - ((~(-(893843554 - 1471418415) - (1295284066 - -177673064) * 1373530559) + -111086227) ^ (916842612 + (-(0x2419016 ^ 0x27BB9A81) - 1340594850 + 796860700))) * 1454234203) ^ ~(~((0x25DB5FA0 ^ 0xE50753E) + ~(-1852593696)) - 177641349 * (1639804738 + (-1456312348 ^ 0x1A210353)))) - (~(-1269555349 ^ 0x2E697F3F) - (-(-1007854763) - 758826044)))) % 3;
					int num5 = -112754088;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= -112754090;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -2135884639;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 - (33786674 + -659434674)) ^ 0x537ECBFC;
						num7 = -1730356986 - (num7 + (-659100287 ^ 0x3949E957));
					}
					if (num3 != (uint)num7)
					{
						int num9 = -320727913;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = -320727913 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = string.IsNullOrWhiteSpace(P_0);
					int[] array = new int[7];
					array[0] = -1241203238;
					array[1] = 520980050;
					array[2] = -27622819;
					array[3] = -700503541;
					array[4] = -225182783;
					array[5] = -1477684407;
					array[6] = 1207905963;
					array[6] = array[3] ^ 0x1F2477C4;
					array[4] ^= -549425888;
					int[] array2 = new int[7] { 1868700185, -1436149285, 1466066414, 1546498591, -1365854783, 1002393765, 659360706 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][0] ^ -1946327563;
					array2[1] = array2[0] ^ -952106771;
					array2[5] = array2[2] ^ 0x59C38942;
					int num11 = array3[1][4] ^ 0x54A326E3;
					num = (int)((num4 * 744427000) ^ 0x56ADCAE0) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static bool _003E_0024_002D_003E_0028_002A_0024_0021(string P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return File.Exists(P_0);
		}
	}

	static StringComparer _0028_0026_0024_002D_003E_0023_003C_002F()
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
				int num = 1044617322;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((~(num2 * -1941296203) ^ ((0x7EEE397E ^ -(1153076645 * (-126528061 - ~-1167892771 + -(-977248838 + -1860988099)))) - 1837525476)) - -2013586299 - (1057419235 - -(-(0xC1281A ^ 0x7BF8FF17) ^ -246396144))))) % 3;
					int num5 = -1917052840;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 + (1537366775 - -483887699) - 884599524;
						num5 = -(~-178128531 - num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 0;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 ^ -1148693294 ^ -1619589640;
						num7 = ~(-num7);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1702074792;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x657399A9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ordinal = StringComparer.Ordinal;
					int[,] array = new int[3, 3]
					{
						{ 1910724362, -746513353, 1810453327 },
						{ -182107731, -2052889687, -918516387 },
						{ 459887291, 1126705873, 715129529 }
					};
					array[1, 1] ^= -607353862;
					array[0, 0] = array[2, 0] ^ -429580952;
					array[1, 0] = array[2, 2] ^ 0x471DE419;
					int num11 = array[1, 0] ^ -364089339;
					num = (int)((num4 * 472727575) ^ 0xF657DCC6u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ordinal;
	}

	static string _0029_005E_0040_003F_003E_005E_0024_002B(string P_0)
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
				int num = 454505748;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-811499197 * (-(-(--1594798356)) ^ -1784044272 ^ -1378157570) - (-(num2 * -503182895) ^ (0x5833330A ^ -(~((1890996916 + 1386387216) * -880483699 + ((-1916133092 ^ 0x4ECC55F7) + 1936253763 * 63800512))) ^ (~(-(-1732436293 * -1071443552 * -798089569 - -31207909 * -661612079)) - (((~1425792407 - ~-778995730 + -(2143344772 - 725549817)) ^ 0x4F8FACE7) + 320761187 * (-714118865 + 1360138982 + (237055323 + -346676323) + (602072575 - -935838799 * 333780871)))))) - (-(~1871104444 * 208928463) * -1594032027 + ((-1306855650 ^ -1657146808) + -2003641154)))) % 3;
					int num5 = 177635532;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 * -1394555331;
						num5 += -147365669 * -14837530;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1275261122;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -1270557601;
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
					result = File.ReadAllText(P_0);
					int[,] array = new int[4, 3];
					array[0, 0] = -1162270189;
					array[0, 1] = 1450825021;
					array[0, 2] = 1718113125;
					array[1, 0] = -1934018078;
					array[1, 1] = -948234314;
					array[1, 2] = 895140230;
					array[2, 0] = 1742382722;
					array[2, 1] = 284920694;
					array[2, 2] = 620407173;
					array[3, 0] = -560553886;
					array[3, 1] = 1811599108;
					array[3, 2] = 493217816;
					array[2, 1] = array[2, 0] ^ 0x7F20AD2B;
					array[0, 0] = array[3, 1] ^ -1289998010;
					array[3, 2] = array[0, 1] ^ -94559763;
					int num11 = array[3, 2] ^ -36895203;
					num = ((int)num4 * -1594162067) ^ -2133033853 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static DirectoryInfo _003C_003E_0024_0026_0026_002A_0024_003F(string P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return Directory.CreateDirectory(P_0);
		}
	}

	static void _0026_003E_0023_005E_002A_0029_002B_005E(JsonSerializerOptions P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -994136210;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~((1525309172 - 1458860691 - (1169733569 - -1731464593)) * 1154976379) - ~((-2081996055 + ~((-936918071 + 323136041 - 1130480251 + (-299052591 - 462609543 - (1889167943 - -1442264163))) * -1498517771 - 771964679) - ~(num2 * -963141471)) ^ ~((-1272759353 ^ -1218531076) - (~(386247094 * 1381140265) + (-492480056 ^ 0x44744526)) - -(-378248959 * -1051090311)))))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = 1421592666 - 1294606654 - num5 + 152460211;
						num5 += 211625614 + 526662183;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -371067220;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= -371067219;
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
						return;
					}
					P_0.WriteIndented = P_1;
					int[,] array = new int[3, 4];
					array[0, 0] = -21757099;
					array[0, 1] = 985776082;
					array[0, 2] = -468159803;
					array[0, 3] = 1053041189;
					array[1, 0] = -1991335123;
					array[1, 1] = 627868603;
					array[1, 2] = 1609054814;
					array[1, 3] = 1374212275;
					array[2, 0] = -1718237265;
					array[2, 1] = -1348665052;
					array[2, 2] = -1072420765;
					array[2, 3] = 112147960;
					array[2, 3] = array[1, 2] ^ -707413797;
					array[0, 3] = array[2, 3] ^ -1659647141;
					array[0, 1] = array[2, 2] ^ -2002464319;
					array[1, 0] = array[1, 1] ^ 0x52255E83;
					int num11 = array[1, 0] ^ 0x2732B3F4;
					num = ((int)num4 * -397694704) ^ -1287821904 ^ num11;
				}
			}
		}
	}

	static void _0024_005E__0024_0024_003C_0021_0024(string P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1825424262;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(~(-num2))))) % 3;
					int num5 = 720871850;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 += -720871850;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 597869698;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 ^ -926653804;
						num7 = -(num7 * -1800799629);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -139453469;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 += 139453470;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					File.WriteAllText(P_0, P_1);
					int[,] array = new int[3, 3];
					array[0, 0] = -815672337;
					array[0, 1] = 1776096224;
					array[0, 2] = 1539131152;
					array[1, 0] = -207694946;
					array[1, 1] = -946355556;
					array[1, 2] = 1965759356;
					array[2, 0] = -410460965;
					array[2, 1] = -532216688;
					array[2, 2] = 2056490600;
					array[2, 1] = array[1, 2] ^ 0x6AED417C;
					array[1, 0] = array[2, 1] ^ -316896099;
					array[0, 2] = array[2, 1] ^ 0x67C86A69;
					array[0, 1] = array[1, 2] ^ -1040806732;
					int num11 = array[0, 1] ^ -489041130;
					num = ((int)num4 * -91439577) ^ 0x19317F43 ^ num11;
				}
			}
		}
	}
}
