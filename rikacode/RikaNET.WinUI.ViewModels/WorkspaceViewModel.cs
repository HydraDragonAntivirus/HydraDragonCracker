using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Xaml.Controls;
using RikaNET.Core.Models;
using RikaNET.Core.Services;

namespace RikaNET.WinUI.ViewModels;

public sealed class WorkspaceViewModel : ObservableObject
{
	[Serializable]
	[CompilerGenerated]
	private sealed class _003C_003Ec
	{
		public static readonly _003C_003Ec _003C_003E9 = new _003C_003Ec();

		public static Func<NamespaceItem, IEnumerable<TypeItem>> _003C_003E9__124_0;

		public static Func<MethodItem, bool> _003C_003E9__124_2;

		internal IEnumerable<TypeItem> _003CCountSelectedMethods_003Eb__124_0(NamespaceItem @namespace)
		{
			return _0025_003C_002A_0028_0024_0021__002B(@namespace);
		}

		internal bool _003CCountSelectedMethods_003Eb__124_2(MethodItem method)
		{
			return _002D_003C_0023_0021_003D_003F_005E_0021(method);
		}

		static IReadOnlyList<TypeItem> _0025_003C_002A_0028_0024_0021__002B(NamespaceItem P_0)
		{
			IReadOnlyList<TypeItem> types = default(IReadOnlyList<TypeItem>);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 37677894;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~((0x387318F2 ^ -1199377029) - -(-((((num2 - -(22686741 * (~(986761603 * (--292516053 ^ -1440461504) * -66461401) * -19117815) - (1517672986 - (~(--734645764 + (-98338308 - 346973921)) ^ -707802363 ^ (-(-251702725 + ~-1555124497) * 1848269371)) + (--2039631539 + -(0x52395ABC ^ 0x3E7279A9)))) + (((-(1038855032 - -(-1685289174 ^ 0x429FC131)) + (~(~1645046914) + (~(-1321432758 * -780479785) * -177857587 - -539028420))) ^ -933330013) + ~(-((0x68027D66 ^ -440715920) * -556692233 - (-565058927 * -(0x502ABD1F ^ 0x23EB7EFD) - ((-512926139 ^ 0x5465740C) - (0x38B15C34 ^ --1176161624))))))) ^ -624030548) + ~(1748926209 * (-651553703 * (648073679 * 170311044 * -1027023953) - -(814733887 * -1689156159 + ~229630094)))) * 1945290359))) + 884623480)) % 3;
						int num5 = 269131938;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = num5 - -1252497765 * 16165040 - -1765666499;
							num5 = (num5 + (-1332302006 - -1488221534)) ^ 0x33AA272F;
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
							int num9 = 1993452132;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 += -1993452132;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						types = P_0.Types;
						int[] array = new int[4];
						array[0] = -105282805;
						array[1] = 1795447290;
						array[2] = 620428641;
						array[3] = -728596310;
						array[2] = array[3] ^ -516195520;
						array[2] = array[3] ^ -1973102779;
						array[3] = array[1] ^ 0x754373FF;
						int[] array2 = new int[4];
						array2[0] = 459217051;
						array2[1] = -1789943847;
						array2[2] = 448860377;
						array2[3] = 70067555;
						array2[2] = array[1] ^ -2057429984;
						array2[0] = array2[2] ^ 0x7330E57;
						array2[0] = array2[2] ^ -1986970280;
						array2[1] = array2[0] ^ 0x22D13CBF;
						int num11 = array2[2] ^ 0x42F91BC4;
						num = ((int)num4 * -1943864486) ^ 0x3AD89D7C ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return types;
		}

		static bool _002D_003C_0023_0021_003D_003F_005E_0021(MethodItem P_0)
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
					int num = 814760033;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(((~(~(-(num2 ^ ((~(-(~-957454561) + ~(~(-1382189122 + 307399101)) * 2089664047 + ~1987152106) + (((~(662138960 - 57374778 - (-819138 + 704777634)) - (-(~906036826) + -2005533094) - -((0x7CD8B73B ^ -277873818) * 1337344701)) ^ (-1062446203 * (-35133811 * -(1625359078 + 880845470) + (0x7E9411BB ^ 0x5553A57D)))) + ((-1163763791 ^ (-((0x70D58609 ^ 0x5C3BE0) - --1588027104) - (~-434274684 - (617406336 + -836428174)) * 710051607)) + ~(0x72D0A4DF ^ (-(-1817324039 + 1207906462) ^ -(1262856167 * 2126295035)))))) ^ (-310948847 - (-(-652470509 - ~1228358199 - ~(-926371096 + -2064557738)) * -795776885 - ((~(-(-1700414461 + -932015348)) - (539728187 * (-783436117 - -676374561) + (-531185744 + -992296268 + 1932995345))) ^ 0x1D32BC1A)) - -(1220848809 * ((0x55128CB6 ^ -1228670576) + (-1824671955 - (1082949848 - 1749993648)) + (-166062885 * (-1229069221 - 1776763795) - (-961514288 ^ -1482960698)))) * -1103741495))) * 728938873 * -235921409)) - (-1820115866 ^ -(693176639 + 252354216))) ^ 0x6D0F88B0) + (1363764068 - -1953074449)))) % 3;
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
						int num7 = 834755331;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 ^= 0x31C15B02;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 922765654;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = (num9 - (929512426 + -1363984310)) * 574436869;
								num9 = (num9 + 810916138) ^ 0x5A3A8B1F;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						ısSelected = P_0.IsSelected;
						int[] array = new int[5];
						array[0] = -789765755;
						array[1] = -1702323728;
						array[2] = -979239252;
						array[3] = 1271911648;
						array[4] = 1176944296;
						array[4] = array[0] ^ 0x7FD8634A;
						array[0] = array[1] ^ 0x53BA5A84;
						array[4] = array[0] ^ 0x6E157B9D;
						int[] array2 = new int[6] { -902156680, -786335208, 181241157, 70865852, -1238750756, 1882003587 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[3] = array3[0][2] ^ 0x52BCC57C;
						array2[4] = array2[2] ^ -1032120708;
						array2[2] ^= -1772861547;
						array2[0] = array2[3] ^ -689883315;
						int num11 = array3[1][3] ^ -129841614;
						num = ((int)num4 * -573116204) ^ 0x674832F0 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return ısSelected;
		}
	}

	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CBrowseAssemblyAsync_003Ed__120 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder _003C_003Et__builder;

		public WorkspaceViewModel _003C_003E4__this;

		private TaskAwaiter<string?> _003C_003Eu__1;

		private TaskAwaiter _003C_003Eu__2;

		private void MoveNext()
		{
			int num = _003C_003E1__state;
			WorkspaceViewModel workspaceViewModel = _003C_003E4__this;
			try
			{
				if (num != 0)
				{
					goto IL_0023;
				}
				goto IL_0968;
				IL_0023:
				int num2 = 549984975;
				goto IL_0028;
				IL_0028:
				TaskAwaiter<string> awaiter = default(TaskAwaiter<string>);
				string result = default(string);
				TaskAwaiter awaiter2 = default(TaskAwaiter);
				while (true)
				{
					int num3 = num2;
					uint num5;
					uint num4 = (num5 = (uint)(~(((((~(~(num3 * 1822393683)) * -1947297995) ^ -1999937574) - -(-1993454339)) ^ -730245061) + (158919636 + 1161905349 - -2107418084) - --845535154))) % 22;
					uint num6 = num4;
					int num7 = 819778310;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7;
						num7 = 1158428620 * 2078650193 - num7 - -1192458999;
					}
					if (num6 == (uint)num7)
					{
						break;
					}
					uint num9 = num4;
					int num10 = 1508682819;
					_ = 0;
					for (int num11 = 0; num11 < 2; num11++)
					{
						num10 *= -231928517;
						num10 = -num10 - 1269498827;
					}
					if (num9 == (uint)num10)
					{
						int num12 = num;
						int[,] array = new int[3, 4];
						array[0, 0] = 100668711;
						array[0, 1] = -1588070868;
						array[0, 2] = 58020596;
						array[0, 3] = 809621868;
						array[1, 0] = -1568029748;
						array[1, 1] = 998236551;
						array[1, 2] = -1880490294;
						array[1, 3] = -1541858659;
						array[2, 0] = 1071259860;
						array[2, 1] = -714697791;
						array[2, 2] = 682069375;
						array[2, 3] = -1173108970;
						array[0, 2] = array[0, 0] ^ 0x1B2646B;
						array[2, 3] = array[0, 1] ^ -1918247697;
						array[2, 0] = array[2, 1] ^ 0x76453E33;
						array[0, 1] = array[1, 1] ^ 0x7DE6D529;
						int num13 = array[0, 1] ^ 0x13273EBC;
						int[] array2 = new int[5];
						array2[0] = 777397388;
						array2[1] = -1438561025;
						array2[2] = 529322993;
						array2[3] = -382317529;
						array2[4] = 1996319653;
						array2[1] = array2[3] ^ 0x72AAC51;
						array2[4] = array2[2] ^ 0x57573F9D;
						int[] array3 = new int[7];
						array3[0] = -1032856427;
						array3[1] = 1533023344;
						array3[2] = -1880501390;
						array3[3] = -470193637;
						array3[4] = -1254070761;
						array3[5] = -847205004;
						array3[6] = -752635682;
						array3[6] = array2[2] ^ 0xE64BB60;
						array3[0] = array3[6] ^ 0x3D81AA12;
						array3[2] = array3[3] ^ 0xB31682E;
						array3[2] = array3[0] ^ 0x228FE826;
						int num14 = array3[6] ^ -284450286;
						int num15 = ((int)num5 * -678070882) ^ 0x440F64FE;
						num13 ^= num15;
						num14 ^= num15;
						int num16;
						int num17;
						if (num12 != 1)
						{
							num16 = num14;
							num17 = num16;
						}
						else
						{
							num16 = num13;
							num17 = num16;
						}
						num2 = num16 ^ num15;
						continue;
					}
					uint num18 = num4;
					int num19 = 536936549;
					_ = 0;
					for (int num20 = 0; num20 < 2; num20++)
					{
						num19 = ~(num19 + 554851907 * 1550920251);
						num19 = (num19 - 10408251 * -904673503) ^ -771714383;
					}
					if (num18 == (uint)num19)
					{
						awaiter = _0024_003C_0026_003D_0024_002D_002A_002F(workspaceViewModel._filePickerService).GetAwaiter();
						int[] array4 = new int[6];
						array4[0] = -1054757081;
						array4[1] = -1907326073;
						array4[2] = 878803704;
						array4[3] = -1392126339;
						array4[4] = -792621010;
						array4[5] = 1249070913;
						array4[1] = array4[5] ^ 0x49DCF7DE;
						array4[2] = array4[4] ^ 0x7F760BD2;
						int[] array5 = new int[6] { -1729326928, 622324956, -682462701, -2129587905, 907485298, 1045913120 };
						int[][] array6 = new int[2][] { array4, array5 };
						array5[1] = array6[0][3] ^ -481556461;
						array5[5] = array5[3] ^ -1378564148;
						array5[0] = array5[4] ^ 0x2D05BCF6;
						array5[4] = array5[3] ^ 0x7C19BCE3;
						int num21 = array6[1][1] ^ -357950699;
						num2 = ((int)num5 * -1582071640) ^ -701774520 ^ num21;
						continue;
					}
					uint num22 = num4;
					int num23 = -2146430891;
					_ = 0;
					for (int num24 = 0; num24 < 2; num24++)
					{
						num23 = -(~num23);
						num23 = (num23 ^ -1096456932) - 1477257503;
					}
					if (num22 == (uint)num23)
					{
						bool ısCompleted = awaiter.IsCompleted;
						int[] array7 = new int[5];
						array7[0] = 228015872;
						array7[1] = 1994039675;
						array7[2] = 2058310086;
						array7[3] = -1599102702;
						array7[4] = -1496304006;
						array7[4] = array7[2] ^ -1899882839;
						array7[3] = array7[0] ^ 0x63E2966B;
						array7[3] = array7[2] ^ -2062373539;
						int[] array8 = new int[7];
						array8[0] = -1665546391;
						array8[1] = 159931821;
						array8[2] = 6542471;
						array8[3] = 2014672677;
						array8[4] = -166276204;
						array8[5] = 2132316433;
						array8[6] = -462152883;
						array8[4] = array7[2] ^ 0x5B17498C;
						array8[6] = array8[1] ^ 0x79E0CE32;
						array8[0] ^= 136926060;
						int num25 = array8[4] ^ -2019178357;
						int[] array9 = new int[5];
						array9[0] = 1709417724;
						array9[1] = 744366846;
						array9[2] = -1545276151;
						array9[3] = -1224792213;
						array9[4] = -1584348544;
						array9[0] = array9[3] ^ -1688970431;
						array9[4] = array9[3] ^ 0x1605BBDC;
						array9[0] = array9[2] ^ -483883162;
						int[] array10 = new int[4] { 901449800, 1949611741, -1016368034, 155456294 };
						int[][] array11 = new int[2][] { array9, array10 };
						array10[0] = array11[0][2] ^ -1035675014;
						array10[2] = array10[1] ^ -1494556796;
						array10[3] = array10[2] ^ 0x699B2F6B;
						int num26 = array11[1][0] ^ 0x5E8086D7;
						int num27 = ((int)num5 * -1083507880) ^ -5390344;
						num25 ^= num27;
						num26 ^= num27;
						int num28;
						int num29;
						if (!ısCompleted)
						{
							num28 = num26;
							num29 = num28;
						}
						else
						{
							num28 = num25;
							num29 = num28;
						}
						num2 = num28 ^ num27;
						continue;
					}
					uint num30 = num4;
					int num31 = 482612284;
					_ = 0;
					for (int num32 = 0; num32 < 2; num32++)
					{
						num31 = -num31 - -771183545;
						num31 = num31 * 980916809 + 655314925;
					}
					if (num30 == (uint)num31)
					{
						num = (_003C_003E1__state = 0);
						int[] array12 = new int[4];
						array12[0] = -804142286;
						array12[1] = 1571111783;
						array12[2] = -1746503371;
						array12[3] = 363334245;
						array12[3] = array12[2] ^ 0x4A1C7BE5;
						array12[2] = array12[1] ^ 0x3F38D35;
						array12[3] = array12[0] ^ 0x7804F5D4;
						int[] array13 = new int[4] { 441579122, -1912923745, 1297452218, -626215657 };
						int[][] array14 = new int[2][] { array12, array13 };
						array13[2] = array14[0][1] ^ 0x5F630D2F;
						array13[3] = array13[1] ^ -1336835255;
						array13[1] = array13[2] ^ 0x67CDDDF5;
						int num33 = array14[1][2] ^ -1583872124;
						num2 = ((int)num5 * -1505481517) ^ -1436747660 ^ num33;
						continue;
					}
					uint num34 = num4;
					int num35 = 1695659902;
					_ = 0;
					for (int num36 = 0; num36 < 2; num36++)
					{
						num35 = (num35 ^ 0xBC1BCD7) * -422762457;
						num35 = num35 - (1962326840 - -1734517054) - 828885673;
					}
					if (num34 == (uint)num35)
					{
						_003C_003Eu__1 = awaiter;
						int[,] array15 = new int[3, 3];
						array15[0, 0] = -543810223;
						array15[0, 1] = -1014493108;
						array15[0, 2] = -490492912;
						array15[1, 0] = -39453289;
						array15[1, 1] = 697856871;
						array15[1, 2] = -1783243982;
						array15[2, 0] = 1471369266;
						array15[2, 1] = -1461010907;
						array15[2, 2] = 1905699664;
						array15[0, 0] = array15[1, 1] ^ 0x3B27192;
						array15[1, 1] = array15[0, 0] ^ -651066285;
						array15[2, 2] = array15[2, 0] ^ -1030149204;
						array15[0, 2] = array15[2, 0] ^ 0x6ABFE6DC;
						int num37 = array15[0, 2] ^ -94005946;
						num2 = (int)((num5 * 468008681) ^ 0x91EEB944u) ^ num37;
						continue;
					}
					uint num38 = num4;
					int num39 = -17;
					_ = 0;
					for (int num40 = 0; num40 < 1; num40++)
					{
						num39 = ~num39;
					}
					if (num38 == (uint)num39)
					{
						_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
						return;
					}
					uint num41 = num4;
					int num42 = 2087531874;
					_ = 0;
					for (int num43 = 0; num43 < 2; num43++)
					{
						num42 = (num42 ^ -1248469855) * 873500107;
						num42 = ~num42 ^ 0x17FF76BD;
					}
					if (num41 == (uint)num42)
					{
						goto IL_0968;
					}
					uint num44 = num4;
					int num45 = -1892411;
					_ = 0;
					for (int num46 = 0; num46 < 2; num46++)
					{
						num45 = 1896027573 - (num45 ^ -1655533450);
						num45 -= -635868425 ^ 0x1465B260;
					}
					if (num44 == (uint)num45)
					{
						_003C_003Eu__1 = default(TaskAwaiter<string>);
						int[] array16 = new int[5];
						array16[0] = 1048900557;
						array16[1] = 927918225;
						array16[2] = -1832056232;
						array16[3] = -1470635627;
						array16[4] = -422264792;
						array16[1] = array16[2] ^ 0x599F5072;
						array16[4] = array16[0] ^ 0x6FF8FEB7;
						int[] array17 = new int[6] { -930312428, 629567350, -2069362431, -1871335459, 862992503, -818530289 };
						int[][] array18 = new int[2][] { array16, array17 };
						array17[4] = array18[0][2] ^ 0x2863985E;
						array17[5] ^= -750499481;
						array17[2] = array17[3] ^ 0x4187A08E;
						int num47 = array18[1][4] ^ 0x35668713;
						num2 = (int)((num5 * 985798944) ^ 0x2367C4E0) ^ num47;
						continue;
					}
					uint num48 = num4;
					int num49 = 473520150;
					_ = 0;
					for (int num50 = 0; num50 < 1; num50++)
					{
						num49 -= 473520137;
					}
					if (num48 == (uint)num49)
					{
						num = (_003C_003E1__state = -1);
						int[] array19 = new int[7];
						array19[0] = -1865719476;
						array19[1] = -853630134;
						array19[2] = -1327420138;
						array19[3] = 538633207;
						array19[4] = 1073211479;
						array19[5] = -477432200;
						array19[6] = 807650401;
						array19[2] = array19[4] ^ 0x58028EF0;
						array19[5] = array19[2] ^ 0x7C62309E;
						int[] array20 = new int[5];
						array20[0] = 1962162323;
						array20[1] = 886771571;
						array20[2] = 1966040624;
						array20[3] = -1857377725;
						array20[4] = -413838121;
						array20[2] = array19[3] ^ 0x52ADA918;
						array20[1] = array20[0] ^ 0x19C40356;
						array20[4] = array20[2] ^ -24654429;
						int num51 = array20[2] ^ -727016914;
						num2 = ((int)num5 * -1746841493) ^ -515837851 ^ num51;
						continue;
					}
					uint num52 = num4;
					int num53 = 1862185683;
					_ = 0;
					for (int num54 = 0; num54 < 2; num54++)
					{
						num53 = ~num53 * -520963425;
						num53 = -(-366863464 - 1933598903 - num53);
					}
					if (num52 == (uint)num53)
					{
						result = awaiter.GetResult();
						int num55;
						if (!_0025_0024_002D_0026_003D_0024_002B_0028(result))
						{
							num2 = 1682744444;
							num55 = num2;
						}
						else
						{
							num2 = 203271762;
							num55 = num2;
						}
						continue;
					}
					uint num56 = num4;
					int num57 = 1245933525;
					_ = 0;
					for (int num58 = 0; num58 < 1; num58++)
					{
						num57 = 1245933543 - num57;
					}
					if (num56 == (uint)num57)
					{
						awaiter2 = _003F_0021_003D_0028_003F_002F_0025_002F(workspaceViewModel.LoadAssemblyAsync(result));
						int[] array21 = new int[7];
						array21[0] = 1024897912;
						array21[1] = 1637689866;
						array21[2] = 1780913907;
						array21[3] = -2009929128;
						array21[4] = 56124149;
						array21[5] = -1025485085;
						array21[6] = -465525447;
						array21[0] = array21[6] ^ 0x2391DDF6;
						array21[4] = array21[2] ^ 0x1072D2B8;
						int[] array22 = new int[7];
						array22[0] = 188394453;
						array22[1] = 1771453202;
						array22[2] = 436028385;
						array22[3] = -1203628018;
						array22[4] = 2000164128;
						array22[5] = -1073615019;
						array22[6] = -532173002;
						array22[2] = array21[1] ^ 0x6464310F;
						array22[0] = array22[2] ^ -259387098;
						array22[3] = array22[0] ^ -327019306;
						array22[6] = array22[4] ^ 0x45F28E9E;
						int num59 = array22[2] ^ -859824082;
						num2 = (int)((num5 * 1814173614) ^ 0x8A404398u) ^ num59;
						continue;
					}
					uint num60 = num4;
					int num61 = 21;
					_ = 0;
					for (int num62 = 0; num62 < 2; num62++)
					{
						num61 = -num61;
						num61 -= 1981746159 + -590305374;
					}
					if (num60 == (uint)num61)
					{
						bool ısCompleted2 = awaiter2.IsCompleted;
						int[,] array23 = new int[3, 4];
						array23[0, 0] = -685256668;
						array23[0, 1] = 2094471582;
						array23[0, 2] = -2024724140;
						array23[0, 3] = 1682660709;
						array23[1, 0] = 10759930;
						array23[1, 1] = 1574891190;
						array23[1, 2] = 1192917149;
						array23[1, 3] = 1212350954;
						array23[2, 0] = -41012427;
						array23[2, 1] = 1786279603;
						array23[2, 2] = 285550921;
						array23[2, 3] = -74030083;
						array23[1, 2] = array23[1, 0] ^ -1792993261;
						array23[1, 2] = array23[2, 1] ^ -1596224311;
						array23[0, 1] = array23[2, 1] ^ -760927387;
						array23[2, 0] = array23[0, 2] ^ 0x63C0FD5;
						int num63 = array23[2, 0] ^ 0x56DF3463;
						int[,] array24 = new int[4, 3];
						array24[0, 0] = -1622785041;
						array24[0, 1] = 1492974060;
						array24[0, 2] = -26004193;
						array24[1, 0] = 327289742;
						array24[1, 1] = -589508179;
						array24[1, 2] = 1445370875;
						array24[2, 0] = -236596005;
						array24[2, 1] = -1964547672;
						array24[2, 2] = 1110789835;
						array24[3, 0] = 336147903;
						array24[3, 1] = 1781664475;
						array24[3, 2] = -1068563942;
						array24[1, 2] = array24[0, 2] ^ 0x4853D284;
						array24[0, 1] = array24[0, 2] ^ -1146081638;
						array24[3, 0] = array24[2, 2] ^ -1297230037;
						int num64 = array24[3, 0] ^ 0x1833515B;
						int num65 = ((int)num5 * -1580038834) ^ -1209896266;
						num63 ^= num65;
						num64 ^= num65;
						int num66;
						int num67;
						if (!ısCompleted2)
						{
							num66 = num64;
							num67 = num66;
						}
						else
						{
							num66 = num63;
							num67 = num66;
						}
						num2 = num66 ^ num65;
						continue;
					}
					uint num68 = num4;
					int num69 = -674104423;
					_ = 0;
					for (int num70 = 0; num70 < 2; num70++)
					{
						num69 = ~(num69 - (1477662948 + 759049573));
						num69 = ~(num69 + -426281088);
					}
					if (num68 == (uint)num69)
					{
						num = (_003C_003E1__state = 1);
						int[] array25 = new int[4];
						array25[0] = -658341325;
						array25[1] = -1492149385;
						array25[2] = -369739669;
						array25[3] = -654230519;
						array25[2] = array25[3] ^ -1426739462;
						array25[0] = array25[3] ^ 0x1147EC4A;
						array25[1] = array25[3] ^ 0x1ADDEFA2;
						int[] array26 = new int[5];
						array26[0] = -1941424632;
						array26[1] = 1016681534;
						array26[2] = -841391284;
						array26[3] = -830756563;
						array26[4] = -34001450;
						array26[3] = array25[3] ^ -1071627270;
						array26[2] ^= -2087163024;
						array26[1] = array26[0] ^ -714333101;
						int num71 = array26[3] ^ 0x2B68F01E;
						num2 = ((int)num5 * -627150875) ^ 0x5FCE29D1 ^ num71;
						continue;
					}
					uint num72 = num4;
					int num73 = -16;
					_ = 0;
					for (int num74 = 0; num74 < 1; num74++)
					{
						num73 = ~num73;
					}
					if (num72 == (uint)num73)
					{
						_003C_003Eu__2 = awaiter2;
						int[,] array27 = new int[4, 4];
						array27[0, 0] = -1043964168;
						array27[0, 1] = 331669444;
						array27[0, 2] = 603914318;
						array27[0, 3] = -461783796;
						array27[1, 0] = -977360629;
						array27[1, 1] = 1681936471;
						array27[1, 2] = -1059259603;
						array27[1, 3] = 1429613190;
						array27[2, 0] = -439860356;
						array27[2, 1] = -1502251004;
						array27[2, 2] = -1395888582;
						array27[2, 3] = -1922484712;
						array27[3, 0] = -1808593028;
						array27[3, 1] = -1789822164;
						array27[3, 2] = 1446883387;
						array27[3, 3] = 701562444;
						array27[1, 2] = array27[1, 3] ^ 0x4E9736D6;
						array27[3, 3] = array27[1, 3] ^ 0x3AFE4041;
						array27[0, 3] = array27[1, 3] ^ 0x61C0BE18;
						array27[2, 0] = array27[0, 1] ^ 0x284350B;
						int num75 = array27[2, 0] ^ 0x1703E986;
						num2 = (int)((num5 * 503729289) ^ 0x2B03517F) ^ num75;
						continue;
					}
					uint num76 = num4;
					int num77 = 2002912722;
					_ = 0;
					for (int num78 = 0; num78 < 1; num78++)
					{
						num77 -= 2002912711;
					}
					if (num76 == (uint)num77)
					{
						_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter2, ref this);
						int[] array28 = new int[6];
						array28[0] = 1212229655;
						array28[1] = -1861340829;
						array28[2] = 1497085915;
						array28[3] = 17701029;
						array28[4] = -979361890;
						array28[5] = 1550711491;
						array28[2] = array28[5] ^ -1153188906;
						array28[5] = array28[1] ^ -551027603;
						array28[2] ^= 176689816;
						int[] array29 = new int[6] { 1677952275, 996903238, 1972938281, -572390765, -100251200, 2922473 };
						int[][] array30 = new int[2][] { array28, array29 };
						array29[0] = array30[0][0] ^ -1014767297;
						array29[5] ^= -1815294194;
						array29[3] ^= -694307599;
						array29[2] = array29[1] ^ -1159534398;
						int num79 = array30[1][0] ^ 0x658382CC;
						num2 = (int)((num5 * 1300399416) ^ 0xD895FE28u) ^ num79;
						continue;
					}
					uint num80 = num4;
					int num81 = -4;
					_ = 0;
					for (int num82 = 0; num82 < 1; num82++)
					{
						num81 = -num81;
					}
					if (num80 == (uint)num81)
					{
						return;
					}
					uint num83 = num4;
					int num84 = 0;
					_ = 0;
					for (int num85 = 0; num85 < 1; num85++)
					{
						num84 *= 402915545;
					}
					if (num83 == (uint)num84)
					{
						awaiter2 = _003C_003Eu__2;
						num2 = -1854512150;
						continue;
					}
					uint num86 = num4;
					int num87 = -102176230;
					_ = 0;
					for (int num88 = 0; num88 < 2; num88++)
					{
						num87 *= 1187449077;
						num87 *= -533839921;
					}
					if (num86 == (uint)num87)
					{
						_003C_003Eu__2 = default(TaskAwaiter);
						int[] array31 = new int[7] { 946339411, -883093531, 713422619, 1727247346, -499507308, 817537946, -1973572772 };
						array31[2] ^= -1149190437;
						array31[3] = array31[0] ^ -400551120;
						array31[4] = array31[0] ^ 0x45700A6F;
						int[] array32 = new int[5] { -477766714, 1552321011, 1720195440, 721881059, -1556446184 };
						int[][] array33 = new int[2][] { array31, array32 };
						array32[4] = array33[0][0] ^ -2018208953;
						array32[2] ^= 1369580095;
						array32[0] = array32[1] ^ 0x7EE265CC;
						array32[0] = array32[1] ^ -648280091;
						int num89 = array33[1][4] ^ -572591069;
						num2 = ((int)num5 * -866307316) ^ -467042408 ^ num89;
						continue;
					}
					uint num90 = num4;
					int num91 = 1786886515;
					_ = 0;
					for (int num92 = 0; num92 < 2; num92++)
					{
						num91 = ~(num91 * -1041371555);
						num91 = ~(num91 * -2034472129);
					}
					if (num90 == (uint)num91)
					{
						num = (_003C_003E1__state = -1);
						int[] array34 = new int[5];
						array34[0] = -1167460057;
						array34[1] = 471438991;
						array34[2] = -1336511147;
						array34[3] = -1549417061;
						array34[4] = -1500953314;
						array34[4] = array34[3] ^ 0x6D9ACC7;
						array34[4] ^= 430320051;
						int[] array35 = new int[6];
						array35[0] = -1876649477;
						array35[1] = 2020284579;
						array35[2] = -659239200;
						array35[3] = 159525397;
						array35[4] = 1805223819;
						array35[5] = 829600708;
						array35[5] = array34[2] ^ 0x5A7D53DE;
						array35[2] = array35[3] ^ -866820072;
						array35[0] = array35[5] ^ -686290893;
						int num93 = array35[5] ^ 0x3D993469;
						num2 = ((int)num5 * -127255550) ^ 0xBAC4872 ^ num93;
						continue;
					}
					uint num94 = num4;
					int num95 = 315672853;
					_ = 0;
					for (int num96 = 0; num96 < 1; num96++)
					{
						num95 += -315672845;
					}
					if (num94 == (uint)num95)
					{
						awaiter2.GetResult();
						num2 = 203271762;
						continue;
					}
					uint num97 = num4;
					int num98 = -73556004;
					_ = 0;
					for (int num99 = 0; num99 < 2; num99++)
					{
						num98 = (-1576525609 - 1177635935 - num98) ^ 0xE4DD208;
						num98 = ~(num98 * 1444913621);
					}
					if (num97 == (uint)num98)
					{
					}
					goto end_IL_001a;
				}
				goto IL_0023;
				IL_0968:
				awaiter = _003C_003Eu__1;
				num2 = 1277717525;
				goto IL_0028;
				end_IL_001a:;
			}
			catch (Exception exception)
			{
				while (true)
				{
					int num100 = 1350960255;
					while (true)
					{
						int num3 = num100;
						uint num5;
						uint num4 = (num5 = (uint)(~(((((~(~(num3 * 1822393683)) * -1947297995) ^ -1999937574) - -(-1993454339)) ^ -730245061) + (158919636 + 1161905349 - -2107418084) - --845535154))) % 4;
						uint num101 = num4;
						int num102 = 0;
						_ = 0;
						for (int num103 = 0; num103 < 1; num103++)
						{
							num102 *= -833871997;
						}
						if (num101 == (uint)num102)
						{
							break;
						}
						uint num104 = num4;
						int num105 = 720775145;
						_ = 0;
						for (int num106 = 0; num106 < 2; num106++)
						{
							num105 = -1258449721 - -num105;
							num105 = (num105 ^ -1892832452) * -1044074153;
						}
						if (num104 != (uint)num105)
						{
							uint num107 = num4;
							int num108 = -1879260957;
							_ = 0;
							for (int num109 = 0; num109 < 2; num109++)
							{
								num108 = num108 ^ -1488560132 ^ 0x5EC4F70C;
								num108 = -num108 + -1136554870;
							}
							if (num107 != (uint)num108)
							{
								uint num110 = num4;
								int num111 = -344335056;
								_ = 0;
								for (int num112 = 0; num112 < 2; num112++)
								{
									num111 = ~(num111 * -349049569);
									num111 = ~(2114657925 - num111);
								}
								if (num110 == (uint)num111)
								{
								}
								return;
							}
							_003C_003Et__builder.SetException(exception);
							int[,] array36 = new int[3, 4];
							array36[0, 0] = -17345650;
							array36[0, 1] = 939249373;
							array36[0, 2] = -594927799;
							array36[0, 3] = 269266220;
							array36[1, 0] = -2066842593;
							array36[1, 1] = 1151200630;
							array36[1, 2] = -1665318751;
							array36[1, 3] = 1817781725;
							array36[2, 0] = -2033510871;
							array36[2, 1] = -400068174;
							array36[2, 2] = 939201296;
							array36[2, 3] = -1250542459;
							array36[0, 3] = array36[1, 3] ^ 0x610694D7;
							array36[2, 0] = array36[1, 3] ^ -1177062896;
							array36[1, 0] = array36[1, 1] ^ 0x39C9FE8;
							int num113 = array36[1, 0] ^ 0x2E1A6230;
							num100 = ((int)num5 * -832906754) ^ -231869758 ^ num113;
						}
						else
						{
							_003C_003E1__state = -2;
							int[] array37 = new int[5];
							array37[0] = -1466736014;
							array37[1] = -1091518644;
							array37[2] = 518672940;
							array37[3] = 1738274141;
							array37[4] = -944447164;
							array37[0] = array37[3] ^ 0x75D5D623;
							array37[0] = array37[4] ^ -1301035930;
							int[] array38 = new int[7] { 1254748434, -133084467, 1864431954, -2022671028, 970835167, -1686935449, 1829004948 };
							int[][] array39 = new int[2][] { array37, array38 };
							array38[6] = array39[0][1] ^ -169632785;
							array38[2] = array38[3] ^ 0x77E5B6B4;
							array38[1] = array38[3] ^ 0x207455BE;
							int num114 = array39[1][6] ^ 0x1D25D226;
							num100 = ((int)num5 * -1025771619) ^ -980822499 ^ num114;
						}
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num115 = 1135300314;
				while (true)
				{
					int num3 = num115;
					uint num5;
					uint num4 = (num5 = (uint)(~(((((~(~(num3 * 1822393683)) * -1947297995) ^ -1999937574) - -(-1993454339)) ^ -730245061) + (158919636 + 1161905349 - -2107418084) - --845535154))) % 3;
					uint num116 = num4;
					int num117 = -2;
					_ = 0;
					for (int num118 = 0; num118 < 1; num118++)
					{
						num117 = -num117;
					}
					if (num116 == (uint)num117)
					{
						break;
					}
					uint num119 = num4;
					int num120 = -1405650855;
					_ = 0;
					for (int num121 = 0; num121 < 2; num121++)
					{
						num120 = (1510026614 + -1152846472 - num120) * -662946653;
						num120 = num120 * 794200115 - 319036239;
					}
					if (num119 != (uint)num120)
					{
						uint num122 = num4;
						int num123 = -959632725;
						_ = 0;
						for (int num124 = 0; num124 < 1; num124++)
						{
							num123 -= -959632725;
						}
						if (num122 == (uint)num123)
						{
						}
						return;
					}
					_003C_003Et__builder.SetResult();
					int[] array40 = new int[7];
					array40[0] = -722076521;
					array40[1] = 784986051;
					array40[2] = 304276094;
					array40[3] = 1442558119;
					array40[4] = 2095173093;
					array40[5] = -1887539664;
					array40[6] = -1638405013;
					array40[6] = array40[1] ^ 0x2D3C28DB;
					array40[2] ^= 271648061;
					array40[1] = array40[6] ^ -389256777;
					int[] array41 = new int[6] { 1717816864, 874927204, 833648316, 876607576, 1192706472, -397614957 };
					int[][] array42 = new int[2][] { array40, array41 };
					array41[0] = array42[0][0] ^ -2036916681;
					array41[4] = array41[5] ^ -1291651576;
					array41[5] ^= 927433736;
					int num125 = array42[1][0] ^ 0x6490B988;
					num115 = (int)((num5 * 762708071) ^ 0x6A0B34FE) ^ num125;
				}
			}
		}

		void IAsyncStateMachine.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			this.MoveNext();
		}

		[DebuggerHidden]
		private void SetStateMachine(IAsyncStateMachine stateMachine)
		{
			_003C_003Et__builder.SetStateMachine(stateMachine);
		}

		void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
			this.SetStateMachine(stateMachine);
		}

		static Task<string> _0024_003C_0026_003D_0024_002D_002A_002F(IFilePickerService P_0)
		{
			Task<string> result = default(Task<string>);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 697091333;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-((-490378320 ^ 0x4F8E436) - (~(~(1453534847 * ~(-(1506145165 * 1005965873)) * 801931173 + ~-1861438175) - (num2 * 1078788135 + -((-(-1550857313 + (-1324956721 ^ -61352508)) - ~2141590034 + (349598351 * 968417403 - (0x62388AAD ^ (--713881433 - 1998979908)))) * 66174375 + -(-((663075372 - 677562793) * 1090207951 + (-1961769010 ^ 0x3AA281CE))) * 882156757))) * 2083913191 - 2054643724 - (-587727609 ^ (-393478151 - -1525966447))) * -1883726239))) % 3;
						int num5 = 2;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -(-num5);
							num5 = ~(~num5);
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
							int num9 = 1082147328;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~(~num9);
								num9 = (num9 - ~1641801475) ^ -1891803619;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.PickAssemblyAsync();
						int[] array = new int[7] { 659961781, -986314187, -482984505, 232324157, 436322464, -1839674074, -2139702079 };
						array[2] ^= -430616467;
						array[5] = array[2] ^ 0x6A567AD3;
						array[1] = array[5] ^ 0x6DA5F9A0;
						int[] array2 = new int[6] { -841360056, 355702299, -1780189983, 1704727191, 254419481, 1064734153 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[0] = array3[0][6] ^ 0x33825C8D;
						array2[1] ^= 970416835;
						array2[1] ^= 1948094018;
						int num11 = array3[1][0] ^ 0x10664EDB;
						num = ((int)num4 * -320500452) ^ 0x28571ACC ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static bool _0025_0024_002D_0026_003D_0024_002B_0028(string P_0)
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
					int num = -1248253917;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(((-(-1313621653 * (271909047 * ((1608633679 - -1627201890) * 78652543))) * 732609837 + ((2049215581 + (~(-402975533 ^ -1327712055) + ~(~-1154854229))) ^ -1582725561)) * -859341193 - (num2 - (-(-(2129058853 * -851245168 + ((-849725844 ^ (--86575606 + ~382998706)) * 64304369 + ~-1591377025))) ^ (~(-1038330374 ^ (-(0x4F2565BA ^ ~(--751149835)) - ~(~(-285296774 ^ -1564541059)))) - (-(-894415049 * (-860831651 * (-1426410507 - ~-1222340631))) + (270278086 + (-1286824157 + ((-341209807 ^ -872291710) - ~-246852368) - -(-250409718 ^ -1905128435))) - 797403599))))) * -1656369205))) % 3;
						int num5 = 951621117;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 ^= 0x38B895FF;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -467595041;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -(num7 - ~385653017);
							num7 ^= 0x7272CA77;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1305616628;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 -= 1305616628;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = string.IsNullOrWhiteSpace(P_0);
						int[] array = new int[4];
						array[0] = -1134941094;
						array[1] = -2092571132;
						array[2] = 1457992697;
						array[3] = -810014136;
						array[1] = array[3] ^ 0x2E68A443;
						array[1] = array[2] ^ 0x7D71839B;
						int[] array2 = new int[5];
						array2[0] = 1363937216;
						array2[1] = 2133965630;
						array2[2] = 1679567754;
						array2[3] = -1113811626;
						array2[4] = -1193887666;
						array2[1] = array[0] ^ -242083985;
						array2[4] = array2[3] ^ -2022260151;
						array2[3] = array2[0] ^ 0x2F426A16;
						int num11 = array2[1] ^ 0x38D6B0A9;
						num = ((int)num4 * -2098176919) ^ 0x3F0B7E7E ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static TaskAwaiter _003F_0021_003D_0028_003F_002F_0025_002F(Task P_0)
		{
			TaskAwaiter awaiter = default(TaskAwaiter);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1866278997;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(((~(-(~(-(num2 * -335676501 + (-(~(((-1967192091 + -208415436) * -461644815 + 671098002) * 296903511)) + 85596014 - ((-(~1491861677 + (-2073101665 ^ --1066124607)) * 1213951023) ^ -81782881 ^ (~(~(-891788435 ^ -2021847737)) - -1347153059 - ~(-(~(-(-506644464 * -798947261)))))))))) - (((-614212378 ^ -109711121) - -1825874809) ^ -(~(2038045929 * -344178803)))) - -827514220) ^ -1789378918) * 682071619)) % 3;
						int num5 = -378757646;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 -= -378757646;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 129838082;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 ^= 0x7BD2C03;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 2128323434;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = num9 - ~-614164156 - -1697486087;
								num9 = ~(~num9);
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						awaiter = P_0.GetAwaiter();
						int[] array = new int[5];
						array[0] = -704293898;
						array[1] = 1472042975;
						array[2] = 910555591;
						array[3] = -454985136;
						array[4] = -874633991;
						array[2] = array[3] ^ -918208463;
						array[3] ^= -1424734023;
						array[0] = array[4] ^ 0xD0AE94E;
						int[] array2 = new int[7];
						array2[0] = 228944719;
						array2[1] = 1199357765;
						array2[2] = -2099800366;
						array2[3] = 588828157;
						array2[4] = -793893066;
						array2[5] = 757867436;
						array2[6] = 2004874278;
						array2[5] = array[1] ^ -557653316;
						array2[2] = array2[0] ^ -259336640;
						array2[4] = array2[6] ^ -2071514666;
						array2[3] = array2[1] ^ -187863860;
						int num11 = array2[5] ^ -675527759;
						num = (int)((num4 * 139305955) ^ 0x18566E13) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return awaiter;
		}
	}

	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CLoadAssemblyAsync_003Ed__117 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder _003C_003Et__builder;

		public WorkspaceViewModel _003C_003E4__this;

		public string filePath;

		private TaskAwaiter<AssemblyProfile> _003C_003Eu__1;

		private void MoveNext()
		{
			int num = _003C_003E1__state;
			WorkspaceViewModel workspaceViewModel = _003C_003E4__this;
			try
			{
				try
				{
					if (num != 0)
					{
						goto IL_0029;
					}
					goto IL_1760;
					IL_0029:
					int num2 = -1961843796;
					goto IL_002e;
					IL_002e:
					TaskAwaiter<AssemblyProfile> awaiter = default(TaskAwaiter<AssemblyProfile>);
					AssemblyProfile result = default(AssemblyProfile);
					while (true)
					{
						int num3 = num2;
						uint num5;
						uint num4 = (num5 = (uint)(((~(num3 + (-(~(497865129 * -1810630345 + (0x5B084ABD ^ ((-30847210 * 1252088095) ^ 0x4CC57C0F)) + (-(~(1702485168 * 581693135)) + ((0x1E8BD273 ^ -33384381) - 817426629)))) - (-305469441 * (((-(--642274992 + (1246065757 + -95678092)) - ~(~(-790275246 + 823228650))) ^ (-((0x4073FFD8 ^ 0xE07BBA2) - (-686982004 ^ 0x354FFE5B)) + -(0x6D187D51 ^ 0x4E3A83CD))) - -(-1289645709 * (~-788998087 - (1569995784 - -1125583776) - -348535605 * 239983126 * 768712321))) + (0x3DD4B3 ^ (((-(-453000795) - ((0x6002FC70 ^ -1074191958) + (-504083066 + 229340133))) ^ -(-1531283599 + -1832254355 - -1041016448)) - -562830191 * (-299005059 * -1161644203) - (-1977108335 * (~-180146034 + -1561927433 + -47092239) - (-762894879 ^ 0x3D54F4B0))))))) ^ -(-(~(-(-(~(-1243654115))))))) - (~(-543509903 * -230912481 - (1326839806 + 1413263048) - (1853159109 - -127481477 + (0x55CD1201 ^ -346918941)) + (-(~1500668535) + ((0x120063AA ^ 0x17E4CF6E) + -200142371 * 775563180))) - 1940063569 * -1896600693)) ^ (~(~(~(-1792666580 * -1958599085))) + (-(-2014723376 - (-405694870 - -467724729)) + -(-2017107508 + ~-1063883960))))) % 15;
						uint num6 = num4;
						int num7 = 333527386;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 ^= 0x13E1395A;
						}
						if (num6 == (uint)num7)
						{
							break;
						}
						uint num9 = num4;
						int num10 = 3;
						_ = 0;
						for (int num11 = 0; num11 < 2; num11++)
						{
							num10 = ~num10 ^ 0x6E967868;
							num10 = ~num10;
						}
						if (num9 == (uint)num10)
						{
							awaiter = _005E_0040_003F_0024_005E_0021_005E_0024(workspaceViewModel._assemblyWorkspaceService, filePath, default(CancellationToken)).GetAwaiter();
							int[] array = new int[5];
							array[0] = 617812458;
							array[1] = 1496276804;
							array[2] = -277172118;
							array[3] = 1077477968;
							array[4] = 799680946;
							array[4] = array[1] ^ -487771988;
							array[3] = array[4] ^ 0x5DFE48F9;
							array[2] = array[4] ^ 0x546D6EB2;
							int[] array2 = new int[5] { 881611868, 1325631327, -1045574805, -1326137643, -10586400 };
							int[][] array3 = new int[2][] { array, array2 };
							array2[4] = array3[0][1] ^ -2145195837;
							array2[2] = array2[4] ^ -956854198;
							array2[0] = array2[3] ^ -112041016;
							int num12 = array3[1][4] ^ 0x42382AAF;
							num2 = (int)((num5 * 1901153182) ^ 0xDEF03C74u) ^ num12;
							continue;
						}
						uint num13 = num4;
						int num14 = -2;
						_ = 0;
						for (int num15 = 0; num15 < 1; num15++)
						{
							num14 = ~num14;
						}
						if (num13 == (uint)num14)
						{
							bool ısCompleted = awaiter.IsCompleted;
							int[] array4 = new int[6];
							array4[0] = 1785809808;
							array4[1] = -197218467;
							array4[2] = -1754656696;
							array4[3] = 155125277;
							array4[4] = 554733400;
							array4[5] = 1377478588;
							array4[0] = array4[4] ^ -602208417;
							array4[4] ^= -1356697584;
							int[] array5 = new int[4] { -1201495510, 1093917600, -1993429167, 1623908198 };
							int[][] array6 = new int[2][] { array4, array5 };
							array5[3] = array6[0][5] ^ 0x36EFC67;
							array5[2] = array5[1] ^ -1324809420;
							array5[0] ^= 275776264;
							array5[2] = array5[1] ^ -1347892852;
							int num16 = array6[1][3] ^ -935923270;
							int[] array7 = new int[5];
							array7[0] = 1068844747;
							array7[1] = 2136303691;
							array7[2] = -752849219;
							array7[3] = 2136686659;
							array7[4] = -1821611881;
							array7[0] = array7[2] ^ 0x42D220C2;
							array7[0] = array7[4] ^ 0x504BD986;
							array7[0] = array7[4] ^ -261716268;
							int[] array8 = new int[7];
							array8[0] = -1882634051;
							array8[1] = -1036555553;
							array8[2] = 1591279033;
							array8[3] = 833211104;
							array8[4] = 295418565;
							array8[5] = -543418855;
							array8[6] = -223172175;
							array8[2] = array7[4] ^ 0x4FF6C951;
							array8[4] = array8[2] ^ 0x1B2C2107;
							array8[0] = array8[6] ^ 0x13DC236;
							array8[4] = array8[3] ^ -298055320;
							int num17 = array8[2] ^ -406220573;
							int num18 = ((int)num5 * -1684564191) ^ 0x3BF62E62;
							num16 ^= num18;
							num17 ^= num18;
							int num19;
							int num20;
							if (!ısCompleted)
							{
								num19 = num17;
								num20 = num19;
							}
							else
							{
								num19 = num16;
								num20 = num19;
							}
							num2 = num19 ^ num18;
							continue;
						}
						uint num21 = num4;
						int num22 = 536871189;
						_ = 0;
						for (int num23 = 0; num23 < 2; num23++)
						{
							num22 = ~-1900883021 - num22;
							num22 = (num22 + ~-1543427132) ^ 0x390340AA;
						}
						if (num21 == (uint)num22)
						{
							num = (_003C_003E1__state = 0);
							int[,] array9 = new int[3, 4];
							array9[0, 0] = -749716059;
							array9[0, 1] = -736955234;
							array9[0, 2] = 978080003;
							array9[0, 3] = -786061137;
							array9[1, 0] = 17960139;
							array9[1, 1] = 1841653361;
							array9[1, 2] = 355461237;
							array9[1, 3] = -1613850098;
							array9[2, 0] = 1985096300;
							array9[2, 1] = -414864648;
							array9[2, 2] = 386286059;
							array9[2, 3] = -1828776346;
							array9[0, 1] = array9[1, 0] ^ -998786384;
							array9[1, 1] = array9[1, 2] ^ -288695399;
							array9[1, 0] ^= 1747445067;
							array9[1, 2] = array9[0, 0] ^ -1614377697;
							int num24 = array9[1, 2] ^ 0x2752D4D5;
							num2 = (int)((num5 * 441153877) ^ 0xC3FC43F1u) ^ num24;
							continue;
						}
						uint num25 = num4;
						int num26 = -1048177265;
						_ = 0;
						for (int num27 = 0; num27 < 2; num27++)
						{
							num26 = -num26 ^ -1738554781;
							num26 *= -1610781145;
						}
						if (num25 == (uint)num26)
						{
							_003C_003Eu__1 = awaiter;
							int[,] array10 = new int[4, 4];
							array10[0, 0] = 329376951;
							array10[0, 1] = -38853324;
							array10[0, 2] = -1321471594;
							array10[0, 3] = -2091930563;
							array10[1, 0] = -77920455;
							array10[1, 1] = 1664131873;
							array10[1, 2] = 130151266;
							array10[1, 3] = 1691974892;
							array10[2, 0] = 1364411857;
							array10[2, 1] = -1638547588;
							array10[2, 2] = -1629364788;
							array10[2, 3] = 977647295;
							array10[3, 0] = 1504197883;
							array10[3, 1] = -1551311502;
							array10[3, 2] = -338279441;
							array10[3, 3] = -1830721379;
							array10[3, 1] = array10[2, 3] ^ -1154062084;
							array10[2, 2] = array10[3, 0] ^ 0x45FB10C5;
							array10[1, 2] = array10[3, 3] ^ 0x338920F2;
							int num28 = array10[1, 2] ^ -1658725921;
							num2 = ((int)num5 * -456832610) ^ -783940894 ^ num28;
							continue;
						}
						uint num29 = num4;
						int num30 = 1682930184;
						_ = 0;
						for (int num31 = 0; num31 < 2; num31++)
						{
							num30 = -num30 - 1459254215;
							num30 = (699248607 * -1181572699 - num30) * 701198465;
						}
						if (num29 == (uint)num30)
						{
							_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
							int[] array11 = new int[7] { 949071803, 664660184, -2108698292, -105347793, -1988450391, 756227473, 1005567963 };
							array11[3] ^= -1954884932;
							array11[1] = array11[4] ^ 0x72B8B3A5;
							array11[1] = array11[5] ^ 0x49C207A0;
							int[] array12 = new int[5];
							array12[0] = -831049268;
							array12[1] = 2013113674;
							array12[2] = 1936872934;
							array12[3] = 1324802027;
							array12[4] = -679525978;
							array12[0] = array11[5] ^ -1743249626;
							array12[3] ^= -1349405501;
							array12[4] = array12[2] ^ -1407899844;
							array12[4] = array12[3] ^ 0x1448061;
							int num32 = array12[0] ^ -377732848;
							num2 = ((int)num5 * -2078771300) ^ 0x26360458 ^ num32;
							continue;
						}
						uint num33 = num4;
						int num34 = -11;
						_ = 0;
						for (int num35 = 0; num35 < 1; num35++)
						{
							num34 = -num34;
						}
						if (num33 == (uint)num34)
						{
							return;
						}
						uint num36 = num4;
						int num37 = -335743983;
						_ = 0;
						for (int num38 = 0; num38 < 1; num38++)
						{
							num37 -= -335743997;
						}
						if (num36 == (uint)num37)
						{
							goto IL_1760;
						}
						uint num39 = num4;
						int num40 = -787815204;
						_ = 0;
						for (int num41 = 0; num41 < 2; num41++)
						{
							num40 = 118056972 - -num40;
							num40 = ~(num40 * -1199327479);
						}
						if (num39 == (uint)num40)
						{
							_003C_003Eu__1 = default(TaskAwaiter<AssemblyProfile>);
							int[] array13 = new int[6];
							array13[0] = 900603532;
							array13[1] = -817227463;
							array13[2] = -478314785;
							array13[3] = -419751593;
							array13[4] = 40465380;
							array13[5] = 1735027158;
							array13[2] = array13[5] ^ -1905584687;
							array13[2] = array13[4] ^ -508792082;
							array13[5] = array13[0] ^ -664354829;
							int[] array14 = new int[5] { -1030733683, -1382439864, 1452179115, 60947383, 1398710973 };
							int[][] array15 = new int[2][] { array13, array14 };
							array14[2] = array15[0][1] ^ -1786511439;
							array14[0] ^= -1654726758;
							array14[1] = array14[4] ^ 0x76632074;
							array14[3] = array14[2] ^ 0xB5C82BF;
							int num42 = array15[1][2] ^ 0x16B615BC;
							num2 = ((int)num5 * -176632247) ^ 0x20BACDEE ^ num42;
							continue;
						}
						uint num43 = num4;
						int num44 = -369203451;
						_ = 0;
						for (int num45 = 0; num45 < 1; num45++)
						{
							num44 -= -369203461;
						}
						if (num43 == (uint)num44)
						{
							num = (_003C_003E1__state = -1);
							int[] array16 = new int[7];
							array16[0] = -892199380;
							array16[1] = 121715725;
							array16[2] = 1279836741;
							array16[3] = 960187413;
							array16[4] = 2088351110;
							array16[5] = -1170822451;
							array16[6] = 1373876992;
							array16[4] = array16[0] ^ -841231480;
							array16[4] = array16[5] ^ 0x577E74F5;
							int[] array17 = new int[5];
							array17[0] = 1222735942;
							array17[1] = 850468615;
							array17[2] = -802094877;
							array17[3] = 2074046640;
							array17[4] = 1212535675;
							array17[0] = array16[0] ^ -107727679;
							array17[2] ^= -1883831829;
							array17[2] ^= -1198256498;
							int num46 = array17[0] ^ -1442545524;
							num2 = (int)((num5 * 1871083200) ^ 0x83465280u) ^ num46;
							continue;
						}
						uint num47 = num4;
						int num48 = 441999377;
						_ = 0;
						for (int num49 = 0; num49 < 2; num49++)
						{
							num48 = ~(-num48);
							num48 = ~num48 * -1765876747;
						}
						if (num47 == (uint)num48)
						{
							result = awaiter.GetResult();
							num2 = -1436757092;
							continue;
						}
						uint num50 = num4;
						int num51 = -497489803;
						_ = 0;
						for (int num52 = 0; num52 < 1; num52++)
						{
							num51 ^= -497489801;
						}
						if (num50 == (uint)num51)
						{
							workspaceViewModel.ApplyProfile(result);
							int[] array18 = new int[7];
							array18[0] = -1216400739;
							array18[1] = 544867743;
							array18[2] = 1777490150;
							array18[3] = 2104511890;
							array18[4] = -679064106;
							array18[5] = -205280444;
							array18[6] = 1741351231;
							array18[3] = array18[5] ^ 0x26679E8D;
							array18[2] = array18[1] ^ 0x31067955;
							array18[3] = array18[6] ^ 0x641A4B39;
							int[] array19 = new int[6];
							array19[0] = 2029046714;
							array19[1] = 841079349;
							array19[2] = -1338522200;
							array19[3] = -993301884;
							array19[4] = 1556521601;
							array19[5] = -1379508269;
							array19[4] = array18[0] ^ 0x7637EC8;
							array19[1] = array19[4] ^ 0x587216B;
							array19[0] = array19[2] ^ 0x7BFC6C6C;
							int num53 = array19[4] ^ 0x12FC168A;
							num2 = ((int)num5 * -1040066593) ^ -1242372438 ^ num53;
							continue;
						}
						uint num54 = num4;
						int num55 = 8;
						_ = 0;
						for (int num56 = 0; num56 < 2; num56++)
						{
							num55 = num55 - (0x52C44224 ^ 0xB0CBA39) - -1677624611;
							num55 = ~(num55 + (1431549910 - -1133535635));
						}
						if (num54 == (uint)num55)
						{
							workspaceViewModel.SetStatus(_002F_002F_002B_003C_002A_0024_0026_0023(workspaceViewModel._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0xAC4C ^ 0xADC3))], new object[2]
							{
								_003F_003E_005E_005E_003F_002A_003C_0023(result),
								_0029_003F_0028_0021_005E_002F_003E_(result)
							}), SeverityLevel.Success);
							int[] array20 = new int[7];
							array20[0] = 1554722668;
							array20[1] = 1009143870;
							array20[2] = -686156418;
							array20[3] = -402416789;
							array20[4] = 733889376;
							array20[5] = 1399906553;
							array20[6] = -305191148;
							array20[1] = array20[4] ^ 0x44D5057A;
							array20[1] = array20[5] ^ 0x6F355D2E;
							int[] array21 = new int[6] { -373343050, -24105835, 760364792, -1582473612, 1841114868, 1803124789 };
							int[][] array22 = new int[2][] { array20, array21 };
							array21[4] = array22[0][6] ^ 0x6B8135CE;
							array21[3] ^= 141315694;
							array21[2] = array21[3] ^ 0x58346A19;
							array21[0] = array21[5] ^ 0x1590EB4B;
							int num57 = array22[1][4] ^ -757773944;
							num2 = (int)((num5 * 1743460980) ^ 0x91AF104Cu) ^ num57;
							continue;
						}
						uint num58 = num4;
						int num59 = 413377433;
						_ = 0;
						for (int num60 = 0; num60 < 2; num60++)
						{
							num59 = 1940794937 - -num59;
							num59 = -(~num59);
						}
						if (num58 == (uint)num59)
						{
							workspaceViewModel.AppViewModel.AddActivity(_002F_002F_002B_003C_002A_0024_0026_0023(workspaceViewModel._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xBF18 ^ 0xBE88], new object[1] { _003F_003E_005E_005E_003F_002A_003C_0023(result) }), SeverityLevel.Success);
							int[,] array23 = new int[4, 3];
							array23[0, 0] = -1283354732;
							array23[0, 1] = -1829710314;
							array23[0, 2] = -1450085646;
							array23[1, 0] = 1082733753;
							array23[1, 1] = 1450810185;
							array23[1, 2] = 199297016;
							array23[2, 0] = -1095157935;
							array23[2, 1] = -1772741917;
							array23[2, 2] = -807690702;
							array23[3, 0] = -1950812467;
							array23[3, 1] = -1008827058;
							array23[3, 2] = -88935440;
							array23[0, 0] = array23[1, 1] ^ -1197569604;
							array23[1, 1] = array23[0, 1] ^ 0x4BFC3688;
							array23[2, 2] = array23[1, 1] ^ 0x5E8C7222;
							array23[3, 0] = array23[1, 0] ^ 0x1696F090;
							int num61 = array23[3, 0] ^ 0x6FF7EEFC;
							num2 = (int)((num5 * 1616004808) ^ 0x13FA43E0) ^ num61;
							continue;
						}
						uint num62 = num4;
						int num63 = -184004799;
						_ = 0;
						for (int num64 = 0; num64 < 1; num64++)
						{
							num63 -= -184004805;
						}
						if (num62 == (uint)num63)
						{
						}
						goto end_IL_0020;
					}
					goto IL_0029;
					IL_1760:
					awaiter = _003C_003Eu__1;
					num2 = -1573252428;
					goto IL_002e;
					end_IL_0020:;
				}
				catch (Exception ex)
				{
					while (true)
					{
						int num65 = 1685235925;
						while (true)
						{
							int num3 = num65;
							uint num5;
							uint num4 = (num5 = (uint)(((~(num3 + (-(~(497865129 * -1810630345 + (0x5B084ABD ^ ((-30847210 * 1252088095) ^ 0x4CC57C0F)) + (-(~(1702485168 * 581693135)) + ((0x1E8BD273 ^ -33384381) - 817426629)))) - (-305469441 * (((-(--642274992 + (1246065757 + -95678092)) - ~(~(-790275246 + 823228650))) ^ (-((0x4073FFD8 ^ 0xE07BBA2) - (-686982004 ^ 0x354FFE5B)) + -(0x6D187D51 ^ 0x4E3A83CD))) - -(-1289645709 * (~-788998087 - (1569995784 - -1125583776) - -348535605 * 239983126 * 768712321))) + (0x3DD4B3 ^ (((-(-453000795) - ((0x6002FC70 ^ -1074191958) + (-504083066 + 229340133))) ^ -(-1531283599 + -1832254355 - -1041016448)) - -562830191 * (-299005059 * -1161644203) - (-1977108335 * (~-180146034 + -1561927433 + -47092239) - (-762894879 ^ 0x3D54F4B0))))))) ^ -(-(~(-(-(~(-1243654115))))))) - (~(-543509903 * -230912481 - (1326839806 + 1413263048) - (1853159109 - -127481477 + (0x55CD1201 ^ -346918941)) + (-(~1500668535) + ((0x120063AA ^ 0x17E4CF6E) + -200142371 * 775563180))) - 1940063569 * -1896600693)) ^ (~(~(~(-1792666580 * -1958599085))) + (-(-2014723376 - (-405694870 - -467724729)) + -(-2017107508 + ~-1063883960))))) % 5;
							uint num66 = num4;
							int num67 = -1;
							_ = 0;
							for (int num68 = 0; num68 < 1; num68++)
							{
								num67 = ~num67;
							}
							if (num66 == (uint)num67)
							{
								break;
							}
							uint num69 = num4;
							int num70 = -47111663;
							_ = 0;
							for (int num71 = 0; num71 < 1; num71++)
							{
								num70 ^= -47111664;
							}
							if (num69 != (uint)num70)
							{
								uint num72 = num4;
								int num73 = -4;
								_ = 0;
								for (int num74 = 0; num74 < 1; num74++)
								{
									num73 = -num73;
								}
								if (num72 != (uint)num73)
								{
									uint num75 = num4;
									int num76 = 5;
									_ = 0;
									for (int num77 = 0; num77 < 2; num77++)
									{
										num76 ^= -2103625095;
										num76 = -num76 ^ 0x325FF022;
									}
									if (num75 != (uint)num76)
									{
										uint num78 = num4;
										int num79 = 354116634;
										_ = 0;
										for (int num80 = 0; num80 < 1; num80++)
										{
											num79 *= -107287355;
										}
										if (num78 == (uint)num79)
										{
										}
										goto end_IL_1fdd;
									}
									workspaceViewModel.AppViewModel.AddActivity(_002D_002F_0029_002B__003E_0029_0040(workspaceViewModel._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xBBC ^ 0xA2E]), SeverityLevel.Error);
									int[] array24 = new int[4];
									array24[0] = -739539089;
									array24[1] = 155789361;
									array24[2] = 575284495;
									array24[3] = 81447135;
									array24[1] = array24[0] ^ 0x36A0116C;
									array24[0] ^= -59157062;
									array24[1] = array24[0] ^ -904073922;
									int[] array25 = new int[7] { -1116321820, 2115097659, 1302408567, 1263511058, 1171242488, -1627072630, 1294234779 };
									int[][] array26 = new int[2][] { array24, array25 };
									array25[5] = array26[0][3] ^ 0x64B53C44;
									array25[4] ^= -1671171896;
									array25[2] = array25[1] ^ 0x4C445070;
									int num81 = array26[1][5] ^ -939737049;
									num65 = (int)((num5 * 1491684847) ^ 0xEDBF2A2Fu) ^ num81;
								}
								else
								{
									workspaceViewModel.SetStatus(_002F_002F_002B_003C_002A_0024_0026_0023(workspaceViewModel._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x9ED ^ 0x87C], new object[1] { @_0028_002F_0028_0028_0025_002A_0021(ex) }), SeverityLevel.Error);
									int[,] array27 = new int[3, 4];
									array27[0, 0] = 1877505969;
									array27[0, 1] = 434014613;
									array27[0, 2] = -1008753659;
									array27[0, 3] = 123208539;
									array27[1, 0] = -1200038555;
									array27[1, 1] = 304382420;
									array27[1, 2] = 293980070;
									array27[1, 3] = -154115137;
									array27[2, 0] = -722397229;
									array27[2, 1] = -1875721099;
									array27[2, 2] = 1005108605;
									array27[2, 3] = 267626479;
									array27[2, 2] = array27[0, 3] ^ 0x6B4E7F78;
									array27[0, 0] = array27[1, 3] ^ 0x56C51E7A;
									array27[1, 1] = array27[1, 0] ^ -1362555095;
									array27[1, 3] = array27[0, 3] ^ -318757781;
									int num82 = array27[1, 3] ^ -1361631815;
									num65 = (int)((num5 * 40575206) ^ 0xD5FF03DCu) ^ num82;
								}
							}
							else
							{
								workspaceViewModel.HasLoadedAssembly = false;
								int[] array28 = new int[6];
								array28[0] = -423833627;
								array28[1] = -1873513554;
								array28[2] = 1463286248;
								array28[3] = -64200669;
								array28[4] = 212770910;
								array28[5] = -756949408;
								array28[3] = array28[5] ^ -375603720;
								array28[3] = array28[0] ^ 0x20B86643;
								int[] array29 = new int[6];
								array29[0] = 1516130578;
								array29[1] = 1888812696;
								array29[2] = -116720296;
								array29[3] = -1050468387;
								array29[4] = -85027287;
								array29[5] = 251544712;
								array29[3] = array28[5] ^ 0x47B757DD;
								array29[5] = array29[2] ^ 0x3084E553;
								array29[4] = array29[2] ^ -1651967498;
								array29[2] = array29[5] ^ 0x39E081ED;
								int num83 = array29[3] ^ -349214483;
								num65 = ((int)num5 * -1895014002) ^ -1325440874 ^ num83;
							}
						}
						continue;
						end_IL_1fdd:
						break;
					}
				}
			}
			catch (Exception exception)
			{
				while (true)
				{
					int num84 = 1252269531;
					while (true)
					{
						int num3 = num84;
						uint num5;
						uint num4 = (num5 = (uint)(((~(num3 + (-(~(497865129 * -1810630345 + (0x5B084ABD ^ ((-30847210 * 1252088095) ^ 0x4CC57C0F)) + (-(~(1702485168 * 581693135)) + ((0x1E8BD273 ^ -33384381) - 817426629)))) - (-305469441 * (((-(--642274992 + (1246065757 + -95678092)) - ~(~(-790275246 + 823228650))) ^ (-((0x4073FFD8 ^ 0xE07BBA2) - (-686982004 ^ 0x354FFE5B)) + -(0x6D187D51 ^ 0x4E3A83CD))) - -(-1289645709 * (~-788998087 - (1569995784 - -1125583776) - -348535605 * 239983126 * 768712321))) + (0x3DD4B3 ^ (((-(-453000795) - ((0x6002FC70 ^ -1074191958) + (-504083066 + 229340133))) ^ -(-1531283599 + -1832254355 - -1041016448)) - -562830191 * (-299005059 * -1161644203) - (-1977108335 * (~-180146034 + -1561927433 + -47092239) - (-762894879 ^ 0x3D54F4B0))))))) ^ -(-(~(-(-(~(-1243654115))))))) - (~(-543509903 * -230912481 - (1326839806 + 1413263048) - (1853159109 - -127481477 + (0x55CD1201 ^ -346918941)) + (-(~1500668535) + ((0x120063AA ^ 0x17E4CF6E) + -200142371 * 775563180))) - 1940063569 * -1896600693)) ^ (~(~(~(-1792666580 * -1958599085))) + (-(-2014723376 - (-405694870 - -467724729)) + -(-2017107508 + ~-1063883960))))) % 4;
						uint num85 = num4;
						int num86 = -975036306;
						_ = 0;
						for (int num87 = 0; num87 < 2; num87++)
						{
							num86 = (num86 + ~1825118015) * -1881352279;
							num86 = -num86 ^ -8483662;
						}
						if (num85 == (uint)num86)
						{
							break;
						}
						uint num88 = num4;
						int num89 = 981001166;
						_ = 0;
						for (int num90 = 0; num90 < 1; num90++)
						{
							num89 ^= 0x3A78E3CD;
						}
						if (num88 != (uint)num89)
						{
							uint num91 = num4;
							int num92 = 0;
							_ = 0;
							for (int num93 = 0; num93 < 1; num93++)
							{
								num92 = -num92;
							}
							if (num91 != (uint)num92)
							{
								uint num94 = num4;
								int num95 = 1101861444;
								_ = 0;
								for (int num96 = 0; num96 < 1; num96++)
								{
									num95 += -1101861443;
								}
								if (num94 == (uint)num95)
								{
								}
								return;
							}
							_003C_003Et__builder.SetException(exception);
							int[,] array30 = new int[3, 3];
							array30[0, 0] = -955094609;
							array30[0, 1] = -466244298;
							array30[0, 2] = 938684366;
							array30[1, 0] = 901801212;
							array30[1, 1] = -1258129346;
							array30[1, 2] = -81747487;
							array30[2, 0] = 880148526;
							array30[2, 1] = -705650161;
							array30[2, 2] = -3477509;
							array30[2, 0] = array30[2, 2] ^ -1433953708;
							array30[1, 1] = array30[2, 0] ^ -1719072447;
							array30[0, 2] = array30[2, 1] ^ -322742401;
							array30[2, 0] = array30[1, 2] ^ -1632753113;
							int num97 = array30[2, 0] ^ 0x33916C3B;
							num84 = (int)((num5 * 866230107) ^ 0x6C7D2740) ^ num97;
						}
						else
						{
							_003C_003E1__state = -2;
							int[] array31 = new int[5];
							array31[0] = 406769914;
							array31[1] = -1520994785;
							array31[2] = -666189905;
							array31[3] = 602081037;
							array31[4] = -1867631894;
							array31[3] = array31[2] ^ -1571810108;
							array31[3] ^= -1601496918;
							array31[3] = array31[2] ^ -223068436;
							int[] array32 = new int[7];
							array32[0] = -2028305342;
							array32[1] = -1539564001;
							array32[2] = 967652704;
							array32[3] = 970633407;
							array32[4] = -352890396;
							array32[5] = 2058516155;
							array32[6] = -579536349;
							array32[4] = array31[2] ^ -1933979973;
							array32[0] = array32[2] ^ 0xB19729D;
							array32[6] = array32[4] ^ 0x6428972;
							array32[3] ^= 1965853120;
							int num98 = array32[4] ^ -1384896110;
							num84 = (int)((num5 * 849187811) ^ 0x199DB8E1) ^ num98;
						}
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num99 = -1843230199;
				while (true)
				{
					int num3 = num99;
					uint num5;
					uint num4 = (num5 = (uint)(((~(num3 + (-(~(497865129 * -1810630345 + (0x5B084ABD ^ ((-30847210 * 1252088095) ^ 0x4CC57C0F)) + (-(~(1702485168 * 581693135)) + ((0x1E8BD273 ^ -33384381) - 817426629)))) - (-305469441 * (((-(--642274992 + (1246065757 + -95678092)) - ~(~(-790275246 + 823228650))) ^ (-((0x4073FFD8 ^ 0xE07BBA2) - (-686982004 ^ 0x354FFE5B)) + -(0x6D187D51 ^ 0x4E3A83CD))) - -(-1289645709 * (~-788998087 - (1569995784 - -1125583776) - -348535605 * 239983126 * 768712321))) + (0x3DD4B3 ^ (((-(-453000795) - ((0x6002FC70 ^ -1074191958) + (-504083066 + 229340133))) ^ -(-1531283599 + -1832254355 - -1041016448)) - -562830191 * (-299005059 * -1161644203) - (-1977108335 * (~-180146034 + -1561927433 + -47092239) - (-762894879 ^ 0x3D54F4B0))))))) ^ -(-(~(-(-(~(-1243654115))))))) - (~(-543509903 * -230912481 - (1326839806 + 1413263048) - (1853159109 - -127481477 + (0x55CD1201 ^ -346918941)) + (-(~1500668535) + ((0x120063AA ^ 0x17E4CF6E) + -200142371 * 775563180))) - 1940063569 * -1896600693)) ^ (~(~(~(-1792666580 * -1958599085))) + (-(-2014723376 - (-405694870 - -467724729)) + -(-2017107508 + ~-1063883960))))) % 3;
					uint num100 = num4;
					int num101 = -101949762;
					_ = 0;
					for (int num102 = 0; num102 < 2; num102++)
					{
						num101 = num101 * 1142645261 - -209820544;
						num101 = num101 - -66089285 * -657499596 + -363101525;
					}
					if (num100 == (uint)num101)
					{
						break;
					}
					uint num103 = num4;
					int num104 = -449748785;
					_ = 0;
					for (int num105 = 0; num105 < 1; num105++)
					{
						num104 -= -449748786;
					}
					if (num103 != (uint)num104)
					{
						uint num106 = num4;
						int num107 = -1781801978;
						_ = 0;
						for (int num108 = 0; num108 < 2; num108++)
						{
							num107 = num107 ^ -658551775 ^ -1223110661;
							num107 = num107 * 457405689 * 1240724663;
						}
						if (num106 == (uint)num107)
						{
						}
						return;
					}
					_003C_003Et__builder.SetResult();
					int[] array33 = new int[4];
					array33[0] = 1761592862;
					array33[1] = -1950114320;
					array33[2] = 159330606;
					array33[3] = 1904968091;
					array33[3] = array33[0] ^ 0x70927E5F;
					array33[0] = array33[2] ^ 0x6C6B5C66;
					int[] array34 = new int[6];
					array34[0] = -422706740;
					array34[1] = 1140091948;
					array34[2] = -1186374106;
					array34[3] = -2037999606;
					array34[4] = 1362730328;
					array34[5] = 107813501;
					array34[4] = array33[2] ^ 0x673B7DF6;
					array34[3] = array34[1] ^ -1577082642;
					array34[3] = array34[2] ^ -495921247;
					int num109 = array34[4] ^ -265695261;
					num99 = ((int)num5 * -712451604) ^ 0x3483A8EC ^ num109;
				}
			}
		}

		void IAsyncStateMachine.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			this.MoveNext();
		}

		[DebuggerHidden]
		private void SetStateMachine(IAsyncStateMachine stateMachine)
		{
			_003C_003Et__builder.SetStateMachine(stateMachine);
		}

		void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
			this.SetStateMachine(stateMachine);
		}

		static Task<AssemblyProfile> _005E_0040_003F_0024_005E_0021_005E_0024(IAssemblyWorkspaceService P_0, string P_1, CancellationToken P_2)
		{
			Task<AssemblyProfile> result = default(Task<AssemblyProfile>);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 850243086;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(~(num2 * 687802543) - ~(-2016904011 * -295781992)) + (-65032748 - (0x410B5C0B ^ 0x484D13F7)) * 1245675423)) % 3;
						int num5 = 311508934;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = ~num5 - 1772852708;
							num5 = (num5 ^ --249296498) - -489671361;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -1316044941;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 ^= -1316044942;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 0;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 *= -1448008415;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.LoadAssemblyAsync(P_1, P_2);
						int[] array = new int[5];
						array[0] = -882619491;
						array[1] = -831108531;
						array[2] = -1595999262;
						array[3] = 140532091;
						array[4] = 1403854404;
						array[2] = array[3] ^ -1471000815;
						array[1] = array[0] ^ 0x17DAC549;
						array[0] ^= -117341740;
						int[] array2 = new int[7];
						array2[0] = 1767131856;
						array2[1] = 1814461337;
						array2[2] = -520629664;
						array2[3] = -1055641383;
						array2[4] = 247259444;
						array2[5] = -1088695867;
						array2[6] = -1538777874;
						array2[6] = array[3] ^ 0x762CA57B;
						array2[4] = array2[5] ^ -876876812;
						array2[0] = array2[5] ^ -1351154112;
						array2[2] = array2[1] ^ 0x4C7926E8;
						int num11 = array2[6] ^ 0x4FBF5DA5;
						num = ((int)num4 * -598483819) ^ -957730198 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static string _003F_003E_005E_005E_003F_002A_003C_0023(AssemblyProfile P_0)
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
					int num = 1825205584;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(-(-(-(-(~(0x476EA844 ^ 0x7668FF50) - (0x33DD1E92 ^ (-(-(1376765847 + -675887355)) ^ -(-(~1992616557)) ^ (-1509429534 ^ -(~(-518661480)))))) - (~(767669927 * ((1128654501 - (2047026356 + -1179274626 + -1300135543) + -(~-35952577 - 432693507 * -1159970590)) * 66131709) + (-2111264890 * 1022842625 + (-(-1382260833 + 1085278647 * ~-2032306523) + ~(-1672414539 * ~(1960975789 * -935934936)))) - ((-(0x5E3213C3 ^ -548450568) ^ (~(~(--1942410173)) ^ -327841560)) - (~2042787158 + -(-(1824423717 * 715536952)) * 1382562425) - (--1278285635 + ~(-(~(-(~1390957471))))))) - num2))))) + ~(-442016248 + 165873265 * -841742895))) % 3;
						int num5 = 1687367630;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 *= 2024901591;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -62653467;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = num7 ^ 0xE8509E9 ^ 0x2FE1DEE8;
							num7 = 96633613 - (num7 ^ -888698474);
						}
						if (num3 != (uint)num7)
						{
							int num9 = 0;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 -= 0x5FDCECAB ^ -2012912677;
								num9 = ~(num9 - (-38491089 + -119290931));
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						fileName = P_0.FileName;
						int[] array = new int[5];
						array[0] = 394951861;
						array[1] = 1408677549;
						array[2] = -480029976;
						array[3] = -604411078;
						array[4] = 1717643837;
						array[4] = array[0] ^ -1755398648;
						array[3] = array[4] ^ 0xDAC84DD;
						array[0] = array[4] ^ 0x215DA874;
						int[] array2 = new int[5];
						array2[0] = -975081867;
						array2[1] = -1850869233;
						array2[2] = -482281888;
						array2[3] = 1147335391;
						array2[4] = 963879324;
						array2[2] = array[1] ^ -1156455751;
						array2[1] ^= -1618149787;
						array2[1] = array2[0] ^ 0x550122AD;
						array2[1] = array2[3] ^ 0x5A105C07;
						int num11 = array2[2] ^ -1809458542;
						num = (int)((num4 * 1677488034) ^ 0x2731D124) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return fileName;
		}

		static string _0029_003F_0028_0021_005E_002F_003E_(AssemblyProfile P_0)
		{
			string fileSizeDisplay = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 1667105468;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((889909299 - -(-(-(-(-(~(-(-(~(158107063 * ~-596682507 - (-160734960 ^ 0x50DA4417)))) + ((-(~(-1044213241 * (-622762435 - 265895448))) - ((-1080987246 ^ -687348135) * 570766275 + -(~(--1613028322)))) ^ -(0x3A7AE05A ^ -1496895251)))) - num2))) ^ (~(-(~945830815) ^ -1183372711) - -(~(1498148056 * -2103481955 + ~-1680981657))) ^ -643307982 ^ 0x1F921819)) * -892799473)) % 3;
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
							int num9 = 2;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = num9 + -626869345 - -1457226474;
								num9 = ~num9 + -1642243663;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						fileSizeDisplay = P_0.FileSizeDisplay;
						int[] array = new int[7];
						array[0] = 1810178742;
						array[1] = -1622260437;
						array[2] = -1714710696;
						array[3] = -1401775113;
						array[4] = 1480656026;
						array[5] = 1291330359;
						array[6] = -1865083430;
						array[1] = array[4] ^ -2129142953;
						array[0] = array[4] ^ 0xBF64E40;
						int[] array2 = new int[7];
						array2[0] = 1663485710;
						array2[1] = 634743456;
						array2[2] = 265105792;
						array2[3] = 2017854250;
						array2[4] = 1445303849;
						array2[5] = -1203384027;
						array2[6] = 231785039;
						array2[4] = array[3] ^ -527201935;
						array2[1] = array2[0] ^ -423707646;
						array2[0] = array2[6] ^ 0x180B2677;
						array2[5] = array2[3] ^ -213707205;
						int num11 = array2[4] ^ 0x39F0F818;
						num = (int)((num4 * 2137572929) ^ 0xEAB00531u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return fileSizeDisplay;
		}

		static string _002F_002F_002B_003C_002A_0024_0026_0023(IStringResourceService P_0, string P_1, object[] P_2)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				return P_0.GetString(P_1, P_2);
			}
		}

		static string @_0028_002F_0028_0028_0025_002A_0021(Exception P_0)
		{
			string message = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 815196329;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(((-(-562006075 * 203434901) - (-639367272 ^ (-(-1447223141 * -52587391) + (-1238339887 + 218502289 + 644420988) - (--388447837 ^ -630286809) * 936122317)) + (-1865584759 * (1456405217 * (1238823153 - 1487428766) * 364504297 + -1555059971) - 2137313197 * --1703999849)) * 644415273 - (num2 - (~(-1889265751 * 289209343) - (~(~(~(1457595611 * 175289372 + 229198054 + (--1102660524 + (0x364B3655 ^ -1437969451)))) - (~(0x7CBFE474 ^ 0x631F42AB) - 503977342 - -986722827 - ~(1497366524 * -1985080155 - -1896418429 + (-1559607010 + -1305741034 - (569256854 + 498855166))))) + ~(-1697801530 ^ 0x4D9B2CA6))))) ^ -((~(--1622572373) ^ (-(1655713977 + -445263124) ^ (-1766221038 ^ -2110049894))) * 719717039 - -(-(-1610396943 - -1898288725) - (--507573416 - -1664584675) - 1533194779)) ^ (~-2069276235 - 1333010401 * ((-(-460711905 * -336161047) - 14528522) ^ 0x68C30811)) ^ 0x39B9A24A))) % 3;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = 405605718 - 410285410 - num5 - -22217139;
							num5 = -(-num5);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1756672445;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -(num7 - (-896597835 ^ 0x6B1B140B));
							num7 = -(num7 * -355387175);
						}
						if (num3 != (uint)num7)
						{
							int num9 = 274438;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = (num9 - 1773737425 * -557424193) ^ 0x16CE5FA3;
								num9 = -num9;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						message = P_0.Message;
						int[] array = new int[7];
						array[0] = -282973271;
						array[1] = -937180829;
						array[2] = -966945767;
						array[3] = -1347682165;
						array[4] = -494060990;
						array[5] = 310220734;
						array[6] = -1617085626;
						array[2] = array[3] ^ -1360386601;
						array[5] = array[1] ^ 0x33FB4B66;
						array[3] = array[4] ^ -2111062475;
						int[] array2 = new int[6];
						array2[0] = -964252305;
						array2[1] = 197572050;
						array2[2] = -1256392334;
						array2[3] = -684617782;
						array2[4] = 1383843861;
						array2[5] = 900493174;
						array2[5] = array[4] ^ 0x7F557DC;
						array2[1] = array2[0] ^ 0x49FBC1E8;
						array2[4] = array2[5] ^ -1122420590;
						array2[2] ^= 232694111;
						int num11 = array2[5] ^ 0x19035A28;
						num = ((int)num4 * -404130760) ^ -2143905968 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return message;
		}

		static string _002D_002F_0029_002B__003E_0029_0040(IStringResourceService P_0, string P_1)
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
					int num = 542478372;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(num2 ^ (-(-(((-1345510825 - (687366531 + -5698636)) ^ (--1596087803 - ~-1375527120)) - -(-1400024005 * -1223802041 + (1262963437 - -2856632)))) * -1510904571 - -(0x4B77D97F ^ ((-1949056247 * 235771867 - (797460923 + 314762662) + (--671339276 + --1916411938)) * -1624757663 * 918787503)) - (((-4799613 * (-(-854319871 ^ -1823672209) - (-419643397 * (-382001191 ^ --558887745) - ((0x59FE815D ^ 0x140CCD10) - -(-1607327050))))) ^ -((1193119818 - 1845435078) * 1386559629 + ~(-21434464 + 1112659109) - -1259756577 * (461581605 + -163678300) * 2002384793 + (--746415302 - -545048775 + -(-2005710840 ^ -1892489554)))) - -((~1971509023 + 1984175618 + (0x87B9354 ^ -(-1859472353 + 1798571553)) + -(1099446266 * 341117367)) ^ ~(0x29161E4E ^ (-(-669032082 ^ 0x22017DF1) + (-1060460019 * -1968600789 + ~1999510395)))))) ^ -(-(~((-107918284 ^ -237360400) + ((-(0x76F7EDAB ^ -782600306) ^ 0x147B3C9C) + (-267282614 + --1298197261 + (-696541662 ^ -1885150705)))))) ^ 0x2D11960A) + --132677835 - 1317272575)) % 3;
						int num5 = -641242178;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = (-353167930 - num5) * -610823887;
							num5 = ~(num5 - -147858928);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 406911257;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = num7 - (-69273630 ^ -664903265) - 246281595;
							num7 = (num7 - --1597885952) * 915652309;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1383149254;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 -= -1383149256;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.GetString(P_1);
						int[,] array = new int[3, 4];
						array[0, 0] = 2029305066;
						array[0, 1] = 2117190040;
						array[0, 2] = -178964390;
						array[0, 3] = -486822501;
						array[1, 0] = -1275273606;
						array[1, 1] = 450414566;
						array[1, 2] = -908018089;
						array[1, 3] = -38729678;
						array[2, 0] = 245196412;
						array[2, 1] = -435135534;
						array[2, 2] = -988552645;
						array[2, 3] = -1988088837;
						array[1, 2] = array[2, 1] ^ 0x62810D5E;
						array[0, 2] = array[0, 1] ^ -147865005;
						array[2, 1] = array[0, 1] ^ 0x2DCD2F00;
						int num11 = array[2, 1] ^ -2009630880;
						num = ((int)num4 * -1064084626) ^ -199649500 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}
	}

	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CProtectAsync_003Ed__126 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder _003C_003Et__builder;

		public WorkspaceViewModel _003C_003E4__this;

		private TaskAwaiter<ProtectionResult> _003C_003Eu__1;

		private unsafe void MoveNext()
		{
			int num = _003C_003E1__state;
			WorkspaceViewModel CS_0024_003C_003E8__locals33 = _003C_003E4__this;
			try
			{
				if (num == 0)
				{
					goto IL_2bb8;
				}
				AssemblyProfile assemblyProfile = default(AssemblyProfile);
				long num67 = default(long);
				ProtectionOptions protectionOptions = default(ProtectionOptions);
				while (true)
				{
					int num2 = 1520119358;
					uint num4;
					while (true)
					{
						int num3 = num2;
						uint num5;
						num4 = (num5 = (uint)((((~(2100204517 + -865830811) - 306661243) * -1190475465 - ~(~(~(-num3 * -1122873841)))) * 1631187285) ^ -140790248)) % 20;
						uint num6 = num4;
						int num7 = -7;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 = -num7;
						}
						if (num6 == (uint)num7)
						{
							break;
						}
						uint num9 = num4;
						int num10 = -1286124695;
						_ = 0;
						for (int num11 = 0; num11 < 1; num11++)
						{
							num10 -= -1286124696;
						}
						if (num9 != (uint)num10)
						{
							uint num12 = num4;
							int num13 = 1415540912;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 += -1415540910;
							}
							if (num12 != (uint)num13)
							{
								uint num15 = num4;
								int num16 = 0;
								_ = 0;
								for (int num17 = 0; num17 < 1; num17++)
								{
									num16 = -num16;
								}
								if (num15 != (uint)num16)
								{
									uint num18 = num4;
									int num19 = -1200341542;
									_ = 0;
									for (int num20 = 0; num20 < 1; num20++)
									{
										num19 *= -1642017617;
									}
									if (num18 == (uint)num19)
									{
										goto end_IL_0023;
									}
									uint num21 = num4;
									int num22 = -158221277;
									_ = 0;
									for (int num23 = 0; num23 < 1; num23++)
									{
										num22 += 158221282;
									}
									if (num21 != (uint)num22)
									{
										uint num24 = num4;
										int num25 = 675573097;
										_ = 0;
										for (int num26 = 0; num26 < 2; num26++)
										{
											num25 = num25 * 1933433051 * 379046785;
											num25 = ~(num25 ^ -1229886644);
										}
										if (num24 != (uint)num25)
										{
											uint num27 = num4;
											int num28 = 1606986180;
											_ = 0;
											for (int num29 = 0; num29 < 2; num29++)
											{
												num28 = ~(num28 ^ 0x5B21D904);
												num28 = (1161467291 - num28) * 1364065051;
											}
											if (num27 != (uint)num28)
											{
												uint num30 = num4;
												int num31 = 1315012;
												_ = 0;
												for (int num32 = 0; num32 < 2; num32++)
												{
													num31 = (num31 + ~375976794) ^ 0x7FE59700;
													num31 = ~(~num31);
												}
												if (num30 == (uint)num31)
												{
													goto end_IL_0023;
												}
												uint num33 = num4;
												int num34 = 980934860;
												_ = 0;
												for (int num35 = 0; num35 < 2; num35++)
												{
													num34 = num34 ^ 0x32573A2A ^ -1125753084;
													num34 = (num34 + -628954654) * 408442633;
												}
												if (num33 != (uint)num34)
												{
													uint num36 = num4;
													int num37 = -596379125;
													_ = 0;
													for (int num38 = 0; num38 < 2; num38++)
													{
														num37 = (num37 * 789635839) ^ 0x851484C;
														num37 = 372472560 - (num37 ^ 0x61A456DA);
													}
													if (num36 != (uint)num37)
													{
														uint num39 = num4;
														int num40 = 2048082634;
														_ = 0;
														for (int num41 = 0; num41 < 2; num41++)
														{
															num40 = -(~num40);
															num40 = (-1987870537 * 2061665612 - num40) ^ 0x3D0DA760;
														}
														if (num39 != (uint)num40)
														{
															uint num42 = num4;
															int num43 = -1493430690;
															_ = 0;
															for (int num44 = 0; num44 < 1; num44++)
															{
																num43 = -1493430674 - num43;
															}
															if (num42 == (uint)num43)
															{
																goto end_IL_0023;
															}
															uint num45 = num4;
															int num46 = 425587516;
															_ = 0;
															for (int num47 = 0; num47 < 1; num47++)
															{
																num46 += -425587501;
															}
															if (num45 != (uint)num46)
															{
																uint num48 = num4;
																int num49 = -974593847;
																_ = 0;
																for (int num50 = 0; num50 < 2; num50++)
																{
																	num49 = -num49 * -1706477115;
																	num49 = -(num49 - ~1455150039);
																}
																if (num48 != (uint)num49)
																{
																	uint num51 = num4;
																	int num52 = 1850251748;
																	_ = 0;
																	for (int num53 = 0; num53 < 1; num53++)
																	{
																		num52 -= 1850251739;
																	}
																	if (num51 != (uint)num52)
																	{
																		uint num54 = num4;
																		int num55 = -9;
																		_ = 0;
																		for (int num56 = 0; num56 < 1; num56++)
																		{
																			num55 = ~num55;
																		}
																		if (num54 != (uint)num55)
																		{
																			uint num57 = num4;
																			int num58 = 1;
																			_ = 0;
																			for (int num59 = 0; num59 < 2; num59++)
																			{
																				num58 = -(~num58);
																				num58 = ~num58 ^ 0x16D8D791;
																			}
																			if (num57 != (uint)num58)
																			{
																				uint num60 = num4;
																				int num61 = -13;
																				_ = 0;
																				for (int num62 = 0; num62 < 1; num62++)
																				{
																					num61 = -num61;
																				}
																				if (num60 == (uint)num61)
																				{
																					CS_0024_003C_003E8__locals33.BusyStep = _005E_0026_0040_0021_0028_002B_003E_003D(CS_0024_003C_003E8__locals33._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[3482 - 3134 + 57]);
																					int[,] array = new int[3, 3]
																					{
																						{ 1894030403, 648408716, 1767542875 },
																						{ 2078123635, 779329575, 281238452 },
																						{ -1000822075, 509619449, 1508799255 }
																					};
																					array[0, 1] ^= -275882107;
																					array[0, 0] = array[2, 1] ^ -2114704438;
																					array[2, 2] = array[2, 1] ^ 0x2CA51D82;
																					array[2, 0] = array[1, 1] ^ 0x6DD05A23;
																					int num63 = array[2, 0] ^ -1363924733;
																					num2 = (int)((num5 * 9644166) ^ 0x8B2AA596u) ^ num63;
																					continue;
																				}
																				goto IL_077d;
																			}
																			CS_0024_003C_003E8__locals33.IsBusy = true;
																			CS_0024_003C_003E8__locals33.BusyProgressValue = 0.0;
																			num2 = -1575704154;
																			continue;
																		}
																		goto end_IL_0023;
																	}
																	CS_0024_003C_003E8__locals33.SetStatus(_005E_0026_0040_0021_0028_002B_003E_003D(CS_0024_003C_003E8__locals33._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-464 + 59)]), SeverityLevel.Error);
																	int[,] array2 = new int[4, 3];
																	array2[0, 0] = 1744991158;
																	array2[0, 1] = -230923407;
																	array2[0, 2] = -963747732;
																	array2[1, 0] = 1136701235;
																	array2[1, 1] = 825676681;
																	array2[1, 2] = 2119766153;
																	array2[2, 0] = 1551893883;
																	array2[2, 1] = 1232755207;
																	array2[2, 2] = -213326082;
																	array2[3, 0] = -482041003;
																	array2[3, 1] = -42265801;
																	array2[3, 2] = 1508613910;
																	array2[3, 1] = array2[0, 0] ^ -354266292;
																	array2[3, 1] = array2[1, 1] ^ 0x47142C0E;
																	array2[3, 0] = array2[0, 2] ^ 0x4D04ECC9;
																	array2[1, 1] = array2[0, 2] ^ 0x5AB311CD;
																	int num64 = array2[1, 1] ^ 0x3289C324;
																	num2 = (int)((num5 * 1618469828) ^ 0xB6A9DBF4u) ^ num64;
																	continue;
																}
																long num65 = _0028_0029_003C_005E_005E_0021_0029_0024(assemblyProfile);
																long num66 = num67;
																int[] array3 = new int[4];
																array3[0] = 1405704086;
																array3[1] = -1353859000;
																array3[2] = -537774601;
																array3[3] = 2018274435;
																array3[3] = array3[1] ^ 0xC768AEE;
																array3[2] = array3[1] ^ -2103089423;
																array3[1] = array3[0] ^ -1952947994;
																int[] array4 = new int[7] { -219207204, 557974827, 1600831366, -151239179, 709562770, 888829615, -233604326 };
																int[][] array5 = new int[2][] { array3, array4 };
																array4[1] = array5[0][0] ^ 0x5CA86F4A;
																array4[6] = array4[1] ^ 0x45DD96F0;
																array4[0] = array4[3] ^ -554993651;
																array4[5] = array4[2] ^ -1690925474;
																int num68 = array5[1][1] ^ 0x7B857E74;
																int[,] array6 = new int[3, 4];
																array6[0, 0] = 1080263716;
																array6[0, 1] = 1266470790;
																array6[0, 2] = 1773491765;
																array6[0, 3] = 1681440928;
																array6[1, 0] = 1123265992;
																array6[1, 1] = -762505254;
																array6[1, 2] = -349683472;
																array6[1, 3] = -675595890;
																array6[2, 0] = -2097587138;
																array6[2, 1] = 1134750291;
																array6[2, 2] = 2067953220;
																array6[2, 3] = 456382541;
																array6[2, 2] = array6[0, 0] ^ 0x65E04A97;
																array6[0, 2] = array6[2, 1] ^ -1171087620;
																array6[0, 2] = array6[2, 1] ^ 0x34868BE5;
																array6[1, 3] = array6[1, 2] ^ 0x5AF9E5EC;
																int num69 = array6[1, 3] ^ -325242698;
																int num70 = ((int)num5 * -182659722) ^ 0x60F55996;
																num68 ^= num70;
																num69 ^= num70;
																int num71;
																int num72;
																if (num65 > num66)
																{
																	num71 = num69;
																	num72 = num71;
																}
																else
																{
																	num71 = num68;
																	num72 = num71;
																}
																num2 = num71 ^ num70;
																continue;
															}
															num67 = 524288000L;
															num2 = -393618706;
															continue;
														}
														CS_0024_003C_003E8__locals33.SetStatus(_005E_0026_0040_0021_0028_002B_003E_003D(CS_0024_003C_003E8__locals33._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(400 + sizeof(int)) ^ sizeof(Guid)]), SeverityLevel.Warning);
														int[,] array7 = new int[3, 4];
														array7[0, 0] = 625434077;
														array7[0, 1] = -1946330455;
														array7[0, 2] = 852854471;
														array7[0, 3] = -779826264;
														array7[1, 0] = -2090342858;
														array7[1, 1] = -1962115803;
														array7[1, 2] = 1219962789;
														array7[1, 3] = -1112387595;
														array7[2, 0] = 80565907;
														array7[2, 1] = -1953657963;
														array7[2, 2] = -860858943;
														array7[2, 3] = 162782214;
														array7[2, 3] = array7[2, 0] ^ -205296856;
														array7[0, 0] = array7[0, 3] ^ -1805035187;
														array7[0, 3] = array7[0, 2] ^ -1843801269;
														int num73 = array7[0, 3] ^ -873141111;
														num2 = (int)((num5 * 1536811022) ^ 0x17B8CCB4) ^ num73;
														continue;
													}
													bool hasSdkReference = CS_0024_003C_003E8__locals33.HasSdkReference;
													int[,] array8 = new int[3, 3];
													array8[0, 0] = -1723767123;
													array8[0, 1] = 539026011;
													array8[0, 2] = -837280768;
													array8[1, 0] = -1425972985;
													array8[1, 1] = -972405066;
													array8[1, 2] = -974546338;
													array8[2, 0] = -264718881;
													array8[2, 1] = 528622907;
													array8[2, 2] = 1837899482;
													array8[2, 0] = array8[1, 1] ^ -1172163036;
													array8[0, 2] = array8[0, 1] ^ 0x3425E366;
													array8[0, 0] = array8[1, 1] ^ 0x1033757E;
													array8[1, 0] = array8[1, 2] ^ 0x2B208791;
													int num74 = array8[1, 0] ^ -768146209;
													int[] array9 = new int[5];
													array9[0] = 1495495215;
													array9[1] = 1247312004;
													array9[2] = 2094802187;
													array9[3] = -850796108;
													array9[4] = 1792877761;
													array9[0] = array9[1] ^ -1731139810;
													array9[2] = array9[3] ^ -378075479;
													array9[2] = array9[1] ^ -608486176;
													int[] array10 = new int[6] { 1461316258, -1589630474, -1603660206, 138662604, 1380433254, 113410700 };
													int[][] array11 = new int[2][] { array9, array10 };
													array10[3] = array11[0][1] ^ -1982092875;
													array10[5] ^= 950081213;
													array10[2] = array10[0] ^ -2036957238;
													array10[5] = array10[3] ^ 0x624AB109;
													int num75 = array11[1][3] ^ 0x65E408BE;
													int num76 = ((int)num5 * -1563610993) ^ -1698771271;
													num74 ^= num76;
													num75 ^= num76;
													int num77;
													int num78;
													if (!hasSdkReference)
													{
														num77 = num75;
														num78 = num77;
													}
													else
													{
														num77 = num74;
														num78 = num77;
													}
													num2 = num77 ^ num76;
													continue;
												}
												int num79;
												if (_0028_002A_002A_0021_002A_0024_0021_0023(protectionOptions))
												{
													num2 = 896459452;
													num79 = num2;
												}
												else
												{
													num2 = 1023285520;
													num79 = num2;
												}
												continue;
											}
											CS_0024_003C_003E8__locals33.SetStatus(_005E_0026_0040_0021_0028_002B_003E_003D(CS_0024_003C_003E8__locals33._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-646 + 242)]), SeverityLevel.Warning);
											int[,] array12 = new int[3, 3];
											array12[0, 0] = -49009546;
											array12[0, 1] = 671723361;
											array12[0, 2] = 628109187;
											array12[1, 0] = 203389085;
											array12[1, 1] = -352641896;
											array12[1, 2] = 197582424;
											array12[2, 0] = -719797016;
											array12[2, 1] = -839260143;
											array12[2, 2] = -1632536277;
											array12[2, 0] = array12[0, 0] ^ -211682291;
											array12[2, 2] = array12[1, 2] ^ -515542823;
											array12[0, 0] = array12[1, 1] ^ -1002037105;
											array12[1, 0] = array12[0, 1] ^ 0x74010381;
											int num80 = array12[1, 0] ^ 0x3000BBA7;
											num2 = (int)((num5 * 52943165) ^ 0xBBC202A8u) ^ num80;
											continue;
										}
										bool num81 = _0028_0024_0024_0028__005E_003D_0025(protectionOptions);
										int[] array13 = new int[6];
										array13[0] = -1625891399;
										array13[1] = -255854702;
										array13[2] = -1817278272;
										array13[3] = 1426893518;
										array13[4] = -1307382055;
										array13[5] = -2093658040;
										array13[0] = array13[5] ^ -1240136485;
										array13[4] = array13[5] ^ -1851534158;
										int[] array14 = new int[7] { -1716181756, -1205183829, -1521069622, -1518577584, 2020890857, -246739864, -1374552665 };
										int[][] array15 = new int[2][] { array13, array14 };
										array14[1] = array15[0][5] ^ 0xB758316;
										array14[5] = array14[2] ^ -2046020907;
										array14[6] = array14[0] ^ -1829543220;
										array14[3] ^= 1189293979;
										int num82 = array15[1][1] ^ 0x7C685BAF;
										int[,] array16 = new int[4, 3];
										array16[0, 0] = -618966510;
										array16[0, 1] = -330621895;
										array16[0, 2] = 1511155286;
										array16[1, 0] = 955185990;
										array16[1, 1] = -1415945647;
										array16[1, 2] = 686960597;
										array16[2, 0] = 1485376735;
										array16[2, 1] = -1808052715;
										array16[2, 2] = -916598056;
										array16[3, 0] = 598560924;
										array16[3, 1] = 1779514195;
										array16[3, 2] = -1027389651;
										array16[0, 0] = array16[3, 0] ^ -490215264;
										array16[3, 1] = array16[2, 0] ^ 0x280FABB5;
										array16[3, 1] = array16[2, 0] ^ -168686808;
										int num83 = array16[3, 1] ^ 0x734E0F5E;
										int num84 = ((int)num5 * -306492856) ^ -352839688;
										num82 ^= num84;
										num83 ^= num84;
										int num85;
										int num86;
										if (!num81)
										{
											num85 = num83;
											num86 = num85;
										}
										else
										{
											num85 = num82;
											num86 = num85;
										}
										num2 = num85 ^ num84;
										continue;
									}
									protectionOptions = CS_0024_003C_003E8__locals33.BuildOptions();
									num2 = 1647455212;
									continue;
								}
								CS_0024_003C_003E8__locals33.SetStatus(_005E_0026_0040_0021_0028_002B_003E_003D(CS_0024_003C_003E8__locals33._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-595 + 197)]), SeverityLevel.Warning);
								int[] array17 = new int[5];
								array17[0] = 1255472461;
								array17[1] = 743592528;
								array17[2] = 699255102;
								array17[3] = -1071483406;
								array17[4] = 1092899288;
								array17[3] = array17[4] ^ -396126793;
								array17[3] = array17[0] ^ 0x2FD3EF93;
								int[] array18 = new int[5] { -956655740, 456837381, 1570833894, 159878879, -180208915 };
								int[][] array19 = new int[2][] { array17, array18 };
								array18[4] = array19[0][1] ^ 0xF436C1;
								array18[1] = array18[3] ^ 0x6A07653D;
								array18[3] = array18[1] ^ -1466791181;
								array18[1] = array18[0] ^ -796963126;
								int num87 = array19[1][4] ^ -1819252338;
								num2 = (int)((num5 * 1317797372) ^ 0x13C2DC0) ^ num87;
								continue;
							}
							AssemblyProfile assemblyProfile2 = assemblyProfile;
							int[] array20 = new int[5];
							array20[0] = -2066481772;
							array20[1] = 739329286;
							array20[2] = 1784213582;
							array20[3] = 1096335698;
							array20[4] = 463616675;
							array20[4] = array20[3] ^ -143660514;
							array20[1] = array20[0] ^ 0x4C2267B1;
							array20[4] = array20[0] ^ -2011221311;
							int[] array21 = new int[7];
							array21[0] = -224703948;
							array21[1] = 464980450;
							array21[2] = -785724394;
							array21[3] = 977325297;
							array21[4] = -1301510638;
							array21[5] = -1802948232;
							array21[6] = -2004133807;
							array21[2] = array20[2] ^ 0x50FE1F77;
							array21[1] = array21[5] ^ -633538472;
							array21[3] = array21[5] ^ 0x266A61F8;
							int num88 = array21[2] ^ 0x6CF4C86F;
							int[,] array22 = new int[3, 4];
							array22[0, 0] = -70594078;
							array22[0, 1] = 11364897;
							array22[0, 2] = -2135904424;
							array22[0, 3] = 1337654349;
							array22[1, 0] = 337269775;
							array22[1, 1] = -2029436886;
							array22[1, 2] = 907771528;
							array22[1, 3] = -732813436;
							array22[2, 0] = 167556692;
							array22[2, 1] = 965568114;
							array22[2, 2] = -1026816073;
							array22[2, 3] = 1932123503;
							array22[0, 1] = array22[0, 0] ^ -1927394326;
							array22[1, 0] = array22[1, 2] ^ -653607595;
							array22[1, 2] = array22[1, 0] ^ 0x1F0B3260;
							array22[1, 1] = array22[0, 2] ^ 0x34A52507;
							int num89 = array22[1, 1] ^ -1474732450;
							int num90 = (int)(num5 * 1660973133) ^ -1316982354;
							num88 ^= num90;
							num89 ^= num90;
							int num91;
							int num92;
							if (assemblyProfile2 == null)
							{
								num91 = num89;
								num92 = num91;
							}
							else
							{
								num91 = num88;
								num92 = num91;
							}
							num2 = num91 ^ num90;
							continue;
						}
						assemblyProfile = _0024_0023_0025_0026_003D_0040_0021_0028(CS_0024_003C_003E8__locals33._assemblyWorkspaceService);
						int[] array23 = new int[6] { 491204198, 1612231809, -1197582773, -639770265, 663455104, -1043380334 };
						array23[4] ^= 545000215;
						array23[4] ^= -51127285;
						array23[4] = array23[2] ^ -202915518;
						int[] array24 = new int[5] { 670474713, -607735274, 797162877, -1512513210, 458440963 };
						int[][] array25 = new int[2][] { array23, array24 };
						array24[0] = array25[0][2] ^ 0x6F09A8E5;
						array24[1] = array24[4] ^ -334810529;
						array24[4] ^= -703543606;
						array24[2] = array24[1] ^ -1147116267;
						int num93 = array25[1][0] ^ 0x6EE8C51;
						num2 = (int)((num5 * 2073277350) ^ 0x9E67E966u) ^ num93;
					}
					continue;
					IL_077d:
					uint num94 = num4;
					int num95 = 937649810;
					_ = 0;
					for (int num96 = 0; num96 < 2; num96++)
					{
						num95 = (-995529261 * -876905978 - num95) ^ -1211501610;
						num95 = -(num95 * -852635907);
					}
					if (num94 == (uint)num95)
					{
					}
					goto IL_2bb8;
					continue;
					end_IL_0023:
					break;
				}
				goto end_IL_001a;
				IL_2bb8:
				try
				{
					if (num != 0)
					{
						goto IL_2bc1;
					}
					goto IL_4b32;
					IL_2bc1:
					int num97 = -1911359008;
					goto IL_2bc6;
					IL_2bc6:
					byte[] array26 = default(byte[]);
					Progress<ProtectionProgress> progress = default(Progress<ProtectionProgress>);
					TaskAwaiter<ProtectionResult> awaiter = default(TaskAwaiter<ProtectionResult>);
					ProtectionResult result = default(ProtectionResult);
					while (true)
					{
						int num3 = num97;
						uint num5;
						uint num4 = (num5 = (uint)((((~(2100204517 + -865830811) - 306661243) * -1190475465 - ~(~(~(-num3 * -1122873841)))) * 1631187285) ^ -140790248)) % 19;
						uint num98 = num4;
						int num99 = 1239394749;
						_ = 0;
						for (int num100 = 0; num100 < 1; num100++)
						{
							num99 += -1239394735;
						}
						if (num98 == (uint)num99)
						{
							break;
						}
						uint num101 = num4;
						int num102 = 249600349;
						_ = 0;
						for (int num103 = 0; num103 < 2; num103++)
						{
							num102 = num102 * 84864699 * -1131398531;
							num102 = num102 ^ 0x7067A21D ^ -2006748822;
						}
						if (num101 == (uint)num102)
						{
							array26 = _002A_0028_0023_0023_0023_002A_002D_0040(CS_0024_003C_003E8__locals33._assemblyWorkspaceService, _0028_002A_002A_0021_002A_0024_0021_0023(protectionOptions));
							int[] array27 = new int[6];
							array27[0] = 392764463;
							array27[1] = -935046545;
							array27[2] = 1928936695;
							array27[3] = 702292704;
							array27[4] = -1405890069;
							array27[5] = 1202947161;
							array27[0] = array27[3] ^ -827365031;
							array27[3] = array27[0] ^ -1524148103;
							array27[3] = array27[5] ^ 0x515F88A9;
							int[] array28 = new int[6];
							array28[0] = 1895621212;
							array28[1] = -1106792304;
							array28[2] = -1762997490;
							array28[3] = 884709556;
							array28[4] = 1128438105;
							array28[5] = 986390832;
							array28[5] = array27[5] ^ 0x380CB086;
							array28[1] = array28[5] ^ -1749325419;
							array28[4] ^= 225885853;
							int num104 = array28[5] ^ -1367398697;
							num97 = (int)((num5 * 866233513) ^ 0xDC5AF8B3u) ^ num104;
							continue;
						}
						uint num105 = num4;
						int num106 = 1849995489;
						_ = 0;
						for (int num107 = 0; num107 < 1; num107++)
						{
							num106 -= 1849995485;
						}
						if (num105 == (uint)num106)
						{
							progress = new Progress<ProtectionProgress>(delegate(ProtectionProgress value)
							{
								CS_0024_003C_003E8__locals33.BusyStep = WorkspaceViewModel._002F_003F_0021_0021_003D_0024_003E_005E(value);
								while (true)
								{
									int num219 = 1868159461;
									while (true)
									{
										int num220 = num219;
										uint num222;
										uint num221 = (num222 = (uint)((~(-(-(-(-num220)))) * 1174567791 - (-1672110308 ^ 0x41F088E8) - ~(-1331156817)) * -2069387453 + 667307387)) % 3;
										int num223 = 502467522;
										_ = 0;
										for (int num224 = 0; num224 < 2; num224++)
										{
											num223 = (num223 ^ 0x572A8F34) - -77691379;
											num223 = -(num223 + (0x1E4F12F0 ^ 0x3F94191F));
										}
										if (num221 == (uint)num223)
										{
											break;
										}
										int num225 = 50395389;
										_ = 0;
										for (int num226 = 0; num226 < 2; num226++)
										{
											num225 = (num225 ^ 0x5282AECB) - -754269546;
											num225 = ~num225;
										}
										if (num221 != (uint)num225)
										{
											int num227 = 0;
											_ = 0;
											for (int num228 = 0; num228 < 1; num228++)
											{
												num227 = -num227;
											}
											if (num221 == (uint)num227)
											{
											}
											return;
										}
										CS_0024_003C_003E8__locals33.BusyProgressValue = WorkspaceViewModel._0028_003E_0040__003C_003C_003D_002B(value) ?? CS_0024_003C_003E8__locals33.BusyProgressValue;
										num219 = -1755208978;
									}
								}
							});
							int[,] array29 = new int[3, 3];
							array29[0, 0] = 241449510;
							array29[0, 1] = 592282223;
							array29[0, 2] = 885191280;
							array29[1, 0] = -145603356;
							array29[1, 1] = -155721099;
							array29[1, 2] = -1396829315;
							array29[2, 0] = 686486540;
							array29[2, 1] = 33747567;
							array29[2, 2] = 48247706;
							array29[0, 2] = array29[0, 1] ^ -1696888015;
							array29[0, 2] = array29[1, 1] ^ -1010983750;
							array29[2, 0] = array29[2, 2] ^ -1410523195;
							int num108 = array29[2, 0] ^ -1766469797;
							num97 = ((int)num5 * -664568841) ^ 0x555211B5 ^ num108;
							continue;
						}
						uint num109 = num4;
						int num110 = 1559949976;
						_ = 0;
						for (int num111 = 0; num111 < 1; num111++)
						{
							num110 *= -1616079397;
						}
						if (num109 == (uint)num110)
						{
							IProtectionService protectionService = CS_0024_003C_003E8__locals33._protectionService;
							ProtectionRequest protectionRequest = new ProtectionRequest();
							_0029_0024_002F_005E_003C_0024_0021_0040(protectionRequest, _0023_003E_0023_0026_002B_0021_002B_003D(assemblyProfile));
							_003D_0024_0040_0040_0024__0023_0040(protectionRequest, _005E_0024_002B_005E_003F__003E_0028(assemblyProfile));
							_003E_0026_005E_002D_0021_003D__0028(protectionRequest, array26);
							_0028_0021_002F_0024_003E_003D_0025_002D(protectionRequest, _005E_0040_003E_0024_0024_0025_005E_002A(CS_0024_003C_003E8__locals33._authenticationService) ?? string.Empty);
							_0021_003C_003D_002A_005E_0029_0029_005E(protectionRequest, protectionOptions);
							awaiter = _002F_003E_0029_002A_0040_0028_0040_002B(protectionService, protectionRequest, (IProgress<ProtectionProgress>)progress, default(CancellationToken)).GetAwaiter();
							num97 = -2000313623;
							continue;
						}
						uint num112 = num4;
						int num113 = -5;
						_ = 0;
						for (int num114 = 0; num114 < 1; num114++)
						{
							num113 = -num113;
						}
						if (num112 == (uint)num113)
						{
							bool ısCompleted = awaiter.IsCompleted;
							int[] array30 = new int[4];
							array30[0] = 17586863;
							array30[1] = 2036665290;
							array30[2] = -2137165306;
							array30[3] = 1217171774;
							array30[2] = array30[1] ^ -2068819402;
							array30[2] = array30[3] ^ -439427920;
							int[] array31 = new int[6] { 421707305, 2082062234, -1236444956, -1990335608, -1755578009, -1441517851 };
							int[][] array32 = new int[2][] { array30, array31 };
							array31[5] = array32[0][3] ^ -1089442765;
							array31[1] = array31[3] ^ 0x66DF1C68;
							array31[0] = array31[1] ^ -1361128299;
							array31[4] ^= 625449166;
							int num115 = array32[1][5] ^ 0x31B28776;
							int[] array33 = new int[7] { 1919300597, -1352293148, 1483759275, -1911136993, -334679880, -1212507421, 1382016551 };
							array33[6] ^= -1736037901;
							array33[3] = array33[4] ^ 0x3A52B826;
							int[] array34 = new int[6];
							array34[0] = -1091712777;
							array34[1] = -727905254;
							array34[2] = -1564328298;
							array34[3] = 622701939;
							array34[4] = -1920819039;
							array34[5] = -2136750118;
							array34[5] = array33[1] ^ -124927874;
							array34[1] = array34[2] ^ -1623058357;
							array34[2] = array34[5] ^ 0x88B2B49;
							int num116 = array34[5] ^ -1815174028;
							int num117 = (int)(num5 * 1704791165) ^ -1706362136;
							num115 ^= num117;
							num116 ^= num117;
							int num118;
							int num119;
							if (!ısCompleted)
							{
								num118 = num116;
								num119 = num118;
							}
							else
							{
								num118 = num115;
								num119 = num118;
							}
							num97 = num118 ^ num117;
							continue;
						}
						uint num120 = num4;
						int num121 = -18;
						_ = 0;
						for (int num122 = 0; num122 < 1; num122++)
						{
							num121 = ~num121;
						}
						if (num120 == (uint)num121)
						{
							num = (_003C_003E1__state = 0);
							int[,] array35 = new int[3, 3];
							array35[0, 0] = 1450258264;
							array35[0, 1] = 793541207;
							array35[0, 2] = 1739823261;
							array35[1, 0] = -852741223;
							array35[1, 1] = 1805807330;
							array35[1, 2] = 2100272826;
							array35[2, 0] = 1787927860;
							array35[2, 1] = -213786789;
							array35[2, 2] = -1560434423;
							array35[1, 0] = array35[2, 1] ^ 0x6B263CA0;
							array35[0, 1] = array35[2, 1] ^ -377201861;
							array35[2, 0] = array35[0, 2] ^ -1287937807;
							int num123 = array35[2, 0] ^ -774704283;
							num97 = ((int)num5 * -1757343046) ^ 0x74CAFB9A ^ num123;
							continue;
						}
						uint num124 = num4;
						int num125 = -1701728026;
						_ = 0;
						for (int num126 = 0; num126 < 2; num126++)
						{
							num125 = ~num125;
							num125 = num125 * -880676623 - 2112676241;
						}
						if (num124 == (uint)num125)
						{
							_003C_003Eu__1 = awaiter;
							int[,] array36 = new int[3, 4];
							array36[0, 0] = -504322718;
							array36[0, 1] = -2011306051;
							array36[0, 2] = -880873244;
							array36[0, 3] = 419139949;
							array36[1, 0] = -1895707526;
							array36[1, 1] = -1966206759;
							array36[1, 2] = -1135552825;
							array36[1, 3] = 905326103;
							array36[2, 0] = 421886015;
							array36[2, 1] = 633325976;
							array36[2, 2] = 1399527361;
							array36[2, 3] = -1017360151;
							array36[1, 3] = array36[2, 3] ^ 0x6581B043;
							array36[0, 0] = array36[2, 2] ^ -939936137;
							array36[0, 1] = array36[2, 1] ^ 0x6BABB803;
							array36[1, 2] = array36[2, 3] ^ 0x4F2AF76A;
							int num127 = array36[1, 2] ^ -1531674474;
							num97 = (int)((num5 * 552875929) ^ 0xB3062F68u) ^ num127;
							continue;
						}
						uint num128 = num4;
						int num129 = -1047282271;
						_ = 0;
						for (int num130 = 0; num130 < 1; num130++)
						{
							num129 ^= -1047282271;
						}
						if (num128 == (uint)num129)
						{
							_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
							int[] array37 = new int[4];
							array37[0] = 1986007208;
							array37[1] = -1148126552;
							array37[2] = -1371753380;
							array37[3] = -962857391;
							array37[1] = array37[2] ^ -888292682;
							array37[3] = array37[0] ^ -1819208505;
							int[] array38 = new int[4] { 878780855, 631872912, 498570815, -1900769738 };
							int[][] array39 = new int[2][] { array37, array38 };
							array38[2] = array39[0][2] ^ -944987117;
							array38[0] = array38[2] ^ -655572748;
							array38[1] = array38[0] ^ -1116057426;
							array38[0] = array38[2] ^ 0x6B49BD81;
							int num131 = array39[1][2] ^ 0x5430AADF;
							num97 = ((int)num5 * -1383315345) ^ -1689201972 ^ num131;
							continue;
						}
						uint num132 = num4;
						int num133 = -3;
						_ = 0;
						for (int num134 = 0; num134 < 1; num134++)
						{
							num133 = -num133;
						}
						if (num132 == (uint)num133)
						{
							return;
						}
						uint num135 = num4;
						int num136 = 119438049;
						_ = 0;
						for (int num137 = 0; num137 < 1; num137++)
						{
							num136 = 119438058 - num136;
						}
						if (num135 == (uint)num136)
						{
							goto IL_4b32;
						}
						uint num138 = num4;
						int num139 = -983176661;
						_ = 0;
						for (int num140 = 0; num140 < 2; num140++)
						{
							num139 = (num139 * 2077220151) ^ -149649478;
							num139 = -num139 ^ -1811090463;
						}
						if (num138 == (uint)num139)
						{
							_003C_003Eu__1 = default(TaskAwaiter<ProtectionResult>);
							int[,] array40 = new int[3, 3];
							array40[0, 0] = -1885939316;
							array40[0, 1] = -41368199;
							array40[0, 2] = -908168813;
							array40[1, 0] = -551387236;
							array40[1, 1] = 2016600254;
							array40[1, 2] = -417873716;
							array40[2, 0] = 558365380;
							array40[2, 1] = 1421777863;
							array40[2, 2] = -821255552;
							array40[0, 0] = array40[1, 1] ^ 0x5ABAA590;
							array40[2, 0] = array40[0, 0] ^ -1645191121;
							array40[2, 0] = array40[2, 2] ^ -2133235786;
							array40[0, 2] = array40[1, 2] ^ -763583969;
							int num141 = array40[0, 2] ^ 0x7E6D288;
							num97 = (int)((num5 * 1449995118) ^ 0x448306F8) ^ num141;
							continue;
						}
						uint num142 = num4;
						int num143 = 2673274;
						_ = 0;
						for (int num144 = 0; num144 < 1; num144++)
						{
							num143 -= 2673273;
						}
						if (num142 == (uint)num143)
						{
							num = (_003C_003E1__state = -1);
							int[] array41 = new int[4] { 1368909271, 1740495227, -1847754184, -1154214297 };
							array41[1] ^= 619092104;
							array41[0] ^= 103316939;
							array41[2] = array41[1] ^ -608709721;
							int[] array42 = new int[5];
							array42[0] = -1309448892;
							array42[1] = -100101836;
							array42[2] = -852255120;
							array42[3] = -1239685056;
							array42[4] = -488290449;
							array42[3] = array41[3] ^ -897397221;
							array42[1] = array42[2] ^ -933472703;
							array42[4] = array42[3] ^ 0x6BEDA40E;
							int num145 = array42[3] ^ -1214733817;
							num97 = (int)((num5 * 280235611) ^ 0xC0DBF26) ^ num145;
							continue;
						}
						uint num146 = num4;
						int num147 = -1040498195;
						_ = 0;
						for (int num148 = 0; num148 < 1; num148++)
						{
							num147 *= -1774658749;
						}
						if (num146 == (uint)num147)
						{
							result = awaiter.GetResult();
							num97 = -1073853273;
							continue;
						}
						uint num149 = num4;
						int num150 = -532672540;
						_ = 0;
						for (int num151 = 0; num151 < 2; num151++)
						{
							num150 = -(-num150);
							num150 = (num150 ^ -301312863) - 2048919370;
						}
						if (num149 == (uint)num150)
						{
							bool num152 = _0029_0024_0021_003C_003C_003E_0025_0029(result);
							int[] array43 = new int[7];
							array43[0] = -282143428;
							array43[1] = -2112199234;
							array43[2] = 780048709;
							array43[3] = -1682619914;
							array43[4] = 1122891223;
							array43[5] = 1142546994;
							array43[6] = -1902369993;
							array43[1] = array43[6] ^ -1053649080;
							array43[0] = array43[6] ^ 0x6833D38A;
							array43[5] ^= -1169142630;
							int[] array44 = new int[6] { -1219652780, -1561014119, 953293850, 1557360281, -1357126196, -2042161641 };
							int[][] array45 = new int[2][] { array43, array44 };
							array44[4] = array45[0][2] ^ -1868238908;
							array44[0] = array44[3] ^ -128298550;
							array44[5] = array44[1] ^ -1354110709;
							array44[5] ^= -191080731;
							int num153 = array45[1][4] ^ 0x76A45A86;
							int[,] array46 = new int[3, 4];
							array46[0, 0] = 652846100;
							array46[0, 1] = -235219342;
							array46[0, 2] = 1192596160;
							array46[0, 3] = 2051815932;
							array46[1, 0] = -1981728666;
							array46[1, 1] = 1761922227;
							array46[1, 2] = 22612851;
							array46[1, 3] = -1186417076;
							array46[2, 0] = -1194551172;
							array46[2, 1] = -1408846705;
							array46[2, 2] = -2033413136;
							array46[2, 3] = -1509741623;
							array46[0, 0] = array46[0, 2] ^ -2064819974;
							array46[1, 1] = array46[0, 3] ^ -2026652961;
							array46[0, 0] = array46[0, 3] ^ -1319885462;
							array46[2, 1] = array46[2, 3] ^ 0x912CADB;
							int num154 = array46[2, 1] ^ -1724055101;
							int num155 = ((int)num5 * -398654204) ^ 0x42E69578;
							num153 ^= num155;
							num154 ^= num155;
							int num156;
							int num157;
							if (!num152)
							{
								num156 = num154;
								num157 = num156;
							}
							else
							{
								num156 = num153;
								num157 = num156;
							}
							num97 = num156 ^ num155;
							continue;
						}
						uint num158 = num4;
						int num159 = -591826757;
						_ = 0;
						for (int num160 = 0; num160 < 1; num160++)
						{
							num159 -= -591826775;
						}
						if (num158 == (uint)num159)
						{
							CS_0024_003C_003E8__locals33.SetStatus(@_005E_002B_0026_0021_0023_0029_0028(CS_0024_003C_003E8__locals33._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0xB637 ^ 0xB7A1))], new object[1] { _005E_003C_003D_0023_003D_005E_005E_0023(result) ?? _005E_0026_0040_0021_0028_002B_003E_003D(CS_0024_003C_003E8__locals33._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(365 + sizeof(int)) ^ sizeof(Guid)]) }), SeverityLevel.Error);
							num97 = -565003347;
							continue;
						}
						uint num161 = num4;
						int num162 = -720428302;
						_ = 0;
						for (int num163 = 0; num163 < 1; num163++)
						{
							num162 += 720428314;
						}
						if (num161 == (uint)num162)
						{
							CS_0024_003C_003E8__locals33.AppViewModel.AddActivity(_005E_0026_0040_0021_0028_002B_003E_003D(CS_0024_003C_003E8__locals33._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(387 + sizeof(int)) ^ sizeof(Guid)]), SeverityLevel.Error);
							int[,] array47 = new int[4, 4];
							array47[0, 0] = -148663552;
							array47[0, 1] = -44766144;
							array47[0, 2] = 1943738176;
							array47[0, 3] = -1261976561;
							array47[1, 0] = 435841240;
							array47[1, 1] = 122362660;
							array47[1, 2] = -1768384499;
							array47[1, 3] = 1214183204;
							array47[2, 0] = 2131924021;
							array47[2, 1] = 613928635;
							array47[2, 2] = -325824153;
							array47[2, 3] = -694914863;
							array47[3, 0] = 118847920;
							array47[3, 1] = -1907967977;
							array47[3, 2] = 2041354179;
							array47[3, 3] = -2024980719;
							array47[0, 1] = array47[1, 0] ^ -319204146;
							array47[2, 0] = array47[3, 2] ^ 0x68180F6B;
							array47[3, 0] = array47[1, 0] ^ -39913104;
							int num164 = array47[3, 0] ^ -71462875;
							num97 = ((int)num5 * -1991711746) ^ 0x430BB208 ^ num164;
							continue;
						}
						uint num165 = num4;
						int num166 = -10;
						_ = 0;
						for (int num167 = 0; num167 < 1; num167++)
						{
							num166 = -num166;
						}
						if (num165 != (uint)num166)
						{
							uint num168 = num4;
							int num169 = -3;
							_ = 0;
							for (int num170 = 0; num170 < 1; num170++)
							{
								num169 = ~num169;
							}
							if (num168 == (uint)num169)
							{
								CS_0024_003C_003E8__locals33.SetStatus(@_005E_002B_0026_0021_0023_0029_0028(CS_0024_003C_003E8__locals33._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[5290 - 4951 + 69], new object[1] { _002B_002F_0040_002A_003C_002F_005E_0024(result) ?? string.Empty }), SeverityLevel.Success);
								num97 = 1692499057;
								continue;
							}
							uint num171 = num4;
							int num172 = 531753253;
							_ = 0;
							for (int num173 = 0; num173 < 2; num173++)
							{
								num172 = (num172 + 1714715309) ^ -1415366580;
								num172 = ~num172 * -1758297223;
							}
							if (num171 != (uint)num172)
							{
							}
							CS_0024_003C_003E8__locals33.AppViewModel.AddActivity(_005E_0026_0040_0021_0028_002B_003E_003D(CS_0024_003C_003E8__locals33._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xBFC ^ 0xA65]), SeverityLevel.Success);
						}
						goto end_IL_2bb8;
					}
					goto IL_2bc1;
					IL_4b32:
					awaiter = _003C_003Eu__1;
					num97 = 1316873829;
					goto IL_2bc6;
					end_IL_2bb8:;
				}
				finally
				{
					if (num < 0)
					{
						while (true)
						{
							int num174 = -1487769976;
							while (true)
							{
								int num3 = num174;
								uint num5;
								uint num4 = (num5 = (uint)((((~(2100204517 + -865830811) - 306661243) * -1190475465 - ~(~(~(-num3 * -1122873841)))) * 1631187285) ^ -140790248)) % 5;
								uint num175 = num4;
								int num176 = 1694112646;
								_ = 0;
								for (int num177 = 0; num177 < 1; num177++)
								{
									num176 *= -465679637;
								}
								if (num175 == (uint)num176)
								{
									break;
								}
								uint num178 = num4;
								int num179 = -4;
								_ = 0;
								for (int num180 = 0; num180 < 1; num180++)
								{
									num179 = ~num179;
								}
								if (num178 != (uint)num179)
								{
									uint num181 = num4;
									int num182 = -549549442;
									_ = 0;
									for (int num183 = 0; num183 < 2; num183++)
									{
										num182 = ~(num182 + -524303300);
										num182 = (num182 ^ 0x71CFE952) * 613004983;
									}
									if (num181 != (uint)num182)
									{
										uint num184 = num4;
										int num185 = -2;
										_ = 0;
										for (int num186 = 0; num186 < 1; num186++)
										{
											num185 = ~num185;
										}
										if (num184 != (uint)num185)
										{
											uint num187 = num4;
											int num188 = -1676584842;
											_ = 0;
											for (int num189 = 0; num189 < 2; num189++)
											{
												num188 = (num188 ^ 0x1EAD12CA) * -1846574995;
												num188 = ~num188 * 2084676007;
											}
											if (num187 == (uint)num188)
											{
											}
											goto end_IL_4f0c;
										}
										CS_0024_003C_003E8__locals33.BusyStep = string.Empty;
										int[] array48 = new int[6];
										array48[0] = 1861717344;
										array48[1] = -829488728;
										array48[2] = -1200761345;
										array48[3] = 2027969712;
										array48[4] = -1964407282;
										array48[5] = 90822854;
										array48[2] = array48[0] ^ -1806322920;
										array48[1] = array48[0] ^ 0x4985D71B;
										int[] array49 = new int[6] { 198609972, 520569448, 1584845386, -1033767960, 1222607947, -756972834 };
										int[][] array50 = new int[2][] { array48, array49 };
										array49[2] = array50[0][5] ^ -611619840;
										array49[0] = array49[1] ^ -939463857;
										array49[5] ^= 315244782;
										int num190 = array50[1][2] ^ -1491764246;
										num174 = ((int)num5 * -49790120) ^ -774631032 ^ num190;
									}
									else
									{
										CS_0024_003C_003E8__locals33.BusyProgressValue = 0.0;
										int[] array51 = new int[5] { -593981906, -1241896252, -1616607053, -988048633, -1709925741 };
										array51[4] ^= 218961091;
										array51[4] = array51[0] ^ -1824218114;
										array51[4] ^= -1698681911;
										int[] array52 = new int[6];
										array52[0] = 1926004142;
										array52[1] = -2012239571;
										array52[2] = -94644224;
										array52[3] = -2088144338;
										array52[4] = -493667131;
										array52[5] = -1565449811;
										array52[0] = array51[1] ^ -344202752;
										array52[4] ^= -310834163;
										array52[5] = array52[1] ^ -1838844289;
										int num191 = array52[0] ^ 0x7DFDA16C;
										num174 = ((int)num5 * -2118324555) ^ -655132158 ^ num191;
									}
								}
								else
								{
									CS_0024_003C_003E8__locals33.IsBusy = false;
									int[,] array53 = new int[4, 4];
									array53[0, 0] = -1581569012;
									array53[0, 1] = -1644487559;
									array53[0, 2] = 1297044610;
									array53[0, 3] = 1913741767;
									array53[1, 0] = 583689880;
									array53[1, 1] = -911226419;
									array53[1, 2] = 1214991332;
									array53[1, 3] = -1843744853;
									array53[2, 0] = -854326382;
									array53[2, 1] = 395872910;
									array53[2, 2] = 167256403;
									array53[2, 3] = 624497680;
									array53[3, 0] = 9942377;
									array53[3, 1] = -845532838;
									array53[3, 2] = -1256190846;
									array53[3, 3] = -634720815;
									array53[0, 2] = array53[1, 0] ^ -1123444128;
									array53[3, 2] = array53[1, 1] ^ -2115824100;
									array53[3, 0] = array53[3, 1] ^ 0x31CC1669;
									array53[2, 0] = array53[3, 1] ^ 0x458DEE22;
									int num192 = array53[2, 0] ^ -1767163861;
									num174 = ((int)num5 * -797658566) ^ 0x5790A78E ^ num192;
								}
							}
							continue;
							end_IL_4f0c:
							break;
						}
					}
				}
				end_IL_001a:;
			}
			catch (Exception exception)
			{
				while (true)
				{
					int num193 = -1572779882;
					while (true)
					{
						int num3 = num193;
						uint num5;
						uint num4 = (num5 = (uint)((((~(2100204517 + -865830811) - 306661243) * -1190475465 - ~(~(~(-num3 * -1122873841)))) * 1631187285) ^ -140790248)) % 4;
						uint num194 = num4;
						int num195 = -1;
						_ = 0;
						for (int num196 = 0; num196 < 1; num196++)
						{
							num195 = ~num195;
						}
						if (num194 == (uint)num195)
						{
							break;
						}
						uint num197 = num4;
						int num198 = 100336274;
						_ = 0;
						for (int num199 = 0; num199 < 1; num199++)
						{
							num198 ^= 0x5FB0293;
						}
						if (num197 != (uint)num198)
						{
							uint num200 = num4;
							int num201 = 70483205;
							_ = 0;
							for (int num202 = 0; num202 < 1; num202++)
							{
								num201 = 70483208 - num201;
							}
							if (num200 != (uint)num201)
							{
								uint num203 = num4;
								int num204 = 1070544313;
								_ = 0;
								for (int num205 = 0; num205 < 1; num205++)
								{
									num204 ^= 0x3FCF35BB;
								}
								if (num203 == (uint)num204)
								{
								}
								return;
							}
							_003C_003Et__builder.SetException(exception);
							int[] array54 = new int[5];
							array54[0] = 1748700285;
							array54[1] = 1356535993;
							array54[2] = -421275168;
							array54[3] = -1288157630;
							array54[4] = -1409164902;
							array54[2] = array54[3] ^ -25131658;
							array54[3] ^= -445569195;
							int[] array55 = new int[4] { -2048035786, -1329060800, 2133854175, -175642924 };
							int[][] array56 = new int[2][] { array54, array55 };
							array55[3] = array56[0][1] ^ 0x234324C1;
							array55[2] = array55[1] ^ 0x2D665DC0;
							array55[1] = array55[2] ^ 0x1EAB4804;
							int num206 = array56[1][3] ^ -129884297;
							num193 = (int)((num5 * 124228977) ^ 0xBF5B5327u) ^ num206;
						}
						else
						{
							_003C_003E1__state = -2;
							int[] array57 = new int[4] { 1732607266, 1571666088, -1428164052, 188595847 };
							array57[2] ^= -270186518;
							array57[0] = array57[3] ^ 0x35687CB8;
							array57[2] = array57[3] ^ -490778264;
							int[] array58 = new int[4] { -1414593353, 69704115, 972074275, -254918697 };
							int[][] array59 = new int[2][] { array57, array58 };
							array58[1] = array59[0][3] ^ -640754458;
							array58[0] ^= 1387226169;
							array58[2] = array58[0] ^ 0x49F87535;
							int num207 = array59[1][1] ^ 0x43BFF97D;
							num193 = ((int)num5 * -323601012) ^ -1165006228 ^ num207;
						}
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num208 = 557710904;
				while (true)
				{
					int num3 = num208;
					uint num5;
					uint num4 = (num5 = (uint)((((~(2100204517 + -865830811) - 306661243) * -1190475465 - ~(~(~(-num3 * -1122873841)))) * 1631187285) ^ -140790248)) % 3;
					uint num209 = num4;
					int num210 = -1544385774;
					_ = 0;
					for (int num211 = 0; num211 < 2; num211++)
					{
						num210 = num210 * 411352373 - -1877248242;
						num210 = -num210 - 870581102;
					}
					if (num209 == (uint)num210)
					{
						break;
					}
					uint num212 = num4;
					int num213 = 868597388;
					_ = 0;
					for (int num214 = 0; num214 < 1; num214++)
					{
						num213 ^= 0x33C5BE8D;
					}
					if (num212 != (uint)num213)
					{
						uint num215 = num4;
						int num216 = -1;
						_ = 0;
						for (int num217 = 0; num217 < 1; num217++)
						{
							num216 = ~num216;
						}
						if (num215 == (uint)num216)
						{
						}
						return;
					}
					_003C_003Et__builder.SetResult();
					int[,] array60 = new int[4, 4];
					array60[0, 0] = -884427521;
					array60[0, 1] = 765068004;
					array60[0, 2] = 308354235;
					array60[0, 3] = -1813862387;
					array60[1, 0] = 1676722863;
					array60[1, 1] = 390900491;
					array60[1, 2] = -15384581;
					array60[1, 3] = 1258161272;
					array60[2, 0] = -1744208284;
					array60[2, 1] = -1217028362;
					array60[2, 2] = 1280807155;
					array60[2, 3] = -450285205;
					array60[3, 0] = -1380253763;
					array60[3, 1] = -917560373;
					array60[3, 2] = -1026053800;
					array60[3, 3] = -1608477273;
					array60[2, 2] = array60[3, 2] ^ -257021134;
					array60[0, 3] = array60[3, 2] ^ 0x55615E13;
					array60[0, 3] = array60[1, 3] ^ -860564953;
					int num218 = array60[0, 3] ^ -603917498;
					num208 = (int)((num5 * 2077105993) ^ 0xAA0D3B5Bu) ^ num218;
				}
			}
		}

		void IAsyncStateMachine.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			this.MoveNext();
		}

		[DebuggerHidden]
		private void SetStateMachine(IAsyncStateMachine stateMachine)
		{
			_003C_003Et__builder.SetStateMachine(stateMachine);
		}

		void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
			this.SetStateMachine(stateMachine);
		}

		static AssemblyProfile _0024_0023_0025_0026_003D_0040_0021_0028(IAssemblyWorkspaceService P_0)
		{
			AssemblyProfile currentProfile = default(AssemblyProfile);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 1950476414;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-((~(-(~(-(~-978997319) - ((-1695629882 ^ 0x5859E09A) + -1711823315)))) ^ -1971874216) - num2 * 1716522571 * 1478530535))) % 3;
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
						int num7 = 73694909;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~(num7 ^ 0x9139C9);
							num7 = num7 * -96085121 + 1679905185;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 251913246;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -(num9 - -263195529 * -1554483205);
								num9 = 1534723998 - (num9 ^ -699126774);
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						currentProfile = P_0.CurrentProfile;
						int[] array = new int[5];
						array[0] = 2024278433;
						array[1] = 739869519;
						array[2] = -1396318893;
						array[3] = -92633727;
						array[4] = -356016483;
						array[1] = array[0] ^ -91583400;
						array[4] = array[0] ^ 0x16940D2E;
						int[] array2 = new int[4];
						array2[0] = 1458892186;
						array2[1] = 1169139857;
						array2[2] = -1977601886;
						array2[3] = -650692157;
						array2[2] = array[0] ^ 0x6A831D37;
						array2[0] = array2[2] ^ -1709170125;
						array2[0] = array2[2] ^ 0x2449E689;
						int num11 = array2[2] ^ 0x2F293945;
						num = (int)((num4 * 527733539) ^ 0xEFB8F3D3u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return currentProfile;
		}

		static string _005E_0026_0040_0021_0028_002B_003E_003D(IStringResourceService P_0, string P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				return P_0.GetString(P_1);
			}
		}

		static bool _0028_0024_0024_0028__005E_003D_0025(ProtectionOptions P_0)
		{
			bool hasAnyEnabled = default(bool);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 2052836990;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(~(-(~(236751021 * (-891903910 ^ -1584603830) + (-690116659 * ~((~-1639113686 - ~1056103267) * 1564490433) + -(642748643 * (-1212590643 * ~(-345092426 * 1278175251)))) - -num2 * 958909913)) + (-1229257323 ^ -(-1888682793 - 944987035 - (0x1FE1D9A1 ^ -421536331)))) + 773600297 * ~-295726624) * 2144036635)) % 3;
						int num5 = -1216775870;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 *= -2067781791;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -63949066;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 += 63949067;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 0;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -num9 * -819845413;
								num9 *= 268735009;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						hasAnyEnabled = P_0.HasAnyEnabled;
						int[,] array = new int[4, 3];
						array[0, 0] = 964829696;
						array[0, 1] = -23190091;
						array[0, 2] = -1841492640;
						array[1, 0] = 1434178070;
						array[1, 1] = 247936131;
						array[1, 2] = 1363621157;
						array[2, 0] = 1849997686;
						array[2, 1] = 1335252217;
						array[2, 2] = 208478838;
						array[3, 0] = -770869702;
						array[3, 1] = 619471536;
						array[3, 2] = 714238139;
						array[1, 2] = array[2, 0] ^ -832677323;
						array[1, 0] = array[2, 2] ^ -252245140;
						array[0, 1] = array[1, 1] ^ -769901350;
						array[3, 1] = array[3, 0] ^ 0xF9CC4DC;
						int num11 = array[3, 1] ^ 0x4282578B;
						num = (int)((num4 * 1734321384) ^ 0xEABEE3B8u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return hasAnyEnabled;
		}

		static bool _0028_002A_002A_0021_002A_0024_0021_0023(ProtectionOptions P_0)
		{
			bool codeVirtualization = default(bool);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -238376540;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(~(~(-(~(~(num2 * 835128917)) ^ ~(--205576726 - (0x2C7C49A0 ^ -2023950768) * -1354346597))))) - (-887176915 - 1390093490))) % 3;
						int num5 = -1843396348;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -(num5 - ~-1158050434);
							num5 = ~(num5 ^ 0x34CB8E2C);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1307407681;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -num7 * 821367061;
							num7 = num7 - (1290305336 - -1377525136) - -334562926;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -2024205960;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 += 2024205962;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						codeVirtualization = P_0.CodeVirtualization;
						int[] array = new int[6];
						array[0] = 1108417723;
						array[1] = -1318201881;
						array[2] = 1031329205;
						array[3] = -365346807;
						array[4] = 1242177391;
						array[5] = 463464380;
						array[4] = array[5] ^ -1561716258;
						array[4] = array[2] ^ 0x2A780E5A;
						array[1] = array[4] ^ -1019973173;
						int[] array2 = new int[7] { -1641548125, -1750612482, 764403825, -1105858001, 732147927, -2014615454, -1248644670 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[2] = array3[0][2] ^ -219318438;
						array2[3] = array2[4] ^ -831598435;
						array2[0] = array2[2] ^ -1749097112;
						int num11 = array3[1][2] ^ -887424563;
						num = (int)((num4 * 1469630684) ^ 0xD6A6939Cu) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return codeVirtualization;
		}

		static long _0028_0029_003C_005E_005E_0021_0029_0024(AssemblyProfile P_0)
		{
			long fileSizeBytes = default(long);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 1513320328;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(((num2 + (-(1202746771 * -563949967) ^ (~((-1641269378 - -(~-1025999154 * 776722491)) ^ -1369320213) * 871456069 - -334019333 * (-684920503 + -(-1953411185 * ((-1405812541 * 170472889) ^ -1738005007)))))) * 2027953815 - ((-(-1449341692 ^ 0x58D888B7) + -145380560) ^ ((-(-(1001909927 - 32875627)) + -1800498379) * 734889013 - (((~(0x494B785C ^ -900510331) - -(-440318474 + -573191685)) ^ (-323941585 * (0x520311EC ^ --1058854231))) + -((0x3F57FB5E ^ 0xB27890B) + 575167137 * -1726079472))))) ^ (~(-(--1509771300) * 1604995903) + (-375995230 * -1764926903 + ~391446303 - 1727033101 - ((0x5D3C20D6 ^ 0x51FEE3CA) + (0x517F0E26 ^ 0x528262AB) - (-439644076 ^ -1051307958))) + -2021688709 * ((-16106776 ^ 0x71F32A95) - (-202334063 * -744919119 - (1687038067 + -987828190) - (-688703543 - ~-1135974695)))) ^ 0x36610419)) % 3;
						int num5 = -851408318;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 ^= 0x391F364B;
							num5 = ~num5 * -1152422575;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -848993045;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~(~num7);
							num7 = (num7 + (-1403024179 - 1212169316)) * -1625918267;
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
						fileSizeBytes = P_0.FileSizeBytes;
						int[] array = new int[4] { -189182393, 1606023005, -1613697106, -1501858516 };
						array[0] ^= -1411002627;
						array[0] = array[1] ^ -486295394;
						int[] array2 = new int[6];
						array2[0] = -1035302093;
						array2[1] = -1414371075;
						array2[2] = 817998780;
						array2[3] = 1719613019;
						array2[4] = 2088626134;
						array2[5] = 1282921171;
						array2[3] = array[2] ^ 0x2859862;
						array2[2] = array2[5] ^ -1563499219;
						array2[1] = array2[4] ^ 0x55D33BC9;
						int num11 = array2[3] ^ 0x5ECEE9DD;
						num = (int)((num4 * 1520139432) ^ 0xC0F0E170u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return fileSizeBytes;
		}

		static byte[] _002A_0028_0023_0023_0023_002A_002D_0040(IAssemblyWorkspaceService P_0, bool P_1)
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
					int num = -1552300198;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((~(-(((1512910979 * (-1078561753 ^ (--1017360912 - --890884521))) ^ 0x5D145096) - -((-((-182155417 - (-1347456566 ^ (1492554616 + ~(--1518921777)))) ^ (-1195089725 * ((--1993814447 + (889747115 - 780723286) + 111752603 * ~1328205745) * 1320314265))) - -(~(-(~(~-1719626185)) + (-728635346 + 1981209829 * --1340713419)) + -807264777 * (--515424629 + (-830781952 + -1395898364) - ~(-623783517 * 1730064572) + (~1637963382 + (0x225AAE77 ^ 0x49674304)) * -994490331)) - -num2) * -328088273))) + -866829475 * (-1248464580 - -927841315)) ^ -70296208 ^ 0x2444AF5A)) % 3;
						int num5 = 1656650601;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 ^= 0x62BE7B69;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -554641667;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 *= -1649379755;
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
						result = P_0.PrepareAssemblyForProtection(P_1);
						int[] array = new int[7];
						array[0] = -1724719062;
						array[1] = -2061661471;
						array[2] = -1238150480;
						array[3] = -1384772926;
						array[4] = 752264622;
						array[5] = 926077513;
						array[6] = -1362373165;
						array[6] = array[5] ^ 0x739F3F9A;
						array[2] = array[3] ^ 0x171EAE22;
						array[1] = array[3] ^ -2048529543;
						int[] array2 = new int[4] { -986156166, 2043080543, 289009139, -60251825 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][4] ^ 0x4036027C;
						array2[0] = array2[1] ^ -1859590595;
						array2[3] = array2[2] ^ -231066721;
						int num11 = array3[1][1] ^ -1900957865;
						num = ((int)num4 * -1416196704) ^ -1833635008 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static string _0023_003E_0023_0026_002B_0021_002B_003D(AssemblyProfile P_0)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				return P_0.FilePath;
			}
		}

		static void _0029_0024_002F_005E_003C_0024_0021_0040(ProtectionRequest P_0, string P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 2050688695;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((((~(((-(1988763007 * --452887173) ^ -(-432738503)) * 1589892061 - num2) * 2131265359 * -813664949) + -((-191314511 ^ 0xEFBD4EA) * -223330479) - -(0x39606BA6 ^ 0xFBB0831)) ^ ((-1536015687 ^ 0x10DDD8E7) + 1316963539 * (-1211544167 * -1278607473))) * 1208141503 + -1314030962) ^ 0x138C7E82)) % 3;
						int num5 = -117700694;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = num5 * 537544749 * -1117013091;
							num5 = -num5 ^ -1994297977;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1983043306;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 *= -283521827;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 931129281;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~(num9 ^ -1362881284);
								num9 = 628639005 - ~num9;
							}
							if (num3 == (uint)num9)
							{
							}
							return;
						}
						P_0.FilePath = P_1;
						int[] array = new int[4];
						array[0] = -1284487519;
						array[1] = -1325063842;
						array[2] = -226027908;
						array[3] = 1921944112;
						array[0] = array[2] ^ 0xD03065A;
						array[0] = array[3] ^ 0x24A98A50;
						array[1] = array[0] ^ 0x5C5462BA;
						int[] array2 = new int[6] { -1589463970, -79616273, 197366216, -1515020038, -1945526080, -366971634 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[4] = array3[0][2] ^ -89043017;
						array2[2] ^= -1186322080;
						array2[5] = array2[4] ^ 0x78963167;
						array2[1] = array2[0] ^ 0x4554C6C;
						int num11 = array3[1][4] ^ -534845229;
						num = ((int)num4 * -909360367) ^ 0x3713662D ^ num11;
					}
				}
			}
		}

		static string _005E_0024_002B_005E_003F__003E_0028(AssemblyProfile P_0)
		{
			string fileExtension = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 1775842542;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-((-(~(~((num2 + ((489245353 * ~(-890899552 ^ -(-(-478255393 ^ --2127356528)))) ^ (-((-12371255 ^ -1376533436) + ~(-1194179902 ^ -22775127) + (--346549446 + ((0x48086861 ^ -833288694) - (-573778565 ^ -208875282)))) + 446817873 - 1157774947 * ~(~((0xFBE89CF ^ -1275435829) - -(--601656034))))) * -389820057) * 1792831)) - 1879299955 * (-440225866 ^ 0x447879DD) - 1853792197) - 1945138579) * -126835495))) % 3;
						int num5 = -20082566;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = (num5 - (1584068572 - 1375189750)) * -1709990857;
							num5 = -(num5 ^ 0x1D1F31F3);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -16179015;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = num7 + (-1726336993 ^ 0x70F3E872) - 230286494;
							num7 -= -608926677;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -118354168;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 ^= 0x1354E732;
								num9 = num9 - ~-2066743651 - -214310078;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						fileExtension = P_0.FileExtension;
						int[] array = new int[7] { 1143129459, -2032168013, -549111121, 729070822, 1932384331, 702744747, -1900594761 };
						array[5] ^= -731307110;
						array[4] = array[6] ^ -533143863;
						int[] array2 = new int[7];
						array2[0] = -2046371485;
						array2[1] = -372472995;
						array2[2] = -86522570;
						array2[3] = -1796912054;
						array2[4] = -1901739678;
						array2[5] = 1637518806;
						array2[6] = -1387207819;
						array2[5] = array[0] ^ 0x38576EC9;
						array2[1] = array2[5] ^ 0xB69DB8E;
						array2[2] = array2[0] ^ -1745753623;
						int num11 = array2[5] ^ -1594163008;
						num = ((int)num4 * -2065388739) ^ 0x3C18AB45 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return fileExtension;
		}

		static void _003D_0024_0040_0040_0024__0023_0040(ProtectionRequest P_0, string P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 456557226;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(((~num2 * -701728091) ^ -73025882) + -(-509299645 * -(0xB6B6ED8 ^ -294668827)) * 892852901 + ~((-(-991427014 - -106942918) + 1902238475) ^ -457210789)))) % 3;
						int num5 = -649175088;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = num5 * 1816111941 * 2058960011;
							num5 = ~((0x6D36F7D8 ^ 0x1D33A41D) - num5);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -2033964567;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 -= -2033964569;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 468831326;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 ^= 0x1BF1CC5F;
							}
							if (num3 == (uint)num9)
							{
							}
							return;
						}
						P_0.FileType = P_1;
						int[] array = new int[6];
						array[0] = -1037162099;
						array[1] = -643335654;
						array[2] = 565673266;
						array[3] = -116129197;
						array[4] = -1376466803;
						array[5] = 584955306;
						array[3] = array[1] ^ -683798899;
						array[4] = array[3] ^ -1225144279;
						int[] array2 = new int[4];
						array2[0] = 2041248349;
						array2[1] = 1963363703;
						array2[2] = 647973993;
						array2[3] = 643098275;
						array2[3] = array[2] ^ -1436831715;
						array2[2] = array2[0] ^ 0x500426E6;
						array2[2] = array2[1] ^ 0x60F92926;
						int num11 = array2[3] ^ -877426163;
						num = (int)((num4 * 856878648) ^ 0xFAA66848u) ^ num11;
					}
				}
			}
		}

		static void _003E_0026_005E_002D_0021_003D__0028(ProtectionRequest P_0, byte[] P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 2106933780;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(((~num2 * 1403541107 - -(~(-(-(1080205972 * -1449032335 - ~-6584570) - (-(628185869 + 1603295260) - -2138741003 * 1616859276 * 1502804869)))) - -(-1438308189 ^ (~(-958954101 ^ 0x52CA62AE) - (~(-1148504517) + (-1814587806 ^ 0x63A30BE) * 702818243))) - ~(~1877041996) - (0x69443AAB ^ -1130057760)) ^ -1530300585) + -767461194) - -1280279391)) % 3;
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
						int num7 = -1;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 = -num7;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1330215478;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -(-1778427444 + -1034163944 - num9);
								num9 = -(-num9);
							}
							if (num3 == (uint)num9)
							{
							}
							return;
						}
						P_0.InputBytes = P_1;
						int[,] array = new int[4, 3];
						array[0, 0] = -2070135376;
						array[0, 1] = 195838503;
						array[0, 2] = 610406871;
						array[1, 0] = -1035121764;
						array[1, 1] = -1584380426;
						array[1, 2] = -2019375459;
						array[2, 0] = 1040213885;
						array[2, 1] = -1856103476;
						array[2, 2] = -470005986;
						array[3, 0] = -1332178434;
						array[3, 1] = -845224201;
						array[3, 2] = 219821519;
						array[1, 1] = array[2, 0] ^ 0x2454CB07;
						array[0, 0] = array[3, 1] ^ -1269835106;
						array[3, 2] = array[2, 0] ^ 0x590C72AD;
						array[1, 0] = array[2, 1] ^ -154028323;
						int num11 = array[1, 0] ^ 0x5AC7945E;
						num = (int)((num4 * 1208290875) ^ 0x2A7BF487) ^ num11;
					}
				}
			}
		}

		static string _005E_0040_003E_0024_0024_0025_005E_002A(IAuthenticationService P_0)
		{
			string currentLicense = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1897831671;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(~(num2 * 1755228533)) - -1762297557 * (0x1189819E ^ -(-(~988708979 * -119632101))))) % 3;
						int num5 = 1511344284;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 ^= 0x5A15489E;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~num7 ^ 0x104275E4;
							num7 = -(-num7);
						}
						if (num3 != (uint)num7)
						{
							int num9 = 965148684;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 ^= 0x2D54B87A;
								num9 = -(num9 - (333365749 - 815958396));
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						currentLicense = P_0.CurrentLicense;
						int[] array = new int[4] { -218524810, -968615956, -732855310, -1623062201 };
						array[1] ^= 1599726765;
						array[3] = array[0] ^ -639794134;
						int[] array2 = new int[5] { 103964148, 1293045745, 1752145649, -615552866, -1067379813 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][2] ^ 0xD3ECC47;
						array2[0] = array2[1] ^ 0x43B36B95;
						array2[3] = array2[1] ^ 0x5C47889D;
						array2[4] = array2[0] ^ 0x709BEA19;
						int num11 = array3[1][1] ^ 0x92C41FC;
						num = (int)((num4 * 687176722) ^ 0xB5B685EEu) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return currentLicense;
		}

		static void _0028_0021_002F_0024_003E_003D_0025_002D(ProtectionRequest P_0, string P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 1428293582;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(((((((~num2 * -2144019053 + -866870443 * ~((0x68CB3029 ^ 0x1A6A91C9) - -(--48747895))) * -859802257) ^ 0x3ADC7FED) * -306150419 - -1647009923) ^ 0x6E41C3E9) - --271500235) * 1821708879)) % 3;
						int num5 = -1908825672;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -(num5 ^ --2074106052);
							num5 *= -475436399;
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
						P_0.License = P_1;
						int[] array = new int[4];
						array[0] = 1201392025;
						array[1] = 2070144858;
						array[2] = 1922541048;
						array[3] = -1780253557;
						array[3] = array[2] ^ -915689956;
						array[0] = array[3] ^ 0x7A883574;
						array[1] = array[3] ^ 0x72B188CE;
						int[] array2 = new int[5] { 1835026952, -894744869, 351397511, 542524777, -1888332910 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][2] ^ -47834868;
						array2[2] = array2[3] ^ -513512859;
						array2[2] = array2[0] ^ -1507531731;
						array2[2] = array2[4] ^ -1205780572;
						int num11 = array3[1][1] ^ -1500904887;
						num = ((int)num4 * -2049341042) ^ 0x76C9111E ^ num11;
					}
				}
			}
		}

		static void _0021_003C_003D_002A_005E_0029_0029_005E(ProtectionRequest P_0, ProtectionOptions P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 520664124;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(~((num2 * 2099861589 - ((-343116147 * -(-(293971202 + -592837246 + 431793382)) + (-47051951 * (~(0x581CAA91 ^ -731125706) + ~(1955719011 - 1634058307)) - ~(~(-1421513246 + 522652679 * 158806801)))) ^ 0x6ACAA929 ^ (-(-((-1701895604 ^ --1111826622) - -(0x55109200 ^ -857097819) + -(-(1738839671 - -1409761598)))) * -1067157407)) + (-(~(-83235103 ^ -1418057493)) + -1302616740 + (~(1149762953 * (1031042755 - 2051745413)) + ~(-(0xF1AF98D ^ -758370935))))) * -636613567 + -(1666699380 + (-1755197726 ^ 0x552AFBE1))) + 1671938513 * ~(-62014813 - 947939294)))) % 3;
						int num5 = -2143567858;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = ~num5 ^ -1445899338;
							num5 = -1234688208 + 1636493480 - num5;
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
							int num9 = 1540632947;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 += -1540632946;
							}
							if (num3 == (uint)num9)
							{
							}
							return;
						}
						P_0.Options = P_1;
						int[,] array = new int[3, 3];
						array[0, 0] = -280860129;
						array[0, 1] = -487816208;
						array[0, 2] = -718306567;
						array[1, 0] = -761407506;
						array[1, 1] = 54300373;
						array[1, 2] = -1907344981;
						array[2, 0] = -2023832892;
						array[2, 1] = 1887203560;
						array[2, 2] = -1834612591;
						array[2, 2] = array[1, 1] ^ -640976143;
						array[2, 0] = array[1, 1] ^ -1011411421;
						array[2, 0] = array[1, 2] ^ 0x7E482BE9;
						int num11 = array[2, 0] ^ 0x199878F2;
						num = (int)((num4 * 155829531) ^ 0x238BA4DB) ^ num11;
					}
				}
			}
		}

		static Task<ProtectionResult> _002F_003E_0029_002A_0040_0028_0040_002B(IProtectionService P_0, ProtectionRequest P_1, IProgress<ProtectionProgress> P_2, CancellationToken P_3)
		{
			Task<ProtectionResult> result = default(Task<ProtectionResult>);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1724717368;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-((~(-(~(1227626131 * (-(~(1912572399 * (-1253727431 * -1397437869 - -305269321 * -397637285 - -(-929481335 ^ 0x79E746DA)))) + ~(~(--1819448854))) * -953439061 - num2 + (-113622730 ^ (-134850980 + -(0x76E6E926 ^ -711807773)))) * -275584427) * -405920087) ^ -(-521936188 ^ 0x1F649C39)) * -2094400167))) % 3;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -(num5 ^ --1218467669);
							num5 = ~(-num5);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 285323333;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = (num7 + --241705565) ^ -174379959;
							num7 = (num7 - -2094598519) ^ 0x606C9E15;
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
						result = P_0.ProtectAsync(P_1, P_2, P_3);
						int[] array = new int[6];
						array[0] = 1804605122;
						array[1] = -829939591;
						array[2] = 240322740;
						array[3] = 1836614643;
						array[4] = -1705873769;
						array[5] = 881921291;
						array[2] = array[1] ^ -191566801;
						array[2] = array[5] ^ -542278492;
						int[] array2 = new int[7] { 1297897173, 1004235314, 1161555516, 486626384, 1994006564, 40119967, -1640258574 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[4] = array3[0][4] ^ 0x340EA8B1;
						array2[3] = array2[2] ^ 0x3D82FA17;
						array2[2] = array2[6] ^ -1619679747;
						array2[3] = array2[1] ^ -310431613;
						int num11 = array3[1][4] ^ -1026868512;
						num = (int)((num4 * 1161402241) ^ 0xC06E29A4u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static bool _0029_0024_0021_003C_003C_003E_0025_0029(ProtectionResult P_0)
		{
			bool ısSuccess = default(bool);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 446233380;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((-((~(~(num2 ^ (-1998933707 * ~(-(~((0x130F5A ^ -1001138450) + (1930678370 + -356763191 - (-1453442245 ^ 0x56BC8C87)) - (-(--637689037) - (~776232858 - ~-60666665))) ^ (0x2FA39ADB ^ -(0x41CC76CD ^ -278487817) ^ (356331734 - -(554503744 - (1804731816 + 1671573391)))))))) - (((0x5976EFAE ^ 0x7CEF8261) + ~(--256020316) + ~(347880699 * -9688741) * -960909913) * -596521305 * 1231946681 - ~((-1392965716 ^ -763874861) * 482251263))) + 821017373 * ~(~(997049176 - -394209762 - (642301542 - -869609213)))) * -1322249139 - -(0x2312FD7A ^ 0x20AD37AA)) + -556582331) ^ -737447536)) % 3;
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
								num9 = ~(num9 * 1091643237);
								num9 = ~num9;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						ısSuccess = P_0.IsSuccess;
						int[,] array = new int[4, 3];
						array[0, 0] = -376564665;
						array[0, 1] = -1555570024;
						array[0, 2] = -903274719;
						array[1, 0] = -148438722;
						array[1, 1] = -1535641132;
						array[1, 2] = -648832387;
						array[2, 0] = -548839251;
						array[2, 1] = 1929710482;
						array[2, 2] = 962256024;
						array[3, 0] = 2072947392;
						array[3, 1] = -1715189950;
						array[3, 2] = -2006187216;
						array[0, 0] = array[2, 1] ^ -1606024134;
						array[2, 1] = array[0, 2] ^ 0x2EFD4BAE;
						array[0, 0] = array[3, 2] ^ -148398528;
						array[0, 0] = array[2, 2] ^ 0x325E0AD;
						int num11 = array[0, 0] ^ 0x313E883;
						num = ((int)num4 * -580564766) ^ 0x65ED84AA ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return ısSuccess;
		}

		static string _005E_003C_003D_0023_003D_005E_005E_0023(ProtectionResult P_0)
		{
			string errorMessage = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1540491808;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(~(((num2 ^ -(115815998 * -1124973027 - ~(0x36AF54CB ^ 0x22089E24) * -542871561)) - -(0x2CAC8942 ^ (((1118047997 + -1397182487 - (0x4F23255E ^ -1227578136) + 308699776 + -(-214101257 - (1662060686 - 1990782793))) ^ (~-697130510 - ~(-678625555) - (-1253268395 * -1467033047 + (0x6185539E ^ 0x3DE6292)))) + (((-(-148341014 ^ -1152348470) + ~(-585634915 + 835025159)) ^ 0x5F884B04) - (-1492555284 + ~(0x377A3D14 ^ -652284928)))))) * 1964683201 * 2138737313 * -837287759)))) % 3;
						int num5 = 1208205798;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 *= 1127495739;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -1526881963;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = --1345074220 - num7;
							num7 = num7 * 1415212075 - 1287211590;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1532667452;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 -= -1532667452;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						errorMessage = P_0.ErrorMessage;
						int[] array = new int[4];
						array[0] = -1330293976;
						array[1] = -1788008431;
						array[2] = -44785675;
						array[3] = -830372735;
						array[0] = array[1] ^ -135367783;
						array[0] = array[1] ^ 0xF4E1FDF;
						int[] array2 = new int[6] { 827275991, 81887982, 1359417611, 931194503, -1305748033, 2048695082 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][1] ^ 0xFE6695E;
						array2[0] = array2[1] ^ 0x3B271C94;
						array2[0] = array2[2] ^ -851987729;
						int num11 = array3[1][1] ^ 0x769FB9FE;
						num = ((int)num4 * -1183805210) ^ -1640358362 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return errorMessage;
		}

		static string @_005E_002B_0026_0021_0023_0029_0028(IStringResourceService P_0, string P_1, object[] P_2)
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
					int num = 1588069889;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-1754192976 - ~(~(-(~(~2032453906 + 1115723155 + (-64604969 - -1685827970 + (141882636 - 261535159))) - (734070883 * -1528569882 - -(-(2143786862 - -1211164354))) - ((((num2 + ~(-1230886247 - -(~(~(~(~(-120298286 ^ 0x3F1758AF)))) - ((0x15D8EAA9 ^ 0x2A70489E) - ~((-979765199 ^ 0xCE0FEA3) - (--1107389955 - ~-1132598787)))))) * 1850517303) ^ (-2029565441 * (0xF7DD652 ^ (-(-940652237) - (-1311577255 + (-1179709769 - -1591213263)) - ((-847166151 + (0x620B8863 ^ -1065977188)) ^ 0x553D84B3))) - (((0xA4704B8 ^ -572319078) - (0x51080479 ^ (-546648942 ^ 0x563F40CA ^ -1470813795))) ^ -((--603617712 - (0x1A43230C ^ 0x41CA2CAE)) ^ -1637737930)))) - 1436823757 * ~(-(~(~1174995446 * 375593869))))) * -1077213425)))) % 3;
						int num5 = -8791872;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = (num5 - (1882939127 - -233500210)) ^ 0x10D716B8;
							num5 = -num5 - 144080693;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1814035458;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -num7 ^ 0x465F191;
							num7 = ~(num7 - ~908758653);
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1362834309;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~(num9 * -2144285363);
								num9 = -num9;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.GetString(P_1, P_2);
						int[] array = new int[4];
						array[0] = 272657371;
						array[1] = 251572158;
						array[2] = 1499074502;
						array[3] = 1812226550;
						array[1] = array[2] ^ -1296004092;
						array[0] = array[1] ^ 0x7A60A383;
						array[0] = array[1] ^ 0x1F4CD02;
						int[] array2 = new int[4];
						array2[0] = 1488007792;
						array2[1] = 1727895662;
						array2[2] = 1743589354;
						array2[3] = 1725086228;
						array2[2] = array[2] ^ 0x7BC27365;
						array2[0] = array2[2] ^ 0x5226BB32;
						array2[3] = array2[0] ^ 0x69D4516C;
						array2[3] ^= 1011577532;
						int num11 = array2[2] ^ -161637874;
						num = (int)((num4 * 1909177818) ^ 0x43EFE380) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static string _002B_002F_0040_002A_003C_002F_005E_0024(ProtectionResult P_0)
		{
			string outputPath = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1434843359;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((0x5BD1C470 ^ 0x69FB5DCE) - (~((~(num2 * 870751085 - (-(-(-800059493 ^ -239370246)) - (-(-(-1589197285 * (-990998022 ^ -2032662402))) + -(~-199054005 * -1761637059 + (-1461516778 ^ -833868072) * 250194065 - (~(-607900459) ^ -(-201024699))) * 271975673))) ^ 0x7E916169) + -(-1710075794 - -(1011678700 + -551271739)) * -840100239) - 1691739593 * (-677552943 + ~-2003472570) - ~-1188674099) - -1195786599)) % 3;
						int num5 = 68260704;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = (num5 ^ -500891609) * -727642611;
							num5 = num5 + -1687542766 - 2143818993;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -596851506;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 *= 1350801751;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 2106745225;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = num9 ^ 0x6F9F1AB1 ^ -278404519;
								num9 = (num9 + -447074975 * 1394947767) * -381117305;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						outputPath = P_0.OutputPath;
						int[] array = new int[4];
						array[0] = 864644399;
						array[1] = 1620231147;
						array[2] = 676429294;
						array[3] = -205226951;
						array[1] = array[3] ^ -1377728279;
						array[0] = array[2] ^ -946164003;
						int[] array2 = new int[5] { -74210830, -881249983, 1892266920, -1186595800, -448234775 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][3] ^ -345305196;
						array2[3] = array2[4] ^ 0x53B7BFE5;
						array2[3] ^= 411663557;
						int num11 = array3[1][1] ^ 0x45660357;
						num = ((int)num4 * -1931347817) ^ 0x7FE3814 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return outputPath;
		}
	}

	private const int NormalAntiTamperModeIndex = 0;

	private const int JitAntiTamperModeIndex = 1;

	private const long StandardSizeLimit = 524288000L;

	private readonly IAssemblyWorkspaceService _assemblyWorkspaceService;

	private readonly IAuthenticationService _authenticationService;

	private readonly IFilePickerService _filePickerService;

	private readonly IProtectionService _protectionService;

	private readonly IStringResourceService _strings;

	private bool _antiTamper;

	private int _antiTamperModeIndex;

	private bool _antiVm;

	private string _assemblyName = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x8EF ^ 0x997];

	private string _assemblyPath = string.Empty;

	private string _busyStep = string.Empty;

	private double _busyProgressValue;

	private bool _codeVirtualization;

	private bool _controlFlowObfuscation;

	private string _fileSizeDisplay = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xCE8 ^ 0xD91];

	private bool _hasLoadedAssembly;

	private bool _hasSdkReference;

	private bool _isBusy;

	private bool _libraryMode;

	private bool _referenceProxy;

	private bool _resourceProtection;

	private string _runtimeDisplay = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x14316 ^ 0x1426E))];

	private SeverityLevel _statusLevel;

	private string _statusMessage = string.Empty;

	private bool _stringEncryption;

	private bool _symbolRenaming;

	public bool AntiTamper
	{
		get
		{
			return _antiTamper;
		}
		set
		{
			if (!SetProperty(ref _antiTamper, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x145A4 ^ 0x144DE))]))
			{
				return;
			}
			while (true)
			{
				int num = 1207496667;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(-(-2047053842 * -1253082277) - ((-170088703 ^ -101052833) - ~-270365617) * 1244928869 - (-((num2 ^ (((-(~(-(0x2F5BA84D ^ 0x7062F214))) * 1253195067 - (-1679555326 + ~226384014 + -787700067 + ((-872194164 ^ 0x9D86AED) + (1918982066 - 584938198) - ~(594770476 - -581796640)) - ~(-(328856361 + 1847336882 - -783103448)))) ^ (1185448996 + -(1439014747 * ~(-237832776 ^ 0x7D850712)))) - ((((0x475D6027 ^ 0x1006FC4A) - (447984446 + -1807434845)) * -1291986261 + (-(-(~-1933782368) ^ 0x22DD8135) + --1476542360 * -611679741)) ^ 0x4B66BA3) - (323921583 + (-262969796 - (~421998289 + -77697241 * -800432087 - (-1979720798 ^ -1679175693) - (-1090747637 ^ -547906146) - ((-928178876 + 525421322) * -323328783 - -(-570018990 ^ 0x2CFE5225))))) * 1084038527)) * 2147474927 * 1610460839) + -((-1500434931 ^ 0x393153E4) + ((0x43492B81 ^ -1937923769) - -(-59655411)))) - ((-1708585693 ^ -1622671993) + (1305470799 + -958077474) - (-827527597 - -185824005 - (845797265 - -254860225))))) - -599016137)) % 3;
					int num5 = -699366632;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= -699366632;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 ^ 0x527B476;
						num7 = num7 ^ -2061062839 ^ 0xDEDD9FD;
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
					_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[431 - 9 - 13 - 30]);
					int[,] array = new int[4, 4]
					{
						{ 617366860, -662188144, 1608318759, -1725476452 },
						{ -2144274066, -2057725453, -1909528632, 1090449112 },
						{ -1504447198, -1201817440, 142286996, -685047704 },
						{ -683469370, -233363562, 1450363695, 1922573747 }
					};
					array[2, 1] ^= -1916621233;
					array[1, 0] = array[1, 2] ^ 0x700DC78D;
					array[1, 3] = array[0, 3] ^ 0x4F5EC7A6;
					int num11 = array[1, 3] ^ -680592332;
					num = (int)((num4 * 400642814) ^ 0xCCE75AAEu) ^ num11;
				}
			}
		}
	}

	public int AntiTamperModeIndex
	{
		get
		{
			return _antiTamperModeIndex;
		}
		set
		{
			SetProperty(ref _antiTamperModeIndex, (value == 1) ? 1 : 0, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x14676 ^ 0x1470A))]);
		}
	}

	public string AntiTamperModeAutomationName => _003E_0021_0040_003F_005E_003D_0024_0025(_strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x7CA6 ^ 0x7DDB]);

	public string AntiTamperToggleAutomationName => _003E_0021_0040_003F_005E_003D_0024_0025(_strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-489 + 106)]);

	public bool AntiVm
	{
		get
		{
			return _antiVm;
		}
		set
		{
			if (!SetProperty(ref _antiVm, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[450 - 42 - 9 - 16]))
			{
				return;
			}
			while (true)
			{
				int num = 1821028367;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(1267323746 + (-1215314996 - ((0x3AFE8959 ^ 0x2738CBA2) + -1686172798) - ((-1403191026 ^ -1750415634) + (-553697676 + -1988738306 + (0x2A32AE0F ^ 0x294BBB46)))) - -(~(~num2 + (~(-((-1074376019 * (-782300637 * 1299606471) - -(-1092496746 - 1580301415) - 1514174413 * -379425498) ^ -(-(1536512021 - -1412877196) ^ -(~1768900139)))) + ((((-1777566722 ^ (1206446127 - ((-1274406404 ^ 0x6DAFB901) - -52644283))) * 23441787) ^ -1611231060) - ~(-1520686417 * (~(~959617796) - (0x6766E76E ^ -256338514)) - ~582222293))))))) % 3;
					int num5 = -1823584968;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 ^= -1349796803;
						num5 = (num5 ^ -1075218778) * 1960951977;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -2031313433;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -2031313435;
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
					_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[1972 - 1620 + 27]);
					int[,] array = new int[3, 4];
					array[0, 0] = -1301321619;
					array[0, 1] = 1712243553;
					array[0, 2] = -1310337194;
					array[0, 3] = 1867381755;
					array[1, 0] = -1017606095;
					array[1, 1] = 340408504;
					array[1, 2] = -332168360;
					array[1, 3] = -189276279;
					array[2, 0] = 1541546393;
					array[2, 1] = 1665356393;
					array[2, 2] = 1161009834;
					array[2, 3] = 184612417;
					array[1, 2] = array[2, 1] ^ 0x5C99E0E9;
					array[0, 2] = array[0, 0] ^ 0x2FACB9E8;
					array[0, 2] = array[1, 1] ^ 0x218B5E0A;
					int num11 = array[0, 2] ^ 0x59EF51F3;
					num = ((int)num4 * -86444460) ^ 0x17B0AF64 ^ num11;
				}
			}
		}
	}

	public unsafe string AssemblyName
	{
		get
		{
			return _assemblyName;
		}
		private set
		{
			SetProperty(ref _assemblyName, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(396 + sizeof(int)) ^ sizeof(Guid)]);
		}
	}

	public string AssemblyPath
	{
		get
		{
			return _assemblyPath;
		}
		private set
		{
			SetProperty(ref _assemblyPath, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xA141 ^ 0xA0C0]);
		}
	}

	public AppViewModel AppViewModel { get; }

	public IAsyncRelayCommand BrowseAssemblyCommand { get; }

	public string BusyStep
	{
		get
		{
			return _busyStep;
		}
		private set
		{
			SetProperty(ref _busyStep, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xDDC ^ 0xC5E]);
		}
	}

	public double BusyProgressValue
	{
		get
		{
			return _busyProgressValue;
		}
		private set
		{
			SetProperty(ref _busyProgressValue, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[444 - 9 - 14 - 34]);
		}
	}

	public bool CanAccessMethodExplorer
	{
		get
		{
			if (HasLoadedAssembly)
			{
				uint num3;
				while (true)
				{
					int num = 1707393990;
					while (true)
					{
						int num2 = num;
						uint num4;
						num3 = (num4 = (uint)(((num2 - ((-(-1762088355 ^ -180920894) - -(-(-1985070378 + -1856723931) - -(-1825442813 * 1703613315)) - -104861709) * -1709990611 + ((-(~(-1121165813) - -(515619972 - -1589653038)) + (-(~(-2091697650 * -2132586619)) + 654953923 * -1541840936) + (~(--1192220413 * -519210421 - (120607984 * 2109874075 + (0x6C86C29D ^ 0x786DFD81))) ^ (-1381653507 * (-1930167441 * (-1807694809 ^ 0x6FBC0DC2))))) ^ -815918611) + ((-1744898650 ^ (-(~-912682427) + -(-2078803680 ^ -186494775) - (-(524716912 - -1851536209) ^ 0x7B5B90C))) + -(-1538537851 * (-1642824478 ^ -406772343) - (~-995785590 + (648951475 - 1240925875)) - -2079313094) - (-822791232 ^ -920537668) - (-(0x2A96BCB9 ^ 0x12189B42) - 169718367)))) * -2066479655 * -1377581673 * 1602161855) ^ (-1661862581 + 33613555 * (0x2630D18B ^ -(~-1334751230))))) % 5;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 *= 1877264183;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1290012378;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = num7 * 1181918419 - 1190130853;
							num7 = ~(num7 * 1202420391);
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~num9 + -1577513421;
								num9 = ~(~num9);
							}
							if (num3 != (uint)num9)
							{
								goto end_IL_000e;
							}
							bool codeVirtualization = CodeVirtualization;
							int[,] array = new int[3, 3];
							array[0, 0] = -460803108;
							array[0, 1] = 1611171776;
							array[0, 2] = -276505203;
							array[1, 0] = 2104467841;
							array[1, 1] = 1055896511;
							array[1, 2] = -923810667;
							array[2, 0] = -2109854329;
							array[2, 1] = 231697954;
							array[2, 2] = 1491442986;
							array[0, 0] = array[2, 1] ^ 0x2CC9B5CB;
							array[0, 0] = array[0, 1] ^ 0x4FAFAB46;
							array[1, 0] = array[1, 1] ^ 0x75242C58;
							int num11 = array[1, 0] ^ 0x3627F9B;
							int[,] array2 = new int[4, 3];
							array2[0, 0] = 1874461437;
							array2[0, 1] = 1045254772;
							array2[0, 2] = 535902824;
							array2[1, 0] = 1086743430;
							array2[1, 1] = 1598170920;
							array2[1, 2] = 2056176937;
							array2[2, 0] = 11433010;
							array2[2, 1] = 2044334653;
							array2[2, 2] = 2084212784;
							array2[3, 0] = 236113173;
							array2[3, 1] = -726243108;
							array2[3, 2] = 1125659153;
							array2[0, 2] = array2[2, 2] ^ 0x30F2B5CC;
							array2[2, 0] = array2[1, 1] ^ 0x3039BE28;
							array2[3, 1] = array2[0, 0] ^ 0x4DDAD018;
							array2[2, 0] = array2[1, 0] ^ 0x66A0EBA4;
							int num12 = array2[2, 0] ^ -334068852;
							int num13 = ((int)num4 * -954476136) ^ -1360021336;
							num11 ^= num13;
							num12 ^= num13;
							int num14;
							int num15;
							if (codeVirtualization)
							{
								num14 = num12;
								num15 = num14;
							}
							else
							{
								num14 = num11;
								num15 = num14;
							}
							num = num14 ^ num13;
							continue;
						}
						bool ısBusy = IsBusy;
						int[] array3 = new int[7];
						array3[0] = 1873733588;
						array3[1] = -608413002;
						array3[2] = 287816913;
						array3[3] = -227808346;
						array3[4] = -828376782;
						array3[5] = -1200862156;
						array3[6] = 1348259182;
						array3[5] = array3[4] ^ -609252944;
						array3[2] = array3[6] ^ 0x60030AF5;
						int[] array4 = new int[5];
						array4[0] = 315361414;
						array4[1] = 529972134;
						array4[2] = -1750571351;
						array4[3] = 990854216;
						array4[4] = 84995905;
						array4[4] = array3[0] ^ -1544971739;
						array4[1] = array4[0] ^ 0x1DD42B3E;
						array4[0] = array4[2] ^ -2068842062;
						array4[1] ^= 1717523316;
						int num16 = array4[4] ^ -2064736883;
						int[] array5 = new int[7];
						array5[0] = 1024158603;
						array5[1] = -1224730402;
						array5[2] = 1635519239;
						array5[3] = -1228468714;
						array5[4] = -1331721502;
						array5[5] = -1773729385;
						array5[6] = 174700783;
						array5[5] = array5[1] ^ 0x2070CE4A;
						array5[5] = array5[6] ^ -2043661928;
						array5[3] = array5[4] ^ -1306719951;
						int[] array6 = new int[6] { 633625225, -1061670169, 799019926, -1848588194, -1482505459, 1148583300 };
						int[][] array7 = new int[2][] { array5, array6 };
						array6[4] = array7[0][1] ^ -978122216;
						array6[5] = array6[2] ^ 0x3A39AB5F;
						array6[2] = array6[3] ^ -2145262712;
						int num17 = array7[1][4] ^ -1497240683;
						int num18 = (int)(num4 * 212983809) ^ -719763644;
						num16 ^= num18;
						num17 ^= num18;
						int num19;
						int num20;
						if (!ısBusy)
						{
							num19 = num17;
							num20 = num19;
						}
						else
						{
							num19 = num16;
							num20 = num19;
						}
						num = num19 ^ num18;
					}
					continue;
					end_IL_000e:
					break;
				}
				int num21 = 1623261155;
				_ = 0;
				for (int num22 = 0; num22 < 2; num22++)
				{
					num21 = -num21 ^ 0x45B766DC;
					num21 = (num21 ^ -1743002396) - 275990382;
				}
				if (num3 == (uint)num21)
				{
					return HasSdkReference;
				}
				int num23 = 2088742061;
				_ = 0;
				for (int num24 = 0; num24 < 1; num24++)
				{
					num23 += -2088742057;
				}
				if (num3 == (uint)num23)
				{
				}
			}
			return false;
		}
	}

	public bool CodeVirtualization
	{
		get
		{
			return _codeVirtualization;
		}
		set
		{
			bool newValue = value;
			while (true)
			{
				int num = -1597391334;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(--1656341682 - (0x364E6F4F ^ 0x5E6B298C)) - (-(~-1630057087) + (1847763942 - 1709338783 * 1807016287)) - ~(-(~(-1402647595 * (416830335 * -902249074) * -1836510153)) - ((~-1297302006 - (-585991830 - ~-180096826) + (-1593315674 + 1863903688) * -345767993) ^ 0x66DB6D4D) - (num2 * -2009380553 - ((2016263461 * (1281897719 * (-739073021 * -1758635439)) + ((0x37FB6D58 ^ 0x49AF9DAE) + (0x1CF57F39 ^ 0x2CF9579A) * 441226177)) * -263215265 * 1161560359 + (-(2122387367 * (~(-914920478 ^ -1245120509) * 1194342421)) - -1265579828)) - (~(-1633860979 * ~-1324566040 - (0x7D24EC3F ^ (((-1303771444 ^ -1622549488) + --1848231339) ^ ~(-242735014)))) - -357116907)))) ^ -(0x78B1A940 ^ -319967935))) % 12;
					int num5 = 1200251438;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 1200251428;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7;
						num7 = num7 ^ 0x4CE7069E ^ 0x752FB893;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -148249455;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 * 382552787 - -1998667720;
							num9 *= -1828771909;
						}
						if (num3 != (uint)num9)
						{
							int num11 = -4;
							_ = 0;
							for (int num12 = 0; num12 < 1; num12++)
							{
								num11 = -num11;
							}
							if (num3 != (uint)num11)
							{
								int num13 = 91389754;
								_ = 0;
								for (int num14 = 0; num14 < 2; num14++)
								{
									num13 = -num13 * -582610499;
									num13 = num13 - ~-1667919390 + -403741381;
								}
								if (num3 != (uint)num13)
								{
									int num15 = 425050346;
									_ = 0;
									for (int num16 = 0; num16 < 2; num16++)
									{
										num15 = (num15 ^ -2058455923) - 1439604615;
										num15 = (num15 * -473325147) ^ 0x3CD0C6C5;
									}
									if (num3 != (uint)num15)
									{
										int num17 = 1079984558;
										_ = 0;
										for (int num18 = 0; num18 < 2; num18++)
										{
											num17 = num17 * 139240297 - -27387385;
											num17 = (num17 - (2039937032 - 1789945328)) * -1733485903;
										}
										if (num3 != (uint)num17)
										{
											int num19 = -552624155;
											_ = 0;
											for (int num20 = 0; num20 < 2; num20++)
											{
												num19 ^= --865006617;
												num19 = ~735497230 - num19;
											}
											int num32;
											if (num3 != (uint)num19)
											{
												int num21 = 1883233111;
												_ = 0;
												for (int num22 = 0; num22 < 1; num22++)
												{
													num21 *= 600490705;
												}
												if (num3 != (uint)num21)
												{
													int num23 = -6;
													_ = 0;
													for (int num24 = 0; num24 < 1; num24++)
													{
														num23 = -num23;
													}
													if (num3 != (uint)num23)
													{
														int num25 = 1001501723;
														_ = 0;
														for (int num26 = 0; num26 < 2; num26++)
														{
															num25 = ~num25;
															num25 = ~num25 * 1932025673;
														}
														if (num3 != (uint)num25)
														{
															int num27 = 2088365057;
															_ = 0;
															for (int num28 = 0; num28 < 2; num28++)
															{
																num27 = -num27 ^ -1205173189;
																num27 = -(num27 - (0xE0DAE78 ^ -808574077));
															}
															if (num3 == (uint)num27)
															{
															}
															return;
														}
														_003C_0024_0029_002A_002D_0021_003E_0028(OpenMethodExplorerCommand);
														int[] array = new int[4] { -1020302040, -1063335909, 567136790, -168788328 };
														array[1] ^= 2093398040;
														array[2] = array[0] ^ 0x27028828;
														array[1] ^= -56052286;
														int[] array2 = new int[7] { 1204008673, -1331074663, -167197682, 969644215, 1406782106, 316828118, -1063974572 };
														int[][] array3 = new int[2][] { array, array2 };
														array2[5] = array3[0][3] ^ 0x15122EFB;
														array2[6] = array2[5] ^ 0x6BC06974;
														array2[1] = array2[3] ^ -1089934097;
														array2[4] = array2[3] ^ -172645722;
														int num29 = array3[1][5] ^ -482719377;
														num = ((int)num4 * -706838043) ^ -695885833 ^ num29;
													}
													else
													{
														_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4099 - 4170 + 86]);
														int[] array4 = new int[5];
														array4[0] = 482262640;
														array4[1] = -696495820;
														array4[2] = -754114325;
														array4[3] = 195551793;
														array4[4] = 107467079;
														array4[1] = array4[2] ^ 0x18BE3CF8;
														array4[2] ^= -1340246963;
														array4[2] = array4[4] ^ 0x6C3C3F78;
														int[] array5 = new int[5] { 2094311687, 586651718, -211808306, -668390464, -1137257165 };
														int[][] array6 = new int[2][] { array4, array5 };
														array5[4] = array6[0][3] ^ 0x3CD2FBDC;
														array5[2] = array5[1] ^ -1228293651;
														array5[3] = array5[2] ^ 0x37755639;
														array5[2] = array5[4] ^ -1022733752;
														int num30 = array6[1][4] ^ -215769845;
														num = ((int)num4 * -1909206265) ^ -939229298 ^ num30;
													}
												}
												else
												{
													_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x160F7 ^ 0x1618C))]);
													int[,] array7 = new int[4, 4];
													array7[0, 0] = 848268650;
													array7[0, 1] = 1400579261;
													array7[0, 2] = -1644855098;
													array7[0, 3] = -544917133;
													array7[1, 0] = -1507996411;
													array7[1, 1] = 1844244513;
													array7[1, 2] = -1375662241;
													array7[1, 3] = -62568042;
													array7[2, 0] = 653658436;
													array7[2, 1] = 2038026656;
													array7[2, 2] = -1067785197;
													array7[2, 3] = 440796523;
													array7[3, 0] = 1177042539;
													array7[3, 1] = 1931979648;
													array7[3, 2] = -276453949;
													array7[3, 3] = -612573723;
													array7[1, 0] = array7[0, 0] ^ 0x407D2FCF;
													array7[2, 0] = array7[3, 0] ^ -1665074372;
													array7[2, 1] = array7[0, 3] ^ -340406981;
													array7[3, 0] = array7[1, 1] ^ 0x22D87F81;
													int num31 = array7[3, 0] ^ 0x7103A2E7;
													num = (int)((num4 * 1682635786) ^ 0xF5825E8Eu) ^ num31;
												}
											}
											else if (SetProperty(ref _codeVirtualization, newValue, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-293 + 276)]))
											{
												num = 1706583350;
												num32 = num;
											}
											else
											{
												num = 64493836;
												num32 = num;
											}
										}
										else
										{
											AppViewModel.AddActivity(_003E_0021_0040_003F_005E_003D_0024_0025(_strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-403 + 14)]), SeverityLevel.Warning);
											int[] array8 = new int[5];
											array8[0] = 88866984;
											array8[1] = -581825373;
											array8[2] = -1910119961;
											array8[3] = 1575544534;
											array8[4] = 1938249622;
											array8[3] = array8[1] ^ -1630730859;
											array8[4] = array8[1] ^ 0xF1C135A;
											array8[0] ^= -1370541867;
											int[] array9 = new int[4] { 606589031, -1667164272, -1061337762, -666229432 };
											int[][] array10 = new int[2][] { array8, array9 };
											array9[0] = array10[0][1] ^ 0x5D9D9A22;
											array9[2] = array9[0] ^ -1841822248;
											array9[1] ^= -92477849;
											int num33 = array10[1][0] ^ 0x7087E131;
											num = (int)((num4 * 562409341) ^ 0xA7247C68u) ^ num33;
										}
									}
									else
									{
										SetStatus(_003E_0021_0040_003F_005E_003D_0024_0025(_strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-601 + 212)]), SeverityLevel.Warning);
										int[,] array11 = new int[4, 4];
										array11[0, 0] = -960007103;
										array11[0, 1] = 709649172;
										array11[0, 2] = -1744487503;
										array11[0, 3] = -184426995;
										array11[1, 0] = 1641933294;
										array11[1, 1] = 2145881954;
										array11[1, 2] = 818165843;
										array11[1, 3] = 1291214499;
										array11[2, 0] = 694181842;
										array11[2, 1] = -1726251399;
										array11[2, 2] = -1226497731;
										array11[2, 3] = -1841612256;
										array11[3, 0] = -1621910955;
										array11[3, 1] = -987643219;
										array11[3, 2] = 249783339;
										array11[3, 3] = 1392487171;
										array11[2, 0] = array11[1, 3] ^ -2131735722;
										array11[2, 0] = array11[3, 2] ^ 0x6A92A1D4;
										array11[2, 0] = array11[0, 2] ^ -1198118262;
										int num34 = array11[2, 0] ^ 0xDD2B94A;
										num = (int)((num4 * 293127646) ^ 0xB17ED5A0u) ^ num34;
									}
								}
								else
								{
									newValue = false;
									int[,] array12 = new int[4, 4];
									array12[0, 0] = 1536690112;
									array12[0, 1] = 291136081;
									array12[0, 2] = -1393159718;
									array12[0, 3] = -294910611;
									array12[1, 0] = 907376886;
									array12[1, 1] = 782621371;
									array12[1, 2] = -1865636133;
									array12[1, 3] = 2054963996;
									array12[2, 0] = -1440130494;
									array12[2, 1] = -1823704247;
									array12[2, 2] = -1442515758;
									array12[2, 3] = -1863620082;
									array12[3, 0] = 1254521266;
									array12[3, 1] = -1219674116;
									array12[3, 2] = -671064713;
									array12[3, 3] = 1771929992;
									array12[3, 2] = array12[1, 0] ^ 0x2C631B67;
									array12[1, 2] = array12[1, 1] ^ 0x507DC03B;
									array12[3, 0] = array12[2, 1] ^ -1413008228;
									array12[3, 2] = array12[1, 0] ^ 0x1E4CEE01;
									int num35 = array12[3, 2] ^ 0x4AF914FE;
									num = (int)((num4 * 2036995579) ^ 0x2C5F9EA2) ^ num35;
								}
							}
							else
							{
								bool hasSdkReference = HasSdkReference;
								int[,] array13 = new int[3, 3];
								array13[0, 0] = 1483137909;
								array13[0, 1] = 1396289309;
								array13[0, 2] = -2140511738;
								array13[1, 0] = -1853060704;
								array13[1, 1] = -2087650246;
								array13[1, 2] = 1171020649;
								array13[2, 0] = -426124985;
								array13[2, 1] = -658792521;
								array13[2, 2] = -1611613325;
								array13[2, 0] = array13[1, 1] ^ 0x524233EC;
								array13[1, 1] = array13[0, 0] ^ -903420692;
								array13[1, 2] = array13[2, 2] ^ -2061024553;
								array13[1, 0] = array13[0, 2] ^ -950868322;
								int num36 = array13[1, 0] ^ -1217334488;
								int[,] array14 = new int[4, 3];
								array14[0, 0] = -2122297824;
								array14[0, 1] = -1877310183;
								array14[0, 2] = 1938740412;
								array14[1, 0] = -1450368795;
								array14[1, 1] = 536074359;
								array14[1, 2] = 705192665;
								array14[2, 0] = 47068211;
								array14[2, 1] = -1134436236;
								array14[2, 2] = 333038358;
								array14[3, 0] = -2018227918;
								array14[3, 1] = -388131418;
								array14[3, 2] = 781184611;
								array14[0, 0] = array14[3, 2] ^ 0x23E3BC6E;
								array14[2, 0] = array14[0, 0] ^ 0x2D8F9141;
								array14[2, 2] = array14[0, 0] ^ -1589214385;
								array14[0, 2] = array14[3, 1] ^ -890524002;
								int num37 = array14[0, 2] ^ -319111013;
								int num38 = ((int)num4 * -690450610) ^ 0x604D1CB8;
								num36 ^= num38;
								num37 ^= num38;
								int num39;
								int num40;
								if (!hasSdkReference)
								{
									num39 = num37;
									num40 = num39;
								}
								else
								{
									num39 = num36;
									num40 = num39;
								}
								num = num39 ^ num38;
							}
						}
						else
						{
							bool hasLoadedAssembly = HasLoadedAssembly;
							int[,] array15 = new int[3, 3];
							array15[0, 0] = -549979015;
							array15[0, 1] = 425592598;
							array15[0, 2] = 650836882;
							array15[1, 0] = 1316791073;
							array15[1, 1] = -575627379;
							array15[1, 2] = 1393850359;
							array15[2, 0] = -1491204433;
							array15[2, 1] = 1620611398;
							array15[2, 2] = 484963689;
							array15[1, 1] = array15[0, 2] ^ -1531772302;
							array15[1, 0] = array15[1, 2] ^ -911921662;
							array15[0, 2] = array15[0, 1] ^ -393979424;
							int num41 = array15[0, 2] ^ 0x1922946;
							int[,] array16 = new int[3, 4]
							{
								{ 1953849130, 738030767, 1395188041, 1211891247 },
								{ 2075615293, 2015765155, 458452220, -510449826 },
								{ 424624083, -1878424278, -1375001029, -414409262 }
							};
							array16[0, 0] ^= -2076209105;
							array16[2, 0] = array16[0, 0] ^ -1712858842;
							array16[1, 0] = array16[2, 2] ^ -1718207151;
							array16[0, 0] = array16[2, 1] ^ 0x256A129A;
							int num42 = array16[0, 0] ^ 0xD8E325;
							int num43 = ((int)num4 * -2121507436) ^ 0xBDACE04;
							num41 ^= num43;
							num42 ^= num43;
							int num44;
							int num45;
							if (hasLoadedAssembly)
							{
								num44 = num42;
								num45 = num44;
							}
							else
							{
								num44 = num41;
								num45 = num44;
							}
							num = num44 ^ num43;
						}
					}
					else
					{
						int[] array17 = new int[7];
						array17[0] = -698027460;
						array17[1] = -1020401375;
						array17[2] = -535647740;
						array17[3] = -1886558784;
						array17[4] = 1672207206;
						array17[5] = -256759129;
						array17[6] = -1795363164;
						array17[3] = array17[5] ^ 0x67EF5FAF;
						array17[3] = array17[1] ^ -644630917;
						array17[5] = array17[1] ^ 0x306A9FE3;
						int[] array18 = new int[4] { 1537964631, 2106327041, 2097425278, -1618557985 };
						int[][] array19 = new int[2][] { array17, array18 };
						array18[2] = array19[0][4] ^ -927549570;
						array18[3] = array18[0] ^ 0xCAE68C3;
						array18[0] ^= 159217934;
						array18[0] = array18[2] ^ 0x7997D312;
						int num46 = array19[1][2] ^ 0x5B551BA8;
						int[] array20 = new int[6];
						array20[0] = -1468426411;
						array20[1] = 930886162;
						array20[2] = 1254295769;
						array20[3] = 649579400;
						array20[4] = 615953631;
						array20[5] = -1348216974;
						array20[5] = array20[0] ^ 0x38CDA451;
						array20[3] = array20[5] ^ -446054445;
						array20[5] = array20[4] ^ 0x4412868B;
						int[] array21 = new int[4] { 2114525873, 1420328046, -1426479522, -1064910361 };
						int[][] array22 = new int[2][] { array20, array21 };
						array21[0] = array22[0][1] ^ -1746244129;
						array21[2] = array21[1] ^ 0x76CFB7D0;
						array21[2] = array21[0] ^ -1783298885;
						int num47 = array22[1][0] ^ 0x4DE5EB79;
						int num48 = ((int)num4 * -2038330567) ^ 0x3F6D1EDF;
						num46 ^= num48;
						num47 ^= num48;
						int num49;
						int num50;
						if (value)
						{
							num49 = num47;
							num50 = num49;
						}
						else
						{
							num49 = num46;
							num50 = num49;
						}
						num = num49 ^ num48;
					}
				}
			}
		}
	}

	public bool ControlFlowObfuscation
	{
		get
		{
			return _controlFlowObfuscation;
		}
		set
		{
			if (!SetProperty(ref _controlFlowObfuscation, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-536 + 146)]))
			{
				return;
			}
			while (true)
			{
				int num = 985617665;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((~((~(1834688401 * (~(-2085277824 ^ -1857372287) - 1617826187 * (636753281 * -683132403))) - (~((num2 ^ (~(-141793237 ^ -(~-494843394)) - (890810206 * 1378434131 - -1321481377 * (-484063655 ^ (-(-1919260455 * (-94874895 + -2143845576)) * -1865171711))))) + ~(-1674082372 - (-(--247819637) - -1107950027 * -806998555 * -1451680005))) + ~(~(0x15D08E08 ^ -1130688813)))) * 1578664117) + 1861703673 * (-1730326435 - -1628617020)) * -1329138455))) % 3;
					int num5 = -799004540;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 + ~1378077362) ^ 0x68F23661;
						num5 = ~num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1553459137;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 - --1518620705) * 1285823817;
						num7 = (num7 * 252960805) ^ -1719568191;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 - 1421192659 - -1105284685;
							num9 = ~(num9 - (925040392 - -336227874));
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[451 - 3 - 42 - 27]);
					int[,] array = new int[4, 3];
					array[0, 0] = -1774850252;
					array[0, 1] = 1292865026;
					array[0, 2] = 1563320989;
					array[1, 0] = 812048115;
					array[1, 1] = -355567570;
					array[1, 2] = 1511661232;
					array[2, 0] = 14820913;
					array[2, 1] = -1860753256;
					array[2, 2] = 1855732522;
					array[3, 0] = 1099532952;
					array[3, 1] = -1849953290;
					array[3, 2] = 1333095891;
					array[3, 2] = array[1, 2] ^ 0xB0768D6;
					array[3, 0] = array[1, 2] ^ -1377289534;
					array[2, 0] = array[0, 1] ^ 0x3A6DD7BE;
					array[2, 1] = array[0, 2] ^ 0x590ED29E;
					int num11 = array[2, 1] ^ 0x75CF86A9;
					num = (int)((num4 * 1422441029) ^ 0x50BC56B) ^ num11;
				}
			}
		}
	}

	public int EnabledFeatureCount => _0028_0026_0025_003F_0024_002A_002F_005E(BuildOptions());

	public string FileSizeDisplay
	{
		get
		{
			return _fileSizeDisplay;
		}
		private set
		{
			SetProperty(ref _fileSizeDisplay, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-598 + 207)]);
		}
	}

	public bool HasLoadedAssembly
	{
		get
		{
			return _hasLoadedAssembly;
		}
		private set
		{
			if (!SetProperty(ref _hasLoadedAssembly, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4026 - 3726 + 18]))
			{
				return;
			}
			while (true)
			{
				int num = -1160926629;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(((724296793 + 338415431 - -363606753 * 1589012541 - -1811624997 * -1889223963 * 2123847589 - (-1615326411 - (-1741091373 ^ -273489352) - -(-1133002746 + 1340364106))) * -997701681 - ~(~((num2 ^ ~(0x2B5A2D74 ^ (-1980064439 * (~(~(0x76B186C5 ^ 0x13CC3D4E)) + (-210893427 ^ (-(-87098399 * 1091231267) ^ -525277339)) - ((-(--1203349942) * -123986637 + --362891185) ^ (642102331 * ~463531549 * -1227788143 + (0x7805F9E8 ^ ((-164678077 ^ 0x74BDDE21) - --91304489)))))))) * 638765859)) + -(364054086 + -1432536753 - 2156369 * -1976559229 - (0x7E7B35CC ^ 0x8C14085))) * 541673873 * -1265275729)))) % 5;
					int num5 = 1099032729;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0x4181E89D;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -4;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = ~num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 543424041;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 543424040;
						}
						if (num3 != (uint)num9)
						{
							int num11 = 806157506;
							_ = 0;
							for (int num12 = 0; num12 < 2; num12++)
							{
								num11 = (num11 ^ 0x2AAAF3A8) - -802641813;
								num11 = 1587826533 - (num11 - ~1189115444);
							}
							if (num3 != (uint)num11)
							{
								int num13 = -1;
								_ = 0;
								for (int num14 = 0; num14 < 1; num14++)
								{
									num13 = ~num13;
								}
								if (num3 == (uint)num13)
								{
								}
								return;
							}
							_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4393 - 4430 + 52]);
							int[] array = new int[6] { 1244581828, 463507088, 782729891, 1289376284, -834756846, -2067605521 };
							array[0] ^= -1759641386;
							array[0] = array[3] ^ 0x480B48A6;
							int[] array2 = new int[7];
							array2[0] = -262505066;
							array2[1] = 1792477080;
							array2[2] = 353383646;
							array2[3] = 1493790937;
							array2[4] = 193423917;
							array2[5] = -1698036515;
							array2[6] = 1772652103;
							array2[4] = array[3] ^ -1806802095;
							array2[0] ^= -2101327605;
							array2[1] = array2[4] ^ -1064111163;
							array2[5] = array2[6] ^ -1133753462;
							int num15 = array2[4] ^ -637555924;
							num = ((int)num4 * -1740387256) ^ 0x248C8B28 ^ num15;
						}
						else
						{
							_003C_0024_0029_002A_002D_0021_003E_0028(OpenMethodExplorerCommand);
							int[] array3 = new int[4];
							array3[0] = 278204285;
							array3[1] = -1618051302;
							array3[2] = 500112294;
							array3[3] = -588836444;
							array3[3] = array3[2] ^ -1430654264;
							array3[0] ^= -1998864823;
							array3[0] = array3[3] ^ 0x2DECED78;
							int[] array4 = new int[4] { 2112245365, -1898333727, -1050303679, -334404842 };
							int[][] array5 = new int[2][] { array3, array4 };
							array4[1] = array5[0][1] ^ -998127206;
							array4[3] = array4[2] ^ 0x17D480F4;
							array4[2] ^= -841065855;
							int num16 = array5[1][1] ^ 0x561DB8DF;
							num = ((int)num4 * -1900570021) ^ 0x9CB6D09 ^ num16;
						}
					}
					else
					{
						_002A_003F_003D_003D_005E_0025_003C_002D((IRelayCommand)ProtectAsyncCommand);
						int[] array6 = new int[7];
						array6[0] = 1742133476;
						array6[1] = -2017081169;
						array6[2] = -76873542;
						array6[3] = -1958237839;
						array6[4] = -283480561;
						array6[5] = 1217415430;
						array6[6] = -1874134902;
						array6[0] = array6[1] ^ 0x47FAE9FA;
						array6[6] = array6[5] ^ 0x38450FE6;
						array6[2] = array6[4] ^ -725601110;
						int[] array7 = new int[6] { -1406107385, 1685024624, -1218782178, 1408416915, 333231909, -2122788348 };
						int[][] array8 = new int[2][] { array6, array7 };
						array7[0] = array8[0][5] ^ -87493784;
						array7[2] ^= -1177594145;
						array7[1] = array7[0] ^ 0x1A5D839C;
						int num17 = array8[1][0] ^ -1832348101;
						num = (int)((num4 * 1195089460) ^ 0xEA78C6F4u) ^ num17;
					}
				}
			}
		}
	}

	public bool HasSdkReference
	{
		get
		{
			return _hasSdkReference;
		}
		private set
		{
			if (!SetProperty(ref _hasSdkReference, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-130 + 112)]))
			{
				return;
			}
			while (true)
			{
				int num = 1626773876;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((-1199465006 ^ -1190210362) + -1534075584 * 170506111 * 616907929 - ~(~(num2 * -899851773) - (~(-1266562577) - (-839350068 - ~-1714254357 - -2127517329 - (0x5DE854CE ^ 0x6987F4D4)) - (0x315209DB ^ (0x783D7292 ^ -(-1408172363 ^ 0x64103335))) + 960827632))) * -1118737871)) % 3;
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
						int num9 = 729019500;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 729019498;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-48 + 32)]);
					int[] array = new int[7];
					array[0] = 1818629444;
					array[1] = 1552900943;
					array[2] = 321861480;
					array[3] = 487323823;
					array[4] = -906098313;
					array[5] = 1671116068;
					array[6] = 319192018;
					array[5] = array[1] ^ -1489531390;
					array[2] = array[1] ^ 0xDA4935E;
					int[] array2 = new int[4];
					array2[0] = -1135058403;
					array2[1] = -1985691382;
					array2[2] = -403729861;
					array2[3] = 46427410;
					array2[1] = array[0] ^ -1553547606;
					array2[3] ^= 800777682;
					array2[0] = array2[2] ^ 0x31FEA06A;
					int num11 = array2[1] ^ -536590903;
					num = ((int)num4 * -2103177805) ^ 0x11400850 ^ num11;
				}
			}
		}
	}

	public bool HasStatus => !_005E_0021_0029_002A_0023_0025_0025_003C(StatusMessage);

	public bool IsBusy
	{
		get
		{
			return _isBusy;
		}
		private set
		{
			if (!SetProperty(ref _isBusy, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-743 + 397)]))
			{
				return;
			}
			while (true)
			{
				int num = 860432326;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-1193431358 - 818017718 - -(2028614567 - -1191409464) - ~(-((0x5AB1A76D ^ -((--321016629 * -1599858471) ^ (879931621 * -2038917017))) + -1090189339 - (~num2 + (1320862385 * ~(--1742627959 + (-1398864547 + 1303499452)) - ~(-(--1608558133) + (0x2DC3227C ^ -1032159865)) + (988166451 * -(1032310386 + 1793107278) - (((~-582862605 - --828651372) ^ -304813780) + ((-991977091 - -786472080) ^ -(--924042791)))) + ((~-111642324 - -1914955475 - (-2002375785 - 380799202 + -1459238820) - ~(-(-1572255292 + -1992518264)) - 1300373055) ^ -1844751275) + (1195359199 + -(-1570928141 ^ 0x5501B068) - -1725718063 - -1747964946)) - ((-795969225 ^ (((~(~1239059259) - -(~-264264271)) ^ ((-1307590349 + (0x148E4744 ^ 0x758C5073)) ^ 0x52CB3ED3)) * -1997870255)) + 1182277963 * 2118845064)))) - -(~-1748643959)) * 786340917 - -1689436992)) % 5;
					int num5 = -32460848;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 ^= 0x6518F8F8;
						num5 = -(num5 - ~1701467118);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 118849284;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(num7 + -1201661699 * 1747308789);
						num7 = ~num7 + -1885419936;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = -num9;
						}
						if (num3 != (uint)num9)
						{
							int num11 = 1138158733;
							_ = 0;
							for (int num12 = 0; num12 < 1; num12++)
							{
								num11 += -1138158730;
							}
							if (num3 != (uint)num11)
							{
								int num13 = -3;
								_ = 0;
								for (int num14 = 0; num14 < 1; num14++)
								{
									num13 = ~num13;
								}
								if (num3 == (uint)num13)
								{
								}
								return;
							}
							_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[138 - 31 - 47 - 45]);
							int[] array = new int[7];
							array[0] = -1225113524;
							array[1] = 1507955591;
							array[2] = 79460394;
							array[3] = 192697478;
							array[4] = 205200173;
							array[5] = 1051797440;
							array[6] = -641779090;
							array[6] = array[0] ^ 0x154486B;
							array[5] = array[3] ^ 0x7FEFD0B3;
							int[] array2 = new int[7] { -844880901, -695811559, 1075236410, -1244983436, 2119304410, -1574813525, 76435846 };
							int[][] array3 = new int[2][] { array, array2 };
							array2[5] = array3[0][2] ^ -231974488;
							array2[0] ^= 1724539572;
							array2[4] = array2[0] ^ -120632196;
							int num15 = array3[1][5] ^ -384968282;
							num = (int)((num4 * 446731701) ^ 0x75353D74) ^ num15;
						}
						else
						{
							_003C_0024_0029_002A_002D_0021_003E_0028(OpenMethodExplorerCommand);
							int[,] array4 = new int[4, 4];
							array4[0, 0] = -1107474536;
							array4[0, 1] = 1346373024;
							array4[0, 2] = -1096368355;
							array4[0, 3] = 1941877781;
							array4[1, 0] = -1268500197;
							array4[1, 1] = 354215145;
							array4[1, 2] = -21049528;
							array4[1, 3] = 133495379;
							array4[2, 0] = -1171323376;
							array4[2, 1] = -245370564;
							array4[2, 2] = 11609590;
							array4[2, 3] = 883788386;
							array4[3, 0] = -341025519;
							array4[3, 1] = 468226205;
							array4[3, 2] = -2046385157;
							array4[3, 3] = -529201754;
							array4[3, 1] = array4[2, 1] ^ 0x73548B43;
							array4[1, 2] = array4[2, 1] ^ 0x39F42D22;
							array4[1, 1] = array4[0, 1] ^ 0x39129AB0;
							int num16 = array4[1, 1] ^ -1585973981;
							num = ((int)num4 * -462242830) ^ 0x65C855E ^ num16;
						}
					}
					else
					{
						_002A_003F_003D_003D_005E_0025_003C_002D((IRelayCommand)ProtectAsyncCommand);
						int[,] array5 = new int[3, 3];
						array5[0, 0] = 776760640;
						array5[0, 1] = -28488018;
						array5[0, 2] = -1143778490;
						array5[1, 0] = 300024710;
						array5[1, 1] = 1337929396;
						array5[1, 2] = -628123503;
						array5[2, 0] = 1852415755;
						array5[2, 1] = -1959269011;
						array5[2, 2] = -842674926;
						array5[1, 1] = array5[1, 0] ^ -1694500376;
						array5[1, 0] = array5[0, 2] ^ -783466684;
						array5[1, 0] = array5[2, 0] ^ 0x128B3371;
						array5[1, 2] = array5[0, 1] ^ 0x7D2F1F4E;
						int num17 = array5[1, 2] ^ -163987716;
						num = ((int)num4 * -297635535) ^ 0x511AE3A5 ^ num17;
					}
				}
			}
		}
	}

	public bool LibraryMode
	{
		get
		{
			return _libraryMode;
		}
		set
		{
			if (!SetProperty(ref _libraryMode, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x86B ^ 0x9EC]))
			{
				return;
			}
			while (true)
			{
				int num = -1345039777;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((num2 ^ (-((0x20C83E40 ^ -1984196218) + 354867025 * ((~(-2007993036 + -1065820965) + -(~-1834537567)) * -1029370177) - (~(-(1468388152 + -1423591498 + (-1808063809 + (-439343973 + 1695339109)))) + -(-(~(-699060259) ^ -1341197208)))) * -1095980103) ^ ((0x7B04FA5A ^ (((~(-901748737 * ~399417600) - ~(~-1380084211 - -1550180810)) ^ ((-487376127 * -1708151927 + (2074965885 + 1130645270)) * 1019179381 + (-(773524491 * 1109094591) + 1403813325 * (-1727815740 + 1432747328)))) - (-956711759 ^ (-(~710674993) + (0x25C83942 ^ --2079685935) + ~(709670579 - (1175129585 - 1474587630)))))) + (((-856700837 ^ (-(-1748464052 + 2011969729) ^ 0x6178B969)) * 1565028165 - (-1757698186 ^ -1176101016)) ^ (~(-1903150784 + (-(631032892 - -1540329069) - -2137663565)) ^ 0x407EB07D)))) - ~-1284423567))) % 3;
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
					int num7 = -3;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = ~num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -429218483;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= -429218484;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xD86 ^ 0xCFD]);
					int[] array = new int[7];
					array[0] = 1472977582;
					array[1] = -1221066491;
					array[2] = 1077462541;
					array[3] = 417927794;
					array[4] = 271006999;
					array[5] = 966305483;
					array[6] = 1929004040;
					array[2] = array[4] ^ 0x168ADC2C;
					array[5] = array[3] ^ 0x62F7F7EB;
					int[] array2 = new int[7];
					array2[0] = 1569022606;
					array2[1] = -649041238;
					array2[2] = 1782429123;
					array2[3] = -1812676248;
					array2[4] = -217637138;
					array2[5] = 444358501;
					array2[6] = 460464818;
					array2[4] = array[0] ^ -659116073;
					array2[0] ^= 1280776509;
					array2[6] ^= 2005779143;
					int num11 = array2[4] ^ 0x1B0D525C;
					num = ((int)num4 * -492620755) ^ -2065835300 ^ num11;
				}
			}
		}
	}

	public RelayCommand OpenMethodExplorerCommand { get; }

	public IAsyncRelayCommand ProtectAsyncCommand { get; }

	public unsafe bool ReferenceProxy
	{
		get
		{
			return _referenceProxy;
		}
		set
		{
			if (!SetProperty(ref _referenceProxy, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x959 ^ 0x8D1]))
			{
				return;
			}
			while (true)
			{
				int num = 142389538;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((-(~(-686460291 * (((~(-(-876946869 + 666219645)) - (0xB599FDD ^ -1281284525) - --161212266) ^ 0x5C29942F) - ((-1537286307 ^ -(-(~-542570980))) * 1127509033 - 656524970) + (~(-382242306 ^ (-(540450721 * 2116742080) + (~(-1118300749) ^ -(--965728862)))) + ~(-1025198352 ^ ((-1654797038 - (0x16B4C7B5 ^ -1415850326)) * -1311116579 * -749970523)))) - num2)) ^ (35981084 + (~1202181520 - (-238640454 ^ 0x201F4FFF)))) * 1376002001 * 1513813647))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= 106262985;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1614767103;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 ^ 0x2D9D2C78;
						num7 = 919789281 - (num7 + (-716727068 + -1827211364));
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
					_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(359 + sizeof(int)) ^ sizeof(Guid)]);
					int[,] array = new int[4, 4];
					array[0, 0] = -1299639305;
					array[0, 1] = 54508436;
					array[0, 2] = 813124989;
					array[0, 3] = -576430383;
					array[1, 0] = 361735681;
					array[1, 1] = -110128018;
					array[1, 2] = -998971187;
					array[1, 3] = 258508236;
					array[2, 0] = 1951447002;
					array[2, 1] = 23786548;
					array[2, 2] = -1178708322;
					array[2, 3] = 1235077547;
					array[3, 0] = 1902225958;
					array[3, 1] = 1362406095;
					array[3, 2] = 91161563;
					array[3, 3] = 835321562;
					array[3, 2] = array[2, 2] ^ -342114039;
					array[3, 0] = array[3, 1] ^ -585314353;
					array[0, 0] = array[2, 1] ^ -1664557701;
					array[0, 0] = array[2, 2] ^ -905774896;
					int num11 = array[0, 0] ^ 0x604996D4;
					num = (int)((num4 * 1908957280) ^ 0xC012D220u) ^ num11;
				}
			}
		}
	}

	public unsafe bool ResourceProtection
	{
		get
		{
			return _resourceProtection;
		}
		set
		{
			if (!SetProperty(ref _resourceProtection, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[3215 - 2848 + 26]))
			{
				return;
			}
			while (true)
			{
				int num = 1366754324;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((((num2 ^ (-(-(-1779919673 ^ 0x4EAB5A1D) ^ ((-1402542223 * -(~2065638743 - -514737288) + -394111641) ^ -2026534940)) + ~(-(-368902355 - ~-1821523629) * 665580657) * -1513737141)) - ((-(1603795879 + (0x292B1AE4 ^ 0x3ACC7509)) ^ ~((0x45271D6F ^ 0x2FC286EF) + --669081661) ^ -789347620) - (-((-1173240916 ^ --1598795148) + (~-1792841075 - ~-1288210155)) - (~333576809 + (-1329638750 + 1398120943) - (-1343527825 + (-1816957844 ^ 0x57D45CE9)) - (-711415926 - -(~581814209)))) + -(~(~(-1592669097 * ~541057701))) - (-(~(~(-(~-447109489)))) + --1219213303 + -(~(-1933480249 + ~(-2047059090 * 270908771 - (-1812334051 + 1522007983))))))) ^ (~(-(299750779 * 2017476654 + ~(-(~180668770)))) * 2009994619)) - ~(-((906599555 * -(-1348955745 * -471248979)) ^ ((-1895874655 - -1000793518) * -1257955791)))) - ((284294417 * (-2023903134 ^ -1061648112)) ^ 0x7597D490))) % 3;
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
					_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(359 + sizeof(int)) ^ sizeof(Guid)]);
					int[] array = new int[4];
					array[0] = 1966591567;
					array[1] = -1345027930;
					array[2] = 215896905;
					array[3] = 1347628880;
					array[0] = array[2] ^ 0x71D808B6;
					array[3] = array[2] ^ -1396041577;
					array[3] = array[0] ^ -2057876226;
					int[] array2 = new int[6];
					array2[0] = -207021073;
					array2[1] = 2063968188;
					array2[2] = 1285119726;
					array2[3] = 2022919207;
					array2[4] = -935300495;
					array2[5] = 707486959;
					array2[5] = array[1] ^ 0x21E50811;
					array2[4] ^= -1446594179;
					array2[2] = array2[0] ^ 0x4CF4FDC3;
					array2[1] = array2[3] ^ 0x3B740FF6;
					int num11 = array2[5] ^ 0x608842B3;
					num = ((int)num4 * -1197580917) ^ 0x2E6D668F ^ num11;
				}
			}
		}
	}

	public string RuntimeDisplay
	{
		get
		{
			return _runtimeDisplay;
		}
		private set
		{
			SetProperty(ref _runtimeDisplay, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-665 + 270)]);
		}
	}

	public bool StringEncryption
	{
		get
		{
			return _stringEncryption;
		}
		set
		{
			if (!SetProperty(ref _stringEncryption, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x11C2 ^ 0x1049]))
			{
				return;
			}
			while (true)
			{
				int num = 1991611018;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((((-(154258471 * (1087444739 * 1033999034 - --18324869) * -1685391707 + ((0x29F052E0 ^ -1021418596) * 930841663 - (2141360687 + -1001466377 + (-1888888645 + -2112336583)) * 383683305) - (((num2 - ((-1942763183 * ~209201825 - ((-1885120180 - (-((-1937759503 ^ -1622583095) + -228468429 * 695323195 - 115963627) ^ -1668501376)) ^ 0x26B1BB37)) ^ (1177181459 * (-(-1235522344 * -631458097) + -(1934949281 + ((0x77681B9E ^ 0x228AF58C) + --1650219452 - ((0x55F33CDC ^ 0x300090E3) - -785375130)) - (-461462198 - ~156476214 + 346371488))))) - ((1125906327 - -(779565241 + 1527643690 + (-979550285 - 1826601949) - -2016725403 * --1576685879 - ~(-667831904 + -1761112983 + -1569895926) + ((0x58C7E7E5 ^ 0x44973371) - (0x58A2AD53 ^ -1469891722) + -(-1736015223 * -1306509875 + --122699624)))) ^ (((0x65976B74 ^ -716938416) - ~(-1532386953 * (-556091863 - 700391098))) * 358394605 - ((0x6E84E877 ^ (643130743 * -148287425 + ~(332764451 * -134093751))) + (2065642027 * 1883221448 * 2145309229 + (-138896191 + 326202754) * 2054974165 + (1602561365 + (76453485 + 34947143) + (-2067454603 ^ -436570294)))) + (-(-(~(0x79132AEC ^ --2129548102))) + -282818482)))) * -881660363) ^ -933181167)) ^ -(62589335 + 840634686 + (-514345372 + -989831502))) - (-138906501 ^ -272315122)) ^ 0x117D76A4) * -1769126597)) % 3;
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
					int num7 = 1709880826;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x65EAB5FB;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1081669726;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(~num9);
							num9 = 951348898 - (num9 ^ 0x6256AD70);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x77F ^ 0x604]);
					int[,] array = new int[3, 4];
					array[0, 0] = -1946473818;
					array[0, 1] = 1057229171;
					array[0, 2] = 1089807027;
					array[0, 3] = 1959469221;
					array[1, 0] = 873462755;
					array[1, 1] = 2068443342;
					array[1, 2] = -1340295967;
					array[1, 3] = 1430377261;
					array[2, 0] = 1681913075;
					array[2, 1] = 404779833;
					array[2, 2] = 1637941699;
					array[2, 3] = -441829511;
					array[1, 1] = array[2, 2] ^ 0x52FFED32;
					array[2, 2] = array[2, 3] ^ -1234947450;
					array[0, 3] = array[0, 0] ^ -152889396;
					int num11 = array[0, 3] ^ 0x579CBC4;
					num = ((int)num4 * -1712081677) ^ 0x1EFBD84F ^ num11;
				}
			}
		}
	}

	public InfoBarSeverity StatusSeverity
	{
		get
		{
			SeverityLevel statusLevel = StatusLevel;
			InfoBarSeverity result = default(InfoBarSeverity);
			while (true)
			{
				int num = -1961730900;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(2027835669 * -1924151914) - (((-(~(num2 - (-1826410555 * --1191439493 - (-350647319 ^ (~(1212394233 * -1937535695) - ~(-(-1485867789 ^ 0x626447B3) + -995817127 * 1421082340))) + (0xCAE47C0 ^ -439597836) + 558137 * (2059513565 * ~((0x644B4924 ^ 0x14EA0160) + ((--1681765383 ^ -248120469) * 369230983 - ~(-1560571258 - -602960142 * 1804759781)))))) + ~694821564) ^ -1685673774) * 1004688079) ^ 0x1EF05C81)) * -1871199203)) % 11;
					int num5 = 9;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 -= --138522413;
						num5 = 1117902195 - (num5 - --1980262917);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1516139083;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(num7 * 1314650895);
						num7 = -num7 * 189827005;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1773134780;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= 2122959345;
						}
						if (num3 != (uint)num9)
						{
							int num11 = -1;
							_ = 0;
							for (int num12 = 0; num12 < 1; num12++)
							{
								num11 = ~num11;
							}
							if (num3 != (uint)num11)
							{
								int num13 = -104446433;
								_ = 0;
								for (int num14 = 0; num14 < 1; num14++)
								{
									num13 -= -104446440;
								}
								if (num3 != (uint)num13)
								{
									int num15 = 2112966666;
									_ = 0;
									for (int num16 = 0; num16 < 2; num16++)
									{
										num15 = num15 ^ -1232050780 ^ -437204348;
										num15 *= -533845041;
									}
									if (num3 == (uint)num15)
									{
										goto IL_0864;
									}
									int num17 = 1006641701;
									_ = 0;
									for (int num18 = 0; num18 < 2; num18++)
									{
										num17 = -num17;
										num17 = (1010552557 * -618883038 - num17) ^ -507779921;
									}
									if (num3 != (uint)num17)
									{
										int num19 = -3;
										_ = 0;
										for (int num20 = 0; num20 < 1; num20++)
										{
											num19 = ~num19;
										}
										if (num3 != (uint)num19)
										{
											int num21 = -430246024;
											_ = 0;
											for (int num22 = 0; num22 < 1; num22++)
											{
												num21 = -430246021 - num21;
											}
											if (num3 != (uint)num21)
											{
												int num23 = -2080112508;
												_ = 0;
												for (int num24 = 0; num24 < 2; num24++)
												{
													num23 = (num23 + 1044600561) ^ -1243793044;
													num23 = -(num23 ^ -606127829);
												}
												if (num3 != (uint)num23)
												{
													int num25 = -814558667;
													_ = 0;
													for (int num26 = 0; num26 < 1; num26++)
													{
														num25 += 814558673;
													}
													if (num3 != (uint)num25)
													{
													}
													return result;
												}
												result = InfoBarSeverity.Informational;
												num = 1146336732;
											}
											else
											{
												int[] array = new int[7];
												array[0] = 258719435;
												array[1] = -1170320802;
												array[2] = -58718185;
												array[3] = -1627967720;
												array[4] = -2056655184;
												array[5] = -1197061455;
												array[6] = -138582614;
												array[6] = array[1] ^ 0xD5EA8CE;
												array[4] = array[0] ^ -595411277;
												int[] array2 = new int[5];
												array2[0] = 1394801014;
												array2[1] = -1248695403;
												array2[2] = 2057979313;
												array2[3] = 367041874;
												array2[4] = 1611408626;
												array2[3] = array[0] ^ -16346970;
												array2[0] ^= 363245614;
												array2[2] = array2[3] ^ -375898189;
												int num27 = array2[3] ^ -1270965327;
												num = (int)((num4 * 1595323335) ^ 0xDDDEFE59u) ^ num27;
											}
											continue;
										}
										goto IL_0877;
									}
									int[,] array3 = new int[4, 3];
									array3[0, 0] = 1838647708;
									array3[0, 1] = 294317605;
									array3[0, 2] = 715513190;
									array3[1, 0] = -871177890;
									array3[1, 1] = -1337860817;
									array3[1, 2] = -282901542;
									array3[2, 0] = 475533715;
									array3[2, 1] = -883442385;
									array3[2, 2] = 1954816083;
									array3[3, 0] = 1262769351;
									array3[3, 1] = -358155747;
									array3[3, 2] = 1900138281;
									array3[0, 0] = array3[3, 0] ^ 0x20B4AE9B;
									array3[0, 2] ^= -1752049497;
									array3[3, 2] = array3[1, 0] ^ -910830504;
									array3[1, 2] = array3[3, 1] ^ 0x7648C45D;
									int num28 = array3[1, 2] ^ -658666596;
									num = (int)((num4 * 1959137210) ^ 0x7CA722D8) ^ num28;
									continue;
								}
								int[] array4 = new int[5];
								array4[0] = -356326895;
								array4[1] = 1137341323;
								array4[2] = 734223466;
								array4[3] = -475889564;
								array4[4] = 564509556;
								array4[2] = array4[4] ^ -587091256;
								array4[2] = array4[3] ^ -160561546;
								int[] array5 = new int[7];
								array5[0] = 1563824964;
								array5[1] = -1750821190;
								array5[2] = 333336157;
								array5[3] = 963585925;
								array5[4] = 1220376281;
								array5[5] = 269980187;
								array5[6] = -1803985605;
								array5[1] = array4[3] ^ -173996691;
								array5[6] = array5[2] ^ -1444955714;
								array5[4] = array5[3] ^ -901715155;
								int num29 = array5[1] ^ 0x525030D5;
								num = ((int)num4 * -559121843) ^ -1210490172 ^ num29;
								continue;
							}
							goto IL_0e03;
						}
						int[] array6 = new int[7];
						array6[0] = 144132935;
						array6[1] = 550263976;
						array6[2] = 2009564940;
						array6[3] = 762951547;
						array6[4] = 1221081748;
						array6[5] = -1144026484;
						array6[6] = -460084517;
						array6[0] = array6[3] ^ -436910886;
						array6[5] = array6[1] ^ 0x7F82E1EB;
						int[] array7 = new int[6] { 1034026573, 374485196, -837772604, -967104586, 80994243, -1980648726 };
						int[][] array8 = new int[2][] { array6, array7 };
						array7[4] = array8[0][3] ^ 0x29645F90;
						array7[3] = array7[0] ^ -389316548;
						array7[3] = array7[0] ^ 0x3CF1B680;
						array7[3] ^= 678730036;
						int num30 = array8[1][4] ^ 0x52769354;
						num = ((int)num4 * -1413123782) ^ 0x143FD26E ^ num30;
						continue;
					}
					switch (statusLevel)
					{
					case SeverityLevel.Warning:
						goto IL_0864;
					case SeverityLevel.Error:
						goto IL_0877;
					case SeverityLevel.Success:
						goto IL_0e03;
					}
					int[] array9 = new int[4] { -1472105467, 545777269, 577234412, -751424072 };
					array9[0] ^= -1418853994;
					array9[0] = array9[2] ^ 0x29B97E7;
					int[] array10 = new int[5];
					array10[0] = -92136020;
					array10[1] = 157984121;
					array10[2] = 771296878;
					array10[3] = -517783416;
					array10[4] = -1685586960;
					array10[2] = array9[3] ^ 0x1999DFC3;
					array10[3] ^= -489399784;
					array10[4] = array10[2] ^ 0x23055F5B;
					array10[0] = array10[3] ^ 0x123C43EB;
					int num31 = array10[2] ^ 0x26D875DA;
					num = (int)((num4 * 1913647541) ^ 0xB8E0F91Eu) ^ num31;
					continue;
					IL_0864:
					result = InfoBarSeverity.Warning;
					num = -717593374;
					continue;
					IL_0877:
					result = InfoBarSeverity.Error;
					num = 1444459221;
					continue;
					IL_0e03:
					result = InfoBarSeverity.Success;
					num = 2109986954;
				}
			}
		}
	}

	public SeverityLevel StatusLevel
	{
		get
		{
			return _statusLevel;
		}
		private set
		{
			if (!SetProperty(ref _statusLevel, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-755 + 406)]))
			{
				return;
			}
			while (true)
			{
				int num = 1237256815;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(-1226932333 * 1321340197 + -270535339 * -1184878753) - (num2 * 1225948755 * 1370303503 * 569709295 * 148654347 - ~(~(-(1905721965 * 625307428 + -1475714883)))) * 143362777 - -(-1077603016)) ^ -2104339564)) % 3;
					int num5 = 1073660032;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 ^ 0x2507A2E5;
						num5 = num5 - (-682874028 - -1460617822) - -514083944;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1909365278;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = 1909365279 - num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 756722687;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x2D1AABFD;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[3483 - 3229 + 95]);
					int[] array = new int[6];
					array[0] = 192745556;
					array[1] = -1540244721;
					array[2] = 2145828211;
					array[3] = 7242180;
					array[4] = -1068129614;
					array[5] = 2030536420;
					array[5] = array[0] ^ 0x25303345;
					array[5] = array[0] ^ -248383265;
					int[] array2 = new int[5];
					array2[0] = 921561017;
					array2[1] = -1278944934;
					array2[2] = 681953300;
					array2[3] = 1012006216;
					array2[4] = 934903522;
					array2[2] = array[1] ^ -507271045;
					array2[3] ^= 1247975260;
					array2[0] = array2[4] ^ 0x4DDE42B7;
					int num11 = array2[2] ^ 0x387BA601;
					num = ((int)num4 * -965233489) ^ 0x4339798A ^ num11;
				}
			}
		}
	}

	public string StatusMessage
	{
		get
		{
			return _statusMessage;
		}
		private set
		{
			if (!SetProperty(ref _statusMessage, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x13EBB ^ 0x13FE5))]))
			{
				return;
			}
			while (true)
			{
				int num = 92987613;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(486443014 - ~(-1981199567 + 1611190032 + (-1986826255 + -1495533088) - ~(~(~(((num2 + ((-320244176 ^ (1697812515 * 2100690053 - ((1428521097 - -(-1282935006 ^ -643390777)) ^ -1461652458 ^ ((--1037971837 + (1056124661 - -768600200) - -(-1195153197)) * -366296461) ^ ~(~(-(~(623171406 + 574972181))))))) + ((-1741600417 * (-642696107 * -334105954 - -852927355 + ((--1118947291 + (-894496517 ^ -1966787160)) ^ (-2085453517 + (0x7E7C7BAD ^ -684452253)))) + (~(1536022069 * 1089582724 + --469779675) ^ -1250886910 ^ (-((-961267539 ^ -2035085386) - (-927359306 + -1789340663)) + (-256009137 ^ (~1981111809 - -1894763553)))) - (-(-(--330957958 - 1203450868)) - -(-918479092 + 1868715310 - (1138554757 + 1372738286) - (-341562094 ^ -219987979)) + (~-1986713860 + ~(~(1792911862 + ~-806833102))))) ^ (-451866055 * (-1096362427 - ~(-(~(326675407 + 520531314))) * 636348243))))) ^ -(-(~563344468 + ~((-178968693 ^ -469276363) - --1794103058)) + (-(-(-1192397821 * (-215605483 - 1400899913))) - -(-(~(0x2801077F ^ 0x285BBC37)))) + ((~(-(-1124994507)) ^ (-(1566092957 * (0x2C886210 ^ 0x1663C89F)) - (~(--1781107989) ^ 0x6588E76C))) + -(-1871512874 ^ 0x1E441D52)))) * -704880273)) * -68055755)))) % 3;
					int num5 = -27262976;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 ^ --2119541113);
						num5 = (num5 - (-582411725 - -564578143)) ^ -1253970448;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(-num7);
						num7 = -(num7 + (-1934474919 + -140352907));
					}
					if (num3 != (uint)num7)
					{
						int num9 = 19809473;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9 - 59881012;
							num9 = -(num9 ^ -966206049);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[454 - 8 - 49 - 46]);
					int[] array = new int[6];
					array[0] = -1204403230;
					array[1] = -821375249;
					array[2] = 603123407;
					array[3] = -992161791;
					array[4] = -1274652459;
					array[5] = 1900346875;
					array[1] = array[2] ^ 0x78A36464;
					array[5] ^= -1147393062;
					array[0] = array[1] ^ -355581531;
					int[] array2 = new int[6];
					array2[0] = -1523626956;
					array2[1] = 1483984919;
					array2[2] = -1436354819;
					array2[3] = 985840884;
					array2[4] = 167854042;
					array2[5] = 410561506;
					array2[3] = array[3] ^ -775795089;
					array2[0] = array2[3] ^ -1682787702;
					array2[0] = array2[5] ^ -1035162843;
					array2[5] ^= 1422620889;
					int num11 = array2[3] ^ -1709411170;
					num = ((int)num4 * -975604585) ^ -674398195 ^ num11;
				}
			}
		}
	}

	public bool SymbolRenaming
	{
		get
		{
			return _symbolRenaming;
		}
		set
		{
			if (!SetProperty(ref _symbolRenaming, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x945 ^ 0x8C9]))
			{
				return;
			}
			while (true)
			{
				int num = -690567693;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(~(((-1788767645 - -(-1305616884 - 1123348454) + 198966871 * -2136399853 * 175017249) * -1628580357 - ~(-num2) * 1325901253 - (((--1904647656 - (-1742685334 ^ -1043422850) + 433203089) ^ -(~-765229749 - -1389754917 * -460429159)) + (189456258 * 2070482673 + (-1168574215 ^ 0x45D6805C)) * -50894225 * 1266761511)) ^ 0x4000D9A8 ^ -339905412))))) % 3;
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
					int num7 = 1176017217;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 1176017216;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 408389642;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 + 377837007 * -49064321 - 1872423068;
							num9 += 2065238246;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[448 - 13 - 21 - 35]);
					int[] array = new int[5] { -971730504, -828613341, 647308069, 2126991916, -1168067561 };
					array[0] ^= 1131744033;
					array[3] = array[4] ^ 0x56FB771F;
					array[4] ^= 1049951235;
					int[] array2 = new int[6];
					array2[0] = 661950791;
					array2[1] = -1824962228;
					array2[2] = 1024332467;
					array2[3] = -2135831852;
					array2[4] = -1643371676;
					array2[5] = 1419700845;
					array2[4] = array[1] ^ 0x6F921CE3;
					array2[1] ^= -295501230;
					array2[2] = array2[1] ^ -1890633374;
					int num11 = array2[4] ^ 0x504222AA;
					num = ((int)num4 * -1715933197) ^ -1727304764 ^ num11;
				}
			}
		}
	}

	public WorkspaceViewModel(AppViewModel appViewModel, IAssemblyWorkspaceService assemblyWorkspaceService, IFilePickerService filePickerService, IProtectionService protectionService, IAuthenticationService authenticationService, IStringResourceService strings)
	{
		while (true)
		{
			int num = -489793829;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(-(112586551 - ((-(--1324385165) ^ -1602068004 ^ (1876536123 * (-1043978125 + (-245835414 - 318949703)))) - 69691148 - ((~num2 ^ -(-(~(1966216153 * ((0x26D245E0 ^ -2106890285) + (1707523033 + 1593061145) * -1722699207) + -(-(~992383302) - -471181619 * ~-1367922110))))) + (-(~(-(--688109783 + (311509064 + 399001795)) - ~(-827141226 - -178111304 + 1424552149 * 881910319))) + (-(-(-120431609 * 1635661771)) * 1728895413 - (-(1311649453 * (-1020192937 + -1250432275)) - (0x2405AD72 ^ -(--986034093)))) * 173120725) - -(~(-(-(2032816649 * 2032862561)))) * -1066149571))) - 331369339 * -1793127265 - -1775951543 * 232519345))) % 10;
				int num5 = -1801970202;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 ^= -1801970207;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -1309130761;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = num7 * 1583776611 - -1917579333;
					num7 *= -1341573713;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -1027212029;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 ^= -1027212026;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 205783472;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = (num11 - -1420117291 * 1772600303) ^ 0x899FD09;
							num11 = ~(-num11);
						}
						if (num3 != (uint)num11)
						{
							int num13 = 0;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 *= -2000356705;
							}
							if (num3 != (uint)num13)
							{
								int num15 = -2;
								_ = 0;
								for (int num16 = 0; num16 < 1; num16++)
								{
									num15 = -num15;
								}
								if (num3 != (uint)num15)
								{
									int num17 = 1214349241;
									_ = 0;
									for (int num18 = 0; num18 < 2; num18++)
									{
										num17 = -num17 * -2015398231;
										num17 = (num17 ^ -271857976) - -1451036557;
									}
									if (num3 != (uint)num17)
									{
										int num19 = 4;
										_ = 0;
										for (int num20 = 0; num20 < 2; num20++)
										{
											num19 = -(num19 ^ 0x5BE2F963);
											num19 = -num19 ^ 0x76951AA8;
										}
										if (num3 != (uint)num19)
										{
											int num21 = -1216083355;
											_ = 0;
											for (int num22 = 0; num22 < 2; num22++)
											{
												num21 = -(num21 - --2015320557);
												num21 = -(num21 + ~475878587);
											}
											if (num3 != (uint)num21)
											{
												int num23 = -1492109306;
												_ = 0;
												for (int num24 = 0; num24 < 2; num24++)
												{
													num23 ^= -1828295299;
													num23 = (num23 - ~-1165444105) ^ -1674076862;
												}
												if (num3 == (uint)num23)
												{
												}
												return;
											}
											ProtectAsyncCommand = new AsyncRelayCommand(ProtectAsync, CanProtect);
											int[] array = new int[7];
											array[0] = -197949393;
											array[1] = -328633596;
											array[2] = 895735098;
											array[3] = 333635263;
											array[4] = 2045502567;
											array[5] = 631810992;
											array[6] = 855790657;
											array[0] = array[3] ^ -191994132;
											array[5] = array[4] ^ 0x41D5A8AA;
											array[5] = array[4] ^ -728483419;
											int[] array2 = new int[5] { -389379667, 1049859803, -837082227, -1054519145, -355122009 };
											int[][] array3 = new int[2][] { array, array2 };
											array2[2] = array3[0][2] ^ -984416476;
											array2[3] = array2[0] ^ 0x4FCCCC35;
											array2[3] = array2[2] ^ -890422773;
											int num25 = array3[1][2] ^ -167580714;
											num = (int)((num4 * 1304966548) ^ 0xBDA4596Cu) ^ num25;
										}
										else
										{
											BrowseAssemblyCommand = new AsyncRelayCommand(BrowseAssemblyAsync);
											OpenMethodExplorerCommand = new RelayCommand(OpenMethodExplorer, CanOpenMethods);
											int[,] array4 = new int[4, 3];
											array4[0, 0] = -1636773762;
											array4[0, 1] = -2093009773;
											array4[0, 2] = -1446689995;
											array4[1, 0] = 1600623425;
											array4[1, 1] = 475841796;
											array4[1, 2] = -1213372191;
											array4[2, 0] = 121555112;
											array4[2, 1] = -1160862086;
											array4[2, 2] = -488330902;
											array4[3, 0] = 1431308989;
											array4[3, 1] = -1437140402;
											array4[3, 2] = 264684417;
											array4[2, 2] = array4[3, 1] ^ 0x3A82B7D3;
											array4[0, 2] = array4[1, 1] ^ 0x4A14D1B1;
											array4[2, 0] = array4[0, 1] ^ 0x207E8617;
											array4[0, 1] = array4[1, 1] ^ -1695194085;
											int num26 = array4[0, 1] ^ -1755408762;
											num = (int)((num4 * 911163669) ^ 0x7460B030) ^ num26;
										}
									}
									else
									{
										_strings = strings;
										int[,] array5 = new int[4, 4];
										array5[0, 0] = 1419892718;
										array5[0, 1] = -1971994677;
										array5[0, 2] = 346135673;
										array5[0, 3] = -524156355;
										array5[1, 0] = 1575138160;
										array5[1, 1] = -690241783;
										array5[1, 2] = 1249547959;
										array5[1, 3] = 1793256109;
										array5[2, 0] = -1169968774;
										array5[2, 1] = -1416463392;
										array5[2, 2] = -291272052;
										array5[2, 3] = -511831129;
										array5[3, 0] = 1611322954;
										array5[3, 1] = 1901704382;
										array5[3, 2] = 171239830;
										array5[3, 3] = -129510523;
										array5[2, 2] = array5[1, 2] ^ 0x72BC8E77;
										array5[2, 2] = array5[1, 2] ^ 0x247C0615;
										array5[2, 0] = array5[3, 3] ^ -480395332;
										array5[0, 0] = array5[2, 1] ^ -1785276137;
										int num27 = array5[0, 0] ^ 0x3DEFF7DF;
										num = (int)((num4 * 1349791146) ^ 0x9BECCDC6u) ^ num27;
									}
								}
								else
								{
									_authenticationService = authenticationService;
									int[,] array6 = new int[3, 3];
									array6[0, 0] = -287245450;
									array6[0, 1] = -1842921231;
									array6[0, 2] = 2123246756;
									array6[1, 0] = -802308427;
									array6[1, 1] = 1928662629;
									array6[1, 2] = 2094599456;
									array6[2, 0] = -1167719329;
									array6[2, 1] = -363473594;
									array6[2, 2] = 1716715013;
									array6[2, 1] = array6[2, 2] ^ 0x64745950;
									array6[2, 0] = array6[1, 2] ^ 0x330D3F7B;
									array6[2, 1] = array6[2, 2] ^ -203161375;
									array6[1, 2] = array6[0, 1] ^ 0x6DF67E78;
									int num28 = array6[1, 2] ^ 0x59682308;
									num = (int)((num4 * 877331852) ^ 0x570ECAD8) ^ num28;
								}
							}
							else
							{
								_protectionService = protectionService;
								int[] array7 = new int[6] { -860454701, 231621516, 492618466, -1547360261, -1564061369, 1757561678 };
								array7[0] ^= 805041878;
								array7[1] = array7[5] ^ 0x2E242FCB;
								int[] array8 = new int[6];
								array8[0] = 890317893;
								array8[1] = 927863220;
								array8[2] = -1599275731;
								array8[3] = -1882660200;
								array8[4] = 2052493978;
								array8[5] = -162792398;
								array8[3] = array7[5] ^ 0x50FEE7AB;
								array8[0] = array8[1] ^ -1287738222;
								array8[0] = array8[4] ^ -123748141;
								array8[5] = array8[4] ^ -1981750949;
								int num29 = array8[3] ^ -685751837;
								num = (int)((num4 * 593264631) ^ 0xEF1510C2u) ^ num29;
							}
						}
						else
						{
							_filePickerService = filePickerService;
							int[] array9 = new int[7];
							array9[0] = -1346395358;
							array9[1] = -1617326974;
							array9[2] = -608056306;
							array9[3] = -889187647;
							array9[4] = -2007111124;
							array9[5] = -2138936311;
							array9[6] = -1067722941;
							array9[3] = array9[0] ^ 0x1E0EB00A;
							array9[0] = array9[3] ^ -976101701;
							array9[1] = array9[5] ^ 0x3742FB12;
							int[] array10 = new int[4];
							array10[0] = -1444743951;
							array10[1] = -53235347;
							array10[2] = 1448333947;
							array10[3] = 277866548;
							array10[1] = array9[2] ^ 0x91B39A1;
							array10[0] = array10[2] ^ -1813909894;
							array10[2] ^= 1072668408;
							array10[2] = array10[3] ^ 0x6CA95941;
							int num30 = array10[1] ^ 0x34BF3225;
							num = ((int)num4 * -193438696) ^ 0x172A8980 ^ num30;
						}
					}
					else
					{
						_assemblyWorkspaceService = assemblyWorkspaceService;
						int[] array11 = new int[4];
						array11[0] = -994393618;
						array11[1] = -1751959217;
						array11[2] = -609005762;
						array11[3] = 66912997;
						array11[3] = array11[2] ^ -854946679;
						array11[2] = array11[0] ^ -1831731581;
						array11[3] = array11[0] ^ -310750856;
						int[] array12 = new int[7] { 1181968845, 500548091, -1183723878, -1489021652, -1665742852, 1686594444, 1554454469 };
						int[][] array13 = new int[2][] { array11, array12 };
						array12[6] = array13[0][0] ^ 0x71260C12;
						array12[1] = array12[2] ^ -1151044008;
						array12[2] = array12[3] ^ 0x4895FAFE;
						array12[3] = array12[1] ^ -2114789728;
						int num31 = array13[1][6] ^ 0x533570B4;
						num = ((int)num4 * -278088230) ^ -1435859806 ^ num31;
					}
				}
				else
				{
					AppViewModel = appViewModel;
					int[,] array14 = new int[4, 4];
					array14[0, 0] = 767493141;
					array14[0, 1] = -2045682021;
					array14[0, 2] = -416194751;
					array14[0, 3] = -574438322;
					array14[1, 0] = 778690451;
					array14[1, 1] = -1046201425;
					array14[1, 2] = 1235835429;
					array14[1, 3] = -1080180901;
					array14[2, 0] = 1445762222;
					array14[2, 1] = 1084473125;
					array14[2, 2] = -740255135;
					array14[2, 3] = -526139282;
					array14[3, 0] = 1852286856;
					array14[3, 1] = 819830373;
					array14[3, 2] = -863297865;
					array14[3, 3] = 810508049;
					array14[0, 0] = array14[0, 2] ^ 0x304802B7;
					array14[1, 1] ^= -306046942;
					array14[3, 0] = array14[3, 1] ^ -2003380257;
					int num32 = array14[3, 0] ^ 0x66E12599;
					num = ((int)num4 * -128654632) ^ -18228360 ^ num32;
				}
			}
		}
	}

	[AsyncStateMachine(typeof(_003CLoadAssemblyAsync_003Ed__117))]
	public Task LoadAssemblyAsync(string filePath)
	{
		_003CLoadAssemblyAsync_003Ed__117 stateMachine = default(_003CLoadAssemblyAsync_003Ed__117);
		stateMachine._003C_003Et__builder = _0023_0028_0028_0024_0028_002A_0029_002D();
		while (true)
		{
			int num = 1779434660;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)((num2 + (~(~(-1573073157 * ((-1956021813 - 416165354 + (2115628565 - -974373426)) * 2076903421))) + (~-15998888 * -1456542653 - -(~(134636929 - 1701070703) * 118221887) - (1436798784 - -211144372)) + (~(~(~(-(-1292895893 + -380868754))) * -909036835) ^ -(~(~(-(--1847209942))) + ~(1818075292 * -650351299 * -990009939))) - (-(1722574063 - (-1791753464 * 770066071 * 1704216011 - -(2040750714 - 874514457)) + 1055848671) ^ --1291306017) * -1845139527)) * 1546040701 * -1695257057 + (732695203 * -(289721748 * -965054983) - (-1568755773 ^ 0x214D4ACA)) - (~(~(-1059502706)) ^ (-1383938083 * -(144186450 + -1453454121)) ^ (-(1101625396 + (-1556691242 + 355460009)) ^ (~(-2017573781 ^ 0x60448330) + -(1720219013 * 719076610)))) + (~(-(1384491393 - 1929203760)) - (-1462444235 ^ 0x33A0332B)))) % 6;
				int num5 = -1883806912;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~(-num5);
					num5 = -1205580191 - -num5;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1292660110;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 += -1292660108;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 452882969;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 *= 400290509;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -4;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 = -num11;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 1858339988;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 += -1858339987;
							}
							if (num3 != (uint)num13)
							{
								int num15 = -4;
								_ = 0;
								for (int num16 = 0; num16 < 1; num16++)
								{
									num15 = ~num15;
								}
								if (num3 != (uint)num15)
								{
								}
								return stateMachine._003C_003Et__builder.Task;
							}
							stateMachine._003C_003Et__builder.Start(ref stateMachine);
							int[] array = new int[6];
							array[0] = 1352173013;
							array[1] = -141452756;
							array[2] = 1644613438;
							array[3] = 1609176511;
							array[4] = -1903559040;
							array[5] = -678796612;
							array[4] = array[2] ^ -1456041982;
							array[3] = array[1] ^ 0x39EA6D41;
							array[4] = array[5] ^ 0x4B8CD34D;
							int[] array2 = new int[7];
							array2[0] = -933681634;
							array2[1] = 526850418;
							array2[2] = -2126578982;
							array2[3] = -119827983;
							array2[4] = 1312763952;
							array2[5] = -447645299;
							array2[6] = 2099554616;
							array2[0] = array[2] ^ 0x58485DE8;
							array2[4] = array2[1] ^ 0x8AC4949;
							array2[1] = array2[5] ^ -1462103537;
							int num17 = array2[0] ^ 0x351FF457;
							num = (int)((num4 * 1241408657) ^ 0xDE1577D9u) ^ num17;
						}
						else
						{
							stateMachine._003C_003E1__state = -1;
							int[] array3 = new int[6];
							array3[0] = -2105478237;
							array3[1] = 1553389452;
							array3[2] = -1195725224;
							array3[3] = -789049084;
							array3[4] = 805860649;
							array3[5] = -1360702064;
							array3[2] = array3[5] ^ 0x7E3AD100;
							array3[5] ^= 251518190;
							int[] array4 = new int[6] { -341445000, 1315690738, -171631154, -1218402847, -1752377608, 204421209 };
							int[][] array5 = new int[2][] { array3, array4 };
							array4[5] = array5[0][1] ^ 0x6579D3F4;
							array4[0] = array4[3] ^ 0x7D8F5E58;
							array4[1] = array4[5] ^ 0x2620BDF4;
							int num18 = array5[1][5] ^ 0x4E44F979;
							num = ((int)num4 * -2051664340) ^ -1932288152 ^ num18;
						}
					}
					else
					{
						stateMachine.filePath = filePath;
						int[,] array6 = new int[4, 3];
						array6[0, 0] = 1339609914;
						array6[0, 1] = -1238447844;
						array6[0, 2] = 1665293990;
						array6[1, 0] = -881677383;
						array6[1, 1] = -742176922;
						array6[1, 2] = -1929762471;
						array6[2, 0] = 570407753;
						array6[2, 1] = -1131738058;
						array6[2, 2] = -143569257;
						array6[3, 0] = 381462125;
						array6[3, 1] = 384228722;
						array6[3, 2] = 122611316;
						array6[0, 1] = array6[1, 1] ^ -517780967;
						array6[0, 1] = array6[2, 2] ^ -2076662299;
						array6[1, 0] = array6[2, 1] ^ -985800431;
						array6[2, 1] = array6[3, 2] ^ -1430916733;
						int num19 = array6[2, 1] ^ -504979121;
						num = (int)((num4 * 1439328238) ^ 0xAE78071Eu) ^ num19;
					}
				}
				else
				{
					stateMachine._003C_003E4__this = this;
					int[,] array7 = new int[3, 4];
					array7[0, 0] = -1027360793;
					array7[0, 1] = 1932932168;
					array7[0, 2] = 2110250421;
					array7[0, 3] = 970877158;
					array7[1, 0] = 509001139;
					array7[1, 1] = 558098868;
					array7[1, 2] = -1598733409;
					array7[1, 3] = -801753117;
					array7[2, 0] = -349060559;
					array7[2, 1] = 1335029916;
					array7[2, 2] = 1434923333;
					array7[2, 3] = 1140966443;
					array7[2, 0] = array7[1, 2] ^ -279208509;
					array7[1, 3] = array7[0, 2] ^ 0x425F8367;
					array7[1, 0] = array7[0, 0] ^ 0x7C17085F;
					int num20 = array7[1, 0] ^ 0x1D95B299;
					num = (int)((num4 * 661582453) ^ 0x4B01A23A) ^ num20;
				}
			}
		}
	}

	public void RefreshSummary()
	{
		AssemblyProfile assemblyProfile = _0029_0029_0023_0021_0040_0023_0029_0028(_assemblyWorkspaceService);
		while (true)
		{
			int num = 1817154995;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(-(~((((num2 - ~(-((~((0x6132783D ^ -(-513570544 - -1362531981)) * -783842301) ^ -928040007) + -(-(-(870573721 - -1578567105) ^ -(-1893009245 - ~-1787344094)))))) * 389630387) ^ ((-(~(-1215971098 + (1502363027 + 1690597988)) ^ 0x454F1471) ^ -970260251) * -321248595) ^ (-(~(0x3BEE4D70 ^ 0xB6F5A89)) * -210113503 + (~(1530722079 * 957541510 * 1462905795) + (-2123953834 - -1760251953 * -1525507706 - (0x7277EA3E ^ -671316470))) - (0x761EE5D4 ^ -1916366759))) * 1493743637) * -196398261 * -1121164127)))) % 5;
				int num5 = 838977408;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = 912331958 - (num5 ^ -1423874208);
					num5 = -(~num5);
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 740827867;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 += -740827864;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -5;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 = ~num9;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 1626796033;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = (num11 ^ 0x2F7233CD) + 76303683;
							num11 = 1632262778 - -num11;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 53305414;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 *= 1297055627;
							}
							if (num3 == (uint)num13)
							{
							}
							return;
						}
						_003D_005E_005E_002B_0026_0026_005E_003D((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[450 - 31 - 18 - 22]);
						num = -92132329;
					}
					else
					{
						ApplyProfile(assemblyProfile);
						int[] array = new int[5] { -1197021848, 107092580, -769804493, 839049379, -1289401588 };
						array[0] ^= -1385600566;
						array[2] ^= 110363027;
						array[0] ^= -874457962;
						int[] array2 = new int[6] { -1187906519, 1505400594, -1274102436, 1871735214, -963765235, -359822095 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[3] = array3[0][1] ^ 0x24BD5287;
						array2[2] = array2[4] ^ 0x55235536;
						array2[5] = array2[2] ^ -2053999699;
						array2[5] = array2[4] ^ 0x6C41FC7B;
						int num15 = array3[1][3] ^ 0x4A733E5F;
						num = ((int)num4 * -1010915932) ^ 0x2572F6EC ^ num15;
					}
				}
				else
				{
					int[,] array4 = new int[3, 4]
					{
						{ -654666165, -170404013, -886008591, 429935275 },
						{ 1221883238, -36680495, -222562836, -1993616152 },
						{ -1831913223, 499496511, 1915634848, -2014516725 }
					};
					array4[0, 2] ^= 471812880;
					array4[2, 1] = array4[1, 3] ^ 0x6B4B888B;
					array4[1, 3] = array4[0, 0] ^ -103374022;
					int num16 = array4[1, 3] ^ 0x498043CD;
					int[] array5 = new int[7];
					array5[0] = -939696976;
					array5[1] = 510742760;
					array5[2] = 707811484;
					array5[3] = -33343213;
					array5[4] = -1277563180;
					array5[5] = 683814487;
					array5[6] = 35387652;
					array5[4] = array5[5] ^ 0x4DDB1402;
					array5[2] = array5[1] ^ -166162146;
					array5[6] = array5[5] ^ 0x35E34CA6;
					int[] array6 = new int[7];
					array6[0] = 1275398036;
					array6[1] = -712712428;
					array6[2] = 337558754;
					array6[3] = -275213932;
					array6[4] = -1100917925;
					array6[5] = 363980761;
					array6[6] = 411185188;
					array6[3] = array5[5] ^ -467717465;
					array6[6] = array6[2] ^ 0x4E19EE30;
					array6[1] = array6[3] ^ 0x2D4E2759;
					int num17 = array6[3] ^ -1310062025;
					int num18 = (int)((num4 * 1339723814) ^ 0x3E2CEF9A);
					num16 ^= num18;
					num17 ^= num18;
					int num19;
					int num20;
					if (assemblyProfile != null)
					{
						num19 = num17;
						num20 = num19;
					}
					else
					{
						num19 = num16;
						num20 = num19;
					}
					num = num19 ^ num18;
				}
			}
		}
	}

	private void ApplyProfile(AssemblyProfile profile)
	{
		if (CodeVirtualization)
		{
			goto IL_000e;
		}
		int num = 0;
		goto IL_0335;
		IL_031b:
		num = ((!_0024_003E_0028_0023_0021__005E_0029(profile)) ? 1 : 0);
		goto IL_0335;
		IL_000e:
		int num2 = -1709148572;
		goto IL_0013;
		IL_0013:
		while (true)
		{
			int num3 = num2;
			uint num5;
			uint num4 = (num5 = (uint)(-((~((~(num3 * 284278893) - (~(~(-1242479772)) + (~(-1095108779 * -692255937) - 6022707)) - -((-(0x29AF7F19 ^ 0x68227A2B) - ((0x25614A7 ^ 0x33F93256) + (-1657139949 + -2141467720)) * 557889315) ^ 0x14EBBDF3)) * -2110002119) - (--1242316202 * 174248431 + -(1830994980 + -626641318))) * -250186331) - -1140767396)) % 6;
			int num6 = 796304730;
			_ = 0;
			for (int num7 = 0; num7 < 1; num7++)
			{
				num6 += -796304728;
			}
			if (num4 == (uint)num6)
			{
				break;
			}
			int num8 = 12413773;
			_ = 0;
			for (int num9 = 0; num9 < 1; num9++)
			{
				num8 -= 12413769;
			}
			if (num4 != (uint)num8)
			{
				int num10 = 375148387;
				_ = 0;
				for (int num11 = 0; num11 < 1; num11++)
				{
					num10 ^= 0x165C4F60;
				}
				if (num4 != (uint)num10)
				{
					int num12 = -496327796;
					_ = 0;
					for (int num13 = 0; num13 < 2; num13++)
					{
						num12 = -(num12 - 1559603659 * -219581513);
						num12 = -num12 - 848281769;
					}
					if (num4 != (uint)num12)
					{
						int num14 = 695251071;
						_ = 0;
						for (int num15 = 0; num15 < 2; num15++)
						{
							num14 = -513390267 * 367019781 - num14 - 1463761233;
							num14 ^= 0x1CB8FA49;
						}
						if (num4 != (uint)num14)
						{
							int num16 = 1415360253;
							_ = 0;
							for (int num17 = 0; num17 < 2; num17++)
							{
								num16 = -1959502670 - ~num16;
								num16 *= -1676722729;
							}
							if (num4 == (uint)num16)
							{
							}
							return;
						}
						AppViewModel.UpdateMethodSelectionCount(CountSelectedMethods());
						int[,] array = new int[4, 3]
						{
							{ 1132857571, 2027411299, 1788477024 },
							{ 1688962044, 793795006, 643435387 },
							{ 85240521, -1351254132, -1749103851 },
							{ 1541217944, -657576081, -937510239 }
						};
						array[2, 1] ^= -1041020018;
						array[2, 2] = array[0, 0] ^ 0x1B7BAD4C;
						array[1, 1] = array[2, 2] ^ 0x66788E47;
						array[1, 0] = array[3, 0] ^ -1849606718;
						int num18 = array[1, 0] ^ -117194307;
						num2 = ((int)num5 * -1213418097) ^ -1070297941 ^ num18;
					}
					else
					{
						AppViewModel.SetWorkspaceSummary(_0023__003C_003E_0024_005E_002F_0021(profile), isLoaded: true);
						num2 = -1989833877;
					}
				}
				else
				{
					CodeVirtualization = false;
					int[,] array2 = new int[3, 4];
					array2[0, 0] = 2051525520;
					array2[0, 1] = 1833030960;
					array2[0, 2] = 851304250;
					array2[0, 3] = 370146231;
					array2[1, 0] = -649444114;
					array2[1, 1] = -1125959817;
					array2[1, 2] = 1419863917;
					array2[1, 3] = 1215592757;
					array2[2, 0] = 631060605;
					array2[2, 1] = -1878846595;
					array2[2, 2] = -1822642037;
					array2[2, 3] = 1871776067;
					array2[0, 3] = array2[2, 2] ^ -429233063;
					array2[2, 2] = array2[2, 0] ^ -1581316584;
					array2[1, 0] = array2[1, 1] ^ 0x89C007A;
					array2[1, 1] = array2[2, 0] ^ -456149988;
					int num19 = array2[1, 1] ^ -1932503759;
					num2 = ((int)num5 * -484710603) ^ -1534705729 ^ num19;
				}
				continue;
			}
			goto IL_031b;
		}
		goto IL_000e;
		IL_0335:
		AssemblyPath = _005E_002F_0028_002B__002A_0026_0024(profile);
		AssemblyName = _0023__003C_003E_0024_005E_002F_0021(profile);
		RuntimeDisplay = _002A_0021_0024_003E_0040_003C__003F(profile);
		FileSizeDisplay = __0040_0025_002A_003F_0023_003C_002B(profile);
		HasSdkReference = _0024_003E_0028_0023_0021__005E_0029(profile);
		HasLoadedAssembly = true;
		int num20;
		if (num != 0)
		{
			num2 = -1777613699;
			num20 = num2;
		}
		else
		{
			num2 = 1300420944;
			num20 = num2;
		}
		goto IL_0013;
	}

	[AsyncStateMachine(typeof(_003CBrowseAssemblyAsync_003Ed__120))]
	private Task BrowseAssemblyAsync()
	{
		_003CBrowseAssemblyAsync_003Ed__120 stateMachine = default(_003CBrowseAssemblyAsync_003Ed__120);
		stateMachine._003C_003Et__builder = _0023_0028_0028_0024_0028_002A_0029_002D();
		while (true)
		{
			int num = 1241855986;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~((729662271 * 1688711552 - 1348153789 * -1586737022 - (((-(~-1785416885) - (-1123151582 ^ 0x149FE3AB) - 226686273) ^ -700548136) - ((~num2 ^ ~(~(--1054625669) + (1777087956 - -783140733 * -1313320309) - (-1507610610 ^ (-(-137546264 ^ 0x2E3E0CCB) - (--938908563 - (-1760755612 ^ 0x21C861DA))) ^ -1994679117) * -1189060953)) + ~(1595844073 + -1829371731 - ~-1854124746 + (1130012625 * 731058480 - 1950199497 * 122362995) + (0x17D673D3 ^ (0xBEE2B10 ^ -1281276712)) + ~-249409448 - (872364479 - (306780212 + 58309493 * (--60894849 * -1315369671)))) + (-(-145093683 * (-856682095 + 1613921472 - (-928647772 + -1831120863) + (-1609796687 * -1790625986 + (844047434 + 871600174)))) + (~(-1095569345 + 326903139 * -927281728) ^ ((-798666969 ^ 0x8A4C7C9) - ~1608529238)) * -404970961)) - (-(~1770038558) - (1279049443 - -1952868278 - ~-2015282492)) * -553144115 - -(-2035474359 ^ 0x376E739D))) * 1452642279))) % 5;
				int num5 = 169652500;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = (num5 * 987067) ^ 0x6FE1D601;
					num5 = -num5 - -1745926083;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1342553888;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = (num7 - -1543498845) ^ 0x6E47629E;
					num7 = ~(num7 - -70437802);
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = -1831913543 - -num9;
						num9 = -(num9 - -1801109167);
					}
					if (num3 != (uint)num9)
					{
						int num11 = -3;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 = -num11;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 1046893626;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = num13 * -880312909 + -1859178011;
								num13 = ~(num13 ^ 0x35C628A1);
							}
							if (num3 != (uint)num13)
							{
							}
							return stateMachine._003C_003Et__builder.Task;
						}
						stateMachine._003C_003Et__builder.Start(ref stateMachine);
						int[] array = new int[7];
						array[0] = -1794219533;
						array[1] = 1415168443;
						array[2] = 1049797745;
						array[3] = -2035829635;
						array[4] = -1755269023;
						array[5] = -1214952012;
						array[6] = -958964770;
						array[1] = array[2] ^ 0x1FCCDFDA;
						array[6] = array[5] ^ 0x5D585ADA;
						array[5] = array[2] ^ -1978993299;
						int[] array2 = new int[6];
						array2[0] = 358148806;
						array2[1] = 2052511881;
						array2[2] = -1575969153;
						array2[3] = 900195534;
						array2[4] = 1196220815;
						array2[5] = -349791710;
						array2[4] = array[2] ^ -1487702226;
						array2[5] = array2[1] ^ 0x595CFBF2;
						array2[1] = array2[0] ^ 0x7686C346;
						int num15 = array2[4] ^ 0x948B1BC;
						num = ((int)num4 * -1741111031) ^ 0x13807780 ^ num15;
					}
					else
					{
						stateMachine._003C_003E1__state = -1;
						int[,] array3 = new int[3, 4];
						array3[0, 0] = 1412653860;
						array3[0, 1] = -1903790303;
						array3[0, 2] = 677983684;
						array3[0, 3] = -164610231;
						array3[1, 0] = -507727890;
						array3[1, 1] = -554758726;
						array3[1, 2] = -275554609;
						array3[1, 3] = 2057660008;
						array3[2, 0] = 103196753;
						array3[2, 1] = -736183900;
						array3[2, 2] = 1844962203;
						array3[2, 3] = 394276909;
						array3[0, 2] = array3[2, 0] ^ 0x6EDE829D;
						array3[1, 0] = array3[2, 2] ^ 0x761F1C3C;
						array3[1, 0] = array3[0, 1] ^ -1134358468;
						int num16 = array3[1, 0] ^ 0x2264A60D;
						num = ((int)num4 * -346740540) ^ -806892576 ^ num16;
					}
				}
				else
				{
					stateMachine._003C_003E4__this = this;
					int[] array4 = new int[6];
					array4[0] = -472397036;
					array4[1] = -1760459739;
					array4[2] = -207310096;
					array4[3] = 163568926;
					array4[4] = -1296122991;
					array4[5] = -1489431229;
					array4[5] = array4[4] ^ 0x4E8C09E6;
					array4[0] = array4[4] ^ -752210263;
					int[] array5 = new int[6];
					array5[0] = 829732554;
					array5[1] = -84578528;
					array5[2] = -1164332353;
					array5[3] = -2084944793;
					array5[4] = -1392576835;
					array5[5] = -1060831195;
					array5[3] = array4[3] ^ 0x57B7A70F;
					array5[5] = array5[4] ^ -809865599;
					array5[5] = array5[4] ^ -2130466008;
					array5[0] = array5[2] ^ -77540952;
					int num17 = array5[3] ^ -1074949431;
					num = (int)((num4 * 2046267355) ^ 0x2F46A25A) ^ num17;
				}
			}
		}
	}

	private ProtectionOptions BuildOptions()
	{
		ProtectionOptions protectionOptions = new ProtectionOptions();
		_0029_005E_003C_002B_005E_002F_0040_0040(protectionOptions, AntiTamper);
		_0023_0024_002F_002B_002A_003C_0029_005E(protectionOptions, (AntiTamperModeIndex == 1) ? AntiTamperMode.Jit : AntiTamperMode.Normal);
		_005E_0028_003E_0024_0026_0024_002A_002B(protectionOptions, AntiVm);
		_002A_002D_0040_0029_0024_0024_002A_0021(protectionOptions, CodeVirtualization);
		_003F_0023_0026_0021_0024_0026_0040_0029(protectionOptions, ControlFlowObfuscation);
		_005E_0040_003D_0023_003F_005E_0028_003E(protectionOptions, LibraryMode);
		_002D_0024_0028_002A_0026_003C_005E_005E(protectionOptions, ReferenceProxy);
		__0024_0025_0026_003F_002D_005E_0024(protectionOptions, ResourceProtection);
		_002B_002F_003E_0025_0028_0028_0040_002D(protectionOptions, StringEncryption);
		_002A_005E_0021_005E__0025_003C_0028(protectionOptions, SymbolRenaming);
		return protectionOptions;
	}

	private bool CanOpenMethods()
	{
		return CanAccessMethodExplorer;
	}

	private bool CanProtect()
	{
		if (HasLoadedAssembly)
		{
			uint num2;
			int num4;
			do
			{
				int num = 94826237;
				uint num3;
				num2 = (num3 = (uint)(-2140925913 + (1318619326 + 1927669464) + -(2071456980 + 510812314) - (~(~(num - (((-1431262027 * (~(-(1345153359 * -247070358)) - (-1882084111 * -378997685 * 1230588807 + ~(269084354 + 2099475557)) - -(~(1935192293 * 2016687045 * -812405941))) * -371067533) ^ (~(~((0x79BF1020 ^ 0x5DB971DC) - (1540046705 - ~(--1754914284)))) ^ 0x707B9F85)) - (-216103629 - -(599842191 * (-694864025 * 2072660209)) + (--1497289048 + ~((-((0x3C93F50F ^ -1722751146) + --1736899697) ^ -(-1324601157 ^ -1807102594)) * -1726923887)))) - -1506247127 * ((-1140259675 ^ -598632463) - (-738961463 ^ (~(-1949639973 * -1857405272 + (-1784265601 ^ 0xD473CE7)) - (-1846467209 * --794524340 + 649368882 * 680070633)))) * 328235541)) - (1430619445 - (-(~457756324) + (1643988908 + -1142532080 + (-1601336751 + 1555506874)) + (-1440594114 + (-1381499653 ^ -595485176))))) * 1146268253)) % 3;
				num4 = 4;
				_ = 0;
				for (int num5 = 0; num5 < 2; num5++)
				{
					num4 = -num4;
					num4 = ~(num4 ^ -55310648);
				}
			}
			while (num2 == (uint)num4);
			int num6 = -1676098703;
			_ = 0;
			for (int num7 = 0; num7 < 1; num7++)
			{
				num6 ^= -1676098704;
			}
			if (num2 == (uint)num6)
			{
				return !IsBusy;
			}
			int num8 = 319225396;
			_ = 0;
			for (int num9 = 0; num9 < 2; num9++)
			{
				num8 = (num8 * 705017029) ^ 0x5C388C67;
				num8 = -(num8 ^ 0x172EB409);
			}
			if (num2 == (uint)num8)
			{
			}
		}
		return false;
	}

	private int CountSelectedMethods()
	{
		AssemblyProfile assemblyProfile = _0029_0029_0023_0021_0040_0023_0029_0028(_assemblyWorkspaceService);
		while (true)
		{
			int num = 1118869697;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(~(636936565 + -384531400 - -1180759512)) - -(num2 - ((~-420966856 * -1838996383 + ~(-1668061802 ^ (((0x1505F894 ^ -532864621) + 292070453 * (-772258166 - 1957104229)) ^ -(-530393036 - (1845558471 + -275943703)))) - ~(-1224174171 - 478175573 * ~-1718323896 * 874746677)) ^ -(~(-(~((-465028898 - 308898052 - (1910000183 - -1392498655)) * 471047947))) ^ (~(1549975155 * -(-1624887572 ^ 0x2D4E876) - (--2075290653 + 172308440 - (0x69552E69 ^ 0x517C1B75))) + -(177061831 * (-1896510974 ^ 0x374F19CE))))) - ~(-1235677050 ^ (-(-847925059) - -848204276) ^ (-1990331683 ^ ~(~(-(--1869885722))))) * -1497708699 + -1088059373 * -1721779561 + (~(-(~(1699688099 + -232939996))) ^ -(0x26A8287A ^ 0xB40B430)) * -2104579101))) % 4;
				int num5 = 0;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~(~num5);
					num5 = -1237614214 + 1561977283 - num5 - 1577904431;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1301473421;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = ~num7;
					num7 = -(num7 - --1496746938);
				}
				if (num3 != (uint)num7)
				{
					int num9 = -1;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 = -num9;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 2;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = ~(num11 ^ -2015784544);
							num11 = ~num11;
						}
						if (num3 != (uint)num11)
						{
						}
						return _0025_005E_002F_0025__0021_003D_0040(assemblyProfile).SelectMany((NamespaceItem @namespace) => _003C_003Ec._0025_003C_002A_0028_0024_0021__002B(@namespace)).Sum((TypeItem type) => _0023_0029_002B_005E_0023_0024_0026_0024(_assemblyWorkspaceService, _002F_0021_0029_0021_0040_003E_003D_0026(type)).Count((MethodItem method) => _003C_003Ec._002D_003C_0023_0021_003D_003F_005E_0021(method)));
					}
					return 0;
				}
				int[,] array = new int[3, 3];
				array[0, 0] = 1010561175;
				array[0, 1] = 1077417012;
				array[0, 2] = -2121015562;
				array[1, 0] = 1578772853;
				array[1, 1] = -941777213;
				array[1, 2] = -2093808087;
				array[2, 0] = -362375285;
				array[2, 1] = -1973089577;
				array[2, 2] = 1348928022;
				array[2, 2] = array[2, 1] ^ -1349654608;
				array[0, 1] = array[2, 0] ^ -381855582;
				array[0, 2] = array[1, 0] ^ 0x1E098BCE;
				int num13 = array[0, 2] ^ 0x1F8C58A3;
				int[] array2 = new int[7];
				array2[0] = 730682420;
				array2[1] = -421498281;
				array2[2] = 359310893;
				array2[3] = 1831999524;
				array2[4] = -1379679323;
				array2[5] = 604676298;
				array2[6] = 805434593;
				array2[3] = array2[0] ^ 0x73EE3C70;
				array2[5] = array2[2] ^ -1578184113;
				int[] array3 = new int[5];
				array3[0] = -794228667;
				array3[1] = 1581071597;
				array3[2] = -200776656;
				array3[3] = -489068703;
				array3[4] = -1017043906;
				array3[1] = array2[2] ^ 0x5E7382A1;
				array3[4] = array3[3] ^ 0x4F43560;
				array3[4] = array3[3] ^ -525821445;
				array3[0] = array3[1] ^ 0x470C4AA5;
				int num14 = array3[1] ^ 0x16115213;
				int num15 = (int)(num4 * 1170285365) ^ -829422113;
				num13 ^= num15;
				num14 ^= num15;
				int num16;
				int num17;
				if (assemblyProfile == null)
				{
					num16 = num14;
					num17 = num16;
				}
				else
				{
					num16 = num13;
					num17 = num16;
				}
				num = num16 ^ num15;
			}
		}
	}

	private void OpenMethodExplorer()
	{
		if (!TryPrepareMethodExplorerNavigation())
		{
			goto IL_000e;
		}
		goto IL_054f;
		IL_000e:
		int num = -1333088793;
		goto IL_0013;
		IL_0013:
		int num2 = num;
		uint num4;
		uint num3 = (num4 = (uint)(~(-(-(-(-((886403935 * (-1927969889 * ((0x15C8D93C ^ 0x5A346926) * 1530943887) + (-1821480238 + ~(~(~-694305035) + -1863197333 * -756856173 * -726739451))) - (1704979092 - 1156561439 * -477612702 + (0x22BAD26A ^ 0x693182E) + ((0x19572E6B ^ 0x79EA84F4) + (0x32F1E5C9 ^ -1520571165)) * -407108681 * -2053665167 - ((--1087404580 - (-1517121569 + 1614292227)) * 821103377 + (42595343 * -2041667537 + -1498629434 - (-1444425330 + 1015582699 + -346774841)) + -(-1437411013 * (905917562 - 1848158968) - (-1324242288 ^ 0x53F3C4D3) * 1496266205) - (-218621076 - (~(-(-1191924326 * -1880741825)) + (-(~-692204012) + ~(-1910308127 + -379432322)))))) - -num2 + (1603102143 * (~(~-2031206411 * 359129961 - -2123450681) + ~(~(-2100748513) * 250665913)) + --491761413) + ((-(-321367482 ^ -62367097) * -579441471) ^ -(~(~(1993015208 * 273571267)) - (0x9F07DD9 ^ -1353611677 ^ -1615973862)))) * -719760291))))))) % 4;
		int num5 = -4;
		_ = 0;
		for (int num6 = 0; num6 < 1; num6++)
		{
			num5 = ~num5;
		}
		if (num3 == (uint)num5)
		{
			goto IL_000e;
		}
		int num7 = 1318628985;
		_ = 0;
		for (int num8 = 0; num8 < 2; num8++)
		{
			num7 = -(~num7);
			num7 -= -1488169155;
		}
		if (num3 == (uint)num7)
		{
			return;
		}
		int num9 = 536874432;
		_ = 0;
		for (int num10 = 0; num10 < 2; num10++)
		{
			num9 ^= --2056522882;
			num9 = (--866619093 - num9) ^ 0x699186F3;
		}
		if (num3 != (uint)num9)
		{
			int num11 = 2;
			_ = 0;
			for (int num12 = 0; num12 < 2; num12++)
			{
				num11 = ~(num11 + (2133206662 - 1579729092));
				num11 -= ~1588931266;
			}
			if (num3 == (uint)num11)
			{
			}
			return;
		}
		goto IL_054f;
		IL_054f:
		AppViewModel.Navigate(ShellSection.Methods);
		num = 473045278;
		goto IL_0013;
	}

	[AsyncStateMachine(typeof(_003CProtectAsync_003Ed__126))]
	private Task ProtectAsync()
	{
		_003CProtectAsync_003Ed__126 stateMachine = default(_003CProtectAsync_003Ed__126);
		stateMachine._003C_003Et__builder = _0023_0028_0028_0024_0028_002A_0029_002D();
		while (true)
		{
			int num = -155771787;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(((~(~((-2019009083 * ~-1732377270 - ~(num2 * -1851482081)) ^ -1749803016) - -7479203) * 1495079923) ^ -1768515525) * 185489635)) % 5;
				int num5 = -1276681488;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = (num5 - (158348874 + 120409877)) * 1848405771;
					num5 = (num5 ^ 0x35314F32) + -503786933;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 2095469571;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = 630232046 - (num7 ^ -1928855241);
					num7 = (-502930679 ^ 0x7BBC8901) - num7 - -1499201253;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -1369380559;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 ^= -1369380557;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 1189396196;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = (num11 ^ 0x4E39D15D) * 39495013;
							num11 = (num11 + (-2062738145 + -1704859472)) * -14644935;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 724867269;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 *= -981785075;
							}
							if (num3 != (uint)num13)
							{
							}
							return stateMachine._003C_003Et__builder.Task;
						}
						stateMachine._003C_003Et__builder.Start(ref stateMachine);
						int[] array = new int[5];
						array[0] = -109921435;
						array[1] = 189142390;
						array[2] = -1123068836;
						array[3] = 1995884694;
						array[4] = 1607246372;
						array[4] = array[0] ^ -1081448108;
						array[3] ^= 1995158550;
						array[0] = array[4] ^ 0x26CB1C3C;
						int[] array2 = new int[5];
						array2[0] = -1921587987;
						array2[1] = 1684872963;
						array2[2] = -896488491;
						array2[3] = -1075181181;
						array2[4] = -900226861;
						array2[2] = array[2] ^ -998863871;
						array2[0] = array2[3] ^ 0xEDDEF49;
						array2[3] = array2[0] ^ -1739313843;
						int num15 = array2[2] ^ 0xAC3E30E;
						num = (int)((num4 * 998578744) ^ 0x56D0AB48) ^ num15;
					}
					else
					{
						stateMachine._003C_003E1__state = -1;
						int[] array3 = new int[5];
						array3[0] = -1554200724;
						array3[1] = -347887739;
						array3[2] = -1211389696;
						array3[3] = -427819774;
						array3[4] = 1574890246;
						array3[3] = array3[0] ^ 0x6BC9C8E5;
						array3[4] = array3[0] ^ 0x3C1C54AA;
						array3[0] = array3[3] ^ 0xA8B5E2E;
						int[] array4 = new int[5];
						array4[0] = -1981277025;
						array4[1] = -986930845;
						array4[2] = 1884178037;
						array4[3] = -2041652552;
						array4[4] = -146317433;
						array4[4] = array3[2] ^ -1265096217;
						array4[2] ^= 1447578851;
						array4[3] = array4[4] ^ 0x1C66EC75;
						int num16 = array4[4] ^ 0x52FA9A92;
						num = ((int)num4 * -1047559006) ^ 0x197A0FE6 ^ num16;
					}
				}
				else
				{
					stateMachine._003C_003E4__this = this;
					int[,] array5 = new int[4, 3];
					array5[0, 0] = 1406847820;
					array5[0, 1] = -1310530157;
					array5[0, 2] = -1800942558;
					array5[1, 0] = 477281729;
					array5[1, 1] = -1965702861;
					array5[1, 2] = -1178157981;
					array5[2, 0] = -1116828059;
					array5[2, 1] = -78362379;
					array5[2, 2] = 1136715089;
					array5[3, 0] = 1341972610;
					array5[3, 1] = -245149577;
					array5[3, 2] = -1622834007;
					array5[0, 2] = array5[1, 2] ^ -638653708;
					array5[3, 2] = array5[1, 1] ^ 0x76909D7C;
					array5[3, 1] = array5[3, 0] ^ 0x662FF139;
					int num17 = array5[3, 1] ^ -306237334;
					num = (int)((num4 * 57299671) ^ 0xBA8DC8D9u) ^ num17;
				}
			}
		}
	}

	private void SetStatus(string message, SeverityLevel level)
	{
		StatusMessage = message;
		while (true)
		{
			int num = -1466022161;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(((num2 * 1360219177) ^ (1018696342 - (0xABEB2FD ^ -540013244) * 1856751559 + (~(--295566255) - -1483213888 - 1585040104) - (-876718822 + (-(~-1195471622) - 678713931)))) * 1519034161 + (-636390617 ^ 0x4E9CB88F)))) % 3;
				int num5 = -1118103680;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = num5 ^ 0x5033EA9C ^ -1586790536;
					num5 *= -832890911;
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
					num7 = 1452584050 - (num7 - (33691157 - -1736095060));
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1032223576;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 = 1032223578 - num9;
					}
					if (num3 == (uint)num9)
					{
					}
					return;
				}
				StatusLevel = level;
				int[,] array = new int[3, 4];
				array[0, 0] = 288714789;
				array[0, 1] = -1244955782;
				array[0, 2] = 984003144;
				array[0, 3] = -839610865;
				array[1, 0] = -1522960478;
				array[1, 1] = -349465483;
				array[1, 2] = 1097513287;
				array[1, 3] = 1390048149;
				array[2, 0] = 1815222605;
				array[2, 1] = -757353534;
				array[2, 2] = 1023229217;
				array[2, 3] = 844656720;
				array[1, 2] = array[1, 0] ^ 0x775AC1A0;
				array[1, 2] = array[2, 2] ^ 0x7FD36076;
				array[1, 1] = array[2, 1] ^ -1764834774;
				array[0, 0] = array[2, 1] ^ 0x6D0D624A;
				int num11 = array[0, 0] ^ -953874219;
				num = ((int)num4 * -440920136) ^ -130213352 ^ num11;
			}
		}
	}

	public bool TryPrepareMethodExplorerNavigation()
	{
		if (!HasLoadedAssembly)
		{
			goto IL_000e;
		}
		goto IL_1084;
		IL_000e:
		int num = -2109024043;
		goto IL_0013;
		IL_0013:
		uint num3;
		while (true)
		{
			int num2 = num;
			uint num4;
			num3 = (num4 = (uint)((((num2 + (~(~566953175) - (~(~((0x39EEB3F3 ^ 0x37AC831A) + (-543420701 ^ -801725917))) - (~(-1574632115 - 1164007267 + (-2072009317 + 1903742335) + -(-668788634)) - (-(-(-457182336)) - 306552923 * (0x6252AFF4 ^ 0x4FA8C580))) + -(-1685784941 ^ (-(--1743195483 - 1900547871 * -135801459) ^ 0x38B5F984))) - ((-(1214306993 + 1959084955 + ~-508352650 + (0x6FE8CA17 ^ 0x6AA07926) + -280307012 - ((0x4A958D2A ^ 0x60DA5C9C) - ~(~134571967) - (~870278752 - (2141076654 + -1004705952) * 91506847))) ^ ~(-231267089 ^ (232020953 + (~(-1980871531) ^ -1794230469)))) + (-1570016721 ^ 0x3E34A884))) - -((-2001661745 ^ -2030888739) + (~((~(-1074719829) ^ -1523965642) + ~-1422328009) - ~(-(-182232317 + (-876208450 + 1045898062) - ~(16328123 - 1674934828)))))) * -376744939) ^ ~(-1017039823 * (-2116846245 + ~(-(--79886929))))) - ~(-(1619039096 + (0x14EEB79D ^ --364651623))))) % 10;
			int num5 = -6;
			_ = 0;
			for (int num6 = 0; num6 < 1; num6++)
			{
				num5 = -num5;
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = -4;
			_ = 0;
			for (int num8 = 0; num8 < 1; num8++)
			{
				num7 = -num7;
			}
			if (num3 != (uint)num7)
			{
				int num9 = 26665781;
				_ = 0;
				for (int num10 = 0; num10 < 2; num10++)
				{
					num9 = -num9 - -1188496149;
					num9 = -(num9 - (1872472734 + 1450174176));
				}
				if (num3 != (uint)num9)
				{
					int num11 = -798513207;
					_ = 0;
					for (int num12 = 0; num12 < 1; num12++)
					{
						num11 *= 1861891649;
					}
					if (num3 != (uint)num11)
					{
						int num13 = 6;
						_ = 0;
						for (int num14 = 0; num14 < 2; num14++)
						{
							num13 = -num13 ^ -1647528234;
							num13 = -(-num13);
						}
						if (num3 != (uint)num13)
						{
							int num15 = -1490575763;
							_ = 0;
							for (int num16 = 0; num16 < 2; num16++)
							{
								num15 = (num15 + ~-660681679) * 1888508371;
								num15 = num15 - (-889644601 ^ -142949596) + 1676987360;
							}
							if (num3 != (uint)num15)
							{
								int num17 = -672880973;
								_ = 0;
								for (int num18 = 0; num18 < 2; num18++)
								{
									num17 = -num17 * 1281990553;
									num17 = -(-num17);
								}
								if (num3 != (uint)num17)
								{
									int num19 = -9;
									_ = 0;
									for (int num20 = 0; num20 < 1; num20++)
									{
										num19 = ~num19;
									}
									if (num3 == (uint)num19)
									{
										SetStatus(_003E_0021_0040_003F_005E_003D_0024_0025(_strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4528 - 4158 + 18]), SeverityLevel.Warning);
										int[] array = new int[5];
										array[0] = 1537161125;
										array[1] = -263488750;
										array[2] = 2096275006;
										array[3] = -1223801257;
										array[4] = 934113055;
										array[1] = array[0] ^ -490662620;
										array[1] = array[2] ^ 0xBDBDF4A;
										int[] array2 = new int[5];
										array2[0] = 1055994213;
										array2[1] = -1422980388;
										array2[2] = -731835383;
										array2[3] = -389472060;
										array2[4] = -528150332;
										array2[0] = array[2] ^ 0x39AFF2CE;
										array2[4] = array2[0] ^ -276216466;
										array2[3] = array2[2] ^ -1167882565;
										int num21 = array2[0] ^ -252107162;
										num = ((int)num4 * -258849470) ^ -2123841008 ^ num21;
										continue;
									}
									goto IL_050c;
								}
								int num22;
								if (!HasSdkReference)
								{
									num = 743461987;
									num22 = num;
								}
								else
								{
									num = 843209053;
									num22 = num;
								}
								continue;
							}
							return false;
						}
						SetStatus(_003E_0021_0040_003F_005E_003D_0024_0025(_strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[2285 - 1907 + 20]), SeverityLevel.Warning);
						int[] array3 = new int[4];
						array3[0] = 1126089835;
						array3[1] = 317355031;
						array3[2] = 424220183;
						array3[3] = -329270181;
						array3[1] = array3[3] ^ 0xD310CA7;
						array3[2] ^= 1434185741;
						int[] array4 = new int[6] { 1135398646, 1267647856, -1191817943, 1092348426, -1118978675, -630111725 };
						int[][] array5 = new int[2][] { array3, array4 };
						array4[2] = array5[0][3] ^ -1741779382;
						array4[0] = array4[4] ^ -1184113460;
						array4[1] = array4[3] ^ -1081209568;
						array4[5] = array4[2] ^ -657003661;
						int num23 = array5[1][2] ^ 0x5B90F763;
						num = (int)((num4 * 642954880) ^ 0xBC1AC100u) ^ num23;
						continue;
					}
					goto IL_1084;
				}
				return false;
			}
			SetStatus(_003E_0021_0040_003F_005E_003D_0024_0025(_strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-481 + 83)]), SeverityLevel.Warning);
			int[] array6 = new int[5];
			array6[0] = -592582315;
			array6[1] = 1832223210;
			array6[2] = 965280875;
			array6[3] = -1056175140;
			array6[4] = -1879984112;
			array6[2] = array6[0] ^ -918166936;
			array6[2] = array6[4] ^ -971041779;
			array6[3] = array6[2] ^ -1397209274;
			int[] array7 = new int[5] { -983141791, 808533760, 255850698, -1326231629, 1241634133 };
			int[][] array8 = new int[2][] { array6, array7 };
			array7[2] = array8[0][0] ^ -1814699;
			array7[3] = array7[1] ^ -1457895993;
			array7[3] = array7[4] ^ -2025051149;
			int num24 = array8[1][2] ^ 0x457AD342;
			num = (int)((num4 * 1781405249) ^ 0x81A645E2u) ^ num24;
		}
		goto IL_000e;
		IL_050c:
		int num25 = 1036132899;
		_ = 0;
		for (int num26 = 0; num26 < 2; num26++)
		{
			num25 = 1629417200 - ~num25;
			num25 = -(-num25);
		}
		if (num3 != (uint)num25)
		{
			int num27 = 70701566;
			_ = 0;
			for (int num28 = 0; num28 < 1; num28++)
			{
				num27 -= 70701566;
			}
			if (num3 != (uint)num27)
			{
			}
			return true;
		}
		return false;
		IL_1084:
		int num29;
		if (!CodeVirtualization)
		{
			num = 1086206109;
			num29 = num;
		}
		else
		{
			num = 1765887208;
			num29 = num;
		}
		goto IL_0013;
	}

	static void _003D_005E_005E_002B_0026_0026_005E_003D(ObservableObject P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1232070378;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(2036992025 - (0x5BD956A3 ^ 0x322D635E) - ((~1733448015 * -478564811 - ~(((-502612885 * ((386153341 * (-1570081327 ^ -740628317) - (--202994203 + -306504840)) ^ -(0x76D17B ^ ((0x1E9B090B ^ -1533949190) - -608700069 * -1942781233 + ~(0x71CE7279 ^ 0x4E42104C) - (-280655188 ^ --1288014359)))) * 2094314767 - num2) ^ ~(~(~(-(~(-201504244 + 1394113624) + (870499381 - -176715113 + (2104348207 - 1708820895)))) ^ -591767496))) - (((-(-1107124773 - -1392939271) - -1654730783) ^ -768782569) - (0x100986B8 ^ -207652167) + (~(0x741D3525 ^ 0x43D97107) - ~(-1169306841 * (-2005478194 * 566494499)) - (~-2020797137 - (651059069 * -1907833911 + (-32272757 - -783666828)) * 1819425897)) - (~(-((-1364087288 ^ -1513159521) * 83948593) ^ (-540843243 * -(~-1916724481))) - -((-348915086 ^ -1433845078) * -1567678167))))) ^ -((-1816848163 ^ -2093199490) - ~(~-517074076))) - -(-1079410065 * -2020347256)) - 1247317275)) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= 1802325897;
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
					P_0.OnPropertyChanged(P_1);
					int[] array = new int[4];
					array[0] = 546055092;
					array[1] = -1003540229;
					array[2] = 2122806048;
					array[3] = 1178377770;
					array[3] = array[1] ^ 0x2520ABEB;
					array[3] = array[1] ^ -1695716013;
					array[3] ^= 963336222;
					int[] array2 = new int[4];
					array2[0] = -1214007343;
					array2[1] = 1372466609;
					array2[2] = 768609938;
					array2[3] = 1925345723;
					array2[3] = array[2] ^ 0x1D568B33;
					array2[2] = array2[0] ^ -251392667;
					array2[1] = array2[0] ^ -254994074;
					int num11 = array2[3] ^ -894635880;
					num = (int)((num4 * 317219060) ^ 0x4A1B4D8) ^ num11;
				}
			}
		}
	}

	static string _003E_0021_0040_003F_005E_003D_0024_0025(IStringResourceService P_0, string P_1)
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
				int num = 1601890292;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((num2 ^ ~(-1470767021 * -704050659)) + (((-((-10210305 - --780134673) * -737811035 + (680341394 - 1837235934 + ~1713088055 - -(~-1157021589))) ^ 0x31F6045A) - (-(1734031649 * (-267964305 * (-483512949 - 1823157401)) - (~(~-349483091) + ~-450908901 * 439520257)) - (-1020974852 ^ (-(-212633410 + 311623662) + (--1300250516 + ~-594253836) - 1508444329)))) ^ ((-1777712163 ^ (~(-(~1039541621) - -1919191231) + (0xCF67D82 ^ 0x5608A57))) - (-((-123972760 - -707043643) ^ -1527255302) - ~(~(-1749940925) - (-1873596866 ^ 0x39795264))) * 1866727615))) ^ 0x346DA5BE ^ (((-798091579 + (--400757858 - 165886330 * -1822324315 - ((0x3174B596 ^ 0x3EC3FD53) + 321270664 * 2061317151))) ^ -1099113274) - ((-1892069961 * ~(-(~-1827828817))) ^ -1860597637)))) % 3;
					int num5 = 1670402781;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 1670402781;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 150643033;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(num7 - --1462983956);
						num7 = -(num7 + ~1387662438);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(-num9);
							num9 = 361538326 - (num9 - ~267162714);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.GetString(P_1);
					int[] array = new int[7];
					array[0] = -1868318544;
					array[1] = -1939665085;
					array[2] = -1487074530;
					array[3] = 1186702159;
					array[4] = 1631569710;
					array[5] = -447176388;
					array[6] = -1668006419;
					array[3] = array[2] ^ 0x96B6DD0;
					array[3] = array[1] ^ 0x2E40A2A0;
					array[5] = array[4] ^ 0x4F9118B1;
					int[] array2 = new int[7];
					array2[0] = -780643200;
					array2[1] = -889384790;
					array2[2] = -1980322633;
					array2[3] = -621685113;
					array2[4] = -984732342;
					array2[5] = -156587937;
					array2[6] = -193599964;
					array2[1] = array[4] ^ 0x4B6CE9E7;
					array2[2] = array2[0] ^ 0x1BB41F3D;
					array2[6] = array2[2] ^ -1670815047;
					int num11 = array2[1] ^ 0x490A683A;
					num = ((int)num4 * -986996267) ^ 0x3F8F6DDD ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _003C_0024_0029_002A_002D_0021_003E_0028(RelayCommand P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1875122685;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((-(0xA344664 ^ (-1703743208 - -(767192219 * 1525916385))) ^ -883795936) - -((num2 * 28199921) ^ (-1864363231 - -1391267469 * ((-248184650 ^ -774286030) + (-485308341 ^ -203944011) - ~(~-1859591449)) + -1277749087 * -(-2051181899 - 720484577 * (90033722 + --572055954)) - ((1112968085 * (771464659 + 1266427747 + --1680716756)) ^ ~(~(1676440493 + -1458159997) - ~(-745446023 ^ 0x7B8515DF) - -141692923 - -(-772965056 ^ (-10001411 + (-1400550914 - 102567823)))))))))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(-num5);
						num5 = -(num5 ^ 0x5AC5BE90);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1616893290;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += 1616893291;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9;
							num9 = -(num9 ^ -1497226337);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.NotifyCanExecuteChanged();
					int[,] array = new int[3, 4];
					array[0, 0] = 1705986229;
					array[0, 1] = 601251933;
					array[0, 2] = 1853430468;
					array[0, 3] = -1403937770;
					array[1, 0] = 1739624824;
					array[1, 1] = 1894316902;
					array[1, 2] = 1336339862;
					array[1, 3] = 1331796709;
					array[2, 0] = -137464634;
					array[2, 1] = -248118982;
					array[2, 2] = -1644623;
					array[2, 3] = -1904249710;
					array[1, 3] = array[2, 1] ^ 0x10BB43D8;
					array[0, 3] = array[2, 3] ^ 0x58BFF02E;
					array[0, 3] = array[0, 2] ^ 0x7AFE085D;
					array[2, 1] = array[2, 3] ^ -882125329;
					int num11 = array[2, 1] ^ 0x33869216;
					num = ((int)num4 * -1083857677) ^ -913583386 ^ num11;
				}
			}
		}
	}

	static int _0028_0026_0025_003F_0024_002A_002F_005E(ProtectionOptions P_0)
	{
		int selectedCount = default(int);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 2132273773;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(-(126780977 * (((0x56893468 ^ -2072664050) - 278149019 * (-1162279521 * -740008506)) * 422269235 + -(-(-496436132) ^ 0x49C425BD ^ 0x6A7E1D92)) - (-454007597 + (~(~-1690772835 + (-767208755 ^ -776527273) + ~-709327756) - ~(~(~(--2030186476))) + ((0x5D63521C ^ 0x1A60D549) - (-57988701 ^ (-1097302489 * -(0x503193C1 ^ -304774818))))))) - num2) + -(~-1641097415)))) % 3;
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
					int num7 = 231916387;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 231916385;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -609750626;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -609750627;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					selectedCount = P_0.SelectedCount;
					int[] array = new int[6];
					array[0] = -1520392234;
					array[1] = 1702771265;
					array[2] = -843570633;
					array[3] = 1700060622;
					array[4] = -1977738368;
					array[5] = -1507247425;
					array[3] = array[2] ^ 0x13B3E9B2;
					array[3] = array[0] ^ -1891450987;
					int[] array2 = new int[7];
					array2[0] = 1640787791;
					array2[1] = 315409392;
					array2[2] = -547537600;
					array2[3] = -1019175673;
					array2[4] = 1549883158;
					array2[5] = 1983957491;
					array2[6] = -1385212677;
					array2[3] = array[1] ^ 0x7A1828D5;
					array2[4] = array2[3] ^ -1178400689;
					array2[4] = array2[5] ^ -170687195;
					array2[5] = array2[6] ^ -294482196;
					int num11 = array2[3] ^ 0x532B2595;
					num = ((int)num4 * -1360970293) ^ 0x48F292F7 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return selectedCount;
	}

	static void _002A_003F_003D_003D_005E_0025_003C_002D(IRelayCommand P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			P_0.NotifyCanExecuteChanged();
		}
	}

	static bool _005E_0021_0029_002A_0023_0025_0025_003C(string P_0)
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
				int num = -683684126;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((((-(num2 * -1429795921 + ~(220687845 * ~(-1265814947 * (109804831 * -1102161435)))) * -1277575157 * -648009705) ^ ~(~(--1497933315 - 370775716))) + ~(-1637708068 * -29771887 - (-1113141590 + -1134692072))) ^ (-260106603 + (-284583492 - -292712183)) ^ -1715676556))) % 3;
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
					int num7 = 1846004230;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = 1846004231 - num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 227541480;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9 * 860934105;
							num9 = num9 - ~-1269308023 - -958550790;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = string.IsNullOrWhiteSpace(P_0);
					int[,] array = new int[3, 3]
					{
						{ 1814958110, 1840452901, -2132045547 },
						{ -705656160, 1816087426, 1196880986 },
						{ 264258334, 433786749, 16043404 }
					};
					array[0, 2] ^= -1176071865;
					array[0, 1] = array[1, 0] ^ -2064103676;
					array[0, 1] = array[2, 0] ^ 0x10ADAFAB;
					array[1, 0] = array[0, 0] ^ -449375157;
					int num11 = array[1, 0] ^ -752716348;
					num = ((int)num4 * -853995817) ^ -2072629527 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static AsyncTaskMethodBuilder _0023_0028_0028_0024_0028_002A_0029_002D()
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return AsyncTaskMethodBuilder.Create();
		}
	}

	static AssemblyProfile _0029_0029_0023_0021_0040_0023_0029_0028(IAssemblyWorkspaceService P_0)
	{
		AssemblyProfile currentProfile = default(AssemblyProfile);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 612893881;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(1879645505 - ~(-1761653335 * --1562196323 - -(~((-num2 * 662437501 * 779553675 - 493669615 * (((--1503161729 - -59937769) ^ 0xB27F46C) + ((-1885101339 - ~41731378) ^ 0x3B49863) - -(-(-295034900 * -494722647) * -1107119357))) * 301037731))))) % 3;
					int num5 = -1675150207;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= -1675150205;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -920766207;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(-num7);
						num7 = (num7 ^ -102747034) * 1991807111;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 ^ -196836800 ^ 0x58A99F49;
							num9 = -(num9 ^ -1741849222);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					currentProfile = P_0.CurrentProfile;
					int[] array = new int[5];
					array[0] = 422717305;
					array[1] = -757848257;
					array[2] = 20398323;
					array[3] = -1610128357;
					array[4] = 326907208;
					array[1] = array[2] ^ 0x36059CC0;
					array[4] ^= 1613009;
					array[1] = array[3] ^ -1376341336;
					int[] array2 = new int[4];
					array2[0] = -1693758576;
					array2[1] = -1641135593;
					array2[2] = 121022615;
					array2[3] = -680522705;
					array2[3] = array[2] ^ 0x13D53D13;
					array2[2] = array2[1] ^ 0x6F838480;
					array2[0] ^= 163770032;
					array2[0] = array2[3] ^ 0x2E567EAE;
					int num11 = array2[3] ^ -1190769366;
					num = ((int)num4 * -1402460667) ^ 0x6F88AAB2 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return currentProfile;
	}

	static bool _0024_003E_0028_0023_0021__005E_0029(AssemblyProfile P_0)
	{
		bool hasSdkReference = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1139822790;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((-(~(~(-485367261 ^ -525175142) - (num2 - 546062691 * (--1575061883 + (((0x141F264C ^ 0x2104DFC6) - (-98604234 ^ -70109141) - (-631268241 - -577171435 - ~-155132952 - (-242945163 ^ 0x1C3344D))) * -1334110741 + (~(~-1876843233 - (197831914 + -1045845896)) + ~(1497811915 * (-777661912 * -1133993451)) + 1673989805 * (0x5F88D5AB ^ (-1395786511 * -60573569 + -950687925))) + ~(~(-1998636040 * -892572413) + 753544594 - ~(-1190338289 * ~(~-999885815))))))) ^ (~(1503646165 * (--736681065 - ((-949628381 ^ 0x26D2969A) + -1251464081))) ^ (-1423876139 - --1718463228)) ^ (-976187097 * -(-(-1110013195 + 1647429830)) + -360980875) ^ 0x1F259F4F) + -1828623559 * (0x5B81B435 ^ -1931315833)) ^ -1573054221))) % 3;
					int num5 = 132120880;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 ^ -1624878309);
						num5 = -858849497 - (num5 ^ -1362909861);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 422819241;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 + -372778901;
						num7 = --1183516553 - num7 + 379778574;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -494919026;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 += 494919028;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					hasSdkReference = P_0.HasSdkReference;
					int[,] array = new int[4, 3];
					array[0, 0] = -220959461;
					array[0, 1] = -211528208;
					array[0, 2] = -391489405;
					array[1, 0] = 2047887289;
					array[1, 1] = 1052279758;
					array[1, 2] = -1302656981;
					array[2, 0] = 2119516609;
					array[2, 1] = -1376086930;
					array[2, 2] = -1373250539;
					array[3, 0] = 430338186;
					array[3, 1] = 1424347815;
					array[3, 2] = 754303107;
					array[3, 2] = array[0, 2] ^ 0x63BCF762;
					array[1, 2] = array[2, 2] ^ 0x5A718B29;
					array[2, 2] = array[0, 0] ^ 0x148A62F7;
					int num11 = array[2, 2] ^ 0x354D14A4;
					num = (int)((num4 * 286042143) ^ 0x1826050A) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return hasSdkReference;
	}

	static string _005E_002F_0028_002B__002A_0026_0024(AssemblyProfile P_0)
	{
		string filePath = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -410802260;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-1599229923 * -1397017403 - -(~(-(~(~(~(0x2456E922 ^ 0x15331CC0) - 1752117851))) - (num2 - -1093487249 * -(-(~((-66891746 - -764099522) ^ 0x30764B73) - (-((0x75F94990 ^ -197795595) * 182177281) ^ (-(-338044983) - (0x6DE644C9 ^ -733645450)))) - (~-798927542 - -2083032602)))) * -1271645325) - -1566308485 - ~-762125077 - (-1068589609 ^ -1589620390)) * 233804373)) % 3;
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
					int num7 = 1729434311;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (1165083387 * -1080187351 - num7) * -616088799;
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 314657304;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9;
							num9 = (num9 - ~1456972410) ^ 0x966B54E;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					filePath = P_0.FilePath;
					int[] array = new int[6];
					array[0] = 1528263583;
					array[1] = -1331156197;
					array[2] = 418547151;
					array[3] = -93565402;
					array[4] = 1498024655;
					array[5] = -119381487;
					array[1] = array[4] ^ 0x3F16AAF7;
					array[5] = array[2] ^ -91093458;
					int[] array2 = new int[7];
					array2[0] = -852653796;
					array2[1] = -2049717560;
					array2[2] = 361335477;
					array2[3] = -381001658;
					array2[4] = 1004520768;
					array2[5] = 2133382925;
					array2[6] = 362594099;
					array2[2] = array[0] ^ -1001439880;
					array2[0] = array2[4] ^ -145701049;
					array2[5] = array2[0] ^ -822104633;
					int num11 = array2[2] ^ 0x2B4D871F;
					num = ((int)num4 * -1585707194) ^ -1077479784 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return filePath;
	}

	static string _0023__003C_003E_0024_005E_002F_0021(AssemblyProfile P_0)
	{
		string assemblyName = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 559879423;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((-1833323650 ^ 0x597594B4) - (-804401865 + -823122225)) - (((~(~(-((~(~(-(-1220988720 - 1396757506) + (-1275273644 - 707665453 - --203977633))) + (-17073833 * (-1137585659 + 1931774489) - 1418551451 + (-1233467124 ^ --1747270604) * 1537265659) * -535723721) ^ (-1918541358 - (-1840983728 - (-(-1279573916 ^ -558213145) + (~(-1697110957 - -910442314) - -(-1819492642 - 852425250))))))) - num2) - ((-1474273743 * ~(-(-667586104 ^ ((-416281655 ^ 0x35056130) + -971155632)))) ^ (~(-(--2116062219)) - ~(-1127709187 ^ -1036398373) - (-1666344653 * (296865896 + -1902225922 - (0x718FB431 ^ 0x376855EC)) + (0x3AF3C677 ^ ((0x15D79DA1 ^ -725944182) + --195511668))) + -1383111239))) ^ (-((1717437358 + -508273373 + -656246918 + 1713457873) ^ -(18416961 + 13683590 * -1696075893)) ^ -2138724472)) + (0x234BD11B ^ -256136082) - --197498493))) % 3;
					int num5 = -745793180;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * -679232529 + 218971143;
						num5 = -num5 + -788010459;
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
						int num9 = 2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(-num9);
							num9 = -num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					assemblyName = P_0.AssemblyName;
					int[] array = new int[4] { 374228356, 138891338, -1176614932, -2115037193 };
					array[0] ^= -1012871738;
					array[2] = array[1] ^ 0x6755B573;
					int[] array2 = new int[4];
					array2[0] = -1414388350;
					array2[1] = -1997953656;
					array2[2] = 1494436160;
					array2[3] = 948897981;
					array2[0] = array[3] ^ 0x6D473F76;
					array2[1] ^= 1937087909;
					array2[1] = array2[0] ^ 0x4889C47F;
					int num11 = array2[0] ^ -1724833161;
					num = (int)((num4 * 774298373) ^ 0x90FB4400u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return assemblyName;
	}

	static string _002A_0021_0024_003E_0040_003C__003F(AssemblyProfile P_0)
	{
		string runtimeDisplay = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 429256410;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(-(1838730210 * 1503435855 - -(num2 * -1898879597) + 2008870556) * -285435191) - (133750463 - (-327021869 - 1289483347)) - ~-1366531759) ^ -1862579016)) % 3;
					int num5 = -862084138;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -num5 + -1270151549;
						num5 = (num5 - (1506866161 + -1990541789)) * -1421317561;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1894075268;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x70E54B85;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1562977214;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(num9 + (-1782159665 ^ 0x46102976));
							num9 = ~(num9 * -458162567);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					runtimeDisplay = P_0.RuntimeDisplay;
					int[] array = new int[4] { -658593412, -133119390, -96021229, 556028562 };
					array[3] ^= -2017354562;
					array[2] = array[3] ^ -250122129;
					array[1] = array[0] ^ 0x135A8AF7;
					int[] array2 = new int[6] { -605248601, -368265193, 1720664079, -75131402, 1094736651, 1484218135 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][0] ^ 0x7D41659B;
					array2[3] = array2[4] ^ 0x7E2FC684;
					array2[0] = array2[2] ^ 0x505BFEB8;
					array2[3] = array2[1] ^ -1470947087;
					int num11 = array3[1][2] ^ -512521142;
					num = ((int)num4 * -1143872046) ^ -952249802 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return runtimeDisplay;
	}

	static string __0040_0025_002A_003F_0023_003C_002B(AssemblyProfile P_0)
	{
		string fileSizeDisplay = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 808235160;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(~(706922810 - ~((num2 ^ (~(-(-(~-1215682223) + 655784141) - -(0x3023C36A ^ -1508046351) - ~(-(-1332769230 + (0x18826575 ^ -502884725)))) - ~(-((488439149 * (0x221B3C87 ^ -451999813) + (502655494 - (-1968931010 - -1091401481))) * -633592409 * 1967686967 - ~(-(-1257964232 + 1220636969) - ~(1066038359 - -1582750002) - 1391534618))))) - (-(-(~(~(0x383316E6 ^ -189116558)))) ^ (452312959 * (-(1249150485 * -951457867 - (373502119 - 1581057391) + ~(1911053359 * 1397461451)) - (-(-(0x46F4DC46 ^ 0x4F844EC3)) ^ -704863652))) ^ (-1521408217 ^ (-(-1604679035 ^ (-549346952 ^ -1346999388) ^ -782132435) ^ (-(-(-1097533925)) ^ -70719671 ^ -(~(-1585684284 - -890323070) - ~(1678701896 + -1698121641)))))) - (-(~(-1194093711 * 2017455971 + (~377744645 + -1973081876)) ^ 0x5C3CE603) + ~(1599814257 * ~((--323970324 ^ 0x6D33BD0C) * -1261977339)))) * 1180914485))) ^ 0x3225FE4E)) % 3;
					int num5 = -678982735;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= -678982735;
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
						int num9 = -267038215;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= -1741643703;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					fileSizeDisplay = P_0.FileSizeDisplay;
					int[] array = new int[7];
					array[0] = 1304506901;
					array[1] = -41246708;
					array[2] = -1305244999;
					array[3] = 1528310106;
					array[4] = 2025204578;
					array[5] = 4056576;
					array[6] = -1794262717;
					array[3] = array[2] ^ 0x703F5395;
					array[0] = array[6] ^ -1142014856;
					int[] array2 = new int[7] { -780442460, 680292969, -1872333403, -993128209, 15418617, 613985279, 65165209 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][6] ^ -1819235898;
					array2[2] = array2[0] ^ 0x69208D2E;
					array2[5] = array2[1] ^ -1765715696;
					int num11 = array3[1][1] ^ 0x3E90B651;
					num = (int)((num4 * 570514741) ^ 0x185EF8CC) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return fileSizeDisplay;
	}

	static void _0029_005E_003C_002B_005E_002F_0040_0040(ProtectionOptions P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 929234770;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(~((num2 ^ ((-(--185632491) + ((1594459025 - -1276303232 + ~-1058889070) * -1493661969 - (~1640474668 + (772301417 - 911971702) + (0x73786804 ^ 0x420303E9)) - (-1078577879 * (1558479072 * -1220474615) + -(-1605282969 - -1718022361) + -1523175155 * (--1702107774 ^ 0x3D6B376E))) + -(1107208331 * ((-954927975 * (-1897244017 ^ -1687367767) - (-60147084 - -193910849 * 1699539214)) ^ -(-580288427 * 1396152259 - -376988925 * -615443021)))) * -1633840355 + ~(~(0x2FF0D059 ^ ~(413162060 - (-709146704 ^ -27577469))) + (0x4855EE2A ^ (939746329 * (-(-(~-1401794729)) - -562719259 * (-2060745508 + -1019716248 + --124658854))))))) * -382712795 - ~(~-1837045444) - 1564482562 - -710416510) ^ 0x20BF98BB) - ~1309299371) * 1364148815)) % 3;
					int num5 = 625767942;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -num5 * -1145441429;
						num5 = ~num5 + 462897074;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1769999987;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += -1769999986;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1647324090;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = -1647324090 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.AntiTamper = P_1;
					int[] array = new int[6];
					array[0] = 1973946419;
					array[1] = -1606799334;
					array[2] = -229632924;
					array[3] = -321614176;
					array[4] = 1559312049;
					array[5] = -1269887375;
					array[0] = array[1] ^ -1673953833;
					array[1] = array[4] ^ -732638157;
					int[] array2 = new int[7] { 1039974759, -527858112, -938393620, -2080263174, -1647385279, 102244503, -1477766060 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][3] ^ 0x3FE65C07;
					array2[5] = array2[6] ^ 0x3E5E60DB;
					array2[3] = array2[6] ^ 0x3897289;
					array2[1] = array2[3] ^ 0x33FFEFDE;
					int num11 = array3[1][0] ^ 0x3F5A87B1;
					num = ((int)num4 * -1768339166) ^ 0x32EE5796 ^ num11;
				}
			}
		}
	}

	static void _0023_0024_002F_002B_002A_003C_0029_005E(ProtectionOptions P_0, AntiTamperMode P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 935501391;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(~(-(-(num2 + ((((~(--2081841615 ^ 0x330481B3) ^ ~(-(~1090931902) - (-1151727099 ^ 0x3134D78C))) - (0x753BED67 ^ (-1472550739 * (-666280211 * --1470402457 - ~(943613786 - -387564034))))) ^ (1135130487 * -(~((-1834416739 ^ -1701259551) + 1592437548)))) - ((((-1162177419 * -(--632559421)) ^ 0xE79BDA) - (1939422115 * 1435368560 * 1146891339 - 1993151903 * --1772203091) * -1790849593) ^ 0x56CCE9D5 ^ -104886215) - (-502239041 ^ (1113544621 * (-107324216 + 1429499978 + --377446101) * -756142829 * -54034079 - -(~(-(-595324109 ^ 0x6C8AE9F1))) - -(-(-595022237 * -1477540623) - (~(~1399160398) - -526110753 * ((-1144768672 ^ 0x47A86082) - (-725861275 - -2132244737))))))))) * -1107740129) ^ -738395952) * 1509225835) - 442327609)) % 3;
					int num5 = 564143360;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 - 1056726755 * 1635337556);
						num5 = ~num5 ^ -2027426500;
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
						int num9 = 1110751497;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ -1758070466) * -1783962109;
							num9 = -num9 - -1436786572;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.AntiTamperMode = P_1;
					int[] array = new int[5];
					array[0] = -2050011277;
					array[1] = 1803060154;
					array[2] = 1182390777;
					array[3] = 1188976921;
					array[4] = -982883510;
					array[4] = array[2] ^ 0x51D437D5;
					array[2] ^= -2038044086;
					int[] array2 = new int[6];
					array2[0] = 1468374325;
					array2[1] = 1156583724;
					array2[2] = -1360242263;
					array2[3] = 1400431214;
					array2[4] = -2078106843;
					array2[5] = 1753653070;
					array2[3] = array[1] ^ -1252181533;
					array2[0] = array2[1] ^ -806325629;
					array2[0] = array2[1] ^ 0x5C3600AA;
					int num11 = array2[3] ^ 0x2D35D6BC;
					num = (int)((num4 * 946804175) ^ 0x9CB247E0u) ^ num11;
				}
			}
		}
	}

	static void _005E_0028_003E_0024_0026_0024_002A_002B(ProtectionOptions P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 978447515;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((-(801126061 * (1334394652 - 84617169 - ((0x3345374E ^ -1713222244) + -382082793 * 227270066))) * -666211293) ^ -((-(0x65D60B96 ^ -145524480) - ((0x1766CC02 ^ -1318236325) + -1620582103 * ~1482757687)) ^ (1189282034 + -(~(--312005285))))) - (~num2 ^ (1683234589 * (((-(1634183302 + -1032583326) - 1602489975 * -19362533) ^ (1383220639 * (-1993844421 - -711035271 * -1167570193))) + 1437177782) - -(~(-(~133916786)) + -(-(1290464265 * 1036890593)) + -1869787639 * (~(2049060532 * -1464871521) - ((-1709171145 ^ 0x54BB54FB) - -1161585336))) + ((-1426738715 * ((~(--1560919678 + (862659546 - -1760558580)) ^ ~(-(1902533300 - -2137481902))) - ~(~(-2001836847 ^ -285259250)) * -2013676385)) ^ (1909434524 - 1218352374 + -(~595025652 - ~-489204146) * 868953561)))) - (2071539063 + (~(-7323286 ^ -1830602613) - ((0x6865267B ^ 0x5C364318) - (-915556347 ^ (-988240470 ^ --1487007628))))) - ~(~((0x4C4CB30 ^ --612627299) * -812354881)) + -(-(~(-58901492))))) % 3;
					int num5 = -1585508056;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= -1585508056;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 -= ~229928082;
						num7 = 276830911 - (num7 - (2006809788 + 356649135));
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(-num9);
							num9 = -371752121 + 318646219 - num9 + 1939632680;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.AntiVm = P_1;
					int[] array = new int[5];
					array[0] = 657110287;
					array[1] = -258092778;
					array[2] = 16661651;
					array[3] = 139656048;
					array[4] = 1724214290;
					array[4] = array[2] ^ 0x8917BE1;
					array[3] ^= 1300361139;
					array[0] ^= -1396256592;
					int[] array2 = new int[4];
					array2[0] = 1312252464;
					array2[1] = 1020352375;
					array2[2] = 515346379;
					array2[3] = 348187130;
					array2[0] = array[2] ^ -1532299629;
					array2[3] = array2[1] ^ 0x7E09291C;
					array2[1] = array2[0] ^ -1568030794;
					int num11 = array2[0] ^ -1762602456;
					num = (int)((num4 * 1092884493) ^ 0x2BFC687) ^ num11;
				}
			}
		}
	}

	static void _002A_002D_0040_0029_0024_0024_002A_0021(ProtectionOptions P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1839713430;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(~(~(-(-(num2 * 635735485 + (-1527078914 ^ (~(-1808739415 ^ ~((848834495 + 905227055 - --405541817) ^ -613709883)) ^ 0x50B0E3D0))) - -(-((0x49D41075 ^ -1433320101) + 763143037))))) - 285809063 * -1546906979)))) % 3;
					int num5 = 192987136;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 ^ 0x56AEA59C;
						num5 = (num5 + ~-1398039653) ^ -102312554;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -51061513;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 * 172717853) ^ 0xF994EDE;
						num7 = (num7 ^ 0x6C5666FC) + 648580331;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 60;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(~num9);
							num9 = num9 ^ -675853319 ^ 0x88D3D1B;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.CodeVirtualization = P_1;
					int[,] array = new int[3, 4];
					array[0, 0] = 1670065345;
					array[0, 1] = -1045201110;
					array[0, 2] = 1748250587;
					array[0, 3] = 1089624899;
					array[1, 0] = -994199445;
					array[1, 1] = 2100347521;
					array[1, 2] = 1995576231;
					array[1, 3] = -485115884;
					array[2, 0] = -865832538;
					array[2, 1] = 515273667;
					array[2, 2] = 626674510;
					array[2, 3] = 375355380;
					array[1, 2] = array[0, 1] ^ -185581477;
					array[2, 0] = array[2, 2] ^ 0x634354EC;
					array[2, 1] = array[0, 3] ^ -1167180349;
					int num11 = array[2, 1] ^ -1585162986;
					num = ((int)num4 * -112437600) ^ 0x7F6BF720 ^ num11;
				}
			}
		}
	}

	static void _003F_0023_0026_0021_0024_0026_0040_0029(ProtectionOptions P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1095362660;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(~(-1975706115 ^ -(~(--317961455 + ~-1670990052) - 2113808777)) - ~-1472454604 + -(--850168782 + ((-240921419 ^ (((-625344730 - 1276657498) ^ -656081940) + (-766793495 + (770297137 + -1441523605)) * 582818145)) + ~((-1689855136 ^ -1194397890) + ~(370737982 * 1250509751 + -899255915 * -695828764)))) - num2 + ((~(-(-(-1727300035))) ^ (-1871892633 * ((~264857314 - -2093526836) ^ -786683675) + (~-992057738 + -(~(-132363105 - -1749191049))))) + 381941672 + -138872641 * -2138592792)) - ((-(-(0x60F70D28 ^ 0x2EC6EB0) - (-1369148657 + 957196370 - (-629729193 - 1204599530))) + -312990729) ^ ((0x7E97D428 ^ 0x2FBB4D2E) + ~(1866898185 * -1756913513) + (-1016631015 + -(~994922059)) + (1688395691 * (396255277 + 1016206529 - ~1927858970) + ~(~-2044872333 + (1280063139 + -1429933528)))))) ^ (((~(1503145897 * 668732300) - -1160152859 * -1649271871) ^ -(1274638765 - -686435665 - -1416997854)) - (-1798184133 ^ (~(--696947124) * -2024271851))) ^ -1331042748)) % 3;
					int num5 = 1753068352;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * -265967501 + -968646057;
						num5 = -num5 * 1267764731;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -788008991;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 ^ 0x443BC56F;
						num7 = (-1990975544 ^ -1709010041) - num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1257467102;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -782824822 - num9 * 216510983;
							num9 = ~num9 * -1387507307;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.ControlFlowObfuscation = P_1;
					int[] array = new int[4] { 1802690821, -1995000407, 1545468751, -1877964606 };
					array[0] ^= -714908588;
					array[1] ^= -1142357574;
					array[0] ^= -1584900899;
					int[] array2 = new int[4];
					array2[0] = -552586085;
					array2[1] = 999279301;
					array2[2] = -1879722566;
					array2[3] = 1301333196;
					array2[1] = array[3] ^ 0x724BE167;
					array2[2] = array2[3] ^ -464446092;
					array2[2] = array2[1] ^ 0x644327;
					array2[0] = array2[3] ^ -1265217070;
					int num11 = array2[1] ^ -279691437;
					num = ((int)num4 * -1022339425) ^ -167336956 ^ num11;
				}
			}
		}
	}

	static void _005E_0040_003D_0023_003F_005E_0028_003E(ProtectionOptions P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 16774432;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(~((num2 - ((((~(1706755205 * (-1452359192 - -603121737)) + -482435296) * 350403751 + -1418492526 - (1544972259 * -93762452 - -(709785009 * -787135867) + -(~((0x3B75F0F ^ 0xA6291E7) + -1040982049 * 333790605)))) ^ ((-(-(-(-243102907)) ^ -(--1640473366 + 2101097402 * -1235960833)) + -(-(-(0x15580B14 ^ 0x5A360452) * -36315691))) ^ -128113402)) + (-1168782523 * (962559643 * ((~-361119991 - (-1905501777 + 1472548018) - (-4506432 + -695144189) * 814607145 + (-1408132249 + (-1199984498 + -714994548) - ~(~1941754671))) * -1804217491)) - ~(-(~(-(~-2103458846))) * 689220799) * -1672199301)) - -(-1998978699 ^ -1897184910) * -2073560479) * 720761519) * -1352498103 - ~(-2086269485 * 367055698 * -24907143 + (~-1478402352 + ~1878362959))) - 1321487636) ^ 0x19D5F5A6)) % 3;
					int num5 = -1703010602;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 - (-937795868 + -2079309349) + 218321614;
						num5 = num5 * -722085927 * 1443075363;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1609968407;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7 + 1033754737;
						num7 = num7 * 1702130989 - -925614236;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 268428280;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 ^= -1812009551;
							num9 = num9 - --415287048 - -24876332;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.LibraryMode = P_1;
					int[] array = new int[4];
					array[0] = -1575119019;
					array[1] = 1207146079;
					array[2] = -1720281592;
					array[3] = -1346947827;
					array[0] = array[3] ^ 0x65E875C8;
					array[2] ^= -312976762;
					array[1] = array[2] ^ 0x3734B29;
					int[] array2 = new int[7];
					array2[0] = 6940028;
					array2[1] = 1829115191;
					array2[2] = -1009474550;
					array2[3] = -1459872100;
					array2[4] = 748437531;
					array2[5] = -1240838313;
					array2[6] = 1354660885;
					array2[3] = array[3] ^ -519804793;
					array2[0] = array2[3] ^ 0x2AB9834B;
					array2[6] = array2[2] ^ -224886143;
					array2[2] = array2[1] ^ -2146669048;
					int num11 = array2[3] ^ 0x5897414B;
					num = (int)((num4 * 215527317) ^ 0xFD0F5A98u) ^ num11;
				}
			}
		}
	}

	static void _002D_0024_0028_002A_0026_003C_005E_005E(ProtectionOptions P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1662932083;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(~(((num2 ^ (~(-1608882270 - -393490947) - --564811161 + (~(603996317 * -795693044) * -792658561 - -1652195337 - ((-(-1417755141 - 749261984) ^ -1035185706) - (1182528631 * ~(-1898272430 - -2090434737) - 85248545 * (~847749201 - ~1370851994))) + --1514430638) * -2071958831)) - ((--930430618 ^ ((-(33455754 + 443996283) + (559169404 + (1947492424 - -1334218296))) ^ -1835099208 ^ (~(-1897806172 ^ 0xE2C1DEE) - (-(2105185392 - 380822058) - -823360103)))) + ((0x2981D199 ^ ((-1767470253 ^ -1686932602) + (-1075033879 * -546885887 - (309181928 - -294991487) + -(~207028468)))) + -(-2086498590 - (450153562 - ~(0x5F2FC9E0 ^ 0x446561C6)))) + 526559825 * ~(-(--1686768036) - 928798745 - (--2051156149 ^ 0x7408F9C7) - (175662204 + (--1534102185 ^ 0x2DFAFEF3)) * 919261821))) * -1965502111 - 410378361 * (-(337898817 * (1720254541 - -1235342578)) + -(~(136150243 + 1411130873)) - -844595363 * (-1368594431 ^ 0x335A696)) - (~(-(-752116408 ^ -1885077067)) ^ (-(-13361664 ^ -1590110053) + (-1777799015 ^ -(-214901535 ^ -376712309)))))) - (1750638441 - 879514863 + 1104172197 * 2050679261)) ^ -1692259147)) % 3;
					int num5 = -503284108;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 - ~191554052) * -124853281;
						num5 = (-314371202 ^ -533672612) - num5 + 351648543;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -743828825;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= -743828827;
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
					P_0.ReferenceProxy = P_1;
					int[] array = new int[7];
					array[0] = 682492913;
					array[1] = -810660294;
					array[2] = 1949435054;
					array[3] = -477195534;
					array[4] = -182402875;
					array[5] = -1135021412;
					array[6] = 348502230;
					array[1] = array[5] ^ -1748754028;
					array[3] = array[2] ^ -1148423451;
					array[0] ^= 361459407;
					int[] array2 = new int[4];
					array2[0] = -1247085460;
					array2[1] = -411453997;
					array2[2] = 854262454;
					array2[3] = 1241560959;
					array2[0] = array[2] ^ -1041774297;
					array2[3] ^= -67454123;
					array2[2] ^= 1155745269;
					array2[2] = array2[1] ^ 0x50E14AF1;
					int num11 = array2[0] ^ -243281305;
					num = (int)((num4 * 811378628) ^ 0x632B3154) ^ num11;
				}
			}
		}
	}

	static void __0024_0025_0026_003F_002D_005E_0024(ProtectionOptions P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -2088943265;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(-((-num2 ^ (2111999441 * --336788786)) + 228335911 * 613217987 * 414879337) ^ 0x7CE34CE5) - (-257612415 + (-1009978181 + -778929429 + ~1394928141))))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= 207920269;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1310593074;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7 * -995721691;
						num7 = -(num7 - (-2072025120 ^ 0x2F1C1BAB));
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
					P_0.ResourceProtection = P_1;
					int[,] array = new int[3, 4];
					array[0, 0] = 1236858911;
					array[0, 1] = -661336350;
					array[0, 2] = -1346561210;
					array[0, 3] = -511868678;
					array[1, 0] = 1953669201;
					array[1, 1] = -1877677339;
					array[1, 2] = 2107415543;
					array[1, 3] = -1607268851;
					array[2, 0] = 7790311;
					array[2, 1] = -338311812;
					array[2, 2] = -41432427;
					array[2, 3] = 1387818073;
					array[1, 1] = array[1, 3] ^ -378749194;
					array[2, 3] = array[1, 3] ^ -650686835;
					array[0, 0] = array[0, 3] ^ -1398234615;
					int num11 = array[0, 0] ^ -1033200256;
					num = (int)((num4 * 1534756598) ^ 0xB7CFA2EAu) ^ num11;
				}
			}
		}
	}

	static void _002B_002F_003E_0025_0028_0028_0040_002D(ProtectionOptions P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 476161978;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((((num2 + -(-(~(~(-1170953069 * (-1586698169 * ~2127501832 + ((-1813919019 ^ 0x10069E59) - -445310745 * 173658098))) - 1881817635 * 1492421838)))) ^ (1344556765 * -((~(1766964140 - (-975002746 + -1981376926) + (-891897585 ^ 0x682B813B)) - (-(~229777624) + -45368621 * (-2135650891 + 581105889) + 1635100684)) ^ -1484522914))) + (--1221022858 + ~(~1315625605) * 440055533)) ^ ~(-(0x482A49AC ^ -1021077340) * -1052805489))) % 3;
					int num5 = -1198059246;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(num5 + ~-1534584866);
						num5 = -num5 - 935555242;
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
						int num9 = 1;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9;
							num9 += -628287599 + 166857252;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.StringEncryption = P_1;
					int[] array = new int[5];
					array[0] = 1385436328;
					array[1] = -2104523632;
					array[2] = -1345134109;
					array[3] = 1169048335;
					array[4] = 665220537;
					array[2] = array[0] ^ 0x640C309C;
					array[0] = array[4] ^ 0x574C8DB5;
					array[0] = array[3] ^ 0x23442C59;
					int[] array2 = new int[7] { -1300557655, -1800747909, 1040165276, 1837274547, 1720594399, -202203488, -485986270 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[5] = array3[0][3] ^ 0xE2A463D;
					array2[6] = array2[5] ^ 0x348FC42B;
					array2[3] = array2[4] ^ -386176464;
					array2[6] = array2[3] ^ -830031002;
					int num11 = array3[1][5] ^ 0x75F5C7FB;
					num = (int)((num4 * 35848410) ^ 0xFC44657Au) ^ num11;
				}
			}
		}
	}

	static void _002A_005E_0021_005E__0025_003C_0028(ProtectionOptions P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1021063227;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((~(-(-809749699 - (-773151157 ^ -356424901) - (~(1039840940 + 35133899) + (-418424668 * -615020333 - (0x3DB3404 ^ 0x139534CC))) + (-(-(~1344414064)) + -17160029 * (653482701 + -121073547) * -1035207687)) - (~(-1476369753 * ~(-(-(111842926 + 1001993092 - (-945292586 ^ 0x2FAFB235))))) + -1972880529 * (((-(-501318899 + -1544692589 - (1518624458 - 1892437287)) - (~858321424 * -1134842129 + (303261483 - -1865486406 - (-406667583 ^ 0x5F58F305)))) ^ ~(-639931717 + (-50615658 ^ 0x12F8A98D) - -(-646108595 + -642747413))) + -(~(~(-1729821089 + -1227488472) - (-82033878 ^ 0x39EC62B6)))) - ((~((828695904 - -(((0x1791F979 ^ 0x5E978520) - (-332040822 - -93279755)) * 1750417267)) * 1882093453) ^ -(~(0x6983751A ^ -(-556865033 * -957995443)) - (~(~(-1434378327 - 465263882)) - (0x7A8BC801 ^ -163393842)) - 580026971 * (-1746954519 ^ 0x2E87EBB7) * -707059145)) - ~(~(-372939156 ^ 0x571BE3B2)) - num2) - -(~(~((1512631418 + ~329919702) * 517312179)) * -2004133237))) - (~((-1204338028 - 1175053576) * -1414721067) + (-(~-1850342526) ^ (-1384713403 ^ -988301575)))) ^ ((-2036955819 * 1447806162 + --1178456246) * -872764445)) - -1092346901)) % 3;
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
						int num9 = 2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9;
							num9 = ~num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.SymbolRenaming = P_1;
					int[] array = new int[5];
					array[0] = 988359878;
					array[1] = 1985449650;
					array[2] = 1249672610;
					array[3] = 2113935970;
					array[4] = -1138064870;
					array[0] = array[1] ^ 0x2EFABBB6;
					array[2] = array[4] ^ -1061572350;
					int[] array2 = new int[6];
					array2[0] = 1769246711;
					array2[1] = -630402546;
					array2[2] = 2070549210;
					array2[3] = 1987783943;
					array2[4] = 1847451771;
					array2[5] = -1244594833;
					array2[3] = array[3] ^ 0x3F701319;
					array2[1] = array2[5] ^ -485135214;
					array2[5] = array2[4] ^ -1851967007;
					array2[0] = array2[2] ^ 0x32437160;
					int num11 = array2[3] ^ -1358106986;
					num = ((int)num4 * -250258555) ^ 0x2D6D485F ^ num11;
				}
			}
		}
	}

	static IReadOnlyList<NamespaceItem> _0025_005E_002F_0025__0021_003D_0040(AssemblyProfile P_0)
	{
		IReadOnlyList<NamespaceItem> namespaces = default(IReadOnlyList<NamespaceItem>);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1981810505;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(num2 - (-211877091 ^ ~(-((-(1920573695 - (587649141 - -1652496321)) + (-2078054986 - --165969580)) * 1540330843)) ^ ~(-312639615 ^ (((-771417174 * 171270453 - -1445403985) * 592814601 * 1508778071) ^ 0x79D4A84C) ^ ~(~(~(-(-143856353 - -404642707)) - ((--340235450 + 290069024 * 1479817457) ^ -1451725088)))))) * 1213026079 - ~(-(-(~(1343983143 * -1692776647 - -1698967427 * -1900258169))))) * -1452143255)) % 3;
					int num5 = -2088651592;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = 1785249785 - (num5 - ~-1548289258);
						num5 *= -1881240595;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1591619647;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 1591619646;
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
					namespaces = P_0.Namespaces;
					int[] array = new int[4];
					array[0] = -1879055362;
					array[1] = 1883911991;
					array[2] = -1255887952;
					array[3] = 1807354221;
					array[0] = array[1] ^ 0x9BC3F8C;
					array[0] = array[1] ^ -1254934409;
					array[0] = array[3] ^ -1785748346;
					int[] array2 = new int[4] { -1735172633, 85510308, -797489560, -1392337209 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][2] ^ 0x78283B98;
					array2[0] ^= -1538264884;
					array2[3] = array2[0] ^ -1525586137;
					array2[3] = array2[1] ^ 0x71343430;
					int num11 = array3[1][1] ^ -1603974926;
					num = ((int)num4 * -1767811000) ^ 0x59C8B3B0 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return namespaces;
	}

	static string _002F_0021_0029_0021_0040_003E_003D_0026(TypeItem P_0)
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
				int num = 224937041;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(~(((num2 - (~(-1554254791 * (-217328304 - -272443055 * ~(0x371AEC0F ^ 0x4419F116))) - (-(-((-(0x149F32F9 ^ 0x30F7FD49) ^ 0x9577CC7) + (~-1511824563 - (-915667671 - 322564129 + --772460784))) + ~-2074459755) ^ 0x4DCFFEAA))) ^ (~(-1973654426) - 1016418660 - ((-1859250043 ^ 0x51C4DE66) - ~(-247609600) * -2042341675 - ~(1034326686 + 1961191849 - (-2029421501 ^ 0x26200271) + (--1239986997 + (-824108447 + -392266740)))) - 1046100262 - (430118606 - (-(((-1835982058 ^ -277925764) * -338830277 + (-535399801 - -384634370 - (53274706 - -530662666))) * -911063371) + (0x2AA9C201 ^ (-110356619 ^ (1871643843 * -542060821 * -762140143 + (-1796990958 + -605933623)))))))) - ((-(950504795 * (-552818375 - 753256537) - ~(1927146886 - 837849213)) ^ -1225504199 ^ ~(-463674232 - (-817179431 ^ (-911046374 + (0x1C9C0AFF ^ 0x3556A6B))))) + ((-345474815 + ((0x7E1D3DA8 ^ -336275985) + (-259086187 ^ (0x3B700D36 ^ --837664120)))) ^ (-(0x41D4FD25 ^ ~(--301702668)) + -581311293))) - (0x509484E8 ^ 0x789DBC20)) * -576141231)) * 1977861057)) % 3;
					int num5 = 2145387524;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 ^ 0x32A09B58 ^ -2058534359;
						num5 = num5 - ~637268482 - 1639527701;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 825574317;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 825574315;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2113937677;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -1827259121 - ~num9;
							num9 = (num9 ^ --813622385) + 232854058;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					fullName = P_0.FullName;
					int[,] array = new int[3, 4];
					array[0, 0] = -872824713;
					array[0, 1] = 1149839024;
					array[0, 2] = 68067624;
					array[0, 3] = -293933714;
					array[1, 0] = 1695639305;
					array[1, 1] = 927482934;
					array[1, 2] = -205559075;
					array[1, 3] = 793721257;
					array[2, 0] = 2069118755;
					array[2, 1] = 582353266;
					array[2, 2] = 829164204;
					array[2, 3] = 2121820096;
					array[2, 3] = array[1, 2] ^ -1608216093;
					array[2, 2] = array[2, 0] ^ -963134008;
					array[2, 0] = array[0, 1] ^ 0x44ED2E2E;
					array[0, 3] = array[0, 0] ^ 0x37DDCE35;
					int num11 = array[0, 3] ^ 0x255FDA11;
					num = (int)((num4 * 152028733) ^ 0x691D4C0F) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return fullName;
	}

	static IReadOnlyList<MethodItem> _0023_0029_002B_005E_0023_0024_0026_0024(IAssemblyWorkspaceService P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return P_0.GetMethodsForType(P_1);
		}
	}

	static string _002F_003F_0021_0021_003D_0024_003E_005E(ProtectionProgress P_0)
	{
		string step = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 2123534185;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((((-(-558464087 * (588170333 * -21827501) * 30223061 + -((0x7E9809C6 ^ 0x3BF4D5CE) * -635566413)) - ~(-(num2 + (~((149696701 - (-1246221051 + -1558716398 + (0x71CC6C2 ^ -742372932)) - (-1206046106 ^ -153062768) + (2016657540 + (-1523601554 ^ (-525489142 - -2017663283)))) ^ (1779293287 + -2104729810 + (-(1513330644 + -1495580613 - ~-14195438) - (-1726581566 ^ -716312975)))) - -(~(1754512009 * (740094279 - 1507480989 * (448499936 * -101166503 - -1401447845)))) + -((0x50817550 ^ ((-1337282403 - 1012088872 - --1880934146 + (~-490648961 - --118457923)) ^ 0x4297B812)) * -2066584969 + (-1160234629 - -(~(-2044203945 + -1005789115) + (~1451300504 + ~1314105329) - -(0x73C93914 ^ -570238268)))))) + ((0x6BD5DB94 ^ -1314786318) - (-928692405 ^ -(-1827660465 * 620124240)) - -1275447779 * (-657574989 * (0x60D3E5A8 ^ 0x2DFFD95D))))) * 780682901) ^ ~(-(2007986614 + 1596811189))) - -872517619 * (0x57BEFF5C ^ -1146619313) - (-2110509843 ^ -2067881769)))) % 3;
					int num5 = -1050482172;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 - -948793435;
						num5 = ~num5 * 1649067107;
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
					step = P_0.Step;
					int[,] array = new int[4, 4];
					array[0, 0] = -18002092;
					array[0, 1] = -269863814;
					array[0, 2] = -960107645;
					array[0, 3] = -1973724284;
					array[1, 0] = -1457761390;
					array[1, 1] = -1200410987;
					array[1, 2] = 1532493464;
					array[1, 3] = 831316445;
					array[2, 0] = -1231684801;
					array[2, 1] = -2006511009;
					array[2, 2] = 1981660779;
					array[2, 3] = -247935340;
					array[3, 0] = -921721978;
					array[3, 1] = -1202009045;
					array[3, 2] = 1431102804;
					array[3, 3] = 880159252;
					array[1, 3] = array[0, 0] ^ -597811213;
					array[0, 2] = array[3, 0] ^ 0x16F9EC1B;
					array[2, 3] = array[2, 0] ^ -1107589685;
					int num11 = array[2, 3] ^ -1800897198;
					num = (int)((num4 * 474007837) ^ 0x60CA8023) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return step;
	}

	static double? _0028_003E_0040__003C_003C_003D_002B(ProtectionProgress P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return P_0.Value;
		}
	}
}
