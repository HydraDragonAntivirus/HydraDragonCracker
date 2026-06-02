using System;
using System.Diagnostics;
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

public sealed class LoginViewModel : ObservableObject
{
	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CInitializeAsync_003Ed__41 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder _003C_003Et__builder;

		public LoginViewModel _003C_003E4__this;

		private TaskAwaiter<AuthBootstrapState> _003C_003Eu__1;

		private void MoveNext()
		{
			int num = _003C_003E1__state;
			LoginViewModel loginViewModel = _003C_003E4__this;
			try
			{
				if (num == 0)
				{
					goto IL_0b0c;
				}
				while (true)
				{
					int num2 = 1022014913;
					uint num4;
					while (true)
					{
						int num3 = num2;
						uint num5;
						num4 = (num5 = (uint)(~(~(((-((-(841685949 + 1300851333) ^ -(1962645491 * -1078712389)) - (~-1152707163 - 1708631581 * 1005066212 + 1696368090) - (1422076036 - ((-2052446186 ^ 0x656AF5E) - --1033912010) - -1608613135)) ^ 0x2D3C7941) - ~(~num3)) * 1909464043 - -2125855495 * (-1171782585 ^ -(~(1461831269 - 1562542820))) - -962354249 * (-14670293 - 1255866044 + -(0x7E49808B ^ -1789266342))) * 613081509) - -1071188629)) % 6;
						uint num6 = num4;
						int num7 = 4;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -(~num7);
							num7 = -(num7 - ~1375389059);
						}
						if (num6 == (uint)num7)
						{
							break;
						}
						uint num9 = num4;
						int num10 = -2;
						_ = 0;
						for (int num11 = 0; num11 < 1; num11++)
						{
							num10 = -num10;
						}
						if (num9 != (uint)num10)
						{
							uint num12 = num4;
							int num13 = -5;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 = -num13;
							}
							if (num12 != (uint)num13)
							{
								uint num15 = num4;
								int num16 = -194200565;
								_ = 0;
								for (int num17 = 0; num17 < 2; num17++)
								{
									num16 = -1156975115 - -num16;
									num16 = num16 - (-2102304560 ^ -1224136513) - -7861365;
								}
								if (num15 != (uint)num16)
								{
									uint num18 = num4;
									int num19 = -1;
									_ = 0;
									for (int num20 = 0; num20 < 1; num20++)
									{
										num19 = ~num19;
									}
									if (num18 == (uint)num19)
									{
										loginViewModel.IsBusy = true;
										int[,] array = new int[4, 3];
										array[0, 0] = -856976574;
										array[0, 1] = -97558571;
										array[0, 2] = -36518091;
										array[1, 0] = -150963114;
										array[1, 1] = -60628879;
										array[1, 2] = 3337436;
										array[2, 0] = -823031739;
										array[2, 1] = -1676459705;
										array[2, 2] = 1146135305;
										array[3, 0] = 926043041;
										array[3, 1] = 889760879;
										array[3, 2] = -1545883951;
										array[3, 1] = array[0, 1] ^ 0x657AE291;
										array[0, 0] = array[3, 0] ^ -254056640;
										array[3, 2] = array[2, 2] ^ -1316183118;
										array[2, 1] = array[3, 0] ^ -1123915254;
										int num21 = array[2, 1] ^ -1622018691;
										num2 = (int)((num5 * 1922874957) ^ 0xC09A7508u) ^ num21;
										continue;
									}
									goto IL_02bb;
								}
								loginViewModel._initialized = true;
								num2 = 678879679;
								continue;
							}
							goto end_IL_0023;
						}
						bool initialized = loginViewModel._initialized;
						int[,] array2 = new int[3, 3];
						array2[0, 0] = -461933624;
						array2[0, 1] = 195137113;
						array2[0, 2] = 118233377;
						array2[1, 0] = 104307547;
						array2[1, 1] = -769610192;
						array2[1, 2] = 206757328;
						array2[2, 0] = 782813055;
						array2[2, 1] = -1557222845;
						array2[2, 2] = 1189188807;
						array2[2, 0] = array2[0, 2] ^ -1437868578;
						array2[0, 2] = array2[1, 1] ^ 0x35911095;
						array2[0, 0] = array2[0, 1] ^ 0x667DF4EA;
						int num22 = array2[0, 0] ^ 0x7F2CD681;
						int[] array3 = new int[7];
						array3[0] = 4184315;
						array3[1] = 1386277963;
						array3[2] = 1875857565;
						array3[3] = 1824580138;
						array3[4] = 308931458;
						array3[5] = -1953886210;
						array3[6] = -1586267436;
						array3[0] = array3[5] ^ 0x4109E2CF;
						array3[1] = array3[6] ^ -143615742;
						array3[1] = array3[4] ^ 0x1DE7C633;
						int[] array4 = new int[5];
						array4[0] = 1408796925;
						array4[1] = -477196536;
						array4[2] = 1490596934;
						array4[3] = 777147814;
						array4[4] = 160217919;
						array4[3] = array3[3] ^ -973844746;
						array4[1] = array4[4] ^ -2017535789;
						array4[1] = array4[3] ^ 0x13E1E634;
						int num23 = array4[3] ^ 0x72ABEFBC;
						int num24 = ((int)num5 * -1038515760) ^ -262420192;
						num22 ^= num24;
						num23 ^= num24;
						int num25;
						int num26;
						if (initialized)
						{
							num25 = num23;
							num26 = num25;
						}
						else
						{
							num25 = num22;
							num26 = num25;
						}
						num2 = num25 ^ num24;
					}
					continue;
					IL_02bb:
					uint num27 = num4;
					int num28 = 634540521;
					_ = 0;
					for (int num29 = 0; num29 < 1; num29++)
					{
						num28 += -634540518;
					}
					if (num27 == (uint)num28)
					{
					}
					goto IL_0b0c;
					continue;
					end_IL_0023:
					break;
				}
				goto end_IL_001a;
				IL_0b0c:
				try
				{
					if (num != 0)
					{
						goto IL_0b15;
					}
					goto IL_17e3;
					IL_0b15:
					int num30 = -1802837630;
					goto IL_0b1a;
					IL_0b1a:
					TaskAwaiter<AuthBootstrapState> awaiter = default(TaskAwaiter<AuthBootstrapState>);
					AuthBootstrapState result = default(AuthBootstrapState);
					string message = default(string);
					while (true)
					{
						int num3 = num30;
						uint num5;
						uint num4 = (num5 = (uint)(~(~(((-((-(841685949 + 1300851333) ^ -(1962645491 * -1078712389)) - (~-1152707163 - 1708631581 * 1005066212 + 1696368090) - (1422076036 - ((-2052446186 ^ 0x656AF5E) - --1033912010) - -1608613135)) ^ 0x2D3C7941) - ~(~num3)) * 1909464043 - -2125855495 * (-1171782585 ^ -(~(1461831269 - 1562542820))) - -962354249 * (-14670293 - 1255866044 + -(0x7E49808B ^ -1789266342))) * 613081509) - -1071188629)) % 24;
						uint num31 = num4;
						int num32 = -1051330826;
						_ = 0;
						for (int num33 = 0; num33 < 1; num33++)
						{
							num32 -= -1051330843;
						}
						if (num31 == (uint)num32)
						{
							break;
						}
						uint num34 = num4;
						int num35 = -673925692;
						_ = 0;
						for (int num36 = 0; num36 < 1; num36++)
						{
							num35 = -673925689 - num35;
						}
						if (num34 == (uint)num35)
						{
							awaiter = _003C_0025_0021_002D_003F_002F_0026_0021(loginViewModel._authenticationService, default(CancellationToken)).GetAwaiter();
							int[,] array5 = new int[4, 4];
							array5[0, 0] = -1433683866;
							array5[0, 1] = -268109330;
							array5[0, 2] = -906465803;
							array5[0, 3] = -818929057;
							array5[1, 0] = 898302585;
							array5[1, 1] = 1595010436;
							array5[1, 2] = -1075002108;
							array5[1, 3] = 1308503571;
							array5[2, 0] = -1221840331;
							array5[2, 1] = -1960548953;
							array5[2, 2] = 77594085;
							array5[2, 3] = 1867796618;
							array5[3, 0] = -128282201;
							array5[3, 1] = -1600146460;
							array5[3, 2] = -202887974;
							array5[3, 3] = 1392368760;
							array5[3, 3] = array5[0, 0] ^ -440473257;
							array5[0, 1] ^= -809631768;
							array5[1, 2] = array5[2, 1] ^ -490496170;
							int num37 = array5[1, 2] ^ -1698109230;
							num30 = (int)((num5 * 1319421807) ^ 0xA3054FCDu) ^ num37;
							continue;
						}
						uint num38 = num4;
						int num39 = 32125668;
						_ = 0;
						for (int num40 = 0; num40 < 2; num40++)
						{
							num39 = -(-num39);
							num39 = -(num39 * -611359811);
						}
						if (num38 == (uint)num39)
						{
							bool ısCompleted = awaiter.IsCompleted;
							int[] array6 = new int[6];
							array6[0] = 1457779914;
							array6[1] = 269318573;
							array6[2] = -1853611753;
							array6[3] = 1087159593;
							array6[4] = 905721983;
							array6[5] = -1953372923;
							array6[0] = array6[3] ^ 0x733A364B;
							array6[2] = array6[0] ^ 0x3BB4A10;
							int[] array7 = new int[4];
							array7[0] = 1388854562;
							array7[1] = -795954712;
							array7[2] = -1447962554;
							array7[3] = -1594041131;
							array7[3] = array6[5] ^ -568541184;
							array7[1] = array7[3] ^ -1672845353;
							array7[1] ^= 1120757203;
							int num41 = array7[3] ^ 0x5CE7A906;
							int[,] array8 = new int[3, 3];
							array8[0, 0] = -539767871;
							array8[0, 1] = -1049641191;
							array8[0, 2] = 1757083708;
							array8[1, 0] = 965904513;
							array8[1, 1] = -613816338;
							array8[1, 2] = 1085974850;
							array8[2, 0] = 1582166869;
							array8[2, 1] = -1412182675;
							array8[2, 2] = 142539638;
							array8[0, 0] = array8[2, 0] ^ 0xE23C154;
							array8[1, 0] ^= -1391271486;
							array8[2, 0] = array8[0, 2] ^ -1024358588;
							int num42 = array8[2, 0] ^ -1369097408;
							int num43 = (int)(num5 * 556553984) ^ -1667206144;
							num41 ^= num43;
							num42 ^= num43;
							int num44;
							int num45;
							if (!ısCompleted)
							{
								num44 = num42;
								num45 = num44;
							}
							else
							{
								num44 = num41;
								num45 = num44;
							}
							num30 = num44 ^ num43;
							continue;
						}
						uint num46 = num4;
						int num47 = 2020742441;
						_ = 0;
						for (int num48 = 0; num48 < 2; num48++)
						{
							num47 = -1336502594 - ~num47;
							num47 = ~num47 * -1127034033;
						}
						if (num46 == (uint)num47)
						{
							num = (_003C_003E1__state = 0);
							int[] array9 = new int[4];
							array9[0] = 771018953;
							array9[1] = -1469766313;
							array9[2] = 521409618;
							array9[3] = 51276978;
							array9[2] = array9[0] ^ 0x1ABC284E;
							array9[3] = array9[0] ^ -871349286;
							int[] array10 = new int[5];
							array10[0] = -862097682;
							array10[1] = -479339023;
							array10[2] = 801976836;
							array10[3] = -1408847031;
							array10[4] = -1399798789;
							array10[2] = array9[1] ^ -365817414;
							array10[3] ^= 1866660371;
							array10[0] = array10[3] ^ 0x225700AB;
							array10[3] = array10[1] ^ -739640868;
							int num49 = array10[2] ^ -1625813141;
							num30 = (int)((num5 * 2109473987) ^ 0x4E6ED47B) ^ num49;
							continue;
						}
						uint num50 = num4;
						int num51 = 2019107856;
						_ = 0;
						for (int num52 = 0; num52 < 1; num52++)
						{
							num51 ^= 0x78592417;
						}
						if (num50 == (uint)num51)
						{
							_003C_003Eu__1 = awaiter;
							int[] array11 = new int[6];
							array11[0] = -1033733661;
							array11[1] = 1801279300;
							array11[2] = -1259749864;
							array11[3] = -178443878;
							array11[4] = 1686180687;
							array11[5] = -121413421;
							array11[0] = array11[5] ^ -1532895330;
							array11[2] ^= 1328035984;
							int[] array12 = new int[6];
							array12[0] = 232376945;
							array12[1] = -1499442698;
							array12[2] = 1613155793;
							array12[3] = 267108034;
							array12[4] = -955477858;
							array12[5] = 312643549;
							array12[1] = array11[1] ^ -1154152625;
							array12[4] = array12[3] ^ -308808512;
							array12[4] = array12[1] ^ 0x17352ED1;
							int num53 = array12[1] ^ 0x71404FB;
							num30 = (int)((num5 * 1073073969) ^ 0xB0EC6AF7u) ^ num53;
							continue;
						}
						uint num54 = num4;
						int num55 = 1319685925;
						_ = 0;
						for (int num56 = 0; num56 < 1; num56++)
						{
							num55 = 1319685926 - num55;
						}
						if (num54 == (uint)num55)
						{
							_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
							int[,] array13 = new int[4, 4];
							array13[0, 0] = 1029612967;
							array13[0, 1] = 2043895825;
							array13[0, 2] = 903462551;
							array13[0, 3] = 963901316;
							array13[1, 0] = 1469086080;
							array13[1, 1] = -9280598;
							array13[1, 2] = -66587206;
							array13[1, 3] = 1178957452;
							array13[2, 0] = -1394826943;
							array13[2, 1] = 883944806;
							array13[2, 2] = -1132978234;
							array13[2, 3] = 2033406658;
							array13[3, 0] = -1160339467;
							array13[3, 1] = 2083095245;
							array13[3, 2] = -422232429;
							array13[3, 3] = 380490776;
							array13[1, 2] = array13[2, 1] ^ 0x546D73EE;
							array13[2, 2] = array13[1, 3] ^ -601725086;
							array13[3, 0] = array13[1, 0] ^ -1389939362;
							array13[1, 2] = array13[1, 3] ^ 0x4D33928D;
							int num57 = array13[1, 2] ^ 0x29ED4BDF;
							num30 = ((int)num5 * -355268849) ^ -1329343313 ^ num57;
							continue;
						}
						uint num58 = num4;
						int num59 = -1078567661;
						_ = 0;
						for (int num60 = 0; num60 < 2; num60++)
						{
							num59 = -(num59 * 611144947);
							num59 = ~num59 * -64074111;
						}
						if (num58 == (uint)num59)
						{
							return;
						}
						uint num61 = num4;
						int num62 = 941445780;
						_ = 0;
						for (int num63 = 0; num63 < 2; num63++)
						{
							num62 = num62 - (0xF5D144 ^ -411536389) - -1859144065;
							num62 = ~(num62 ^ --1552854986);
						}
						if (num61 == (uint)num62)
						{
							goto IL_17e3;
						}
						uint num64 = num4;
						int num65 = 361564794;
						_ = 0;
						for (int num66 = 0; num66 < 1; num66++)
						{
							num65 ^= 0x158D0A78;
						}
						if (num64 == (uint)num65)
						{
							_003C_003Eu__1 = default(TaskAwaiter<AuthBootstrapState>);
							int[,] array14 = new int[3, 4];
							array14[0, 0] = -4105119;
							array14[0, 1] = -365544240;
							array14[0, 2] = 2123593244;
							array14[0, 3] = 706425180;
							array14[1, 0] = -1516507650;
							array14[1, 1] = -2083543654;
							array14[1, 2] = 1339850291;
							array14[1, 3] = -2077064092;
							array14[2, 0] = 439645589;
							array14[2, 1] = 1350883044;
							array14[2, 2] = -1864745433;
							array14[2, 3] = 690855005;
							array14[1, 2] = array14[0, 0] ^ 0x617E1268;
							array14[2, 0] = array14[1, 3] ^ 0x2D163667;
							array14[2, 3] = array14[0, 2] ^ 0x6292AEE5;
							int num67 = array14[2, 3] ^ -1748624592;
							num30 = (int)((num5 * 1996274421) ^ 0x1419B29A) ^ num67;
							continue;
						}
						uint num68 = num4;
						int num69 = 18;
						_ = 0;
						for (int num70 = 0; num70 < 2; num70++)
						{
							num69 = ~(num69 - (-912297971 ^ 0x2309BA81));
							num69 = ~(-num69);
						}
						if (num68 == (uint)num69)
						{
							num = (_003C_003E1__state = -1);
							int[,] array15 = new int[4, 4];
							array15[0, 0] = 1230853071;
							array15[0, 1] = -350790205;
							array15[0, 2] = 664503009;
							array15[0, 3] = -222262105;
							array15[1, 0] = 1724756415;
							array15[1, 1] = 202181057;
							array15[1, 2] = 402619516;
							array15[1, 3] = 1223329128;
							array15[2, 0] = 635446013;
							array15[2, 1] = -1172125131;
							array15[2, 2] = -394217216;
							array15[2, 3] = -1800628049;
							array15[3, 0] = 1202431374;
							array15[3, 1] = -1674869152;
							array15[3, 2] = -1014393970;
							array15[3, 3] = 1968148219;
							array15[3, 3] = array15[3, 2] ^ 0x640953AA;
							array15[0, 2] = array15[0, 3] ^ -1512482495;
							array15[2, 0] = array15[2, 2] ^ -2110108757;
							array15[3, 1] = array15[2, 2] ^ 0x41435ADF;
							int num71 = array15[3, 1] ^ -1599508516;
							num30 = (int)((num5 * 1085236664) ^ 0x2C682770) ^ num71;
							continue;
						}
						uint num72 = num4;
						int num73 = -1173036672;
						_ = 0;
						for (int num74 = 0; num74 < 2; num74++)
						{
							num73 = ~num73 * -1142347849;
							num73 = (num73 ^ -1765577078) * -1092874681;
						}
						if (num72 == (uint)num73)
						{
							result = awaiter.GetResult();
							num30 = -1962927124;
							continue;
						}
						uint num75 = num4;
						int num76 = -235863851;
						_ = 0;
						for (int num77 = 0; num77 < 2; num77++)
						{
							num76 = -num76 ^ 0x1226590C;
							num76 = -(num76 + (784460185 - 1139216701));
						}
						if (num75 == (uint)num76)
						{
							bool num78 = _002F_003D_002A_0028_0024_003E_002D_(_005E_002B_003C_005E_003E_002F_0025_0029(result));
							int[] array16 = new int[6];
							array16[0] = -1849488702;
							array16[1] = -2135371516;
							array16[2] = 1636827063;
							array16[3] = 1688374486;
							array16[4] = -843333530;
							array16[5] = 876235329;
							array16[3] = array16[1] ^ -1143957884;
							array16[5] ^= -807801402;
							int[] array17 = new int[4] { -351314450, 1978646186, -969814495, -651186084 };
							int[][] array18 = new int[2][] { array16, array17 };
							array17[0] = array18[0][4] ^ -1086433392;
							array17[3] = array17[0] ^ -464560693;
							array17[2] ^= -1541555170;
							array17[1] = array17[2] ^ 0x20BA5375;
							int num79 = array18[1][0] ^ -1346689582;
							int[] array19 = new int[6];
							array19[0] = -622728842;
							array19[1] = 268264351;
							array19[2] = -1102162059;
							array19[3] = -752908361;
							array19[4] = -147224561;
							array19[5] = -1223501445;
							array19[5] = array19[3] ^ 0x30E4ED87;
							array19[0] = array19[2] ^ -1954723784;
							array19[0] = array19[3] ^ 0x55BD45FF;
							int[] array20 = new int[4] { 985937246, -1588522507, 1270603645, 738210661 };
							int[][] array21 = new int[2][] { array19, array20 };
							array20[0] = array21[0][1] ^ -1362534020;
							array20[2] = array20[1] ^ 0x267289A2;
							array20[3] ^= 1292995961;
							array20[1] = array20[2] ^ 0x39F0FF87;
							int num80 = array21[1][0] ^ -531516065;
							int num81 = (int)((num5 * 2108957315) ^ 0x1CA3B037);
							num79 ^= num81;
							num80 ^= num81;
							int num82;
							int num83;
							if (!num78)
							{
								num82 = num80;
								num83 = num82;
							}
							else
							{
								num82 = num79;
								num83 = num82;
							}
							num30 = num82 ^ num81;
							continue;
						}
						uint num84 = num4;
						int num85 = -108368099;
						_ = 0;
						for (int num86 = 0; num86 < 2; num86++)
						{
							num85 = (-193547416 ^ 0x59BD3AB8) - num85 - 207686556;
							num85 = num85 * -1685629285 * 1462771583;
						}
						if (num84 == (uint)num85)
						{
							loginViewModel.LicenseKey = _005E_002B_003C_005E_003E_002F_0025_0029(result);
							int[] array22 = new int[6];
							array22[0] = 2146052947;
							array22[1] = -464338971;
							array22[2] = 525317772;
							array22[3] = -525095480;
							array22[4] = -1472352261;
							array22[5] = 1532508978;
							array22[4] = array22[0] ^ -417332622;
							array22[3] = array22[2] ^ 0x49EAE6AB;
							array22[5] = array22[2] ^ 0x48D0A838;
							int[] array23 = new int[7];
							array23[0] = 1789284306;
							array23[1] = 1204093191;
							array23[2] = -837643768;
							array23[3] = 1996494059;
							array23[4] = 773787108;
							array23[5] = 1472173589;
							array23[6] = -294290102;
							array23[5] = array22[2] ^ 0x7E3AA999;
							array23[2] = array23[5] ^ -1600578866;
							array23[3] = array23[5] ^ -1968540713;
							array23[6] ^= 886242583;
							int num87 = array23[5] ^ 0x56512220;
							num30 = ((int)num5 * -863026032) ^ 0x20B83350 ^ num87;
							continue;
						}
						uint num88 = num4;
						int num89 = 906578950;
						_ = 0;
						for (int num90 = 0; num90 < 2; num90++)
						{
							num89 = (num89 + ~-781233043) * 222457065;
							num89 = -1646612829 - (num89 + (-1729716606 + 632894637));
						}
						if (num88 == (uint)num89)
						{
							loginViewModel.RememberLicense = true;
							int[] array24 = new int[7];
							array24[0] = 1116518883;
							array24[1] = 2064892106;
							array24[2] = -781098493;
							array24[3] = 897192524;
							array24[4] = 965536389;
							array24[5] = -1505088532;
							array24[6] = -819078301;
							array24[0] = array24[3] ^ -366084559;
							array24[5] = array24[2] ^ 0x244A2072;
							int[] array25 = new int[7] { -810523256, 1418967926, 1456593391, -1258411358, -1689298675, -2080820655, -1803446766 };
							int[][] array26 = new int[2][] { array24, array25 };
							array25[6] = array26[0][1] ^ 0x31B21602;
							array25[4] = array25[0] ^ 0x23BB3465;
							array25[5] = array25[3] ^ 0x2F12CB3;
							int num91 = array26[1][6] ^ -1751161620;
							num30 = ((int)num5 * -1413933561) ^ -908993758 ^ num91;
							continue;
						}
						uint num92 = num4;
						int num93 = 507370611;
						_ = 0;
						for (int num94 = 0; num94 < 1; num94++)
						{
							num93 *= 782504319;
						}
						if (num92 == (uint)num93)
						{
							int num95;
							if (!_003D_003C_0021_0028_002F_002A_003D_002A(result))
							{
								num30 = -223025158;
								num95 = num30;
							}
							else
							{
								num30 = 1983100583;
								num95 = num30;
							}
							continue;
						}
						uint num96 = num4;
						int num97 = 6932539;
						_ = 0;
						for (int num98 = 0; num98 < 2; num98++)
						{
							num97 = 78242696 - (num97 ^ 0x53767F9A);
							num97 = -num97 * 816450813;
						}
						string text;
						if (num96 == (uint)num97)
						{
							if (__002A_005E_002A_005E_003C_0023_0040(result))
							{
								text = _002A_002D_0023_002D_005E_005E_0025_005E(loginViewModel._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-817 + 462)]);
								goto IL_1a4d;
							}
							int[] array27 = new int[7];
							array27[0] = -361821426;
							array27[1] = -1088865244;
							array27[2] = 853229886;
							array27[3] = -1741179983;
							array27[4] = -872707249;
							array27[5] = 1933451868;
							array27[6] = -1668189695;
							array27[1] = array27[4] ^ 0x51C87B08;
							array27[0] = array27[2] ^ 0x1361DEE5;
							int[] array28 = new int[7];
							array28[0] = 777386736;
							array28[1] = -1964781642;
							array28[2] = 325834183;
							array28[3] = -19651630;
							array28[4] = -216747695;
							array28[5] = -970060228;
							array28[6] = -452208957;
							array28[3] = array27[4] ^ -2135873620;
							array28[4] ^= -1467778943;
							array28[6] = array28[3] ^ 0x448A20A4;
							int num99 = array28[3] ^ 0x59467969;
							num30 = ((int)num5 * -15970810) ^ 0x2688D662 ^ num99;
							continue;
						}
						uint num100 = num4;
						int num101 = -1700250275;
						_ = 0;
						for (int num102 = 0; num102 < 1; num102++)
						{
							num101 *= -653792209;
						}
						if (num100 == (uint)num101)
						{
							text = _002D__005E_0040_003F_005E_0023_(loginViewModel._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[2930 - 2639 + 61], new object[1] { _003E_002F_003E_003E_0025_0024_0023_003E(result) ?? _002A_002D_0023_002D_005E_005E_0025_005E(loginViewModel._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[419 - 34 - 4 - 28]) });
							goto IL_1a4d;
						}
						uint num103 = num4;
						int num104 = -1739760880;
						_ = 0;
						for (int num105 = 0; num105 < 2; num105++)
						{
							num104 = ~-62643167 - num104;
							num104 = ~(num104 * -2001459793);
						}
						if (num103 == (uint)num104)
						{
							loginViewModel.SetStatus(message, __002A_005E_002A_005E_003C_0023_0040(result) ? SeverityLevel.Warning : SeverityLevel.Error);
							num30 = -1396381987;
							continue;
						}
						uint num106 = num4;
						int num107 = 1747837450;
						_ = 0;
						for (int num108 = 0; num108 < 2; num108++)
						{
							num107 = -(~num107);
							num107 = (num107 - ~1479068368) * -1218848655;
						}
						if (num106 == (uint)num107)
						{
							loginViewModel.AppViewModel.SetUpdateState(message, _002F_002A_003E_002A_002D_002F_0025_0024(result));
							int[] array29 = new int[5];
							array29[0] = -431982573;
							array29[1] = -750780351;
							array29[2] = -1465293425;
							array29[3] = 1263012019;
							array29[4] = 609564525;
							array29[3] = array29[0] ^ 0x2D503BC6;
							array29[3] = array29[2] ^ 0x57234127;
							array29[2] = array29[4] ^ 0x28038CFA;
							int[] array30 = new int[6];
							array30[0] = -142559765;
							array30[1] = 1899412482;
							array30[2] = 460647102;
							array30[3] = -1666514643;
							array30[4] = 236187963;
							array30[5] = 1882050286;
							array30[5] = array29[1] ^ -615489043;
							array30[4] ^= -1689496376;
							array30[2] = array30[4] ^ 0x624B7E0;
							int num109 = array30[5] ^ -1301196423;
							num30 = (int)((num5 * 434919101) ^ 0xE54CC1DEu) ^ num109;
							continue;
						}
						uint num110 = num4;
						int num111 = -2162380;
						_ = 0;
						for (int num112 = 0; num112 < 2; num112++)
						{
							num111 = (num111 + (-156133066 ^ 0x4990CD98)) ^ -754413431;
							num111 = (num111 ^ 0x3686EF99) - 2115939653;
						}
						if (num110 == (uint)num111)
						{
							loginViewModel.AppViewModel.AddActivity(message, loginViewModel.StatusLevel);
							int[] array31 = new int[6];
							array31[0] = 1567603799;
							array31[1] = -1159007062;
							array31[2] = -641004919;
							array31[3] = 1007195339;
							array31[4] = 878400535;
							array31[5] = -366114747;
							array31[4] = array31[1] ^ -203530279;
							array31[1] = array31[3] ^ -1586985010;
							array31[4] = array31[2] ^ -1070353783;
							int[] array32 = new int[5];
							array32[0] = 4854660;
							array32[1] = 74968426;
							array32[2] = 1249373272;
							array32[3] = -1879855792;
							array32[4] = 1656187652;
							array32[1] = array31[2] ^ -1591867219;
							array32[4] = array32[2] ^ 0x706A032;
							array32[0] = array32[2] ^ -1117694350;
							int num113 = array32[1] ^ -833011243;
							num30 = ((int)num5 * -1419041659) ^ 0x14FE52A6 ^ num113;
							continue;
						}
						uint num114 = num4;
						int num115 = -149154288;
						_ = 0;
						for (int num116 = 0; num116 < 1; num116++)
						{
							num115 -= -149154298;
						}
						if (num114 == (uint)num115)
						{
							bool num117 = __002A_005E_002A_005E_003C_0023_0040(result);
							int[] array33 = new int[7] { -127202472, 327974122, 346561509, 761908489, 785988901, 886718626, 1016417883 };
							array33[3] ^= -806268055;
							array33[4] = array33[5] ^ -324338375;
							array33[3] = array33[1] ^ -940399759;
							int[] array34 = new int[5];
							array34[0] = 107346170;
							array34[1] = -636241318;
							array34[2] = -1360423365;
							array34[3] = 1462984662;
							array34[4] = 150858311;
							array34[3] = array33[5] ^ 0x74A00F78;
							array34[1] ^= -475583887;
							array34[4] = array34[3] ^ 0x6850DF60;
							array34[1] = array34[2] ^ 0x277D59E1;
							int num118 = array34[3] ^ -499669156;
							int[] array35 = new int[4];
							array35[0] = 1823373939;
							array35[1] = 1673872725;
							array35[2] = 2143367182;
							array35[3] = -838615947;
							array35[0] = array35[1] ^ 0x23971A08;
							array35[1] = array35[0] ^ -1627376746;
							int[] array36 = new int[5];
							array36[0] = -1127203052;
							array36[1] = -1460612783;
							array36[2] = -1788928589;
							array36[3] = 855561997;
							array36[4] = 1057974793;
							array36[4] = array35[3] ^ -371250772;
							array36[3] = array36[1] ^ 0x285B0CFF;
							array36[3] = array36[2] ^ 0xAF96609;
							array36[0] = array36[2] ^ 0x51AADF6;
							int num119 = array36[4] ^ 0x38A26E6A;
							int num120 = (int)(num5 * 88175720) ^ -1164841200;
							num118 ^= num120;
							num119 ^= num120;
							int num121;
							int num122;
							if (num117)
							{
								num121 = num119;
								num122 = num121;
							}
							else
							{
								num121 = num118;
								num122 = num121;
							}
							num30 = num121 ^ num120;
							continue;
						}
						uint num123 = num4;
						int num124 = -930123984;
						_ = 0;
						for (int num125 = 0; num125 < 2; num125++)
						{
							num124 = -(num124 ^ -2096683504);
							num124 = ~(num124 + (1511841972 + 220508877));
						}
						if (num123 == (uint)num124)
						{
							ProcessStartInfo processStartInfo = new ProcessStartInfo();
							__0026_003D_0026_0021_002F_0026_003C(processStartInfo, _002F_002A_003E_002A_002D_002F_0025_0024(result));
							_002B_005E_0021_005E_005E_0040_0040_0025(processStartInfo, true);
							_0024_0026_003C_003E_003E_0021_0025_002F(processStartInfo);
							int[,] array37 = new int[3, 3];
							array37[0, 0] = 1097070742;
							array37[0, 1] = -339213334;
							array37[0, 2] = -259929078;
							array37[1, 0] = -2061043740;
							array37[1, 1] = 965977367;
							array37[1, 2] = 341631758;
							array37[2, 0] = 1104291121;
							array37[2, 1] = -1616327287;
							array37[2, 2] = 465916996;
							array37[2, 0] = array37[0, 2] ^ -1463889699;
							array37[0, 2] = array37[1, 2] ^ 0x1C4B72AC;
							array37[2, 1] = array37[1, 2] ^ 0x64EADC06;
							int num126 = array37[2, 1] ^ -755247218;
							num30 = (int)((num5 * 1664432922) ^ 0x724F9718) ^ num126;
							continue;
						}
						uint num127 = num4;
						int num128 = 486945554;
						_ = 0;
						for (int num129 = 0; num129 < 1; num129++)
						{
							num128 = 486945569 - num128;
						}
						if (num127 != (uint)num128)
						{
							uint num130 = num4;
							int num131 = -643496696;
							_ = 0;
							for (int num132 = 0; num132 < 1; num132++)
							{
								num131 ^= -643496704;
							}
							if (num130 == (uint)num131)
							{
							}
						}
						goto end_IL_0b0c;
						IL_1a4d:
						message = text;
						num30 = 1652175991;
					}
					goto IL_0b15;
					IL_17e3:
					awaiter = _003C_003Eu__1;
					num30 = -1986816071;
					goto IL_0b1a;
					end_IL_0b0c:;
				}
				finally
				{
					if (num < 0)
					{
						while (true)
						{
							int num133 = -1360976821;
							while (true)
							{
								int num3 = num133;
								uint num5;
								uint num4 = (num5 = (uint)(~(~(((-((-(841685949 + 1300851333) ^ -(1962645491 * -1078712389)) - (~-1152707163 - 1708631581 * 1005066212 + 1696368090) - (1422076036 - ((-2052446186 ^ 0x656AF5E) - --1033912010) - -1608613135)) ^ 0x2D3C7941) - ~(~num3)) * 1909464043 - -2125855495 * (-1171782585 ^ -(~(1461831269 - 1562542820))) - -962354249 * (-14670293 - 1255866044 + -(0x7E49808B ^ -1789266342))) * 613081509) - -1071188629)) % 3;
								uint num134 = num4;
								int num135 = 440181434;
								_ = 0;
								for (int num136 = 0; num136 < 1; num136++)
								{
									num135 *= -1063220491;
								}
								if (num134 == (uint)num135)
								{
									break;
								}
								uint num137 = num4;
								int num138 = -1521488107;
								_ = 0;
								for (int num139 = 0; num139 < 2; num139++)
								{
									num138 = (num138 - -1449215957) ^ -1631161936;
									num138 = num138 * -523463915 - -314855365;
								}
								if (num137 != (uint)num138)
								{
									uint num140 = num4;
									int num141 = -577346865;
									_ = 0;
									for (int num142 = 0; num142 < 1; num142++)
									{
										num141 += 577346865;
									}
									if (num140 == (uint)num141)
									{
									}
									goto end_IL_3a0a;
								}
								loginViewModel.IsBusy = false;
								int[,] array38 = new int[4, 4];
								array38[0, 0] = -661428385;
								array38[0, 1] = 1437933265;
								array38[0, 2] = 251715047;
								array38[0, 3] = -2069032191;
								array38[1, 0] = -1676996725;
								array38[1, 1] = 597058200;
								array38[1, 2] = 566802640;
								array38[1, 3] = -2019806356;
								array38[2, 0] = -851914448;
								array38[2, 1] = 424822020;
								array38[2, 2] = 2043950683;
								array38[2, 3] = 1913475403;
								array38[3, 0] = -68690693;
								array38[3, 1] = -87338538;
								array38[3, 2] = -699788970;
								array38[3, 3] = -49638498;
								array38[3, 1] = array38[2, 2] ^ -372549167;
								array38[0, 0] = array38[1, 2] ^ 0x65B84A70;
								array38[1, 3] = array38[3, 0] ^ -1581114116;
								array38[3, 1] = array38[0, 1] ^ 0x4E9E575F;
								int num143 = array38[3, 1] ^ -263857753;
								num133 = ((int)num5 * -1728386181) ^ -1613227108 ^ num143;
							}
							continue;
							end_IL_3a0a:
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
					int num144 = 1030200232;
					while (true)
					{
						int num3 = num144;
						uint num5;
						uint num4 = (num5 = (uint)(~(~(((-((-(841685949 + 1300851333) ^ -(1962645491 * -1078712389)) - (~-1152707163 - 1708631581 * 1005066212 + 1696368090) - (1422076036 - ((-2052446186 ^ 0x656AF5E) - --1033912010) - -1608613135)) ^ 0x2D3C7941) - ~(~num3)) * 1909464043 - -2125855495 * (-1171782585 ^ -(~(1461831269 - 1562542820))) - -962354249 * (-14670293 - 1255866044 + -(0x7E49808B ^ -1789266342))) * 613081509) - -1071188629)) % 4;
						uint num145 = num4;
						int num146 = -1637089314;
						_ = 0;
						for (int num147 = 0; num147 < 1; num147++)
						{
							num146 ^= -1637089315;
						}
						if (num145 == (uint)num146)
						{
							break;
						}
						uint num148 = num4;
						int num149 = 1740626049;
						_ = 0;
						for (int num150 = 0; num150 < 2; num150++)
						{
							num149 = num149 * 305892353 * 1833418897;
							num149 = -num149 ^ 0x61305038;
						}
						if (num148 != (uint)num149)
						{
							uint num151 = num4;
							int num152 = -2;
							_ = 0;
							for (int num153 = 0; num153 < 1; num153++)
							{
								num152 = -num152;
							}
							if (num151 != (uint)num152)
							{
								uint num154 = num4;
								int num155 = -1454305136;
								_ = 0;
								for (int num156 = 0; num156 < 2; num156++)
								{
									num155 = (num155 + (1531776725 - -1646286775)) ^ 0xB06414;
									num155 = (num155 - -235647950) ^ 0x21A5829B;
								}
								if (num154 == (uint)num155)
								{
								}
								return;
							}
							_003C_003Et__builder.SetException(exception);
							int[] array39 = new int[6];
							array39[0] = -626101302;
							array39[1] = -1323724272;
							array39[2] = -158439382;
							array39[3] = 735785577;
							array39[4] = 676164399;
							array39[5] = 169178273;
							array39[0] = array39[3] ^ 0x2795FE35;
							array39[1] = array39[5] ^ 0x3C7CA71C;
							array39[4] ^= 1684338035;
							int[] array40 = new int[5];
							array40[0] = 1588607178;
							array40[1] = 1590391491;
							array40[2] = 1796286965;
							array40[3] = -540478341;
							array40[4] = 798308992;
							array40[2] = array39[3] ^ 0x5048167B;
							array40[1] = array40[4] ^ -469982977;
							array40[3] ^= 371216613;
							array40[3] = array40[2] ^ 0x4151BE45;
							int num157 = array40[2] ^ 0x667C0C69;
							num144 = (int)((num5 * 38142185) ^ 0x1BB922A6) ^ num157;
						}
						else
						{
							_003C_003E1__state = -2;
							int[,] array41 = new int[4, 3];
							array41[0, 0] = 216077090;
							array41[0, 1] = 1971641515;
							array41[0, 2] = 1933885430;
							array41[1, 0] = -1275593107;
							array41[1, 1] = 1511161748;
							array41[1, 2] = -1482741462;
							array41[2, 0] = -124126276;
							array41[2, 1] = 622200269;
							array41[2, 2] = 2068661043;
							array41[3, 0] = 2132075424;
							array41[3, 1] = -1807222344;
							array41[3, 2] = -1190582504;
							array41[2, 2] = array41[0, 1] ^ -590203125;
							array41[0, 1] = array41[3, 0] ^ 0x5C9BCB30;
							array41[0, 0] = array41[3, 0] ^ 0x6351F1B5;
							int num158 = array41[0, 0] ^ -986873784;
							num144 = ((int)num5 * -55505487) ^ -1742365943 ^ num158;
						}
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num159 = -809644091;
				while (true)
				{
					int num3 = num159;
					uint num5;
					uint num4 = (num5 = (uint)(~(~(((-((-(841685949 + 1300851333) ^ -(1962645491 * -1078712389)) - (~-1152707163 - 1708631581 * 1005066212 + 1696368090) - (1422076036 - ((-2052446186 ^ 0x656AF5E) - --1033912010) - -1608613135)) ^ 0x2D3C7941) - ~(~num3)) * 1909464043 - -2125855495 * (-1171782585 ^ -(~(1461831269 - 1562542820))) - -962354249 * (-14670293 - 1255866044 + -(0x7E49808B ^ -1789266342))) * 613081509) - -1071188629)) % 3;
					uint num160 = num4;
					int num161 = 0;
					_ = 0;
					for (int num162 = 0; num162 < 1; num162++)
					{
						num161 = -num161;
					}
					if (num160 == (uint)num161)
					{
						break;
					}
					uint num163 = num4;
					int num164 = -1;
					_ = 0;
					for (int num165 = 0; num165 < 1; num165++)
					{
						num164 = -num164;
					}
					if (num163 != (uint)num164)
					{
						uint num166 = num4;
						int num167 = -2;
						_ = 0;
						for (int num168 = 0; num168 < 1; num168++)
						{
							num167 = -num167;
						}
						if (num166 == (uint)num167)
						{
						}
						return;
					}
					_003C_003Et__builder.SetResult();
					int[] array42 = new int[7];
					array42[0] = -1040196065;
					array42[1] = 389227450;
					array42[2] = 135041439;
					array42[3] = -2132911090;
					array42[4] = -1757062644;
					array42[5] = 800239322;
					array42[6] = -284075303;
					array42[5] = array42[6] ^ -7508236;
					array42[5] = array42[1] ^ -867191446;
					array42[0] = array42[6] ^ -1645175188;
					int[] array43 = new int[6] { -462138410, 911597974, 553398214, 1135923551, -761026051, -523791233 };
					int[][] array44 = new int[2][] { array42, array43 };
					array43[5] = array44[0][2] ^ 0x2678B74F;
					array43[0] = array43[3] ^ 0x5FEA6B75;
					array43[4] = array43[1] ^ -275695607;
					int num169 = array44[1][5] ^ -1510971892;
					num159 = (int)((num5 * 1933663907) ^ 0xA328C5DAu) ^ num169;
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

		static Task<AuthBootstrapState> _003C_0025_0021_002D_003F_002F_0026_0021(IAuthenticationService P_0, CancellationToken P_1)
		{
			Task<AuthBootstrapState> result = default(Task<AuthBootstrapState>);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1379866954;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((((num2 * -259833633 - ((-(2036237761 * (-1213548186 * -195640203)) ^ ~(--335522757 ^ 0x5C838906 ^ 0x67F551B6) ^ 0x392551DB ^ -2118204159) - ~(-(~1196136623)))) ^ (1720311523 - -(-((0x4A403841 ^ -486398689) + -417674303 * (1559120341 - -302686808))) + (-432410462 ^ (-534689877 * (0x4084F0F9 ^ 0x4555959) + (~(-284144431 * --1000900708) - (-1913885267 * -1305031078 - -1925322981 * (-553353621 ^ 0x51C605CC))))))) * 1445625973) ^ (-2020259870 - (-1143049662 ^ 0x7F3534CF) - ((0x4BFA7CE2 ^ --1720584487) - (1604351898 + -2140132623 + 950121782)) + -1462154824))) % 3;
						int num5 = 666172678;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 -= 666172678;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~(~num7);
							num7 = -num7 - 329671621;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -406372006;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 *= -2008104155;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.InitializeAsync(P_1);
						int[] array = new int[7];
						array[0] = -641641443;
						array[1] = -968869427;
						array[2] = -344979384;
						array[3] = -474622684;
						array[4] = 1041196826;
						array[5] = 1092292080;
						array[6] = -49212291;
						array[5] = array[3] ^ -1291636687;
						array[2] = array[3] ^ -1442094;
						int[] array2 = new int[4] { 249997620, -842207287, -987862841, -2083380935 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[0] = array3[0][0] ^ -649145924;
						array2[2] = array2[0] ^ 0x717DEF96;
						array2[1] = array2[2] ^ 0x6CA08082;
						array2[2] ^= 894740814;
						int num11 = array3[1][0] ^ -1456073415;
						num = ((int)num4 * -1377334521) ^ -990766190 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static string _005E_002B_003C_005E_003E_002F_0025_0029(AuthBootstrapState P_0)
		{
			string cachedLicense = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -132535550;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-((-((num2 ^ ~(~(~(0x3A2424AC ^ (~(-(-1982351853 ^ 0x7D2A77E9)) * 827870443))) + (((~(0x246FB168 ^ -1119781967) + -(1790249504 + -1919178346) + (-1124215334 ^ -71002620) * -10955369 * -942156495) ^ (-777718773 - (-(-1246354464 + 971822368) - ((0x66F989EA ^ 0x26827B3A) + ~-2131265498)))) + -252744435 - -(~(0xA72917E ^ -315883069) ^ (-1269315909 * 1991356895 + ~(1540510138 * 654609211) - -339475484))))) + -(-573118545 ^ (0x42E34EBF ^ (-261320331 + (19857058 + -803078485) - (-1521615047 - -1838219086 + -180205121) + (-1048567926 ^ -1733929495))) ^ -1840362945)) * 387130871 * 1766815107) ^ -((-983627127 ^ 0x670FDE83) * 1591254479)))) % 3;
						int num5 = 1610976728;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 ^= 0x60058DD8;
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
							int num9 = 97408029;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = (num9 ^ 0x7F291F56) - 1038162569;
								num9 = -(num9 ^ 0x6CD83578);
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						cachedLicense = P_0.CachedLicense;
						int[,] array = new int[3, 4];
						array[0, 0] = -246344018;
						array[0, 1] = 1253668104;
						array[0, 2] = 521673663;
						array[0, 3] = -1016639443;
						array[1, 0] = 1804074100;
						array[1, 1] = 77623096;
						array[1, 2] = -1048688464;
						array[1, 3] = 1475674343;
						array[2, 0] = 1823663564;
						array[2, 1] = -2094750751;
						array[2, 2] = -1372283690;
						array[2, 3] = 1283260445;
						array[2, 3] = array[2, 0] ^ 0x53FE4C0F;
						array[2, 3] = array[0, 3] ^ -820025988;
						array[2, 1] = array[0, 1] ^ 0x4F57750C;
						array[2, 1] = array[1, 2] ^ 0xE961622;
						int num11 = array[2, 1] ^ 0x6DF4CA97;
						num = (int)((num4 * 1205036709) ^ 0x777B43C5) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return cachedLicense;
		}

		static bool _002F_003D_002A_0028_0024_003E_002D_(string P_0)
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
					int num = 297251433;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((~(-(((-(~(~(-2012783128 + -108726479 + (194066361 + -1389343269)))) + -745488920) ^ (-(-(473428083 * 2099121961 - (431592997 - -1721068625 - (-634840829 + -210190663)))) * -2047484753)) - ~(~num2))) - (~-1392385113 - (1288031771 - (-1418109802 ^ -1995937643))) - (-310610298 ^ -(~2075495445)) - -(--1721833362) - 1220923884) ^ 0x4EDA5B1F)) % 3;
						int num5 = -785195352;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -(num5 ^ -1340325267);
							num5 = (num5 ^ -2067806009) * -248702037;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -541196047;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 ^= 0x4712ED66;
							num7 = num7 + 713174303 - 1449234809;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 136963896;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 ^= 0x829E73A;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = string.IsNullOrWhiteSpace(P_0);
						int[] array = new int[7] { 680740365, -1582801521, -533803341, -5322980, -603619608, -233945515, 1211027548 };
						array[6] ^= -400809024;
						array[6] ^= -1427170480;
						int[] array2 = new int[4] { -637833427, 1059671383, -1329137129, 468047783 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[3] = array3[0][4] ^ -2145661544;
						array2[1] = array2[0] ^ 0x6BE53CBA;
						array2[1] = array2[2] ^ 0x468BE6AE;
						array2[0] = array2[2] ^ 0x15F0F4F6;
						int num11 = array3[1][3] ^ 0x44B8C245;
						num = (int)((num4 * 1735146445) ^ 0x248027A3) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static bool _003D_003C_0021_0028_002F_002A_003D_002A(AuthBootstrapState P_0)
		{
			bool ısReady = default(bool);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 1382975947;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(((--1554580176 ^ -534881694) + 470347123 - ~(1564330197 * (-325656709 * --228150265) - (~(~(~((1925626116 - 2026666829) * 724546237) - (1273068526 - 263440319 + (934848732 - -402077308) - ((-552312766 ^ 0x4A1FF3BD) - (-1059195572 ^ 0x6B854980))))) + (--673192048 ^ (1317556821 + (--326483676 - -1384465677 - ~(0x792D9028 ^ 0x7DFF5187) - (-203501137 * (-1214616846 ^ -1551375207) + (-1226448235 - -892956811) * -555625039)))) - (-1588513296 + (-1184778235 ^ (785490449 * -(~(364497636 - -114254186)))) - ~(-1122484103 * ~(~-71151410) * 2092138111 - -(-1168678571 ^ -399794990))) - -num2 + (-211118892 - ((0x7371ACF5 ^ -1768293605) - (~(-1491576639 * -1457762031) - (--1150374029 ^ 0x20BA2B3C)) + -(((0x53A0977C ^ -1628778214) + 2084167601 * -1548058654) * -186856981)) + (-(--2134710924) - 496859971 * ((-2050554770 - (-2103052399 - -1567689974)) * -326226199) + ~(-1627796089 ^ 0x667E275E))))) * 1939197619) * -908973047) * -828120809)) % 3;
						int num5 = 579411669;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 -= 579411669;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1344604257;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = (num7 - 1583104696 * -1031980637) ^ -693552246;
							num7 = -(-num7);
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1372623690;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 -= -1372623692;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						ısReady = P_0.IsReady;
						int[,] array = new int[3, 4];
						array[0, 0] = 1064179533;
						array[0, 1] = 1964908197;
						array[0, 2] = 67264913;
						array[0, 3] = -1186410458;
						array[1, 0] = 2028785850;
						array[1, 1] = -1649161729;
						array[1, 2] = 1645205167;
						array[1, 3] = 809794180;
						array[2, 0] = -1512994344;
						array[2, 1] = -2111686390;
						array[2, 2] = -2060526341;
						array[2, 3] = -17987953;
						array[1, 1] = array[2, 1] ^ 0x35F9EA24;
						array[2, 0] = array[2, 1] ^ 0x7E016118;
						array[2, 2] = array[2, 3] ^ -428549425;
						int num11 = array[2, 2] ^ 0x5621DE70;
						num = ((int)num4 * -1820744478) ^ 0x3137FDBA ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return ısReady;
		}

		static bool __002A_005E_002A_005E_003C_0023_0040(AuthBootstrapState P_0)
		{
			bool requiresUpdate = default(bool);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 771411865;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(num2 ^ -(-2057099987 * ~((1361293171 * (0x1A6590D3 ^ -477570716) + -1987051636 * -535713657 - ((0x11D702F1 ^ 0x54D96303) - (~(-273224393 - -794909417) + (-143652463 * -1659672361 - -66442784)))) * 116612225)) ^ (-2019562903 * (~((0x688853A3 ^ (-447283934 ^ ~(-558302898))) + 1068231188) * -679531527)) ^ (-2078332120 - ~(-((0x4B19606F ^ 0x7E3FBB50) * -548295215)) - (519587718 * -316679625 - -(~(-699461304 + -623037669 + --877139321) + -1440857789 * -1496650584))) ^ -(-(-1189212305 ^ 0x3491634F) + (0x44D216A3 ^ 0x553AE504) + 664200737)))) % 3;
						int num5 = 1188385885;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 ^= 0x46D5545D;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1701342865;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 -= 1701342863;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1094195555;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 *= 1319489461;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						requiresUpdate = P_0.RequiresUpdate;
						int[,] array = new int[3, 4];
						array[0, 0] = 617956584;
						array[0, 1] = 439438139;
						array[0, 2] = -1992377860;
						array[0, 3] = 432550837;
						array[1, 0] = 236460392;
						array[1, 1] = 523863489;
						array[1, 2] = 171280198;
						array[1, 3] = -584244960;
						array[2, 0] = 458683876;
						array[2, 1] = -1019132728;
						array[2, 2] = 1517910479;
						array[2, 3] = -403637491;
						array[1, 1] = array[0, 0] ^ 0x1E9C9673;
						array[1, 3] = array[0, 2] ^ -2046049601;
						array[1, 3] = array[2, 0] ^ -1897926033;
						int num11 = array[1, 3] ^ -473046372;
						num = ((int)num4 * -705540089) ^ 0x686C383A ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return requiresUpdate;
		}

		static string _003E_002F_003E_003E_0025_0024_0023_003E(AuthBootstrapState P_0)
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
					int num = -1463450469;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(-(-(-((((-num2 ^ ((-1777411513 - ~418203817) * -561885957 + (2099418341 * 351513772 + (0x5414DCCF ^ 0x47117756) - ~-1550849531 + (~(-(-1183579941 * -1153122479)) ^ 0x3004BFA) + -(~(-(-(-1095667847 ^ -249588959))))) - (-(((-1857766585 + -2050172943 + (-432425612 ^ -403867708)) * -1596209433 + (0x4B5A6733 ^ 0x280D5A3B)) * -1814162013) - (~(-1167231939 * -(578585803 * -1360564237)) + -(1109949419 * (~-399278851 - -1749978248 * -877912769))) * 14740027))) + (~(1353762476 - (1126512190 - -2001085659) * 476966529 - ~(-38519121 * 1092795153) * 338445457 + 1296034167) + (~((0x4E0A2A2C ^ 0x6ADB75F5) * -574546525) + (0x515E3508 ^ ~(-(-(-1819807096 + -1071889214))))))) ^ -(~(0x2DDEA8C3 ^ -2023843146) + (-(-1344586345 ^ -1065408525) - -(0x4AA555E ^ -1996379199)) - ~(-665101769 - (-1980530916 - 707094491) + ((-250268080 ^ -542586462) + (0x223EB56 ^ 0x60E1FB7D))))) * 389958039))) - ~1403604911))) % 3;
						int num5 = -2139858834;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 *= -712947321;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -2147319735;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -(num7 - (1620500642 - -1055009663));
							num7 = ~(num7 ^ 0x238C359B);
						}
						if (num3 != (uint)num7)
						{
							int num9 = 123754260;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 += -123754260;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						message = P_0.Message;
						int[] array = new int[5];
						array[0] = -2099604593;
						array[1] = 979490912;
						array[2] = 1462904566;
						array[3] = 1305088517;
						array[4] = 1634574402;
						array[1] = array[4] ^ 0x1B8831D1;
						array[4] ^= -588313868;
						int[] array2 = new int[6];
						array2[0] = -761050642;
						array2[1] = 1572842296;
						array2[2] = 1728939196;
						array2[3] = 1399975666;
						array2[4] = -58241824;
						array2[5] = 1189010598;
						array2[0] = array[3] ^ 0x5A09B40B;
						array2[2] = array2[4] ^ -1171430353;
						array2[2] = array2[4] ^ -1631973207;
						array2[1] = array2[4] ^ 0x38E3FF3C;
						int num11 = array2[0] ^ 0x7008147C;
						num = ((int)num4 * -864385204) ^ -1070627240 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return message;
		}

		static string _002A_002D_0023_002D_005E_005E_0025_005E(IStringResourceService P_0, string P_1)
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

		static string _002D__005E_0040_003F_005E_0023_(IStringResourceService P_0, string P_1, object[] P_2)
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
					int num = -578094148;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(-((-((((num2 ^ ~(~(-(-875968122 ^ -1718615805) * -268557259) ^ (1114804841 * (-618116146 + --432536964 * 14876163 + ((-2029087580 ^ --163384763) + (600428778 - (-121708152 ^ -246005231)))) + -(-(-1262275169 ^ -264702577)) + ~(~((-1181402272 ^ 0x494DC530) + 1900039137 * 80950554 + (-45036343 + -1656496981 * -1474200301)) - -(0x3066D7CC ^ -1163078140))))) - (~(-(-(-2130763696 ^ -((-680399573 ^ 0x670889BF) - ~-627854871)))) - 2029283425 * ~(-240570215 * (~(-234719137 * (-614511018 ^ 0x134C69AE)) - (~(--2064572014) - ~(34014759 * -1262922751)))))) * -310937137) ^ ((-(0x62FD621F ^ -(--871675294)) ^ 0x6CB39D85) * -174576239)) ^ -528025793) * 805785669)))) % 3;
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
						int num7 = -1607683319;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -(num7 * -1364578889);
							num7 = (num7 * 423772371) ^ 0x77D2287E;
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
						result = P_0.GetString(P_1, P_2);
						int[,] array = new int[4, 4];
						array[0, 0] = -1864190741;
						array[0, 1] = -931416814;
						array[0, 2] = 1983364372;
						array[0, 3] = 1221694313;
						array[1, 0] = 456476837;
						array[1, 1] = -398911452;
						array[1, 2] = 623864261;
						array[1, 3] = 285953550;
						array[2, 0] = 2009190663;
						array[2, 1] = -651265449;
						array[2, 2] = 867414724;
						array[2, 3] = 462357854;
						array[3, 0] = 663971073;
						array[3, 1] = 2112272382;
						array[3, 2] = -480251926;
						array[3, 3] = -64993894;
						array[1, 2] = array[1, 0] ^ -1295689975;
						array[0, 0] = array[0, 1] ^ 0x49709481;
						array[1, 3] = array[0, 2] ^ 0x664E3686;
						int num11 = array[1, 3] ^ -408623763;
						num = (int)((num4 * 1631929985) ^ 0x807CD397u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static string _002F_002A_003E_002A_002D_002F_0025_0024(AuthBootstrapState P_0)
		{
			string downloadUrl = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 953736235;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(1228486935 * (-599998885 * ~((1056454291 - -1229876852) * -1394594503)) + -1458157841 - (num2 ^ (-(-220308769 * (1724306371 * (843788651 * (-178961379 * ~(~(--1453100718)))))) ^ (-(~(-187766548 ^ 0x24B1F99A)) + (457005188 - (-(~790669357) - -119128881 * (1043839415 * -1975087659)) - -96612947 * ~(-404635591 * (-1717971447 ^ 0x6371EADE)) - ~(~(~(1460609341 * -1018130038) - (0x359904E6 ^ 0x5D655670)))) + ~(-(~(-103828444 - 1979906974)) + ((-458534299 + (-1478950026 ^ 0x6B62C1DA) - -941476553 * ~-834486340) ^ 0x384BFD7C) - (-1286284184 - ((-1033000366 ^ -33578930) * -2062842981 + ~(-469366625 ^ -1411545158))))))) * 1962525289 * -2038796207 - --1190451607))) % 3;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = ~(444262144 - -1107283443 - num5);
							num5 = -(num5 + 78069138 * 1097913109);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 691471267;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 = 691471268 - num7;
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
						downloadUrl = P_0.DownloadUrl;
						int[] array = new int[5];
						array[0] = -504082057;
						array[1] = 563437636;
						array[2] = -1136286767;
						array[3] = 773051289;
						array[4] = 855308221;
						array[2] = array[4] ^ -685664424;
						array[3] = array[4] ^ 0x48F1C2EF;
						array[4] = array[1] ^ -2139562357;
						int[] array2 = new int[4] { 1957069787, -540860013, -686968435, -1964426505 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[3] = array3[0][1] ^ 0x13DBFA61;
						array2[1] = array2[0] ^ 0x57BFD2F3;
						array2[0] = array2[3] ^ -1045989526;
						int num11 = array3[1][3] ^ -1141169567;
						num = (int)((num4 * 299074403) ^ 0x3394829D) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return downloadUrl;
		}

		static void __0026_003D_0026_0021_002F_0026_003C(ProcessStartInfo P_0, string P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1564446063;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(~(-1811178785 - -(-(-(~(-94045329 + -84908023) - ~(--896070992)) - -(1855218853 * (-426667158 ^ -1046064369)) - 1434380812) - (~(-(-1900827631 - (0x24C051AD ^ -527657675))) + ~(-171872460 ^ -1020093586)) - ((~-447257497 - (((-984154930 + (56625662 - (-205240185 - ~1789943453))) ^ 0x739AFE75) - (-1555180126 * -715597595 - (0x644DB991 ^ -19278619)))) * 566278445 - ((0x67EE949D ^ (~(-1141541013 ^ 0x166F29F6) + (--1408827151 ^ -1222583047) + 1789823041 * 211273150) ^ ((-1812797568 ^ -111568308) - --1627793747 + -328324124)) + (~(-1039877531) - -494964509 * 1013046247 - (-2078931262 ^ -79238338))) * -1568337053 - num2)))) * 2079423945)) % 3;
						int num5 = -1678542518;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = (num5 + -1891523162) * 25932979;
							num5 = -1602758497 - ~num5;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 468551998;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 -= 468551997;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1276116112;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = 502796169 - 1141301176 - num9 - 248984164;
								num9 = ((-715145500 ^ 0x5032EB95) - num9) * 1689396051;
							}
							if (num3 == (uint)num9)
							{
							}
							return;
						}
						P_0.FileName = P_1;
						int[,] array = new int[4, 3];
						array[0, 0] = 1938110579;
						array[0, 1] = 2087036900;
						array[0, 2] = -2088019702;
						array[1, 0] = -612953416;
						array[1, 1] = -138941226;
						array[1, 2] = 1792206496;
						array[2, 0] = -1414915983;
						array[2, 1] = -1394945455;
						array[2, 2] = 1796495356;
						array[3, 0] = 551541244;
						array[3, 1] = -441121583;
						array[3, 2] = 593265979;
						array[0, 0] = array[3, 2] ^ 0x7257A06C;
						array[0, 2] = array[3, 1] ^ -1918987649;
						array[1, 2] = array[0, 1] ^ 0x5033F3A1;
						int num11 = array[1, 2] ^ 0x115C7542;
						num = ((int)num4 * -1851789508) ^ 0x30D479A4 ^ num11;
					}
				}
			}
		}

		static void _002B_005E_0021_005E_005E_0040_0040_0025(ProcessStartInfo P_0, bool P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -210415657;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((-(~(--1112814865 ^ (-163877939 + ~1628426138 - (-(229186441 * (751380147 + -778816459)) - 1461455582 - (~(-681543233 ^ 0x610D3D91) + (818596254 - -1009433107 - ~1558497210) - -95222601 * ((0x486DAC26 ^ -1412826013) * 6330461)))) ^ ~(-1699184279 - (1567972211 * ~(0x78BA0DC ^ -1396991106) + ((-1503022425 * 1787312812 - -1877578429) ^ 0x732FC065)) + -461322007 * (-1566423135 * -(~(-2007812035 ^ 0x287103ED))))) - num2) - -446543145 * (~((-1555607540 ^ -1244880025) - (-511372766 ^ -1877399813)) - (--1503418566 ^ 0x42A1B4F) - (1497906807 + -(-(1598074792 - -485575617))) - (-1361597285 ^ -((0x71D02565 ^ 0x12E7ABB9) + 1542642357 - (-1399332572 + (0x449272A1 ^ -1545986616))))) - ~(-(-1721506646 + (1644712548 - -878954373)) - (~(--1407352530) ^ -(-680396821 ^ 0x65AB7F70))) * -477567201) ^ ~(-(-1527301657 + 610295925) + --1381664879 - (~(0x7C259A7A ^ 0x3161EBCD) - ~(-56610142 ^ -741366744))))) % 3;
						int num5 = 301365036;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 -= 301365036;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -874583434;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 *= 1704696819;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1240989443;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 ^= -1240989444;
							}
							if (num3 == (uint)num9)
							{
							}
							return;
						}
						P_0.UseShellExecute = P_1;
						int[,] array = new int[3, 3];
						array[0, 0] = -1390124401;
						array[0, 1] = 1669510789;
						array[0, 2] = -780377384;
						array[1, 0] = 689572566;
						array[1, 1] = 1145340611;
						array[1, 2] = 683748470;
						array[2, 0] = 358952074;
						array[2, 1] = 140722842;
						array[2, 2] = 884051693;
						array[2, 0] = array[0, 2] ^ -1947613585;
						array[2, 1] = array[0, 1] ^ -2070401313;
						array[0, 2] = array[1, 2] ^ -1525687159;
						int num11 = array[0, 2] ^ 0x78B7122D;
						num = (int)((num4 * 1608223485) ^ 0xF293B9DDu) ^ num11;
					}
				}
			}
		}

		static Process _0024_0026_003C_003E_003E_0021_0025_002F(ProcessStartInfo P_0)
		{
			Process result = default(Process);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 410878707;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(-((num2 - -952727853 * -(0x5477ED6E ^ (~((-(4309691 * 1101607106) ^ -832611615) - ~(~(-1280320906 ^ -141343701))) ^ (-(-(-2033710705 ^ -2065296783)) ^ ((-1342727999 ^ -1526376711) * -1841333845))))) ^ (((1672165737 + (~(-(0x3429A2AC ^ -710207869)) - -(-824725508 ^ -2105282079) * 640749399)) * 1294379163) ^ (782110453 * -1546140858))) - (~(~2005412890) - (((-1747309930 ^ 0x5DEBB4DB) + 1925590049 * (-1180843529 ^ -1006396153)) ^ -(-(-1501749664 + 310092619) + ~(-1839351339))))))) % 3;
						int num5 = 430701669;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 += -430701667;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 45992001;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 += -45992000;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -527827979;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 -= -527827979;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = Process.Start(P_0);
						int[] array = new int[5];
						array[0] = -270140021;
						array[1] = -424252237;
						array[2] = -1956054533;
						array[3] = -1604506476;
						array[4] = 585470396;
						array[4] = array[0] ^ -990393638;
						array[2] = array[0] ^ 0x40E3B88;
						int[] array2 = new int[6];
						array2[0] = -1711115240;
						array2[1] = 1708739581;
						array2[2] = -383963880;
						array2[3] = -587467755;
						array2[4] = 1945549167;
						array2[5] = 972631881;
						array2[3] = array[0] ^ 0xE50C905;
						array2[2] = array2[5] ^ 0x1C696C8C;
						array2[5] = array2[2] ^ -141031231;
						int num11 = array2[3] ^ -1279537130;
						num = (int)((num4 * 1459719984) ^ 0x6F0518C0) ^ num11;
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
	private struct _003COpenUpdateAsync_003Ed__45 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder _003C_003Et__builder;

		public LoginViewModel _003C_003E4__this;

		private TaskAwaiter _003C_003Eu__1;

		private void MoveNext()
		{
			int num = _003C_003E1__state;
			LoginViewModel loginViewModel = _003C_003E4__this;
			try
			{
				if (num != 0)
				{
					goto IL_0023;
				}
				goto IL_08d2;
				IL_0023:
				int num2 = 409750991;
				goto IL_0028;
				IL_0028:
				TaskAwaiter awaiter = default(TaskAwaiter);
				while (true)
				{
					int num3 = num2;
					uint num5;
					uint num4 = (num5 = (uint)((-num3 ^ (1604846941 * 1086705569 + (-(-1855773081 * ~(~(-2017409945 * -1019969827)) + 425263627 * (~(~302336872) + (~598496298 - (-1163803457 ^ 0x2AEB25D1)))) + -2010945069 * 1476368216)) ^ (-(~((870620783 + 41860913) * 46057951 - (-248223658 + -49017999) * -19441687)) ^ (-(-1065449694 - -(-919217219 + 2007402155)) * 1991218773) ^ 0x1C0151E0)) * -186892877 - -1361206540)) % 14;
					uint num6 = num4;
					int num7 = -1581604839;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (1178128577 + 195759200 - num7) ^ 0x2CF9E782;
						num7 = (--1217322240 - num7) * 2017908675;
					}
					if (num6 == (uint)num7)
					{
						break;
					}
					uint num9 = num4;
					int num10 = -153928919;
					_ = 0;
					for (int num11 = 0; num11 < 1; num11++)
					{
						num10 -= -153928923;
					}
					if (num9 == (uint)num10)
					{
						bool num12 = loginViewModel.CanOpenUpdate();
						int[] array = new int[6];
						array[0] = 151649839;
						array[1] = 1699644219;
						array[2] = 1614407221;
						array[3] = 1527375342;
						array[4] = 1404902090;
						array[5] = -1570546965;
						array[3] = array[5] ^ -1731669873;
						array[1] = array[0] ^ -531814584;
						array[2] = array[0] ^ 0x6001B3B0;
						int[] array2 = new int[4] { -933296479, 1640121551, 1825994513, -349764081 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][0] ^ 0x1CD9273;
						array2[2] = array2[3] ^ -623708553;
						array2[3] ^= 416436290;
						array2[0] = array2[3] ^ -1666046924;
						int num13 = array3[1][1] ^ 0xCB39F8E;
						int[] array4 = new int[7];
						array4[0] = -1139349855;
						array4[1] = 1848309080;
						array4[2] = 1029190271;
						array4[3] = -1956851246;
						array4[4] = -1916452876;
						array4[5] = -662485868;
						array4[6] = 1433359679;
						array4[6] = array4[3] ^ 0x3B707692;
						array4[2] = array4[6] ^ 0x3649C98E;
						int[] array5 = new int[7] { 774942353, -1117517772, -249671290, -719242626, 1292110361, 1024282858, -1436933680 };
						int[][] array6 = new int[2][] { array4, array5 };
						array5[6] = array6[0][3] ^ 0x38C68D70;
						array5[4] = array5[0] ^ -1742515783;
						array5[4] ^= 1905538375;
						int num14 = array6[1][6] ^ -1792546987;
						int num15 = (int)((num5 * 118528427) ^ 0x61762B12);
						num13 ^= num15;
						num14 ^= num15;
						int num16;
						int num17;
						if (!num12)
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
					int num19 = -1755253942;
					_ = 0;
					for (int num20 = 0; num20 < 2; num20++)
					{
						num19 = -num19 ^ 0x43A10634;
						num19 = num19 * -500060109 * 1277432311;
					}
					if (num18 != (uint)num19)
					{
						uint num21 = num4;
						int num22 = 2113947679;
						_ = 0;
						for (int num23 = 0; num23 < 2; num23++)
						{
							num22 = -(num22 - (-1065451870 + -890266610));
							num22 = (num22 ^ 0x6767261E) - 990566684;
						}
						if (num21 == (uint)num22)
						{
							awaiter = _002A_005E_0023_0024_002D_002F_005E_003E(_003C_0025_002F_003F_0024_003E_0024_0029(loginViewModel._launcherService, new Uri(loginViewModel.AppViewModel.UpdateUrl)));
							num2 = -1502103654;
							continue;
						}
						uint num24 = num4;
						int num25 = 1903161381;
						_ = 0;
						for (int num26 = 0; num26 < 2; num26++)
						{
							num25 = ~num25 ^ 0x35D81D73;
							num25 = (num25 - -408366159) ^ 0x3F4E056F;
						}
						if (num24 == (uint)num25)
						{
							bool ısCompleted = awaiter.IsCompleted;
							int[] array7 = new int[5];
							array7[0] = 1335490398;
							array7[1] = 538888347;
							array7[2] = -610754648;
							array7[3] = 799612493;
							array7[4] = -1940236342;
							array7[1] = array7[4] ^ 0xCEF6FE3;
							array7[0] = array7[4] ^ 0x7ABBA66E;
							int[] array8 = new int[6];
							array8[0] = 1959136410;
							array8[1] = -406371418;
							array8[2] = 908473707;
							array8[3] = 2017028790;
							array8[4] = -337507845;
							array8[5] = -1530389031;
							array8[3] = array7[2] ^ 0x7947AF80;
							array8[5] = array8[2] ^ 0x3A2EBA80;
							array8[0] = array8[5] ^ 0x657CD018;
							array8[1] = array8[3] ^ -415071523;
							int num27 = array8[3] ^ 0x5B7DDA47;
							int[,] array9 = new int[3, 3];
							array9[0, 0] = -1242788227;
							array9[0, 1] = 1154268146;
							array9[0, 2] = -951539869;
							array9[1, 0] = 1600840201;
							array9[1, 1] = -1962715412;
							array9[1, 2] = 133361628;
							array9[2, 0] = 622192276;
							array9[2, 1] = -892041484;
							array9[2, 2] = -2109489832;
							array9[0, 1] = array9[2, 2] ^ 0x7456D9F6;
							array9[1, 2] = array9[0, 0] ^ 0x353CD705;
							array9[0, 0] = array9[0, 1] ^ 0x53690298;
							array9[0, 2] = array9[2, 1] ^ 0x32208D56;
							int num28 = array9[0, 2] ^ 0x5061E7B6;
							int num29 = (int)((num5 * 66644527) ^ 0x3AB100A9);
							num27 ^= num29;
							num28 ^= num29;
							int num30;
							int num31;
							if (!ısCompleted)
							{
								num30 = num28;
								num31 = num30;
							}
							else
							{
								num30 = num27;
								num31 = num30;
							}
							num2 = num30 ^ num29;
							continue;
						}
						uint num32 = num4;
						int num33 = 11;
						_ = 0;
						for (int num34 = 0; num34 < 2; num34++)
						{
							num33 = 1091905085 - -num33;
							num33 = ~num33 - 1373077405;
						}
						if (num32 == (uint)num33)
						{
							num = (_003C_003E1__state = 0);
							int[,] array10 = new int[3, 3];
							array10[0, 0] = -1985960849;
							array10[0, 1] = 381234065;
							array10[0, 2] = -627786320;
							array10[1, 0] = -648825531;
							array10[1, 1] = -1683656198;
							array10[1, 2] = -2057677286;
							array10[2, 0] = -1987178397;
							array10[2, 1] = 860318865;
							array10[2, 2] = 1868004691;
							array10[0, 0] = array10[1, 0] ^ 0x369EE008;
							array10[0, 1] = array10[1, 0] ^ 0x24BCC3E9;
							array10[0, 0] = array10[0, 2] ^ 0xF522B4C;
							array10[1, 1] = array10[1, 0] ^ -1468228760;
							int num35 = array10[1, 1] ^ 0x37DC2954;
							num2 = ((int)num5 * -586586880) ^ 0x7ACDA900 ^ num35;
							continue;
						}
						uint num36 = num4;
						int num37 = -1501141972;
						_ = 0;
						for (int num38 = 0; num38 < 2; num38++)
						{
							num37 = -(num37 + ~-1038285951);
							num37 = -1605872696 - num37 - 829325910;
						}
						if (num36 == (uint)num37)
						{
							_003C_003Eu__1 = awaiter;
							int[] array11 = new int[4] { 2033346369, 1584815826, 1818457072, 1896719808 };
							array11[2] ^= 2105329768;
							array11[0] = array11[2] ^ -1545779492;
							int[] array12 = new int[6];
							array12[0] = -1745697512;
							array12[1] = -517097770;
							array12[2] = 1509937827;
							array12[3] = 1522551414;
							array12[4] = 149466293;
							array12[5] = 1340205063;
							array12[2] = array11[3] ^ -701628700;
							array12[4] = array12[2] ^ -1049713849;
							array12[3] = array12[0] ^ 0x3AD8A41C;
							int num39 = array12[2] ^ -1390703243;
							num2 = ((int)num5 * -1922502963) ^ 0x9CDC444 ^ num39;
							continue;
						}
						uint num40 = num4;
						int num41 = 0;
						_ = 0;
						for (int num42 = 0; num42 < 2; num42++)
						{
							num41 = -num41 + -1115426562;
							num41 = ~(~num41);
						}
						if (num40 == (uint)num41)
						{
							_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
							int[,] array13 = new int[4, 3];
							array13[0, 0] = -1617110345;
							array13[0, 1] = 1742760536;
							array13[0, 2] = 2012419514;
							array13[1, 0] = -158648710;
							array13[1, 1] = -1726196688;
							array13[1, 2] = -780509137;
							array13[2, 0] = 1193933436;
							array13[2, 1] = -2121346281;
							array13[2, 2] = 1899218724;
							array13[3, 0] = 1713852636;
							array13[3, 1] = 1468471008;
							array13[3, 2] = -939600316;
							array13[3, 0] = array13[3, 1] ^ -2098172575;
							array13[1, 0] = array13[2, 2] ^ -1269628047;
							array13[3, 0] = array13[3, 2] ^ 0x4C4822C7;
							int num43 = array13[3, 0] ^ 0x2C58837A;
							num2 = (int)((num5 * 1385624937) ^ 0xB68C987Cu) ^ num43;
							continue;
						}
						uint num44 = num4;
						int num45 = 537132680;
						_ = 0;
						for (int num46 = 0; num46 < 2; num46++)
						{
							num45 = (num45 ^ -1286995484) - 1867489981;
							num45 = -num45;
						}
						if (num44 == (uint)num45)
						{
							return;
						}
						uint num47 = num4;
						int num48 = -809921715;
						_ = 0;
						for (int num49 = 0; num49 < 2; num49++)
						{
							num48 *= 1537935059;
							num48 = -num48 ^ 0x430A708A;
						}
						if (num47 == (uint)num48)
						{
							goto IL_08d2;
						}
						uint num50 = num4;
						int num51 = -2;
						_ = 0;
						for (int num52 = 0; num52 < 1; num52++)
						{
							num51 = -num51;
						}
						if (num50 == (uint)num51)
						{
							_003C_003Eu__1 = default(TaskAwaiter);
							int[] array14 = new int[7] { -1500132185, -453182796, 152111478, 1289621168, -1209447250, 1596716256, -2034493846 };
							array14[0] ^= -1871678097;
							array14[3] = array14[6] ^ -1788797041;
							int[] array15 = new int[4];
							array15[0] = -915480139;
							array15[1] = 1380501020;
							array15[2] = 781747362;
							array15[3] = 2092363846;
							array15[1] = array14[4] ^ 0x7B22D03D;
							array15[3] ^= 518396601;
							array15[0] = array15[3] ^ -177950251;
							int num53 = array15[1] ^ -976494529;
							num2 = (int)((num5 * 81637111) ^ 0x32E76E0C) ^ num53;
							continue;
						}
						uint num54 = num4;
						int num55 = -1834958103;
						_ = 0;
						for (int num56 = 0; num56 < 1; num56++)
						{
							num55 *= 577910105;
						}
						if (num54 == (uint)num55)
						{
							num = (_003C_003E1__state = -1);
							int[,] array16 = new int[4, 4];
							array16[0, 0] = 1576644369;
							array16[0, 1] = 852060291;
							array16[0, 2] = 82001866;
							array16[0, 3] = 81854111;
							array16[1, 0] = -829569193;
							array16[1, 1] = 1170725136;
							array16[1, 2] = 893997680;
							array16[1, 3] = -517694369;
							array16[2, 0] = -1463791295;
							array16[2, 1] = 167290510;
							array16[2, 2] = -1150373027;
							array16[2, 3] = -1715603779;
							array16[3, 0] = 1419207408;
							array16[3, 1] = -607738412;
							array16[3, 2] = -662934081;
							array16[3, 3] = -922794027;
							array16[1, 0] = array16[1, 3] ^ 0x4DDBC802;
							array16[2, 3] = array16[2, 1] ^ 0x5F845130;
							array16[1, 0] = array16[0, 1] ^ 0x76AA31A8;
							int num57 = array16[1, 0] ^ -1111379132;
							num2 = (int)((num5 * 1556117830) ^ 0xCE9F492Eu) ^ num57;
							continue;
						}
						uint num58 = num4;
						int num59 = 1302131974;
						_ = 0;
						for (int num60 = 0; num60 < 2; num60++)
						{
							num59 = (num59 * -1118668263) ^ -1431205904;
							num59 *= 1380960473;
						}
						if (num58 == (uint)num59)
						{
							awaiter.GetResult();
							num2 = 1314532106;
							continue;
						}
						uint num61 = num4;
						int num62 = -2115805732;
						_ = 0;
						for (int num63 = 0; num63 < 1; num63++)
						{
							num62 += 2115805735;
						}
						if (num61 == (uint)num62)
						{
						}
					}
					goto end_IL_001a;
				}
				goto IL_0023;
				IL_08d2:
				awaiter = _003C_003Eu__1;
				num2 = 1463169401;
				goto IL_0028;
				end_IL_001a:;
			}
			catch (Exception exception)
			{
				while (true)
				{
					int num64 = 1993071583;
					while (true)
					{
						int num3 = num64;
						uint num5;
						uint num4 = (num5 = (uint)((-num3 ^ (1604846941 * 1086705569 + (-(-1855773081 * ~(~(-2017409945 * -1019969827)) + 425263627 * (~(~302336872) + (~598496298 - (-1163803457 ^ 0x2AEB25D1)))) + -2010945069 * 1476368216)) ^ (-(~((870620783 + 41860913) * 46057951 - (-248223658 + -49017999) * -19441687)) ^ (-(-1065449694 - -(-919217219 + 2007402155)) * 1991218773) ^ 0x1C0151E0)) * -186892877 - -1361206540)) % 4;
						uint num65 = num4;
						int num66 = -1;
						_ = 0;
						for (int num67 = 0; num67 < 1; num67++)
						{
							num66 = ~num66;
						}
						if (num65 == (uint)num66)
						{
							break;
						}
						uint num68 = num4;
						int num69 = -1801043414;
						_ = 0;
						for (int num70 = 0; num70 < 2; num70++)
						{
							num69 = -(num69 * -1975282111);
							num69 = -num69 - -1308059372;
						}
						if (num68 != (uint)num69)
						{
							uint num71 = num4;
							int num72 = -2130711675;
							_ = 0;
							for (int num73 = 0; num73 < 2; num73++)
							{
								num72 = ~(num72 ^ 0x3D0960B2);
								num72 = ~num72 - 1903662435;
							}
							if (num71 != (uint)num72)
							{
								uint num74 = num4;
								int num75 = 35733537;
								_ = 0;
								for (int num76 = 0; num76 < 2; num76++)
								{
									num75 = -num75 - -1729011535;
									num75 ^= --1100344863;
								}
								if (num74 == (uint)num75)
								{
								}
								return;
							}
							_003C_003Et__builder.SetException(exception);
							int[] array17 = new int[4];
							array17[0] = -1294961416;
							array17[1] = 641727043;
							array17[2] = -1467422526;
							array17[3] = 1277435791;
							array17[1] = array17[2] ^ -723085162;
							array17[2] ^= -541412683;
							int[] array18 = new int[7] { -1959074168, 1749146566, -1985534992, -290374340, -1661123981, -1262883330, -1162518607 };
							int[][] array19 = new int[2][] { array17, array18 };
							array18[3] = array19[0][3] ^ 0x6DF3D038;
							array18[0] = array18[5] ^ 0x6F8F4C30;
							array18[4] = array18[3] ^ 0x5FEC9BF1;
							array18[1] = array18[3] ^ -928749508;
							int num77 = array19[1][3] ^ -222898885;
							num64 = (int)((num5 * 1470835917) ^ 0x378023D7) ^ num77;
						}
						else
						{
							_003C_003E1__state = -2;
							int[] array20 = new int[5] { -1616400964, -1189039869, -1252839293, 1658951161, -1195591282 };
							array20[4] ^= -1200772379;
							array20[2] ^= -441862237;
							array20[3] = array20[4] ^ -1107411622;
							int[] array21 = new int[4] { 1721014622, 1448950892, 1126023280, 1911391772 };
							int[][] array22 = new int[2][] { array20, array21 };
							array21[0] = array22[0][1] ^ -1065447444;
							array21[2] = array21[3] ^ 0x14EDBD74;
							array21[3] = array21[0] ^ 0x205D1DFB;
							array21[1] = array21[0] ^ 0x65F0357D;
							int num78 = array22[1][0] ^ 0x502830B1;
							num64 = ((int)num5 * -2102971242) ^ 0x1420B3C4 ^ num78;
						}
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num79 = -1057549669;
				while (true)
				{
					int num3 = num79;
					uint num5;
					uint num4 = (num5 = (uint)((-num3 ^ (1604846941 * 1086705569 + (-(-1855773081 * ~(~(-2017409945 * -1019969827)) + 425263627 * (~(~302336872) + (~598496298 - (-1163803457 ^ 0x2AEB25D1)))) + -2010945069 * 1476368216)) ^ (-(~((870620783 + 41860913) * 46057951 - (-248223658 + -49017999) * -19441687)) ^ (-(-1065449694 - -(-919217219 + 2007402155)) * 1991218773) ^ 0x1C0151E0)) * -186892877 - -1361206540)) % 3;
					uint num80 = num4;
					int num81 = -222617085;
					_ = 0;
					for (int num82 = 0; num82 < 1; num82++)
					{
						num81 -= -222617085;
					}
					if (num80 == (uint)num81)
					{
						break;
					}
					uint num83 = num4;
					int num84 = -1132825510;
					_ = 0;
					for (int num85 = 0; num85 < 2; num85++)
					{
						num84 = (num84 - ~442083330) * -1930619081;
						num84 = ~num84 * -1720698597;
					}
					if (num83 != (uint)num84)
					{
						uint num86 = num4;
						int num87 = 1665718209;
						_ = 0;
						for (int num88 = 0; num88 < 2; num88++)
						{
							num87 = num87 * -1301841939 - -2062405866;
							num87 = (num87 - -2121035309 * 1354723252) ^ 0x494814C6;
						}
						if (num86 == (uint)num87)
						{
						}
						return;
					}
					_003C_003Et__builder.SetResult();
					int[,] array23 = new int[4, 3];
					array23[0, 0] = 1839747891;
					array23[0, 1] = -164026522;
					array23[0, 2] = 468760412;
					array23[1, 0] = -199834368;
					array23[1, 1] = 63042430;
					array23[1, 2] = -1932068312;
					array23[2, 0] = 389931137;
					array23[2, 1] = 925436003;
					array23[2, 2] = 1352112849;
					array23[3, 0] = 1563165572;
					array23[3, 1] = 2068289901;
					array23[3, 2] = -160614512;
					array23[0, 2] = array23[0, 1] ^ 0x5022BEA0;
					array23[1, 1] = array23[3, 1] ^ -669389182;
					array23[0, 2] = array23[0, 1] ^ 0x1DDE76BB;
					array23[3, 0] = array23[2, 0] ^ 0x574C2AE2;
					int num89 = array23[3, 0] ^ 0x7A64B4C3;
					num79 = (int)((num5 * 1069027886) ^ 0x11C522C) ^ num89;
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

		static Task _003C_0025_002F_003F_0024_003E_0024_0029(ILauncherService P_0, Uri P_1)
		{
			Task result = default(Task);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -711223788;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(~(~(-((num2 * 1070453873) ^ (((~((0x337E13B2 ^ (-1679664833 * -957485767 + --204048561)) + ~(-715074971 - 1435461695) * -1884016479) ^ ~(~(0x2D94D434 ^ (-1273941850 - -1691923425)))) - --1044511358) ^ (((~(-(-1894343925 - -1374476946)) - 784699872 - (0x7B3BC49 ^ -1975387390)) ^ (-244579817 ^ ((~(-1966016506 + -576032971) - -(-791754669 + 723155744)) * -69628191))) - -(~(1652550808 * -2117420615)))))))) * -1978166553)) % 3;
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
						int num7 = 933306663;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = num7 * 1420078945 * 1789274385;
							num7 = (num7 - -949598915) * -69472803;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 0;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -num9 * 933867713;
								num9 = -num9;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.LaunchUriAsync(P_1);
						int[] array = new int[4] { -965727137, 1499144043, -1814641649, 1068169270 };
						array[0] ^= -1120037328;
						array[3] = array[1] ^ 0x1DA78274;
						array[0] ^= -542693370;
						int[] array2 = new int[7] { 754370565, -930184341, 1317484553, -309307855, 1413966872, 315782861, 1693711876 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[0] = array3[0][1] ^ 0x7DCD406B;
						array2[6] = array2[2] ^ 0x48125BD4;
						array2[2] = array2[6] ^ 0x70119CA8;
						array2[2] = array2[4] ^ 0x34E67F1D;
						int num11 = array3[1][0] ^ -981942259;
						num = ((int)num4 * -146706010) ^ -2024152168 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static TaskAwaiter _002A_005E_0023_0024_002D_002F_005E_003E(Task P_0)
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
					int num = -51472288;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(num2 * 396872045 - (-(~(-849636163 + (-1466296312 - 1882301310 * -1909401611 * -1486271871)) * 1940552353) - -2139162757 * (133717057 * -1219008222 - ~-1091200575) * -637751593) - ~(-(~(-(~(-1857751743 * 1417242141))))) - (~(~(2115712458 - -1236270424)) + (~(1495886215 * -1212014286) - (-335115952 ^ -1304537347))) * -1469462657 * -1516295807)) % 3;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 *= 1032458667;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -2133907626;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 += 2133907628;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1307829549;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -1580688402 - (num9 ^ -1908995107);
								num9 = (num9 + -656092609 * 778292693) * 846755063;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						awaiter = P_0.GetAwaiter();
						int[] array = new int[7] { 2059993046, -211413811, 1145564525, -1214145251, -308393608, 1554357348, -58637538 };
						array[5] ^= 375233755;
						array[0] = array[2] ^ -824124686;
						int[] array2 = new int[4] { 1683003136, 823111665, -13435106, -755863881 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[2] = array3[0][3] ^ -2014881999;
						array2[3] = array2[1] ^ 0x22FB0E48;
						array2[3] = array2[1] ^ -385838763;
						int num11 = array3[1][2] ^ -383737277;
						num = ((int)num4 * -2101448226) ^ 0x23A9104C ^ num11;
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
	private struct _003CResetHwidAsync_003Ed__48 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder _003C_003Et__builder;

		public LoginViewModel _003C_003E4__this;

		private TaskAwaiter<bool> _003C_003Eu__1;

		private TaskAwaiter<AuthResult> _003C_003Eu__2;

		private void MoveNext()
		{
			int num = _003C_003E1__state;
			LoginViewModel loginViewModel = _003C_003E4__this;
			try
			{
				if (num != 0)
				{
					goto IL_0023;
				}
				goto IL_130d;
				IL_0023:
				int num2 = 750909023;
				goto IL_0028;
				IL_0028:
				TaskAwaiter<bool> awaiter = default(TaskAwaiter<bool>);
				TaskAwaiter<AuthResult> awaiter2 = default(TaskAwaiter<AuthResult>);
				AuthResult result = default(AuthResult);
				string text = default(string);
				string text2 = default(string);
				string message = default(string);
				while (true)
				{
					int num3 = num2;
					uint num5;
					uint num4 = (num5 = (uint)(-(~num3 + (1583090351 + -2108844825 * (201391711 * (-92828201 + -1589318123 * -1306210674 - -(-900964712))) - ((-((0x555CA5A4 ^ -460232292) * -766679953) - ~(-1038366856 + 1098909596 - -767542135 * 113760238)) ^ ~(2122974039 - 489121956 - --1944404575 + (-729542386 ^ 0x87FA039)) ^ 0x38F18F72)) * 2084200075) + ((~(-1997797629) - 2009056182 - (((--1713967421 - (365815904 + -59472764)) ^ -332969992) - -660292469 * ((1154129376 - 210984640) * -622182633))) ^ 0x6ACDB49F))) % 17;
					uint num6 = num4;
					int num7 = -515156746;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 *= 1975071995;
						num7 = -(-num7);
					}
					if (num6 == (uint)num7)
					{
						break;
					}
					uint num9 = num4;
					int num10 = -2;
					_ = 0;
					for (int num11 = 0; num11 < 1; num11++)
					{
						num10 = ~num10;
					}
					if (num9 == (uint)num10)
					{
						int num12 = num;
						int[,] array = new int[4, 4];
						array[0, 0] = 736383024;
						array[0, 1] = -153893944;
						array[0, 2] = -2045321067;
						array[0, 3] = -1929979640;
						array[1, 0] = 1719399861;
						array[1, 1] = 439196772;
						array[1, 2] = -1821328535;
						array[1, 3] = 1133459398;
						array[2, 0] = 2127381135;
						array[2, 1] = 1395539187;
						array[2, 2] = -276729395;
						array[2, 3] = -569726579;
						array[3, 0] = -504245854;
						array[3, 1] = -1651635179;
						array[3, 2] = -1881248197;
						array[3, 3] = 1643445466;
						array[1, 3] = array[3, 2] ^ 0x3B02D051;
						array[3, 1] = array[1, 1] ^ 0x627E94FE;
						array[1, 3] = array[0, 3] ^ -1965654301;
						array[3, 1] = array[2, 3] ^ 0x58B9EE60;
						int num13 = array[3, 1] ^ -717753120;
						int[] array2 = new int[4];
						array2[0] = 1218761904;
						array2[1] = 1645526670;
						array2[2] = 1032432726;
						array2[3] = -1908741085;
						array2[0] = array2[2] ^ -204349695;
						array2[0] ^= -2061003165;
						array2[0] = array2[2] ^ 0x5442E7B1;
						int[] array3 = new int[6];
						array3[0] = -542273063;
						array3[1] = 71143790;
						array3[2] = 12156576;
						array3[3] = 1851415393;
						array3[4] = 1018157593;
						array3[5] = -834082506;
						array3[0] = array2[3] ^ 0x1D3F32B9;
						array3[2] ^= -808538772;
						array3[4] = array3[3] ^ 0x53264035;
						int num14 = array3[0] ^ -2039842739;
						int num15 = (int)(num5 * 1967153451) ^ -1923995709;
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
					int num19 = -215488928;
					_ = 0;
					for (int num20 = 0; num20 < 2; num20++)
					{
						num19 = -(num19 * -463968707);
						num19 = (num19 - (-1229542039 + 638296749)) * 1967230295;
					}
					if (num18 == (uint)num19)
					{
						bool num21 = _0025_0025__002B_002F_002F_005E_003F(loginViewModel.LicenseKey);
						int[] array4 = new int[6];
						array4[0] = -626911516;
						array4[1] = 540754644;
						array4[2] = -161251629;
						array4[3] = 2017702149;
						array4[4] = 980513767;
						array4[5] = -1944548981;
						array4[4] = array4[2] ^ 0x3F2717EB;
						array4[3] = array4[1] ^ 0xBA9FD63;
						array4[5] ^= -97671311;
						int[] array5 = new int[5] { 144795681, 245048441, 1740373404, 1882910714, 109206921 };
						int[][] array6 = new int[2][] { array4, array5 };
						array5[4] = array6[0][1] ^ 0x6364B8CD;
						array5[2] = array5[3] ^ 0x63B1E018;
						array5[2] ^= -2123148710;
						array5[2] = array5[3] ^ 0x66232D2A;
						int num22 = array6[1][4] ^ 0x732BA860;
						int[] array7 = new int[7];
						array7[0] = 1708934224;
						array7[1] = 1229422437;
						array7[2] = 1457316404;
						array7[3] = -1706321290;
						array7[4] = 686078327;
						array7[5] = 1829572127;
						array7[6] = 2104009615;
						array7[0] = array7[1] ^ -1347567159;
						array7[2] = array7[0] ^ -1664146593;
						int[] array8 = new int[7];
						array8[0] = 1326264869;
						array8[1] = -105054754;
						array8[2] = -1251170606;
						array8[3] = 2131040467;
						array8[4] = 1956654975;
						array8[5] = 1683146754;
						array8[6] = 1005996478;
						array8[5] = array7[5] ^ -2142838072;
						array8[0] = array8[3] ^ 0x3DB32F46;
						array8[6] ^= 776828559;
						array8[6] = array8[2] ^ 0x3E4ED07;
						int num23 = array8[5] ^ -121700042;
						int num24 = ((int)num5 * -1815132259) ^ 0x2D69D6DD;
						num22 ^= num24;
						num23 ^= num24;
						int num25;
						int num26;
						if (num21)
						{
							num25 = num23;
							num26 = num25;
						}
						else
						{
							num25 = num22;
							num26 = num25;
						}
						num2 = num25 ^ num24;
						continue;
					}
					uint num27 = num4;
					int num28 = 14;
					_ = 0;
					for (int num29 = 0; num29 < 2; num29++)
					{
						num28 = -(~num28);
						num28 = -num28 ^ 0x6965C180;
					}
					if (num27 == (uint)num28)
					{
						loginViewModel.SetStatus(_0026__0025_005E_0023_0029_002A_0029(loginViewModel._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[445 - 34 - 19 - 37]), SeverityLevel.Warning);
						int[] array9 = new int[7];
						array9[0] = 2087964645;
						array9[1] = 375937858;
						array9[2] = 632383732;
						array9[3] = -1823519831;
						array9[4] = 1677125455;
						array9[5] = 2134271420;
						array9[6] = -2127632555;
						array9[4] = array9[0] ^ 0xA476CB5;
						array9[4] = array9[5] ^ -901471635;
						int[] array10 = new int[5];
						array10[0] = 526607113;
						array10[1] = 1804739743;
						array10[2] = 1900547240;
						array10[3] = 939506872;
						array10[4] = -1986643044;
						array10[4] = array9[2] ^ 0x1F3FE86F;
						array10[2] = array10[3] ^ -1543975205;
						array10[1] = array10[4] ^ -1917098016;
						int num30 = array10[4] ^ 0x11236AAA;
						num2 = (int)((num5 * 464172702) ^ 0x6E8EC24A) ^ num30;
						continue;
					}
					uint num31 = num4;
					int num32 = -382340323;
					_ = 0;
					for (int num33 = 0; num33 < 2; num33++)
					{
						num32 = num32 * -442921955 * 367716555;
						num32 = ~num32 * -748379339;
					}
					if (num31 != (uint)num32)
					{
						uint num34 = num4;
						int num35 = -191900943;
						_ = 0;
						for (int num36 = 0; num36 < 2; num36++)
						{
							num35 = ~(num35 ^ -1368281358);
							num35 = 1704858268 - (num35 ^ -816321918);
						}
						if (num34 == (uint)num35)
						{
							awaiter = loginViewModel.AppViewModel.ShowResetHwidConfirmationAsync().GetAwaiter();
							num2 = 186537505;
							continue;
						}
						uint num37 = num4;
						int num38 = 2111072136;
						_ = 0;
						for (int num39 = 0; num39 < 2; num39++)
						{
							num38 = -(-num38);
							num38 = num38 * 1072700137 * -1290306047;
						}
						if (num37 == (uint)num38)
						{
							bool ısCompleted = awaiter.IsCompleted;
							int[] array11 = new int[4];
							array11[0] = 1642027781;
							array11[1] = 1196198444;
							array11[2] = 2064378855;
							array11[3] = -1365481000;
							array11[3] = array11[1] ^ 0x52A59478;
							array11[1] ^= 1863775312;
							int[] array12 = new int[6] { 993872602, -738085594, -1337041313, 1280904631, -114706285, 1159996828 };
							int[][] array13 = new int[2][] { array11, array12 };
							array12[2] = array13[0][2] ^ 0x257A1C8F;
							array12[3] = array12[2] ^ -1608019415;
							array12[4] = array12[5] ^ 0x271CE896;
							array12[4] ^= -1051480303;
							int num40 = array13[1][2] ^ 0x1B41D88;
							int[] array14 = new int[7];
							array14[0] = 945667524;
							array14[1] = 2138775104;
							array14[2] = 1318428085;
							array14[3] = 844430477;
							array14[4] = -1397562606;
							array14[5] = 887371686;
							array14[6] = -506072504;
							array14[2] = array14[3] ^ -312235546;
							array14[3] = array14[0] ^ 0x7C6365B4;
							array14[0] = array14[4] ^ -941669480;
							int[] array15 = new int[4];
							array15[0] = 53288344;
							array15[1] = -661462046;
							array15[2] = -433187254;
							array15[3] = -1222118016;
							array15[3] = array14[4] ^ 0x3B081782;
							array15[0] = array15[2] ^ 0xDE036DA;
							array15[2] ^= -135543246;
							array15[0] ^= -253372946;
							int num41 = array15[3] ^ 0x6294A910;
							int num42 = (int)((num5 * 1713930866) ^ 0x794BD1E6);
							num40 ^= num42;
							num41 ^= num42;
							int num43;
							int num44;
							if (!ısCompleted)
							{
								num43 = num41;
								num44 = num43;
							}
							else
							{
								num43 = num40;
								num44 = num43;
							}
							num2 = num43 ^ num42;
							continue;
						}
						uint num45 = num4;
						int num46 = 755153406;
						_ = 0;
						for (int num47 = 0; num47 < 2; num47++)
						{
							num46 = -1443313662 - (num46 ^ -1135770811);
							num46 = -num46 * -1608396519;
						}
						if (num45 == (uint)num46)
						{
							num = (_003C_003E1__state = 0);
							int[] array16 = new int[4];
							array16[0] = -44613128;
							array16[1] = 630630930;
							array16[2] = -1648761978;
							array16[3] = 579690549;
							array16[1] = array16[0] ^ -425757543;
							array16[0] = array16[3] ^ 0xB4D79D5;
							array16[2] = array16[3] ^ -676528290;
							int[] array17 = new int[5];
							array17[0] = -1126142503;
							array17[1] = 1620829669;
							array17[2] = 101126477;
							array17[3] = -1834638198;
							array17[4] = -1235578030;
							array17[1] = array16[3] ^ -2130709371;
							array17[3] = array17[0] ^ 0x664A0F9A;
							array17[0] = array17[4] ^ -20497856;
							int num48 = array17[1] ^ -1338188850;
							num2 = (int)((num5 * 853601165) ^ 0x2FAFB4E2) ^ num48;
							continue;
						}
						uint num49 = num4;
						int num50 = 412155487;
						_ = 0;
						for (int num51 = 0; num51 < 2; num51++)
						{
							num50 = -(1891871088 + 399130393 - num50);
							num50 += 0x16658BD ^ 0x7D2331DD;
						}
						if (num49 == (uint)num50)
						{
							_003C_003Eu__1 = awaiter;
							int[] array18 = new int[7];
							array18[0] = -582136321;
							array18[1] = -2047652976;
							array18[2] = 634776772;
							array18[3] = 1380381166;
							array18[4] = -1289908610;
							array18[5] = 890101103;
							array18[6] = 188222366;
							array18[4] = array18[2] ^ 0x31D2CF1D;
							array18[1] = array18[0] ^ 0x6C8385BF;
							array18[3] = array18[2] ^ 0x1F6ECE6E;
							int[] array19 = new int[4];
							array19[0] = -515928455;
							array19[1] = -36162296;
							array19[2] = -942777286;
							array19[3] = 998384832;
							array19[0] = array18[2] ^ 0x2111973B;
							array19[3] = array19[0] ^ 0x6B7D4402;
							array19[3] = array19[0] ^ 0x32689BBF;
							int num52 = array19[0] ^ 0x293FEEA;
							num2 = (int)((num5 * 1293981214) ^ 0x487B2B30) ^ num52;
							continue;
						}
						uint num53 = num4;
						int num54 = 2099209554;
						_ = 0;
						for (int num55 = 0; num55 < 1; num55++)
						{
							num54 *= 607999997;
						}
						if (num53 == (uint)num54)
						{
							_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
							int[] array20 = new int[5];
							array20[0] = 175336287;
							array20[1] = -1126505407;
							array20[2] = -1893552814;
							array20[3] = -1964179141;
							array20[4] = -228275541;
							array20[2] = array20[0] ^ -2127166740;
							array20[3] = array20[1] ^ -637726911;
							array20[0] = array20[1] ^ 0x71BC2434;
							int[] array21 = new int[5];
							array21[0] = -354211729;
							array21[1] = -493550084;
							array21[2] = 1236898823;
							array21[3] = 703055153;
							array21[4] = -1948922999;
							array21[2] = array20[1] ^ 0x64562B5;
							array21[1] = array21[0] ^ -327519389;
							array21[3] = array21[0] ^ 0x24761E1D;
							array21[4] = array21[3] ^ -206478989;
							int num56 = array21[2] ^ -1806101927;
							num2 = ((int)num5 * -1973716276) ^ 0x580A3334 ^ num56;
							continue;
						}
						uint num57 = num4;
						int num58 = -1671429907;
						_ = 0;
						for (int num59 = 0; num59 < 2; num59++)
						{
							num58 = num58 - -611135681 * 1113575098 - -78171347;
							num58 = -(num58 ^ --1589071997);
						}
						if (num57 == (uint)num58)
						{
							return;
						}
						uint num60 = num4;
						int num61 = -1407118320;
						_ = 0;
						for (int num62 = 0; num62 < 2; num62++)
						{
							num61 -= -430486522 ^ 0x33991A0C;
							num61 = -(num61 ^ -675705968);
						}
						if (num60 == (uint)num61)
						{
							goto IL_130d;
						}
						uint num63 = num4;
						int num64 = 2119872853;
						_ = 0;
						for (int num65 = 0; num65 < 1; num65++)
						{
							num64 *= -1692539931;
						}
						if (num63 == (uint)num64)
						{
							_003C_003Eu__1 = default(TaskAwaiter<bool>);
							num = (_003C_003E1__state = -1);
							int[] array22 = new int[6];
							array22[0] = 159138680;
							array22[1] = -1848874706;
							array22[2] = -227305024;
							array22[3] = 1427820515;
							array22[4] = 1521626257;
							array22[5] = -1965075271;
							array22[2] = array22[5] ^ -1899227178;
							array22[4] = array22[1] ^ 0x2915D585;
							array22[4] = array22[3] ^ -400847830;
							int[] array23 = new int[4];
							array23[0] = -1866982698;
							array23[1] = 1279557464;
							array23[2] = -1309703980;
							array23[3] = -1891261051;
							array23[1] = array22[5] ^ -200791524;
							array23[0] = array23[2] ^ 0x485691C7;
							array23[2] = array23[3] ^ -835533775;
							array23[2] ^= -44378273;
							int num66 = array23[1] ^ 0x21129445;
							num2 = (int)((num5 * 1463996986) ^ 0xDE07BF46u) ^ num66;
							continue;
						}
						uint num67 = num4;
						int num68 = -1472167677;
						_ = 0;
						for (int num69 = 0; num69 < 2; num69++)
						{
							num68 = -(num68 ^ -875902604);
							num68 = num68 * -32861039 * 1219555461;
						}
						if (num67 == (uint)num68)
						{
							int num70;
							if (!awaiter.GetResult())
							{
								num2 = 1029828918;
								num70 = num2;
							}
							else
							{
								num2 = 221184889;
								num70 = num2;
							}
							continue;
						}
						uint num71 = num4;
						int num72 = -787372324;
						_ = 0;
						for (int num73 = 0; num73 < 1; num73++)
						{
							num72 *= 1426541589;
						}
						if (num71 != (uint)num72)
						{
							uint num74 = num4;
							int num75 = -1174850027;
							_ = 0;
							for (int num76 = 0; num76 < 1; num76++)
							{
								num75 *= 856468115;
							}
							if (num74 == (uint)num75)
							{
								loginViewModel.IsBusy = true;
								num2 = 1401205517;
								continue;
							}
							uint num77 = num4;
							int num78 = 583717238;
							_ = 0;
							for (int num79 = 0; num79 < 1; num79++)
							{
								num78 ^= 0x22CAD176;
							}
							if (num77 != (uint)num78)
							{
							}
							try
							{
								if (num != 1)
								{
									goto IL_21ec;
								}
								goto IL_2d35;
								IL_21ec:
								int num80 = -445401063;
								goto IL_21f1;
								IL_21f1:
								while (true)
								{
									num3 = num80;
									num4 = (num5 = (uint)(-(~num3 + (1583090351 + -2108844825 * (201391711 * (-92828201 + -1589318123 * -1306210674 - -(-900964712))) - ((-((0x555CA5A4 ^ -460232292) * -766679953) - ~(-1038366856 + 1098909596 - -767542135 * 113760238)) ^ ~(2122974039 - 489121956 - --1944404575 + (-729542386 ^ 0x87FA039)) ^ 0x38F18F72)) * 2084200075) + ((~(-1997797629) - 2009056182 - (((--1713967421 - (365815904 + -59472764)) ^ -332969992) - -660292469 * ((1154129376 - 210984640) * -622182633))) ^ 0x6ACDB49F))) % 20;
									uint num81 = num4;
									int num82 = 13;
									_ = 0;
									for (int num83 = 0; num83 < 2; num83++)
									{
										num82 = -(num82 - (-726570923 - -279593160));
										num82 = num82 - 1895882175 * 1512813267 - -420989998;
									}
									if (num81 == (uint)num82)
									{
										break;
									}
									uint num84 = num4;
									int num85 = 104605493;
									_ = 0;
									for (int num86 = 0; num86 < 1; num86++)
									{
										num85 += -104605474;
									}
									if (num84 == (uint)num85)
									{
										awaiter2 = _0023_002B_005E_0026_005E_0040_002B_005E(loginViewModel._authenticationService, _0023_003E_002D_003F_0024_0029__003F(loginViewModel.LicenseKey), default(CancellationToken)).GetAwaiter();
										int[,] array24 = new int[4, 3];
										array24[0, 0] = 1633285939;
										array24[0, 1] = -382350452;
										array24[0, 2] = 1439975635;
										array24[1, 0] = -173164708;
										array24[1, 1] = -476991797;
										array24[1, 2] = -1846239958;
										array24[2, 0] = -262041091;
										array24[2, 1] = 1366527529;
										array24[2, 2] = 1143062120;
										array24[3, 0] = 472927743;
										array24[3, 1] = -544017786;
										array24[3, 2] = 1596119383;
										array24[0, 0] = array24[2, 1] ^ 0x776F0E57;
										array24[0, 1] = array24[0, 0] ^ -523715756;
										array24[1, 2] = array24[2, 0] ^ -1865436900;
										array24[0, 2] = array24[2, 0] ^ -1451512761;
										int num87 = array24[0, 2] ^ 0x772F9CB9;
										num80 = (int)((num5 * 1185872007) ^ 0x33719C15) ^ num87;
										continue;
									}
									uint num88 = num4;
									int num89 = -33110382;
									_ = 0;
									for (int num90 = 0; num90 < 1; num90++)
									{
										num89 = -33110377 - num89;
									}
									if (num88 == (uint)num89)
									{
										bool ısCompleted2 = awaiter2.IsCompleted;
										int[,] array25 = new int[4, 3];
										array25[0, 0] = 1069252354;
										array25[0, 1] = -1572995105;
										array25[0, 2] = -1845421031;
										array25[1, 0] = -317034912;
										array25[1, 1] = -49380208;
										array25[1, 2] = 1175670282;
										array25[2, 0] = -576776125;
										array25[2, 1] = 74110736;
										array25[2, 2] = 1597169907;
										array25[3, 0] = -1802141343;
										array25[3, 1] = -469435809;
										array25[3, 2] = -2005075709;
										array25[2, 0] = array25[1, 0] ^ -923164716;
										array25[0, 2] = array25[0, 1] ^ -1616546616;
										array25[3, 0] = array25[3, 1] ^ -155490175;
										int num91 = array25[3, 0] ^ -361519724;
										int[,] array26 = new int[4, 3];
										array26[0, 0] = 1633677191;
										array26[0, 1] = 1079770131;
										array26[0, 2] = -549423488;
										array26[1, 0] = -2140236509;
										array26[1, 1] = -2078992760;
										array26[1, 2] = 1332389544;
										array26[2, 0] = 1316144391;
										array26[2, 1] = 827254233;
										array26[2, 2] = 80477152;
										array26[3, 0] = -1872834856;
										array26[3, 1] = 1108951935;
										array26[3, 2] = -160153478;
										array26[2, 1] = array26[3, 2] ^ 0x3D7B9B8A;
										array26[0, 0] = array26[3, 1] ^ -663755267;
										array26[1, 0] = array26[0, 2] ^ 0x792E89D0;
										int num92 = array26[1, 0] ^ -2015387660;
										int num93 = ((int)num5 * -22494860) ^ 0x51844664;
										num91 ^= num93;
										num92 ^= num93;
										int num94;
										int num95;
										if (!ısCompleted2)
										{
											num94 = num92;
											num95 = num94;
										}
										else
										{
											num94 = num91;
											num95 = num94;
										}
										num80 = num94 ^ num93;
										continue;
									}
									uint num96 = num4;
									int num97 = -3;
									_ = 0;
									for (int num98 = 0; num98 < 1; num98++)
									{
										num97 = ~num97;
									}
									if (num96 == (uint)num97)
									{
										num = (_003C_003E1__state = 1);
										int[,] array27 = new int[3, 3];
										array27[0, 0] = -1018880703;
										array27[0, 1] = -1546020519;
										array27[0, 2] = -1650385036;
										array27[1, 0] = 386766983;
										array27[1, 1] = 1194709559;
										array27[1, 2] = 1593022808;
										array27[2, 0] = -64380296;
										array27[2, 1] = 1459547018;
										array27[2, 2] = -162275527;
										array27[2, 1] = array27[0, 0] ^ -1847541003;
										array27[0, 0] ^= 59265424;
										array27[1, 1] = array27[2, 0] ^ 0x5A2360F9;
										array27[0, 1] = array27[2, 2] ^ -1257670471;
										int num99 = array27[0, 1] ^ 0x739DD537;
										num80 = (int)((num5 * 960114906) ^ 0xA89D5FECu) ^ num99;
										continue;
									}
									uint num100 = num4;
									int num101 = 1476935681;
									_ = 0;
									for (int num102 = 0; num102 < 2; num102++)
									{
										num101 = -(num101 - -506220576 * -128381291);
										num101 = -(num101 ^ -738486616);
									}
									if (num100 == (uint)num101)
									{
										_003C_003Eu__2 = awaiter2;
										int[] array28 = new int[4];
										array28[0] = -1436299182;
										array28[1] = -1414497171;
										array28[2] = 1321421442;
										array28[3] = -393517672;
										array28[3] = array28[2] ^ -671886807;
										array28[3] ^= -1672097294;
										array28[3] = array28[1] ^ -195093109;
										int[] array29 = new int[7] { -631511290, -1110402723, 2117441304, -118238025, 1951656408, -1953957031, 1937576530 };
										int[][] array30 = new int[2][] { array28, array29 };
										array29[1] = array30[0][1] ^ 0xC42B1CF;
										array29[4] = array29[0] ^ 0x17768B8F;
										array29[6] = array29[5] ^ -1710564227;
										array29[2] ^= -1937892105;
										int num103 = array30[1][1] ^ 0x4E5B5380;
										num80 = ((int)num5 * -1072348785) ^ -1336008849 ^ num103;
										continue;
									}
									uint num104 = num4;
									int num105 = 0;
									_ = 0;
									for (int num106 = 0; num106 < 1; num106++)
									{
										num105 *= 1024929107;
									}
									if (num104 == (uint)num105)
									{
										_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter2, ref this);
										int[] array31 = new int[7];
										array31[0] = 506039404;
										array31[1] = 13115219;
										array31[2] = -816744261;
										array31[3] = -1359837010;
										array31[4] = -1722341715;
										array31[5] = -440303566;
										array31[6] = -14154555;
										array31[2] = array31[5] ^ 0x4CB6B2CB;
										array31[0] = array31[3] ^ 0x12ED9B7;
										int[] array32 = new int[5];
										array32[0] = -674533131;
										array32[1] = 597083034;
										array32[2] = 318590061;
										array32[3] = -427043490;
										array32[4] = -257974424;
										array32[4] = array31[5] ^ 0x5C975088;
										array32[2] = array32[3] ^ -1023557351;
										array32[1] = array32[3] ^ 0x3329B035;
										array32[3] = array32[2] ^ 0x57EB8F6F;
										int num107 = array32[4] ^ 0x5DD3B056;
										num80 = (int)((num5 * 1384199770) ^ 0x3606DF38) ^ num107;
										continue;
									}
									uint num108 = num4;
									int num109 = 1191990422;
									_ = 0;
									for (int num110 = 0; num110 < 2; num110++)
									{
										num109 = (num109 * 295348201) ^ 0x40C29EFE;
										num109 = -num109 + 1418256986;
									}
									if (num108 == (uint)num109)
									{
										return;
									}
									uint num111 = num4;
									int num112 = 2103480586;
									_ = 0;
									for (int num113 = 0; num113 < 1; num113++)
									{
										num112 = 2103480590 - num112;
									}
									if (num111 == (uint)num112)
									{
										goto IL_2d35;
									}
									uint num114 = num4;
									int num115 = -1029473632;
									_ = 0;
									for (int num116 = 0; num116 < 1; num116++)
									{
										num115 ^= -1029473621;
									}
									if (num114 == (uint)num115)
									{
										_003C_003Eu__2 = default(TaskAwaiter<AuthResult>);
										num = (_003C_003E1__state = -1);
										int[,] array33 = new int[4, 4];
										array33[0, 0] = 796163313;
										array33[0, 1] = -1505751430;
										array33[0, 2] = -1976558054;
										array33[0, 3] = 1431854990;
										array33[1, 0] = -2027624899;
										array33[1, 1] = -1575005234;
										array33[1, 2] = 908939706;
										array33[1, 3] = 608422158;
										array33[2, 0] = 619784744;
										array33[2, 1] = 665185750;
										array33[2, 2] = -1569376414;
										array33[2, 3] = 1536620861;
										array33[3, 0] = -818738829;
										array33[3, 1] = -611938548;
										array33[3, 2] = 1528227276;
										array33[3, 3] = -1972276556;
										array33[2, 0] = array33[2, 1] ^ 0x2A064D9;
										array33[0, 2] = array33[0, 0] ^ -2132046492;
										array33[1, 0] = array33[0, 3] ^ -1944794694;
										array33[2, 3] = array33[3, 3] ^ 0x1ADF51A8;
										int num117 = array33[2, 3] ^ 0x68621456;
										num80 = ((int)num5 * -1976775874) ^ 0x759F1B8A ^ num117;
										continue;
									}
									uint num118 = num4;
									int num119 = -13;
									_ = 0;
									for (int num120 = 0; num120 < 1; num120++)
									{
										num119 = ~num119;
									}
									if (num118 == (uint)num119)
									{
										result = awaiter2.GetResult();
										num80 = 1569500793;
										continue;
									}
									uint num121 = num4;
									int num122 = 2095055263;
									_ = 0;
									for (int num123 = 0; num123 < 2; num123++)
									{
										num122 = (num122 ^ --1808798190) - -72165658;
										num122 = 1031941678 - (num122 - (0x7656F3F1 ^ 0x7E0F27D2));
									}
									if (num121 == (uint)num122)
									{
										bool num124 = _0028_0024____002D_0024_002F(result);
										int[,] array34 = new int[4, 3];
										array34[0, 0] = -1182841396;
										array34[0, 1] = 517637329;
										array34[0, 2] = 2056423970;
										array34[1, 0] = -2041596649;
										array34[1, 1] = 717892087;
										array34[1, 2] = -2014402522;
										array34[2, 0] = 501490474;
										array34[2, 1] = 907398511;
										array34[2, 2] = -1743089367;
										array34[3, 0] = -936011798;
										array34[3, 1] = 1020547824;
										array34[3, 2] = 552054288;
										array34[3, 2] = array34[2, 2] ^ 0x51060CBB;
										array34[0, 2] = array34[3, 1] ^ -2036800326;
										array34[0, 1] = array34[3, 0] ^ -1541515447;
										int num125 = array34[0, 1] ^ 0x24A3E7D3;
										int[] array35 = new int[6];
										array35[0] = 1837949547;
										array35[1] = 2058863757;
										array35[2] = 1743471664;
										array35[3] = 278344605;
										array35[4] = -1408402968;
										array35[5] = 1818616213;
										array35[3] = array35[5] ^ 0x2F558FB5;
										array35[1] ^= -890096508;
										array35[1] = array35[4] ^ -1106162737;
										int[] array36 = new int[4] { -2061227136, 1958796719, 290328458, 1594368457 };
										int[][] array37 = new int[2][] { array35, array36 };
										array36[1] = array37[0][2] ^ 0x2A37A3CC;
										array36[3] ^= 2085456349;
										array36[2] = array36[1] ^ -757830020;
										array36[2] = array36[3] ^ -2105381975;
										int num126 = array37[1][1] ^ -1289966899;
										int num127 = (int)(num5 * 1976201502) ^ -209481830;
										num125 ^= num127;
										num126 ^= num127;
										int num128;
										int num129;
										if (!num124)
										{
											num128 = num126;
											num129 = num128;
										}
										else
										{
											num128 = num125;
											num129 = num128;
										}
										num80 = num128 ^ num127;
										continue;
									}
									uint num130 = num4;
									int num131 = 3;
									_ = 0;
									for (int num132 = 0; num132 < 2; num132++)
									{
										num131 = ~-111785238 - num131;
										num131 = ~(~num131);
									}
									if (num130 == (uint)num131)
									{
										text = _005E_0021__002D__002F_0026_002F(result) ?? _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xB7F ^ 0xA1B];
										num80 = 245373276;
										continue;
									}
									uint num133 = num4;
									int num134 = -19;
									_ = 0;
									for (int num135 = 0; num135 < 1; num135++)
									{
										num134 = ~num134;
									}
									if (num133 == (uint)num134)
									{
										loginViewModel.SetStatus(text, SeverityLevel.Error);
										int[] array38 = new int[7];
										array38[0] = 769344105;
										array38[1] = 1874014535;
										array38[2] = 1043441518;
										array38[3] = -1679693632;
										array38[4] = -229260598;
										array38[5] = 306483631;
										array38[6] = 1221412136;
										array38[1] = array38[2] ^ -473736380;
										array38[6] = array38[5] ^ 0x6F5887AB;
										array38[3] = array38[2] ^ -732570625;
										int[] array39 = new int[5] { -1164410045, -668419842, -117325754, -1275182823, -1470515280 };
										int[][] array40 = new int[2][] { array38, array39 };
										array39[1] = array40[0][0] ^ -1693767557;
										array39[0] ^= -1964542518;
										array39[0] ^= -2011462549;
										int num136 = array40[1][1] ^ 0x43803074;
										num80 = (int)((num5 * 1604467581) ^ 0x34F754AE) ^ num136;
										continue;
									}
									uint num137 = num4;
									int num138 = 1268334280;
									_ = 0;
									for (int num139 = 0; num139 < 2; num139++)
									{
										num138 = ~(num138 - 1525407756);
										num138 = (--1441026307 - num138) * -859138473;
									}
									if (num137 == (uint)num138)
									{
										loginViewModel.AppViewModel.AddActivity(_002B_002D_003F_003F_005E_0023_003E_003C(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x2410 ^ 0x2575))], text), SeverityLevel.Error);
										int[,] array41 = new int[4, 4];
										array41[0, 0] = 1082069605;
										array41[0, 1] = 1979369513;
										array41[0, 2] = 2076482616;
										array41[0, 3] = 1117394500;
										array41[1, 0] = 84413877;
										array41[1, 1] = 494684324;
										array41[1, 2] = -1739699894;
										array41[1, 3] = -1663658716;
										array41[2, 0] = 430236043;
										array41[2, 1] = -1087785332;
										array41[2, 2] = 234769405;
										array41[2, 3] = 1418959736;
										array41[3, 0] = -921781546;
										array41[3, 1] = -1294161751;
										array41[3, 2] = 822206336;
										array41[3, 3] = 1194896310;
										array41[3, 0] = array41[1, 3] ^ 0x67E7264;
										array41[2, 2] = array41[3, 2] ^ -661391725;
										array41[0, 1] = array41[3, 1] ^ -889429630;
										array41[0, 2] = array41[3, 3] ^ -1374652395;
										int num140 = array41[0, 2] ^ -1461839980;
										num80 = (int)((num5 * 1400726232) ^ 0x1A061780) ^ num140;
										continue;
									}
									uint num141 = num4;
									int num142 = 9;
									_ = 0;
									for (int num143 = 0; num143 < 2; num143++)
									{
										num142 = ~(num142 - -1190268548);
										num142 = num142 - (-938572280 ^ -1923075158) - -1285407849;
									}
									if (num141 != (uint)num142)
									{
										uint num144 = num4;
										int num145 = 673610879;
										_ = 0;
										for (int num146 = 0; num146 < 1; num146++)
										{
											num145 += -673610873;
										}
										if (num144 == (uint)num145)
										{
											text2 = _005E_0021__002D__002F_0026_002F(result) ?? _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[2276 - 2016 + 98];
											num80 = -7038175;
											continue;
										}
										uint num147 = num4;
										int num148 = -1851374283;
										_ = 0;
										for (int num149 = 0; num149 < 1; num149++)
										{
											num148 -= -1851374290;
										}
										if (num147 == (uint)num148)
										{
											loginViewModel.SetStatus(text2, SeverityLevel.Success);
											int[] array42 = new int[5] { -13007563, -2023956605, 274530870, 328894459, 1778800496 };
											array42[1] ^= 1966019570;
											array42[0] = array42[1] ^ 0x2A988D7E;
											array42[1] = array42[0] ^ -1185727488;
											int[] array43 = new int[6] { -618795403, 1580347765, -711068225, 303456608, 1242285578, 1287704224 };
											int[][] array44 = new int[2][] { array42, array43 };
											array43[3] = array44[0][2] ^ 0x1802EED8;
											array43[2] = array43[4] ^ 0x6BFC812F;
											array43[0] = array43[1] ^ 0xB038639;
											array43[1] = array43[2] ^ -528386545;
											int num150 = array44[1][3] ^ -229364659;
											num80 = ((int)num5 * -1826797137) ^ -23034363 ^ num150;
											continue;
										}
										uint num151 = num4;
										int num152 = 1740522792;
										_ = 0;
										for (int num153 = 0; num153 < 1; num153++)
										{
											num152 = 1740522809 - num152;
										}
										if (num151 == (uint)num152)
										{
											message = _003C_003D_0029_0026_0024_0024_002F_0025(text2, '\n', StringSplitOptions.None)[0];
											int[] array45 = new int[5];
											array45[0] = -1938772215;
											array45[1] = -907895538;
											array45[2] = 2015686548;
											array45[3] = -581945347;
											array45[4] = -98921231;
											array45[0] = array45[4] ^ -806355239;
											array45[4] = array45[0] ^ 0x4660A738;
											array45[1] ^= 702205155;
											int[] array46 = new int[5] { 1497328586, -943685242, 497971157, -2131530714, -517956861 };
											int[][] array47 = new int[2][] { array45, array46 };
											array46[2] = array47[0][3] ^ 0x3A84E4BF;
											array46[0] = array46[4] ^ -422459232;
											array46[1] = array46[4] ^ 0x5B7E45D2;
											int num154 = array47[1][2] ^ -1269868614;
											num80 = (int)((num5 * 1971677687) ^ 0xC3186F8Bu) ^ num154;
											continue;
										}
										uint num155 = num4;
										int num156 = -243273722;
										_ = 0;
										for (int num157 = 0; num157 < 2; num157++)
										{
											num156 = num156 + (-752492784 ^ 0x47948DE3) - -1274839479;
											num156 = (num156 ^ -2137788187) - -646001427;
										}
										if (num155 == (uint)num156)
										{
											loginViewModel.AppViewModel.AddActivity(message, SeverityLevel.Success);
											int[] array48 = new int[7] { -835839426, 1993757075, -1386033636, -1665026883, -232533570, -1486784846, -1967303790 };
											array48[4] ^= -1721176105;
											array48[6] = array48[5] ^ 0x46024122;
											array48[6] = array48[5] ^ -80565044;
											int[] array49 = new int[6] { -1417575531, -1974654793, 1282054252, 1434850360, 1458014481, -1609786190 };
											int[][] array50 = new int[2][] { array48, array49 };
											array49[3] = array50[0][5] ^ 0x7E5012B6;
											array49[2] = array49[1] ^ -1298399607;
											array49[4] = array49[2] ^ 0x5619CD13;
											array49[5] ^= -1860395680;
											int num158 = array50[1][3] ^ -175915070;
											num80 = ((int)num5 * -591761827) ^ 0x65408D9A ^ num158;
											continue;
										}
										uint num159 = num4;
										int num160 = 32279076;
										_ = 0;
										for (int num161 = 0; num161 < 2; num161++)
										{
											num160 = ~(num160 - --817164528);
											num160 = (-1534303135 - -191487496 - num160) * -840339355;
										}
										if (num159 == (uint)num160)
										{
										}
									}
									goto end_IL_21de;
								}
								goto IL_21ec;
								IL_2d35:
								awaiter2 = _003C_003Eu__2;
								num80 = 1130514609;
								goto IL_21f1;
								end_IL_21de:;
							}
							finally
							{
								if (num < 0)
								{
									while (true)
									{
										int num162 = 1374664895;
										while (true)
										{
											num3 = num162;
											num4 = (num5 = (uint)(-(~num3 + (1583090351 + -2108844825 * (201391711 * (-92828201 + -1589318123 * -1306210674 - -(-900964712))) - ((-((0x555CA5A4 ^ -460232292) * -766679953) - ~(-1038366856 + 1098909596 - -767542135 * 113760238)) ^ ~(2122974039 - 489121956 - --1944404575 + (-729542386 ^ 0x87FA039)) ^ 0x38F18F72)) * 2084200075) + ((~(-1997797629) - 2009056182 - (((--1713967421 - (365815904 + -59472764)) ^ -332969992) - -660292469 * ((1154129376 - 210984640) * -622182633))) ^ 0x6ACDB49F))) % 3;
											uint num163 = num4;
											int num164 = -864326029;
											_ = 0;
											for (int num165 = 0; num165 < 1; num165++)
											{
												num164 ^= -864326029;
											}
											if (num163 == (uint)num164)
											{
												break;
											}
											uint num166 = num4;
											int num167 = -20135427;
											_ = 0;
											for (int num168 = 0; num168 < 1; num168++)
											{
												num167 += 20135428;
											}
											if (num166 != (uint)num167)
											{
												uint num169 = num4;
												int num170 = 2087592870;
												_ = 0;
												for (int num171 = 0; num171 < 1; num171++)
												{
													num170 *= 1705799259;
												}
												if (num169 == (uint)num170)
												{
												}
												goto end_IL_4c67;
											}
											loginViewModel.IsBusy = false;
											int[,] array51 = new int[3, 3];
											array51[0, 0] = 183289192;
											array51[0, 1] = 2106091865;
											array51[0, 2] = -1752197287;
											array51[1, 0] = 836760479;
											array51[1, 1] = -1813932062;
											array51[1, 2] = 1313518929;
											array51[2, 0] = 892496338;
											array51[2, 1] = 2074553524;
											array51[2, 2] = 1693702999;
											array51[2, 1] = array51[2, 2] ^ 0x67B63EB;
											array51[0, 0] = array51[2, 2] ^ -961988942;
											array51[2, 1] = array51[0, 1] ^ 0x4E51B9D0;
											array51[2, 0] = array51[1, 0] ^ 0x475C734E;
											int num172 = array51[2, 0] ^ 0x630A59CA;
											num162 = (int)((num5 * 1454003947) ^ 0xB06609A3u) ^ num172;
										}
										continue;
										end_IL_4c67:
										break;
									}
								}
							}
						}
					}
					goto end_IL_001a;
				}
				goto IL_0023;
				IL_130d:
				awaiter = _003C_003Eu__1;
				num2 = 1503243861;
				goto IL_0028;
				end_IL_001a:;
			}
			catch (Exception exception)
			{
				while (true)
				{
					int num173 = -183098131;
					while (true)
					{
						int num3 = num173;
						uint num5;
						uint num4 = (num5 = (uint)(-(~num3 + (1583090351 + -2108844825 * (201391711 * (-92828201 + -1589318123 * -1306210674 - -(-900964712))) - ((-((0x555CA5A4 ^ -460232292) * -766679953) - ~(-1038366856 + 1098909596 - -767542135 * 113760238)) ^ ~(2122974039 - 489121956 - --1944404575 + (-729542386 ^ 0x87FA039)) ^ 0x38F18F72)) * 2084200075) + ((~(-1997797629) - 2009056182 - (((--1713967421 - (365815904 + -59472764)) ^ -332969992) - -660292469 * ((1154129376 - 210984640) * -622182633))) ^ 0x6ACDB49F))) % 3;
						uint num174 = num4;
						int num175 = 314407914;
						_ = 0;
						for (int num176 = 0; num176 < 2; num176++)
						{
							num175 = (num175 ^ --887662334) * -2140153845;
							num175 = num175 - --1046345771 - -2075474540;
						}
						if (num174 == (uint)num175)
						{
							break;
						}
						uint num177 = num4;
						int num178 = 1996772497;
						_ = 0;
						for (int num179 = 0; num179 < 2; num179++)
						{
							num178 = -num178;
							num178 = -(num178 * -1211974375);
						}
						if (num177 != (uint)num178)
						{
							uint num180 = num4;
							int num181 = 481667092;
							_ = 0;
							for (int num182 = 0; num182 < 1; num182++)
							{
								num181 += -481667092;
							}
							if (num180 == (uint)num181)
							{
							}
							return;
						}
						_003C_003E1__state = -2;
						_003C_003Et__builder.SetException(exception);
						int[] array52 = new int[7];
						array52[0] = 1377138927;
						array52[1] = -45643411;
						array52[2] = 289738781;
						array52[3] = -91900867;
						array52[4] = 2022238576;
						array52[5] = -1421691934;
						array52[6] = 1935906958;
						array52[3] = array52[4] ^ 0x6781F37F;
						array52[4] ^= 600452557;
						array52[5] ^= -1101772337;
						int[] array53 = new int[7] { 888921088, -1916292599, -1698891560, -1946568694, -1974045424, 579333501, -673665426 };
						int[][] array54 = new int[2][] { array52, array53 };
						array53[6] = array54[0][2] ^ 0x11B8D9AE;
						array53[2] = array53[1] ^ -1127821025;
						array53[3] = array53[2] ^ -2085137306;
						int num183 = array54[1][6] ^ 0x4C8EBAC5;
						num173 = (int)((num5 * 1095942812) ^ 0xA7A2CB04u) ^ num183;
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num184 = -47954530;
				while (true)
				{
					int num3 = num184;
					uint num5;
					uint num4 = (num5 = (uint)(-(~num3 + (1583090351 + -2108844825 * (201391711 * (-92828201 + -1589318123 * -1306210674 - -(-900964712))) - ((-((0x555CA5A4 ^ -460232292) * -766679953) - ~(-1038366856 + 1098909596 - -767542135 * 113760238)) ^ ~(2122974039 - 489121956 - --1944404575 + (-729542386 ^ 0x87FA039)) ^ 0x38F18F72)) * 2084200075) + ((~(-1997797629) - 2009056182 - (((--1713967421 - (365815904 + -59472764)) ^ -332969992) - -660292469 * ((1154129376 - 210984640) * -622182633))) ^ 0x6ACDB49F))) % 3;
					uint num185 = num4;
					int num186 = -2;
					_ = 0;
					for (int num187 = 0; num187 < 1; num187++)
					{
						num186 = -num186;
					}
					if (num185 == (uint)num186)
					{
						break;
					}
					uint num188 = num4;
					int num189 = -1118858590;
					_ = 0;
					for (int num190 = 0; num190 < 1; num190++)
					{
						num189 -= -1118858591;
					}
					if (num188 != (uint)num189)
					{
						uint num191 = num4;
						int num192 = -1974628337;
						_ = 0;
						for (int num193 = 0; num193 < 1; num193++)
						{
							num192 -= -1974628337;
						}
						if (num191 == (uint)num192)
						{
						}
						return;
					}
					_003C_003Et__builder.SetResult();
					int[] array55 = new int[4];
					array55[0] = -1041623315;
					array55[1] = -705809224;
					array55[2] = -1097696706;
					array55[3] = -798008355;
					array55[0] = array55[3] ^ 0x240464FA;
					array55[0] = array55[1] ^ -547175485;
					array55[0] = array55[3] ^ -645100415;
					int[] array56 = new int[7] { 29946331, -1668304790, 497216616, 1509306445, 819774026, 1861797692, -670269615 };
					int[][] array57 = new int[2][] { array55, array56 };
					array56[0] = array57[0][3] ^ 0x5BAFDDE2;
					array56[4] = array56[2] ^ -1274291984;
					array56[2] = array56[1] ^ 0x4365403E;
					array56[3] = array56[1] ^ 0x7C48E7EA;
					int num194 = array57[1][0] ^ -624443199;
					num184 = ((int)num5 * -359563423) ^ -118554104 ^ num194;
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

		static bool _0025_0025__002B_002F_002F_005E_003F(string P_0)
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
					int num = 198641315;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((((((num2 ^ (-(-(~-799332352) ^ (~358307311 + --1025993614 - (-1195478066 ^ 0x62EE1E8E) - 151145429 * (255423129 * (-380171574 ^ -202128660))) ^ (-1610986587 ^ (-(-(-1410143347 ^ -1346807392)) - ((0x28864600 ^ -1669478119) - (~-547080054 - -1580244337 * -30256015))))) - (1086707134 + -(~621578503 * -1532525413) + ~-1615592177 + ((0x22CD291C ^ -79845283) - 1995786157) + -(-(~-1046546315))) - (-(-173069751 * (~(~(--1030893286)) - (-(457641514 * 1396575407) ^ 0x2923769F) - -1291132535 * -(-939765111 ^ 0x62CDC7D8))) - ~((-233606868 ^ (-(1298849173 * ~1350060092) + --450179894)) - (~(--2120183895) + -67563823 - ~(0x4DABAE82 ^ -1046193203)))))) * 167706487 - (-(-(~1607687338 + (945296312 - -1601816265) - (-967289525 ^ 0x2ECF00AF) * 1315966925) - 1543875438) - ((-(-(-362357785 * -680804621) + 627066469 * (-523241763 * 1308171400)) ^ ((0x625A0514 ^ 0x6BE4D865) - (-(--1946494252) - (--1449039677 + --447629152)))) + (~(290280 * -773423569) + (433238394 * 1701978263 + -349186965 * 1758841029 - (-383307752 + -1313710799 - --414589851) + (-1637407839 * -755996667 + (-1344404770 ^ 0x25EE4802) + ((0x5B9D37CE ^ 0x76A94C5B) - (1103529498 + 1522103303)))))))) * 574804537) ^ ((-1743550471 ^ -(570929159 + -1548140549 - --6765313)) - ~426265254)) + -(-(~(--1561989109)))) ^ 0x5B8A7B46)) % 3;
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
						int num7 = -2;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 = ~num7;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -532525760;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -(num9 * 1736438389);
								num9 -= 876488367 * 45424144;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = string.IsNullOrWhiteSpace(P_0);
						int[] array = new int[4] { 1245489612, 1960022864, -656274152, -427674953 };
						array[3] ^= 83845217;
						array[1] = array[0] ^ -276520500;
						array[3] = array[1] ^ 0x74CE10F8;
						int[] array2 = new int[5] { 143921859, -738860225, -56542406, -776207975, 1073590979 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[2] = array3[0][0] ^ -381099642;
						array2[1] = array2[3] ^ -1171852993;
						array2[4] = array2[0] ^ -153016679;
						array2[0] = array2[1] ^ 0x1567F9BE;
						int num11 = array3[1][2] ^ -857841906;
						num = (int)((num4 * 1718443100) ^ 0xBBDB04ECu) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static string _0026__0025_005E_0023_0029_002A_0029(IStringResourceService P_0, string P_1)
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
					int num = 701169532;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-num2 - -(-(~1063553305)) - (0x2311808F ^ 0x13828F1D) - 1578434274 - 1706653655)) % 3;
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
						int num7 = 1;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = num7 ^ -993657587 ^ 0x65AB8987;
							num7 = -num7;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1077071191;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 -= 1077071189;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.GetString(P_1);
						int[] array = new int[6];
						array[0] = 1387421446;
						array[1] = 1741201672;
						array[2] = 105771970;
						array[3] = -856517815;
						array[4] = 2083836315;
						array[5] = -711859207;
						array[0] = array[4] ^ -124040257;
						array[5] = array[2] ^ 0x5E6FFA91;
						array[0] = array[5] ^ 0x48A4BB13;
						int[] array2 = new int[7];
						array2[0] = 2005558934;
						array2[1] = 1338143234;
						array2[2] = 522988616;
						array2[3] = 772028597;
						array2[4] = -1539417995;
						array2[5] = 724520871;
						array2[6] = -784453752;
						array2[6] = array[3] ^ 0x268033BF;
						array2[2] = array2[3] ^ 0x10FB2727;
						array2[1] = array2[5] ^ 0x2E393664;
						array2[3] ^= 511725576;
						int num11 = array2[6] ^ 0x269AA164;
						num = ((int)num4 * -676626774) ^ -1908011234 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static string _0023_003E_002D_003F_0024_0029__003F(string P_0)
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
					int num = 336723968;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(-num2 + ((-750686977 + (-(((0x295D967 ^ -1047787310) + -1735260982) * 1214415665) + (1446734893 - -(--257187261 + (1007667789 + 1442743565))) + -(~(-1929243027 * (-477548964 ^ 0x55487B43)) * -742735057))) ^ -1329999274)) ^ 0x5A0B9B43)) % 3;
						int num5 = 401110850;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 += -401110850;
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
							int num9 = -1540688807;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -num9;
								num9 = (num9 ^ 0x23FF9E0F) * -1348138537;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.Trim();
						int[] array = new int[4];
						array[0] = 1988252272;
						array[1] = -223482923;
						array[2] = -1710261947;
						array[3] = -1845155249;
						array[1] = array[2] ^ -222427713;
						array[3] = array[1] ^ 0xE42C026;
						int[] array2 = new int[6];
						array2[0] = -1132552312;
						array2[1] = -536264742;
						array2[2] = -630825527;
						array2[3] = -1877433733;
						array2[4] = -846284658;
						array2[5] = -358484960;
						array2[4] = array[0] ^ 0x5FC3A611;
						array2[2] = array2[1] ^ -1052837142;
						array2[2] = array2[1] ^ -1287643520;
						array2[2] = array2[4] ^ 0x53D10FE3;
						int num11 = array2[4] ^ 0xEBFB92F;
						num = ((int)num4 * -1262739468) ^ 0x45207314 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static Task<AuthResult> _0023_002B_005E_0026_005E_0040_002B_005E(IAuthenticationService P_0, string P_1, CancellationToken P_2)
		{
			Task<AuthResult> result = default(Task<AuthResult>);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1763486120;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(-(-(~(num2 + -(~(-1425011973 ^ (-(~((894117671 * -217441475 - -341873637) * 1170526471)) - 1781552127 * (-(1929065656 - -2131389671) - (2078084721 - (794407629 - -303693355)) + -((0xE0F17FB ^ -129944770) - -388770490))))))))))) % 3;
						int num5 = 1823940500;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 ^= 0x6CB71F94;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 272696407;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 ^= 0x10410456;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -533709950;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~(-num9);
								num9 = (num9 ^ -514686543) + 782623282;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.ResetHardwareIdAsync(P_1, P_2);
						int[] array = new int[6];
						array[0] = -2008679469;
						array[1] = 515920393;
						array[2] = -2037841387;
						array[3] = -1006873683;
						array[4] = 645940034;
						array[5] = 2123544952;
						array[5] = array[1] ^ 0x4AF4135C;
						array[1] = array[2] ^ 0x69CED4E3;
						int[] array2 = new int[6] { 714787705, -935053383, 1369681186, -27401624, 1633607762, 724950897 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[0] = array3[0][0] ^ 0x49D58B;
						array2[3] = array2[1] ^ 0x7423FFB0;
						array2[1] = array2[4] ^ 0x748D0AA9;
						int num11 = array3[1][0] ^ 0x19608689;
						num = ((int)num4 * -1318083035) ^ 0x45AD6D67 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static bool _0028_0024____002D_0024_002F(AuthResult P_0)
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
					int num = 1261671399;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(-(-(~(~(num2 ^ (((0x1DAEC5F1 ^ ((-1378699276 + (-(-979807863 + 219987208) ^ -392770575 ^ -1950305099)) * -1920431479)) + ((1296348517 * 1039332451 + (0x6E096A8 ^ -489517585) + (0x5F3D2064 ^ -899487614) - -656122528 - 1487007229 * ~(-779424822 ^ -2018289201) * -1707267871 - (-(-870692666 ^ -(1200825669 + 2029533769)) - -76426399)) ^ (-979354584 - (1760243569 + (-281390920 - 690349660 + -26083210 + ((0x3C9BD38B ^ -1964848292) - 477780308))) - -((-1154695227 + 1745583871 + 2124344447 + ~(1719852742 - -2076402368)) * 161302445)))) ^ -((0x2F34AE4A ^ 0x77BBCCE9) - (-1371967623 + 135147681 + (-318919996 ^ -781086245)) - ((-1757890712 ^ -505334705) + (-1065680288 ^ -1605778492)) - (-476602617 ^ 0x634AC0B6) - -1560542166 - (~(~(~(-1917979679 + -1973144072 + (0x21A97896 ^ -1060264040)))) - (-(1855174801 * (-1905052151 ^ --1805449305)) ^ ((280115072 + -75896824 + --1544093052 + -(~1696692051)) ^ -1388038335))))) ^ (-((-(-(~-1855978831 * -1882918977)) + 1948721 * (~(~-2028469733) * 1716047129)) * 1193497217) ^ -1686096751)))))) ^ -1885051409)) % 3;
						int num5 = -2087520789;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 -= -2087520789;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -1754881970;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = (num7 - (-1318813363 ^ 0x467217A4)) * -883299219;
							num7 = (-1163963976 + 1491034552 - num7) ^ -1648914064;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1902605785;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = (1678586948 + 2101206313 - num9) * -1889734547;
								num9 = num9 * 196136953 + 2091220459;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						ısSuccess = P_0.IsSuccess;
						int[,] array = new int[4, 3];
						array[0, 0] = -1260803691;
						array[0, 1] = -458878274;
						array[0, 2] = 1825875227;
						array[1, 0] = -2077723659;
						array[1, 1] = -1557634085;
						array[1, 2] = 424436175;
						array[2, 0] = -812956156;
						array[2, 1] = -1944890258;
						array[2, 2] = -1125412816;
						array[3, 0] = -1963581227;
						array[3, 1] = 347249004;
						array[3, 2] = 1505635817;
						array[2, 0] = array[3, 2] ^ 0xEDC7C66;
						array[0, 0] = array[1, 0] ^ -447398941;
						array[0, 2] = array[1, 2] ^ 0x65B24DB8;
						int num11 = array[0, 2] ^ 0x5266D7DD;
						num = (int)((num4 * 1971093968) ^ 0x383ED1D0) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return ısSuccess;
		}

		static string _005E_0021__002D__002F_0026_002F(AuthResult P_0)
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
					int num = 1927876551;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(-num2 - (-1127697057 * (-(1568874637 * -395569746 + (-1414242935 - -(1252535531 * -1861929083))) ^ 0x781E1DBA) - (0x6F6986BE ^ (-(-(-688993164 + -1017935328) * -984711929 + (~-367528744 * 1782897455 + (695752919 - 164659053 + -1653464500))) - -511999275 * ((-(--1559387219) - ~-454575766) ^ 0xE36760B))))) ^ (-(-525503164 ^ 0x76532B66) * 158541203))) % 3;
						int num5 = 1205853740;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -1384340217 - (num5 - (-48739677 + -949315802));
							num5 = ~num5 * -203153853;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -1334929603;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 ^= -1334929604;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1678309230;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 *= -541044217;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						errorMessage = P_0.ErrorMessage;
						int[] array = new int[4];
						array[0] = -1946548306;
						array[1] = -1480059510;
						array[2] = 282484712;
						array[3] = 1607703944;
						array[0] = array[2] ^ -2054272532;
						array[2] = array[3] ^ -508398853;
						int[] array2 = new int[6] { 915778236, 1802823531, -563802102, 108609277, 1907286995, 1326157855 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[0] = array3[0][1] ^ 0x60E99690;
						array2[4] = array2[0] ^ 0x7F0D76B9;
						array2[4] = array2[3] ^ -2053407145;
						int num11 = array3[1][0] ^ -577687800;
						num = ((int)num4 * -1203595600) ^ -942605584 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return errorMessage;
		}

		static string _002B_002D_003F_003F_005E_0023_003E_003C(string P_0, string P_1)
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
					int num = 877034736;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-((-(-(num2 + ~(-((-1847035274 + --413031161 + -662220969 + ~((-210913308 + -103526245) * -472340107)) * 830803249 * -2109694769 + -(-((1341169581 + 1503067398) * -1000461041 - ~(0x7BFF6DFD ^ 0x6CA403))) * 2012012769)) - ~(1954882301 * (882892425 * (((-462136015 - -(224681276 + -518288103)) ^ ((0x22AF8374 ^ --1018731762) - ~(~-353542472))) - ((~1080039204 - 161398180) * -1170733541 - ~((-757135207 ^ 0x56E1B931) - (-1777954427 + 879674924)))))) - (-109619532 ^ (-221986397 * ~(-(-1279187799 ^ -550456541)) * -1761019783)))) - 1619483237 * (662675955 * -288391535 - (0x68162FDC ^ -1590498965)) * 1157734657) * -534049447 * 1143654305 - (-1620367846 + 1031430795)))) % 3;
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
						int num7 = 1240286912;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 += -1240286910;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1;
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
						result = P_0 + P_1;
						int[,] array = new int[3, 3];
						array[0, 0] = -337842224;
						array[0, 1] = -211828111;
						array[0, 2] = 1935795247;
						array[1, 0] = -424669060;
						array[1, 1] = 1274063352;
						array[1, 2] = -131037492;
						array[2, 0] = -2010757699;
						array[2, 1] = 355922750;
						array[2, 2] = -380161373;
						array[2, 2] = array[0, 1] ^ 0x66E54B72;
						array[1, 0] = array[2, 2] ^ 0x1105DCEB;
						array[0, 0] = array[1, 1] ^ -1389789778;
						array[0, 0] = array[0, 2] ^ 0x774498DF;
						int num11 = array[0, 0] ^ 0x56FB6A8D;
						num = (int)((num4 * 1735176658) ^ 0xCDE0F37Eu) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static string[] _003C_003D_0029_0026_0024_0024_002F_0025(string P_0, char P_1, StringSplitOptions P_2)
		{
			string[] result = default(string[]);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -626305782;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(((204694937 - (((num2 ^ (-(438302355 * 337011737 - ~((-1256782989 * 1677316180 + 1747480409 * 1280522075 + ~(~1644363247)) * 1269606205)) - ((~(-1645287567 + 1571632042 + -1711741719) - -823989601 * (1644976015 - -948414863 - -1824897145 * -687617241)) ^ ((-(985750620 + -13853633) - -166277381) * 124994081) ^ ((~(-719099347) ^ ~(--308607160)) * 759830023 - ~(-1609724807 ^ -(--237911297))) ^ (-(~-1698578878) + (-466346053 + ~(657998988 + (-1937312523 ^ 0x4FC85222)) - (~900222267 + 931507900 + (~1158621160 + 2106368916 * 1193164353) - -778255702)))) - ~(-(-(~((0x4F130F08 ^ -127244234) - -(-1233439818 + 1748988388)))) - ((0x1D7B7D90 ^ (-1786563979 ^ --110877603)) - 1138095356 * 968418039 - (-(~-1453257977) ^ -(-950379951 - 923798234) ^ (-1864764153 ^ -(~1874729323))) + 1550896124)))) + -(~(0x414124F6 ^ 0x2177F9F6))) ^ (-(~(~(~288422635 - (-1503867911 ^ -2127909408) + -(627257306 - -1328330409)))) ^ (-1756096939 ^ (((0x57754A7E ^ 0x526D3E64) - (-485744825 ^ 0x1993FC1) - -(1102831192 - 1660437260 - (-357809358 + 1662974358))) ^ (-(-2000052139 * -284696497) + (0x467E77BA ^ 0x5735CD3C)))))) - -1258671953) * -1721206939 * -1977024173 - (~1745801416 + (-965638478 ^ 0x5AEACFE5)) - (1721416490 + 136140342)) ^ 0x2152A440)) % 3;
						int num5 = -2;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = ~(num5 ^ -208637620);
							num5 = -(num5 ^ 0x763AF5C6);
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
							int num9 = 396611118;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 += -396611117;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.Split(P_1, P_2);
						int[] array = new int[5];
						array[0] = -1079477893;
						array[1] = -1377030793;
						array[2] = -26981604;
						array[3] = -1204530768;
						array[4] = -67018008;
						array[3] = array[2] ^ 0x201E85B0;
						array[0] = array[1] ^ 0x7BC3A100;
						int[] array2 = new int[6] { 591421354, -1212296909, -597623604, -1518375405, -999519373, -1849129789 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[4] = array3[0][2] ^ -302695839;
						array2[3] = array2[0] ^ -1399165414;
						array2[1] = array2[3] ^ 0x4D232C30;
						int num11 = array3[1][4] ^ 0x73C2765C;
						num = ((int)num4 * -147059506) ^ -1496700980 ^ num11;
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
	private struct _003CSignInAsync_003Ed__47 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder _003C_003Et__builder;

		public LoginViewModel _003C_003E4__this;

		private TaskAwaiter<AuthResult> _003C_003Eu__1;

		private unsafe void MoveNext()
		{
			int num = _003C_003E1__state;
			LoginViewModel loginViewModel = _003C_003E4__this;
			try
			{
				if (num == 0)
				{
					goto IL_0a67;
				}
				while (true)
				{
					int num2 = -20978020;
					uint num4;
					while (true)
					{
						int num3 = num2;
						uint num5;
						num4 = (num5 = (uint)(((num3 ^ (-(1061469623 * ~(~(-1044190011)) - ~(-(-(~(1011121831 - ~721954800))))) ^ ~(-(~(~((-651129167 * 888161749 + (1373652871 - 1020931432)) * 232919041))) + (-(0x5AC631A7 ^ 0x513BAFC) * -789150657 + -(-2028053595 - -1794798770 - (-1451673725 - -1123753407)) - -(--567011446) - ((0x188AAD9C ^ ~(-(~-122933956))) - (~-783737205 - (-1640624548 ^ 0x27621B74) + (-1949411292 ^ -1763846010) + 1324694887)))))) * -521173167 + -2083528305 * 1551912993) ^ -1190229043)) % 6;
						uint num6 = num4;
						int num7 = 70680549;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = (num7 ^ 0x5E3D445D) - -1391032349;
							num7 = ~num7 + -1328555604;
						}
						if (num6 == (uint)num7)
						{
							break;
						}
						uint num9 = num4;
						int num10 = 116944897;
						_ = 0;
						for (int num11 = 0; num11 < 2; num11++)
						{
							num10 = ~num10 ^ 0x27382DC;
							num10 = -(num10 + ~2092123492);
						}
						if (num9 != (uint)num10)
						{
							uint num12 = num4;
							int num13 = -3;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 = ~num13;
							}
							if (num12 != (uint)num13)
							{
								uint num15 = num4;
								int num16 = 214018052;
								_ = 0;
								for (int num17 = 0; num17 < 2; num17++)
								{
									num16 = -377318340 - (~-1318427464 - num16);
									num16 = -295968121 - (-751736627 - 1132968271 - num16);
								}
								if (num15 != (uint)num16)
								{
									uint num18 = num4;
									int num19 = 439266551;
									_ = 0;
									for (int num20 = 0; num20 < 1; num20++)
									{
										num19 *= -1382165305;
									}
									if (num18 == (uint)num19)
									{
										loginViewModel.IsBusy = true;
										num2 = -470035023;
										continue;
									}
									goto IL_032f;
								}
								goto end_IL_0023;
							}
							loginViewModel.SetStatus(_003F_003C_005E_005E_005E_002F_005E_0025(loginViewModel._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x922 ^ 0x841]), SeverityLevel.Warning);
							int[] array = new int[4];
							array[0] = -1751894632;
							array[1] = -774472544;
							array[2] = -674294411;
							array[3] = 22151459;
							array[2] = array[3] ^ -839237377;
							array[2] = array[3] ^ -1690696717;
							array[0] = array[1] ^ 0x75A1EB0D;
							int[] array2 = new int[5];
							array2[0] = -1999944953;
							array2[1] = 1699015200;
							array2[2] = -152882779;
							array2[3] = -54870270;
							array2[4] = -213157884;
							array2[1] = array[3] ^ 0x7D62CED3;
							array2[0] = array2[4] ^ 0x108E55CF;
							array2[0] = array2[3] ^ 0x59B1F363;
							int num21 = array2[1] ^ 0x3FE88A27;
							num2 = ((int)num5 * -184362767) ^ 0x1DB4CB44 ^ num21;
							continue;
						}
						bool num22 = _0024_0024_002F_0024_005E_002F_005E_0029(loginViewModel.LicenseKey);
						int[] array3 = new int[6];
						array3[0] = 1754639688;
						array3[1] = 1630852034;
						array3[2] = -135008595;
						array3[3] = 1897669139;
						array3[4] = 1772705820;
						array3[5] = 1165489141;
						array3[0] = array3[5] ^ -2043845434;
						array3[1] = array3[4] ^ 0x72D83A24;
						array3[1] = array3[3] ^ -951991040;
						int[] array4 = new int[4];
						array4[0] = -1951771852;
						array4[1] = 397265317;
						array4[2] = 1440367388;
						array4[3] = 960100493;
						array4[3] = array3[2] ^ 0x59EE9D46;
						array4[0] = array4[1] ^ 0x6B3E6B0;
						array4[1] ^= -1495681911;
						int num23 = array4[3] ^ 0x47E10BCB;
						int[,] array5 = new int[3, 4]
						{
							{ 1940533844, -220208066, -816058812, 1959276120 },
							{ -1719206222, 76254235, 1033574190, -1521685707 },
							{ 326308038, -1971421281, -1916564886, 608655757 }
						};
						array5[2, 2] ^= 1535690470;
						array5[0, 2] = array5[0, 0] ^ 0x400AA2E8;
						array5[0, 0] = array5[0, 3] ^ -173657786;
						array5[2, 2] = array5[2, 3] ^ -1385066035;
						int num24 = array5[2, 2] ^ 0x347CFB4F;
						int num25 = (int)((num5 * 1169301653) ^ 0x2EB30B09);
						num23 ^= num25;
						num24 ^= num25;
						int num26;
						int num27;
						if (num22)
						{
							num26 = num24;
							num27 = num26;
						}
						else
						{
							num26 = num23;
							num27 = num26;
						}
						num2 = num26 ^ num25;
					}
					continue;
					IL_032f:
					uint num28 = num4;
					int num29 = 229292558;
					_ = 0;
					for (int num30 = 0; num30 < 2; num30++)
					{
						num29 = num29 * -180613769 - 192691151;
						num29 = -num29;
					}
					if (num28 == (uint)num29)
					{
					}
					goto IL_0a67;
					continue;
					end_IL_0023:
					break;
				}
				goto end_IL_001a;
				IL_0a67:
				try
				{
					if (num != 0)
					{
						goto IL_0a70;
					}
					goto IL_2b29;
					IL_0a70:
					int num31 = 43834667;
					goto IL_0a75;
					IL_0a75:
					TaskAwaiter<AuthResult> awaiter = default(TaskAwaiter<AuthResult>);
					AuthResult result = default(AuthResult);
					string message = default(string);
					while (true)
					{
						int num3 = num31;
						uint num5;
						uint num4 = (num5 = (uint)(((num3 ^ (-(1061469623 * ~(~(-1044190011)) - ~(-(-(~(1011121831 - ~721954800))))) ^ ~(-(~(~((-651129167 * 888161749 + (1373652871 - 1020931432)) * 232919041))) + (-(0x5AC631A7 ^ 0x513BAFC) * -789150657 + -(-2028053595 - -1794798770 - (-1451673725 - -1123753407)) - -(--567011446) - ((0x188AAD9C ^ ~(-(~-122933956))) - (~-783737205 - (-1640624548 ^ 0x27621B74) + (-1949411292 ^ -1763846010) + 1324694887)))))) * -521173167 + -2083528305 * 1551912993) ^ -1190229043)) % 19;
						uint num32 = num4;
						int num33 = -8;
						_ = 0;
						for (int num34 = 0; num34 < 1; num34++)
						{
							num33 = -num33;
						}
						if (num32 == (uint)num33)
						{
							break;
						}
						uint num35 = num4;
						int num36 = -1483814023;
						_ = 0;
						for (int num37 = 0; num37 < 1; num37++)
						{
							num36 *= -1458118603;
						}
						if (num35 == (uint)num36)
						{
							awaiter = _0025_003E_003F_002F_0024_002D_005E_005E(loginViewModel._authenticationService, _0025_0021_003E_005E_005E_003C_0024_0026(loginViewModel.LicenseKey), loginViewModel.RememberLicense, default(CancellationToken)).GetAwaiter();
							int[] array6 = new int[4];
							array6[0] = 706189346;
							array6[1] = -1686017406;
							array6[2] = 604661755;
							array6[3] = 379639135;
							array6[0] = array6[3] ^ -791196183;
							array6[0] ^= 1942011910;
							int[] array7 = new int[4] { 1210423664, -502373375, 1383063259, 1380355088 };
							int[][] array8 = new int[2][] { array6, array7 };
							array7[1] = array8[0][1] ^ 0x5A02F6FC;
							array7[3] = array7[0] ^ 0x53D2A3BC;
							array7[0] = array7[1] ^ 0x6BCEDE6F;
							int num38 = array8[1][1] ^ 0x6FA24C67;
							num31 = ((int)num5 * -748649915) ^ 0xFC04120 ^ num38;
							continue;
						}
						uint num39 = num4;
						int num40 = 2055625504;
						_ = 0;
						for (int num41 = 0; num41 < 1; num41++)
						{
							num40 ^= 0x7A865B29;
						}
						if (num39 == (uint)num40)
						{
							bool ısCompleted = awaiter.IsCompleted;
							int[] array9 = new int[7];
							array9[0] = -435636144;
							array9[1] = 1415071741;
							array9[2] = 1133953914;
							array9[3] = -1921897854;
							array9[4] = 1013401054;
							array9[5] = -1368699333;
							array9[6] = 689287773;
							array9[1] = array9[2] ^ 0x281A68D3;
							array9[4] = array9[5] ^ 0x43ACD5AB;
							int[] array10 = new int[4];
							array10[0] = -187508526;
							array10[1] = 1459740891;
							array10[2] = 1344012330;
							array10[3] = -1123333001;
							array10[0] = array9[0] ^ -841051641;
							array10[1] = array10[2] ^ -684254754;
							array10[3] = array10[2] ^ 0x75D36BFE;
							array10[2] ^= 626576209;
							int num42 = array10[0] ^ 0x10B0C519;
							int[,] array11 = new int[3, 4];
							array11[0, 0] = -58799483;
							array11[0, 1] = -2049747776;
							array11[0, 2] = 513625621;
							array11[0, 3] = -1966835671;
							array11[1, 0] = 1410530188;
							array11[1, 1] = -60139059;
							array11[1, 2] = -800021240;
							array11[1, 3] = -85652410;
							array11[2, 0] = -648784494;
							array11[2, 1] = 2089083734;
							array11[2, 2] = -422215106;
							array11[2, 3] = -1272595492;
							array11[0, 0] = array11[0, 3] ^ 0x3F593A10;
							array11[1, 2] = array11[1, 3] ^ 0x4FDEB7F5;
							array11[2, 3] = array11[2, 2] ^ -1229804644;
							int num43 = array11[2, 3] ^ -2079863379;
							int num44 = ((int)num5 * -1059617512) ^ -1958250480;
							num42 ^= num44;
							num43 ^= num44;
							int num45;
							int num46;
							if (!ısCompleted)
							{
								num45 = num43;
								num46 = num45;
							}
							else
							{
								num45 = num42;
								num46 = num45;
							}
							num31 = num45 ^ num44;
							continue;
						}
						uint num47 = num4;
						int num48 = 0;
						_ = 0;
						for (int num49 = 0; num49 < 2; num49++)
						{
							num48 = -num48 * 473874701;
							num48 *= 1575515353;
						}
						if (num47 == (uint)num48)
						{
							num = (_003C_003E1__state = 0);
							int[] array12 = new int[5];
							array12[0] = 285309174;
							array12[1] = -346555002;
							array12[2] = -1516115628;
							array12[3] = -450941568;
							array12[4] = -507107126;
							array12[4] = array12[2] ^ -137649652;
							array12[1] = array12[0] ^ -2145269797;
							array12[3] = array12[2] ^ 0x331CD1C7;
							int[] array13 = new int[7];
							array13[0] = -2072268567;
							array13[1] = -2140340356;
							array13[2] = -1581885345;
							array13[3] = -1239761388;
							array13[4] = 1101465732;
							array13[5] = 1917892651;
							array13[6] = -33055536;
							array13[1] = array12[2] ^ 0x4A382888;
							array13[6] = array13[1] ^ 0xE5D8B58;
							array13[5] = array13[0] ^ 0x54202FFE;
							int num50 = array13[1] ^ -1038708411;
							num31 = (int)((num5 * 439580808) ^ 0x3C9CA620) ^ num50;
							continue;
						}
						uint num51 = num4;
						int num52 = 322962026;
						_ = 0;
						for (int num53 = 0; num53 < 2; num53++)
						{
							num52 = (~2091000081 - num52) ^ -1717076357;
							num52 = -num52 ^ 0x7FE81C35;
						}
						if (num51 == (uint)num52)
						{
							_003C_003Eu__1 = awaiter;
							int[] array14 = new int[6];
							array14[0] = -1916073025;
							array14[1] = -42610512;
							array14[2] = -1981683796;
							array14[3] = -1679116511;
							array14[4] = 686943528;
							array14[5] = -339064192;
							array14[3] = array14[1] ^ -518751343;
							array14[3] = array14[2] ^ -990496920;
							array14[1] = array14[2] ^ -1264558236;
							int[] array15 = new int[5];
							array15[0] = 1274614907;
							array15[1] = 280949545;
							array15[2] = 1620968289;
							array15[3] = 1891820457;
							array15[4] = -1995139972;
							array15[4] = array14[5] ^ -1372274924;
							array15[0] ^= 1521458529;
							array15[0] = array15[4] ^ 0x7B15B28F;
							array15[0] = array15[3] ^ 0x56BB0125;
							int num54 = array15[4] ^ 0x3CC2675C;
							num31 = ((int)num5 * -2070051923) ^ 0x2AA7E5E ^ num54;
							continue;
						}
						uint num55 = num4;
						int num56 = -654543410;
						_ = 0;
						for (int num57 = 0; num57 < 2; num57++)
						{
							num56 = 1654912027 - 1168694751 - num56 - 813488988;
							num56 = -num56;
						}
						if (num55 == (uint)num56)
						{
							_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
							int[] array16 = new int[6];
							array16[0] = -799722759;
							array16[1] = -1447548127;
							array16[2] = 145347076;
							array16[3] = 1594358676;
							array16[4] = -375672765;
							array16[5] = -2011341852;
							array16[0] = array16[4] ^ 0x6E012069;
							array16[5] = array16[4] ^ -1555853765;
							array16[0] = array16[4] ^ 0x14F31C3B;
							int[] array17 = new int[4] { 1703244229, -917412763, 1906025230, -1992503803 };
							int[][] array18 = new int[2][] { array16, array17 };
							array17[2] = array18[0][3] ^ -1933145002;
							array17[1] = array17[2] ^ -1953706486;
							array17[3] = array17[2] ^ -135340822;
							int num58 = array18[1][2] ^ -576487689;
							num31 = (int)((num5 * 286042710) ^ 0x94B5F876u) ^ num58;
							continue;
						}
						uint num59 = num4;
						int num60 = -16;
						_ = 0;
						for (int num61 = 0; num61 < 1; num61++)
						{
							num60 = -num60;
						}
						if (num59 == (uint)num60)
						{
							return;
						}
						uint num62 = num4;
						int num63 = -5;
						_ = 0;
						for (int num64 = 0; num64 < 1; num64++)
						{
							num63 = -num63;
						}
						if (num62 == (uint)num63)
						{
							goto IL_2b29;
						}
						uint num65 = num4;
						int num66 = -12;
						_ = 0;
						for (int num67 = 0; num67 < 1; num67++)
						{
							num66 = ~num66;
						}
						if (num65 == (uint)num66)
						{
							_003C_003Eu__1 = default(TaskAwaiter<AuthResult>);
							int[] array19 = new int[7];
							array19[0] = 792013424;
							array19[1] = -1743760561;
							array19[2] = -1065521211;
							array19[3] = 237570403;
							array19[4] = 1277214848;
							array19[5] = 1916197761;
							array19[6] = -1087043442;
							array19[4] = array19[0] ^ 0x69957EE9;
							array19[3] = array19[1] ^ 0x95838C1;
							array19[2] = array19[1] ^ 0x12D27828;
							int[] array20 = new int[5];
							array20[0] = 1204781771;
							array20[1] = 695594262;
							array20[2] = 302455942;
							array20[3] = 1272728831;
							array20[4] = 1502705139;
							array20[4] = array19[6] ^ 0x1C3B58ED;
							array20[2] ^= 804691517;
							array20[1] = array20[2] ^ 0x4749B671;
							array20[3] = array20[2] ^ -619996550;
							int num68 = array20[4] ^ 0x40D129A6;
							num31 = ((int)num5 * -1102355848) ^ -1272515952 ^ num68;
							continue;
						}
						uint num69 = num4;
						int num70 = -1105923232;
						_ = 0;
						for (int num71 = 0; num71 < 2; num71++)
						{
							num70 = -(-num70);
							num70 = num70 * -1361301851 + 22125074;
						}
						if (num69 == (uint)num70)
						{
							num = (_003C_003E1__state = -1);
							int[] array21 = new int[7];
							array21[0] = 1847860852;
							array21[1] = 616572252;
							array21[2] = 1692888943;
							array21[3] = 162943632;
							array21[4] = -884293600;
							array21[5] = 1624674077;
							array21[6] = 1276927768;
							array21[6] = array21[2] ^ -1250218049;
							array21[5] = array21[0] ^ -692447854;
							array21[4] = array21[3] ^ -751806724;
							int[] array22 = new int[5];
							array22[0] = 695595760;
							array22[1] = 1222890155;
							array22[2] = 1933191717;
							array22[3] = -1224043999;
							array22[4] = 912907053;
							array22[1] = array21[1] ^ -1192727823;
							array22[3] = array22[2] ^ -1619569736;
							array22[4] = array22[3] ^ -2052953448;
							int num72 = array22[1] ^ -1488019229;
							num31 = ((int)num5 * -214931835) ^ 0x6A660C5A ^ num72;
							continue;
						}
						uint num73 = num4;
						int num74 = -297084646;
						_ = 0;
						for (int num75 = 0; num75 < 1; num75++)
						{
							num74 = -297084644 - num74;
						}
						if (num73 == (uint)num74)
						{
							result = awaiter.GetResult();
							num31 = -1587273575;
							continue;
						}
						uint num76 = num4;
						int num77 = 932361220;
						_ = 0;
						for (int num78 = 0; num78 < 1; num78++)
						{
							num77 = 932361223 - num77;
						}
						if (num76 == (uint)num77)
						{
							bool num79 = _0024_005E_003D_002B_0021_0024_0024_003D(result);
							int[,] array23 = new int[4, 3];
							array23[0, 0] = -2137191117;
							array23[0, 1] = 1687703461;
							array23[0, 2] = 20041487;
							array23[1, 0] = -1363855216;
							array23[1, 1] = -1511908468;
							array23[1, 2] = 1885856787;
							array23[2, 0] = -171975788;
							array23[2, 1] = 2048697413;
							array23[2, 2] = 230650290;
							array23[3, 0] = -1477664674;
							array23[3, 1] = 1817859704;
							array23[3, 2] = -1661059708;
							array23[0, 1] = array23[2, 1] ^ 0x79B83AAC;
							array23[3, 0] = array23[2, 1] ^ -287423243;
							array23[1, 0] = array23[2, 0] ^ 0x5524FF71;
							int num80 = array23[1, 0] ^ -1903047567;
							int[] array24 = new int[4];
							array24[0] = -1172880788;
							array24[1] = -571275526;
							array24[2] = -1839198412;
							array24[3] = 669333373;
							array24[1] = array24[0] ^ -2066538642;
							array24[1] = array24[2] ^ -1581196057;
							array24[1] = array24[0] ^ -1259092371;
							int[] array25 = new int[4];
							array25[0] = -403833968;
							array25[1] = -1014513843;
							array25[2] = -1265611618;
							array25[3] = -903907236;
							array25[0] = array24[2] ^ 0x36356139;
							array25[1] = array25[3] ^ 0x6053B8AE;
							array25[1] = array25[0] ^ -1441576789;
							int num81 = array25[0] ^ 0x3A965240;
							int num82 = ((int)num5 * -794943421) ^ 0x3A6EF042;
							num80 ^= num82;
							num81 ^= num82;
							int num83;
							int num84;
							if (!num79)
							{
								num83 = num81;
								num84 = num83;
							}
							else
							{
								num83 = num80;
								num84 = num83;
							}
							num31 = num83 ^ num82;
							continue;
						}
						uint num85 = num4;
						int num86 = -804204846;
						_ = 0;
						for (int num87 = 0; num87 < 2; num87++)
						{
							num86 = ~num86 * -36215007;
							num86 = num86 - 1104471813 * 2004228345 + 159196424;
						}
						if (num85 == (uint)num86)
						{
							message = _003C_002A_0021_002B_0025_003F_003F_003F(result) ?? _003F_003C_005E_005E_005E_002F_005E_0025(loginViewModel._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0xF8C2 ^ 0xF9A5))]);
							num31 = -66233674;
							continue;
						}
						uint num88 = num4;
						int num89 = -1266147812;
						_ = 0;
						for (int num90 = 0; num90 < 2; num90++)
						{
							num89 = 1853706388 - num89 * -629663369;
							num89 = ~num89;
						}
						if (num88 == (uint)num89)
						{
							loginViewModel.SetStatus(message, SeverityLevel.Error);
							int[] array26 = new int[6] { 877345153, 1877109380, -76345458, 2036205453, 318936884, 1357925998 };
							array26[3] ^= -416551727;
							array26[3] = array26[5] ^ -255388966;
							int[] array27 = new int[7] { 463713861, -1128693903, -849344638, 1599923474, -1178636184, 783044777, 945376869 };
							int[][] array28 = new int[2][] { array26, array27 };
							array27[2] = array28[0][0] ^ -699910370;
							array27[3] = array27[5] ^ 0x31A5A835;
							array27[6] = array27[1] ^ -1685284388;
							array27[0] ^= 932380846;
							int num91 = array28[1][2] ^ 0x4B010B91;
							num31 = ((int)num5 * -1271359384) ^ 0x2F405718 ^ num91;
							continue;
						}
						uint num92 = num4;
						int num93 = -1;
						_ = 0;
						for (int num94 = 0; num94 < 1; num94++)
						{
							num93 = -num93;
						}
						if (num92 == (uint)num93)
						{
							loginViewModel.AppViewModel.AddActivity(message, SeverityLevel.Error);
							int[,] array29 = new int[4, 3];
							array29[0, 0] = 330029407;
							array29[0, 1] = -2141866627;
							array29[0, 2] = 1232721765;
							array29[1, 0] = 169200154;
							array29[1, 1] = -1194767610;
							array29[1, 2] = -1636220513;
							array29[2, 0] = -1850602692;
							array29[2, 1] = 653821309;
							array29[2, 2] = -1640886791;
							array29[3, 0] = -991935451;
							array29[3, 1] = -12686136;
							array29[3, 2] = -1264305480;
							array29[0, 0] = array29[2, 2] ^ 0x244C94AF;
							array29[1, 1] = array29[2, 2] ^ 0xC8B6D9E;
							array29[0, 0] = array29[3, 0] ^ 0x49705468;
							array29[0, 1] = array29[3, 2] ^ 0x29BBC0AF;
							int num95 = array29[0, 1] ^ -619247173;
							num31 = (int)((num5 * 1130727481) ^ 0xC5C5755Fu) ^ num95;
							continue;
						}
						uint num96 = num4;
						int num97 = -7;
						_ = 0;
						for (int num98 = 0; num98 < 1; num98++)
						{
							num97 = -num97;
						}
						if (num96 != (uint)num97)
						{
							uint num99 = num4;
							int num100 = -977097585;
							_ = 0;
							for (int num101 = 0; num101 < 2; num101++)
							{
								num100 = num100 * 1383769583 + 1089069167;
								num100 = ~num100 ^ 0x621BCB58;
							}
							if (num99 == (uint)num100)
							{
								loginViewModel.AppViewModel.SetAuthenticated(_0025_0021_003E_005E_005E_003C_0024_0026(loginViewModel.LicenseKey), _002A_0025_0023_005E_0025_002B_0024_0025(result), _0024_002B_0024_0023_0021_0040_005E_0025(result));
								num31 = -428240712;
								continue;
							}
							uint num102 = num4;
							int num103 = 459605622;
							_ = 0;
							for (int num104 = 0; num104 < 2; num104++)
							{
								num103 = -(num103 * -1983172601);
								num103 = -(num103 * 119106611);
							}
							if (num102 == (uint)num103)
							{
								loginViewModel.SetStatus(_003F_003C_005E_005E_005E_002F_005E_0025(loginViewModel._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-471 + 110)]), SeverityLevel.Success);
								loginViewModel.AppViewModel.AddActivity(_003F_003C_005E_005E_005E_002F_005E_0025(loginViewModel._strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(373 + sizeof(int)) ^ sizeof(Guid)]), SeverityLevel.Success);
								int[] array30 = new int[4] { 129752510, 1141772165, -576245045, -143055590 };
								array30[2] ^= 655587361;
								array30[3] = array30[2] ^ -1586469493;
								int[] array31 = new int[5];
								array31[0] = -1623894884;
								array31[1] = -1758351879;
								array31[2] = -45788594;
								array31[3] = 582632289;
								array31[4] = -755216428;
								array31[2] = array30[1] ^ -1944156209;
								array31[4] ^= 1317929848;
								array31[1] = array31[4] ^ -1686852230;
								int num105 = array31[2] ^ 0x6F0E0689;
								num31 = ((int)num5 * -1462964972) ^ -1567487468 ^ num105;
								continue;
							}
							uint num106 = num4;
							int num107 = 528493335;
							_ = 0;
							for (int num108 = 0; num108 < 2; num108++)
							{
								num107 = (num107 - --1189184915) ^ 0x65A43DA3;
								num107 = (num107 ^ -2126792807) + 397043694;
							}
							if (num106 == (uint)num107)
							{
							}
						}
						goto end_IL_0a67;
					}
					goto IL_0a70;
					IL_2b29:
					awaiter = _003C_003Eu__1;
					num31 = -2133204063;
					goto IL_0a75;
					end_IL_0a67:;
				}
				finally
				{
					if (num < 0)
					{
						while (true)
						{
							int num109 = -728877805;
							while (true)
							{
								int num3 = num109;
								uint num5;
								uint num4 = (num5 = (uint)(((num3 ^ (-(1061469623 * ~(~(-1044190011)) - ~(-(-(~(1011121831 - ~721954800))))) ^ ~(-(~(~((-651129167 * 888161749 + (1373652871 - 1020931432)) * 232919041))) + (-(0x5AC631A7 ^ 0x513BAFC) * -789150657 + -(-2028053595 - -1794798770 - (-1451673725 - -1123753407)) - -(--567011446) - ((0x188AAD9C ^ ~(-(~-122933956))) - (~-783737205 - (-1640624548 ^ 0x27621B74) + (-1949411292 ^ -1763846010) + 1324694887)))))) * -521173167 + -2083528305 * 1551912993) ^ -1190229043)) % 3;
								uint num110 = num4;
								int num111 = -1;
								_ = 0;
								for (int num112 = 0; num112 < 1; num112++)
								{
									num111 = ~num111;
								}
								if (num110 == (uint)num111)
								{
									break;
								}
								uint num113 = num4;
								int num114 = 1496403970;
								_ = 0;
								for (int num115 = 0; num115 < 2; num115++)
								{
									num114 = (num114 ^ 0x4AB15E3E) * -1224294183;
									num114 = (num114 ^ 0x4DA9E4A2) * -640453527;
								}
								if (num113 != (uint)num114)
								{
									uint num116 = num4;
									int num117 = -738063194;
									_ = 0;
									for (int num118 = 0; num118 < 1; num118++)
									{
										num117 -= -738063195;
									}
									if (num116 == (uint)num117)
									{
									}
									goto end_IL_2d93;
								}
								loginViewModel.IsBusy = false;
								int[] array32 = new int[7];
								array32[0] = -1050080534;
								array32[1] = 119320718;
								array32[2] = 1788467847;
								array32[3] = 818567287;
								array32[4] = -1132066506;
								array32[5] = 798606878;
								array32[6] = -1795259784;
								array32[3] = array32[0] ^ -921824369;
								array32[1] = array32[2] ^ -572690387;
								int[] array33 = new int[4] { 932434491, -1948633620, -1519372227, -1669396575 };
								int[][] array34 = new int[2][] { array32, array33 };
								array33[2] = array34[0][2] ^ -25542308;
								array33[0] = array33[2] ^ -176385600;
								array33[1] = array33[3] ^ 0x2CF18464;
								array33[3] = array33[2] ^ -408798498;
								int num119 = array34[1][2] ^ 0x622F4D85;
								num109 = ((int)num5 * -673554181) ^ 0x24185AE8 ^ num119;
							}
							continue;
							end_IL_2d93:
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
					int num120 = 1851968660;
					while (true)
					{
						int num3 = num120;
						uint num5;
						uint num4 = (num5 = (uint)(((num3 ^ (-(1061469623 * ~(~(-1044190011)) - ~(-(-(~(1011121831 - ~721954800))))) ^ ~(-(~(~((-651129167 * 888161749 + (1373652871 - 1020931432)) * 232919041))) + (-(0x5AC631A7 ^ 0x513BAFC) * -789150657 + -(-2028053595 - -1794798770 - (-1451673725 - -1123753407)) - -(--567011446) - ((0x188AAD9C ^ ~(-(~-122933956))) - (~-783737205 - (-1640624548 ^ 0x27621B74) + (-1949411292 ^ -1763846010) + 1324694887)))))) * -521173167 + -2083528305 * 1551912993) ^ -1190229043)) % 4;
						uint num121 = num4;
						int num122 = -1924099609;
						_ = 0;
						for (int num123 = 0; num123 < 1; num123++)
						{
							num122 -= -1924099609;
						}
						if (num121 == (uint)num122)
						{
							break;
						}
						uint num124 = num4;
						int num125 = 980614217;
						_ = 0;
						for (int num126 = 0; num126 < 2; num126++)
						{
							num125 = -(num125 * -1458392663);
							num125 = ~(-num125);
						}
						if (num124 != (uint)num125)
						{
							uint num127 = num4;
							int num128 = 1174365209;
							_ = 0;
							for (int num129 = 0; num129 < 1; num129++)
							{
								num128 -= 1174365207;
							}
							if (num127 != (uint)num128)
							{
								uint num130 = num4;
								int num131 = -957303325;
								_ = 0;
								for (int num132 = 0; num132 < 2; num132++)
								{
									num131 = num131 * 71455519 - 1714756135;
									num131 = num131 - (0x6467559F ^ 0x8EFC938) - 1503461971;
								}
								if (num130 == (uint)num131)
								{
								}
								return;
							}
							_003C_003Et__builder.SetException(exception);
							int[,] array35 = new int[3, 3];
							array35[0, 0] = 1259441999;
							array35[0, 1] = 868837670;
							array35[0, 2] = -1385388129;
							array35[1, 0] = 83417320;
							array35[1, 1] = -710142747;
							array35[1, 2] = 462809681;
							array35[2, 0] = -1037363360;
							array35[2, 1] = 1078850100;
							array35[2, 2] = 692633667;
							array35[0, 1] = array35[2, 0] ^ 0x45B968B1;
							array35[1, 0] = array35[0, 0] ^ -1410123755;
							array35[2, 0] = array35[2, 2] ^ 0x54477E9B;
							int num133 = array35[2, 0] ^ -1676084934;
							num120 = ((int)num5 * -622012556) ^ -333223880 ^ num133;
						}
						else
						{
							_003C_003E1__state = -2;
							int[] array36 = new int[5];
							array36[0] = 1129045421;
							array36[1] = -1077276168;
							array36[2] = 945874226;
							array36[3] = 697840923;
							array36[4] = 1730952315;
							array36[3] = array36[0] ^ 0x4E4D79B9;
							array36[0] = array36[2] ^ -373836759;
							array36[1] ^= 858471035;
							int[] array37 = new int[6] { -1011070089, -25982036, -924469116, 820713075, -86167599, -1122037594 };
							int[][] array38 = new int[2][] { array36, array37 };
							array37[3] = array38[0][2] ^ -1768995055;
							array37[1] = array37[5] ^ 0x27B6ABA7;
							array37[5] = array37[2] ^ -1080506795;
							array37[0] = array37[2] ^ 0x22A2E31E;
							int num134 = array38[1][3] ^ -1661898518;
							num120 = ((int)num5 * -86840500) ^ -1076413348 ^ num134;
						}
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num135 = -26459034;
				while (true)
				{
					int num3 = num135;
					uint num5;
					uint num4 = (num5 = (uint)(((num3 ^ (-(1061469623 * ~(~(-1044190011)) - ~(-(-(~(1011121831 - ~721954800))))) ^ ~(-(~(~((-651129167 * 888161749 + (1373652871 - 1020931432)) * 232919041))) + (-(0x5AC631A7 ^ 0x513BAFC) * -789150657 + -(-2028053595 - -1794798770 - (-1451673725 - -1123753407)) - -(--567011446) - ((0x188AAD9C ^ ~(-(~-122933956))) - (~-783737205 - (-1640624548 ^ 0x27621B74) + (-1949411292 ^ -1763846010) + 1324694887)))))) * -521173167 + -2083528305 * 1551912993) ^ -1190229043)) % 3;
					uint num136 = num4;
					int num137 = -170564213;
					_ = 0;
					for (int num138 = 0; num138 < 1; num138++)
					{
						num137 -= -170564213;
					}
					if (num136 == (uint)num137)
					{
						break;
					}
					uint num139 = num4;
					int num140 = 1077951496;
					_ = 0;
					for (int num141 = 0; num141 < 2; num141++)
					{
						num140 = ~(num140 ^ 0x64E0EE4F);
						num140 -= 1932873216 - 1259089917;
					}
					if (num139 != (uint)num140)
					{
						uint num142 = num4;
						int num143 = 96312871;
						_ = 0;
						for (int num144 = 0; num144 < 1; num144++)
						{
							num143 -= 96312870;
						}
						if (num142 == (uint)num143)
						{
						}
						return;
					}
					_003C_003Et__builder.SetResult();
					int[] array39 = new int[4];
					array39[0] = -2079555406;
					array39[1] = 1724722968;
					array39[2] = -1242412497;
					array39[3] = -1382645190;
					array39[3] = array39[2] ^ -1560127234;
					array39[2] ^= -362686996;
					array39[3] ^= -1491868920;
					int[] array40 = new int[7] { 583107344, -1429810466, 253492605, 751326572, -260862607, 161579995, -1614577436 };
					int[][] array41 = new int[2][] { array39, array40 };
					array40[5] = array41[0][0] ^ 0x62E2CB0A;
					array40[0] = array40[2] ^ -795455751;
					array40[3] = array40[2] ^ 0x41D1209F;
					array40[0] = array40[2] ^ -1642878904;
					int num145 = array41[1][5] ^ 0x13DFB98C;
					num135 = ((int)num5 * -1131821145) ^ -641790375 ^ num145;
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

		static bool _0024_0024_002F_0024_005E_002F_005E_0029(string P_0)
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
					int num = -1026940618;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(~((-(~(~((975589320 - -(0x20618A64 ^ -1267431867)) ^ -1297419836) - -(--2053570964 ^ 0x1D18148C)) ^ (~(1758691613 * -(~1875645564)) ^ 0x70A952EC)) - num2) ^ (-760015495 * (-1108298373 * -(~(-1741388467 * -1726409489 + -1323894729 * 1194764549)) + (0x6116EE8F ^ 0x722AB69F)) * 58876749) ^ (--1106350949 * -996830927 * -114887313)) * 1780803289))) % 3;
						int num5 = -1452742124;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = ~num5 * -1522887363;
							num5 = -(-num5);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -1558849850;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 *= 199093835;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 849853153;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = (num9 - -2098157694 * -355015563) * -61432837;
								num9 = ~num9 + 1464655551;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = string.IsNullOrWhiteSpace(P_0);
						int[,] array = new int[4, 3];
						array[0, 0] = 1562381905;
						array[0, 1] = 499671252;
						array[0, 2] = -712287473;
						array[1, 0] = 1213267916;
						array[1, 1] = -1088222539;
						array[1, 2] = 1149662439;
						array[2, 0] = 1597069104;
						array[2, 1] = 248073251;
						array[2, 2] = 1412054050;
						array[3, 0] = 787590057;
						array[3, 1] = 825355057;
						array[3, 2] = 1866186913;
						array[2, 0] = array[3, 0] ^ -680689900;
						array[0, 0] = array[0, 2] ^ 0x743AB8AC;
						array[1, 2] = array[2, 2] ^ -1976947209;
						int num11 = array[1, 2] ^ 0x43A744EB;
						num = (int)((num4 * 1184532124) ^ 0x69778538) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static string _003F_003C_005E_005E_005E_002F_005E_0025(IStringResourceService P_0, string P_1)
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
					int num = -811026951;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(((~-998723814 + (-2016242931 + (-1299543616 - (-59653561 + 746636519))) - 1510784923 * -(0x6EBF978D ^ 0x6AA03F7A) - ((~(~(~(155472922 + -1220677897) + --480964320)) ^ 0x54257208) - ((num2 + ~((-414816253 * (-(-(~((-1806986890 ^ 0x5781DF1F) * 92124639))) - (-1315388866 ^ -644778973))) ^ (-(~(~-796943288 * 230323389 + (~-249394343 + 448810198)) * 60115969) + (~(-2084493847 + 639402652) - (~-1196465079 - (~-1610347075 - ~876620112 + 182491177 * ~-938285857 + (1908527610 * 641870173 * -700515155 - ~(918224377 * -221574541)))))))) * 530728391 - (~(2041734485 * (-703515839 * (140463649 + 1463783942))) * -610338629 * -1742692177 - -598709203)))) ^ (-179512377 + (-1397309995 ^ -(-1703393022 * 1223026779)))) + -(1954231657 * -970969299 - (93448117 + 1299081534))) * -37216211 - -35855302)) % 3;
						int num5 = 1193663970;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = (num5 + (-1227998038 - -778956741)) * 264035853;
							num5 = -(735724958 * -342782225 - num5);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1460722827;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 = 1460722828 - num7;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 224277046;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -(~num9);
								num9 = num9 + ~-1715080385 + -1827218907;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.GetString(P_1);
						int[,] array = new int[4, 3];
						array[0, 0] = -1594471980;
						array[0, 1] = -218547283;
						array[0, 2] = -932347230;
						array[1, 0] = 1451396579;
						array[1, 1] = 593023122;
						array[1, 2] = -1625905019;
						array[2, 0] = -1518468456;
						array[2, 1] = 1603027060;
						array[2, 2] = -954327099;
						array[3, 0] = 1058599681;
						array[3, 1] = -867269377;
						array[3, 2] = -409137527;
						array[1, 2] = array[0, 1] ^ 0x41B6C0CD;
						array[0, 1] = array[2, 1] ^ -1088096791;
						array[1, 1] = array[3, 1] ^ -1180362504;
						array[1, 2] = array[3, 1] ^ 0x5E4874C9;
						int num11 = array[1, 2] ^ 0x6809B5CF;
						num = ((int)num4 * -1327874683) ^ -1713799358 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static string _0025_0021_003E_005E_005E_003C_0024_0026(string P_0)
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
					int num = -1556837202;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((num2 + ~(-164325903 ^ (~((~1923202941 - -(-120695934 * -182074357)) ^ 0x7702D1C0) ^ ((-(-2038647277 + -922253280) + (-262946099 * -1181763623 - (229714257 + -2139687261))) * 1178441373 - ~((0x5EE52D8E ^ 0x4099074A) * 880372663)) ^ (-(~(1697060025 - -720359623 * (-1507704900 + -473078396))) - -(~-179312962 + (-1987763762 ^ (--1251376322 + -1031628926)))))) - (-(~(~(54560017 * ((-1575338088 ^ 0x37772396) - (~1402483505 - ~375281943))))) + ~(~(-(-(-(--685443930 + -1102933641))))))) ^ ((122285621 * -(~(-(-487424586 * 1623631195) ^ -(-1133716115 + 1303647667)))) ^ (0x24354634 ^ -(-1643044417 ^ ~(-(2105103673 * -694621196))))) ^ (~((-524740099 ^ -838186006) + ~(-1842504218 ^ -916498571)) + (-(~1286179624) + 2042930718 * 270605435 + -(-2045159515 * -1107446207) * 256273603) + -1914261353 * 1456319802))) % 3;
						int num5 = -1416843466;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 ^= -1416843466;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -1792890328;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 ^= -1792890327;
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
						result = P_0.Trim();
						int[] array = new int[7];
						array[0] = 1486723443;
						array[1] = -1710321962;
						array[2] = -1974760290;
						array[3] = -1533217781;
						array[4] = 1260900369;
						array[5] = 37671435;
						array[6] = -105606680;
						array[0] = array[1] ^ -1431073426;
						array[0] = array[6] ^ -2075680097;
						array[5] = array[2] ^ -613191948;
						int[] array2 = new int[5];
						array2[0] = 1947695645;
						array2[1] = 947784741;
						array2[2] = 829463582;
						array2[3] = 1147295702;
						array2[4] = 637382389;
						array2[3] = array[6] ^ -2009805503;
						array2[1] = array2[3] ^ 0xBEA2280;
						array2[0] ^= 566665991;
						int num11 = array2[3] ^ -232649375;
						num = (int)((num4 * 103634504) ^ 0x285AC398) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static Task<AuthResult> _0025_003E_003F_002F_0024_002D_005E_005E(IAuthenticationService P_0, string P_1, bool P_2, CancellationToken P_3)
		{
			Task<AuthResult> result = default(Task<AuthResult>);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1145897015;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(-((num2 * 2025428163) ^ (-2125773439 * ((-(~(~1925279644) - ((-282409018 ^ -1519925058) + ~-534424870)) - (-1335384281 - ~1629654301 - 1911807573 + ~(298317019 * (-1577911157 ^ -913646077))) - ~859557621) ^ ~(~(-(~(-1928170633 * 1668634219))) ^ -(~(--1520332361))))))))) % 3;
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
						int num7 = 1409825821;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = 1442081565 - (num7 ^ 0x471363B3);
							num7 ^= -1445002772;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 0;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 *= 620519495;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.SignInAsync(P_1, P_2, P_3);
						int[] array = new int[4];
						array[0] = -1463875677;
						array[1] = 480054361;
						array[2] = 219210578;
						array[3] = 773291141;
						array[2] = array[1] ^ -1357381813;
						array[0] = array[1] ^ -2098700619;
						int[] array2 = new int[6];
						array2[0] = 578375690;
						array2[1] = -508491798;
						array2[2] = -781995876;
						array2[3] = 194348131;
						array2[4] = 49026559;
						array2[5] = 1451526638;
						array2[1] = array[1] ^ -1402087834;
						array2[5] = array2[0] ^ 0x5B3040E5;
						array2[2] = array2[0] ^ 0x7D68751;
						int num11 = array2[1] ^ 0x416A56E8;
						num = (int)((num4 * 50837421) ^ 0xE81CEBA3u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static bool _0024_005E_003D_002B_0021_0024_0024_003D(AuthResult P_0)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				return P_0.IsSuccess;
			}
		}

		static string _003C_002A_0021_002B_0025_003F_003F_003F(AuthResult P_0)
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
					int num = -1535881988;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(-(~(-(~(((num2 - ~(-(~(-(-1196092568 ^ 0x58B5C1E1))) + (-2127244987 * (~(-207251792 ^ 0x6A784C3F) - (-984758498 ^ 0x693EF6A3)) + (601207431 * (-1284037919 * (-393512153 * 2092196327 - ~88439123) * 736286693) + -626800016)))) ^ ((-1903379931 ^ -41199589) - ((-2109691606 ^ (0x3784F0D ^ (-82768064 ^ -275311879))) - (0x75E0F96 ^ -(-((0x4B146F2F ^ -495013143) - (59811853 - -57339328)))) - ~(-(~(547237976 + -1221525542) - ~(-(-1700315138 * 339905955))))))) + (-1217475640 ^ (-1163920951 * ((1809872807 * ~(-(-1595646545 * -991930743))) ^ (191590137 * -(~896852716) - (~(--61227498) ^ (-732837298 + --465022333))))))))))) + -1578421386)) % 3;
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
						int num7 = 1504516559;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~num7 * 268552509;
							num7 = ~num7 - 829376377;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 414487724;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 += -414487722;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						errorMessage = P_0.ErrorMessage;
						int[] array = new int[5];
						array[0] = 1368583325;
						array[1] = 1776778000;
						array[2] = 1047910620;
						array[3] = -1809721980;
						array[4] = -1675394741;
						array[3] = array[0] ^ -275074209;
						array[0] = array[2] ^ 0x6BD6C977;
						int[] array2 = new int[6] { -1895811671, 544449413, 829991083, -950088426, -1288440903, -1756621091 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][1] ^ 0x58E4A390;
						array2[5] = array2[3] ^ -578106108;
						array2[5] = array2[1] ^ 0x6861C621;
						array2[3] ^= -2066251636;
						int num11 = array3[1][1] ^ 0x5B68E821;
						num = ((int)num4 * -351921558) ^ 0x7E2E26D2 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return errorMessage;
		}

		static int? _002A_0025_0023_005E_0025_002B_0024_0025(AuthResult P_0)
		{
			int? remainingDays = default(int?);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -249716158;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(-(-(num2 - -(~(-1032552) ^ -1784713577)))))) % 3;
						int num5 = 1127307704;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 *= 1175171383;
							num5 = 1660514035 - num5 - 238823519;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1571378885;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ((0x5AFF9A4E ^ 0x18AC238C) - num7) * -968973473;
							num7 *= -1716939567;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -10362686;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -(num9 - 1096749865 * 40423703);
								num9 = (num9 ^ -1823000600) + -1651619508;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						remainingDays = P_0.RemainingDays;
						int[,] array = new int[3, 3];
						array[0, 0] = -123219095;
						array[0, 1] = -1600818551;
						array[0, 2] = 1306325815;
						array[1, 0] = -1375255342;
						array[1, 1] = -1996079018;
						array[1, 2] = -634669615;
						array[2, 0] = 609403965;
						array[2, 1] = 1559557191;
						array[2, 2] = 309366059;
						array[2, 2] = array[0, 2] ^ 0xD1FA65F;
						array[1, 1] = array[1, 2] ^ 0x4947BF4;
						array[2, 1] = array[1, 2] ^ -1776642155;
						array[0, 0] = array[1, 0] ^ 0x4C378C4B;
						int num11 = array[0, 0] ^ -706675504;
						num = (int)((num4 * 1766793563) ^ 0x5EB334DF) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return remainingDays;
		}

		static string _0024_002B_0024_0023_0021_0040_005E_0025(AuthResult P_0)
		{
			string planType = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 2045101072;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(num2 + -((0x5CEE8458 ^ 0x281F2F04) + 1427724895) * -332763391 + -1204841283 * ((-1783914110 ^ (~(~(~(-2068853567))) ^ (~(-881759330 - -1169070373 - -1513416293) - (-2109579011 + -(1001793517 + 1681726636))))) + ((1474955985 * (-(189874359 + ~1564193913) - (0xD3B3D1F ^ (--1976654170 + -1119716613)))) ^ (((-845449573 ^ -(236776797 - -934304316)) + ~(-1805658434 ^ -1961470025) * -1282751517) ^ (935986129 * (-46809865 - -723054134) + -((-1017278042 - 697767016) * -1975369241)))))) - (-124719236 ^ 0x45504269))) % 3;
						int num5 = 1892844332;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -num5 - 912138837;
							num5 = -(num5 - 288922645);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -404516878;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -(num7 * 967919203);
							num7 = ~(~num7);
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
						planType = P_0.PlanType;
						int[] array = new int[5];
						array[0] = -1661803001;
						array[1] = 1867005707;
						array[2] = 567984497;
						array[3] = -430056935;
						array[4] = 1323117590;
						array[4] = array[2] ^ -1809505457;
						array[4] = array[3] ^ 0x7F4059F9;
						array[0] = array[3] ^ -688432318;
						int[] array2 = new int[6] { 1036435930, -1359959580, -2095589047, -1796051270, -1938813761, 193011962 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][2] ^ -814962110;
						array2[5] ^= 1145534149;
						array2[3] = array2[0] ^ 0x2327048;
						array2[0] = array2[3] ^ -763797050;
						int num11 = array3[1][1] ^ -1876473926;
						num = ((int)num4 * -754651141) ^ 0x59ECEF92 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return planType;
		}
	}

	private readonly IAuthenticationService _authenticationService;

	private readonly ILauncherService _launcherService;

	private readonly IStringResourceService _strings;

	private bool _initialized;

	private bool _isBusy;

	private string _licenseKey = string.Empty;

	private bool _rememberLicense = true;

	private SeverityLevel _statusLevel;

	private string _statusMessage = string.Empty;

	public AppViewModel AppViewModel { get; }

	public bool HasStatus => !__005E_002D_003D_0021_0021_002A_0024(StatusMessage);

	public bool IsBusy
	{
		get
		{
			return _isBusy;
		}
		private set
		{
			if (!SetProperty(ref _isBusy, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xBE2D ^ 0xBF74]))
			{
				return;
			}
			while (true)
			{
				int num = -818999634;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-((num2 ^ (((1986186282 + (-(~1122828427) ^ -(~-457411253))) ^ -655750966) + -1881374199 - ((-(--951518510 - 501030169) - -(-287232060 ^ 0x25D72415)) * -1909763147 - (--1044491525 ^ -1971941510)) - -(0x54C7CD2A ^ (~(~(-1254556705 + -1107840543)) + -(~(154602028 + -358814155)) - ((0x6E5B3D06 ^ -456826744) + (0x7EBECDE6 ^ -2131092552)))) + ~(-1956853822 + ~-1403554731 + (-(-1963197322 + (101334218 - (-1228974858 - 22819190 + (0x6E630B62 ^ -1738680506)))) ^ ((854150317 * -(~-341615223) - -1293306712) ^ 0x23FAAE2D))))) - (-(-1914571255 ^ (0x7A6F7141 ^ (836754633 * -(1026362833 + 58763544)))) + 151368582 - 673998585 * (~(--272498530) ^ (-(~1843227687 * -387112467 - ~(-1757435636 * 1936742065)) ^ -753164523))) - --1409045055) * 1707017991) - -1290543095 + -(-1416265968))) % 5;
					int num5 = -1151281093;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (0x54809F0B ^ 0x6DF83B2C) - num5 - -607635444;
						num5 = ~num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 768336030;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -1337252177;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1069420492;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(num9 ^ -585599149);
							num9 = ~-294086475 - num9 - 812035377;
						}
						if (num3 != (uint)num9)
						{
							int num11 = -658971969;
							_ = 0;
							for (int num12 = 0; num12 < 1; num12++)
							{
								num11 -= -658971969;
							}
							if (num3 != (uint)num11)
							{
								int num13 = 3;
								_ = 0;
								for (int num14 = 0; num14 < 2; num14++)
								{
									num13 = -(num13 ^ -1985883928);
									num13 = ~num13;
								}
								if (num3 == (uint)num13)
								{
								}
								return;
							}
							_0021_005E_003F_0024_002B_005E_0026_0024((IRelayCommand)OpenUpdateCommand);
							int[] array = new int[7];
							array[0] = -473086031;
							array[1] = -1795041202;
							array[2] = 1817841315;
							array[3] = 1672402330;
							array[4] = 1784812840;
							array[5] = -157920620;
							array[6] = 1967466080;
							array[6] = array[5] ^ 0x37F82522;
							array[5] = array[6] ^ 0x7AE1FFE2;
							int[] array2 = new int[5];
							array2[0] = -769402415;
							array2[1] = 2042804091;
							array2[2] = -81075525;
							array2[3] = -465528590;
							array2[4] = -1171558360;
							array2[0] = array[2] ^ 0x63ED2DD7;
							array2[2] = array2[3] ^ -1020276900;
							array2[1] = array2[4] ^ 0x4FFC7D2A;
							int num15 = array2[0] ^ -1486448889;
							num = (int)((num4 * 1731323091) ^ 0x1DD0A31) ^ num15;
						}
						else
						{
							_0021_005E_003F_0024_002B_005E_0026_0024((IRelayCommand)ResetHwidCommand);
							int[,] array3 = new int[4, 4];
							array3[0, 0] = 1954005043;
							array3[0, 1] = 1537194898;
							array3[0, 2] = 1736084233;
							array3[0, 3] = -225904761;
							array3[1, 0] = 984501528;
							array3[1, 1] = -2132667758;
							array3[1, 2] = 551945126;
							array3[1, 3] = 1321854835;
							array3[2, 0] = 1408639400;
							array3[2, 1] = 739697253;
							array3[2, 2] = -152250848;
							array3[2, 3] = 1545694974;
							array3[3, 0] = 1671514986;
							array3[3, 1] = -1610572744;
							array3[3, 2] = 1839148147;
							array3[3, 3] = 156714113;
							array3[3, 3] = array3[1, 3] ^ 0x5E183ACA;
							array3[1, 0] = array3[0, 2] ^ -1150223851;
							array3[0, 1] = array3[3, 3] ^ -189219885;
							array3[1, 1] = array3[1, 2] ^ -1187614237;
							int num16 = array3[1, 1] ^ 0x2A85582B;
							num = ((int)num4 * -1131347277) ^ 0x70AC8D1D ^ num16;
						}
					}
					else
					{
						_0021_005E_003F_0024_002B_005E_0026_0024((IRelayCommand)SignInCommand);
						int[] array4 = new int[6];
						array4[0] = -2096497341;
						array4[1] = 227927139;
						array4[2] = -43341006;
						array4[3] = -1811427850;
						array4[4] = 784505080;
						array4[5] = -64671447;
						array4[3] = array4[5] ^ 0x4BBB4EDB;
						array4[1] = array4[5] ^ -1167299798;
						array4[0] = array4[2] ^ 0x54B927A1;
						int[] array5 = new int[4];
						array5[0] = -264341598;
						array5[1] = -643710352;
						array5[2] = -433350691;
						array5[3] = -866504883;
						array5[2] = array4[5] ^ -1300129107;
						array5[0] = array5[1] ^ 0x206A029B;
						array5[3] ^= -447783054;
						int num17 = array5[2] ^ -1920060850;
						num = (int)((num4 * 277731051) ^ 0x16060479) ^ num17;
					}
				}
			}
		}
	}

	public string LicenseKey
	{
		get
		{
			return _licenseKey;
		}
		set
		{
			SetProperty(ref _licenseKey, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x655 ^ 0x70F]);
		}
	}

	public IAsyncRelayCommand OpenUpdateCommand { get; }

	public IAsyncRelayCommand ResetHwidCommand { get; }

	public bool RememberLicense
	{
		get
		{
			return _rememberLicense;
		}
		set
		{
			SetProperty(ref _rememberLicense, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-706 + 358)]);
		}
	}

	public IAsyncRelayCommand SignInCommand { get; }

	public InfoBarSeverity StatusSeverity
	{
		get
		{
			SeverityLevel statusLevel = StatusLevel;
			InfoBarSeverity result = default(InfoBarSeverity);
			while (true)
			{
				int num = 425736546;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~((~(~(-(1234802129 * -107392474 * 796851361)) - -1008276799 * (-1897812085 * -2051241517 - (~-1983145988 + ~-2070707193))) - ((num2 ^ -((78302377 * (0x54B714CF ^ ((-(~81860933) - (0x7AC77250 ^ 0x48A83A85)) * -1468965977)) + -1534890410) ^ -(-((2062930981 * -(-1046396061 * -322307674)) ^ 0x2F2577B1) ^ -1617972562)) ^ -(~(((-(-(-1162425424)) + ~-160182912) ^ 0x7F1C5D84) + (-((0x36365320 ^ 0x437A5193) + (432037081 * 437659252 + -592720845 * -1271216803)) - (-5879384 + -1050198407 * (-947323515 * -2005067524)))))) - (-(~(-(~(-647887734))) ^ 0x655FF4F0) - -(395029631 * (-1561981635 * -(1790020288 * 755433017) - ~(0x4DCFA637 ^ -1843829000))))) + (((0x4D87D59D ^ -441902623) * 1313991645 - (507844984 + -1726663997) + 277369507 * (-1131667897 ^ -308583628)) ^ (16503025 * (629938768 + 1034155201) + ((-1477988733 ^ 0x5454A956) + ~-77966614) - ((-1675926787 - -923620209) * -1464507427 + -(-1432295117))))) * 879693159) ^ -1190755971) * 1988714849 * 30877489)) % 11;
					int num5 = 397198904;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 ^ -2135993978;
						num5 = -(num5 * -677662123);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 499362758;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 499362757;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -11;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = ~num9;
						}
						if (num3 == (uint)num9)
						{
							int[] array = new int[4] { -1353253426, 1891237343, -1529370055, -1285737629 };
							array[2] ^= -1997211020;
							array[0] = array[1] ^ -975272210;
							array[2] = array[1] ^ 0x23341BE0;
							int[] array2 = new int[5];
							array2[0] = -1134049448;
							array2[1] = 837008716;
							array2[2] = 1352722708;
							array2[3] = -895966187;
							array2[4] = -1051191226;
							array2[2] = array[1] ^ 0x39084462;
							array2[3] = array2[1] ^ -233746583;
							array2[4] ^= 25654617;
							int num11 = array2[2] ^ 0x48E24FDD;
							num = ((int)num4 * -479094340) ^ 0x5EC516D8 ^ num11;
							continue;
						}
						int num12 = 1600016905;
						_ = 0;
						for (int num13 = 0; num13 < 1; num13++)
						{
							num12 *= -494533233;
						}
						if (num3 == (uint)num12)
						{
							goto IL_0f19;
						}
						int num14 = -960428808;
						_ = 0;
						for (int num15 = 0; num15 < 1; num15++)
						{
							num14 *= -30344353;
						}
						if (num3 == (uint)num14)
						{
							int[] array3 = new int[7];
							array3[0] = -1796432342;
							array3[1] = 1103135042;
							array3[2] = -1723830824;
							array3[3] = -1412490597;
							array3[4] = 57394015;
							array3[5] = -631630644;
							array3[6] = 835027593;
							array3[5] = array3[4] ^ -1505296177;
							array3[5] = array3[1] ^ 0x35C578BC;
							int[] array4 = new int[6] { 1480145661, 158579501, -1380238150, 1718103698, -1103396852, 348680225 };
							int[][] array5 = new int[2][] { array3, array4 };
							array4[5] = array5[0][0] ^ 0x35E813D9;
							array4[1] = array4[4] ^ -1625129781;
							array4[2] = array4[3] ^ 0x592959DA;
							int num16 = array5[1][5] ^ 0x122059A5;
							num = (int)((num4 * 992501299) ^ 0xC4EC5180u) ^ num16;
							continue;
						}
						int num17 = -1777176423;
						_ = 0;
						for (int num18 = 0; num18 < 2; num18++)
						{
							num17 = ~(num17 ^ 0x204AC0DA);
							num17 = (num17 * -1005642387) ^ 0xDC3ABC8;
						}
						if (num3 != (uint)num17)
						{
							int num19 = -664292778;
							_ = 0;
							for (int num20 = 0; num20 < 2; num20++)
							{
								num19 = (num19 ^ -35396212) * 581622853;
								num19 = -(num19 + ~361192560);
							}
							if (num3 != (uint)num19)
							{
								int num21 = -1304439816;
								_ = 0;
								for (int num22 = 0; num22 < 2; num22++)
								{
									num21 = ~(~1539118750 - num21);
									num21 = ~num21 * -152281799;
								}
								if (num3 != (uint)num21)
								{
									int num23 = -766120330;
									_ = 0;
									for (int num24 = 0; num24 < 1; num24++)
									{
										num23 -= -766120339;
									}
									if (num3 != (uint)num23)
									{
										int num25 = 4;
										_ = 0;
										for (int num26 = 0; num26 < 2; num26++)
										{
											num25 = ~(num25 - -1174861127 * 1648744715);
											num25 = -(~num25);
										}
										if (num3 != (uint)num25)
										{
											int num27 = 1884551782;
											_ = 0;
											for (int num28 = 0; num28 < 1; num28++)
											{
												num27 ^= 0x7053FA65;
											}
											if (num3 != (uint)num27)
											{
											}
											return result;
										}
										result = InfoBarSeverity.Informational;
										num = -1289431978;
									}
									else
									{
										int[] array6 = new int[5];
										array6[0] = -1065959;
										array6[1] = 675879056;
										array6[2] = -915705172;
										array6[3] = -1940242925;
										array6[4] = 1847214262;
										array6[3] = array6[2] ^ -296309695;
										array6[0] ^= -1305430953;
										int[] array7 = new int[5] { 539203778, 1460936082, 1811727479, 1420830242, -836104887 };
										int[][] array8 = new int[2][] { array6, array7 };
										array7[4] = array8[0][4] ^ -1321134244;
										array7[3] ^= 1286824971;
										array7[3] ^= 1936710790;
										int num29 = array8[1][4] ^ 0x6C7F83BC;
										num = (int)((num4 * 1698890452) ^ 0x87CEE6D4u) ^ num29;
									}
									continue;
								}
								goto IL_098c;
							}
							int[] array9 = new int[5];
							array9[0] = -812306699;
							array9[1] = 334652500;
							array9[2] = -1167746884;
							array9[3] = -811161675;
							array9[4] = -37583755;
							array9[3] = array9[2] ^ -796798803;
							array9[0] = array9[4] ^ -192500706;
							int[] array10 = new int[5] { 2007895461, 209772505, 1856272909, 1579360653, 885847017 };
							int[][] array11 = new int[2][] { array9, array10 };
							array10[1] = array11[0][1] ^ 0x4EECB00F;
							array10[2] = array10[3] ^ 0x412F0AA4;
							array10[3] ^= 1353525586;
							array10[3] = array10[2] ^ -546333479;
							int num30 = array11[1][1] ^ -298188787;
							num = (int)((num4 * 1845803379) ^ 0x56F85F25) ^ num30;
							continue;
						}
					}
					else
					{
						switch (statusLevel)
						{
						case SeverityLevel.Warning:
							break;
						case SeverityLevel.Error:
							goto IL_098c;
						default:
							goto IL_0b92;
						case SeverityLevel.Success:
							goto IL_0f19;
						}
					}
					result = InfoBarSeverity.Warning;
					num = -1559945864;
					continue;
					IL_098c:
					result = InfoBarSeverity.Error;
					num = -1186654710;
					continue;
					IL_0f19:
					result = InfoBarSeverity.Success;
					num = -1736268429;
					continue;
					IL_0b92:
					int[,] array12 = new int[3, 4];
					array12[0, 0] = 237178567;
					array12[0, 1] = 697143797;
					array12[0, 2] = -568332630;
					array12[0, 3] = -1066810655;
					array12[1, 0] = 1852800088;
					array12[1, 1] = 166114881;
					array12[1, 2] = 372960111;
					array12[1, 3] = 620213317;
					array12[2, 0] = 1078010382;
					array12[2, 1] = 901505676;
					array12[2, 2] = -1207863031;
					array12[2, 3] = 80429295;
					array12[0, 0] = array12[2, 2] ^ 0x4F13A826;
					array12[2, 1] = array12[2, 2] ^ -1027721132;
					array12[1, 2] = array12[1, 3] ^ -206226199;
					array12[0, 0] = array12[1, 0] ^ -271127481;
					int num31 = array12[0, 0] ^ 0x6E1F04FA;
					num = ((int)num4 * -1007991082) ^ 0x245A9DE6 ^ num31;
				}
			}
		}
	}

	public unsafe SeverityLevel StatusLevel
	{
		get
		{
			return _statusLevel;
		}
		private set
		{
			if (!SetProperty(ref _statusLevel, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(328 + sizeof(int)) ^ sizeof(Guid)]))
			{
				return;
			}
			while (true)
			{
				int num = -2111074209;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-808992248 - -1218567255) + (-1887824810 + 1450372441) * -2114901361 - (-1210778443 - (-((num2 ^ (-1711565887 ^ (((-2137119875 ^ -469662298) + 1254108048 + ~(~((-715988084 ^ -2051673438) * -1801239175))) ^ ((-591776581 ^ 0x3EFCBD23) - (451458930 + (-1468343006 + (0x35742435 ^ 0x1345B10B))) - ~1289582890 + (~(-(1782726515 - 1639463995 - (0x20AF739A ^ -1338743378))) - -(~(-1582323978 ^ -1002834866)))) ^ -(--842208711 ^ (2108931927 * (-2041814275 ^ (-524788515 ^ (0xA3C6DB ^ -242516109)))))))) - ~(~1978942492)) + (-(-1350496802 - -501159814 + (-2011676719 - 1452160500) + -(--1253887770) + -339666059 * -(-1246322886 ^ 0x194DB8BF)) + ~(-(-(--2124067030) - -1524153053)))) * -1832590545))) % 3;
					int num5 = 65972414;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 * -2130758961;
						num5 = num5 ^ 0x2BAC9BE8 ^ -64689888;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1564996153;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 * 357027979;
						num7 = -num7 - 1163951572;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -938458126;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -938458128;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					_005E_0023_005E_003D_0026_0024_0025_002F((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(329 + sizeof(int)) ^ sizeof(Guid)]);
					int[] array = new int[6];
					array[0] = 1946236618;
					array[1] = 1136656885;
					array[2] = -71322477;
					array[3] = -310722667;
					array[4] = 1820776236;
					array[5] = -558179795;
					array[1] = array[5] ^ 0x156273D1;
					array[5] = array[1] ^ 0x1C437233;
					array[3] = array[4] ^ 0x340FA9FA;
					int[] array2 = new int[6] { 1895115982, -121013270, 1449942923, -469775845, 350817989, -1660772342 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][2] ^ 0x1FFB27D9;
					array2[4] = array2[5] ^ 0x5AD9CF95;
					array2[4] ^= 1334490913;
					array2[2] = array2[5] ^ 0x120153B1;
					int num11 = array3[1][0] ^ 0x708EF220;
					num = (int)((num4 * 652549882) ^ 0xD20DF55Cu) ^ num11;
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
			if (!SetProperty(ref _statusMessage, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-658 + 307)]))
			{
				return;
			}
			while (true)
			{
				int num = -1619612340;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-878842388 - ((((0x36E9867F ^ -1614333015) - -1700970 - (~(((~(~(--183935388 - -770285966) * 2137813343 + (-1848213765 * 1221524496 - -119425859 * -(2123586278 - 1537456164))) ^ (-(-1047247885 * (-1323816203 * -1531294976) + 989403944 * 627241567 * -429657033 - ((0x3177BCD3 ^ 0xA445DFD) - (0x4198957E ^ -745638223) + ~(530382148 + -1659753845))) + (8962232 + ((0x7A8A00B1 ^ (-407646188 * 1452331733)) + 1725798588)))) + ((-(~(~(1233089292 - -412424917) - (-1114434548 ^ -1761571688))) ^ 0x6334FBE) + (-2112048696 - ~(~(-434204112 - (1645874320 - 1385829643) + -1989105654 * -1569196743)))) - -num2 + (-(-(0x29D3FF8A ^ -976555538) ^ (-663350228 ^ -(-1432844409 * -1004380462)) ^ ~(-(~(~1234164498)))) ^ ((-(~(-(~-600912979))) ^ ~((-1726202151 - (0x7E564298 ^ 0x2C01CB78)) ^ -1095714627)) - ~(-(~(-975448415 * 447436649)) ^ (834928741 * (1769471542 - -138544344 + --390254042)))))) ^ 0x52D75705) ^ -(-2064144786))) * 1856506131) ^ -1830362342))) % 3;
					int num5 = 2;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 ^ 0x5354EE63);
						num5 = ~(-num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1135073695;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~1809967209 - num7;
						num7 = -num7 - -905053286;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2004082694;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 ^ -1539835471 ^ 0x37131D02;
							num9 = num9 + (-1783289172 ^ 0x1A118E26) - -435465226;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					_005E_0023_005E_003D_0026_0024_0025_002F((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x2AD8 ^ 0x2B87]);
					int[] array = new int[5] { -1699331310, 1547764309, 1188046526, -695317850, -1738130814 };
					array[0] ^= 381085559;
					array[0] = array[3] ^ 0x78B627F5;
					int[] array2 = new int[4];
					array2[0] = -1614464154;
					array2[1] = 70336738;
					array2[2] = 1799256357;
					array2[3] = 933412793;
					array2[1] = array[1] ^ 0x5A7B557B;
					array2[2] = array2[0] ^ 0x457BB1D1;
					array2[3] = array2[2] ^ -549120873;
					int num11 = array2[1] ^ 0x543A5AEA;
					num = (int)((num4 * 924877174) ^ 0xC2E8C9CCu) ^ num11;
				}
			}
		}
	}

	public LoginViewModel(AppViewModel appViewModel, IAuthenticationService authenticationService, ILauncherService launcherService, IStringResourceService strings)
	{
		while (true)
		{
			int num = -216241613;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(-(num2 ^ ((~(((~(~-509734834) * -429324763 - -(0x4B4475E6 ^ 0x29930AAE)) ^ -118856110) - (447292774 * 1049362305 * -1813015833 + 1000571255)) + (--466352103 ^ (38007117 * -(--1608246030) * -834333117) ^ (0x11AB029A ^ ~(-2135423565 * ~(-(-1724481883 - 22837327)))))) ^ -912775323)) + (--1971661529 - -((-(~(1217307304 - 1301685551)) * -1384660259) ^ -886417594))) + (-(0x1EEE80DE ^ (--244984624 ^ -553408580)) ^ (-1103526520 ^ ((-1973471551 - (0x13BC998F ^ 0x1C7C9CC7)) ^ (-467717774 - 1388465887)))))) % 9;
				int num5 = 1983048534;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = -(num5 - (-1931945109 + -1791983122));
					num5 = ~num5 * -1108435119;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 2147481089;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -(num7 ^ --1109986616);
					num7 -= 1149688449 * -364882814;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 483375413;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 += -483375407;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 640630616;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = num11 + (0x55FEFDB2 ^ -1152355523) + -1898557927;
							num11 = -num11 * 505817539;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -1064894723;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = (num13 + 316589731) * 286883379;
								num13 = (num13 * 2020650827) ^ -237465855;
							}
							if (num3 != (uint)num13)
							{
								int num15 = -171882362;
								_ = 0;
								for (int num16 = 0; num16 < 1; num16++)
								{
									num15 -= -171882362;
								}
								if (num3 != (uint)num15)
								{
									int num17 = -1655228;
									_ = 0;
									for (int num18 = 0; num18 < 1; num18++)
									{
										num17 = -1655225 - num17;
									}
									if (num3 != (uint)num17)
									{
										int num19 = -1028501584;
										_ = 0;
										for (int num20 = 0; num20 < 1; num20++)
										{
											num19 -= -1028501591;
										}
										if (num3 != (uint)num19)
										{
											int num21 = 4;
											_ = 0;
											for (int num22 = 0; num22 < 2; num22++)
											{
												num21 -= ~-1634066612;
												num21 = ~(num21 - (-1851858719 ^ 0x3DD5DABA));
											}
											if (num3 == (uint)num21)
											{
											}
											return;
										}
										SignInCommand = new AsyncRelayCommand(SignInAsync, CanSignIn);
										int[] array = new int[4] { 585402968, 1992108274, -1721916584, 149080262 };
										array[0] ^= 476000409;
										array[0] = array[1] ^ 0x736867FC;
										int[] array2 = new int[6] { 1545225859, 1250297553, -13254050, -696829279, -690944136, -960051973 };
										int[][] array3 = new int[2][] { array, array2 };
										array2[0] = array3[0][1] ^ 0x6E41B480;
										array2[2] = array2[1] ^ -1647800012;
										array2[5] = array2[3] ^ -807190628;
										int num23 = array3[1][0] ^ -1187565748;
										num = (int)((num4 * 655756152) ^ 0xC4279650u) ^ num23;
									}
									else
									{
										ResetHwidCommand = new AsyncRelayCommand(ResetHwidAsync, CanResetHwid);
										int[] array4 = new int[5];
										array4[0] = -707147142;
										array4[1] = -551993839;
										array4[2] = -1920153781;
										array4[3] = -1587350978;
										array4[4] = 1168498628;
										array4[1] = array4[2] ^ 0x6D384274;
										array4[0] = array4[4] ^ -2099513917;
										int[] array5 = new int[5] { 2084927353, -1068605859, 636569264, -48783195, -1983880786 };
										int[][] array6 = new int[2][] { array4, array5 };
										array5[0] = array6[0][2] ^ 0x7198BBC6;
										array5[1] = array5[0] ^ -815606692;
										array5[3] = array5[1] ^ -1692756259;
										array5[1] ^= 22547809;
										int num24 = array6[1][0] ^ 0x114151C7;
										num = ((int)num4 * -567777013) ^ 0x28CB7BE5 ^ num24;
									}
								}
								else
								{
									OpenUpdateCommand = new AsyncRelayCommand(OpenUpdateAsync, CanOpenUpdate);
									int[] array7 = new int[6] { -1431916240, 590326311, -1357443249, 1989283265, -902646661, -1960068230 };
									array7[3] ^= 1455265643;
									array7[5] = array7[1] ^ 0x14055E2;
									int[] array8 = new int[7];
									array8[0] = 440722925;
									array8[1] = -1674022476;
									array8[2] = -2000650158;
									array8[3] = -944257624;
									array8[4] = -756340486;
									array8[5] = 176557853;
									array8[6] = -983089397;
									array8[1] = array7[4] ^ 0xE3F4821;
									array8[6] = array8[1] ^ -1519871163;
									array8[5] = array8[2] ^ 0x53E75B51;
									array8[2] = array8[4] ^ 0x181F19C4;
									int num25 = array8[1] ^ 0x5F893D19;
									num = ((int)num4 * -1809145282) ^ 0x4ACF7054 ^ num25;
								}
							}
							else
							{
								_strings = strings;
								int[,] array9 = new int[3, 4];
								array9[0, 0] = -1601008824;
								array9[0, 1] = -1374766492;
								array9[0, 2] = 1628218382;
								array9[0, 3] = -375484854;
								array9[1, 0] = -95767629;
								array9[1, 1] = -1489080046;
								array9[1, 2] = 695409450;
								array9[1, 3] = -387213116;
								array9[2, 0] = -834552794;
								array9[2, 1] = -581488833;
								array9[2, 2] = -406032356;
								array9[2, 3] = -1762035129;
								array9[2, 3] = array9[0, 3] ^ -291639349;
								array9[0, 1] = array9[1, 2] ^ 0x52892E4F;
								array9[1, 1] = array9[0, 1] ^ 0x308BA972;
								array9[0, 3] = array9[0, 0] ^ -709364420;
								int num26 = array9[0, 3] ^ -420125826;
								num = (int)((num4 * 2022070917) ^ 0x44A3A73A) ^ num26;
							}
						}
						else
						{
							_launcherService = launcherService;
							int[] array10 = new int[6];
							array10[0] = -128871873;
							array10[1] = -1610067842;
							array10[2] = -1254974149;
							array10[3] = -1421734818;
							array10[4] = 1973506948;
							array10[5] = 1555969007;
							array10[1] = array10[5] ^ 0x776BC4EE;
							array10[2] = array10[5] ^ 0x888D7CF;
							int[] array11 = new int[6];
							array11[0] = 1102221507;
							array11[1] = 559533088;
							array11[2] = -1877999644;
							array11[3] = 1843752419;
							array11[4] = 1025188903;
							array11[5] = -2072565788;
							array11[4] = array10[4] ^ -1679319419;
							array11[5] = array11[3] ^ -1040021843;
							array11[3] = array11[1] ^ 0x5C1E5D5F;
							array11[3] = array11[1] ^ 0x30F034DB;
							int num27 = array11[4] ^ 0x2C40B827;
							num = ((int)num4 * -781953796) ^ 0x2CE02AB4 ^ num27;
						}
					}
					else
					{
						_authenticationService = authenticationService;
						int[,] array12 = new int[4, 4];
						array12[0, 0] = 1457825517;
						array12[0, 1] = -429148029;
						array12[0, 2] = -1793631013;
						array12[0, 3] = -1335835074;
						array12[1, 0] = 1224265383;
						array12[1, 1] = 1724190021;
						array12[1, 2] = 681697863;
						array12[1, 3] = -1252378720;
						array12[2, 0] = -304146505;
						array12[2, 1] = -104821072;
						array12[2, 2] = -1209361856;
						array12[2, 3] = 164809206;
						array12[3, 0] = 983824173;
						array12[3, 1] = 1517020110;
						array12[3, 2] = 525859348;
						array12[3, 3] = -93737999;
						array12[0, 1] = array12[1, 0] ^ -826378164;
						array12[1, 0] = array12[3, 1] ^ -263513838;
						array12[1, 3] = array12[1, 2] ^ 0x28781722;
						int num28 = array12[1, 3] ^ -1509568030;
						num = (int)((num4 * 1198485467) ^ 0x4C599E94) ^ num28;
					}
				}
				else
				{
					AppViewModel = appViewModel;
					int[,] array13 = new int[4, 3];
					array13[0, 0] = -342871657;
					array13[0, 1] = 409794855;
					array13[0, 2] = 1172809384;
					array13[1, 0] = -1346506824;
					array13[1, 1] = 1416231319;
					array13[1, 2] = 930891032;
					array13[2, 0] = -1257146077;
					array13[2, 1] = -905753960;
					array13[2, 2] = -948703569;
					array13[3, 0] = -1000794654;
					array13[3, 1] = 2073449048;
					array13[3, 2] = 1029018043;
					array13[3, 2] = array13[1, 0] ^ -1163303483;
					array13[0, 2] = array13[3, 1] ^ -717612739;
					array13[1, 0] = array13[0, 1] ^ 0x547A8A13;
					array13[3, 2] = array13[2, 0] ^ -304820876;
					int num29 = array13[3, 2] ^ -926818309;
					num = ((int)num4 * -1297604308) ^ -1969720492 ^ num29;
				}
			}
		}
	}

	[AsyncStateMachine(typeof(_003CInitializeAsync_003Ed__41))]
	public Task InitializeAsync()
	{
		_003CInitializeAsync_003Ed__41 stateMachine = default(_003CInitializeAsync_003Ed__41);
		stateMachine._003C_003Et__builder = _002D_002D_0023_0021_0026_003D_003C_0028();
		while (true)
		{
			int num = -815863550;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(~(((-990019751 * ~(0x6C94FCB4 ^ -1576622325) - -(~num2) * 1442744099 - (-((0x3091128C ^ 0x367BF964) * -623888999 + (-1985961540 - -2107665403 + (1185586891 - -962524553))) + 45105337)) * 1312522201 - (1180639596 - 1458887194 - ~-1935215153 + -(-1107181751 * -1221112957))) * -763138335)))) % 5;
				int num5 = 877450164;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~num5 * 1294110391;
					num5 -= -1909247478 ^ 0x763AA331;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1371772058;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -1995538437 - (num7 - 610304272);
					num7 = -num7 - 2071120193;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 830972281;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = num9 * 430285727 - -1451515549;
						num9 = (num9 * 855726163) ^ -1934439089;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -468218972;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 ^= -468218976;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -3;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 = -num13;
							}
							if (num3 != (uint)num13)
							{
							}
							return stateMachine._003C_003Et__builder.Task;
						}
						stateMachine._003C_003Et__builder.Start(ref stateMachine);
						int[] array = new int[6];
						array[0] = 301656327;
						array[1] = 591108072;
						array[2] = 1138076871;
						array[3] = 203010584;
						array[4] = 239917467;
						array[5] = 31321714;
						array[4] = array[0] ^ 0x2FE3FD57;
						array[3] = array[2] ^ 0x74931DBB;
						array[3] = array[4] ^ 0x7AA1A5B4;
						int[] array2 = new int[4];
						array2[0] = 1155256341;
						array2[1] = -1239210698;
						array2[2] = 1859927186;
						array2[3] = 2111953482;
						array2[0] = array[1] ^ -262958923;
						array2[1] ^= 1423465505;
						array2[2] = array2[3] ^ 0x5190E496;
						array2[1] = array2[0] ^ -913282743;
						int num15 = array2[0] ^ 0x1894D008;
						num = ((int)num4 * -509174397) ^ 0x3E65F283 ^ num15;
					}
					else
					{
						stateMachine._003C_003E1__state = -1;
						int[,] array3 = new int[4, 4];
						array3[0, 0] = -1419064871;
						array3[0, 1] = -1581141405;
						array3[0, 2] = -1984821828;
						array3[0, 3] = -2081090218;
						array3[1, 0] = 1742707351;
						array3[1, 1] = -1682408504;
						array3[1, 2] = -782798170;
						array3[1, 3] = -992621964;
						array3[2, 0] = 482753372;
						array3[2, 1] = -1141081280;
						array3[2, 2] = 1010788575;
						array3[2, 3] = 858365285;
						array3[3, 0] = -1424044702;
						array3[3, 1] = -691340263;
						array3[3, 2] = -675219132;
						array3[3, 3] = -171511450;
						array3[1, 2] = array3[1, 0] ^ 0x7854BCEE;
						array3[2, 1] ^= -733305603;
						array3[1, 0] = array3[3, 0] ^ -1101274683;
						array3[0, 0] = array3[3, 1] ^ -1246795178;
						int num16 = array3[0, 0] ^ 0x4C8B308A;
						num = (int)((num4 * 203149324) ^ 0x156678A4) ^ num16;
					}
				}
				else
				{
					stateMachine._003C_003E4__this = this;
					int[] array4 = new int[6];
					array4[0] = 169121111;
					array4[1] = -496525562;
					array4[2] = -1053040018;
					array4[3] = 1692933645;
					array4[4] = -1596218434;
					array4[5] = 239880430;
					array4[3] = array4[2] ^ 0x6A1A617F;
					array4[0] = array4[2] ^ 0x5FF48007;
					array4[2] = array4[3] ^ 0x3EBB6863;
					int[] array5 = new int[4] { -319182230, -744952150, -823176508, 1911043166 };
					int[][] array6 = new int[2][] { array4, array5 };
					array5[2] = array6[0][1] ^ -1885843547;
					array5[1] = array5[3] ^ 0x26456E3D;
					array5[1] = array5[3] ^ -998721798;
					array5[0] = array5[1] ^ 0x36C38E72;
					int num17 = array6[1][2] ^ 0x54147C;
					num = (int)((num4 * 917619789) ^ 0x685BB43A) ^ num17;
				}
			}
		}
	}

	private bool CanOpenUpdate()
	{
		return !__005E_002D_003D_0021_0021_002A_0024(AppViewModel.UpdateUrl);
	}

	private bool CanSignIn()
	{
		return !IsBusy;
	}

	private bool CanResetHwid()
	{
		if (!IsBusy)
		{
			uint num2;
			int num4;
			do
			{
				int num = 998361;
				uint num3;
				num2 = (num3 = (uint)((-(~(-(num ^ (1340673583 * (91430809 * (~((1028018335 * -1510457583 * -1431838223 + -(-1728733409 ^ -2116904347)) ^ (-1524187949 ^ -(390999802 - 1170056917))) + ((-375137912 ^ -(170085134 + 1866849941) ^ (1433050055 * (-632565377 ^ 0x1DD884D2))) + ((-972537727 ^ -962847374) - (-(~2129226384) + -679398775))))) - (((-711348781 * -685284499) ^ 0x3AF12056) - ((0x2701A880 ^ ((465540015 + (--1766951418 + (420841934 - 997541111)) + (-821526362 ^ -357643918 ^ (0x1BD6DC9C ^ --1015182841))) ^ (0x78103E2F ^ ((-1760859497 ^ 0x66675D3A) - ((0x11D7879 ^ 0x7F481052) - (795952506 - -1819541301)))))) + -229193727 * (-97363209 - (0x63CE75FF ^ -1850260642) + -174758956 * -1725265055))))))) + ((-65581653 ^ 0x426D7C7C) - -503219581)) * 215960155)) % 3;
				num4 = -1480456224;
				_ = 0;
				for (int num5 = 0; num5 < 1; num5++)
				{
					num4 ^= -1480456224;
				}
			}
			while (num2 == (uint)num4);
			int num6 = -1053858048;
			_ = 0;
			for (int num7 = 0; num7 < 1; num7++)
			{
				num6 -= -1053858050;
			}
			if (num2 == (uint)num6)
			{
				return !__005E_002D_003D_0021_0021_002A_0024(LicenseKey);
			}
			int num8 = -1094332925;
			_ = 0;
			for (int num9 = 0; num9 < 1; num9++)
			{
				num8 ^= -1094332926;
			}
			if (num2 == (uint)num8)
			{
			}
		}
		return false;
	}

	[AsyncStateMachine(typeof(_003COpenUpdateAsync_003Ed__45))]
	private Task OpenUpdateAsync()
	{
		_003COpenUpdateAsync_003Ed__45 stateMachine = default(_003COpenUpdateAsync_003Ed__45);
		stateMachine._003C_003Et__builder = _002D_002D_0023_0021_0026_003D_003C_0028();
		while (true)
		{
			int num = -1127716441;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(((~(num2 ^ (-844816257 * (-(344868285 * 1332524881) ^ (-140078053 * (~(~(~-2053081976 + (-1387703695 - -1113825727))) - -161885259 * -(-1888766686 ^ -802485154)) + (-271202098 + (0x59196989 ^ 0x62CCB81) - 2135833973))))) + -(429344582 + (~(-(~(-1805380957 ^ 0x2FC31B9E))) ^ -(~(0x329EAF8D ^ -824665570))))) ^ (-(-(0x391505BE ^ 0x22E40D02)) + 1714889721 + (-(-994628025 * (-1454453417 ^ -1807795344)) - ((-1488892568 - 1509022608) * 1328610823 - (-1535504561 ^ 0x53DF19FB))) - (~1157671487 * -1134748229 - -(~703038440 * 1293666503 - (80727638 * -2113430877 - 1490127201))))) * -1213258211))) % 5;
				int num5 = -1649165852;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 -= -412130221 - -182143315;
					num5 = ~(1552887627 - num5);
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
					int num9 = 796178521;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 = 796178523 - num9;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -2;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 = ~num11;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -4;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 = ~num13;
							}
							if (num3 != (uint)num13)
							{
							}
							return stateMachine._003C_003Et__builder.Task;
						}
						stateMachine._003C_003Et__builder.Start(ref stateMachine);
						int[] array = new int[6];
						array[0] = -1964752984;
						array[1] = 385107724;
						array[2] = -35817228;
						array[3] = 851036652;
						array[4] = 1735915857;
						array[5] = 1581171378;
						array[5] = array[0] ^ 0x2E18ECC7;
						array[4] = array[5] ^ 0x1AFB0790;
						int[] array2 = new int[7] { -646784959, -1507976955, 1346175321, 1207834395, -1053396371, 620131990, 1298400774 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][1] ^ 0x78804D6;
						array2[0] = array2[2] ^ 0x3786F433;
						array2[3] = array2[4] ^ -2026240495;
						int num15 = array3[1][1] ^ -16456111;
						num = ((int)num4 * -2098657764) ^ -867353876 ^ num15;
					}
					else
					{
						stateMachine._003C_003E1__state = -1;
						int[] array4 = new int[5] { 965794707, 1706948898, -1315013945, -720744339, -317632980 };
						array4[0] ^= 246375629;
						array4[3] = array4[1] ^ 0x4EF710BA;
						array4[3] = array4[0] ^ -962318190;
						int[] array5 = new int[5] { -1502970531, -577342120, -1300434608, 578977825, 1376060999 };
						int[][] array6 = new int[2][] { array4, array5 };
						array5[4] = array6[0][1] ^ 0x90C2F6B;
						array5[3] ^= -577925478;
						array5[0] = array5[2] ^ 0x3EB4C6A4;
						int num16 = array6[1][4] ^ -2118533124;
						num = (int)((num4 * 645092384) ^ 0x48DA5580) ^ num16;
					}
				}
				else
				{
					stateMachine._003C_003E4__this = this;
					int[,] array7 = new int[3, 4];
					array7[0, 0] = -1701918375;
					array7[0, 1] = 882967394;
					array7[0, 2] = -1779689198;
					array7[0, 3] = -1906290403;
					array7[1, 0] = 547555247;
					array7[1, 1] = 728631501;
					array7[1, 2] = -1932848275;
					array7[1, 3] = 2029285839;
					array7[2, 0] = 588854790;
					array7[2, 1] = 807341372;
					array7[2, 2] = -20816922;
					array7[2, 3] = -606908833;
					array7[2, 1] = array7[1, 0] ^ 0x633E7A84;
					array7[0, 0] = array7[1, 2] ^ -2015264026;
					array7[0, 1] = array7[0, 2] ^ 0x1389FFF5;
					int num17 = array7[0, 1] ^ -400807027;
					num = ((int)num4 * -453047358) ^ 0x5B002AC6 ^ num17;
				}
			}
		}
	}

	private void SetStatus(string message, SeverityLevel level)
	{
		StatusMessage = message;
		while (true)
		{
			int num = 1080362790;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(((num2 - (890713903 * (1241745959 * (((-959512098 ^ -(~(0x4340EBAE ^ 0x3C91C895))) - (~(-(~731517673)) ^ -1502856246)) ^ 0x359CEFBC)) - (2076546173 * -979729783 + -(-(-101499781 * (-316671715 * -1849657035 - (1558904299 + -667729158) + (-1779698821 * -1271865317 + (-1682009423 ^ -617696436)))) - (-194295565 - -1604769474) * 742595053))) - ((-1925463463 + ((0x25C76D39 ^ 0x7EFC556A) - (-1198995102 ^ -1133636617))) ^ (-((~(-(-497220771 + 1396383025)) + (-1488592979 * -2070314019 - (0x35C42575 ^ -971270581))) ^ -((-993700284 ^ 0x7C1E5242) * 1555461733)) + 289617977 * (-1963176116 - -(-74125095 ^ 0x332E0708))))) ^ ((1620587285 * (-(1844257591 * 799053338 + (-1035279804 ^ -1492060561)) + ~(-(306954612 + 1864656330)) - -534198318)) ^ (-1094915965 - -1627251453 + -64279832 * -895044865 - (~266109695 + (-2055589551 ^ -2008242038)) + -1951176110 - (-390536050 ^ 0x63EF559F) - -(0x38B643E7 ^ -1053785955) * 937182435))) * 196782575)) % 3;
				int num5 = 166102098;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~num5 + 83051049;
					num5 = ~num5;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -814399547;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 = -814399545 - num7;
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
				StatusLevel = level;
				int[] array = new int[4];
				array[0] = 1286666422;
				array[1] = -454138332;
				array[2] = -1184041018;
				array[3] = -870837070;
				array[0] = array[2] ^ -1028856359;
				array[0] = array[1] ^ -1819936572;
				array[2] = array[3] ^ -1318812444;
				int[] array2 = new int[6];
				array2[0] = -1239152874;
				array2[1] = 282900279;
				array2[2] = -1612211199;
				array2[3] = 1756164117;
				array2[4] = 1911383847;
				array2[5] = -741047548;
				array2[0] = array[3] ^ -2059316148;
				array2[2] ^= -723755042;
				array2[5] ^= -1460557163;
				int num11 = array2[0] ^ 0x2725965C;
				num = ((int)num4 * -523737054) ^ 0x1342D9DE ^ num11;
			}
		}
	}

	[AsyncStateMachine(typeof(_003CSignInAsync_003Ed__47))]
	private Task SignInAsync()
	{
		_003CSignInAsync_003Ed__47 stateMachine = default(_003CSignInAsync_003Ed__47);
		stateMachine._003C_003Et__builder = _002D_002D_0023_0021_0026_003D_003C_0028();
		while (true)
		{
			int num = 964307005;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(((-(-(-num2) * -24457107) ^ (~(~((0xD757F87 ^ 0xC5DD48) - (1785262774 - 711039664))) + -(58913168 * -1843467365))) * 1732904145 + (-839654172 ^ -1348812306)) * 4556253) + -1262542476)) % 5;
				int num5 = 4;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = -num5 - 1223567601;
					num5 = 1433327418 - ~num5;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -127508573;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 *= 1532893663;
					num7 = num7 * 1266784257 + 669268339;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -318895480;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = (num9 - 398451869 * 1837917926) ^ -836943164;
						num9 = (~-1138646618 - num9) ^ -777763452;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 981632845;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = num11 * -1583664365 * 656914391;
							num11 = (-1878374042 * -434666891 - num11) * -264987925;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 2;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = ~(-num13);
								num13 = ~(num13 + 998932203 * 1902346964);
							}
							if (num3 != (uint)num13)
							{
							}
							return stateMachine._003C_003Et__builder.Task;
						}
						stateMachine._003C_003Et__builder.Start(ref stateMachine);
						int[] array = new int[6];
						array[0] = 1732600833;
						array[1] = -772459010;
						array[2] = -269058655;
						array[3] = 200308463;
						array[4] = -1455952070;
						array[5] = -1231067108;
						array[4] = array[3] ^ 0x5736902A;
						array[4] = array[2] ^ -1128931396;
						int[] array2 = new int[5];
						array2[0] = -252444534;
						array2[1] = 499707949;
						array2[2] = 623926301;
						array2[3] = 525352328;
						array2[4] = -1346698947;
						array2[1] = array[1] ^ -1292519222;
						array2[3] = array2[0] ^ 0xE248616;
						array2[4] ^= 229118533;
						int num15 = array2[1] ^ -1661476134;
						num = (int)((num4 * 924842644) ^ 0xC4670904u) ^ num15;
					}
					else
					{
						stateMachine._003C_003E1__state = -1;
						int[] array3 = new int[6];
						array3[0] = -89995419;
						array3[1] = -1705839239;
						array3[2] = 1036473830;
						array3[3] = 941554260;
						array3[4] = 527225527;
						array3[5] = -1209931501;
						array3[0] = array3[2] ^ 0x67A30420;
						array3[3] ^= 1561572229;
						int[] array4 = new int[5];
						array4[0] = -1663189728;
						array4[1] = 1454817000;
						array4[2] = -2037428095;
						array4[3] = -1932015531;
						array4[4] = -816174088;
						array4[1] = array3[1] ^ 0x4919E6B;
						array4[0] = array4[3] ^ 0x36ED7FCB;
						array4[2] ^= -1716672241;
						int num16 = array4[1] ^ -1016175662;
						num = ((int)num4 * -762326388) ^ -1070111928 ^ num16;
					}
				}
				else
				{
					stateMachine._003C_003E4__this = this;
					int[] array5 = new int[7];
					array5[0] = -1726307178;
					array5[1] = 1897732885;
					array5[2] = 2102872539;
					array5[3] = 218995267;
					array5[4] = -1309332955;
					array5[5] = 121892963;
					array5[6] = -1868027504;
					array5[2] = array5[3] ^ 0x77E4E495;
					array5[4] = array5[5] ^ 0x52697054;
					array5[4] = array5[1] ^ 0x4717BEB4;
					int[] array6 = new int[4] { -1863557066, -1572746878, 1100373625, 1278276949 };
					int[][] array7 = new int[2][] { array5, array6 };
					array6[0] = array7[0][6] ^ -854786954;
					array6[3] = array6[2] ^ -960996738;
					array6[1] ^= -2089031943;
					int num17 = array7[1][0] ^ -2028376255;
					num = (int)((num4 * 187700484) ^ 0x1DA63630) ^ num17;
				}
			}
		}
	}

	[AsyncStateMachine(typeof(_003CResetHwidAsync_003Ed__48))]
	private Task ResetHwidAsync()
	{
		_003CResetHwidAsync_003Ed__48 stateMachine = default(_003CResetHwidAsync_003Ed__48);
		stateMachine._003C_003Et__builder = _002D_002D_0023_0021_0026_003D_003C_0028();
		while (true)
		{
			int num = -786479209;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(~(-num2) * 533894763))) % 5;
				int num5 = 2013790660;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = (num5 - ~-1859720964) ^ 0x53C2740C;
					num5 = -1141082461 - (num5 ^ --362183548);
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1078069249;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -(~num7);
					num7 = (num7 - (-185491767 - 1692755146)) ^ -1655244077;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1002075843;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = (num9 ^ -504676950) * 141262255;
						num9 = -num9 - -1937732312;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 104894464;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = (num11 - -1110759722) ^ -960595471;
							num11 = (num11 ^ -812729265) * 1451905025;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 1610653698;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = ~num13 + -1344484653;
								num13 = -num13 ^ -1943034050;
							}
							if (num3 != (uint)num13)
							{
							}
							return stateMachine._003C_003Et__builder.Task;
						}
						stateMachine._003C_003Et__builder.Start(ref stateMachine);
						int[] array = new int[7];
						array[0] = 394448909;
						array[1] = 656459331;
						array[2] = -27296944;
						array[3] = 284347837;
						array[4] = 524592894;
						array[5] = -1824982973;
						array[6] = -1905835308;
						array[1] = array[0] ^ 0x75506EEB;
						array[2] ^= 1524700699;
						int[] array2 = new int[5] { -764629970, -631352635, 1454376413, -1649042599, 486536736 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[3] = array3[0][5] ^ -1737377183;
						array2[4] ^= -1238397005;
						array2[1] ^= 2000687375;
						int num15 = array3[1][3] ^ 0x13F745BF;
						num = (int)((num4 * 1630418538) ^ 0x4A497A7C) ^ num15;
					}
					else
					{
						stateMachine._003C_003E1__state = -1;
						int[] array4 = new int[5];
						array4[0] = -704720661;
						array4[1] = -600700875;
						array4[2] = -623157015;
						array4[3] = -511825839;
						array4[4] = 1732864195;
						array4[1] = array4[3] ^ 0x19DA8CD8;
						array4[2] = array4[1] ^ -229280625;
						int[] array5 = new int[6] { 1850082663, 867127859, -117367882, -721503946, -441005985, 780262672 };
						int[][] array6 = new int[2][] { array4, array5 };
						array5[2] = array6[0][3] ^ 0x4A80719D;
						array5[3] = array5[2] ^ -1833954456;
						array5[0] = array5[4] ^ 0xF48AAD8;
						array5[1] = array5[4] ^ -288879965;
						int num16 = array6[1][2] ^ 0x62221DA3;
						num = (int)((num4 * 1725463379) ^ 0x9E5D5EA8u) ^ num16;
					}
				}
				else
				{
					stateMachine._003C_003E4__this = this;
					int[,] array7 = new int[3, 4];
					array7[0, 0] = 1998408217;
					array7[0, 1] = 492398434;
					array7[0, 2] = -1503823628;
					array7[0, 3] = 2088789054;
					array7[1, 0] = 393493638;
					array7[1, 1] = 1557082128;
					array7[1, 2] = 1389862116;
					array7[1, 3] = -2039487152;
					array7[2, 0] = -521486970;
					array7[2, 1] = -1316943762;
					array7[2, 2] = 657533434;
					array7[2, 3] = 586033558;
					array7[2, 3] = array7[1, 2] ^ -831347888;
					array7[1, 0] = array7[1, 2] ^ 0x25269D26;
					array7[1, 2] = array7[0, 0] ^ 0x63192D5A;
					int num17 = array7[1, 2] ^ 0x6FA339A;
					num = (int)((num4 * 122999577) ^ 0x97C4019Eu) ^ num17;
				}
			}
		}
	}

	static bool __005E_002D_003D_0021_0021_002A_0024(string P_0)
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
				int num = 1152793433;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(-((716312439 * ((1473644675 * -(0x1DAA4639 ^ -618097268)) ^ -214574057) + ~(-424172157) - (-num2 + -(0x4AA5AFAE ^ ~(-724466626 * 59985681 + (-318512569 + -1477174739) + ~(1635449405 * 2047019328) + ~(~(-889472557 - -1323602170)) - (1066302181 + ~(-853455400 - -468347263)))))) ^ (-1161523287 * (-1382353337 * ~(~235330182)) - (1571039883 * 671125961 + -(-567801283 * (-1196156165 ^ --395816915))))) - -(~(0x5B25F532 ^ -1191538938)) - (-1045817555 * (1413882360 + 1561064898) - -1086416227 * -94747005))) * 1205625463)) % 3;
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
					int num7 = 236935474;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(424322427 - 1925373464 - num7);
						num7 = (num7 ^ -826649179) * 1246433321;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1421619710;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = 1421619711 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = string.IsNullOrWhiteSpace(P_0);
					int[] array = new int[4] { -1142914375, 992979716, 763920828, 877598604 };
					array[2] ^= -1110194516;
					array[0] ^= -1154358469;
					int[] array2 = new int[7] { 844211256, -350694146, -1958163693, 2070856660, 2006931489, -293029006, 1173107990 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][1] ^ 0x1794F057;
					array2[2] = array2[5] ^ -294167287;
					array2[6] = array2[1] ^ 0x7CB90D2;
					int num11 = array3[1][4] ^ 0x126077B2;
					num = ((int)num4 * -2117112881) ^ -1002711808 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _0021_005E_003F_0024_002B_005E_0026_0024(IRelayCommand P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 641739341;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(-358387110) - (((~(-(-970389835 ^ 0x2D26720B) + -1723877642) - ~num2) ^ (-(511221799 * (-4388441 * (~(1687948993 + -1315236681) - (-138044789 ^ -1306122042)))) ^ ((0x2B245E00 ^ --1723234023) + 89643831 * (-((0x1298FA45 ^ -1798227062) + -702182223 * 1833351737) - (-1512448256 ^ 0x35BB2E5))))) + (-(-(-(~1517332254)) - (0x5319E087 ^ 0x6C5F171B)) + (-((-2033197175 - -1421916587) * -605585023 * -1072262417) ^ -(-(--1702543645) ^ 0x558C67E9))) - -1569678561 + (~(1302608283 - 1564160308) + (0x24984BAD ^ 0x1E0BC04E) + (-1307022961 ^ -42414350))) * -1837602223) ^ -1139335633)) % 3;
					int num5 = 167103394;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= -1819045071;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1781260497;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 1497860047;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -233651898;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= -233651898;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.NotifyCanExecuteChanged();
					int[,] array = new int[4, 4];
					array[0, 0] = 1774935596;
					array[0, 1] = -1860999339;
					array[0, 2] = 1067466272;
					array[0, 3] = 1437645144;
					array[1, 0] = -1668681779;
					array[1, 1] = 698622401;
					array[1, 2] = 1884765918;
					array[1, 3] = 1599787367;
					array[2, 0] = 497014882;
					array[2, 1] = -1567858777;
					array[2, 2] = 1641246158;
					array[2, 3] = -1453330010;
					array[3, 0] = -1651330817;
					array[3, 1] = -2072098976;
					array[3, 2] = -892858993;
					array[3, 3] = -1540589266;
					array[2, 0] = array[1, 2] ^ -1831490157;
					array[1, 2] ^= 1681069076;
					array[2, 2] = array[1, 3] ^ 0x63306F3A;
					array[1, 1] = array[0, 0] ^ -560680874;
					int num11 = array[1, 1] ^ 0x763AF284;
					num = ((int)num4 * -703404947) ^ -956205008 ^ num11;
				}
			}
		}
	}

	static void _005E_0023_005E_003D_0026_0024_0025_002F(ObservableObject P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1739885670;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((~(1558625842 - 1014531642) - ~(-(~((~(num2 ^ (-(~-1675471130) + (1623395647 * (-1426091108 ^ -(767480324 + 1971166609 * -334136089 + ~(--717279684))) - 160296709 * (-((--1475794703 ^ 0x49E3D23) - ~-716231238) + (-(~(-721945265 * -920753809)) + -167640828)) + -90737639 * ~(-1140170763 * 761273823)))) + (~((~(~(-1791606228 * -1164893891)) - -(1588620357 - -2117969508 - (-1595359059 ^ -666766686))) * -1076538211) - ~((-1625094526 + -96276352 - ~(-1164018830) - ((0x4F62D6A6 ^ -231057070) + -1617881273) * -988095225) * -1750187367))) * 536713951)))) ^ -1286971639))) % 3;
					int num5 = -841464056;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 * 1105665229);
						num5 = num5 - ~-574616589 - -193182643;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 4;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(-num7);
						num7 ^= -919033848;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(-num9);
							num9 = ~num9 - -1565946363;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.OnPropertyChanged(P_1);
					int[] array = new int[5] { -734772197, 707201421, 668171574, -515719288, 386158094 };
					array[1] ^= 373768500;
					array[0] = array[4] ^ -1750611477;
					int[] array2 = new int[5];
					array2[0] = 1681820577;
					array2[1] = 1113388931;
					array2[2] = -2052309479;
					array2[3] = 1050816744;
					array2[4] = 1541726632;
					array2[4] = array[3] ^ -1705026994;
					array2[1] = array2[3] ^ -972386121;
					array2[1] = array2[2] ^ -842820842;
					int num11 = array2[4] ^ 0x5AEAF476;
					num = ((int)num4 * -855402101) ^ 0x58404772 ^ num11;
				}
			}
		}
	}

	static AsyncTaskMethodBuilder _002D_002D_0023_0021_0026_003D_003C_0028()
	{
		AsyncTaskMethodBuilder result = default(AsyncTaskMethodBuilder);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 687229028;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((num2 ^ -((-(0x2A1F705E ^ -(-145931453 ^ 0xC9851E4) ^ -1178696475) ^ -(~(-(559866857 * -1071758775 + --278169831 + 1685549166)))) - (((-1533136745 * --1044601164) ^ (-1135326482 + (1536421713 * 1927423359 + --2071844547 + 1502283952)) ^ -(-(-473690033) - -(-195986435 - -1143640705))) - (-(1553385544 + (0x7E2190C2 ^ 0x18B62508)) + (0x29A444DA ^ (2123464858 - (-954948300 + 2123593709 * 1956912607 - -(-1161171311 - 1889208375)))))))) + ~(~(~(~(-1303895813 * (0x5BD82343 ^ -717053))) ^ (-2024835761 * (-(-490096168) - ~(~-2087688033)) + -1197774722))) - (~(-((-433799523 ^ 0x5B39AF23) + 1198356353 * (1112245765 * 2096826725)) - ~(-1283764832 ^ -1363219396)) - 806016999)) + (556768811 - (~(~(-336613007)) + (((-152383551 ^ -1901751937) + --1503971537) ^ -(-642896758 ^ -1063542048)))))) % 3;
					int num5 = 1434610218;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 * -1001726993) ^ -245457137;
						num5 = num5 + -578260583 * -974907584 - -1758871860;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 764453899;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -83245149;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 4;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9;
							num9 = ~(num9 ^ 0x5E97BD60);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = AsyncTaskMethodBuilder.Create();
					int[] array = new int[5] { 1775545987, 1768545265, 1437070140, -534386451, -148314104 };
					array[0] ^= 1289175903;
					array[3] = array[4] ^ 0x30D4E94B;
					int[] array2 = new int[7];
					array2[0] = -131157219;
					array2[1] = 545988863;
					array2[2] = -1051623471;
					array2[3] = 481182816;
					array2[4] = 229903661;
					array2[5] = 1504298938;
					array2[6] = 2061503591;
					array2[1] = array[2] ^ 0x59477EB8;
					array2[4] = array2[1] ^ -1528603767;
					array2[6] = array2[4] ^ -1074007849;
					array2[6] = array2[2] ^ -461983523;
					int num11 = array2[1] ^ 0x16B0863C;
					num = (int)((num4 * 636141545) ^ 0x307A012B) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}
}
