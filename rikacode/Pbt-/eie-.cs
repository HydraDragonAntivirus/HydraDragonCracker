using System;
using System.CodeDom.Compiler;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Markup;
using RikaNET.Core.Models;
using RikaNET.WinUI.ViewModels;
using RikaNET.WinUI.Views;
using Windows.Foundation;
using WinRT;

namespace Pbt_003D;

public sealed class eie_003D : Window, IComponentConnector
{
	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CTryLoadPendingAssemblyAsync_003Ed__10 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder _003C_003Et__builder;

		public eie_003D _003C_003E4__this;

		private TaskAwaiter _003C_003Eu__1;

		private void MoveNext()
		{
			int num = _003C_003E1__state;
			eie_003D eie_003D2 = _003C_003E4__this;
			try
			{
				if (num != 0)
				{
					goto IL_0023;
				}
				goto IL_1cd8;
				IL_0023:
				int num2 = -503680844;
				goto IL_0028;
				IL_0028:
				string Qqg_003D = default(string);
				TaskAwaiter awaiter = default(TaskAwaiter);
				while (true)
				{
					int num3 = num2;
					uint num5;
					uint num4 = (num5 = (uint)(-(-(~(~((~(~(-num3)) - (-(0x22C20BC8 ^ 0x4CFBEC27) - ~(-1793201377 * -153397608 + (0x4216FD1F ^ -2062172154)) + ~(-(1666111475 * -251695549) + (1289058831 + -734321588 - ~-1968486813)) - -(~569427132))) ^ (-(--1104600602) + ~(-694200415 ^ ~(--2023329931)))))) ^ 0x3F4D2574))) % 20;
					uint num6 = num4;
					int num7 = 1678727343;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(-num7);
						num7 = ~(num7 * 155496327);
					}
					if (num6 == (uint)num7)
					{
						break;
					}
					uint num9 = num4;
					int num10 = 20055061;
					_ = 0;
					for (int num11 = 0; num11 < 2; num11++)
					{
						num10 = ~(num10 - 1713076517 * 1546685071);
						num10 = ~(num10 ^ -1083808271);
					}
					if (num9 == (uint)num10)
					{
						bool ısAuthenticated = eie_003D2.DaU_003D.IsAuthenticated;
						int[,] array = new int[4, 3];
						array[0, 0] = -744531147;
						array[0, 1] = 40600611;
						array[0, 2] = -2118939275;
						array[1, 0] = 1246808466;
						array[1, 1] = 842692149;
						array[1, 2] = -84944033;
						array[2, 0] = -1019863956;
						array[2, 1] = -58649337;
						array[2, 2] = 2047719426;
						array[3, 0] = -817732686;
						array[3, 1] = -1646924377;
						array[3, 2] = 1696732835;
						array[1, 0] = array[3, 2] ^ 0x3B76C50A;
						array[2, 2] ^= -600755426;
						array[1, 1] = array[0, 2] ^ 0x69E13E4;
						int num12 = array[1, 1] ^ -2008747577;
						int[,] array2 = new int[3, 3];
						array2[0, 0] = -512997487;
						array2[0, 1] = -846793350;
						array2[0, 2] = -2114051357;
						array2[1, 0] = -1217050441;
						array2[1, 1] = 696821473;
						array2[1, 2] = 1541275601;
						array2[2, 0] = -1826394870;
						array2[2, 1] = -1351127601;
						array2[2, 2] = -1174166133;
						array2[2, 1] = array2[1, 1] ^ 0x52AFC46E;
						array2[2, 1] = array2[1, 2] ^ -740848334;
						array2[0, 0] = array2[0, 1] ^ 0x13D9DDE2;
						array2[2, 2] = array2[0, 2] ^ 0x42742F7F;
						int num13 = array2[2, 2] ^ -593051689;
						int num14 = ((int)num5 * -2127268989) ^ 0x10780E6B;
						num12 ^= num14;
						num13 ^= num14;
						int num15;
						int num16;
						if (!ısAuthenticated)
						{
							num15 = num13;
							num16 = num15;
						}
						else
						{
							num15 = num12;
							num16 = num15;
						}
						num2 = num15 ^ num14;
						continue;
					}
					uint num17 = num4;
					int num18 = 1833163982;
					_ = 0;
					for (int num19 = 0; num19 < 2; num19++)
					{
						num18 = (num18 - (61827683 + 34401493)) * -1118438363;
						num18 ^= 0x7DB6F3EB;
					}
					if (num17 != (uint)num18)
					{
						uint num20 = num4;
						int num21 = 637414567;
						_ = 0;
						for (int num22 = 0; num22 < 2; num22++)
						{
							num21 = (-2012257291 - num21) * 366216011;
							num21 = (num21 ^ --1082607391) + 1613736555;
						}
						if (num20 == (uint)num21)
						{
							int num23;
							if (AVZ_003D.rSb_003D(out Qqg_003D))
							{
								num2 = -720269114;
								num23 = num2;
							}
							else
							{
								num2 = -698594325;
								num23 = num2;
							}
							continue;
						}
						uint num24 = num4;
						int num25 = 1968081629;
						_ = 0;
						for (int num26 = 0; num26 < 2; num26++)
						{
							num25 = (num25 - (341515161 + -1049041867)) * -306011857;
							num25 = (num25 ^ 0x18A1EB01) + -526690594;
						}
						if (num24 == (uint)num25)
						{
							bool num27 = _003E_002B_003C_0024_0024__0026_003D(Qqg_003D);
							int[,] array3 = new int[3, 3];
							array3[0, 0] = 1602206904;
							array3[0, 1] = -81710660;
							array3[0, 2] = -1547273003;
							array3[1, 0] = -461311527;
							array3[1, 1] = 295670623;
							array3[1, 2] = 822695579;
							array3[2, 0] = -1091672165;
							array3[2, 1] = 1184586301;
							array3[2, 2] = -321800625;
							array3[0, 1] = array3[2, 2] ^ -177086123;
							array3[0, 1] = array3[1, 0] ^ -2077605244;
							array3[1, 0] = array3[1, 1] ^ -533535972;
							int num28 = array3[1, 0] ^ 0x39D57C62;
							int[] array4 = new int[6];
							array4[0] = -1872231744;
							array4[1] = -1885833398;
							array4[2] = 2050232570;
							array4[3] = 957722011;
							array4[4] = 766081768;
							array4[5] = -31460087;
							array4[0] = array4[1] ^ 0x50E9D249;
							array4[5] = array4[2] ^ 0x741E9CF5;
							int[] array5 = new int[7] { -1934483922, -1157301898, 57918417, -1286604293, 2083616362, 959108785, 1281079049 };
							int[][] array6 = new int[2][] { array4, array5 };
							array5[4] = array6[0][4] ^ 0x6051320;
							array5[0] = array5[3] ^ 0x71FEF798;
							array5[6] = array5[5] ^ -1766489940;
							array5[0] = array5[1] ^ -208406808;
							int num29 = array6[1][4] ^ -34594269;
							int num30 = (int)((num5 * 1332964780) ^ 0x74023394);
							num28 ^= num30;
							num29 ^= num30;
							int num31;
							int num32;
							if (num27)
							{
								num31 = num29;
								num32 = num31;
							}
							else
							{
								num31 = num28;
								num32 = num31;
							}
							num2 = num31 ^ num30;
							continue;
						}
						uint num33 = num4;
						int num34 = 2;
						_ = 0;
						for (int num35 = 0; num35 < 2; num35++)
						{
							num34 = ~(-num34);
							num34 = ~num34 - -223124930;
						}
						if (num33 != (uint)num34)
						{
							uint num36 = num4;
							int num37 = 1886506240;
							_ = 0;
							for (int num38 = 0; num38 < 2; num38++)
							{
								num37 = -(~num37);
								num37 = num37 * 952768767 - 1133347540;
							}
							if (num36 == (uint)num37)
							{
								awaiter = _0028_005E_005E_0028_0024_0040_005E_002D(eie_003D2.xAv_003D.ViewModel.LoadAssemblyAsync(Qqg_003D));
								num2 = 510816974;
								continue;
							}
							uint num39 = num4;
							int num40 = 943061531;
							_ = 0;
							for (int num41 = 0; num41 < 1; num41++)
							{
								num40 ^= 0x3835FA1C;
							}
							if (num39 == (uint)num40)
							{
								bool ısCompleted = awaiter.IsCompleted;
								int[,] array7 = new int[3, 4];
								array7[0, 0] = -214341420;
								array7[0, 1] = 1440589067;
								array7[0, 2] = -1462665470;
								array7[0, 3] = 1067637813;
								array7[1, 0] = -1991199351;
								array7[1, 1] = 1752145294;
								array7[1, 2] = -160057508;
								array7[1, 3] = 1955172441;
								array7[2, 0] = 2107991881;
								array7[2, 1] = -864496985;
								array7[2, 2] = 2002570733;
								array7[2, 3] = -2041546408;
								array7[1, 0] = array7[2, 1] ^ 0x44CBC53B;
								array7[1, 3] = array7[0, 0] ^ 0x338D86B1;
								array7[1, 1] = array7[0, 0] ^ 0x21C90075;
								array7[1, 0] = array7[0, 1] ^ -590029859;
								int num42 = array7[1, 0] ^ 0x541B4486;
								int[] array8 = new int[5];
								array8[0] = 683734849;
								array8[1] = -654078910;
								array8[2] = -946330583;
								array8[3] = 1303774048;
								array8[4] = -1053761498;
								array8[3] = array8[4] ^ 0x3DF4990D;
								array8[4] = array8[2] ^ 0x1B3FA0EA;
								array8[0] ^= 1307954175;
								int[] array9 = new int[5];
								array9[0] = -1077227288;
								array9[1] = 791472017;
								array9[2] = 1972501191;
								array9[3] = -37600493;
								array9[4] = 1534765334;
								array9[2] = array8[1] ^ 0x44D30262;
								array9[3] = array9[2] ^ -1629950564;
								array9[4] ^= 1751650721;
								int num43 = array9[2] ^ 0x2A434723;
								int num44 = (int)((num5 * 921948145) ^ 0x641A477);
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
								num2 = num45 ^ num44;
								continue;
							}
							uint num47 = num4;
							int num48 = 319924058;
							_ = 0;
							for (int num49 = 0; num49 < 1; num49++)
							{
								num48 *= -1561573043;
							}
							if (num47 == (uint)num48)
							{
								num = (_003C_003E1__state = 0);
								int[,] array10 = new int[4, 4];
								array10[0, 0] = 1745946209;
								array10[0, 1] = -983114951;
								array10[0, 2] = 1334498848;
								array10[0, 3] = -30642036;
								array10[1, 0] = -1642877777;
								array10[1, 1] = 623919929;
								array10[1, 2] = -990739429;
								array10[1, 3] = -631911514;
								array10[2, 0] = -761791463;
								array10[2, 1] = 2111566860;
								array10[2, 2] = 678518918;
								array10[2, 3] = -599975495;
								array10[3, 0] = -835175679;
								array10[3, 1] = -1339623509;
								array10[3, 2] = -1931643430;
								array10[3, 3] = -2109138404;
								array10[0, 1] = array10[0, 2] ^ 0x22CE5174;
								array10[1, 0] = array10[0, 3] ^ -505155667;
								array10[3, 2] = array10[1, 0] ^ 0x15CB4FB8;
								array10[2, 3] = array10[1, 3] ^ -1409049418;
								int num50 = array10[2, 3] ^ -636051730;
								num2 = (int)((num5 * 492353718) ^ 0x313605DC) ^ num50;
								continue;
							}
							uint num51 = num4;
							int num52 = 1215915690;
							_ = 0;
							for (int num53 = 0; num53 < 1; num53++)
							{
								num52 ^= 0x487966A1;
							}
							if (num51 == (uint)num52)
							{
								_003C_003Eu__1 = awaiter;
								int[,] array11 = new int[4, 3];
								array11[0, 0] = 986830672;
								array11[0, 1] = -1813799301;
								array11[0, 2] = 297392744;
								array11[1, 0] = 1981576282;
								array11[1, 1] = 338722689;
								array11[1, 2] = -1205255030;
								array11[2, 0] = -1670974228;
								array11[2, 1] = -784177358;
								array11[2, 2] = 2041141286;
								array11[3, 0] = 322753439;
								array11[3, 1] = -113262349;
								array11[3, 2] = -1335150033;
								array11[0, 1] = array11[0, 0] ^ 0x428054B8;
								array11[0, 1] = array11[3, 0] ^ -1226370706;
								array11[2, 2] = array11[2, 0] ^ 0x46A8F08B;
								array11[1, 1] = array11[1, 0] ^ -555470796;
								int num54 = array11[1, 1] ^ 0x7759E6FF;
								num2 = (int)((num5 * 296093533) ^ 0x6A26A3FB) ^ num54;
								continue;
							}
							uint num55 = num4;
							int num56 = 644707888;
							_ = 0;
							for (int num57 = 0; num57 < 1; num57++)
							{
								num56 *= 1952014923;
							}
							if (num55 == (uint)num56)
							{
								_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
								int[] array12 = new int[4];
								array12[0] = 1078994178;
								array12[1] = 43292349;
								array12[2] = 1994481858;
								array12[3] = -1583286061;
								array12[0] = array12[3] ^ -1191051691;
								array12[3] ^= -1298989577;
								array12[0] = array12[2] ^ -2078410042;
								int[] array13 = new int[6];
								array13[0] = -370086623;
								array13[1] = -307911593;
								array13[2] = 1969838333;
								array13[3] = 2127943099;
								array13[4] = -723074526;
								array13[5] = -1765946572;
								array13[1] = array12[1] ^ -1566568235;
								array13[2] = array13[4] ^ -591440410;
								array13[3] = array13[0] ^ -683060419;
								int num58 = array13[1] ^ -2087316651;
								num2 = ((int)num5 * -557536828) ^ 0x785F3F0 ^ num58;
								continue;
							}
							uint num59 = num4;
							int num60 = 8;
							_ = 0;
							for (int num61 = 0; num61 < 2; num61++)
							{
								num60 = -(~num60);
								num60 = -(num60 ^ 0x19F050B7);
							}
							if (num59 == (uint)num60)
							{
								return;
							}
							uint num62 = num4;
							int num63 = 744267103;
							_ = 0;
							for (int num64 = 0; num64 < 1; num64++)
							{
								num63 = 744267120 - num63;
							}
							if (num62 == (uint)num63)
							{
								goto IL_1cd8;
							}
							uint num65 = num4;
							int num66 = -1379732398;
							_ = 0;
							for (int num67 = 0; num67 < 2; num67++)
							{
								num66 = num66 * 18359111 - -1493961177;
								num66 = num66 ^ -707122459 ^ 0x356323EA;
							}
							if (num65 == (uint)num66)
							{
								_003C_003Eu__1 = default(TaskAwaiter);
								int[] array14 = new int[5];
								array14[0] = -1581361837;
								array14[1] = 1100122131;
								array14[2] = -442338696;
								array14[3] = -661906128;
								array14[4] = 1058101693;
								array14[0] = array14[4] ^ 0x715A208C;
								array14[1] ^= -763929568;
								array14[1] = array14[4] ^ 0x591E4B76;
								int[] array15 = new int[4];
								array15[0] = 1642288439;
								array15[1] = -1084163292;
								array15[2] = -1775883864;
								array15[3] = -509288281;
								array15[0] = array14[4] ^ -658670650;
								array15[3] = array15[2] ^ 0x50587277;
								array15[1] ^= 1352805705;
								int num68 = array15[0] ^ 0xE3585E;
								num2 = ((int)num5 * -809109750) ^ -988294036 ^ num68;
								continue;
							}
							uint num69 = num4;
							int num70 = 62389432;
							_ = 0;
							for (int num71 = 0; num71 < 2; num71++)
							{
								num70 = (num70 ^ 0x636C36FC) - -332315511;
								num70 = -(num70 + (-118424659 ^ 0x798B4148));
							}
							if (num69 == (uint)num70)
							{
								num = (_003C_003E1__state = -1);
								int[] array16 = new int[5];
								array16[0] = -414217139;
								array16[1] = -1541760629;
								array16[2] = -1953434213;
								array16[3] = -266752053;
								array16[4] = -745850530;
								array16[1] = array16[4] ^ -873693636;
								array16[2] = array16[4] ^ 0xB811B86;
								array16[3] = array16[2] ^ -10538046;
								int[] array17 = new int[6];
								array17[0] = 845643828;
								array17[1] = 635488570;
								array17[2] = 781753023;
								array17[3] = 545047179;
								array17[4] = 2015736301;
								array17[5] = -920362248;
								array17[1] = array16[0] ^ -1967976403;
								array17[2] = array17[0] ^ -1835614756;
								array17[4] = array17[2] ^ 0x1F2BCF99;
								array17[0] = array17[4] ^ -552862922;
								int num72 = array17[1] ^ -1326537168;
								num2 = (int)((num5 * 1773628611) ^ 0x6F38BDF0) ^ num72;
								continue;
							}
							uint num73 = num4;
							int num74 = -1861301619;
							_ = 0;
							for (int num75 = 0; num75 < 1; num75++)
							{
								num74 += 1861301632;
							}
							if (num73 == (uint)num74)
							{
								awaiter.GetResult();
								num2 = -709356152;
								continue;
							}
							uint num76 = num4;
							int num77 = 50335881;
							_ = 0;
							for (int num78 = 0; num78 < 2; num78++)
							{
								num77 = num77 - 1387676647 + 359325116;
								num77 ^= -1002658913;
							}
							if (num76 == (uint)num77)
							{
								eie_003D2.DaU_003D.Navigate(ShellSection.Workspace);
								int[] array18 = new int[5] { -644753930, -1988853996, -996107517, 1829444141, -2020580036 };
								array18[3] ^= 453082934;
								array18[0] = array18[2] ^ 0x6E1D6E78;
								int[] array19 = new int[4];
								array19[0] = -387338989;
								array19[1] = -1861616795;
								array19[2] = 1636230426;
								array19[3] = 1229950489;
								array19[0] = array18[4] ^ -1163671336;
								array19[3] = array19[0] ^ -703484563;
								array19[1] = array19[2] ^ 0x33FD3C2;
								int num79 = array19[0] ^ 0x3AE4E612;
								num2 = ((int)num5 * -618411826) ^ -1923656394 ^ num79;
								continue;
							}
							uint num80 = num4;
							int num81 = 3;
							_ = 0;
							for (int num82 = 0; num82 < 2; num82++)
							{
								num81 = -num81;
								num81 = num81 + (-874260825 - 1521972630) - -771914670;
							}
							if (num80 == (uint)num81)
							{
								eie_003D2.dTr_003D();
								int[] array20 = new int[6] { -419629698, -1250901041, -2068268973, 857380125, 846064622, 1646242053 };
								array20[2] ^= -920324581;
								array20[5] = array20[0] ^ 0x47ED06C8;
								int[] array21 = new int[4] { -164718103, 506733002, 1979834043, -2053396294 };
								int[][] array22 = new int[2][] { array20, array21 };
								array21[0] = array22[0][4] ^ 0x56A4110F;
								array21[3] = array21[0] ^ 0x1F3A933;
								array21[2] = array21[1] ^ 0x56D71100;
								int num83 = array22[1][0] ^ -824853516;
								num2 = ((int)num5 * -901232437) ^ -1362952971 ^ num83;
								continue;
							}
							uint num84 = num4;
							int num85 = -847457764;
							_ = 0;
							for (int num86 = 0; num86 < 2; num86++)
							{
								num85 = num85 * 1649499953 + -1691456044;
								num85 = -(-num85);
							}
							if (num84 == (uint)num85)
							{
								_0024_002B_0024_002F_0028_0024_002D_0021(eie_003D2.sDd_003D, (object)eie_003D2.mVZ_003D);
								int[,] array23 = new int[4, 4];
								array23[0, 0] = 28847876;
								array23[0, 1] = -472524792;
								array23[0, 2] = 1108395093;
								array23[0, 3] = -198673469;
								array23[1, 0] = 2025237487;
								array23[1, 1] = 854489590;
								array23[1, 2] = 970195541;
								array23[1, 3] = 1074291827;
								array23[2, 0] = 2147300099;
								array23[2, 1] = -691321141;
								array23[2, 2] = -1345765669;
								array23[2, 3] = 1834551043;
								array23[3, 0] = 179852833;
								array23[3, 1] = -892197504;
								array23[3, 2] = -705936263;
								array23[3, 3] = 1731085635;
								array23[2, 3] = array23[2, 1] ^ -1439784449;
								array23[0, 1] = array23[3, 0] ^ 0x5D76CC7A;
								array23[0, 1] = array23[1, 0] ^ 0x2F2AFC4F;
								array23[0, 1] = array23[0, 0] ^ 0x72AE9376;
								int num87 = array23[0, 1] ^ 0x6ED30401;
								num2 = (int)((num5 * 4682665) ^ 0x3B652B60) ^ num87;
								continue;
							}
							uint num88 = num4;
							int num89 = 1901982542;
							_ = 0;
							for (int num90 = 0; num90 < 2; num90++)
							{
								num89 -= -293047007 + 586717772;
								num89 = -num89 * -366418679;
							}
							if (num88 == (uint)num89)
							{
							}
						}
					}
					goto end_IL_001a;
				}
				goto IL_0023;
				IL_1cd8:
				awaiter = _003C_003Eu__1;
				num2 = 63870199;
				goto IL_0028;
				end_IL_001a:;
			}
			catch (Exception exception)
			{
				while (true)
				{
					int num91 = 533767608;
					while (true)
					{
						int num3 = num91;
						uint num5;
						uint num4 = (num5 = (uint)(-(-(~(~((~(~(-num3)) - (-(0x22C20BC8 ^ 0x4CFBEC27) - ~(-1793201377 * -153397608 + (0x4216FD1F ^ -2062172154)) + ~(-(1666111475 * -251695549) + (1289058831 + -734321588 - ~-1968486813)) - -(~569427132))) ^ (-(--1104600602) + ~(-694200415 ^ ~(--2023329931)))))) ^ 0x3F4D2574))) % 4;
						uint num92 = num4;
						int num93 = 452283446;
						_ = 0;
						for (int num94 = 0; num94 < 1; num94++)
						{
							num93 ^= 0x1AF54C36;
						}
						if (num92 == (uint)num93)
						{
							break;
						}
						uint num95 = num4;
						int num96 = -1;
						_ = 0;
						for (int num97 = 0; num97 < 1; num97++)
						{
							num96 = -num96;
						}
						if (num95 != (uint)num96)
						{
							uint num98 = num4;
							int num99 = -69849277;
							_ = 0;
							for (int num100 = 0; num100 < 2; num100++)
							{
								num99 = (num99 * -1627077791) ^ 0x1834C5C0;
								num99 = -num99 ^ -452221816;
							}
							if (num98 != (uint)num99)
							{
								uint num101 = num4;
								int num102 = 1291102421;
								_ = 0;
								for (int num103 = 0; num103 < 1; num103++)
								{
									num102 -= 1291102419;
								}
								if (num101 == (uint)num102)
								{
								}
								return;
							}
							_003C_003Et__builder.SetException(exception);
							int[] array24 = new int[4];
							array24[0] = -164094076;
							array24[1] = -567851743;
							array24[2] = 1711626532;
							array24[3] = -1583956679;
							array24[2] = array24[1] ^ -179172502;
							array24[2] = array24[3] ^ -1560963900;
							int[] array25 = new int[4] { 380207717, -207431764, -1286045984, -2146765773 };
							int[][] array26 = new int[2][] { array24, array25 };
							array25[2] = array26[0][3] ^ 0x4B0D0B9F;
							array25[1] = array25[0] ^ 0x5BF3D5BE;
							array25[0] = array25[2] ^ -2012426985;
							array25[3] = array25[0] ^ -404555861;
							int num104 = array26[1][2] ^ 0x13535C59;
							num91 = ((int)num5 * -407759911) ^ -2083141357 ^ num104;
						}
						else
						{
							_003C_003E1__state = -2;
							int[,] array27 = new int[4, 4];
							array27[0, 0] = -1431904956;
							array27[0, 1] = 334985147;
							array27[0, 2] = 141164315;
							array27[0, 3] = -1536663126;
							array27[1, 0] = -1608735284;
							array27[1, 1] = -218922585;
							array27[1, 2] = 698886310;
							array27[1, 3] = -337043642;
							array27[2, 0] = -1860003031;
							array27[2, 1] = 375100398;
							array27[2, 2] = -450379357;
							array27[2, 3] = -1191277800;
							array27[3, 0] = 321444160;
							array27[3, 1] = 438226812;
							array27[3, 2] = 1729767632;
							array27[3, 3] = 960890167;
							array27[2, 2] = array27[0, 1] ^ 0x730D240;
							array27[1, 0] = array27[2, 2] ^ -819929618;
							array27[1, 3] = array27[0, 3] ^ 0x4FC5B9CD;
							int num105 = array27[1, 3] ^ 0x26A398C5;
							num91 = ((int)num5 * -712680218) ^ 0x4301B94E ^ num105;
						}
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num106 = 627445094;
				while (true)
				{
					int num3 = num106;
					uint num5;
					uint num4 = (num5 = (uint)(-(-(~(~((~(~(-num3)) - (-(0x22C20BC8 ^ 0x4CFBEC27) - ~(-1793201377 * -153397608 + (0x4216FD1F ^ -2062172154)) + ~(-(1666111475 * -251695549) + (1289058831 + -734321588 - ~-1968486813)) - -(~569427132))) ^ (-(--1104600602) + ~(-694200415 ^ ~(--2023329931)))))) ^ 0x3F4D2574))) % 3;
					uint num107 = num4;
					int num108 = -2;
					_ = 0;
					for (int num109 = 0; num109 < 1; num109++)
					{
						num108 = -num108;
					}
					if (num107 == (uint)num108)
					{
						break;
					}
					uint num110 = num4;
					int num111 = 772632672;
					_ = 0;
					for (int num112 = 0; num112 < 1; num112++)
					{
						num111 += -772632671;
					}
					if (num110 != (uint)num111)
					{
						uint num113 = num4;
						int num114 = 1611043716;
						_ = 0;
						for (int num115 = 0; num115 < 2; num115++)
						{
							num114 = num114 ^ 0x5CB9E06 ^ -681271520;
							num114 = ((0x53725A78 ^ 0x156F299) - num114) ^ -1888723220;
						}
						if (num113 == (uint)num114)
						{
						}
						return;
					}
					_003C_003Et__builder.SetResult();
					int[] array28 = new int[6];
					array28[0] = -391677565;
					array28[1] = 1902225879;
					array28[2] = -527403090;
					array28[3] = -1403861281;
					array28[4] = 1475588044;
					array28[5] = -212948994;
					array28[5] = array28[3] ^ -1434993018;
					array28[5] = array28[4] ^ -1912449726;
					int[] array29 = new int[4] { -1741212325, -1269156822, -1684548349, 1882622317 };
					int[][] array30 = new int[2][] { array28, array29 };
					array29[0] = array30[0][4] ^ -599503338;
					array29[3] = array29[0] ^ 0x3AAD0636;
					array29[1] ^= -1395100479;
					int num116 = array30[1][0] ^ 0x7ED54DBF;
					num106 = (int)((num5 * 1822292573) ^ 0xBCAA9CF3u) ^ num116;
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

		static bool _003E_002B_003C_0024_0024__0026_003D(string P_0)
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
					int num = 1357685992;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(((-num2 ^ (-((0x3BCC61D5 ^ ((0x4DE52C57 ^ -1130841944) + (-1947084401 - 631879371))) - ~(1024708721 * ((319987820 + 1139991554) * 723043487)) * -100231275) ^ -877322206)) + (~((-1670761525 ^ 0xFEF84C3) + (-224414033 ^ -(-1770756338 ^ 0x5B9C2B27))) + (~(-(--121703559)) - ~((0x64FCE7C0 ^ 0x467FFB1D) + (1817977098 + 1190348336)) + ~(-(-1524995262 ^ -357145338) * 1072007281)) - ((1426165285 * -354326718) ^ 0x6919F2D0))) ^ ((((0x68C6E8FC ^ -2762150) - -(~-947607540) + (-(0x1E8B632D ^ 0x1D7F4348) ^ -2125934353)) ^ 0x78F5A481) + (-(~(834544242 - 1564459463)) ^ ~(-(~396925852))) * -1687067601))) % 3;
						int num5 = -1037326732;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = num5 * 498763703 - 612822167;
							num5 = ~num5 * -1448669351;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 409337895;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~num7 ^ -1261095489;
							num7 -= -1894528493;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 411177038;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = --528296708 - num9;
								num9 = ((-321312775 ^ -7064346) - num9) ^ -501549503;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = string.IsNullOrWhiteSpace(P_0);
						int[,] array = new int[4, 4];
						array[0, 0] = -1982841966;
						array[0, 1] = 10863578;
						array[0, 2] = 1086979314;
						array[0, 3] = 494523264;
						array[1, 0] = 462410570;
						array[1, 1] = -2097359272;
						array[1, 2] = 485718667;
						array[1, 3] = 620662526;
						array[2, 0] = 1860016620;
						array[2, 1] = -189449845;
						array[2, 2] = -36752284;
						array[2, 3] = 730837103;
						array[3, 0] = -1151019577;
						array[3, 1] = -395479137;
						array[3, 2] = 46502401;
						array[3, 3] = -645131358;
						array[2, 3] = array[1, 3] ^ 0xB76C158;
						array[2, 1] = array[1, 2] ^ -1816490230;
						array[2, 3] = array[1, 2] ^ -2053979927;
						int num11 = array[2, 3] ^ -411523201;
						num = ((int)num4 * -1645626551) ^ 0x294DC3A1 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static TaskAwaiter _0028_005E_005E_0028_0024_0040_005E_002D(Task P_0)
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
					int num = 2115767865;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-516823234 - (((~(-(((num2 ^ (101379443 * (-852063113 + (1779260190 + ~(-1640618390 - (0x3C747702 ^ 0x3B287F0C) - (-1588048627 + -405405713 - (-1697637456 ^ -795776098)))) - -(-365508593 + 1959507455 + (1554160909 + -736806088) + -(1669117219 * -1197026905) - ~(~1398710660) * 1993732235 - (-1563355855 - -309989627)) + 1669632157 * ((-(-(391108667 + -2139913771)) ^ 0x14E008CD) + (517855501 * 712447959 + -1976328074 + (-1335916885 ^ -346149321)) - 581041669 * (-183852294 ^ -1730992733))))) - (--1679719965 - -(~(656393192 * -1189376477) - ~(1971105779 + ~((1110370428 + 1323754515) * 1018785849))))) * -354275353)) * 1399979931) ^ (~(-2019825276 + 1769540022) - (~838601055 + --1123702974))) - (~2038613879 - (-1960206238 ^ 0x3C222A11))))) % 3;
						int num5 = -662410780;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -(num5 * -1011383219);
							num5 = -195909829 - -num5;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1270179853;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 *= 1703487173;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -363724430;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 ^= -363724432;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						awaiter = P_0.GetAwaiter();
						int[,] array = new int[3, 3];
						array[0, 0] = 485354133;
						array[0, 1] = 851626328;
						array[0, 2] = 1459225751;
						array[1, 0] = 1820589939;
						array[1, 1] = -1113795735;
						array[1, 2] = 1465989203;
						array[2, 0] = 825909608;
						array[2, 1] = 2072746258;
						array[2, 2] = 475011596;
						array[2, 1] = array[2, 0] ^ -885448717;
						array[0, 2] = array[1, 1] ^ 0x6B64CC6F;
						array[2, 2] = array[0, 0] ^ 0x2D01FD87;
						int num11 = array[2, 2] ^ 0x37C7291B;
						num = ((int)num4 * -213888925) ^ 0x6A3DE86D ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return awaiter;
		}

		static void _0024_002B_0024_002F_0028_0024_002D_0021(NavigationView P_0, object P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 792787026;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((-(~(~((-1211543152 + -278610751) ^ 0x514F330D)) - -(-(-(-931255113 * ((-1321079637 + 883366210 - --458774190 + (0x19876CA1 ^ 0x79CD8B2)) * -1675590967))) - (num2 * 1470456353 + (-(((((--1101518087 ^ -216670928) + -1542283169) ^ -(--801925223)) + ~(-(0x2500306A ^ 0x35B492E7))) * -1813484331) ^ 0x23AD2D95))) - (-(-(471602804 - 2009068852)) + (-256622075 * -1657685671 + (2114199648 + 79375874)) * -1987043885) - (-915807074 ^ -(-656701156 ^ -1690899425))) ^ -705688722) * 1126277795)) % 3;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = ~num5 - -640194246;
							num5 -= -784398299;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -1619160091;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = (-906710011 - -628297492 - num7) ^ 0x507BFF9B;
							num7 = -1699940025 - ~num7;
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
						P_0.SelectedItem = P_1;
						int[] array = new int[5] { -1687515052, 2004617357, -914594497, 1269829050, -1186790261 };
						array[4] ^= -1362410421;
						array[3] = array[4] ^ 0x2AD05EDF;
						array[0] = array[3] ^ -2059252953;
						int[] array2 = new int[6] { -2123687293, -569063446, 25939225, -205342239, 1202784083, 1277850793 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][1] ^ 0x3728F195;
						array2[2] = array2[4] ^ -284487228;
						array2[2] = array2[3] ^ 0x3B95DC86;
						int num11 = array3[1][1] ^ -1407584259;
						num = ((int)num4 * -1782697863) ^ 0x75556B9E ^ num11;
					}
				}
			}
		}
	}

	private readonly MethodsView kuV_003D;

	private readonly SettingsView IQI_003D;

	private readonly WorkspaceView xAv_003D;

	[CompilerGenerated]
	private readonly AppViewModel Cgw_003D;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private Window AUl_003D;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private Grid ZvE_003D;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private Grid ooe_003D;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private LoginView rpw_003D;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private NavigationView sDd_003D;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private NavigationViewItem mVZ_003D;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private NavigationViewItem nfB_003D;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private NavigationViewItem hYn_003D;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private ContentPresenter wEo_003D;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private bool DnV_003D;

	public AppViewModel DaU_003D
	{
		[CompilerGenerated]
		get
		{
			return Cgw_003D;
		}
	}

	public eie_003D()
	{
		while (true)
		{
			int num = -1365121080;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)((-((((num2 ^ -(-1224507277 * -(0x284648C ^ (-1765795783 ^ (--1735155995 - -((1350985667 + 1900403128) * 824888501))))) ^ ~((-(1881111364 + (~-1623493792 - ~-1882125008)) - (--602871268 ^ 0x5AC78B90) - (~(~(-221250700 * 853176221) + (0x655DC574 ^ -77625107)) - ((0x744027A1 ^ --2101278561 ^ -353432572) + ((-1087642779 ^ -860445529) + -2073532547)))) ^ -(-1383119653 * (0x3C8C8E64 ^ -1791553877)))) * 142924281) ^ (0xC341B76 ^ -(~1239019838 * -2065809779 + ~(0x58C27946 ^ -1047286541) - (0x450D4EDF ^ (1231579661 * -26931161))))) + -(~(1437983619 + 761042083) + -1283395766) * -963062391) - ~-1869362891 - -1079669515 * 2026745868) ^ -1337071514)) % 17;
				int num5 = -1958971969;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 -= -1958971978;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -2138439099;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = num7 - (1587894914 + 429471460) + -685534005;
					num7 = ~(num7 ^ 0x40D56974);
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1072055969;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = (num9 ^ 0x3C955697) * -955172385;
						num9 = (num9 ^ -254210246) - 265855772;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 1622457377;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = num11 + ~-1975215737 + 1048205634;
							num11 = -1687166403 - -num11;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -1495136447;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 -= -1495136448;
							}
							if (num3 != (uint)num13)
							{
								int num15 = -836603513;
								_ = 0;
								for (int num16 = 0; num16 < 2; num16++)
								{
									num15 = -num15 - -1979316815;
									num15 = (num15 - (0x449CE5C ^ 0x6AD2E961)) * -1638340255;
								}
								if (num3 != (uint)num15)
								{
									int num17 = 329025107;
									_ = 0;
									for (int num18 = 0; num18 < 1; num18++)
									{
										num17 ^= 0x139C865D;
									}
									if (num3 != (uint)num17)
									{
										int num19 = -962080072;
										_ = 0;
										for (int num20 = 0; num20 < 1; num20++)
										{
											num19 *= -115568281;
										}
										if (num3 != (uint)num19)
										{
											int num21 = -7;
											_ = 0;
											for (int num22 = 0; num22 < 1; num22++)
											{
												num21 = ~num21;
											}
											if (num3 != (uint)num21)
											{
												int num23 = -1;
												_ = 0;
												for (int num24 = 0; num24 < 1; num24++)
												{
													num23 = ~num23;
												}
												if (num3 != (uint)num23)
												{
													int num25 = -1124026203;
													_ = 0;
													for (int num26 = 0; num26 < 1; num26++)
													{
														num25 += 1124026208;
													}
													if (num3 != (uint)num25)
													{
														int num27 = -583015486;
														_ = 0;
														for (int num28 = 0; num28 < 2; num28++)
														{
															num27 = ~(num27 * -2128681059);
															num27 = 661390769 - (num27 ^ 0x7E0699CA);
														}
														if (num3 != (uint)num27)
														{
															int num29 = -1422416818;
															_ = 0;
															for (int num30 = 0; num30 < 2; num30++)
															{
																num29 = -num29 + -1339419661;
																num29 = ~628211243 - num29;
															}
															if (num3 != (uint)num29)
															{
																int num31 = -320439054;
																_ = 0;
																for (int num32 = 0; num32 < 1; num32++)
																{
																	num31 *= -143262995;
																}
																if (num3 != (uint)num31)
																{
																	int num33 = 462406068;
																	_ = 0;
																	for (int num34 = 0; num34 < 1; num34++)
																	{
																		num33 *= 13683759;
																	}
																	if (num3 != (uint)num33)
																	{
																		int num35 = 4;
																		_ = 0;
																		for (int num36 = 0; num36 < 2; num36++)
																		{
																			num35 = -(~num35);
																			num35 = -(num35 ^ --261137929);
																		}
																		if (num3 != (uint)num35)
																		{
																			int num37 = 931918627;
																			_ = 0;
																			for (int num38 = 0; num38 < 2; num38++)
																			{
																				num37 = -(num37 ^ -414213823);
																				num37 = (num37 - -695584370) * -292313853;
																			}
																			if (num3 == (uint)num37)
																			{
																			}
																			return;
																		}
																		igp_003D();
																		int[] array = new int[6];
																		array[0] = -256128749;
																		array[1] = 753371581;
																		array[2] = -1080286253;
																		array[3] = -1836236365;
																		array[4] = 506289409;
																		array[5] = 1614999283;
																		array[3] = array[1] ^ -1381650313;
																		array[4] = array[5] ^ 0x36B2314F;
																		int[] array2 = new int[7] { -2012630954, 166944135, 1072786623, 169714508, -1571509346, -2080463247, 1994968319 };
																		int[][] array3 = new int[2][] { array, array2 };
																		array2[0] = array3[0][2] ^ -971064461;
																		array2[2] = array2[4] ^ -1411616873;
																		array2[6] = array2[1] ^ -976786781;
																		int num39 = array3[1][0] ^ 0x10916163;
																		num = ((int)num4 * -689629904) ^ -1159294848 ^ num39;
																	}
																	else
																	{
																		dTr_003D();
																		int[] array4 = new int[7] { -856039661, 159037874, 1317539186, -681834147, 933732144, -1038876420, -939672316 };
																		array4[0] ^= 820258671;
																		array4[3] = array4[4] ^ -884929711;
																		array4[6] ^= -1400542810;
																		int[] array5 = new int[7];
																		array5[0] = 1103018343;
																		array5[1] = -1785631571;
																		array5[2] = 839893312;
																		array5[3] = 1551075808;
																		array5[4] = -1145994524;
																		array5[5] = -548634692;
																		array5[6] = 2025231046;
																		array5[5] = array4[4] ^ -1861272303;
																		array5[0] = array5[5] ^ 0x3E7FE6CC;
																		array5[4] = array5[5] ^ -66344591;
																		int num40 = array5[5] ^ -726504852;
																		num = ((int)num4 * -1103728199) ^ -1187469431 ^ num40;
																	}
																}
																else
																{
																	MAj_003D();
																	int[] array6 = new int[5];
																	array6[0] = 738297314;
																	array6[1] = -627320913;
																	array6[2] = 856637494;
																	array6[3] = 1268920053;
																	array6[4] = -2050845594;
																	array6[4] = array6[3] ^ 0x723E7AED;
																	array6[2] ^= -1176208177;
																	array6[2] = array6[4] ^ 0x475A7979;
																	int[] array7 = new int[7];
																	array7[0] = -98801628;
																	array7[1] = 1889180091;
																	array7[2] = -1800708747;
																	array7[3] = -2133963576;
																	array7[4] = -274118565;
																	array7[5] = 2009677206;
																	array7[6] = -1991796015;
																	array7[1] = array6[1] ^ -1143164736;
																	array7[0] = array7[5] ^ 0xD7758FD;
																	array7[0] = array7[5] ^ 0x5EAB3D78;
																	array7[4] = array7[1] ^ 0x72614AAA;
																	int num41 = array7[1] ^ 0x468B02A3;
																	num = (int)((num4 * 781399571) ^ 0x9F7F1638u) ^ num41;
																}
															}
															else
															{
																_0021_0023_002B__002B_0023_003F_0028((Window)this, DaU_003D.WindowTitle);
																int[,] array8 = new int[3, 3];
																array8[0, 0] = 392101100;
																array8[0, 1] = 1984074744;
																array8[0, 2] = 26762789;
																array8[1, 0] = -298917340;
																array8[1, 1] = 1585264412;
																array8[1, 2] = 622708827;
																array8[2, 0] = 292201067;
																array8[2, 1] = 219463216;
																array8[2, 2] = -1033843779;
																array8[1, 1] = array8[0, 1] ^ -1549222313;
																array8[0, 1] = array8[2, 0] ^ 0xA8AEAF5;
																array8[1, 1] = array8[0, 1] ^ 0x37188A59;
																array8[1, 2] = array8[2, 0] ^ -535826387;
																int num42 = array8[1, 2] ^ 0x12319A5B;
																num = ((int)num4 * -931401303) ^ -1170439129 ^ num42;
															}
														}
														else
														{
															__0026_0023_0023_003F_002F_0029_0024((ObservableObject)DaU_003D, (PropertyChangedEventHandler)uip_003D);
															int[,] array9 = new int[3, 4];
															array9[0, 0] = 1990643064;
															array9[0, 1] = -1274277785;
															array9[0, 2] = 1656829771;
															array9[0, 3] = 180568923;
															array9[1, 0] = -1265522144;
															array9[1, 1] = -2051278432;
															array9[1, 2] = -1995574072;
															array9[1, 3] = 1943823065;
															array9[2, 0] = 81862675;
															array9[2, 1] = 770893946;
															array9[2, 2] = 244947941;
															array9[2, 3] = -1162369683;
															array9[2, 0] = array9[2, 1] ^ -721223253;
															array9[1, 1] = array9[2, 2] ^ -1472772241;
															array9[2, 1] = array9[1, 0] ^ 0x596E358B;
															array9[1, 0] = array9[1, 3] ^ 0x53F684CC;
															int num43 = array9[1, 0] ^ 0x342FA8DB;
															num = (int)((num4 * 911625215) ^ 0xC9FB5B88u) ^ num43;
														}
													}
													else
													{
														_0024_0024_0028_005E_005E_005E_003F_002F(_003D_0024_003E_0029_003F_003C_0025_((Window)this), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4153 - 4226 + 82]);
														int[] array10 = new int[7];
														array10[0] = 1334306336;
														array10[1] = 1425633188;
														array10[2] = 974381823;
														array10[3] = 1710005540;
														array10[4] = -294162967;
														array10[5] = -795366658;
														array10[6] = -1723792034;
														array10[4] = array10[1] ^ 0x4321862;
														array10[4] = array10[1] ^ -1753826812;
														array10[3] = array10[6] ^ -766769182;
														int[] array11 = new int[6];
														array11[0] = -1630795806;
														array11[1] = 2044645371;
														array11[2] = 258212017;
														array11[3] = 443663436;
														array11[4] = 1267139495;
														array11[5] = 1783386360;
														array11[0] = array10[1] ^ 0x67FD8761;
														array11[5] ^= -1830399944;
														array11[3] = array11[2] ^ -463065378;
														array11[1] = array11[5] ^ -556075117;
														int num44 = array11[0] ^ 0x78B93628;
														num = ((int)num4 * -309183992) ^ -1320929560 ^ num44;
													}
												}
												else
												{
													_0024_003F_0026_003E_0028_003C_003E_0021((Window)this, (UIElement)ooe_003D);
													int[] array12 = new int[6] { -273948961, -1992412831, -247453281, 557907969, 1348257750, -733761608 };
													array12[5] ^= -1331745622;
													array12[2] ^= -556876506;
													array12[4] = array12[0] ^ 0xA2274CA;
													int[] array13 = new int[7];
													array13[0] = 392770910;
													array13[1] = -1075023252;
													array13[2] = -1975855914;
													array13[3] = 1621733393;
													array13[4] = -1617687259;
													array13[5] = -1391187725;
													array13[6] = -1401507248;
													array13[3] = array12[1] ^ 0x14A22B9B;
													array13[4] = array13[6] ^ 0x4CC69E76;
													array13[5] = array13[3] ^ -579019858;
													array13[5] = array13[3] ^ 0x70227E3A;
													int num45 = array13[3] ^ 0x7B820D2;
													num = (int)((num4 * 1948429534) ^ 0x9B7CCD92u) ^ num45;
												}
											}
											else
											{
												_0028_003C_003C_003D_002A_0029_003E_0024((Window)this, true);
												int[] array14 = new int[5] { -530810742, -1167632898, 1955498290, 1182650323, -1856123330 };
												array14[0] ^= 1202604498;
												array14[0] = array14[1] ^ -492070241;
												array14[0] = array14[4] ^ 0x16EA3C58;
												int[] array15 = new int[7] { -849340077, -1617749170, -1586028134, -1813830268, 199691384, -477613197, 696846199 };
												int[][] array16 = new int[2][] { array14, array15 };
												array15[5] = array16[0][2] ^ 0x6E45D6D9;
												array15[0] ^= -1836023731;
												array15[1] = array15[6] ^ 0x1C4A7DB6;
												int num46 = array16[1][5] ^ 0x31C433ED;
												num = ((int)num4 * -303687723) ^ -1601196828 ^ num46;
											}
										}
										else
										{
											__0026_0023_0023_003F_002F_0029_0024((ObservableObject)xAv_003D.ViewModel, (PropertyChangedEventHandler)UMc_003D);
											int[] array17 = new int[6] { 1163478961, -1135020185, -1528058981, 660147727, -123149991, -441022378 };
											array17[2] ^= 662828177;
											array17[1] = array17[5] ^ 0x235E0404;
											array17[2] = array17[5] ^ 0x269CB1FA;
											int[] array18 = new int[6];
											array18[0] = -176568605;
											array18[1] = 1693415482;
											array18[2] = 1805723341;
											array18[3] = -1458431222;
											array18[4] = 1320059630;
											array18[5] = 965171677;
											array18[0] = array17[5] ^ 0x5DCF78D0;
											array18[2] = array18[4] ^ -1978973319;
											array18[2] ^= 1321850393;
											int num47 = array18[0] ^ 0x463E0C1F;
											num = (int)((num4 * 1308884243) ^ 0xA78F722Bu) ^ num47;
										}
									}
									else
									{
										IQI_003D = new SettingsView();
										int[,] array19 = new int[4, 4]
										{
											{ 1479261526, -1778123514, 99049168, 276704114 },
											{ 2105094217, 341568700, 176056736, 566811759 },
											{ -1540386638, 1123912284, -1558629871, 273439924 },
											{ -1760760186, -1358578301, 36671132, 1615869108 }
										};
										array19[2, 2] ^= 549495932;
										array19[0, 0] = array19[3, 0] ^ 0x50432D68;
										array19[1, 3] = array19[1, 0] ^ -980146373;
										int num48 = array19[1, 3] ^ 0x5B6F9936;
										num = ((int)num4 * -934831661) ^ 0x262233ED ^ num48;
									}
								}
								else
								{
									kuV_003D = new MethodsView();
									int[] array20 = new int[5];
									array20[0] = -322153244;
									array20[1] = 1420895245;
									array20[2] = -1471275464;
									array20[3] = -330880563;
									array20[4] = -39827459;
									array20[0] = array20[4] ^ -661665400;
									array20[4] = array20[2] ^ -1317681583;
									int[] array21 = new int[7] { 1130952956, 1301221341, 499100770, 1271035102, -1669797906, 443821246, -1690469700 };
									int[][] array22 = new int[2][] { array20, array21 };
									array21[1] = array22[0][1] ^ 0x105E2F17;
									array21[3] = array21[0] ^ 0x670016C;
									array21[5] = array21[6] ^ -230618075;
									array21[6] = array21[0] ^ -1057729249;
									int num49 = array22[1][1] ^ -1134148060;
									num = (int)((num4 * 1320855500) ^ 0x1020BC48) ^ num49;
								}
							}
							else
							{
								xAv_003D = new WorkspaceView();
								int[,] array23 = new int[4, 3];
								array23[0, 0] = -985146572;
								array23[0, 1] = -672549086;
								array23[0, 2] = -346561787;
								array23[1, 0] = -1542147699;
								array23[1, 1] = 656079448;
								array23[1, 2] = 1641505853;
								array23[2, 0] = -1174344937;
								array23[2, 1] = 692516005;
								array23[2, 2] = 1380007197;
								array23[3, 0] = -285310233;
								array23[3, 1] = 944289833;
								array23[3, 2] = 476288399;
								array23[1, 1] = array23[3, 2] ^ 0x62E14F0E;
								array23[2, 1] = array23[2, 0] ^ -1212684107;
								array23[3, 0] ^= -475077085;
								array23[3, 0] = array23[1, 0] ^ 0x128A5CE;
								int num50 = array23[3, 0] ^ -1977416164;
								num = ((int)num4 * -1045425719) ^ 0x3D4624F2 ^ num50;
							}
						}
						else
						{
							_002F_003E_0040_005E_0025_0026_002B_0021((FrameworkElement)ZvE_003D, (object)DaU_003D);
							int[,] array24 = new int[3, 4];
							array24[0, 0] = 1178523334;
							array24[0, 1] = 1263065858;
							array24[0, 2] = 1456499886;
							array24[0, 3] = -54374504;
							array24[1, 0] = 1986595116;
							array24[1, 1] = 152941517;
							array24[1, 2] = 793340592;
							array24[1, 3] = 1745288700;
							array24[2, 0] = 1296370080;
							array24[2, 1] = -388571762;
							array24[2, 2] = 1365800994;
							array24[2, 3] = -2143267424;
							array24[1, 1] = array24[0, 1] ^ -1221926043;
							array24[1, 1] = array24[0, 3] ^ -1810450133;
							array24[2, 3] = array24[0, 0] ^ 0x5D442E96;
							array24[0, 0] = array24[1, 2] ^ -1166495262;
							int num51 = array24[0, 0] ^ 0x6B721DE9;
							num = ((int)num4 * -679102832) ^ 0x16E3DF40 ^ num51;
						}
					}
					else
					{
						vjV_003D();
						int[] array25 = new int[4];
						array25[0] = 1449570541;
						array25[1] = -779080976;
						array25[2] = -687748495;
						array25[3] = -1535850218;
						array25[0] = array25[3] ^ 0x1E18344D;
						array25[2] ^= 700693806;
						int[] array26 = new int[4];
						array26[0] = 90114248;
						array26[1] = 1011179450;
						array26[2] = -1512114571;
						array26[3] = -991077083;
						array26[1] = array25[1] ^ 0x68A21B93;
						array26[2] = array26[1] ^ 0x57D32CC7;
						array26[3] ^= 290233298;
						int num52 = array26[1] ^ 0xDB2FD7A;
						num = (int)((num4 * 297470621) ^ 0x9660F54Cu) ^ num52;
					}
				}
				else
				{
					Cgw_003D = AVZ_003D.TbG_003D.GetRequiredService<AppViewModel>();
					int[] array27 = new int[5];
					array27[0] = -1752299314;
					array27[1] = -51818086;
					array27[2] = -319595402;
					array27[3] = 2093112193;
					array27[4] = -1989481659;
					array27[3] = array27[2] ^ -1998940721;
					array27[2] ^= -223881924;
					array27[4] = array27[3] ^ 0x7CA4463C;
					int[] array28 = new int[7] { -883491908, -1326997879, 289615384, 613591243, -766688505, 1792616170, 2052068294 };
					int[][] array29 = new int[2][] { array27, array28 };
					array28[6] = array29[0][0] ^ -899862896;
					array28[1] ^= -797898217;
					array28[5] ^= -1620021977;
					array28[0] ^= -1390780862;
					int num53 = array29[1][6] ^ 0x56709DF;
					num = ((int)num4 * -1217285253) ^ 0x72C0A64F ^ num53;
				}
			}
		}
	}

	private void nTp_003D(NavigationView KyD_003D, NavigationViewSelectionChangedEventArgs faN_003D)
	{
		if (!DaU_003D.IsAuthenticated)
		{
			goto IL_0013;
		}
		goto IL_1e50;
		IL_0013:
		int num = -890502934;
		goto IL_0018;
		IL_0018:
		AppViewModel viewModel = default(AppViewModel);
		ShellSection section = default(ShellSection);
		string text = default(string);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)(-(~(-(-141196822 + -1077516875) * 791287227) * -976643303 - (-num2 + ((((-(0x3B6D60FF ^ -1617414530) ^ ((~-1174677845 - (-905645768 ^ -2066793596)) * 841463967 - (--496032634 * 1878500587 - (-297608952 - ~-424091205)))) + -1086821053 * (0x6C99EB2B ^ -132186235)) * -1789058871) ^ (-1266900797 * (((0x3372E8E9 ^ -(~-1093571610) ^ 0x5AAF9B62) * -1432585479) ^ (0x6770FE8C ^ (-1965163015 * (0x6AB9F2E5 ^ (--429246308 + -1024865225 * -373096531))))))) - (-1721396685 - -(632016407 - (-1003533122 - 1944030814)) + 1872915068 + (-1469717708 + -160921084 - ~-17828755 + (0x799642FE ^ 0x5F2BABD2) + ~(~(524764428 - -1417726079)) + 762768167) + -(-(~(-(~1746944702) - ((0x51E25FD7 ^ -1974564527) + ~1290845968)))))) * 1450729459))) % 21;
			int num5 = -281851612;
			_ = 0;
			for (int num6 = 0; num6 < 2; num6++)
			{
				num5 = -(num5 * 1806825253);
				num5 = ~(num5 * -484329145);
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = 1136034125;
			_ = 0;
			for (int num8 = 0; num8 < 1; num8++)
			{
				num7 *= -744203101;
			}
			if (num3 == (uint)num7)
			{
				return;
			}
			int num9 = -757595518;
			_ = 0;
			for (int num10 = 0; num10 < 2; num10++)
			{
				num9 = (num9 - (221022926 + -1784204091)) * 1081847225;
				num9 = -(-num9);
			}
			if (num3 != (uint)num9)
			{
				int num11 = -1235007583;
				_ = 0;
				for (int num12 = 0; num12 < 2; num12++)
				{
					num11 = (num11 ^ 0x4A8748C0) - 1871522038;
					num11 *= -1618899001;
				}
				if (num3 != (uint)num11)
				{
					int num13 = 1520213998;
					_ = 0;
					for (int num14 = 0; num14 < 1; num14++)
					{
						num13 += -1520213988;
					}
					if (num3 == (uint)num13)
					{
						return;
					}
					int num15 = 15;
					_ = 0;
					for (int num16 = 0; num16 < 2; num16++)
					{
						num15 = -(num15 + ~151163572);
						num15 -= -301728434 - 473012899;
					}
					int num70;
					if (num3 != (uint)num15)
					{
						int num17 = -6;
						_ = 0;
						for (int num18 = 0; num18 < 1; num18++)
						{
							num17 = -num17;
						}
						if (num3 != (uint)num17)
						{
							int num19 = 18;
							_ = 0;
							for (int num20 = 0; num20 < 2; num20++)
							{
								num19 = -(num19 ^ -119731052);
								num19 = -(-num19);
							}
							if (num3 != (uint)num19)
							{
								int num21 = -1686444433;
								_ = 0;
								for (int num22 = 0; num22 < 2; num22++)
								{
									num21 = ~num21 * 2036293723;
									num21 *= 736879333;
								}
								if (num3 != (uint)num21)
								{
									int num23 = 1317990267;
									_ = 0;
									for (int num24 = 0; num24 < 2; num24++)
									{
										num23 = (num23 ^ 0x348597FA) * 674719949;
										num23 -= -298073809 + 1129550311;
									}
									if (num3 == (uint)num23)
									{
										return;
									}
									int num25 = 503643618;
									_ = 0;
									for (int num26 = 0; num26 < 2; num26++)
									{
										num25 = -(num25 + 115850788 * -881891573);
										num25 = (num25 ^ -1723891279) * -190278233;
									}
									if (num3 != (uint)num25)
									{
										int num27 = 369661069;
										_ = 0;
										for (int num28 = 0; num28 < 2; num28++)
										{
											num27 = ~(num27 * 1681691355);
											num27 = -(~num27);
										}
										if (num3 != (uint)num27)
										{
											int num29 = -1200693742;
											_ = 0;
											for (int num30 = 0; num30 < 1; num30++)
											{
												num29 += 1200693750;
											}
											if (num3 != (uint)num29)
											{
												int num31 = 1938029164;
												_ = 0;
												for (int num32 = 0; num32 < 2; num32++)
												{
													num31 = -num31 ^ 0x209560AF;
													num31 = -num31 - -1715151576;
												}
												if (num3 != (uint)num31)
												{
													int num33 = 16;
													_ = 0;
													for (int num34 = 0; num34 < 2; num34++)
													{
														num33 = ~(num33 ^ 0x6093FF88);
														num33 = -num33 ^ -396386833;
													}
													if (num3 != (uint)num33)
													{
														int num35 = -1238729996;
														_ = 0;
														for (int num36 = 0; num36 < 2; num36++)
														{
															num35 *= 435489389;
															num35 = 452982209 - (num35 + 273514867 * 36256123);
														}
														if (num3 != (uint)num35)
														{
															int num37 = -53467827;
															_ = 0;
															for (int num38 = 0; num38 < 1; num38++)
															{
																num37 *= 891114453;
															}
															if (num3 != (uint)num37)
															{
																int num39 = 1073736719;
																_ = 0;
																for (int num40 = 0; num40 < 2; num40++)
																{
																	num39 = ~num39 ^ 0x16D6E5B8;
																	num39 = -(num39 - (1959103223 + 2144395758));
																}
																if (num3 != (uint)num39)
																{
																	int num41 = 2108813285;
																	_ = 0;
																	for (int num42 = 0; num42 < 2; num42++)
																	{
																		num41 = (num41 * 599283273) ^ -1096180043;
																		num41 = -(-num41);
																	}
																	if (num3 != (uint)num41)
																	{
																		int num43 = -343605085;
																		_ = 0;
																		for (int num44 = 0; num44 < 1; num44++)
																		{
																			num43 += 343605088;
																		}
																		if (num3 != (uint)num43)
																		{
																			int num45 = 176150676;
																			_ = 0;
																			for (int num46 = 0; num46 < 1; num46++)
																			{
																				num45 ^= 0xA7FD89A;
																			}
																			if (num3 == (uint)num45)
																			{
																			}
																			return;
																		}
																		viewModel.Navigate(section);
																		num = -443711877;
																	}
																	else
																	{
																		section = ShellSection.Workspace;
																		num = 39429545;
																	}
																}
																else
																{
																	int[] array = new int[5];
																	array[0] = -474712830;
																	array[1] = -1252454711;
																	array[2] = -2024352688;
																	array[3] = -1165938169;
																	array[4] = -1140407640;
																	array[0] = array[3] ^ -941686859;
																	array[3] = array[1] ^ -789000745;
																	array[1] = array[0] ^ 0x161A5D75;
																	int[] array2 = new int[4] { -1118223359, 1117157784, -933353017, -1458987075 };
																	int[][] array3 = new int[2][] { array, array2 };
																	array2[1] = array3[0][2] ^ -2100878348;
																	array2[2] ^= -1144044163;
																	array2[0] = array2[2] ^ 0x38A05BE7;
																	array2[3] = array2[1] ^ 0x5B2C3617;
																	int num47 = array3[1][1] ^ 0x7C8520D;
																	num = (int)((num4 * 1361173529) ^ 0x2C036AF1) ^ num47;
																}
															}
															else
															{
																section = ShellSection.Settings;
																num = -769284241;
															}
														}
														else
														{
															int[] array4 = new int[4] { -1780033317, 1614777495, -349724076, 604816303 };
															array4[0] ^= 1934811864;
															array4[2] ^= -477787510;
															array4[0] = array4[1] ^ -1985901246;
															int[] array5 = new int[7];
															array5[0] = 2132223065;
															array5[1] = -1441473904;
															array5[2] = -1736094896;
															array5[3] = 2107512166;
															array5[4] = 618871845;
															array5[5] = -1740752770;
															array5[6] = -1409011713;
															array5[3] = array4[1] ^ 0x7E5A38C5;
															array5[0] = array5[3] ^ -1011904339;
															array5[0] = array5[1] ^ 0x5A65CF7F;
															int num48 = array5[3] ^ 0x1C3C11FB;
															num = (int)((num4 * 1023030862) ^ 0xC38D8188u) ^ num48;
														}
													}
													else
													{
														section = ShellSection.Methods;
														num = -317726018;
													}
												}
												else
												{
													int[] array6 = new int[4];
													array6[0] = 1787296950;
													array6[1] = 1727829185;
													array6[2] = -1650347322;
													array6[3] = -1415470862;
													array6[1] = array6[3] ^ -81162071;
													array6[2] ^= -2029674941;
													array6[2] = array6[3] ^ -1990198154;
													int[] array7 = new int[6] { 2111850334, -1863379653, 2032807675, -1644513619, 187826585, -853614975 };
													int[][] array8 = new int[2][] { array6, array7 };
													array7[4] = array8[0][3] ^ -730916156;
													array7[5] = array7[0] ^ 0x495802DA;
													array7[2] ^= 1012992701;
													array7[1] = array7[5] ^ -770862706;
													int num49 = array8[1][4] ^ 0x56B0D86E;
													num = (int)((num4 * 1140016821) ^ 0x6A052708) ^ num49;
												}
											}
											else
											{
												bool num50 = __0025_003D_0024_0021_003F_005E_005E(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[3585 - 3647 + 73]);
												int[,] array9 = new int[4, 3];
												array9[0, 0] = -982598158;
												array9[0, 1] = 359334907;
												array9[0, 2] = 770994234;
												array9[1, 0] = -333936873;
												array9[1, 1] = -1153745826;
												array9[1, 2] = 1840669333;
												array9[2, 0] = 1951931531;
												array9[2, 1] = 1029322368;
												array9[2, 2] = 1368334014;
												array9[3, 0] = -1941791206;
												array9[3, 1] = 247759003;
												array9[3, 2] = 1600239068;
												array9[0, 1] = array9[3, 2] ^ 0x6EF7C899;
												array9[3, 2] = array9[1, 2] ^ -1079129537;
												array9[2, 1] = array9[0, 0] ^ -1300164302;
												int num51 = array9[2, 1] ^ 0x67088740;
												int[,] array10 = new int[4, 4];
												array10[0, 0] = -1679981979;
												array10[0, 1] = -1300619636;
												array10[0, 2] = -1728908581;
												array10[0, 3] = 1055131575;
												array10[1, 0] = -663261958;
												array10[1, 1] = -1360153693;
												array10[1, 2] = 1408594769;
												array10[1, 3] = -1853768841;
												array10[2, 0] = -1633057917;
												array10[2, 1] = 712927031;
												array10[2, 2] = 1684912103;
												array10[2, 3] = 1697991529;
												array10[3, 0] = 356490680;
												array10[3, 1] = 1283127379;
												array10[3, 2] = -1087739477;
												array10[3, 3] = -1077510606;
												array10[2, 2] = array10[2, 1] ^ -1630145245;
												array10[3, 0] ^= -1748053696;
												array10[1, 2] = array10[3, 2] ^ -910684139;
												int num52 = array10[1, 2] ^ -988364668;
												int num53 = (int)((num4 * 1831146813) ^ 0x6C1B5C02);
												num51 ^= num53;
												num52 ^= num53;
												int num54;
												int num55;
												if (!num50)
												{
													num54 = num52;
													num55 = num54;
												}
												else
												{
													num54 = num51;
													num55 = num54;
												}
												num = num54 ^ num53;
											}
										}
										else
										{
											bool num56 = __0025_003D_0024_0021_003F_005E_005E(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[108 - 46 - 8 - 44]);
											int[] array11 = new int[6];
											array11[0] = 1732058769;
											array11[1] = 1433181595;
											array11[2] = -1442480421;
											array11[3] = 637374163;
											array11[4] = 1385730076;
											array11[5] = 170804507;
											array11[2] = array11[1] ^ -1561227230;
											array11[5] ^= -818853137;
											int[] array12 = new int[4] { 729496898, -946244476, 1740028974, 606037612 };
											int[][] array13 = new int[2][] { array11, array12 };
											array12[1] = array13[0][4] ^ 0x29AA6BF3;
											array12[3] = array12[0] ^ 0x51E26EDA;
											array12[2] = array12[0] ^ 0x750913;
											int num57 = array13[1][1] ^ -292269545;
											int[,] array14 = new int[3, 4];
											array14[0, 0] = 786600022;
											array14[0, 1] = -1976458502;
											array14[0, 2] = 519455814;
											array14[0, 3] = -1112899346;
											array14[1, 0] = 542727141;
											array14[1, 1] = 366751438;
											array14[1, 2] = -431025972;
											array14[1, 3] = 1135823985;
											array14[2, 0] = 1479769609;
											array14[2, 1] = -702436237;
											array14[2, 2] = -1563841656;
											array14[2, 3] = 15113215;
											array14[0, 2] = array14[1, 0] ^ 0x1536E343;
											array14[0, 1] = array14[1, 3] ^ 0x268F8083;
											array14[1, 3] = array14[2, 3] ^ 0x3A3E4BE9;
											array14[2, 1] = array14[1, 0] ^ -1606825945;
											int num58 = array14[2, 1] ^ 0x4EF3C6;
											int num59 = (int)(num4 * 252908203) ^ -858104000;
											num57 ^= num59;
											num58 ^= num59;
											int num60;
											int num61;
											if (!num56)
											{
												num60 = num58;
												num61 = num60;
											}
											else
											{
												num60 = num57;
												num61 = num60;
											}
											num = num60 ^ num59;
										}
									}
									else
									{
										viewModel = DaU_003D;
										num = -1527826318;
									}
								}
								else
								{
									DaU_003D.Navigate(ShellSection.Workspace);
									int[] array15 = new int[4];
									array15[0] = -1060541197;
									array15[1] = -275450427;
									array15[2] = -1866075817;
									array15[3] = -1324800479;
									array15[1] = array15[2] ^ 0x3F012996;
									array15[2] ^= -825444918;
									int[] array16 = new int[5];
									array16[0] = 1142369558;
									array16[1] = -219323597;
									array16[2] = 1499379956;
									array16[3] = -898979695;
									array16[4] = 10358215;
									array16[0] = array15[3] ^ -980583074;
									array16[2] = array16[1] ^ -1634092223;
									array16[1] = array16[0] ^ 0x7AC5143D;
									int num62 = array16[0] ^ 0x70F8836F;
									num = (int)((num4 * 1479103543) ^ 0x6B94C22C) ^ num62;
								}
							}
							else
							{
								_0024_0029_003C_0026_0024_0025_0029_(sDd_003D, (object)mVZ_003D);
								int[] array17 = new int[6] { 1325518277, -32798647, -1421981750, 1649234127, 921330140, 241612148 };
								array17[3] ^= -586104617;
								array17[4] = array17[5] ^ 0x50F65F0E;
								array17[2] = array17[5] ^ -223169830;
								int[] array18 = new int[6];
								array18[0] = 285443268;
								array18[1] = 1189002333;
								array18[2] = -1160488303;
								array18[3] = -713843465;
								array18[4] = 1317465139;
								array18[5] = -1953775614;
								array18[3] = array17[1] ^ -361714072;
								array18[0] = array18[2] ^ -623104336;
								array18[2] = array18[0] ^ -479716216;
								array18[2] = array18[5] ^ -1042003287;
								int num63 = array18[3] ^ -269332841;
								num = ((int)num4 * -540204740) ^ -97637392 ^ num63;
							}
						}
						else
						{
							bool num64 = xAv_003D.ViewModel.TryPrepareMethodExplorerNavigation();
							int[] array19 = new int[7];
							array19[0] = 1602237099;
							array19[1] = 2053717052;
							array19[2] = 1344811682;
							array19[3] = -2095099350;
							array19[4] = -167623882;
							array19[5] = -2044883532;
							array19[6] = -712670456;
							array19[0] = array19[1] ^ -1088347775;
							array19[1] = array19[4] ^ -60175585;
							int[] array20 = new int[6];
							array20[0] = 1196458250;
							array20[1] = 1007362812;
							array20[2] = -1963125322;
							array20[3] = 2078299596;
							array20[4] = 785935278;
							array20[5] = 492900818;
							array20[2] = array19[4] ^ 0x63372E78;
							array20[4] = array20[0] ^ 0x2875C013;
							array20[0] = array20[3] ^ 0x4FC476D5;
							array20[3] ^= -748325312;
							int num65 = array20[2] ^ 0xF360422;
							int[] array21 = new int[5];
							array21[0] = 571795446;
							array21[1] = 813632327;
							array21[2] = 1881070362;
							array21[3] = -985048619;
							array21[4] = 1959933427;
							array21[1] = array21[4] ^ -707490577;
							array21[3] = array21[4] ^ 0x591093F6;
							array21[0] = array21[1] ^ -1497140224;
							int[] array22 = new int[5] { -1487751081, -345029625, -50734344, -2062821419, 851184112 };
							int[][] array23 = new int[2][] { array21, array22 };
							array22[0] = array23[0][4] ^ -1481866095;
							array22[2] = array22[0] ^ -1022457001;
							array22[1] = array22[3] ^ 0x50F86259;
							int num66 = array23[1][0] ^ 0x414C0364;
							int num67 = (int)(num4 * 296594649) ^ -765265162;
							num65 ^= num67;
							num66 ^= num67;
							int num68;
							int num69;
							if (!num64)
							{
								num68 = num66;
								num69 = num68;
							}
							else
							{
								num68 = num65;
								num69 = num68;
							}
							num = num68 ^ num67;
						}
					}
					else if (__0025_003D_0024_0021_003F_005E_005E(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4945 - 4987 + 52]))
					{
						num = -129251152;
						num70 = num;
					}
					else
					{
						num = -1711052436;
						num70 = num;
					}
				}
				else
				{
					string text2 = text;
					int[,] array24 = new int[3, 3];
					array24[0, 0] = 394945621;
					array24[0, 1] = 1102642480;
					array24[0, 2] = -1730949574;
					array24[1, 0] = -1357717685;
					array24[1, 1] = -2035453125;
					array24[1, 2] = -1057519649;
					array24[2, 0] = 488237671;
					array24[2, 1] = -986031046;
					array24[2, 2] = 837626242;
					array24[1, 1] = array24[2, 2] ^ -765623611;
					array24[0, 1] = array24[2, 0] ^ -788386739;
					array24[1, 2] = array24[2, 1] ^ 0x5704659E;
					array24[0, 2] = array24[1, 0] ^ -220551960;
					int num71 = array24[0, 2] ^ 0x7BBF76CB;
					int[] array25 = new int[6];
					array25[0] = -1414270818;
					array25[1] = -1999415333;
					array25[2] = 1447984028;
					array25[3] = 1616878483;
					array25[4] = -3281262;
					array25[5] = 199346220;
					array25[0] = array25[1] ^ 0x7D3BEA9B;
					array25[0] = array25[4] ^ 0xAF792B2;
					int[] array26 = new int[7];
					array26[0] = 233017290;
					array26[1] = 1039193373;
					array26[2] = 35924332;
					array26[3] = -694993520;
					array26[4] = -731022005;
					array26[5] = -122076665;
					array26[6] = 1042936324;
					array26[3] = array25[2] ^ -1975863355;
					array26[4] = array26[1] ^ 0x44E1D9D;
					array26[4] = array26[5] ^ 0x17D64E67;
					array26[4] ^= -1303147027;
					int num72 = array26[3] ^ -1161854612;
					int num73 = ((int)num4 * -441767712) ^ 0x140A6760;
					num71 ^= num73;
					num72 ^= num73;
					int num74;
					int num75;
					if (text2 == null)
					{
						num74 = num72;
						num75 = num74;
					}
					else
					{
						num74 = num71;
						num75 = num74;
					}
					num = num74 ^ num73;
				}
				continue;
			}
			goto IL_1e50;
		}
		goto IL_0013;
		IL_1e50:
		NavigationViewItemBase navigationViewItemBase = _0024_002F_003C_0028_0021_003E_002D_003E(faN_003D);
		text = (((object)navigationViewItemBase != null) ? _002B_0040_0028_002D_0040_0021_0023_003D((FrameworkElement)navigationViewItemBase) : null) as string;
		num = -396153453;
		goto IL_0018;
	}

	private void uip_003D(object? rHq_003D, PropertyChangedEventArgs Ybe_003D)
	{
		if (__0025_003D_0024_0021_003F_005E_005E(_002A_002A_0029_0024_0024_003F__0024(Ybe_003D), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4198 - 4263 + 77]))
		{
			goto IL_002a;
		}
		goto IL_1cb9;
		IL_002a:
		int num = -1966863648;
		goto IL_002f;
		IL_002f:
		NavigationView navigationView = default(NavigationView);
		NavigationViewItem navigationViewItem = default(NavigationViewItem);
		ShellSection currentSection = default(ShellSection);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)(((-(~(-(-(~(~(0xA382AA4 ^ 0x3EC40D06))) - (num2 - ~(~(1732978368 - -(-(--1121368135 + -82132114))) ^ ~(-(-1608339613 ^ 0xDC4A59D) * -24014395 + (-239210950 - (-1793204315 + (0x5730D658 ^ 0x558A25A)) - ~(-1254742965 ^ 0x16230E0B)))))) * -429221755)) ^ 0xD8F86D) + -(-1588303209) - ~758129113) ^ 0x334A40EE)) % 22;
			int num5 = -659704006;
			_ = 0;
			for (int num6 = 0; num6 < 1; num6++)
			{
				num5 -= -659704026;
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = -1094167997;
			_ = 0;
			for (int num8 = 0; num8 < 1; num8++)
			{
				num7 -= -1094168010;
			}
			if (num3 != (uint)num7)
			{
				int num9 = 1581310501;
				_ = 0;
				for (int num10 = 0; num10 < 1; num10++)
				{
					num9 += -1581310480;
				}
				if (num3 == (uint)num9)
				{
					return;
				}
				int num11 = 1119606688;
				_ = 0;
				for (int num12 = 0; num12 < 1; num12++)
				{
					num11 = 1119606697 - num11;
				}
				if (num3 != (uint)num11)
				{
					int num13 = -2;
					_ = 0;
					for (int num14 = 0; num14 < 1; num14++)
					{
						num13 = ~num13;
					}
					if (num3 != (uint)num13)
					{
						int num15 = -535118066;
						_ = 0;
						for (int num16 = 0; num16 < 2; num16++)
						{
							num15 = num15 ^ 0x583544E7 ^ -1084928088;
							num15 = -1685420143 - (-338172859 - num15);
						}
						if (num3 != (uint)num15)
						{
							int num17 = 6;
							_ = 0;
							for (int num18 = 0; num18 < 2; num18++)
							{
								num17 = ~(~num17);
								num17 ^= -1061560722;
							}
							if (num3 != (uint)num17)
							{
								int num19 = -5;
								_ = 0;
								for (int num20 = 0; num20 < 1; num20++)
								{
									num19 = ~num19;
								}
								if (num3 != (uint)num19)
								{
									int num21 = -17;
									_ = 0;
									for (int num22 = 0; num22 < 1; num22++)
									{
										num21 = -num21;
									}
									if (num3 != (uint)num21)
									{
										int num23 = -62669025;
										_ = 0;
										for (int num24 = 0; num24 < 1; num24++)
										{
											num23 -= -62669032;
										}
										if (num3 != (uint)num23)
										{
											int num25 = -16;
											_ = 0;
											for (int num26 = 0; num26 < 1; num26++)
											{
												num25 = ~num25;
											}
											if (num3 != (uint)num25)
											{
												int num27 = -1442282366;
												_ = 0;
												for (int num28 = 0; num28 < 1; num28++)
												{
													num27 *= -710722615;
												}
												if (num3 != (uint)num27)
												{
													int num29 = 16;
													_ = 0;
													for (int num30 = 0; num30 < 2; num30++)
													{
														num29 = -(num29 - ~1773736464);
														num29 = -(-num29);
													}
													if (num3 != (uint)num29)
													{
														int num31 = -2007946437;
														_ = 0;
														for (int num32 = 0; num32 < 2; num32++)
														{
															num31 = -num31 + 1334305676;
															num31 = -1691542406 + -265145990 - num31;
														}
														if (num3 != (uint)num31)
														{
															int num33 = 2019527983;
															_ = 0;
															for (int num34 = 0; num34 < 2; num34++)
															{
																num33 = ~(num33 - ~-851184949);
																num33 = ~(num33 - (-510987087 - -352408045));
															}
															if (num3 != (uint)num33)
															{
																int num35 = -12;
																_ = 0;
																for (int num36 = 0; num36 < 1; num36++)
																{
																	num35 = -num35;
																}
																if (num3 != (uint)num35)
																{
																	int num37 = 1892998182;
																	_ = 0;
																	for (int num38 = 0; num38 < 2; num38++)
																	{
																		num37 = (num37 - ~1094284028) * 233922139;
																		num37 = ~num37 - -129521310;
																	}
																	if (num3 == (uint)num37)
																	{
																		return;
																	}
																	int num39 = -185742169;
																	_ = 0;
																	for (int num40 = 0; num40 < 2; num40++)
																	{
																		num39 = 1901011875 - num39 * -577655035;
																		num39 -= ~-195444309;
																	}
																	int num52;
																	if (num3 != (uint)num39)
																	{
																		int num41 = -1181274259;
																		_ = 0;
																		for (int num42 = 0; num42 < 1; num42++)
																		{
																			num41 *= -480248839;
																		}
																		if (num3 != (uint)num41)
																		{
																			int num43 = 0;
																			_ = 0;
																			for (int num44 = 0; num44 < 1; num44++)
																			{
																				num43 = -num43;
																			}
																			if (num3 != (uint)num43)
																			{
																				int num45 = 1036049894;
																				_ = 0;
																				for (int num46 = 0; num46 < 2; num46++)
																				{
																					num45 = (num45 * 1862230261) ^ 0x1119F772;
																					num45 = ~(num45 - ~461425735);
																				}
																				if (num3 != (uint)num45)
																				{
																					int num47 = -8;
																					_ = 0;
																					for (int num48 = 0; num48 < 1; num48++)
																					{
																						num47 = -num47;
																					}
																					if (num3 == (uint)num47)
																					{
																					}
																					return;
																				}
																				igp_003D();
																				int[] array = new int[5];
																				array[0] = 209855987;
																				array[1] = 242682158;
																				array[2] = 715805089;
																				array[3] = -1284230203;
																				array[4] = 812246718;
																				array[0] = array[4] ^ -163098599;
																				array[1] ^= -132881632;
																				array[4] ^= -601511290;
																				int[] array2 = new int[6];
																				array2[0] = 498517771;
																				array2[1] = 935790852;
																				array2[2] = 1241953142;
																				array2[3] = -570411426;
																				array2[4] = -883074184;
																				array2[5] = 1899556084;
																				array2[4] = array[2] ^ 0x1218EC96;
																				array2[3] = array2[4] ^ -808443239;
																				array2[1] ^= -858197108;
																				int num49 = array2[4] ^ 0x43DA9E7E;
																				num = (int)((num4 * 1981013439) ^ 0x8FD1B348u) ^ num49;
																			}
																			else
																			{
																				dTr_003D();
																				int[,] array3 = new int[4, 3];
																				array3[0, 0] = 1348472621;
																				array3[0, 1] = -304134265;
																				array3[0, 2] = -789759806;
																				array3[1, 0] = 169533058;
																				array3[1, 1] = -2131034897;
																				array3[1, 2] = 1389667034;
																				array3[2, 0] = 759551649;
																				array3[2, 1] = 376262560;
																				array3[2, 2] = 997416719;
																				array3[3, 0] = -221974712;
																				array3[3, 1] = -903371291;
																				array3[3, 2] = -979926601;
																				array3[0, 1] = array3[0, 2] ^ -174366345;
																				array3[0, 1] = array3[3, 2] ^ 0x2258861D;
																				array3[1, 2] = array3[3, 0] ^ 0x5A38BC33;
																				int num50 = array3[1, 2] ^ -265595430;
																				num = (int)((num4 * 1578236820) ^ 0x6E458AB0) ^ num50;
																			}
																		}
																		else
																		{
																			MAj_003D();
																			int[] array4 = new int[4] { 174642289, -853830889, -1609927577, -962428347 };
																			array4[1] ^= -856643048;
																			array4[0] = array4[3] ^ 0x6C65359F;
																			array4[3] ^= 1241903630;
																			int[] array5 = new int[4] { -992951827, 1421562316, -962081388, -1429265342 };
																			int[][] array6 = new int[2][] { array4, array5 };
																			array5[0] = array6[0][2] ^ 0x561E1267;
																			array5[2] = array5[0] ^ 0x5587CB5E;
																			array5[1] ^= 998771687;
																			int num51 = array6[1][0] ^ -1109684811;
																			num = ((int)num4 * -1779141595) ^ 0x534A8D95 ^ num51;
																		}
																	}
																	else if (__0025_003D_0024_0021_003F_005E_005E(_002A_002A_0029_0024_0024_003F__0024(Ybe_003D), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[66 - 10 - 20 - 22]))
																	{
																		num = 307911864;
																		num52 = num;
																	}
																	else
																	{
																		num = 2070422345;
																		num52 = num;
																	}
																}
																else
																{
																	dTr_003D();
																	int[,] array7 = new int[3, 4];
																	array7[0, 0] = -333090479;
																	array7[0, 1] = -733710929;
																	array7[0, 2] = -788544904;
																	array7[0, 3] = 537240809;
																	array7[1, 0] = -1218257000;
																	array7[1, 1] = 1345414074;
																	array7[1, 2] = -212668972;
																	array7[1, 3] = -1005565722;
																	array7[2, 0] = -1477584492;
																	array7[2, 1] = -1655957410;
																	array7[2, 2] = 2068986189;
																	array7[2, 3] = 1504571564;
																	array7[0, 1] = array7[1, 3] ^ -131654918;
																	array7[2, 0] = array7[1, 1] ^ 0x5BAEDD33;
																	array7[0, 3] = array7[2, 2] ^ 0x4E291B37;
																	array7[2, 0] = array7[2, 1] ^ 0x198699E3;
																	int num53 = array7[2, 0] ^ 0x2C077E48;
																	num = ((int)num4 * -1013540404) ^ -29521576 ^ num53;
																}
															}
															else
															{
																_0024_0029_003C_0026_0024_0025_0029_(navigationView, (object)navigationViewItem);
																num = 812257855;
															}
														}
														else
														{
															navigationViewItem = mVZ_003D;
															num = 842665864;
														}
													}
													else
													{
														int[] array8 = new int[6];
														array8[0] = -889214717;
														array8[1] = -1925660176;
														array8[2] = 1016213472;
														array8[3] = -1731032962;
														array8[4] = -1991428547;
														array8[5] = -1322622497;
														array8[2] = array8[1] ^ -420194149;
														array8[0] = array8[3] ^ -163982594;
														array8[4] = array8[5] ^ -787843989;
														int[] array9 = new int[4] { 637545751, 1852388289, 123358765, -1697460563 };
														int[][] array10 = new int[2][] { array8, array9 };
														array9[2] = array10[0][5] ^ -1716466095;
														array9[3] = array9[0] ^ 0x4FAA786F;
														array9[1] = array9[2] ^ -1442342322;
														int num54 = array10[1][2] ^ 0x1AA0A006;
														num = (int)((num4 * 1626452860) ^ 0x651EC4F8) ^ num54;
													}
												}
												else
												{
													navigationViewItem = hYn_003D;
													num = 1876506415;
												}
											}
											else
											{
												int[,] array11 = new int[3, 3];
												array11[0, 0] = -291032768;
												array11[0, 1] = 1709541908;
												array11[0, 2] = -791184635;
												array11[1, 0] = -1962041166;
												array11[1, 1] = -1743106310;
												array11[1, 2] = -802944132;
												array11[2, 0] = 1493520704;
												array11[2, 1] = -255360556;
												array11[2, 2] = -2119637849;
												array11[1, 0] = array11[0, 1] ^ -1409703030;
												array11[1, 2] = array11[2, 2] ^ -726987716;
												array11[2, 2] = array11[2, 1] ^ 0x109F9028;
												int num55 = array11[2, 2] ^ -765321612;
												num = ((int)num4 * -271406323) ^ -1726317847 ^ num55;
											}
										}
										else
										{
											navigationViewItem = nfB_003D;
											num = 1215461028;
										}
									}
									else
									{
										int[,] array12 = new int[3, 3];
										array12[0, 0] = 1822933470;
										array12[0, 1] = -2123282956;
										array12[0, 2] = 1646693932;
										array12[1, 0] = 1381283263;
										array12[1, 1] = -1544591182;
										array12[1, 2] = 2097932454;
										array12[2, 0] = -214556448;
										array12[2, 1] = 1170811795;
										array12[2, 2] = -561995729;
										array12[1, 2] = array12[0, 1] ^ -2009651498;
										array12[2, 1] = array12[2, 2] ^ -1441836873;
										array12[2, 1] = array12[0, 1] ^ -1068715333;
										array12[0, 0] = array12[1, 0] ^ 0x3B219ED5;
										int num56 = array12[0, 0] ^ 0x54203D86;
										num = ((int)num4 * -1953567699) ^ -1707245569 ^ num56;
									}
								}
								else
								{
									ShellSection num57 = currentSection;
									int[,] array13 = new int[3, 3];
									array13[0, 0] = 565760702;
									array13[0, 1] = 1350878668;
									array13[0, 2] = -925902211;
									array13[1, 0] = 1501953251;
									array13[1, 1] = -556611604;
									array13[1, 2] = 310380675;
									array13[2, 0] = 760761270;
									array13[2, 1] = -97080682;
									array13[2, 2] = -326630602;
									array13[2, 0] = array13[0, 1] ^ -1758334735;
									array13[1, 0] = array13[1, 1] ^ -1899687031;
									array13[2, 0] = array13[0, 1] ^ -1263737489;
									array13[2, 1] = array13[0, 1] ^ 0x5BE8C661;
									int num58 = array13[2, 1] ^ -1054973636;
									int[] array14 = new int[5];
									array14[0] = -1428262289;
									array14[1] = -1152461520;
									array14[2] = -1899786009;
									array14[3] = -1208447333;
									array14[4] = -1359174381;
									array14[2] = array14[0] ^ 0x221D98A7;
									array14[4] = array14[3] ^ -238184677;
									int[] array15 = new int[7];
									array15[0] = -1234067355;
									array15[1] = 2039562443;
									array15[2] = 1185285580;
									array15[3] = 1306550846;
									array15[4] = -1122608285;
									array15[5] = -497781904;
									array15[6] = 944811757;
									array15[2] = array14[3] ^ -1256825129;
									array15[1] = array15[0] ^ -98490368;
									array15[0] = array15[1] ^ -1337719815;
									array15[6] = array15[0] ^ 0x7CCA86F1;
									int num59 = array15[2] ^ 0x5F9CF042;
									int num60 = (int)((num4 * 846441903) ^ 0x52CC8D6E);
									num58 ^= num60;
									num59 ^= num60;
									int num61;
									int num62;
									if (num57 != ShellSection.Settings)
									{
										num61 = num59;
										num62 = num61;
									}
									else
									{
										num61 = num58;
										num62 = num61;
									}
									num = num61 ^ num60;
								}
							}
							else
							{
								ShellSection num63 = currentSection;
								int[] array16 = new int[6] { 1708049284, 812053802, 1439603666, 352318476, 990440578, 1798978279 };
								array16[4] ^= -814693441;
								array16[1] = array16[4] ^ 0x2347E5C0;
								int[] array17 = new int[4] { -239954747, 2018175366, 2069632822, -14968288 };
								int[][] array18 = new int[2][] { array16, array17 };
								array17[2] = array18[0][5] ^ -121661617;
								array17[0] = array17[2] ^ -1395428817;
								array17[1] = array17[2] ^ -1208401394;
								int num64 = array18[1][2] ^ 0x682905A0;
								int[] array19 = new int[6];
								array19[0] = -855873692;
								array19[1] = -252631275;
								array19[2] = -871428252;
								array19[3] = 217875804;
								array19[4] = -230045013;
								array19[5] = 708615000;
								array19[4] = array19[5] ^ 0x3598C84F;
								array19[3] = array19[4] ^ 0x46879A91;
								int[] array20 = new int[6] { -1444645117, -1890850337, 677720045, -846042523, 1580525999, 1143396821 };
								int[][] array21 = new int[2][] { array19, array20 };
								array20[2] = array21[0][0] ^ -683623891;
								array20[0] = array20[3] ^ -943651941;
								array20[0] = array20[2] ^ -1325929969;
								array20[5] = array20[2] ^ -721162312;
								int num65 = array21[1][2] ^ -1587511146;
								int num66 = (int)((num4 * 63956010) ^ 0x74C2BC0);
								num64 ^= num66;
								num65 ^= num66;
								int num67;
								int num68;
								if (num63 != ShellSection.Methods)
								{
									num67 = num65;
									num68 = num67;
								}
								else
								{
									num67 = num64;
									num68 = num67;
								}
								num = num67 ^ num66;
							}
						}
						else
						{
							currentSection = DaU_003D.CurrentSection;
							int[] array22 = new int[6];
							array22[0] = 958726808;
							array22[1] = 191649853;
							array22[2] = -2043529165;
							array22[3] = 1702221697;
							array22[4] = -1956029607;
							array22[5] = 571661746;
							array22[3] = array22[5] ^ 0x50FDF6D7;
							array22[5] = array22[3] ^ 0x4EFD04C6;
							int[] array23 = new int[5] { 409454077, -1686709180, 897321206, 2017354440, 1242115388 };
							int[][] array24 = new int[2][] { array22, array23 };
							array23[4] = array24[0][1] ^ -1914896401;
							array23[3] ^= -116862500;
							array23[0] = array23[1] ^ -1355387563;
							array23[2] = array23[1] ^ 0x69A4EDD3;
							int num69 = array24[1][4] ^ 0x715703FB;
							num = (int)((num4 * 1244697318) ^ 0xD9B29C50u) ^ num69;
						}
					}
					else
					{
						navigationView = sDd_003D;
						int[] array25 = new int[5] { 154702091, 1899621330, 1344650403, -322531799, 2092276526 };
						array25[3] ^= 689553640;
						array25[0] = array25[4] ^ 0x5E0F77BF;
						int[] array26 = new int[6] { 441634301, -1320481275, 80028841, -857202355, 1175376039, -363763742 };
						int[][] array27 = new int[2][] { array25, array26 };
						array26[2] = array27[0][4] ^ 0x6A587A56;
						array26[5] = array26[0] ^ -464287877;
						array26[3] = array26[2] ^ 0x7B75D7E0;
						int num70 = array27[1][2] ^ 0xC0A2B59;
						num = ((int)num4 * -1705974156) ^ 0x50A226C ^ num70;
					}
					continue;
				}
				goto IL_1cb9;
			}
			_0021_0023_002B__002B_0023_003F_0028((Window)this, DaU_003D.WindowTitle);
			int[,] array28 = new int[3, 3]
			{
				{ -551130145, 1936184588, -1866530647 },
				{ 763483803, 422463676, -1142925979 },
				{ -738532526, 473479927, -1988519070 }
			};
			array28[0, 2] ^= 517379280;
			array28[0, 2] = array28[2, 1] ^ 0x388CF8BA;
			array28[2, 0] = array28[2, 2] ^ -417217402;
			array28[1, 2] = array28[1, 1] ^ -1918074903;
			int num71 = array28[1, 2] ^ -1279316693;
			num = (int)((num4 * 484749202) ^ 0xE2D14202u) ^ num71;
		}
		goto IL_002a;
		IL_1cb9:
		int num72;
		if (__0025_003D_0024_0021_003F_005E_005E(_002A_002A_0029_0024_0024_003F__0024(Ybe_003D), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x13C9E ^ 0x13C93))]))
		{
			num = -391204070;
			num72 = num;
		}
		else
		{
			num = 357691914;
			num72 = num;
		}
		goto IL_002f;
	}

	public void xHA_003D()
	{
		OverlappedPresenter overlappedPresenter = _002B_003D_002A_0024_002F_0024_003E_0021(_003D_0024_003E_0029_003F_003C_0025_((Window)this)) as OverlappedPresenter;
		while (true)
		{
			int num = -195231803;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(~(-(-(~num2) ^ -1233274028))) - -(0x1C84517E ^ 0x481788BE))) % 6;
				int num5 = 1432343855;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = num5 ^ 0x57546263 ^ -280459763;
					num5 = 1820076466 - num5 * 916816061;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -1886101908;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 += 1886101909;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1050501;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = ~(num9 ^ -1854140599);
						num9 = num9 - -830417560 - 428396154;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 354209284;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 = 354209288 - num11;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -988183166;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = -1032741737 - ~num13;
								num13 = -num13 * -342551967;
							}
							if (num3 != (uint)num13)
							{
								int num15 = 0;
								_ = 0;
								for (int num16 = 0; num16 < 1; num16++)
								{
									num15 *= 23175697;
								}
								if (num3 == (uint)num15)
								{
								}
								return;
							}
							_002D_002F_005E_003C__0024_003D_003D((Window)this);
							num = -1940509772;
						}
						else
						{
							_005E_003F_0028__0040_005E_002B_0026(overlappedPresenter);
							int[] array = new int[5];
							array[0] = 1774924652;
							array[1] = -1590598270;
							array[2] = 744460353;
							array[3] = -222382929;
							array[4] = 577524207;
							array[1] = array[4] ^ 0x758E95DE;
							array[3] = array[1] ^ -379008798;
							array[4] = array[2] ^ 0x5FC707BE;
							int[] array2 = new int[4] { 82022745, 686373226, -638110371, -1513963000 };
							int[][] array3 = new int[2][] { array, array2 };
							array2[2] = array3[0][0] ^ 0x3794A2AE;
							array2[1] ^= 1278481303;
							array2[0] = array2[2] ^ 0x69D7861D;
							array2[3] = array2[1] ^ 0x6AC8A6B4;
							int num17 = array3[1][2] ^ -666316468;
							num = ((int)num4 * -1075386776) ^ 0x251673A0 ^ num17;
						}
					}
					else
					{
						OverlappedPresenterState num18 = _0024_002F_0021_002A_0028_003D_002A_0023(overlappedPresenter);
						int[] array4 = new int[4] { -320503620, -934581319, -277826796, -12613397 };
						array4[2] ^= 1194621597;
						array4[1] = array4[2] ^ -543032697;
						array4[1] = array4[3] ^ -438170690;
						int[] array5 = new int[4] { -1169044079, -1721764407, 314655011, 1072921950 };
						int[][] array6 = new int[2][] { array4, array5 };
						array5[2] = array6[0][0] ^ 0x436E3B1;
						array5[0] = array5[3] ^ 0x7BBF43D0;
						array5[1] ^= -1100889855;
						array5[3] = array5[1] ^ 0x364580F8;
						int num19 = array6[1][2] ^ 0x6EC42383;
						int[] array7 = new int[5];
						array7[0] = -1961373795;
						array7[1] = 1289456102;
						array7[2] = -1027803304;
						array7[3] = 1427044600;
						array7[4] = 1925279314;
						array7[0] = array7[3] ^ -479500883;
						array7[3] = array7[1] ^ -25146281;
						int[] array8 = new int[4];
						array8[0] = 891569838;
						array8[1] = -673440555;
						array8[2] = -1420658301;
						array8[3] = 1480766624;
						array8[1] = array7[2] ^ 0x49F607E8;
						array8[3] = array8[1] ^ -2083704777;
						array8[2] = array8[3] ^ -1562393642;
						array8[0] ^= 134246447;
						int num20 = array8[1] ^ 0x2A8C5A98;
						int num21 = (int)((num4 * 1352721154) ^ 0x72A6101E);
						num19 ^= num21;
						num20 ^= num21;
						int num22;
						int num23;
						if (num18 == OverlappedPresenterState.Minimized)
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
				else
				{
					int[,] array9 = new int[4, 3];
					array9[0, 0] = -135788162;
					array9[0, 1] = -1612441290;
					array9[0, 2] = -1485892546;
					array9[1, 0] = 309498729;
					array9[1, 1] = -1544680284;
					array9[1, 2] = 2067963668;
					array9[2, 0] = 810620011;
					array9[2, 1] = -1709311982;
					array9[2, 2] = 31263117;
					array9[3, 0] = 65618923;
					array9[3, 1] = 778946701;
					array9[3, 2] = 666650925;
					array9[0, 1] = array9[1, 0] ^ 0x4B0D1AAE;
					array9[3, 1] = array9[1, 1] ^ 0x2FBD2A7A;
					array9[1, 1] = array9[0, 0] ^ -2006742620;
					int num24 = array9[1, 1] ^ -107167660;
					int[,] array10 = new int[4, 4];
					array10[0, 0] = -1200151956;
					array10[0, 1] = -1525323831;
					array10[0, 2] = 1144685836;
					array10[0, 3] = -1383621318;
					array10[1, 0] = 899072574;
					array10[1, 1] = -156713227;
					array10[1, 2] = 293506430;
					array10[1, 3] = 1279372220;
					array10[2, 0] = -1093078984;
					array10[2, 1] = -1699354372;
					array10[2, 2] = 1036639393;
					array10[2, 3] = -1480209061;
					array10[3, 0] = -1518402988;
					array10[3, 1] = -1067814690;
					array10[3, 2] = 1501022337;
					array10[3, 3] = 1786665188;
					array10[1, 1] = array10[3, 1] ^ 0x37100621;
					array10[2, 0] ^= 967273474;
					array10[0, 0] = array10[2, 3] ^ 0x33082220;
					array10[1, 3] = array10[2, 2] ^ -2080622284;
					int num25 = array10[1, 3] ^ 0x999E6F0;
					int num26 = ((int)num4 * -1492482165) ^ -306656891;
					num24 ^= num26;
					num25 ^= num26;
					int num27;
					int num28;
					if ((object)overlappedPresenter != null)
					{
						num27 = num25;
						num28 = num27;
					}
					else
					{
						num27 = num24;
						num28 = num27;
					}
					num = num27 ^ num26;
				}
			}
		}
	}

	[AsyncStateMachine(typeof(_003CTryLoadPendingAssemblyAsync_003Ed__10))]
	public Task igp_003D()
	{
		_003CTryLoadPendingAssemblyAsync_003Ed__10 stateMachine = default(_003CTryLoadPendingAssemblyAsync_003Ed__10);
		stateMachine._003C_003Et__builder = _003D__002B_002A_0029_003E_0021_003F();
		while (true)
		{
			int num = -1034106960;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(-(-(num2 * -118076931 * 597864133))))) % 5;
				int num5 = 1035732224;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 = 1035732224 - num5;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -2138144605;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = ~num7 - -2076214804;
					num7 = (num7 + -1362428671 * -1184121546) ^ -915447567;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -1866630066;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = num9 * 1025931869 - -927319278;
						num9 = ~num9 ^ 0x710140E8;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -450875372;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 = -450875368 - num11;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -1070981111;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = num13 + (18638610 + 2000367758) + 800285870;
								num13 ^= --236989787;
							}
							if (num3 != (uint)num13)
							{
							}
							return stateMachine._003C_003Et__builder.Task;
						}
						stateMachine._003C_003Et__builder.Start(ref stateMachine);
						int[] array = new int[4];
						array[0] = 2121471325;
						array[1] = -406162243;
						array[2] = 125822720;
						array[3] = -1722119959;
						array[1] = array[0] ^ -896306206;
						array[0] = array[3] ^ -1820363221;
						array[0] = array[1] ^ 0x453583DF;
						int[] array2 = new int[5];
						array2[0] = 1536933835;
						array2[1] = 861622233;
						array2[2] = -269711208;
						array2[3] = -456606659;
						array2[4] = -1991594172;
						array2[2] = array[2] ^ 0xF2309EB;
						array2[0] = array2[2] ^ -1769918216;
						array2[1] = array2[2] ^ 0x45FC6D3;
						array2[1] ^= -1341285825;
						int num15 = array2[2] ^ 0x217981AD;
						num = (int)((num4 * 1459254005) ^ 0x3FD92078) ^ num15;
					}
					else
					{
						stateMachine._003C_003E1__state = -1;
						int[] array3 = new int[4];
						array3[0] = 1792773175;
						array3[1] = 450101950;
						array3[2] = -1846498232;
						array3[3] = 139137109;
						array3[1] = array3[2] ^ -1762799049;
						array3[1] = array3[3] ^ 0x6BC8DAAF;
						array3[2] = array3[1] ^ -1151829250;
						int[] array4 = new int[6];
						array4[0] = -2090826909;
						array4[1] = -1310022942;
						array4[2] = 568858316;
						array4[3] = 163292792;
						array4[4] = 1026298291;
						array4[5] = 1225072111;
						array4[4] = array3[3] ^ 0x47C7F7C5;
						array4[3] = array4[4] ^ 0x1C867B11;
						array4[0] = array4[2] ^ -2122725694;
						int num16 = array4[4] ^ -1129499129;
						num = (int)((num4 * 524030608) ^ 0x95D3A090u) ^ num16;
					}
				}
				else
				{
					stateMachine._003C_003E4__this = this;
					int[] array5 = new int[6];
					array5[0] = 1980791711;
					array5[1] = -449222023;
					array5[2] = 36486428;
					array5[3] = -632660827;
					array5[4] = -758694013;
					array5[5] = 5378661;
					array5[4] = array5[1] ^ -620344826;
					array5[5] = array5[0] ^ -471865511;
					int[] array6 = new int[4];
					array6[0] = -1408004246;
					array6[1] = 934245970;
					array6[2] = -1187076318;
					array6[3] = 1102651125;
					array6[2] = array5[3] ^ -901695194;
					array6[3] = array6[0] ^ -1302093887;
					array6[3] = array6[0] ^ -902269985;
					array6[1] = array6[0] ^ -662308427;
					int num17 = array6[2] ^ -62754563;
					num = ((int)num4 * -1319077487) ^ -1266847041 ^ num17;
				}
			}
		}
	}

	private void dTr_003D()
	{
		if (!DaU_003D.IsAuthenticated)
		{
			goto IL_0013;
		}
		goto IL_19a7;
		IL_0013:
		int num = 368897262;
		goto IL_0018;
		IL_0018:
		ContentPresenter contentPresenter = default(ContentPresenter);
		object ıQI_003D = default(object);
		ShellSection currentSection = default(ShellSection);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)(-(-((-(-(~num2) * -2093451585 * -2078241999) + (~(-2013771094 + -2026314638) - -1865467672)) ^ -(~1474091382 * -178482671) ^ -1782845760)))) % 15;
			int num5 = 7;
			_ = 0;
			for (int num6 = 0; num6 < 2; num6++)
			{
				num5 = ~(392816249 - num5);
				num5 = ~num5 - 1414988009;
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = 994799555;
			_ = 0;
			for (int num8 = 0; num8 < 1; num8++)
			{
				num7 *= -438477673;
			}
			if (num3 != (uint)num7)
			{
				int num9 = -1204864686;
				_ = 0;
				for (int num10 = 0; num10 < 1; num10++)
				{
					num9 ^= -1204864679;
				}
				if (num3 == (uint)num9)
				{
					return;
				}
				int num11 = -13;
				_ = 0;
				for (int num12 = 0; num12 < 1; num12++)
				{
					num11 = ~num11;
				}
				if (num3 != (uint)num11)
				{
					int num13 = -1;
					_ = 0;
					for (int num14 = 0; num14 < 1; num14++)
					{
						num13 = -num13;
					}
					if (num3 != (uint)num13)
					{
						int num15 = 1498188062;
						_ = 0;
						for (int num16 = 0; num16 < 2; num16++)
						{
							num15 = (num15 ^ -395510383) * -155790307;
							num15 = (num15 ^ 0x7C4EE78F) * 1252976013;
						}
						if (num3 != (uint)num15)
						{
							int num17 = -5;
							_ = 0;
							for (int num18 = 0; num18 < 1; num18++)
							{
								num17 = ~num17;
							}
							if (num3 != (uint)num17)
							{
								int num19 = -7016461;
								_ = 0;
								for (int num20 = 0; num20 < 2; num20++)
								{
									num19 = ~num19 * 729408093;
									num19 = (num19 ^ 0xD83CEDF) + 1962878995;
								}
								if (num3 != (uint)num19)
								{
									int num21 = -1224013055;
									_ = 0;
									for (int num22 = 0; num22 < 1; num22++)
									{
										num21 ^= -1224013054;
									}
									if (num3 != (uint)num21)
									{
										int num23 = 1212848292;
										_ = 0;
										for (int num24 = 0; num24 < 2; num24++)
										{
											num23 = (num23 - (-1074699566 - -467781597)) ^ 0x478934FB;
											num23 = -(num23 ^ -257656672);
										}
										if (num3 != (uint)num23)
										{
											int num25 = -442651991;
											_ = 0;
											for (int num26 = 0; num26 < 2; num26++)
											{
												num25 = (num25 - (1339773335 - 1502120395)) ^ 0x6250A7D0;
												num25 = -num25 * -1453264191;
											}
											if (num3 != (uint)num25)
											{
												int num27 = -1;
												_ = 0;
												for (int num28 = 0; num28 < 1; num28++)
												{
													num27 = ~num27;
												}
												if (num3 != (uint)num27)
												{
													int num29 = 22037780;
													_ = 0;
													for (int num30 = 0; num30 < 2; num30++)
													{
														num29 = ~(num29 + 1403959766 * -929180865);
														num29 = -(num29 ^ 0x5657D538);
													}
													if (num3 != (uint)num29)
													{
														int num31 = -2;
														_ = 0;
														for (int num32 = 0; num32 < 1; num32++)
														{
															num31 = -num31;
														}
														if (num3 != (uint)num31)
														{
															int num33 = -877882506;
															_ = 0;
															for (int num34 = 0; num34 < 2; num34++)
															{
																num33 = -(num33 * 1842852945);
																num33 = num33 * -992683715 * 1441253959;
															}
															if (num3 == (uint)num33)
															{
															}
															return;
														}
														_003D_003D_002A_0026_0025_0023_0040_003C(contentPresenter, ıQI_003D);
														num = 451421132;
													}
													else
													{
														ıQI_003D = xAv_003D;
														num = -1277536194;
													}
												}
												else
												{
													int[,] array = new int[4, 4]
													{
														{ -961664004, 311735175, 173666738, 983352521 },
														{ 1920592336, -1539085736, 1892828385, -383885708 },
														{ -575171287, 729254039, -1145606123, -405446437 },
														{ 1516742550, -925076359, 1548067546, 826313375 }
													};
													array[1, 3] ^= -120747180;
													array[0, 3] = array[2, 3] ^ 0x5F7B161D;
													array[3, 2] = array[1, 2] ^ -19742936;
													int num35 = array[3, 2] ^ 0x3DDAA3F7;
													num = ((int)num4 * -1892962903) ^ -325605927 ^ num35;
												}
											}
											else
											{
												ıQI_003D = IQI_003D;
												num = 69297098;
											}
										}
										else
										{
											int[,] array2 = new int[3, 4];
											array2[0, 0] = 1095340277;
											array2[0, 1] = -1886732898;
											array2[0, 2] = -623417111;
											array2[0, 3] = 1346429316;
											array2[1, 0] = 473047858;
											array2[1, 1] = 1574211792;
											array2[1, 2] = -1286916765;
											array2[1, 3] = 961778051;
											array2[2, 0] = 1977235442;
											array2[2, 1] = -77639005;
											array2[2, 2] = -1148263600;
											array2[2, 3] = -1066004213;
											array2[1, 3] = array2[0, 0] ^ 0x31EFEA0A;
											array2[1, 3] = array2[0, 3] ^ 0x6D8174F6;
											array2[0, 3] = array2[2, 3] ^ -1002296173;
											int num36 = array2[0, 3] ^ -1209113178;
											num = ((int)num4 * -151396362) ^ 0x1E0CE702 ^ num36;
										}
									}
									else
									{
										ıQI_003D = kuV_003D;
										num = -1844010072;
									}
								}
								else
								{
									int[,] array3 = new int[4, 4];
									array3[0, 0] = -1098592353;
									array3[0, 1] = -3946757;
									array3[0, 2] = -616203663;
									array3[0, 3] = -1961300806;
									array3[1, 0] = -1108743960;
									array3[1, 1] = 1508348877;
									array3[1, 2] = 324879510;
									array3[1, 3] = -380661382;
									array3[2, 0] = 935075981;
									array3[2, 1] = -1843117637;
									array3[2, 2] = -296037820;
									array3[2, 3] = 1182644143;
									array3[3, 0] = 780965018;
									array3[3, 1] = 2049556453;
									array3[3, 2] = -1036242377;
									array3[3, 3] = 955842281;
									array3[2, 3] = array3[3, 1] ^ -1332434950;
									array3[3, 3] = array3[0, 1] ^ -147455917;
									array3[3, 1] = array3[1, 0] ^ 0x13CF6020;
									int num37 = array3[3, 1] ^ 0x2D0BBA43;
									num = (int)((num4 * 1696955609) ^ 0x161D304B) ^ num37;
								}
							}
							else
							{
								ShellSection num38 = currentSection;
								int[] array4 = new int[4];
								array4[0] = 782673137;
								array4[1] = 1031470910;
								array4[2] = -1541128385;
								array4[3] = 1378166861;
								array4[0] = array4[2] ^ -626504316;
								array4[1] = array4[0] ^ 0x3CC6DADD;
								int[] array5 = new int[5];
								array5[0] = 1867495321;
								array5[1] = 1616063165;
								array5[2] = -1838299770;
								array5[3] = -634737901;
								array5[4] = -1286086819;
								array5[4] = array4[2] ^ 0x77C4BE4D;
								array5[0] = array5[3] ^ -2118732576;
								array5[1] ^= 1795693241;
								array5[3] = array5[4] ^ -1094173806;
								int num39 = array5[4] ^ -2051126602;
								int[] array6 = new int[5];
								array6[0] = -1602535525;
								array6[1] = 69402968;
								array6[2] = 1769673241;
								array6[3] = -210379152;
								array6[4] = 369173188;
								array6[4] = array6[1] ^ -1520263975;
								array6[3] = array6[4] ^ 0x58C1C674;
								int[] array7 = new int[6] { 656794779, -1326739487, 309940442, 574985154, 2013338055, 1159432326 };
								int[][] array8 = new int[2][] { array6, array7 };
								array7[3] = array8[0][0] ^ -1655219295;
								array7[5] = array7[2] ^ -2032171972;
								array7[2] = array7[4] ^ 0x78BA7705;
								int num40 = array8[1][3] ^ 0x62A43EC2;
								int num41 = (int)(num4 * 920644031) ^ -1493040968;
								num39 ^= num41;
								num40 ^= num41;
								int num42;
								int num43;
								if (num38 != ShellSection.Settings)
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
						}
						else
						{
							ShellSection num44 = currentSection;
							int[,] array9 = new int[3, 4];
							array9[0, 0] = 1062823274;
							array9[0, 1] = 278082556;
							array9[0, 2] = 1245193515;
							array9[0, 3] = -1265112658;
							array9[1, 0] = -1318357733;
							array9[1, 1] = 1832103797;
							array9[1, 2] = 1462798156;
							array9[1, 3] = 580814442;
							array9[2, 0] = -1289723986;
							array9[2, 1] = 1575875853;
							array9[2, 2] = -1423383024;
							array9[2, 3] = 977804473;
							array9[0, 1] = array9[0, 2] ^ 0x6487C07D;
							array9[0, 0] = array9[0, 3] ^ 0x6F90AB19;
							array9[1, 0] = array9[2, 0] ^ 0x692AB538;
							array9[2, 3] = array9[2, 0] ^ -1223135700;
							int num45 = array9[2, 3] ^ -1758409819;
							int[,] array10 = new int[3, 3];
							array10[0, 0] = 1120291478;
							array10[0, 1] = -1332989436;
							array10[0, 2] = -1187396554;
							array10[1, 0] = 653804122;
							array10[1, 1] = -209590700;
							array10[1, 2] = 728967808;
							array10[2, 0] = 1259393601;
							array10[2, 1] = -699842425;
							array10[2, 2] = -625250235;
							array10[2, 2] = array10[0, 1] ^ 0x68AD990D;
							array10[1, 0] = array10[0, 2] ^ 0xE2FD7E;
							array10[2, 1] = array10[0, 1] ^ -186259687;
							array10[2, 2] = array10[1, 1] ^ 0x73528586;
							int num46 = array10[2, 2] ^ 0x5D587561;
							int num47 = (int)((num4 * 1870267894) ^ 0x5C4D9812);
							num45 ^= num47;
							num46 ^= num47;
							int num48;
							int num49;
							if (num44 != ShellSection.Methods)
							{
								num48 = num46;
								num49 = num48;
							}
							else
							{
								num48 = num45;
								num49 = num48;
							}
							num = num48 ^ num47;
						}
					}
					else
					{
						currentSection = DaU_003D.CurrentSection;
						int[] array11 = new int[4];
						array11[0] = 398479428;
						array11[1] = -771861896;
						array11[2] = 1334613655;
						array11[3] = 425004698;
						array11[0] = array11[2] ^ 0x40702A49;
						array11[3] ^= 1897730688;
						array11[3] = array11[2] ^ -471989818;
						int[] array12 = new int[5] { 1968209681, -1033923714, 1095741649, -1810403176, -1599658427 };
						int[][] array13 = new int[2][] { array11, array12 };
						array12[2] = array13[0][1] ^ -994763964;
						array12[1] = array12[2] ^ -2118429328;
						array12[4] ^= 1875544338;
						int num50 = array13[1][2] ^ 0x6E4CE4BC;
						num = (int)((num4 * 1410367810) ^ 0xCFE9DC16u) ^ num50;
					}
					continue;
				}
				goto IL_19a7;
			}
			_003D_003D_002A_0026_0025_0023_0040_003C(wEo_003D, (object)null);
			int[] array14 = new int[6];
			array14[0] = 1758188730;
			array14[1] = 1936641254;
			array14[2] = -2074339724;
			array14[3] = 1506012758;
			array14[4] = 1729787097;
			array14[5] = -1645410802;
			array14[4] = array14[5] ^ 0x36802E7A;
			array14[3] = array14[2] ^ -1513692701;
			array14[4] = array14[2] ^ -53412625;
			int[] array15 = new int[5] { 1214421016, -1703289647, 289023864, 1052622511, 271641276 };
			int[][] array16 = new int[2][] { array14, array15 };
			array15[3] = array16[0][5] ^ 0x603C8A39;
			array15[2] = array15[4] ^ 0x27A2927E;
			array15[0] = array15[2] ^ -1007169910;
			array15[0] ^= -1459598173;
			int num51 = array16[1][3] ^ -2055357413;
			num = (int)((num4 * 1994631971) ^ 0xB84082B7u) ^ num51;
		}
		goto IL_0013;
		IL_19a7:
		contentPresenter = wEo_003D;
		num = -2050988896;
		goto IL_0018;
	}

	private void MAj_003D()
	{
		if (DaU_003D.IsAuthenticated)
		{
			goto IL_0013;
		}
		goto IL_16b5;
		IL_0013:
		int num = -999041796;
		goto IL_0018;
		IL_0018:
		NavigationView navigationView = default(NavigationView);
		NavigationViewItem navigationViewItem = default(NavigationViewItem);
		ShellSection currentSection = default(ShellSection);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)(((~(-num2 * -365735199) ^ 0xAED8533) + -(-(~-1027423575 + --1622579662) + (-(~455667318) - (-704390961 ^ 0x6EB5FA5B))) + 1463922525 * -(-1400765096 * -399277853) - (~1588308999 - -1457962033 - (-1792562560 - --1136998411)) - (243360925 + -1175806256 - -1825635753)) * 625559219 - -123046065)) % 19;
			int num5 = -1114567302;
			_ = 0;
			for (int num6 = 0; num6 < 2; num6++)
			{
				num5 = (num5 - -1040899889 * 237240745) ^ 0x421370B2;
				num5 = num5 * -1214457887 * -139884151;
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = 2110608686;
			_ = 0;
			for (int num8 = 0; num8 < 1; num8++)
			{
				num7 -= 2110608675;
			}
			if (num3 != (uint)num7)
			{
				int num9 = 1700330198;
				_ = 0;
				for (int num10 = 0; num10 < 1; num10++)
				{
					num9 -= 1700330190;
				}
				if (num3 != (uint)num9)
				{
					int num11 = -2010886713;
					_ = 0;
					for (int num12 = 0; num12 < 1; num12++)
					{
						num11 *= 556376935;
					}
					if (num3 != (uint)num11)
					{
						int num13 = -1182151538;
						_ = 0;
						for (int num14 = 0; num14 < 1; num14++)
						{
							num13 ^= -1182151541;
						}
						if (num3 != (uint)num13)
						{
							int num15 = -2125979258;
							_ = 0;
							for (int num16 = 0; num16 < 2; num16++)
							{
								num15 -= 0x57BC6A48 ^ -333478448;
								num15 = num15 ^ -1573052735 ^ -1791167507;
							}
							if (num3 != (uint)num15)
							{
								int num17 = -16714236;
								_ = 0;
								for (int num18 = 0; num18 < 2; num18++)
								{
									num17 ^= 0x7D4372EB;
									num17 = -((0x724354CE ^ 0x79823D4F) - num17);
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
										int num21 = 1958734606;
										_ = 0;
										for (int num22 = 0; num22 < 1; num22++)
										{
											num21 *= 1217052947;
										}
										if (num3 != (uint)num21)
										{
											int num23 = -1635407550;
											_ = 0;
											for (int num24 = 0; num24 < 2; num24++)
											{
												num23 = (num23 * -2021813823) ^ 0x11FCE6CD;
												num23 = ~num23 + -660072057;
											}
											if (num3 != (uint)num23)
											{
												int num25 = -1058397109;
												_ = 0;
												for (int num26 = 0; num26 < 1; num26++)
												{
													num25 -= -1058397118;
												}
												if (num3 != (uint)num25)
												{
													int num27 = -7;
													_ = 0;
													for (int num28 = 0; num28 < 1; num28++)
													{
														num27 = -num27;
													}
													if (num3 != (uint)num27)
													{
														int num29 = -854479996;
														_ = 0;
														for (int num30 = 0; num30 < 2; num30++)
														{
															num29 = ~(~num29);
															num29 = -1590303233 - (555592991 + 1721831065 - num29);
														}
														if (num3 != (uint)num29)
														{
															int num31 = -2060328639;
															_ = 0;
															for (int num32 = 0; num32 < 1; num32++)
															{
																num31 ^= -2060328625;
															}
															if (num3 != (uint)num31)
															{
																int num33 = -744861741;
																_ = 0;
																for (int num34 = 0; num34 < 1; num34++)
																{
																	num33 *= 1902108763;
																}
																if (num3 != (uint)num33)
																{
																	int num35 = -1560358519;
																	_ = 0;
																	for (int num36 = 0; num36 < 1; num36++)
																	{
																		num35 += 1560358522;
																	}
																	if (num3 == (uint)num35)
																	{
																		return;
																	}
																	int num37 = 0;
																	_ = 0;
																	for (int num38 = 0; num38 < 1; num38++)
																	{
																		num37 *= -1136592761;
																	}
																	if (num3 != (uint)num37)
																	{
																		int num39 = -16;
																		_ = 0;
																		for (int num40 = 0; num40 < 1; num40++)
																		{
																			num39 = ~num39;
																		}
																		if (num3 != (uint)num39)
																		{
																			int num41 = -67104371;
																			_ = 0;
																			for (int num42 = 0; num42 < 2; num42++)
																			{
																				num41 ^= -687211190;
																				num41 = ~(num41 - (-167867831 ^ 0x74837FDC));
																			}
																			if (num3 == (uint)num41)
																			{
																			}
																			return;
																		}
																		_0021_002A_0021_0024_002A_0024_0023_005E((UIElement)rpw_003D, Visibility.Visible);
																		int[] array = new int[4];
																		array[0] = 1098623947;
																		array[1] = -1084493285;
																		array[2] = -908027458;
																		array[3] = -1749243716;
																		array[0] = array[3] ^ 0x3098D491;
																		array[2] = array[1] ^ 0x55E51E25;
																		array[3] ^= -240951403;
																		int[] array2 = new int[5] { -904328916, 669450056, -1024570062, 2027429069, 301962027 };
																		int[][] array3 = new int[2][] { array, array2 };
																		array2[2] = array3[0][1] ^ -1011430889;
																		array2[4] = array2[0] ^ 0x4C40B29B;
																		array2[0] = array2[3] ^ 0x613C3860;
																		int num43 = array3[1][2] ^ 0x437D6188;
																		num = ((int)num4 * -254935435) ^ 0x58F51D0F ^ num43;
																		continue;
																	}
																	goto IL_16b5;
																}
																_0023_0040_002B_0024_005E_0040__003E((Control)nfB_003D, xAv_003D.ViewModel.CanAccessMethodExplorer);
																int[] array4 = new int[5] { -1021960041, -1037357791, 1365390060, -927315989, -852605808 };
																array4[3] ^= 2060653627;
																array4[4] = array4[0] ^ -444406059;
																array4[1] = array4[3] ^ -685871132;
																int[] array5 = new int[5] { 2080488802, -1471932741, 590456613, -1008286832, -1284201018 };
																int[][] array6 = new int[2][] { array4, array5 };
																array5[3] = array6[0][0] ^ 0x68A61750;
																array5[2] = array5[1] ^ -280252688;
																array5[2] = array5[4] ^ 0x215F5E1E;
																int num44 = array6[1][3] ^ -1046728036;
																num = ((int)num4 * -1156310838) ^ 0x2B6F1282 ^ num44;
																continue;
															}
															_0024_0029_003C_0026_0024_0025_0029_(navigationView, (object)navigationViewItem);
															num = 1841278871;
															continue;
														}
														navigationViewItem = mVZ_003D;
														num = -677353219;
														continue;
													}
													int[,] array7 = new int[3, 3];
													array7[0, 0] = 721556129;
													array7[0, 1] = -893258304;
													array7[0, 2] = -263922203;
													array7[1, 0] = 120082386;
													array7[1, 1] = 1180359313;
													array7[1, 2] = -1870496830;
													array7[2, 0] = -1677461334;
													array7[2, 1] = -1721573662;
													array7[2, 2] = -314968589;
													array7[2, 0] = array7[1, 1] ^ 0x72AA44C;
													array7[0, 2] = array7[2, 2] ^ 0x66C62AE1;
													array7[1, 2] ^= -1741345265;
													array7[0, 0] = array7[1, 1] ^ 0x12F5A510;
													int num45 = array7[0, 0] ^ -2096162948;
													num = (int)((num4 * 1182702144) ^ 0x80563700u) ^ num45;
													continue;
												}
												navigationViewItem = hYn_003D;
												num = 396965386;
												continue;
											}
											int[,] array8 = new int[3, 3];
											array8[0, 0] = 1882154510;
											array8[0, 1] = -319603910;
											array8[0, 2] = 681756892;
											array8[1, 0] = -1908172765;
											array8[1, 1] = -1264415695;
											array8[1, 2] = -865753961;
											array8[2, 0] = 1437618651;
											array8[2, 1] = 955957403;
											array8[2, 2] = -108137569;
											array8[2, 2] = array8[0, 2] ^ -1083187964;
											array8[2, 0] = array8[1, 1] ^ 0x7AED42AE;
											array8[1, 1] = array8[1, 0] ^ 0x6E58F87A;
											array8[1, 2] = array8[0, 2] ^ 0x1CC7194D;
											int num46 = array8[1, 2] ^ -473581204;
											num = (int)((num4 * 1459749534) ^ 0x28E580BC) ^ num46;
											continue;
										}
										navigationViewItem = nfB_003D;
										num = 1107167024;
										continue;
									}
									int[] array9 = new int[5];
									array9[0] = -1918987330;
									array9[1] = 1879372500;
									array9[2] = -1211887018;
									array9[3] = 488718263;
									array9[4] = -603502822;
									array9[0] = array9[1] ^ 0x1DAAAA2A;
									array9[4] = array9[3] ^ 0x39A35A38;
									array9[2] = array9[4] ^ -1091688526;
									int[] array10 = new int[5] { 1846192767, 1767789184, 453358663, -2049066595, 353934379 };
									int[][] array11 = new int[2][] { array9, array10 };
									array10[2] = array11[0][3] ^ 0x306F14D9;
									array10[4] = array10[2] ^ -1401380151;
									array10[1] = array10[2] ^ 0x645C9F1;
									array10[1] ^= 1436532457;
									int num47 = array11[1][2] ^ -1254375864;
									num = (int)((num4 * 2131891714) ^ 0xF957AD92u) ^ num47;
									continue;
								}
								ShellSection num48 = currentSection;
								int[] array12 = new int[6];
								array12[0] = -962939983;
								array12[1] = -1064749305;
								array12[2] = 512157053;
								array12[3] = -228236949;
								array12[4] = 1996897491;
								array12[5] = -1902998349;
								array12[1] = array12[4] ^ -911915509;
								array12[4] = array12[0] ^ 0x2DD2D51;
								array12[2] = array12[0] ^ 0x1E73A86C;
								int[] array13 = new int[5] { -1606874088, 1472882492, 847401206, -106376315, -1948169603 };
								int[][] array14 = new int[2][] { array12, array13 };
								array13[2] = array14[0][5] ^ -1932206334;
								array13[4] = array13[0] ^ -1415068981;
								array13[4] = array13[0] ^ -1723549196;
								array13[4] = array13[1] ^ -2091091830;
								int num49 = array14[1][2] ^ -174066796;
								int[] array15 = new int[4];
								array15[0] = 535783238;
								array15[1] = -1980149711;
								array15[2] = 1998482070;
								array15[3] = -495927465;
								array15[0] = array15[2] ^ -405252343;
								array15[0] = array15[1] ^ 0x1D9CD626;
								int[] array16 = new int[6];
								array16[0] = -1905263276;
								array16[1] = 2062376369;
								array16[2] = 1535577386;
								array16[3] = 1406392232;
								array16[4] = 593463922;
								array16[5] = 326993127;
								array16[0] = array15[1] ^ 0x2E54751E;
								array16[3] = array16[0] ^ -1937579983;
								array16[5] = array16[4] ^ -2053670623;
								int num50 = array16[0] ^ -383121916;
								int num51 = (int)(num4 * 1647007747) ^ -1771954268;
								num49 ^= num51;
								num50 ^= num51;
								int num52;
								int num53;
								if (num48 != ShellSection.Settings)
								{
									num52 = num50;
									num53 = num52;
								}
								else
								{
									num52 = num49;
									num53 = num52;
								}
								num = num52 ^ num51;
								continue;
							}
							ShellSection num54 = currentSection;
							int[,] array17 = new int[3, 3];
							array17[0, 0] = -1595088957;
							array17[0, 1] = 614637955;
							array17[0, 2] = 377832528;
							array17[1, 0] = -2139000844;
							array17[1, 1] = -88067012;
							array17[1, 2] = -1643350531;
							array17[2, 0] = 1167713364;
							array17[2, 1] = 873762874;
							array17[2, 2] = -834303999;
							array17[2, 2] = array17[1, 0] ^ 0x5D84D398;
							array17[2, 1] = array17[0, 2] ^ 0x3F4570FC;
							array17[2, 2] = array17[0, 1] ^ 0x217A8251;
							int num55 = array17[2, 2] ^ -1978376148;
							int[,] array18 = new int[3, 3];
							array18[0, 0] = -2147069938;
							array18[0, 1] = 668461820;
							array18[0, 2] = 1065470048;
							array18[1, 0] = 266931044;
							array18[1, 1] = -1375100763;
							array18[1, 2] = 1018894266;
							array18[2, 0] = -1127006654;
							array18[2, 1] = 1971749083;
							array18[2, 2] = -1257426973;
							array18[2, 2] = array18[1, 1] ^ -1522544389;
							array18[0, 0] = array18[1, 1] ^ -491347427;
							array18[2, 2] = array18[1, 1] ^ -1055267149;
							array18[0, 1] = array18[2, 1] ^ -1800796797;
							int num56 = array18[0, 1] ^ -1782212990;
							int num57 = (int)((num4 * 1001920339) ^ 0x14B5F5F);
							num55 ^= num57;
							num56 ^= num57;
							int num58;
							int num59;
							if (num54 != ShellSection.Methods)
							{
								num58 = num56;
								num59 = num58;
							}
							else
							{
								num58 = num55;
								num59 = num58;
							}
							num = num58 ^ num57;
							continue;
						}
						currentSection = DaU_003D.CurrentSection;
						int[] array19 = new int[7];
						array19[0] = 164102971;
						array19[1] = 892694959;
						array19[2] = 296272875;
						array19[3] = -624581613;
						array19[4] = -1631689371;
						array19[5] = -2141593252;
						array19[6] = -1541909314;
						array19[0] = array19[4] ^ 0x4780417B;
						array19[2] ^= -1758727204;
						array19[4] = array19[0] ^ 0x79209228;
						int[] array20 = new int[5];
						array20[0] = -1444728973;
						array20[1] = -707607816;
						array20[2] = -1974977435;
						array20[3] = 1932769591;
						array20[4] = -1379667464;
						array20[4] = array19[6] ^ -146930194;
						array20[1] = array20[4] ^ -847138771;
						array20[1] = array20[2] ^ -703576137;
						int num60 = array20[4] ^ -2141320497;
						num = (int)((num4 * 729908121) ^ 0xF6A99076u) ^ num60;
						continue;
					}
					navigationView = sDd_003D;
					int[] array21 = new int[6];
					array21[0] = 1185764719;
					array21[1] = 1078840148;
					array21[2] = 367133251;
					array21[3] = 1121559678;
					array21[4] = -1315816329;
					array21[5] = 1432592618;
					array21[5] = array21[2] ^ 0xE80CBFB;
					array21[4] = array21[1] ^ -51424429;
					array21[2] = array21[1] ^ 0xC168CE2;
					int[] array22 = new int[7];
					array22[0] = -1453622869;
					array22[1] = 776130150;
					array22[2] = 1504612817;
					array22[3] = -1785002950;
					array22[4] = 1888142277;
					array22[5] = 1449004843;
					array22[6] = 1419024624;
					array22[5] = array21[1] ^ 0x694A3DC;
					array22[2] = array22[3] ^ 0x1AEB205D;
					array22[3] = array22[2] ^ 0x515CD29;
					array22[2] = array22[5] ^ -1959766735;
					int num61 = array22[5] ^ 0x414A7AD4;
					num = (int)((num4 * 1778294820) ^ 0x806A7098u) ^ num61;
					continue;
				}
				_0021_002A_0021_0024_002A_0024_0023_005E((UIElement)sDd_003D, Visibility.Visible);
				int[,] array23 = new int[3, 4];
				array23[0, 0] = 1492869076;
				array23[0, 1] = -1272968807;
				array23[0, 2] = 241206393;
				array23[0, 3] = -1502665332;
				array23[1, 0] = -109233156;
				array23[1, 1] = 179878725;
				array23[1, 2] = 2090252849;
				array23[1, 3] = -2093607649;
				array23[2, 0] = 13143660;
				array23[2, 1] = 416046628;
				array23[2, 2] = 796284251;
				array23[2, 3] = 195399464;
				array23[1, 3] = array23[0, 0] ^ 0x48698887;
				array23[0, 3] = array23[0, 1] ^ -84765284;
				array23[0, 3] = array23[2, 3] ^ -38693621;
				array23[0, 2] = array23[2, 0] ^ 0x3D3B8790;
				int num62 = array23[0, 2] ^ -1610371504;
				num = (int)((num4 * 878139702) ^ 0xC5BDE066u) ^ num62;
				continue;
			}
			_0021_002A_0021_0024_002A_0024_0023_005E((UIElement)rpw_003D, Visibility.Collapsed);
			int[] array24 = new int[6];
			array24[0] = 42984717;
			array24[1] = -1717081676;
			array24[2] = 1414400112;
			array24[3] = 1633774337;
			array24[4] = 238657905;
			array24[5] = -63242294;
			array24[4] = array24[2] ^ -1321437084;
			array24[0] ^= 454627242;
			array24[4] = array24[1] ^ -1765177594;
			int[] array25 = new int[4];
			array25[0] = 599868038;
			array25[1] = 1890810169;
			array25[2] = -628186230;
			array25[3] = 1647684615;
			array25[1] = array24[2] ^ -595988569;
			array25[0] = array25[3] ^ 0x6A2B0E5B;
			array25[2] = array25[0] ^ -1180375189;
			int num63 = array25[1] ^ -1799675012;
			num = (int)((num4 * 1858542322) ^ 0x305ADBAC) ^ num63;
		}
		goto IL_0013;
		IL_16b5:
		_0021_002A_0021_0024_002A_0024_0023_005E((UIElement)sDd_003D, Visibility.Collapsed);
		num = 1625023925;
		goto IL_0018;
	}

	private void UMc_003D(object? rYu_003D, PropertyChangedEventArgs ILM_003D)
	{
		if (!__0025_003D_0024_0021_003F_005E_005E(_002A_002A_0029_0024_0024_003F__0024(ILM_003D), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xA0E2 ^ 0xA0ED]))
		{
			goto IL_0036;
		}
		goto IL_03f1;
		IL_0036:
		int num = 1538538098;
		goto IL_003b;
		IL_003b:
		uint num3;
		while (true)
		{
			int num2 = num;
			uint num4;
			num3 = (num4 = (uint)(-(--192062668 - -(((((383920195 + ((-(-(-975573249 + 2118498827)) + -1990970547 * ((0x8F32CA2 ^ -1397747558) * -1655540605)) ^ 0x2318FF6)) * 1510964283 - (-685676545 * (823003393 - (-1721857440 ^ -1545910134)) + (-261686077 * ~2107757801 + (-95026438 - (-1079971870 + 561093848) + -975481085) * -1312845517) - (-(-(-210003270 ^ 0x5D4EF128)) - -1715329915)) - num2 * 1052680359 + -(248885949 * (~(~((0x4AA8C340 ^ -462202625) + (589716769 - -538896131))) * 2081438145))) ^ (2002633619 * (~(-761279844 ^ -1516455855) + -(-1652333865) - -110160960) + -(~(-826127822 ^ -(-725126714 + -695969182))))) - ((-(610653834 + 1653206036 + (-1868839416 + -234777915)) * -1101752093) ^ (150830597 * (1483024241 * -(179848867 + -2031603788)))) - ~(~(1322276896 - 762602130) + ~(340343839 + -1292501111))) ^ (-1247297262 ^ -(-939597325 * 113674229)))))) % 5;
			int num5 = 1177938668;
			_ = 0;
			for (int num6 = 0; num6 < 1; num6++)
			{
				num5 -= 1177938665;
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = 550832129;
			_ = 0;
			for (int num8 = 0; num8 < 1; num8++)
			{
				num7 = 550832130 - num7;
			}
			if (num3 != (uint)num7)
			{
				int num9 = -1373835916;
				_ = 0;
				for (int num10 = 0; num10 < 2; num10++)
				{
					num9 = num9 - (-386864980 - 1910734767) - -466746849;
					num9 *= 877204051;
				}
				if (num3 == (uint)num9)
				{
					bool num11 = __0025_003D_0024_0021_003F_005E_005E(_002A_002A_0029_0024_0024_003F__0024(ILM_003D), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-155 + 137)]);
					int[,] array = new int[4, 4];
					array[0, 0] = 953240716;
					array[0, 1] = 382537795;
					array[0, 2] = 1455482669;
					array[0, 3] = -1366224740;
					array[1, 0] = 1049776708;
					array[1, 1] = 2033289981;
					array[1, 2] = -1354669500;
					array[1, 3] = -1570846978;
					array[2, 0] = 1557585636;
					array[2, 1] = -1399796629;
					array[2, 2] = -1327501542;
					array[2, 3] = -455481128;
					array[3, 0] = 805148964;
					array[3, 1] = 1859865109;
					array[3, 2] = -1689207526;
					array[3, 3] = 591259965;
					array[0, 0] = array[1, 0] ^ -386857485;
					array[1, 2] = array[2, 3] ^ 0x1FC2ED2B;
					array[2, 0] = array[0, 3] ^ -1667181776;
					array[0, 1] = array[3, 2] ^ -698777045;
					int num12 = array[0, 1] ^ 0x5B7397B4;
					int[,] array2 = new int[4, 4];
					array2[0, 0] = -1175951557;
					array2[0, 1] = 1509188389;
					array2[0, 2] = -1574524098;
					array2[0, 3] = -1901354002;
					array2[1, 0] = 31441141;
					array2[1, 1] = 248178507;
					array2[1, 2] = 670053348;
					array2[1, 3] = 762688122;
					array2[2, 0] = -480721231;
					array2[2, 1] = 1813215864;
					array2[2, 2] = -1772221241;
					array2[2, 3] = 791721316;
					array2[3, 0] = 1041752019;
					array2[3, 1] = 1003120408;
					array2[3, 2] = 764464887;
					array2[3, 3] = -925189301;
					array2[0, 1] = array2[2, 0] ^ 0x3EFF8A72;
					array2[1, 0] = array2[0, 1] ^ 0x6107A7C3;
					array2[3, 0] = array2[0, 0] ^ -679941631;
					int num13 = array2[3, 0] ^ -1869418224;
					int num14 = ((int)num4 * -2096103876) ^ 0x2E098104;
					num12 ^= num14;
					num13 ^= num14;
					int num15;
					int num16;
					if (num11)
					{
						num15 = num13;
						num16 = num15;
					}
					else
					{
						num15 = num12;
						num16 = num15;
					}
					num = num15 ^ num14;
					continue;
				}
				goto IL_032b;
			}
			bool num17 = __0025_003D_0024_0021_003F_005E_005E(_002A_002A_0029_0024_0024_003F__0024(ILM_003D), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[82 - 7 - 36 - 23]);
			int[] array3 = new int[5];
			array3[0] = -50013393;
			array3[1] = -301774723;
			array3[2] = -1634055026;
			array3[3] = 1180154104;
			array3[4] = -1972689583;
			array3[2] = array3[1] ^ 0x388260B8;
			array3[4] ^= 1761865363;
			array3[1] = array3[2] ^ 0x6660F645;
			int[] array4 = new int[5];
			array4[0] = 765373152;
			array4[1] = -1724590254;
			array4[2] = 961933446;
			array4[3] = -913518123;
			array4[4] = -1794044854;
			array4[4] = array3[0] ^ 0x4EFADF37;
			array4[1] ^= -211321914;
			array4[0] = array4[3] ^ -1016379592;
			int num18 = array4[4] ^ 0x4DFC7832;
			int[,] array5 = new int[4, 3];
			array5[0, 0] = 1635596496;
			array5[0, 1] = 594602750;
			array5[0, 2] = -875094700;
			array5[1, 0] = 582799131;
			array5[1, 1] = 2145371103;
			array5[1, 2] = 1223909262;
			array5[2, 0] = 994148505;
			array5[2, 1] = -1911999800;
			array5[2, 2] = -2033060702;
			array5[3, 0] = -1270619381;
			array5[3, 1] = -1456341800;
			array5[3, 2] = -550300841;
			array5[3, 0] = array5[1, 0] ^ 0x504C2B;
			array5[0, 2] = array5[3, 2] ^ -226238867;
			array5[2, 1] = array5[3, 0] ^ -1804395963;
			array5[3, 1] = array5[0, 0] ^ -423359836;
			int num19 = array5[3, 1] ^ 0x676BE0F0;
			int num20 = ((int)num4 * -384137451) ^ -1263013391;
			num18 ^= num20;
			num19 ^= num20;
			int num21;
			int num22;
			if (!num17)
			{
				num21 = num19;
				num22 = num21;
			}
			else
			{
				num21 = num18;
				num22 = num21;
			}
			num = num21 ^ num20;
		}
		goto IL_0036;
		IL_03f1:
		_0023_0040_002B_0024_005E_0040__003E((Control)nfB_003D, xAv_003D.ViewModel.CanAccessMethodExplorer);
		num = 377137285;
		goto IL_003b;
		IL_032b:
		int num23 = 1121945405;
		_ = 0;
		for (int num24 = 0; num24 < 1; num24++)
		{
			num23 -= 1121945403;
		}
		if (num3 != (uint)num23)
		{
			int num25 = -868092814;
			_ = 0;
			for (int num26 = 0; num26 < 2; num26++)
			{
				num25 = num25 - -248278960 + 2129650172;
				num25 = -1943882726 - ~num25;
			}
			if (num3 == (uint)num25)
			{
			}
			return;
		}
		goto IL_03f1;
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public void vjV_003D()
	{
		if (DnV_003D)
		{
			goto IL_000e;
		}
		goto IL_05d0;
		IL_000e:
		int num = 214614506;
		goto IL_0013;
		IL_0013:
		Uri uri = default(Uri);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)((~(~946339064 + 240827077) - ~num2) * 1140671707 - (~((~1885417610 - ~417023696 - 165356569) * -1277660393) - ~((0x6B49C87C ^ -1484504684) + (-1195770479 + 156805256 + -1073024943 * 631089197) * 1806762981)))) % 5;
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
			if (num3 == (uint)num7)
			{
				return;
			}
			int num9 = 2;
			_ = 0;
			for (int num10 = 0; num10 < 2; num10++)
			{
				num9 = ~(-num9);
				num9 = ~(~num9);
			}
			if (num3 != (uint)num9)
			{
				int num11 = -468918329;
				_ = 0;
				for (int num12 = 0; num12 < 2; num12++)
				{
					num11 = (num11 ^ -1758834876) + -770580694;
					num11 ^= -84534756;
				}
				if (num3 != (uint)num11)
				{
					int num13 = -590556760;
					_ = 0;
					for (int num14 = 0; num14 < 2; num14++)
					{
						num13 = -num13 + -1292167709;
						num13 = (num13 - (-2133084981 + -32963058)) * 401398471;
					}
					if (num3 != (uint)num13)
					{
					}
					_0024_0026_003D_005E_0040_0024_003D_0024((object)this, uri, ComponentResourceLocation.Application);
					return;
				}
				uri = new Uri(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x167C8 ^ 0x167DA))]);
				int[,] array = new int[3, 3];
				array[0, 0] = 1129164353;
				array[0, 1] = -1430072868;
				array[0, 2] = -2120842133;
				array[1, 0] = -1318592613;
				array[1, 1] = 777559253;
				array[1, 2] = -83733840;
				array[2, 0] = 1786503316;
				array[2, 1] = 67717213;
				array[2, 2] = -1527173396;
				array[1, 1] = array[0, 2] ^ -1742074574;
				array[2, 2] = array[1, 0] ^ 0x63EE699F;
				array[1, 0] = array[1, 2] ^ -184601879;
				int num15 = array[1, 0] ^ 0x23A67B03;
				num = (int)((num4 * 373173161) ^ 0x8E0F69E4u) ^ num15;
				continue;
			}
			goto IL_05d0;
		}
		goto IL_000e;
		IL_05d0:
		DnV_003D = true;
		num = 103496361;
		goto IL_0013;
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public void Connect(int yvS_003D, object Nqy_003D)
	{
		int num;
		switch (yvS_003D)
		{
		default:
			num = 1997950208;
			goto IL_0038;
		case 4:
			rpw_003D = Nqy_003D.As<LoginView>();
			num = 1787597399;
			goto IL_0038;
		case 9:
			wEo_003D = Nqy_003D.As<ContentPresenter>();
			num = 1941629798;
			goto IL_0038;
		case 7:
			nfB_003D = Nqy_003D.As<NavigationViewItem>();
			num = 1491839159;
			goto IL_0038;
		case 8:
			hYn_003D = Nqy_003D.As<NavigationViewItem>();
			num = 289657710;
			goto IL_0038;
		case 5:
			sDd_003D = Nqy_003D.As<NavigationView>();
			num = 2019240369;
			goto IL_0038;
		case 3:
			ooe_003D = Nqy_003D.As<Grid>();
			num = 753310799;
			goto IL_0038;
		case 6:
			mVZ_003D = Nqy_003D.As<NavigationViewItem>();
			num = 2050963198;
			goto IL_0038;
		case 2:
			ZvE_003D = Nqy_003D.As<Grid>();
			num = 1711234292;
			goto IL_0038;
		case 1:
			{
				AUl_003D = Nqy_003D.As<Window>();
				num = 415282910;
				goto IL_0038;
			}
			IL_0038:
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(-(-(-1568182055 * 762003175))) - -(-(~num2 * 544090931) - 919824469 * ((0x3F1F0F90 ^ -1282222045) - (0x40D1E65D ^ --2092405695) - (-(-(-142950071)) + (865002143 * 1047271139 + (-1568826652 - 587645271 + (962963585 + 355565170)))))))) % 22;
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
				int num7 = 157843327;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -(num7 * -1552760439);
					num7 ^= -610765559;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1235655920;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = (num9 ^ 0x2F328522) * -1508615601;
						num9 = ~(num9 ^ 0x1C0340C3);
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
							int num13 = -13;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 = -num13;
							}
							if (num3 != (uint)num13)
							{
								int num15 = -533346507;
								_ = 0;
								for (int num16 = 0; num16 < 2; num16++)
								{
									num15 -= -891190802 ^ -1785922923;
									num15 = num15 - --184991443 - 94808387;
								}
								if (num3 != (uint)num15)
								{
									int num17 = -764421636;
									_ = 0;
									for (int num18 = 0; num18 < 2; num18++)
									{
										num17 = -num17 * 1718063201;
										num17 = (num17 ^ 0x692D0D6D) * 564314617;
									}
									if (num3 == (uint)num17)
									{
										goto case 3;
									}
									int num19 = -18;
									_ = 0;
									for (int num20 = 0; num20 < 1; num20++)
									{
										num19 = -num19;
									}
									if (num3 != (uint)num19)
									{
										int num21 = 505622795;
										_ = 0;
										for (int num22 = 0; num22 < 2; num22++)
										{
											num21 = (num21 ^ -1824608344) - 812595052;
											num21 = -num21;
										}
										if (num3 == (uint)num21)
										{
											goto case 4;
										}
										int num23 = 144704502;
										_ = 0;
										for (int num24 = 0; num24 < 2; num24++)
										{
											num23 = -num23 - -1112015296;
											num23 = ~(num23 ^ -626377675);
										}
										if (num3 != (uint)num23)
										{
											int num25 = -1006001835;
											_ = 0;
											for (int num26 = 0; num26 < 1; num26++)
											{
												num25 ^= -1006001855;
											}
											if (num3 == (uint)num25)
											{
												goto case 5;
											}
											int num27 = 1701057332;
											_ = 0;
											for (int num28 = 0; num28 < 1; num28++)
											{
												num27 ^= 0x65641332;
											}
											if (num3 != (uint)num27)
											{
												int num29 = -1256627707;
												_ = 0;
												for (int num30 = 0; num30 < 2; num30++)
												{
													num29 = ~num29 - -1519169787;
													num29 = -num29;
												}
												if (num3 != (uint)num29)
												{
													int num31 = -8;
													_ = 0;
													for (int num32 = 0; num32 < 1; num32++)
													{
														num31 = -num31;
													}
													if (num3 != (uint)num31)
													{
														int num33 = -6;
														_ = 0;
														for (int num34 = 0; num34 < 1; num34++)
														{
															num33 = ~num33;
														}
														if (num3 != (uint)num33)
														{
															int num35 = -1112273136;
															_ = 0;
															for (int num36 = 0; num36 < 2; num36++)
															{
																num35 = ~(num35 - (-1908293093 + 1938184692));
																num35 = -(num35 * 299081817);
															}
															if (num3 == (uint)num35)
															{
																goto case 7;
															}
															int num37 = -16;
															_ = 0;
															for (int num38 = 0; num38 < 1; num38++)
															{
																num37 = -num37;
															}
															if (num3 != (uint)num37)
															{
																int num39 = 1620487214;
																_ = 0;
																for (int num40 = 0; num40 < 1; num40++)
																{
																	num39 ^= 0x6096AC20;
																}
																if (num3 != (uint)num39)
																{
																	int num41 = 1375731727;
																	_ = 0;
																	for (int num42 = 0; num42 < 2; num42++)
																	{
																		num41 = (num41 ^ 0x4ADA778) - -1490954745;
																		num41 = num41 ^ 0x29961553 ^ 0x7B4C45E2;
																	}
																	if (num3 != (uint)num41)
																	{
																		int num43 = 21;
																		_ = 0;
																		for (int num44 = 0; num44 < 2; num44++)
																		{
																			num43 = num43 - -1293267307 - 2091759358;
																			num43 = 1311353277 - (num43 - -675350031);
																		}
																		if (num3 != (uint)num43)
																		{
																			int num45 = 1642064759;
																			_ = 0;
																			for (int num46 = 0; num46 < 1; num46++)
																			{
																				num45 *= 997364721;
																			}
																			if (num3 != (uint)num45)
																			{
																				int num47 = -589634865;
																				_ = 0;
																				for (int num48 = 0; num48 < 2; num48++)
																				{
																					num47 = -num47 * -1039288159;
																					num47 = (num47 - (703676032 + -933201995)) ^ 0x6DADFF63;
																				}
																				if (num3 == (uint)num47)
																				{
																				}
																				return;
																			}
																			DnV_003D = true;
																			num = -916921946;
																			continue;
																		}
																		goto case 9;
																	}
																	int[] array = new int[5];
																	array[0] = 1427363039;
																	array[1] = 259492587;
																	array[2] = 1328755917;
																	array[3] = 934393859;
																	array[4] = -413977426;
																	array[4] = array[3] ^ -1447033689;
																	array[4] = array[1] ^ -121880188;
																	int[] array2 = new int[5];
																	array2[0] = 2133736133;
																	array2[1] = 1654052626;
																	array2[2] = -477322189;
																	array2[3] = -54429649;
																	array2[4] = -1511917481;
																	array2[3] = array[1] ^ 0x5802CC77;
																	array2[0] = array2[4] ^ -592714765;
																	array2[1] = array2[3] ^ -1108992452;
																	int num49 = array2[3] ^ 0x24CFADFA;
																	num = ((int)num4 * -334073757) ^ 0x6ACBA595 ^ num49;
																	continue;
																}
																goto case 8;
															}
															int[] array3 = new int[6] { 2085885784, 1146071442, -1364468903, 809078394, 1322863153, -1293581326 };
															array3[2] ^= 482441505;
															array3[1] = array3[4] ^ -1977835771;
															array3[3] = array3[2] ^ 0xFC0C89;
															int[] array4 = new int[7];
															array4[0] = 1277465630;
															array4[1] = 342605528;
															array4[2] = -21681236;
															array4[3] = 908330655;
															array4[4] = -2091165752;
															array4[5] = -64122333;
															array4[6] = 2133101653;
															array4[3] = array3[0] ^ -729391479;
															array4[1] = array4[4] ^ -195466527;
															array4[1] = array4[6] ^ -1632285862;
															int num50 = array4[3] ^ -613899593;
															num = ((int)num4 * -1342123023) ^ -982151918 ^ num50;
															continue;
														}
														int[] array5 = new int[7] { 1198737677, 808852048, 1091070017, -107730964, -1329020341, 2114791131, -1014395063 };
														array5[5] ^= -1901929429;
														array5[3] = array5[5] ^ -33669928;
														array5[6] = array5[1] ^ 0x72794CC7;
														int[] array6 = new int[7];
														array6[0] = 1201332958;
														array6[1] = 2108945063;
														array6[2] = 1575342551;
														array6[3] = 56717961;
														array6[4] = 1511173652;
														array6[5] = -1463686566;
														array6[6] = -48106161;
														array6[3] = array5[1] ^ -589441879;
														array6[0] = array6[5] ^ 0x798B5C8E;
														array6[1] = array6[0] ^ -551176518;
														int num51 = array6[3] ^ -1622071905;
														num = (int)((num4 * 966866957) ^ 0x8F5156B) ^ num51;
														continue;
													}
													goto case 6;
												}
												int[,] array7 = new int[3, 3];
												array7[0, 0] = 240811644;
												array7[0, 1] = 1560690513;
												array7[0, 2] = 81759898;
												array7[1, 0] = 1287061361;
												array7[1, 1] = 578634151;
												array7[1, 2] = 510130649;
												array7[2, 0] = -1853662039;
												array7[2, 1] = 311549343;
												array7[2, 2] = -1188866269;
												array7[1, 1] = array7[2, 1] ^ -741655256;
												array7[1, 2] = array7[2, 1] ^ 0x7A88CBD7;
												array7[2, 0] = array7[2, 1] ^ 0x671BD3DA;
												int num52 = array7[2, 0] ^ 0x630E523;
												num = ((int)num4 * -824113030) ^ -510577998 ^ num52;
												continue;
											}
											_003F_002D_003F_002A_005E_0025_0023_(sDd_003D, (TypedEventHandler<NavigationView, NavigationViewSelectionChangedEventArgs>)nTp_003D);
											int[] array8 = new int[4];
											array8[0] = 1091532862;
											array8[1] = -430349559;
											array8[2] = 1167185518;
											array8[3] = -540176645;
											array8[0] = array8[2] ^ -504522;
											array8[0] = array8[1] ^ 0x3F01E688;
											int[] array9 = new int[5] { -1498774082, 481472200, 1316016670, 1442505733, 241907424 };
											int[][] array10 = new int[2][] { array8, array9 };
											array9[0] = array10[0][2] ^ -1039686334;
											array9[4] ^= 1653359237;
											array9[3] = array9[4] ^ -89947525;
											int num53 = array10[1][0] ^ 0xCB30E1C;
											num = ((int)num4 * -144016193) ^ 0x343EA800 ^ num53;
											continue;
										}
										int[] array11 = new int[4];
										array11[0] = 972015512;
										array11[1] = 1765699443;
										array11[2] = -230880236;
										array11[3] = 885872581;
										array11[2] = array11[1] ^ 0x58510302;
										array11[3] = array11[2] ^ 0x4C8630E4;
										int[] array12 = new int[5];
										array12[0] = -1855798279;
										array12[1] = -647743195;
										array12[2] = -2005151944;
										array12[3] = -555362713;
										array12[4] = -145493292;
										array12[2] = array11[0] ^ -1791789962;
										array12[3] ^= 1658889472;
										array12[1] = array12[3] ^ 0x55C33D57;
										int num54 = array12[2] ^ -546940792;
										num = ((int)num4 * -566684151) ^ 0x6C6137A2 ^ num54;
										continue;
									}
									int[,] array13 = new int[3, 3];
									array13[0, 0] = -551581073;
									array13[0, 1] = -1261807993;
									array13[0, 2] = -1193235085;
									array13[1, 0] = -1129844245;
									array13[1, 1] = 851736751;
									array13[1, 2] = -605791316;
									array13[2, 0] = -205446231;
									array13[2, 1] = -1294265962;
									array13[2, 2] = 1835477914;
									array13[2, 2] = array13[0, 2] ^ -581018157;
									array13[2, 0] = array13[1, 2] ^ 0x1A28F62A;
									array13[1, 2] = array13[2, 1] ^ 0x29121AFB;
									int num55 = array13[1, 2] ^ -395059189;
									num = ((int)num4 * -602490017) ^ 0x3C973446 ^ num55;
									continue;
								}
								int[,] array14 = new int[3, 3];
								array14[0, 0] = -1122205439;
								array14[0, 1] = -263417819;
								array14[0, 2] = -485384241;
								array14[1, 0] = -738812538;
								array14[1, 1] = 711221656;
								array14[1, 2] = 243092759;
								array14[2, 0] = -1830126719;
								array14[2, 1] = 1066408052;
								array14[2, 2] = -566228891;
								array14[2, 0] = array14[2, 1] ^ -935498064;
								array14[0, 2] ^= -1149742962;
								array14[1, 0] = array14[2, 2] ^ -156840151;
								int num56 = array14[1, 0] ^ 0x5B5C2C2A;
								num = ((int)num4 * -131576165) ^ -688412445 ^ num56;
								continue;
							}
							goto case 2;
						}
						int[,] array15 = new int[3, 3];
						array15[0, 0] = 1988871438;
						array15[0, 1] = 343153751;
						array15[0, 2] = -298712077;
						array15[1, 0] = -927649395;
						array15[1, 1] = -99612204;
						array15[1, 2] = -1374660137;
						array15[2, 0] = 1075497675;
						array15[2, 1] = -1680378104;
						array15[2, 2] = 513930392;
						array15[1, 0] = array15[0, 0] ^ -440539759;
						array15[0, 2] = array15[1, 0] ^ 0x74B1E097;
						array15[0, 1] = array15[0, 2] ^ -1622131349;
						array15[2, 1] = array15[1, 2] ^ 0x2FAB1DB7;
						int num57 = array15[2, 1] ^ -234770682;
						num = ((int)num4 * -2064777082) ^ 0x5227A54A ^ num57;
						continue;
					}
					goto case 1;
				}
				int[] array16 = new int[5];
				array16[0] = 339906444;
				array16[1] = 1324197272;
				array16[2] = 1773374998;
				array16[3] = -1906592465;
				array16[4] = -1391067614;
				array16[4] = array16[2] ^ -1170140628;
				array16[2] = array16[0] ^ 0x5BDD2BD3;
				int[] array17 = new int[5];
				array17[0] = 1127232211;
				array17[1] = -1694262745;
				array17[2] = -949911041;
				array17[3] = -1814100972;
				array17[4] = 351710326;
				array17[1] = array16[1] ^ -1111818762;
				array17[0] = array17[2] ^ -1230227406;
				array17[0] ^= 2027925587;
				array17[4] = array17[0] ^ 0x158F5263;
				int num58 = array17[1] ^ -2131905784;
				num = (int)((num4 * 1177669776) ^ 0x5463CA50) ^ num58;
			}
			goto default;
		}
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public IComponentConnector GetBindingConnector(int NLy_003D, object PlU_003D)
	{
		return null;
	}

	static void _002F_003E_0040_005E_0025_0026_002B_0021(FrameworkElement P_0, object P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -788316437;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(-((num2 * -1136808723 - (-441525702 + -351140997 * ~(-(0x2720E8EE ^ (-2018572469 - -990354710 - (-1817116946 + 1651073382) + -(0x36009B12 ^ -266980380)))))) * 1672789709) ^ ~(-(-503392425 * 550877024 + (-1448811826 ^ -1848734796) + (~-1167501565 + (-1254160834 - 1481946980)))) ^ ~(-(-850972478) - -(-997697238 - -1288411479))) * 1197647703) - 1053969048)) % 3;
					int num5 = -11713518;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * -581338675 * -563867327;
						num5 = -num5 * 397860201;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 69435401;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 - (343901321 + 1221634012) - 524381725;
						num7 = ~num7 ^ 0x5A7BC044;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 745299645;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 += -745299645;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.DataContext = P_1;
					int[,] array = new int[4, 4];
					array[0, 0] = -2011809222;
					array[0, 1] = -743467071;
					array[0, 2] = -420062249;
					array[0, 3] = 2004934332;
					array[1, 0] = -372535667;
					array[1, 1] = 1728276452;
					array[1, 2] = -1417058616;
					array[1, 3] = -1654472086;
					array[2, 0] = -308187730;
					array[2, 1] = -730536884;
					array[2, 2] = -1465581430;
					array[2, 3] = -736798810;
					array[3, 0] = 1377779165;
					array[3, 1] = -547125431;
					array[3, 2] = 16370018;
					array[3, 3] = 923944893;
					array[1, 0] = array[3, 3] ^ -126308890;
					array[0, 3] = array[0, 1] ^ 0x1191A3ED;
					array[1, 0] = array[1, 2] ^ -1593233950;
					int num11 = array[1, 0] ^ 0x40367508;
					num = ((int)num4 * -182805482) ^ -127135520 ^ num11;
				}
			}
		}
	}

	static void __0026_0023_0023_003F_002F_0029_0024(ObservableObject P_0, PropertyChangedEventHandler P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -188232855;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(-((-1804313639 ^ (~(-(-788727497) - (1362090173 * -907020712 + ~1133234832)) + (0x4A63DC92 ^ -370674382))) + ~(2032246943 * (~523195418 - ((0x602E5CFA ^ 0x22780CDE) + (-1933212943 ^ 0x13FBE1DE)) * 2044707255))) - (num2 + ~(~(-(-(~(-(1792215460 + 1987754347) * 1726173445))) - ((-773138822 ^ -1552781075) + (((-1139036777 ^ -1596931221) - ~1498848503 * -1967007111 + ((-1338630878 ^ 0x5785F3F2) - -(-1298058053))) ^ (-1056850547 * ~(-131266994 ^ --455580995))))))) - ((((-1136667828 ^ 0x2FB8011D) + (-107153267 + -1593587427 - (1530463815 + -1724946379))) * -1345146717 + -534357989 * -(~-1152471984) - (-(0x3CC419E2 ^ -400790896) ^ 0x33D4F05C)) ^ 0x6D3BC4AD))) ^ ~(~(-399452301 + 1292369769 * -1668283607)))) % 3;
					int num5 = -1669518509;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= -1669518509;
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
						int num9 = 646560097;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x2689B963;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.PropertyChanged += P_1;
					int[] array = new int[7];
					array[0] = -373678837;
					array[1] = 1419973518;
					array[2] = -743912887;
					array[3] = -1903409081;
					array[4] = -1519272685;
					array[5] = -1273016423;
					array[6] = 1349323227;
					array[0] = array[5] ^ 0x3B39229B;
					array[3] = array[2] ^ 0x628F6A38;
					int[] array2 = new int[5];
					array2[0] = 197775866;
					array2[1] = -1511683283;
					array2[2] = -1099396817;
					array2[3] = 612973080;
					array2[4] = -919926852;
					array2[4] = array[1] ^ 0x67EE94AC;
					array2[2] = array2[1] ^ -1382738988;
					array2[3] ^= -46488746;
					int num11 = array2[4] ^ 0x3C38528E;
					num = ((int)num4 * -1159699600) ^ -532769408 ^ num11;
				}
			}
		}
	}

	static void _0028_003C_003C_003D_002A_0029_003E_0024(Window P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -562573518;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(-((~(-(num2 + -(0x55CA801B ^ (-(-(-192310487 * (~(~-1877641741) - (0x31D3126E ^ -1123081147)))) * 1391798401))) * -235135957) - ~(-(0x612B1121 ^ -1779029900))) * -971102401))) * 366237251)) % 3;
					int num5 = 2;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(~num5);
						num5 = ~(num5 ^ --703053783);
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
						int num9 = 1291714386;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 -= -1004635559 * -1190741267;
							num9 = num9 * 1565813209 - -1042298688;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.ExtendsContentIntoTitleBar = P_1;
					int[] array = new int[6];
					array[0] = -437673415;
					array[1] = -1492326544;
					array[2] = 145968141;
					array[3] = -1889135010;
					array[4] = 1171135290;
					array[5] = 1737227876;
					array[1] = array[5] ^ 0x439A9CFD;
					array[0] = array[3] ^ -1146694859;
					array[0] ^= 1952876514;
					int[] array2 = new int[4] { 1238676217, -1723033390, 567318840, 1835381157 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][5] ^ 0x12E507DE;
					array2[0] = array2[3] ^ -619107724;
					array2[1] = array2[0] ^ 0x62795F88;
					int num11 = array3[1][2] ^ -1845799819;
					num = (int)((num4 * 2067690583) ^ 0xF1C1B025u) ^ num11;
				}
			}
		}
	}

	static void _0024_003F_0026_003E_0028_003C_003E_0021(Window P_0, UIElement P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1038818627;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(1837450836 - -1029395215 - -(-(~((num2 * -574036947) ^ 0x33769A13)) - (~(596799623 * (-417780667 * -203920491)) + -(0x4B6ACBC6 ^ (-870526299 ^ -309476780))) - (0x201F81BF ^ ((-1117354510 ^ -786480178) + (895346455 + -1924476299) + (--1614630493 - ~1868776896))) - (~-904763185 - (1505700705 - -1522551490)) * -762468907)))) % 3;
					int num5 = 1121166864;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 ^ 0x57EF0EB2) * 2063274813;
						num5 += -882378970 + 1163529502;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1020626860;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 1020626858;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -168951205;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(num9 - --1935815405);
							num9 = -(num9 * -138029951);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.SetTitleBar(P_1);
					int[,] array = new int[4, 4];
					array[0, 0] = 1237787437;
					array[0, 1] = 1340211821;
					array[0, 2] = 617550945;
					array[0, 3] = 1642041366;
					array[1, 0] = 61670628;
					array[1, 1] = 1324328602;
					array[1, 2] = 597618338;
					array[1, 3] = 1790777353;
					array[2, 0] = 1057086028;
					array[2, 1] = 1445783217;
					array[2, 2] = -319146137;
					array[2, 3] = 1951787103;
					array[3, 0] = -1836062780;
					array[3, 1] = 2138131933;
					array[3, 2] = -1553904459;
					array[3, 3] = 1750373944;
					array[3, 1] = array[0, 0] ^ 0x2D751CA;
					array[1, 0] = array[2, 1] ^ 0x38DCDAEC;
					array[0, 0] = array[2, 3] ^ -955562871;
					int num11 = array[0, 0] ^ -1798225620;
					num = (int)((num4 * 1630809179) ^ 0x81272C3Eu) ^ num11;
				}
			}
		}
	}

	static AppWindow _003D_0024_003E_0029_003F_003C_0025_(Window P_0)
	{
		AppWindow appWindow = default(AppWindow);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1468890597;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-((-(-1248956314 + (120130531 * -1235866663 + (969874205 - -1520152027)) * -645051455) - ~(-(-(num2 - (~(-749686273 * ~(~-681785262 + -581855676)) + ~(1005275149 * (-(~(--1619862064 * -2057097933)) - (~(~-1578928172) * -533076435 - (-(-765623850 - -1696792767) + ~(0x48872EB2 ^ -2052255860))))) * -1642370267))))) ^ -2123695351 ^ 0x138CB261)) * 1360521073)) % 3;
					int num5 = -785157502;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 ^ 0x122E7474) + 1165826067;
						num5 = -773621161 - (num5 ^ 0x2FC6AFA7);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 288265218;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 1892464129;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 846976431;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 - 1592141067);
							num9 = -(num9 - 1746047883 * 1522215161);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					appWindow = P_0.AppWindow;
					int[] array = new int[6];
					array[0] = -1798426138;
					array[1] = -2045176970;
					array[2] = 809384621;
					array[3] = -1512916834;
					array[4] = 1962927767;
					array[5] = 291295324;
					array[5] = array[1] ^ 0x44DECB10;
					array[1] ^= 76076294;
					int[] array2 = new int[5];
					array2[0] = 1820628151;
					array2[1] = 860802088;
					array2[2] = -1594858086;
					array2[3] = -1530021594;
					array2[4] = -124152210;
					array2[0] = array[3] ^ 0x1AADF783;
					array2[3] = array2[1] ^ -810741108;
					array2[1] = array2[0] ^ -354034806;
					array2[4] ^= 1293690396;
					int num11 = array2[0] ^ -977432055;
					num = ((int)num4 * -856141952) ^ 0x2272AA00 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return appWindow;
	}

	static void _0024_0024_0028_005E_005E_005E_003F_002F(AppWindow P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1907697675;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(-1364634647 - 967542783 + (2043727473 + 1024211133)) + ~(-960881821)) - ((num2 - (-(848781096 - -(-1897949087)) - ~(-52124292 ^ -1735268275) + -2091475324 + (0x76E1D07A ^ -(~-1516237644 + ~-680117078 + (-953245943 - (1496872602 - 1731861071)) - (-983661424 ^ 0x7C69EAC4))) - ~(-(((0x1C9E8639 ^ 0x5576A6D5) - -(--849094584) + (0x54FB1F3B ^ 0x25525138)) * -1083787315))) * 1386988271) * -129446921 - (~(~1840955146) * -1724923009 - (~-740856300 - 795778545 * (885694803 * -922630571)) + (1241319307 * (-31090628 + 173222967) * -1210480191 - -(-(0x5C8D7533 ^ 0x5ADA5EC0)) - (790432053 + (-1672167710 ^ 0x729A69AD))) - (-1865664343 - (~(432566459 * (-552120418 ^ -952630739)) - ((0x546EC87F ^ ~(--593803803)) + 1638491211 * (-1120577744 + 1828835679 + ~1729082096))))) + -(~(~(-(0x6BEE0E61 ^ 0x646BC2A4)) * -2048102893))))) % 3;
					int num5 = 1982989058;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 + 1003289037;
						num5 = num5 * -2105748917 * 894955139;
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
						int num9 = 1625468019;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x60E2AC73;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.SetIcon(P_1);
					int[,] array = new int[4, 4]
					{
						{ -1747924388, 35377681, -1824906929, -1128871343 },
						{ -61568928, -1720633568, -903033280, -1653541809 },
						{ -186766740, -1538419551, 1824914283, 527381163 },
						{ 2143199202, 1423155140, -1301992210, 1966527417 }
					};
					array[0, 1] ^= 1157270248;
					array[0, 3] = array[0, 0] ^ -1167886226;
					array[3, 1] = array[2, 2] ^ -113078261;
					int num11 = array[3, 1] ^ -1673056669;
					num = (int)((num4 * 472607477) ^ 0x3FE2F23C) ^ num11;
				}
			}
		}
	}

	static void _0021_0023_002B__002B_0023_003F_0028(Window P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1961647013;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-333854310 - (((-((num2 * -1541713729) ^ (~((-874174293 * -1970393772) ^ (-1086498862 ^ (-1042040970 - -(-1387462797 ^ 0x4A29A859))) ^ 0x1B41FA9C) + ((-(-408605969 ^ -644588078) ^ (-1534139077 - (-178769144 * 2037423735 - ~1632104268 + (-934301532 ^ ~(-503440133))))) - ((834585127 * (-758385122 ^ -468727596) + -884384636 - (-1376794569 * -1115191475 - -1300270027 + (0x1F0E45A5 ^ --1450824460) - ((-1575255516 ^ 0x6E7EBA5A) + -(-887251345 - 422471047)))) ^ (-(955846406 - 1655950895 - ~618792510 + ((0x3C575042 ^ -2069391755) - (-281997330 ^ 0x7425C3E9))) * 1504087935))))) ^ (450333647 * ~(-(~(2003134967 - 1068071390)) - ((0x63CB66FF ^ -507531171) * -1622165301 - 608768739)))) * 201816591 * -696726629) ^ 0x34F03C9D)) * -650020275 - 1556205997)) % 3;
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
					int num7 = 1762175770;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 * 1006012473) ^ 0x4B8D2C94;
						num7 = (num7 * 1367535309) ^ -426196258;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -217537483;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 + (-2027620594 - -409941446)) ^ 0x18F1790B;
							num9 = num9 * 1074574651 - 1191752227;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Title = P_1;
					int[,] array = new int[3, 4];
					array[0, 0] = 529857990;
					array[0, 1] = 10126459;
					array[0, 2] = -1229375863;
					array[0, 3] = 725473104;
					array[1, 0] = -2093960643;
					array[1, 1] = 273821878;
					array[1, 2] = -1963076019;
					array[1, 3] = 1174547866;
					array[2, 0] = -398722645;
					array[2, 1] = -170724101;
					array[2, 2] = -467099571;
					array[2, 3] = 1374475812;
					array[1, 0] = array[2, 1] ^ 0x2798EDD3;
					array[0, 3] = array[2, 3] ^ -1175502437;
					array[2, 0] = array[0, 0] ^ 0x47505160;
					array[2, 2] = array[1, 1] ^ 0x771001EC;
					int num11 = array[2, 2] ^ 0x2F0339AD;
					num = (int)((num4 * 1563141238) ^ 0x9ACD266Cu) ^ num11;
				}
			}
		}
	}

	static NavigationViewItemBase _0024_002F_003C_0028_0021_003E_002D_003E(NavigationViewSelectionChangedEventArgs P_0)
	{
		NavigationViewItemBase selectedItemContainer = default(NavigationViewItemBase);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -941272062;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((((~(~(~((num2 - ~(-((1041212341 - (-(1787146014 - 7161614 - (-1535147173 + 1391827694)) * 1540392525 - 1185368957)) ^ 0x50B7F523))) * -1490862561 + -1678201654 * 1034244655))) ^ (-(-73103438 - 1221788770) * -732351433)) + (-2067876747 ^ -1385771020)) ^ 0x6DAC28E7) * 695039079)) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -num5;
						num5 -= --1648098324;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -770533183;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(-15042129 - num7);
						num7 = (num7 * 1318254895) ^ 0x251EA736;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1039966344;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 += -1039966342;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					selectedItemContainer = P_0.SelectedItemContainer;
					int[] array = new int[7];
					array[0] = -577875985;
					array[1] = 1749823021;
					array[2] = 33009924;
					array[3] = -521568170;
					array[4] = 536010135;
					array[5] = 391928734;
					array[6] = 1485563523;
					array[0] = array[4] ^ -1656677926;
					array[0] = array[5] ^ 0x2D289C24;
					array[3] = array[6] ^ -1337550730;
					int[] array2 = new int[7] { 296660278, -570235442, -213540655, 1930602250, 62366207, 243654759, -856291773 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[5] = array3[0][1] ^ -2113680622;
					array2[2] = array2[3] ^ -1798538443;
					array2[1] ^= -1871263833;
					int num11 = array3[1][5] ^ -91947557;
					num = (int)((num4 * 617090632) ^ 0xDEFDC2C0u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return selectedItemContainer;
	}

	static object _002B_0040_0028_002D_0040_0021_0023_003D(FrameworkElement P_0)
	{
		object tag = default(object);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1652919988;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(~((~(1192079749 * 855302145) + -(--1598587697 + ~-2116288153) - -(num2 - (-470637185 ^ (~(-70891864 + (-1035536307 * (-358742934 - 1219381867 + (0x43AB8360 ^ 0x102CA7C6)) - ~(754053297 - -1739310177) * -2002334971)) - -(-(-(-758025738 ^ -2122372444))) + (-61961979 + (-(271424135 * (-786012555 ^ 0x462B4B0F) - (109060411 * -426829701 * -1934731189 + (~1473817156 - -230907583 * 239307076))) ^ (880169223 * ~(~(-1312752585 - 757366083) + (--1176011773 ^ 0x555DB96C))))))))) * -1252847737 + (1315593449 * (1962910185 * (-1805507447 + (1852647133 - 1451971924))) - (-(~(~-1196560573)) + (-(1258541471 - -279616283) + (-134465781 - 1051114423 - 137988574)))))) ^ -(0x418E9503 ^ 0x49DCD60A)) ^ -1886490064)) % 3;
					int num5 = 891226900;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 ^ -564091146) * 92952757;
						num5 = -num5 - -2109029319;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -560092909;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= -560092911;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 374349183;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 * -1121906219 - 882866344;
							num9 = ~(-num9);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					tag = P_0.Tag;
					int[] array = new int[6] { 1495445778, 1259284668, 1919246409, -837365083, 2041041192, -610121621 };
					array[1] ^= -713273776;
					array[3] = array[2] ^ 0x23021507;
					int[] array2 = new int[4];
					array2[0] = -1880478640;
					array2[1] = -1192151562;
					array2[2] = 1015762499;
					array2[3] = -113817337;
					array2[2] = array[5] ^ 0x123AA8E2;
					array2[3] = array2[2] ^ -1986076893;
					array2[3] = array2[1] ^ 0x31839D70;
					array2[3] = array2[1] ^ 0x75EF2D05;
					int num11 = array2[2] ^ -2086532502;
					num = (int)((num4 * 1203292933) ^ 0x88D374C4u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return tag;
	}

	static bool __0025_003D_0024_0021_003F_005E_005E(string P_0, string P_1)
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
				int num = -843996561;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(~((num2 + ((-1844679385 - ~(-(982071821 + ((-762133598 ^ -1374403567) + --1234936739 - (-954178996 ^ -74099273)))) - (~(-(~(-1496634339 ^ -1910829860))) + 1842400669 * ((0x56478DC7 ^ -((-217314967 + 657772642) * -1821762589)) * 1648690357))) ^ (-1801590189 ^ (~((0x3FB0B75F ^ -969655637) + -378123859) - (350861941 * ((-725324993 ^ -1087285220) - -(1317536127 * 242876953)) - (-492259872 + -(~(-1076036489 * -1190020220))) - (0x1ABDB652 ^ (795752693 + (~(-1162625508) + -2104045923)))))))) ^ (~(-(-1198434727 * (-54334643 + 827566007 - (0x4CB04D99 ^ 0x3A69C2D8)) - -1912341510) ^ ((-(~(789048167 - 516284616)) - -(0xB1CC17E ^ -1171713601)) ^ -1543087583)) + ~(-(~-955923489 + 948481624) ^ 0x6029102E ^ (-1035540923 * -((-246436529 - -942222547) * 1311888889)) ^ ((-(~-816620572) ^ -(~-105409945)) + -1071532265 + 554426564)))) - ~(~((44209395 + -1948696008) * -936880253))) + -1234085445))) % 3;
					int num5 = 371187718;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 ^= -1477276094;
						num5 = (num5 ^ -450902088) + -200259841;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = 565451922 - -num7;
						num7 = -(num7 - --1688431230);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 145491335;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ -205801580) - 330714439;
							num9 = ~(num9 ^ --1044943095);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0 == P_1;
					int[] array = new int[7];
					array[0] = -1766877983;
					array[1] = -1060887008;
					array[2] = 44582204;
					array[3] = -1923893808;
					array[4] = 2065720141;
					array[5] = 291635713;
					array[6] = 702294060;
					array[2] = array[0] ^ -1314584138;
					array[5] ^= 1986259920;
					int[] array2 = new int[7];
					array2[0] = 2121798352;
					array2[1] = -2072239136;
					array2[2] = 1196403977;
					array2[3] = 986897305;
					array2[4] = 728311527;
					array2[5] = 1710333;
					array2[6] = -1609875626;
					array2[3] = array[3] ^ 0x20D257D7;
					array2[5] = array2[6] ^ -1768168250;
					array2[5] = array2[6] ^ -181461529;
					int num11 = array2[3] ^ 0x492D9767;
					num = ((int)num4 * -2069466222) ^ 0x66D1CC68 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _0024_0029_003C_0026_0024_0025_0029_(NavigationView P_0, object P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -481704690;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(-(--1945767557 - -1563654501 * (-1851169427 * 2104470445))) - -num2 * -272576955) * -17450963 * 616467563)) % 3;
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
					int num7 = 1129044457;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(-num7);
						num7 = (-1022874001 - num7) * 1000848005;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1832020032;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 * -2111463921) ^ 0xADA35EE;
							num9 = ~(num9 - 73106613);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.SelectedItem = P_1;
					int[] array = new int[4] { -1467461871, 870605087, -1047944203, -1244763083 };
					array[0] ^= 1391071078;
					array[2] = array[0] ^ -888496891;
					int[] array2 = new int[4] { 1711708756, 630357697, 833962255, -1036421799 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][1] ^ 0x6B8E5BB6;
					array2[1] = array2[0] ^ -1730714993;
					array2[1] = array2[3] ^ -399090185;
					array2[1] ^= -258832431;
					int num11 = array3[1][3] ^ 0x12808399;
					num = (int)((num4 * 913938442) ^ 0x484F33A) ^ num11;
				}
			}
		}
	}

	static string _002A_002A_0029_0024_0024_003F__0024(PropertyChangedEventArgs P_0)
	{
		string propertyName = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1012257363;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-136823524 - (((~(~(~(-(--1628040205) ^ -563080793)) - -688602211 * (-1446217997 + (282252601 - -972384073) + ~2071709961) * 240364189) - ((num2 - (-(~(~(~(-(-976944148 ^ 0x69A82D7B)))) ^ -(-568113958 ^ (~(-746234012 + 2056837712) + (~342475901 + -982001532) - ~(~(-1034393265))))) ^ ~(-(~(~(0x53242C6C ^ (-2048270078 ^ -248472016)))) + (-431488831 ^ (-558754064 ^ ~(-(-1854308382 ^ -1265277217))) ^ -911454511)))) ^ ~(-(~(~(1657871117 + -(-462824308))) - 2095746356))) - (-(~(0x3177BB7D ^ 0xD88D871)) ^ -(~(-1952803847 + -1348926947) - ~(~-1761366626) + (~(1893055206 - -70912786) - (1934874816 - 680876011 + -2109402623))))) ^ (-(-308320259 ^ -500390834 ^ 0x7ED23073) - ~(0xB6D562F ^ 0x4B22CDB3))) - -(~((-1891786756 ^ -1356586579) + (662371813 - -566566017)))) + -(-1283139765 - -1682203210) - 769224802) ^ 0x4B906BC2)) % 3;
					int num5 = -1803559999;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= -1803559997;
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
						int num9 = -215846551;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -215846551;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					propertyName = P_0.PropertyName;
					int[] array = new int[5];
					array[0] = 1043804398;
					array[1] = -2065280477;
					array[2] = -1653422650;
					array[3] = -1016813214;
					array[4] = 148066547;
					array[1] = array[4] ^ 0x630E530A;
					array[3] = array[2] ^ -2038536167;
					array[3] = array[2] ^ -217243400;
					int[] array2 = new int[5] { -202858087, -1990767821, 319263625, -202084643, 48288727 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][2] ^ -936931197;
					array2[4] ^= -249874249;
					array2[4] = array2[3] ^ -1569764130;
					int num11 = array3[1][1] ^ 0x573749AD;
					num = (int)((num4 * 1869756231) ^ 0xA1C05E8Fu) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return propertyName;
	}

	static AppWindowPresenter _002B_003D_002A_0024_002F_0024_003E_0021(AppWindow P_0)
	{
		AppWindowPresenter presenter = default(AppWindowPresenter);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1434881939;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(~(((0x620E0CA9 ^ 0x365636EE) * 1136184559 - (((~(~(~(2100956563 * (127411137 + -3983251 * 456626769)) - (1372535277 * ~-141417999 - (0x1F1DC9D8 ^ --103526003) - 1862762148) - 1370005790)) - (num2 ^ -(-((~(-413083879 ^ 0x3BFC8A83) + ((0x6F9537BF ^ (-2144675792 ^ -1358681672)) + 1996265043) + 1158689929) ^ ~((-(-708991741 + 1189345073 - 126866986) - -1077247100) ^ (0x775CF760 ^ (-(1258154921 + 212799190) + -(~1847539748))))))) - (~(~(~(-134732071 * -2095818612) - ~(-520459923) - ~(945359178 + (-1026839486 + -181776220)))) - (~(~(-(-2113058967 - -1643542680 - (-1779045575 - -1487674483)))) - -1551469368))) ^ (-(-1393686131 ^ -1457322330) - ~(-(-(1465039362 + 213473360) * -2080554837)))) - ~(-1678397725 - (-986930510 + --1870721658 - (0x4E838039 ^ 0x1EAA548F))))) * 296497623))))) % 3;
					int num5 = 820938891;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0x30EE888B;
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
					presenter = P_0.Presenter;
					int[] array = new int[5];
					array[0] = 1124006616;
					array[1] = 1367574875;
					array[2] = 1249652939;
					array[3] = 839186415;
					array[4] = 953238349;
					array[3] = array[2] ^ 0x583ED0D4;
					array[1] ^= -825563704;
					int[] array2 = new int[5] { -1917705102, 754345727, -1837762518, 1716186577, -1248011410 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][4] ^ -250142379;
					array2[1] = array2[4] ^ -1504161011;
					array2[3] = array2[4] ^ 0x15CC9138;
					array2[4] = array2[1] ^ 0x1F415AFE;
					int num11 = array3[1][2] ^ -573590817;
					num = (int)((num4 * 1942657624) ^ 0x9E29FFF8u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return presenter;
	}

	static OverlappedPresenterState _0024_002F_0021_002A_0028_003D_002A_0023(OverlappedPresenter P_0)
	{
		OverlappedPresenterState state = default(OverlappedPresenterState);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -677254570;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-1201860706 - (-(((num2 + ~(-1763854187 ^ (-(0x3DD46550 ^ 0x2E0C9D6) ^ (669551333 * -(~1302906689))))) * 282027791 * 652832081) ^ 0x5DFD919 ^ 0x6C43F471) ^ (-(1862690268 - -561943696) - ~(-1497954923 - -1466660499))) * -1435494725) ^ 0x18699FD)) % 3;
					int num5 = 656480778;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 ^= -95783824;
						num5 = num5 * -644589277 - -1236912802;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1858209148;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x6EC2057D;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1712500294;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 += -1712500294;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					state = P_0.State;
					int[] array = new int[4] { -1380206274, 1703647029, 485884984, 1122474280 };
					array[1] ^= -1892119005;
					array[1] ^= 656212249;
					array[1] = array[3] ^ 0x16843867;
					int[] array2 = new int[7] { 401761320, -282993988, -1137461645, 1093849205, -309417000, -1538488391, -1630774664 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][3] ^ -224374565;
					array2[5] = array2[6] ^ 0x4FBF148D;
					array2[1] = array2[0] ^ 0xBDA22C2;
					int num11 = array3[1][2] ^ -617220876;
					num = ((int)num4 * -1150588309) ^ 0x9F8205E ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return state;
	}

	static void _005E_003F_0028__0040_005E_002B_0026(OverlappedPresenter P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1739533698;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(-num2)) * -806930397 * 1403923939)) % 3;
					int num5 = 1002056321;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0x3BBA2A83;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1475253271;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 ^ -1015642937 ^ 0x297A7856;
						num7 = (num7 + ~-636412501) * -1570838895;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1257679076;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= -1257679076;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Restore();
					int[] array = new int[5];
					array[0] = 1165249583;
					array[1] = -1995781873;
					array[2] = -862870385;
					array[3] = -1463013701;
					array[4] = 868157462;
					array[3] = array[4] ^ -7704597;
					array[0] = array[2] ^ 0x99E6EB6;
					array[2] = array[0] ^ -2077967263;
					int[] array2 = new int[4];
					array2[0] = 2086509586;
					array2[1] = -2087284785;
					array2[2] = -1254026839;
					array2[3] = -1822589369;
					array2[0] = array[4] ^ -155402316;
					array2[3] = array2[0] ^ 0x44D117C0;
					array2[1] = array2[2] ^ -982019392;
					array2[2] = array2[3] ^ 0xC41BF30;
					int num11 = array2[0] ^ 0x48298CDA;
					num = ((int)num4 * -1435378212) ^ -35733828 ^ num11;
				}
			}
		}
	}

	static void _002D_002F_005E_003C__0024_003D_003D(Window P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 198423662;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(-(~1575725204)) - -(~((-num2 ^ -(-1003016235 ^ -(~(~(-(0x7169497 ^ 0x23D20FCE))) * 296135343))) - (~-1503552224 + -(--1444042376 - -(-1719677235 + -1495038773 - --1443770167))) * 392782659)) * -473964781) ^ 0x20662D9B)) % 3;
					int num5 = -1411925056;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 += 1411925058;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1049641791;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= -1049641792;
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
					P_0.Activate();
					int[] array = new int[7];
					array[0] = -348434476;
					array[1] = 1146842763;
					array[2] = 277999010;
					array[3] = -2028147207;
					array[4] = -1214312517;
					array[5] = 550683574;
					array[6] = 91047603;
					array[2] = array[1] ^ 0x6CD084BF;
					array[4] ^= 366312571;
					array[6] = array[3] ^ -1926275553;
					int[] array2 = new int[5] { 930994141, -652312992, -1607182353, -1110133062, -791130017 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][0] ^ -82737496;
					array2[4] ^= -1505285540;
					array2[1] ^= -1740925630;
					int num11 = array3[1][0] ^ -1663061573;
					num = ((int)num4 * -370328026) ^ -789421170 ^ num11;
				}
			}
		}
	}

	static AsyncTaskMethodBuilder _003D__002B_002A_0029_003E_0021_003F()
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
				int num = 99185254;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((num2 - -(~(~(2115342629 * ~(487612656 - -527443720))) * 1620466055) + (--2128107978 + ~((-(-1099096 - -1386481784) * -291421123) ^ -260258901 ^ -(-2044408019 * -(-1974658842))) * 721826033)) * 869687777))) % 3;
					int num5 = 1182201216;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 - ~408883202) * 825998631;
						num5 = num5 * -672327157 * 2090074459;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1697203282;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -1697203284;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 10876365;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0xA5F5CC;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = AsyncTaskMethodBuilder.Create();
					int[] array = new int[7] { 1470070816, 1094597745, -1563165442, -982853802, 1640255112, 714324439, 967024485 };
					array[6] ^= 206896838;
					array[6] = array[5] ^ -827394879;
					int[] array2 = new int[4];
					array2[0] = -392851571;
					array2[1] = -1141044153;
					array2[2] = 95566473;
					array2[3] = -1886944889;
					array2[1] = array[4] ^ 0x856F7AE;
					array2[0] = array2[2] ^ -1244734050;
					array2[0] = array2[3] ^ -1985977345;
					int num11 = array2[1] ^ 0x1F4DA20A;
					num = ((int)num4 * -637633688) ^ 0xDBC8A68 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _003D_003D_002A_0026_0025_0023_0040_003C(ContentPresenter P_0, object P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1487270875;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(-(~(-(-(-(num2 ^ (~(-(~((~(-1911658744 + 607009553) + (~397312080 - -1748506993 * -1026660189)) * 575528137) + -(-(-(1519391632 - 1988425255)) - (0x69B3CBBB ^ -1236246177 ^ -1320362781)))) - -(~(-615864910 + -(-135301395 + (-484623499 * 1142209302 + ~-1824683383)))) * -1381829393)))) * -208656769)))) * -142132461)) % 3;
					int num5 = 814490680;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5;
						num5 = -num5 * -871139849;
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
						int num9 = 1427373954;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 * -364501309) ^ 0x3E124206;
							num9 = ~num9 + 833635519;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Content = P_1;
					int[] array = new int[5];
					array[0] = 698637929;
					array[1] = 1946118580;
					array[2] = -1067463051;
					array[3] = -906448203;
					array[4] = -1627967350;
					array[0] = array[1] ^ -2097756652;
					array[0] = array[1] ^ -1151403769;
					int[] array2 = new int[7];
					array2[0] = 808915993;
					array2[1] = -614852560;
					array2[2] = -1142016863;
					array2[3] = 1402787193;
					array2[4] = -258732055;
					array2[5] = 403135102;
					array2[6] = -996176647;
					array2[6] = array[3] ^ -1540982819;
					array2[1] = array2[3] ^ 0x1CA0486B;
					array2[2] = array2[6] ^ 0x571C329;
					array2[0] = array2[5] ^ 0x38D7B995;
					int num11 = array2[6] ^ -626639853;
					num = ((int)num4 * -149703789) ^ -1121073890 ^ num11;
				}
			}
		}
	}

	static void _0021_002A_0021_0024_002A_0024_0023_005E(UIElement P_0, Visibility P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 251302098;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(~(num2 ^ ~(-(~(2000376241 + -288292804 + 963569800 + -(--989761868) - (-557953 + ~-473806175) * -121650887) + 848330647) - ~(~(705769279 * 2117732189)) * 370991611))) - 271314078 - (159774773 - -1151929908 - -(0x3A2A030F ^ --448758574 ^ -925282300)) - -1951625198) ^ -1944371545 ^ -1745331212)) % 3;
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
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7 ^ 0x1E0336AD;
						num7 ^= -541021096;
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
					P_0.Visibility = P_1;
					int[,] array = new int[3, 4];
					array[0, 0] = -1569863474;
					array[0, 1] = 771964708;
					array[0, 2] = 836842131;
					array[0, 3] = -293558016;
					array[1, 0] = -922953692;
					array[1, 1] = -1588331774;
					array[1, 2] = -810860022;
					array[1, 3] = -450639750;
					array[2, 0] = -975024642;
					array[2, 1] = 736295485;
					array[2, 2] = -2033265856;
					array[2, 3] = -901890352;
					array[0, 1] = array[1, 0] ^ -1305533098;
					array[2, 2] = array[1, 3] ^ -1552224367;
					array[0, 1] = array[2, 0] ^ 0x2F17BA41;
					int num11 = array[0, 1] ^ -774974928;
					num = (int)((num4 * 1238736248) ^ 0xD84285F8u) ^ num11;
				}
			}
		}
	}

	static void _0023_0040_002B_0024_005E_0040__003E(Control P_0, bool P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 550017713;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((~(847567495 * (-76506997 ^ (--1616457238 + ~1866646867))) * 337013467 - (1219402291 + (-(~(-(-273561619 * -462966504)) + ~(-807650011 * ~-1802690887)) + (-1853725101 + -328520706 + ~-95614371 + 48457679 - 2024083909) * -1122650337) - ((num2 * -418714851) ^ (1786774252 - ~646267546 - (1094780217 * ~1117993186 * -1104964699 - (-(-633335992 ^ 0x7F5327E1) ^ 0x6FFDAF79)))))) ^ ((-(~-1979042709 - -127314655) * 1363291431) ^ 0x66568C87)) * -193116717)) % 3;
					int num5 = 1252441608;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(num5 - (-24977481 ^ 0x5463C95E));
						num5 = (num5 * 1065588063) ^ 0x52292B3B;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 58224929;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(num7 ^ -758359632);
						num7 += 1532192105;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -739724691;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -739724693;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.IsEnabled = P_1;
					int[] array = new int[7];
					array[0] = 2096981466;
					array[1] = 10959808;
					array[2] = 987624167;
					array[3] = 1082680604;
					array[4] = 1126527473;
					array[5] = -1122234432;
					array[6] = -1753202673;
					array[1] = array[6] ^ -1891596471;
					array[3] = array[2] ^ 0x6BD52660;
					int[] array2 = new int[6];
					array2[0] = 309728684;
					array2[1] = 1108846476;
					array2[2] = 1200167934;
					array2[3] = 453177706;
					array2[4] = -1178698325;
					array2[5] = 1519130522;
					array2[4] = array[0] ^ 0x2766631C;
					array2[1] = array2[3] ^ -1106202338;
					array2[3] = array2[4] ^ -2146444723;
					int num11 = array2[4] ^ -2089504470;
					num = (int)((num4 * 1112373406) ^ 0xD5CE1FC6u) ^ num11;
				}
			}
		}
	}

	static void _0024_0026_003D_005E_0040_0024_003D_0024(object P_0, Uri P_1, ComponentResourceLocation P_2)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1567249330;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(((num2 + -(0x24C8F96 ^ ((-(0x114499A1 ^ 0x5234DF12) ^ -416130921) + (~(192979656 + 2065351500 - (462059402 - 563263032) - (430940027 + 658619094 + 844841582)) * 1133850137 + -(93074879 - 1357150114) * 1354830431))) + (787619819 * -(((~(--1225355521) - (~-1394351562 + -551649575)) * 931857847) ^ -24474060) + (~(-(~(--244029467))) * -60263195 - --2019196565 - -504330441))) ^ --1790906262) + ~(-(-(-(-(-193784286 ^ -1365726122)))))))) % 3;
					int num5 = -2117990022;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -2117990020 - num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 -= -1054665113 + -1931612565;
						num7 = -num7 + -275943093;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1914788471;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 += -1914788471;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					Application.LoadComponent(P_0, P_1, P_2);
					int[] array = new int[7];
					array[0] = 1529845587;
					array[1] = 2022355484;
					array[2] = 2094852431;
					array[3] = -170003095;
					array[4] = -1000175615;
					array[5] = -1935457588;
					array[6] = 1846656057;
					array[3] = array[0] ^ -765239016;
					array[3] = array[0] ^ -1595692446;
					int[] array2 = new int[7];
					array2[0] = -198147985;
					array2[1] = 1328437242;
					array2[2] = -583419587;
					array2[3] = 1361974604;
					array2[4] = 1716209524;
					array2[5] = 738921607;
					array2[6] = 39942061;
					array2[5] = array[4] ^ 0x66190899;
					array2[3] = array2[4] ^ -372041347;
					array2[2] = array2[1] ^ -1443965047;
					int num11 = array2[5] ^ 0x6E38902B;
					num = (int)((num4 * 1257128901) ^ 0x2B2F8FD7) ^ num11;
				}
			}
		}
	}

	static void _003F_002D_003F_002A_005E_0025_0023_(NavigationView P_0, TypedEventHandler<NavigationView, NavigationViewSelectionChangedEventArgs> P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1746397325;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(833716297 * -(~918967405 + (-875549348 ^ 0x419195F6) - -424787844 + -(-2140592994 ^ 0x5EA2AC20)) - ~((num2 - ~(0x31C42470 ^ (~(-(-622671550 * 801192073)) + ((934503979 * -1742807502 + 1544479871 * (1625001142 * -1289811185)) ^ 0x399E9333) + (-2079846429 ^ 0x369765D5) + ~1525829835))) ^ -(-((-763536780 - (-1575191463 + 1445976863)) * -2015091099 - (638118701 * 217048761 - --1318148751) * -157693855 + -((-503954168 - -337864255) * -1105219971 * -769550457)) - ~(-(~(~(0x73E12109 ^ -192775851)))))))) % 3;
					int num5 = -1216994676;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= -1216994676;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 -= -1316579616;
						num7 = -num7 - 1208031897;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 595120822;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 - (-806083216 ^ -2053465883) - 306666898;
							num9 = -889605683 - -num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.SelectionChanged += P_1;
					int[] array = new int[6];
					array[0] = -1461710217;
					array[1] = 1382483899;
					array[2] = 145312557;
					array[3] = -747377044;
					array[4] = 527535963;
					array[5] = -505412605;
					array[5] = array[1] ^ -5793408;
					array[3] = array[2] ^ -876926576;
					array[4] = array[0] ^ 0x68B887E2;
					int[] array2 = new int[5];
					array2[0] = -738101509;
					array2[1] = -1938939913;
					array2[2] = -1469481147;
					array2[3] = -903988064;
					array2[4] = 1298033867;
					array2[2] = array[2] ^ 0x2A4CC694;
					array2[3] ^= 1400853051;
					array2[1] = array2[4] ^ -943374902;
					array2[1] ^= -664001202;
					int num11 = array2[2] ^ 0x454A023E;
					num = ((int)num4 * -543691326) ^ -245770378 ^ num11;
				}
			}
		}
	}
}
