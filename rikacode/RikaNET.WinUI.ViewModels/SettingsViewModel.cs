using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Xaml.Controls;
using RikaNET.Core.Models;
using RikaNET.Core.Services;

namespace RikaNET.WinUI.ViewModels;

public sealed class SettingsViewModel : ObservableObject
{
	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003COpenUpdateAsync_003Ed__35 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder _003C_003Et__builder;

		public SettingsViewModel _003C_003E4__this;

		private TaskAwaiter _003C_003Eu__1;

		private void MoveNext()
		{
			int num = _003C_003E1__state;
			SettingsViewModel settingsViewModel = _003C_003E4__this;
			try
			{
				if (num != 0)
				{
					goto IL_0023;
				}
				goto IL_148c;
				IL_0023:
				int num2 = -1947255834;
				goto IL_0028;
				IL_0028:
				TaskAwaiter awaiter = default(TaskAwaiter);
				while (true)
				{
					int num3 = num2;
					uint num5;
					uint num4 = (num5 = (uint)(-(~(((~(~(-(1145106915 * (0x3537EEE1 ^ -1398292289) - ~192336837 + (--844259409 + (0x620EFC80 ^ -2116921174))))) - (-(~(0x5C9392B1 ^ 0x73A11788) + (290377289 * ~(~(2039757154 - 1118532574)) - (((-1699515100 ^ 0x47CE7EB6) - -(-1187140442)) ^ (-559444190 * -1963126515 + -939627113 - 554963881))) + ((~(~(--1719627396) ^ 0x2A9A0A47) - (-((195705126 + 1768460453) * 2058898735) ^ 0x5F03D3E5)) ^ -779217400)) - ~num3)) * -251024393) ^ -697505699 ^ 0xD8E3F81)) - (-1885225817 - -1240166403) + 976256187)) % 12;
					uint num6 = num4;
					int num7 = 4;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 - ~-1882601142 - 637226296;
						num7 = -(num7 - (735609806 + 568207223));
					}
					if (num6 == (uint)num7)
					{
						break;
					}
					uint num9 = num4;
					int num10 = 553638457;
					_ = 0;
					for (int num11 = 0; num11 < 2; num11++)
					{
						num10 = ~num10 * 1180664339;
						num10 = ~num10 ^ 0x3E4CDF20;
					}
					if (num9 == (uint)num10)
					{
						awaiter = _002A_005E_002D_0023_005E_005E_003C_0040(_005E_002F_003D_005E_0028_0024_0040_0024(settingsViewModel._launcherService, new Uri(settingsViewModel.AppViewModel.UpdateUrl)));
						int[] array = new int[4] { 1712382264, -750443051, -180341219, 1462835002 };
						array[3] ^= 1724233658;
						array[3] = array[1] ^ 0x62160A4E;
						int[] array2 = new int[4];
						array2[0] = -1723726806;
						array2[1] = 1853268503;
						array2[2] = 1454395484;
						array2[3] = 148100961;
						array2[3] = array[1] ^ 0x127E874F;
						array2[2] = array2[1] ^ 0x707F01E5;
						array2[1] ^= 97837147;
						array2[2] = array2[3] ^ -1938757697;
						int num12 = array2[3] ^ -2004697909;
						num2 = ((int)num5 * -898561598) ^ -218839166 ^ num12;
						continue;
					}
					uint num13 = num4;
					int num14 = 798187744;
					_ = 0;
					for (int num15 = 0; num15 < 2; num15++)
					{
						num14 = (num14 ^ 0x3E897E89) - 1785865666;
						num14 = (num14 * -643273283) ^ -2116669312;
					}
					if (num13 == (uint)num14)
					{
						bool ısCompleted = awaiter.IsCompleted;
						int[] array3 = new int[5];
						array3[0] = 1486686888;
						array3[1] = 1354079348;
						array3[2] = 373054331;
						array3[3] = -1392300420;
						array3[4] = -708776997;
						array3[2] = array3[0] ^ 0x1C832333;
						array3[2] ^= 1860852507;
						int[] array4 = new int[4] { -1043253458, 749510449, -443022163, -1889982395 };
						int[][] array5 = new int[2][] { array3, array4 };
						array4[0] = array5[0][1] ^ -189375018;
						array4[3] ^= 2060445087;
						array4[3] ^= -792499627;
						array4[1] ^= 1092262820;
						int num16 = array5[1][0] ^ -1486888710;
						int[,] array6 = new int[4, 3];
						array6[0, 0] = 598219854;
						array6[0, 1] = -1168271630;
						array6[0, 2] = 982728407;
						array6[1, 0] = -763027243;
						array6[1, 1] = -537891737;
						array6[1, 2] = 1726496806;
						array6[2, 0] = 1640392642;
						array6[2, 1] = -971159965;
						array6[2, 2] = -1158816567;
						array6[3, 0] = -887055458;
						array6[3, 1] = -1089916979;
						array6[3, 2] = 823930757;
						array6[2, 2] = array6[3, 2] ^ -1314654909;
						array6[0, 0] = array6[1, 2] ^ 0x92751DB;
						array6[2, 0] = array6[3, 1] ^ 0x1A1CF2B8;
						array6[2, 1] = array6[0, 1] ^ 0x3806F490;
						int num17 = array6[2, 1] ^ -921355195;
						int num18 = (int)(num5 * 588779503) ^ -666360540;
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
					int num22 = -394233082;
					_ = 0;
					for (int num23 = 0; num23 < 2; num23++)
					{
						num22 = -num22 ^ 0x75BA7358;
						num22 = -(num22 * 716710945);
					}
					if (num21 == (uint)num22)
					{
						num = (_003C_003E1__state = 0);
						int[,] array7 = new int[4, 4];
						array7[0, 0] = -1934574051;
						array7[0, 1] = 1925069384;
						array7[0, 2] = -1366753652;
						array7[0, 3] = 374860347;
						array7[1, 0] = -2007780281;
						array7[1, 1] = -1377624741;
						array7[1, 2] = -1330165013;
						array7[1, 3] = -638213492;
						array7[2, 0] = -1615631595;
						array7[2, 1] = -2065839456;
						array7[2, 2] = 185155203;
						array7[2, 3] = 582242082;
						array7[3, 0] = -768072008;
						array7[3, 1] = 1872266224;
						array7[3, 2] = -1951647387;
						array7[3, 3] = -1842023311;
						array7[3, 1] = array7[0, 0] ^ -1623701937;
						array7[1, 2] = array7[3, 0] ^ 0x735E6996;
						array7[0, 2] = array7[2, 2] ^ 0x38AC3A0F;
						array7[0, 1] = array7[2, 3] ^ -1537403051;
						int num24 = array7[0, 1] ^ 0x1E9462C;
						num2 = ((int)num5 * -270847656) ^ -236399568 ^ num24;
						continue;
					}
					uint num25 = num4;
					int num26 = -1965948091;
					_ = 0;
					for (int num27 = 0; num27 < 1; num27++)
					{
						num26 -= -1965948101;
					}
					if (num25 == (uint)num26)
					{
						_003C_003Eu__1 = awaiter;
						int[] array8 = new int[5];
						array8[0] = -1140324789;
						array8[1] = -4627923;
						array8[2] = -1381483878;
						array8[3] = -269406865;
						array8[4] = 1592529148;
						array8[4] = array8[2] ^ -1403040026;
						array8[2] = array8[1] ^ 0x4BC41B02;
						array8[1] = array8[3] ^ -23077741;
						int[] array9 = new int[7] { 744375220, -69562546, -937731375, 1883202598, 298277281, 1230101032, 161091585 };
						int[][] array10 = new int[2][] { array8, array9 };
						array9[4] = array10[0][3] ^ -70772605;
						array9[2] = array9[6] ^ -1141201101;
						array9[0] = array9[4] ^ -2046537663;
						int num28 = array10[1][4] ^ 0x4C438854;
						num2 = (int)((num5 * 1988507184) ^ 0x254AC3A0) ^ num28;
						continue;
					}
					uint num29 = num4;
					int num30 = 476249939;
					_ = 0;
					for (int num31 = 0; num31 < 2; num31++)
					{
						num30 = (num30 * 1975776205) ^ 0x190F7F7;
						num30 = 657155807 - (-16956506 - num30);
					}
					if (num29 == (uint)num30)
					{
						_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
						int[] array11 = new int[7];
						array11[0] = -1348061154;
						array11[1] = 616491816;
						array11[2] = 748078460;
						array11[3] = -1327833444;
						array11[4] = -1295138921;
						array11[5] = -1333273550;
						array11[6] = -1927142431;
						array11[6] = array11[5] ^ -123667088;
						array11[2] = array11[4] ^ 0x15787F42;
						int[] array12 = new int[4];
						array12[0] = -1165326035;
						array12[1] = -1960317649;
						array12[2] = 225654747;
						array12[3] = 1969527452;
						array12[3] = array11[3] ^ 0x20A3CAE0;
						array12[2] = array12[0] ^ 0x3167903F;
						array12[2] = array12[1] ^ -1012621236;
						array12[1] = array12[0] ^ -375991586;
						int num32 = array12[3] ^ -165976741;
						num2 = ((int)num5 * -1350615446) ^ 0x66A48B6E ^ num32;
						continue;
					}
					uint num33 = num4;
					int num34 = -2;
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
					int num37 = 2054378089;
					_ = 0;
					for (int num38 = 0; num38 < 1; num38++)
					{
						num37 += -2054378086;
					}
					if (num36 == (uint)num37)
					{
						goto IL_148c;
					}
					uint num39 = num4;
					int num40 = -1;
					_ = 0;
					for (int num41 = 0; num41 < 1; num41++)
					{
						num40 = -num40;
					}
					if (num39 == (uint)num40)
					{
						_003C_003Eu__1 = default(TaskAwaiter);
						int[] array13 = new int[4];
						array13[0] = -1431217172;
						array13[1] = 470878085;
						array13[2] = -43386935;
						array13[3] = -2103321130;
						array13[2] = array13[3] ^ 0x78625E0B;
						array13[2] = array13[3] ^ 0x2B3719AA;
						array13[2] = array13[3] ^ -2137071531;
						int[] array14 = new int[5];
						array14[0] = 321715693;
						array14[1] = 298801382;
						array14[2] = 833721550;
						array14[3] = 284493946;
						array14[4] = 623676104;
						array14[1] = array13[1] ^ 0x58CC626A;
						array14[3] = array14[0] ^ -1184208235;
						array14[4] = array14[0] ^ 0x5F9187B0;
						int num42 = array14[1] ^ 0x5DA5876;
						num2 = ((int)num5 * -1171198004) ^ -625877844 ^ num42;
						continue;
					}
					uint num43 = num4;
					int num44 = -2009040824;
					_ = 0;
					for (int num45 = 0; num45 < 2; num45++)
					{
						num44 = (2120691425 + -39295615 - num44) ^ 0x219FBBD7;
						num44 = ~(num44 - ~1218420174);
					}
					if (num43 == (uint)num44)
					{
						num = (_003C_003E1__state = -1);
						int[,] array15 = new int[4, 4];
						array15[0, 0] = 1793334004;
						array15[0, 1] = -1977967854;
						array15[0, 2] = 848253265;
						array15[0, 3] = 692581914;
						array15[1, 0] = 437775779;
						array15[1, 1] = -656886172;
						array15[1, 2] = -480717558;
						array15[1, 3] = 1696775135;
						array15[2, 0] = 1865124913;
						array15[2, 1] = -1230330775;
						array15[2, 2] = -949375822;
						array15[2, 3] = -1085818489;
						array15[3, 0] = -599271596;
						array15[3, 1] = -952217045;
						array15[3, 2] = 1475142626;
						array15[3, 3] = 1447959138;
						array15[1, 1] = array15[1, 3] ^ 0x305E6053;
						array15[3, 2] = array15[1, 1] ^ -561262604;
						array15[2, 0] = array15[0, 0] ^ -802967297;
						array15[1, 2] = array15[0, 2] ^ -285671171;
						int num46 = array15[1, 2] ^ -550866700;
						num2 = (int)((num5 * 244489622) ^ 0x926C64B8u) ^ num46;
						continue;
					}
					uint num47 = num4;
					int num48 = 587558379;
					_ = 0;
					for (int num49 = 0; num49 < 1; num49++)
					{
						num48 -= 587558372;
					}
					if (num47 == (uint)num48)
					{
						awaiter.GetResult();
						num2 = -97419622;
						continue;
					}
					uint num50 = num4;
					int num51 = 620430815;
					_ = 0;
					for (int num52 = 0; num52 < 2; num52++)
					{
						num51 = (num51 ^ 0x6B19E86D) * 848198903;
						num51 = ~num51 ^ 0x776F9DD7;
					}
					if (num50 == (uint)num51)
					{
					}
					goto end_IL_001a;
				}
				goto IL_0023;
				IL_148c:
				awaiter = _003C_003Eu__1;
				num2 = 730963742;
				goto IL_0028;
				end_IL_001a:;
			}
			catch (Exception exception)
			{
				while (true)
				{
					int num53 = -1054841028;
					while (true)
					{
						int num3 = num53;
						uint num5;
						uint num4 = (num5 = (uint)(-(~(((~(~(-(1145106915 * (0x3537EEE1 ^ -1398292289) - ~192336837 + (--844259409 + (0x620EFC80 ^ -2116921174))))) - (-(~(0x5C9392B1 ^ 0x73A11788) + (290377289 * ~(~(2039757154 - 1118532574)) - (((-1699515100 ^ 0x47CE7EB6) - -(-1187140442)) ^ (-559444190 * -1963126515 + -939627113 - 554963881))) + ((~(~(--1719627396) ^ 0x2A9A0A47) - (-((195705126 + 1768460453) * 2058898735) ^ 0x5F03D3E5)) ^ -779217400)) - ~num3)) * -251024393) ^ -697505699 ^ 0xD8E3F81)) - (-1885225817 - -1240166403) + 976256187)) % 4;
						uint num54 = num4;
						int num55 = -3;
						_ = 0;
						for (int num56 = 0; num56 < 1; num56++)
						{
							num55 = ~num55;
						}
						if (num54 == (uint)num55)
						{
							break;
						}
						uint num57 = num4;
						int num58 = -3;
						_ = 0;
						for (int num59 = 0; num59 < 1; num59++)
						{
							num58 = -num58;
						}
						if (num57 != (uint)num58)
						{
							uint num60 = num4;
							int num61 = 0;
							_ = 0;
							for (int num62 = 0; num62 < 1; num62++)
							{
								num61 = -num61;
							}
							if (num60 != (uint)num61)
							{
								uint num63 = num4;
								int num64 = -150780029;
								_ = 0;
								for (int num65 = 0; num65 < 2; num65++)
								{
									num64 = ~(num64 - -1583790526);
									num64 = -num64 - -639083136;
								}
								if (num63 == (uint)num64)
								{
								}
								return;
							}
							_003C_003Et__builder.SetException(exception);
							int[] array16 = new int[7];
							array16[0] = 560901565;
							array16[1] = 11345422;
							array16[2] = -882286403;
							array16[3] = -1246208500;
							array16[4] = -1246888455;
							array16[5] = -834450163;
							array16[6] = -132267152;
							array16[3] = array16[1] ^ 0x3F448EB9;
							array16[5] ^= -882895242;
							int[] array17 = new int[4] { -856455681, -1639974567, -2077858597, -1273939304 };
							int[][] array18 = new int[2][] { array16, array17 };
							array17[2] = array18[0][1] ^ -1752976445;
							array17[0] = array17[2] ^ -773103260;
							array17[0] = array17[3] ^ -1691089069;
							int num66 = array18[1][2] ^ -157158081;
							num53 = (int)((num5 * 856884259) ^ 0x931A5EDCu) ^ num66;
						}
						else
						{
							_003C_003E1__state = -2;
							int[] array19 = new int[5] { 1232980186, 1153184087, 2108755034, 153704814, -2023845814 };
							array19[3] ^= 770576195;
							array19[2] = array19[0] ^ 0x4027E048;
							int[] array20 = new int[7];
							array20[0] = -182919277;
							array20[1] = -580125562;
							array20[2] = 1295492039;
							array20[3] = -774867005;
							array20[4] = 467184158;
							array20[5] = 1336057330;
							array20[6] = -1887103321;
							array20[5] = array19[4] ^ 0x4B776848;
							array20[1] = array20[5] ^ -1798254323;
							array20[4] = array20[0] ^ -1665052322;
							int num67 = array20[5] ^ -1008831237;
							num53 = (int)((num5 * 1060347981) ^ 0xA44A0CABu) ^ num67;
						}
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num68 = 1453950556;
				while (true)
				{
					int num3 = num68;
					uint num5;
					uint num4 = (num5 = (uint)(-(~(((~(~(-(1145106915 * (0x3537EEE1 ^ -1398292289) - ~192336837 + (--844259409 + (0x620EFC80 ^ -2116921174))))) - (-(~(0x5C9392B1 ^ 0x73A11788) + (290377289 * ~(~(2039757154 - 1118532574)) - (((-1699515100 ^ 0x47CE7EB6) - -(-1187140442)) ^ (-559444190 * -1963126515 + -939627113 - 554963881))) + ((~(~(--1719627396) ^ 0x2A9A0A47) - (-((195705126 + 1768460453) * 2058898735) ^ 0x5F03D3E5)) ^ -779217400)) - ~num3)) * -251024393) ^ -697505699 ^ 0xD8E3F81)) - (-1885225817 - -1240166403) + 976256187)) % 3;
					uint num69 = num4;
					int num70 = 1730934460;
					_ = 0;
					for (int num71 = 0; num71 < 2; num71++)
					{
						num70 = ~(num70 - (0x566E946C ^ -1456357920));
						num70 = -num70 - -1271475757;
					}
					if (num69 == (uint)num70)
					{
						break;
					}
					uint num72 = num4;
					int num73 = 558636190;
					_ = 0;
					for (int num74 = 0; num74 < 1; num74++)
					{
						num73 = 558636191 - num73;
					}
					if (num72 != (uint)num73)
					{
						uint num75 = num4;
						int num76 = -2;
						_ = 0;
						for (int num77 = 0; num77 < 1; num77++)
						{
							num76 = -num76;
						}
						if (num75 == (uint)num76)
						{
						}
						return;
					}
					_003C_003Et__builder.SetResult();
					int[] array21 = new int[4];
					array21[0] = -1495775340;
					array21[1] = 1575155985;
					array21[2] = -164328264;
					array21[3] = -261095646;
					array21[1] = array21[0] ^ -723037005;
					array21[2] ^= 219070154;
					array21[2] = array21[0] ^ 0x5B345BC4;
					int[] array22 = new int[6];
					array22[0] = 1630772143;
					array22[1] = -1972375751;
					array22[2] = -735976339;
					array22[3] = -155128331;
					array22[4] = 259879375;
					array22[5] = -1753090818;
					array22[5] = array21[3] ^ -1817803876;
					array22[1] = array22[3] ^ 0xC3B9624;
					array22[3] = array22[4] ^ 0x25A2889E;
					array22[3] = array22[5] ^ -1315183650;
					int num78 = array22[5] ^ 0x436C64DC;
					num68 = ((int)num5 * -735371901) ^ 0x23E89565 ^ num78;
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

		static Task _005E_002F_003D_005E_0028_0024_0040_0024(ILauncherService P_0, Uri P_1)
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
					int num = 1539906101;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(~-987424448 - -(-(~(((-num2 - (-653986189 - ~(-(-(-61399104 + -1775117289 * ~-455989108))) - 1524395682 * -1910037657 * -31228325 * -1463743159 * -437209847)) * 583820561 - ~((--1382267745 * 2040703273 + (-991049039 - -446758319 * -1936690987) - -(0x2BF89BD1 ^ 0x63CA3A2C)) * 1239433145)) * 1245999845)))))) % 3;
						int num5 = -430808010;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 ^= -430808012;
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
							int num9 = -97326989;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 = -97326989 - num9;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.LaunchUriAsync(P_1);
						int[] array = new int[4];
						array[0] = -958421550;
						array[1] = 1249338138;
						array[2] = 8026684;
						array[3] = -1208016608;
						array[0] = array[2] ^ -382368765;
						array[0] = array[2] ^ 0x3544A8F7;
						array[1] = array[3] ^ 0x199CE330;
						int[] array2 = new int[6];
						array2[0] = -547863857;
						array2[1] = -1816750438;
						array2[2] = 800582135;
						array2[3] = 285609445;
						array2[4] = -2034786104;
						array2[5] = -873991993;
						array2[4] = array[2] ^ 0x7CCF226A;
						array2[5] ^= 576673366;
						array2[2] = array2[1] ^ 0x35B3E33D;
						int num11 = array2[4] ^ -848519015;
						num = (int)((num4 * 834500492) ^ 0x7308B6B0) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static TaskAwaiter _002A_005E_002D_0023_005E_005E_003C_0040(Task P_0)
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
					int num = 39907430;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-((~(-894272210 ^ (--1437636059 - (-62638418 * 2042231571 + 1834460737)) ^ -1933407075) - num2 - ~(~(~((0x58B42BF6 ^ -816618548) + (0x4990CA1D ^ -806754812)) - -((0x767BD3E1 ^ 0x4FB5D655) * 244493649 * 1540967181)) - ((0x7956E56F ^ 0x21856ADF) + (-(0x4844226E ^ -1599766544) ^ (-(~(~-1452223530)) ^ -1930557261))))) * -1548809943))) % 3;
						int num5 = -535789534;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = ~(num5 ^ 0x5F38D1B9);
							num5 = num5 + -104364343 + -1243016413;
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
						awaiter = P_0.GetAwaiter();
						int[,] array = new int[3, 4];
						array[0, 0] = 1325368977;
						array[0, 1] = -907254423;
						array[0, 2] = -368753837;
						array[0, 3] = -520586367;
						array[1, 0] = 1803907214;
						array[1, 1] = 146902503;
						array[1, 2] = 813818119;
						array[1, 3] = -1640352563;
						array[2, 0] = 2030939939;
						array[2, 1] = 111843895;
						array[2, 2] = 1485402503;
						array[2, 3] = -1544702732;
						array[0, 1] = array[0, 0] ^ 0x23C9B208;
						array[0, 3] = array[2, 0] ^ 0x1094F6E3;
						array[0, 0] = array[0, 1] ^ 0x3F6EB335;
						array[2, 1] = array[2, 2] ^ -1859869457;
						int num11 = array[2, 1] ^ -1896782626;
						num = ((int)num4 * -865218210) ^ 0x4D44C206 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return awaiter;
		}
	}

	private readonly IAuthenticationService _authenticationService;

	private readonly ILauncherService _launcherService;

	private readonly ISettingsStore _settingsStore;

	private readonly IStringResourceService _strings;

	private SeverityLevel _statusLevel;

	private string _statusMessage = string.Empty;

	public RelayCommand ClearStoredLicenseCommand { get; }

	public string CurrentLicenseDisplay => AppViewModel.CurrentLicenseDisplay;

	public AppViewModel AppViewModel { get; }

	public bool HasStatus => !_003C_0029_0040_0025_005E_002A_003D_003F(StatusMessage);

	public bool HasUpdateLink => AppViewModel.UpdateAvailable;

	public AsyncRelayCommand OpenUpdateCommand { get; }

	public RelayCommand SignOutCommand { get; }

	public InfoBarSeverity StatusSeverity
	{
		get
		{
			SeverityLevel statusLevel = StatusLevel;
			InfoBarSeverity result = default(InfoBarSeverity);
			while (true)
			{
				int num = -337260425;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(-(-(~(~(-num2) ^ (1308141714 - ~((1444554005 * ((--910089379 ^ 0x7A8AB035) - (480734849 - (-1517152480 ^ -889027933)))) ^ ((-1512738622 ^ 0xD776DC0) - ~(--1475312417 ^ -2115249442))))) - (-384861325 - ~(727200089 + (-1095719192 + 408386904) * -1177901235))))) ^ -865721468))) % 11;
					int num5 = 1146235930;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 += -1146235926;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1719778287;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += -1719778285;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1436745547;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(num9 * 672479267);
							num9 = ~num9 ^ 0x5CA46A6E;
						}
						if (num3 == (uint)num9)
						{
							int[] array = new int[5];
							array[0] = 388159113;
							array[1] = 1173482181;
							array[2] = 793113818;
							array[3] = -242807730;
							array[4] = -1847261482;
							array[1] = array[3] ^ -383872699;
							array[4] = array[2] ^ 0x7F5CB92E;
							array[4] = array[0] ^ -160699198;
							int[] array2 = new int[5];
							array2[0] = -189405481;
							array2[1] = 1251454218;
							array2[2] = 194673053;
							array2[3] = 301583974;
							array2[4] = 925846138;
							array2[2] = array[3] ^ 0x4BB021FF;
							array2[1] = array2[3] ^ -2026420085;
							array2[0] = array2[3] ^ 0x6BA65FC0;
							array2[4] = array2[3] ^ -2123406437;
							int num11 = array2[2] ^ 0x9BE29FD;
							num = ((int)num4 * -2071355822) ^ 0x50A82AD0 ^ num11;
							continue;
						}
						int num12 = -7;
						_ = 0;
						for (int num13 = 0; num13 < 1; num13++)
						{
							num12 = -num12;
						}
						if (num3 != (uint)num12)
						{
							int num14 = 1946350261;
							_ = 0;
							for (int num15 = 0; num15 < 1; num15++)
							{
								num14 -= 1946350261;
							}
							if (num3 != (uint)num14)
							{
								int num16 = 1844706288;
								_ = 0;
								for (int num17 = 0; num17 < 2; num17++)
								{
									num16 = ~(num16 - 1106047006);
									num16 = (num16 ^ 0x7F0A0F8D) - 1976122804;
								}
								if (num3 != (uint)num16)
								{
									int num18 = 2036427157;
									_ = 0;
									for (int num19 = 0; num19 < 1; num19++)
									{
										num18 = 2036427166 - num18;
									}
									if (num3 != (uint)num18)
									{
										int num20 = 72257022;
										_ = 0;
										for (int num21 = 0; num21 < 2; num21++)
										{
											num20 = (num20 - (286097073 - -339876573)) ^ -204550602;
											num20 = (num20 - -521224915 * 1428310794) ^ 0x625E3C84;
										}
										if (num3 != (uint)num20)
										{
											int num22 = 1991674403;
											_ = 0;
											for (int num23 = 0; num23 < 1; num23++)
											{
												num22 *= -805745737;
											}
											if (num3 != (uint)num22)
											{
												int num24 = -600909962;
												_ = 0;
												for (int num25 = 0; num25 < 1; num25++)
												{
													num24 -= -600909972;
												}
												if (num3 != (uint)num24)
												{
													int num26 = 10496107;
													_ = 0;
													for (int num27 = 0; num27 < 2; num27++)
													{
														num26 = ~num26 - -372181108;
														num26 = num26 ^ -1817368463 ^ -1829249971;
													}
													if (num3 != (uint)num26)
													{
													}
													return result;
												}
												result = InfoBarSeverity.Informational;
												num = -2101836618;
											}
											else
											{
												int[] array3 = new int[7];
												array3[0] = -1508529726;
												array3[1] = 1146434719;
												array3[2] = 707777523;
												array3[3] = -1365232435;
												array3[4] = -1250286901;
												array3[5] = 1046923444;
												array3[6] = 1379094305;
												array3[4] = array3[1] ^ -1987948512;
												array3[1] = array3[5] ^ -123484247;
												array3[0] = array3[3] ^ 0x8E16266;
												int[] array4 = new int[5] { -1349692308, 37392967, 1909462306, 1033448300, -1612836902 };
												int[][] array5 = new int[2][] { array3, array4 };
												array4[4] = array5[0][5] ^ 0x528654;
												array4[1] ^= -1799168629;
												array4[2] = array4[1] ^ -974051207;
												int num28 = array5[1][4] ^ -1131623850;
												num = ((int)num4 * -1937419219) ^ -1843912585 ^ num28;
											}
											continue;
										}
										goto IL_06bd;
									}
									int[] array6 = new int[7];
									array6[0] = 19385254;
									array6[1] = -118552905;
									array6[2] = 61445859;
									array6[3] = 67533207;
									array6[4] = -895937908;
									array6[5] = -766828986;
									array6[6] = -131161019;
									array6[2] = array6[4] ^ 0x60CCD655;
									array6[4] ^= 432509184;
									array6[2] = array6[1] ^ -1674254413;
									int[] array7 = new int[4];
									array7[0] = -1064940036;
									array7[1] = 1489354929;
									array7[2] = 141919007;
									array7[3] = -32513060;
									array7[3] = array6[5] ^ -709496429;
									array7[0] = array7[1] ^ -126108428;
									array7[1] = array7[0] ^ -2131606346;
									int num29 = array7[3] ^ -2058982557;
									num = ((int)num4 * -2146338519) ^ -330994398 ^ num29;
									continue;
								}
								goto IL_06d0;
							}
							int[] array8 = new int[5];
							array8[0] = -1443654693;
							array8[1] = -1489807598;
							array8[2] = -918527055;
							array8[3] = -234477016;
							array8[4] = -1092382744;
							array8[1] = array8[2] ^ -4164865;
							array8[1] ^= -425723662;
							array8[3] ^= -2069813147;
							int[] array9 = new int[7] { -956756459, 2105329812, 1183855536, 96167700, -879711229, -265450665, 1193964267 };
							int[][] array10 = new int[2][] { array8, array9 };
							array9[2] = array10[0][0] ^ 0x103A31B5;
							array9[3] = array9[6] ^ -770301607;
							array9[6] ^= -1709920340;
							array9[1] = array9[3] ^ 0x40A9DDDE;
							int num30 = array10[1][2] ^ 0x3B7126D8;
							num = ((int)num4 * -1100527651) ^ 0x681621CF ^ num30;
							continue;
						}
					}
					else
					{
						switch (statusLevel)
						{
						case SeverityLevel.Success:
							break;
						case SeverityLevel.Error:
							goto IL_06bd;
						case SeverityLevel.Warning:
							goto IL_06d0;
						default:
							goto IL_0c09;
						}
					}
					result = InfoBarSeverity.Success;
					num = -1545242912;
					continue;
					IL_06bd:
					result = InfoBarSeverity.Error;
					num = 1897727160;
					continue;
					IL_0c09:
					int[] array11 = new int[7];
					array11[0] = 909831043;
					array11[1] = 1135719122;
					array11[2] = 247272126;
					array11[3] = 34345297;
					array11[4] = -847985681;
					array11[5] = 1128315379;
					array11[6] = 1323252540;
					array11[6] = array11[3] ^ 0x15B48B0A;
					array11[0] = array11[6] ^ 0x73378086;
					array11[0] ^= 573266304;
					int[] array12 = new int[7];
					array12[0] = 1780815439;
					array12[1] = 1248722768;
					array12[2] = 2142060270;
					array12[3] = 572011104;
					array12[4] = -1377794502;
					array12[5] = 107574779;
					array12[6] = -961350404;
					array12[1] = array11[2] ^ 0x54779A88;
					array12[5] = array12[1] ^ -902364767;
					array12[3] = array12[2] ^ 0xEF43B5E;
					int num31 = array12[1] ^ -262507905;
					num = (int)((num4 * 450251152) ^ 0xA6915A20u) ^ num31;
					continue;
					IL_06d0:
					result = InfoBarSeverity.Warning;
					num = -876541161;
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
			if (!SetProperty(ref _statusLevel, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x979 ^ 0x825))]))
			{
				return;
			}
			while (true)
			{
				int num = 779362071;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(~(~((~(-(~944734458)) + ~(--925194920 + -1193401684)) * 2143312099 - ((num2 * -1882423879 + (~(987742332 - ((-(--1332677338 * 968442715) + -(~2026048376 * 410435499)) ^ -858892734)) ^ (1165912302 + 1687737620 + -1781644461 * (--1903272632 * -479257999))) + ~(-(-1594488653 * (-(0x785351C5 ^ -1166475304) ^ -1276524562) + ~(--2110047316)))) ^ (~((2079047735 - -1492266912) * -154172999 - -(-434871567)) - ((-1098603725 * (1921134943 * -1114852509) + -(-1941082827 ^ 0x6AFCE320)) ^ -(~(-491388237 ^ 0x2BCBD70))) - ~(-958738839 * 218243113 - ~((0x55864E5 ^ -198332320) * -689275879))))) ^ 0x759B2758))))) % 3;
					int num5 = 1883681868;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 - (261252590 - 255597232)) * 873218237;
						num5 = -(num5 ^ 0x16A2B181);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 -= 1366755639;
						num7 = 828458308 - -1245142616 - num7 - -2056850174;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 834080128;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 - (-1662878595 ^ 0x855F0DD));
							num9 = -num9 * 1533099391;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					_002F_003F_005E_0040_002D_005E_0028_0021((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[440 - 23 - 24 - 44]);
					int[] array = new int[5];
					array[0] = -2096739857;
					array[1] = 472581946;
					array[2] = 1956249908;
					array[3] = -1092925000;
					array[4] = -611031097;
					array[3] = array[0] ^ 0x39A54DF8;
					array[1] = array[2] ^ -1669024240;
					array[3] = array[0] ^ -728289746;
					int[] array2 = new int[6];
					array2[0] = -1214615151;
					array2[1] = 1635372385;
					array2[2] = -1106859300;
					array2[3] = 598859191;
					array2[4] = 518670583;
					array2[5] = 1533078537;
					array2[5] = array[0] ^ 0x5E787202;
					array2[2] ^= 2056208540;
					array2[0] = array2[5] ^ 0x7DE5A8A7;
					array2[2] = array2[0] ^ -1711643054;
					int num11 = array2[5] ^ -639412342;
					num = ((int)num4 * -1911122690) ^ 0x1FAC79A6 ^ num11;
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
			if (!SetProperty(ref _statusMessage, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xC46 ^ 0xD18]))
			{
				return;
			}
			while (true)
			{
				int num = -1158528646;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(-(0x538A87A2 ^ --355021051))) - ~(~(num2 * 293513755 - (-(-(-(~(56859585 * (-2031216432 ^ -438216886)))) + ((-1850751481 * (1427889345 * (-102178293 ^ -237901460))) ^ -896330890)) ^ ((0x48BF71FA ^ -(~(1500684929 - 876715565 - -808356346))) + 2010420813 * -(~(433222406 * -1628268529 + (514067414 + -1758719478))) - -(1866197923 - -334864391 * ~(566843177 * -535559388 + (-2051699711 - 426307668))))))))) % 3;
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
						int num9 = -342284327;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 - (0x7380C08B ^ -720918478)) ^ -989247263;
							num9 = ~(870311741 * -182972337 - num9);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					_002F_003F_005E_0040_002D_005E_0028_0021((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[420 - 2 - 31 - 36]);
					int[,] array = new int[3, 4];
					array[0, 0] = 1420251977;
					array[0, 1] = 1934801226;
					array[0, 2] = 697133247;
					array[0, 3] = 422551303;
					array[1, 0] = 246682994;
					array[1, 1] = 668938573;
					array[1, 2] = -665864597;
					array[1, 3] = 38329210;
					array[2, 0] = 896581241;
					array[2, 1] = -1644973605;
					array[2, 2] = -1192660520;
					array[2, 3] = 1885126024;
					array[0, 1] = array[0, 0] ^ -109443277;
					array[2, 2] = array[0, 2] ^ -1886348119;
					array[1, 3] = array[1, 2] ^ 0x70488C50;
					int num11 = array[1, 3] ^ -22334338;
					num = (int)((num4 * 554584834) ^ 0x7751922E) ^ num11;
				}
			}
		}
	}

	public SettingsViewModel(AppViewModel appViewModel, IAuthenticationService authenticationService, ILauncherService launcherService, ISettingsStore settingsStore, IStringResourceService strings)
	{
		while (true)
		{
			int num = 1819075822;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(~num2) * 2147240825 * 956587749 * -2141851231)) % 10;
				int num5 = -711422587;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = (-722302866 - num5) * -1348887775;
					num5 = 2085793637 + -322020600 - num5 + 1276239856;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 116192564;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 ^= 0x6ECF53D;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -581889007;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = (num9 ^ 0x365DE336) + 1116858508;
						num9 = num9 * 1745250513 - -1571236504;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 288057204;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 ^= 0x112B6774;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -8;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 = -num13;
							}
							if (num3 != (uint)num13)
							{
								int num15 = -1242765036;
								_ = 0;
								for (int num16 = 0; num16 < 2; num16++)
								{
									num15 = -(num15 + -1541826011);
									num15 = (num15 ^ --761386251) * -828924191;
								}
								if (num3 != (uint)num15)
								{
									int num17 = 383857984;
									_ = 0;
									for (int num18 = 0; num18 < 1; num18++)
									{
										num17 ^= 0x16E13546;
									}
									if (num3 != (uint)num17)
									{
										int num19 = -1155641726;
										_ = 0;
										for (int num20 = 0; num20 < 2; num20++)
										{
											num19 = (num19 * 1406923553) ^ 0x557F710D;
											num19 += 2083174863 * -2044056299;
										}
										if (num3 != (uint)num19)
										{
											int num21 = 268566675;
											_ = 0;
											for (int num22 = 0; num22 < 2; num22++)
											{
												num21 = num21 - --1765526040 + -2050267902;
												num21 = -num21 ^ 0x86F644D;
											}
											if (num3 != (uint)num21)
											{
												int num23 = 1428791207;
												_ = 0;
												for (int num24 = 0; num24 < 2; num24++)
												{
													num23 = ~num23 * -635173075;
													num23 = ~(num23 ^ -737863976);
												}
												if (num3 == (uint)num23)
												{
												}
												return;
											}
											_0028_0040__0029_0024_0028_003C_0024((ObservableObject)appViewModel, (PropertyChangedEventHandler)delegate
											{
												_002F_003F_005E_0040_002D_005E_0028_0021((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x16447 ^ 0x1657E))]);
												while (true)
												{
													int num33 = 1579314038;
													while (true)
													{
														int num34 = num33;
														uint num36;
														uint num35 = (num36 = (uint)(-(~(~(((num34 + (((~(~(-(-1761609576 ^ -1475739680))) * 1393049759) ^ ~(~(-(-(1074273332 - -1756588606 + (-863288395 + -2093789140))) ^ -1572862409))) - (-(~-800884794) ^ 0x7097865D))) ^ ((~((95329344 + 1597791983 + -1747017948) ^ -(-714141039 - 2011684405)) - -215795351 * (-289823220 ^ (0x7BDE8264 ^ --1405584445)) - (37169581 * ~(~175801916) + ~-1042907022) + -999030502) ^ -(-(~(~(0x57F38DFA ^ -1033313321)))))) * -1605519355 * -1522137899)) + -261664582 - (1496089304 + -2094205548 - (1483848142 - -1502563080)) - (1285535389 - -513440183)))) % 4;
														int num37 = -1269448736;
														_ = 0;
														for (int num38 = 0; num38 < 2; num38++)
														{
															num37 = num37 + (-599668518 + -1577483111) + 180993114;
															num37 = num37 * 1250025857 * -1723921185;
														}
														if (num35 == (uint)num37)
														{
															break;
														}
														int num39 = 1140990211;
														_ = 0;
														for (int num40 = 0; num40 < 2; num40++)
														{
															num39 = -num39 - -427572823;
															num39 = (num39 - (570819483 - 440438660)) ^ 0x2B8130BA;
														}
														if (num35 != (uint)num39)
														{
															int num41 = 1564671;
															_ = 0;
															for (int num42 = 0; num42 < 2; num42++)
															{
																num41 = ~(-num41);
																num41 = (num41 ^ -1142846850) + -434825118;
															}
															if (num35 != (uint)num41)
															{
																int num43 = 1853630712;
																_ = 0;
																for (int num44 = 0; num44 < 2; num44++)
																{
																	num43 = ~(num43 ^ -68469091);
																	num43 -= 0x5C09F70F ^ -350002668;
																}
																if (num35 == (uint)num43)
																{
																}
																return;
															}
															_0024_0023_002F_0026_005E_0024_003E_0021(OpenUpdateCommand);
															int[,] array14 = new int[4, 3];
															array14[0, 0] = -1726798056;
															array14[0, 1] = -230412690;
															array14[0, 2] = 1536248673;
															array14[1, 0] = 1056588187;
															array14[1, 1] = 1583479635;
															array14[1, 2] = 1022029286;
															array14[2, 0] = -1505569019;
															array14[2, 1] = -418008189;
															array14[2, 2] = 1106408796;
															array14[3, 0] = -934030320;
															array14[3, 1] = -559707329;
															array14[3, 2] = -218422982;
															array14[1, 0] = array14[3, 1] ^ 0x6969098;
															array14[1, 1] = array14[3, 0] ^ -1938553225;
															array14[2, 0] = array14[3, 2] ^ -2025028712;
															int num45 = array14[2, 0] ^ -1164184565;
															num33 = ((int)num36 * -151491326) ^ -372805038 ^ num45;
														}
														else
														{
															_002F_003F_005E_0040_002D_005E_0028_0021((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x5CC8 ^ 0x5DBF))]);
															int[] array15 = new int[5];
															array15[0] = 536350872;
															array15[1] = -1832840971;
															array15[2] = 1659414186;
															array15[3] = -185632204;
															array15[4] = 896027090;
															array15[2] = array15[1] ^ -2009650967;
															array15[4] = array15[3] ^ 0x17A47214;
															int[] array16 = new int[5] { -859775215, -1020497433, -1265683689, 1374080054, 659110214 };
															int[][] array17 = new int[2][] { array15, array16 };
															array16[4] = array17[0][3] ^ 0x26542270;
															array16[3] = array16[0] ^ 0xDAFDF56;
															array16[1] = array16[3] ^ -1843357001;
															array16[3] = array16[4] ^ -248356420;
															int num46 = array17[1][4] ^ -536363032;
															num33 = ((int)num36 * -1143908901) ^ -520410731 ^ num46;
														}
													}
												}
											});
											int[,] array = new int[3, 4];
											array[0, 0] = -954760063;
											array[0, 1] = 786588242;
											array[0, 2] = 1794530630;
											array[0, 3] = -1558641695;
											array[1, 0] = -1201375631;
											array[1, 1] = 491762460;
											array[1, 2] = -584919144;
											array[1, 3] = -1390182892;
											array[2, 0] = 287276688;
											array[2, 1] = 637786770;
											array[2, 2] = -297032970;
											array[2, 3] = 1121341105;
											array[2, 0] = array[1, 0] ^ -932412731;
											array[1, 1] = array[0, 2] ^ 0x5802EDCE;
											array[1, 2] = array[2, 1] ^ 0x2F099BE1;
											int num25 = array[1, 2] ^ -174871865;
											num = ((int)num4 * -753866426) ^ -1062672298 ^ num25;
										}
										else
										{
											OpenUpdateCommand = new AsyncRelayCommand(OpenUpdateAsync, CanOpenUpdate);
											SignOutCommand = new RelayCommand(SignOut);
											int[,] array2 = new int[4, 3];
											array2[0, 0] = 1195977718;
											array2[0, 1] = -1458442652;
											array2[0, 2] = 160495035;
											array2[1, 0] = -225008487;
											array2[1, 1] = -1371207619;
											array2[1, 2] = -601368396;
											array2[2, 0] = 665837807;
											array2[2, 1] = 2122713353;
											array2[2, 2] = 1141539764;
											array2[3, 0] = -231670834;
											array2[3, 1] = -1368729741;
											array2[3, 2] = -811531476;
											array2[3, 1] = array2[1, 2] ^ -512843343;
											array2[2, 0] = array2[1, 1] ^ -1177795232;
											array2[2, 0] = array2[0, 0] ^ -542997690;
											int num26 = array2[2, 0] ^ -1139292132;
											num = (int)((num4 * 517702296) ^ 0xE20CDCD0u) ^ num26;
										}
									}
									else
									{
										ClearStoredLicenseCommand = new RelayCommand(ClearStoredLicense);
										int[,] array3 = new int[3, 4];
										array3[0, 0] = -1801645065;
										array3[0, 1] = -1639111471;
										array3[0, 2] = -971392699;
										array3[0, 3] = 404394472;
										array3[1, 0] = -510587043;
										array3[1, 1] = 147393613;
										array3[1, 2] = -36933523;
										array3[1, 3] = -945440735;
										array3[2, 0] = 1795564997;
										array3[2, 1] = 94335601;
										array3[2, 2] = 428681233;
										array3[2, 3] = 2050198040;
										array3[0, 3] = array3[0, 2] ^ -1735315912;
										array3[1, 1] = array3[2, 0] ^ 0x6D400184;
										array3[0, 3] = array3[1, 3] ^ 0x26376423;
										array3[2, 2] = array3[2, 3] ^ 0x5D1082B;
										int num27 = array3[2, 2] ^ 0x430E6BE6;
										num = ((int)num4 * -316723910) ^ 0x33C72204 ^ num27;
									}
								}
								else
								{
									_strings = strings;
									int[] array4 = new int[4];
									array4[0] = 2113255188;
									array4[1] = -21609184;
									array4[2] = 144720988;
									array4[3] = 1068380403;
									array4[2] = array4[0] ^ 0x3EA04C54;
									array4[0] = array4[2] ^ -26542994;
									int[] array5 = new int[4];
									array5[0] = -1799021358;
									array5[1] = -313593837;
									array5[2] = -1023929488;
									array5[3] = -1304238502;
									array5[3] = array4[1] ^ 0x7A0470B2;
									array5[2] = array5[1] ^ -184040655;
									array5[2] ^= -2032376858;
									int num28 = array5[3] ^ 0x5A1A9AE3;
									num = (int)((num4 * 780534438) ^ 0x62D8393C) ^ num28;
								}
							}
							else
							{
								_settingsStore = settingsStore;
								int[] array6 = new int[4] { -1340259738, -1572041847, 67930367, -699231486 };
								array6[2] ^= 172569104;
								array6[0] = array6[3] ^ 0x28779CD3;
								int[] array7 = new int[6] { -1653364635, -152620317, -1357956443, -281773813, 147139439, 566575794 };
								int[][] array8 = new int[2][] { array6, array7 };
								array7[0] = array8[0][1] ^ -92322887;
								array7[2] = array7[4] ^ 0x79055F3E;
								array7[1] = array7[2] ^ 0x38D57004;
								array7[2] = array7[0] ^ 0x6AC703D8;
								int num29 = array8[1][0] ^ 0x76D3F901;
								num = (int)((num4 * 137430473) ^ 0xC7F8EB06u) ^ num29;
							}
						}
						else
						{
							_launcherService = launcherService;
							int[,] array9 = new int[3, 3];
							array9[0, 0] = 1457869018;
							array9[0, 1] = 795610897;
							array9[0, 2] = 1952147685;
							array9[1, 0] = -207910782;
							array9[1, 1] = 1626151671;
							array9[1, 2] = -1702297543;
							array9[2, 0] = -163352352;
							array9[2, 1] = 1033522916;
							array9[2, 2] = -1702622184;
							array9[1, 0] = array9[2, 1] ^ -881332699;
							array9[0, 1] = array9[1, 1] ^ 0xD43B721;
							array9[0, 1] = array9[0, 0] ^ -1702487912;
							int num30 = array9[0, 1] ^ -966398065;
							num = (int)((num4 * 2054725256) ^ 0x8C1D290) ^ num30;
						}
					}
					else
					{
						_authenticationService = authenticationService;
						int[] array10 = new int[7];
						array10[0] = -1473640873;
						array10[1] = -1868377648;
						array10[2] = 1635174792;
						array10[3] = -195679179;
						array10[4] = 757284534;
						array10[5] = 692356451;
						array10[6] = -1085757104;
						array10[4] = array10[6] ^ -1954813627;
						array10[5] = array10[3] ^ 0x6BB6ABAE;
						int[] array11 = new int[7] { -973313435, -1731082702, 1519862301, 567249995, 36689935, 2027227345, -972373027 };
						int[][] array12 = new int[2][] { array10, array11 };
						array11[6] = array12[0][0] ^ -371954227;
						array11[2] = array11[3] ^ -1433443554;
						array11[3] = array11[6] ^ 0x5A3DECB8;
						int num31 = array12[1][6] ^ 0x5B771CC3;
						num = ((int)num4 * -1522235770) ^ 0x2624642 ^ num31;
					}
				}
				else
				{
					AppViewModel = appViewModel;
					int[,] array13 = new int[4, 3];
					array13[0, 0] = 779569347;
					array13[0, 1] = 167158796;
					array13[0, 2] = 679781592;
					array13[1, 0] = -675081526;
					array13[1, 1] = 1393212288;
					array13[1, 2] = 203297014;
					array13[2, 0] = 188891227;
					array13[2, 1] = 1672643996;
					array13[2, 2] = 930328064;
					array13[3, 0] = 1610146230;
					array13[3, 1] = 123423103;
					array13[3, 2] = -1413245532;
					array13[2, 0] = array13[3, 0] ^ 0x3687339C;
					array13[3, 2] = array13[1, 1] ^ 0x6BCAA566;
					array13[3, 0] = array13[0, 1] ^ 0xD1DDF32;
					int num32 = array13[3, 0] ^ 0x4B1978;
					num = (int)((num4 * 1741491790) ^ 0x3C0B1E4A) ^ num32;
				}
			}
		}
	}

	private bool CanOpenUpdate()
	{
		return !_003C_0029_0040_0025_005E_002A_003D_003F(AppViewModel.UpdateUrl);
	}

	private unsafe void ClearStoredLicense()
	{
		_0024_002A_0026_0024_002D_005E_0026_0024(_settingsStore, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xB03C ^ 0xB14E]);
		while (true)
		{
			int num = 1626773152;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)((~(-(~(-(~(num2 ^ (((~(--54295344 + (0x7DFB78E4 ^ -307949891)) + ((0xA09A454 ^ 0x34DCDAC2) - ~-1908114174 * 1886895491)) ^ -226355391) * -1388839733 - ~(~(~-722499563)))) ^ -(780539133 * ~(-1380897597 * ~-2009684298 - (-1854877680 ^ 0x48BEBF26) * -262743523) * -1517292583))))) * 1745604847 + (2069809937 + -1109560246)) ^ -1849633663)) % 4;
				int num5 = 662701954;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = -1908310191 - (num5 ^ 0x4FB159A);
					num5 = num5 ^ -15158308 ^ 0x6F1F9087;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 975175693;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -982422518 - -num7;
					num7 = -(num7 ^ 0x1D1E0065);
				}
				if (num3 != (uint)num7)
				{
					int num9 = 0;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 = -num9;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 326880885;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = num11 * -352141653 + 853786095;
							num11 = ~num11 - 79482658;
						}
						if (num3 == (uint)num11)
						{
						}
						return;
					}
					SetStatus(_0028_0026_003F_005E_005E_003F_0024_0040(_strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(352 + sizeof(int)) ^ sizeof(Guid)]), SeverityLevel.Success);
					int[] array = new int[4];
					array[0] = 1022142334;
					array[1] = -618107611;
					array[2] = -15159848;
					array[3] = -184271631;
					array[2] = array[0] ^ 0x757F21E2;
					array[1] = array[2] ^ 0x646C79D7;
					array[2] = array[0] ^ 0x2FD48D6D;
					int[] array2 = new int[4];
					array2[0] = -375568171;
					array2[1] = 1397211252;
					array2[2] = -1768099801;
					array2[3] = -612809065;
					array2[0] = array[0] ^ 0x556D0B8;
					array2[1] = array2[3] ^ -458866086;
					array2[3] = array2[1] ^ -371926716;
					array2[3] = array2[2] ^ 0x7561107D;
					int num13 = array2[0] ^ -960141804;
					num = ((int)num4 * -852468767) ^ 0x5415B27C ^ num13;
				}
				else
				{
					_0026_0024_0028__0040_002F_005E_0040(_settingsStore, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[3425 - 3140 + 86], false);
					int[] array3 = new int[6];
					array3[0] = -1670295703;
					array3[1] = 267549577;
					array3[2] = -1022835674;
					array3[3] = -1447174066;
					array3[4] = 1731946647;
					array3[5] = -283836837;
					array3[0] = array3[3] ^ 0x52F3E41;
					array3[4] ^= 1987019667;
					int[] array4 = new int[7];
					array4[0] = -856499736;
					array4[1] = 407288885;
					array4[2] = 124398167;
					array4[3] = -1877782486;
					array4[4] = 1183271115;
					array4[5] = 567501429;
					array4[6] = -689417259;
					array4[4] = array3[2] ^ -1944088083;
					array4[3] = array4[0] ^ -620566294;
					array4[0] = array4[2] ^ -71815811;
					array4[3] = array4[6] ^ -1183177588;
					int num14 = array4[4] ^ -1893195888;
					num = ((int)num4 * -148814253) ^ -1241710103 ^ num14;
				}
			}
		}
	}

	[AsyncStateMachine(typeof(_003COpenUpdateAsync_003Ed__35))]
	private Task OpenUpdateAsync()
	{
		_003COpenUpdateAsync_003Ed__35 stateMachine = default(_003COpenUpdateAsync_003Ed__35);
		stateMachine._003C_003Et__builder = _002A__0021_002A_0025_005E_0026_0024();
		while (true)
		{
			int num = -1267847825;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(-(num2 - (-314143043 * ((-1144648511 * ((~(--1639482668) ^ 0x7DE7A7F2) - ((-13912295 * --1139786708) ^ -(--474651879)))) ^ -(~(~((0x197ABBA5 ^ 0x7C7A0E44) - ~-1677405492)))) * 1701274027 + ((-(-1826501421 * ~(0x156BC03F ^ -783979851)) ^ -1867450754) + (0x37E6F66B ^ (((1767963864 - -1550238651) * 887785339 - (-57289286 ^ -876362986) + ((-752728844 ^ -2024018204) + 1877947381 * ~1204443365)) ^ -93799189)) + 969695313 * ~(-(0x61A2C528 ^ 0x486801C8)))))) ^ (-(~(678843305 * (184268029 * 1894566775)) + (-(423445973 * 1927118249) + -(-1884941142 - 714480179))) - ~(-877063217 * 497114485 - ~(-728532379 * (0x34EEBFA5 ^ -106425022)))))) % 5;
				int num5 = 1585144600;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~(num5 * -134502653);
					num5 ^= 0x6097E82B;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -1239099852;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 *= -484436667;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 858135555;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 *= 1175968863;
						num9 = num9 * -53117679 - -1983302998;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 1;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = ~num11 - -375772206;
							num11 = -(~num11);
						}
						if (num3 != (uint)num11)
						{
							int num13 = 2143873898;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = ~(num13 - (1692176355 - 1761662544));
								num13 = -(num13 * 1827121651);
							}
							if (num3 != (uint)num13)
							{
							}
							return stateMachine._003C_003Et__builder.Task;
						}
						stateMachine._003C_003Et__builder.Start(ref stateMachine);
						int[] array = new int[7];
						array[0] = 1927179877;
						array[1] = -1721463323;
						array[2] = 655761341;
						array[3] = -1222378833;
						array[4] = 1491955416;
						array[5] = 293513541;
						array[6] = -563942205;
						array[1] = array[3] ^ 0x263D7F21;
						array[3] ^= -1211115531;
						array[1] = array[5] ^ -1608527689;
						int[] array2 = new int[5];
						array2[0] = -1440144778;
						array2[1] = -1791524442;
						array2[2] = 970047857;
						array2[3] = 759973009;
						array2[4] = -306217457;
						array2[0] = array[4] ^ -1017756473;
						array2[4] ^= -407816739;
						array2[2] ^= 1311601662;
						int num15 = array2[0] ^ 0x81F787F;
						num = (int)((num4 * 562811121) ^ 0x221D8666) ^ num15;
					}
					else
					{
						stateMachine._003C_003E1__state = -1;
						int[] array3 = new int[4] { 1826967404, -896060517, -531074960, -256994932 };
						array3[2] ^= -169353125;
						array3[1] = array3[3] ^ 0x6EF962CA;
						array3[0] = array3[1] ^ -717402287;
						int[] array4 = new int[4];
						array4[0] = 2079687364;
						array4[1] = 1427430662;
						array4[2] = -1486162740;
						array4[3] = -1985586740;
						array4[0] = array3[3] ^ -990539639;
						array4[2] ^= 2082068870;
						array4[1] = array4[0] ^ 0x1B4BA46E;
						int num16 = array4[0] ^ -660133589;
						num = (int)((num4 * 982497204) ^ 0x3E2A5B30) ^ num16;
					}
				}
				else
				{
					stateMachine._003C_003E4__this = this;
					int[,] array5 = new int[3, 4];
					array5[0, 0] = -2044008910;
					array5[0, 1] = -1146771653;
					array5[0, 2] = -1079613015;
					array5[0, 3] = 538314094;
					array5[1, 0] = 2028419510;
					array5[1, 1] = 1790922727;
					array5[1, 2] = 1915962170;
					array5[1, 3] = 671292185;
					array5[2, 0] = 1978815919;
					array5[2, 1] = 1264310431;
					array5[2, 2] = 1949798489;
					array5[2, 3] = -1848603832;
					array5[0, 2] = array5[0, 0] ^ 0x5222D29B;
					array5[2, 1] = array5[2, 2] ^ 0x2D6E8804;
					array5[0, 2] = array5[1, 3] ^ -1263710636;
					int num17 = array5[0, 2] ^ 0x5D3966D9;
					num = ((int)num4 * -560794649) ^ -83801775 ^ num17;
				}
			}
		}
	}

	private void SetStatus(string message, SeverityLevel level)
	{
		StatusMessage = message;
		while (true)
		{
			int num = -242713742;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)((-(~(-502132714 + 254751853) + ((-1771954064 ^ -486200610) + (-1873451263 ^ -919225316)) - (-993653591 * (-1884713192 ^ -4332097) + 787871790 - (--576786259 - 1175603315 * (-517752046 ^ (-617666569 * -1788382911) ^ 0x2BC2C2A1) - ((num2 - (-239865529 * -(~(437309133 - (-(-175081006 + -1069877304) - (-445119188 ^ 0x634BBF0A) * 185280119))) + 712140943 * (-(-1676490399 - ~1202132423 + ~(~801540145) + 1808223688) + -629798383 * (((-1212985965 ^ 0x5FC3C6BC) + (~1869525008 - --793444564)) ^ 0x4703428E)) + ~(-(0x6C00A89E ^ (-(--1812184044) - (1817254925 * 384609793 - 77170324))) ^ (-(-150667144 - 1818373763 - (-2050622257 - (-1484122747 ^ 0x756E6A23))) * -1451211705) ^ 0x11EE9BAA)) - -842963959 * (-938575547 * 988905095)) ^ (-412931494 + -(~(-(0x3B754B18 ^ -99477639) + -(-1684602587 + 1980329156 + -1016289626)))))) + -(-819327861 * --1789431873 - (-1582237143 ^ 0x788AE751)))) - -2127618155 * 1395170217) ^ -1724815700)) % 3;
				int num5 = 36720656;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 += 1596021580;
					num5 = (num5 - -1076678511) ^ 0x66E7D2F7;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -2142997517;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = (num7 ^ 0x3B8911F2) - 1252206841;
					num7 = -(-num7);
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1312163454;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 *= -1509528385;
					}
					if (num3 == (uint)num9)
					{
					}
					return;
				}
				StatusLevel = level;
				int[] array = new int[6];
				array[0] = 926699905;
				array[1] = 1492925582;
				array[2] = 60077985;
				array[3] = 315251734;
				array[4] = -254376601;
				array[5] = 2093571849;
				array[3] = array[1] ^ 0x178B7E8E;
				array[3] = array[5] ^ 0x63A3BB4C;
				array[3] = array[0] ^ -447771695;
				int[] array2 = new int[5] { -1458510053, 1522256501, -708174005, 1818398332, -617162160 };
				int[][] array3 = new int[2][] { array, array2 };
				array2[0] = array3[0][1] ^ 0x16B5C830;
				array2[2] = array2[0] ^ -1070064737;
				array2[1] = array2[3] ^ -1623268447;
				array2[3] = array2[1] ^ -639730793;
				int num11 = array3[1][0] ^ 0x4EE6B9D0;
				num = ((int)num4 * -1807036716) ^ 0xCF9144 ^ num11;
			}
		}
	}

	private void SignOut()
	{
		_002D_0029__002B_0023_003E__003E(_authenticationService);
		while (true)
		{
			int num = -1888546226;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(~(-(~(-509369453)))) - ((~(~num2) - (1915458636 + ~(-(-(0x38F017AE ^ 0x5FF2FE02) + (3279707 * 1392829522 + (0x2AA41787 ^ 0x4D121808))) - (-1107179863 ^ -232764583)))) ^ (~(-(-113434070 - 78337756 + (636313982 + 334085855))) - -(~(--671515518 + -1809193465)) + ((-1433879557 ^ 0x2975A1C4) + ((942667328 * -659794203 + -2128146075) ^ (-1197935318 ^ --133776931))) * -371588221)))) % 5;
				int num5 = 16778626;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~(num5 ^ 0x6C72483F);
					num5 = -num5 + -551684848;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1841353286;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 ^= 0x6DC0D242;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1188244805;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 ^= 0x46D32D46;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -1667659270;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 = -1667659270 - num11;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 1;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = -num13 ^ 0x6082FEE9;
								num13 ^= -750585617;
							}
							if (num3 != (uint)num13)
							{
							}
							_002F_003F_005E_0040_002D_005E_0028_0021((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[3213 - 2932 + 94]);
							return;
						}
						_002F_003F_005E_0040_002D_005E_0028_0021((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xCFC ^ 0xDC5]);
						int[] array = new int[5] { 1026473752, -423087898, -788264553, -1120569334, 2128197952 };
						array[0] ^= -2070588667;
						array[4] = array[0] ^ 0x6D420F96;
						int[] array2 = new int[5];
						array2[0] = -464482612;
						array2[1] = 1966238904;
						array2[2] = -487958080;
						array2[3] = -1698453855;
						array2[4] = -400468663;
						array2[4] = array[1] ^ 0x173A1AF1;
						array2[0] = array2[4] ^ -506906115;
						array2[2] = array2[1] ^ 0x6DFD3BD4;
						array2[1] = array2[2] ^ -1743978326;
						int num15 = array2[4] ^ -1841792402;
						num = (int)((num4 * 733187473) ^ 0xAC38DF6) ^ num15;
					}
					else
					{
						SetStatus(_0028_0026_003F_005E_005E_003F_0024_0040(_strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x7FD ^ 0x68B]), SeverityLevel.Warning);
						int[,] array3 = new int[3, 4];
						array3[0, 0] = 1996818490;
						array3[0, 1] = 1244126892;
						array3[0, 2] = -1959330908;
						array3[0, 3] = -676581755;
						array3[1, 0] = 443135212;
						array3[1, 1] = 1526841825;
						array3[1, 2] = 1542127752;
						array3[1, 3] = 108630326;
						array3[2, 0] = 1774684213;
						array3[2, 1] = 10562267;
						array3[2, 2] = 270275827;
						array3[2, 3] = 1873398266;
						array3[0, 2] = array3[1, 1] ^ 0x3AF383FE;
						array3[2, 0] = array3[0, 3] ^ 0x1CD0714F;
						array3[2, 1] = array3[0, 2] ^ -1749464012;
						array3[1, 1] = array3[0, 1] ^ 0x1510832E;
						int num16 = array3[1, 1] ^ -859723428;
						num = ((int)num4 * -726596745) ^ -1626863090 ^ num16;
					}
				}
				else
				{
					AppViewModel.SignOut();
					AppViewModel.AddActivity(_0028_0026_003F_005E_005E_003F_0024_0040(_strings, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x4292 ^ 0x43E7))]), SeverityLevel.Warning);
					int[] array4 = new int[5];
					array4[0] = -627216595;
					array4[1] = -1581391881;
					array4[2] = 1463345858;
					array4[3] = 1303896448;
					array4[4] = 202758856;
					array4[2] = array4[1] ^ -423542735;
					array4[4] = array4[2] ^ -1073726257;
					array4[4] = array4[0] ^ 0x2CF9354E;
					int[] array5 = new int[6];
					array5[0] = 1604527783;
					array5[1] = 2105979146;
					array5[2] = 1775459911;
					array5[3] = -1949243629;
					array5[4] = -139735469;
					array5[5] = 2017493890;
					array5[5] = array4[0] ^ 0x76954DBB;
					array5[0] = array5[3] ^ -1051490486;
					array5[0] = array5[3] ^ 0x7BE304CD;
					int num17 = array5[5] ^ -461052532;
					num = (int)((num4 * 600350004) ^ 0x5967FDB8) ^ num17;
				}
			}
		}
	}

	static void _0028_0040__0029_0024_0028_003C_0024(ObservableObject P_0, PropertyChangedEventHandler P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1456983846;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((-257643011 ^ ~(~(~589810770 + 1415608347 + 765270091 * (-33909527 + 1722259219) - -(--146382521 + (0xF77FBE4 ^ 0x6BFDF513))))) - ((num2 - (~(-((-(1573495367 * -626085285) - ~(1164495364 * 1559985025) + -480156281 * ((0x3BCF518E ^ -437110744) * 2045850969) - -(-(-353645729 * -321976248))) * 1524309905)) + ~(-(~(0x74D2A7AF ^ 0x74CA6651) + 1150280111 + (-334217703 + (1547352352 - -828388192)) * -1199887643 + -1043656347 - -(-725582575 + -388590827 * ~-1639000379 - (697688532 + -1908670741 - (0x51274580 ^ -1818742793) - 944681726)))))) ^ (-577451175 * (1774883211 + ~((~(--390100707) ^ -(-1931437068 ^ -899867539)) - -365355497) + ~(-1940620474 - ((-426675903 * -(-1542215635 - -2088612106)) ^ 0x6E603ABD)))))) + (-(266263853 - (~-1836535978 - 1000169895 * -196544960)) ^ -(~(-1953392222 ^ 0x25DFEA6B))))) % 3;
					int num5 = -244937312;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(-num5);
						num5 = num5 * -1580726251 * 851494307;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 52109015;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x31B1ED6;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2032308518;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ --1792995279) * 506708259;
							num9 = -num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.PropertyChanged += P_1;
					int[] array = new int[7];
					array[0] = -652814072;
					array[1] = 80810901;
					array[2] = 1787680098;
					array[3] = -330791899;
					array[4] = 36648831;
					array[5] = 82347187;
					array[6] = 1484112220;
					array[1] = array[2] ^ -349338358;
					array[1] = array[3] ^ 0x122E3C2C;
					array[2] = array[1] ^ 0x4D4EF557;
					int[] array2 = new int[4] { 1186810886, 1331786479, -920214513, 591849341 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][4] ^ 0x3D37E8B7;
					array2[2] = array2[1] ^ -1778290639;
					array2[2] = array2[0] ^ -1875849631;
					array2[1] = array2[2] ^ 0x4C1D9B29;
					int num11 = array3[1][3] ^ -2144123864;
					num = ((int)num4 * -1154763556) ^ -263919332 ^ num11;
				}
			}
		}
	}

	static bool _003C_0029_0040_0025_005E_002A_003D_003F(string P_0)
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
				int num = 400048061;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(-(~(-(-(~num2) * -1407247443)) - (-402706665 ^ (--36932889 + 268601141) ^ -1625615947)))))) % 3;
					int num5 = -1856724054;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 - -1746123796;
						num5 = ~num5 - 1620481472;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -89144957;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += 89144958;
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
					result = string.IsNullOrWhiteSpace(P_0);
					int[] array = new int[6];
					array[0] = 2087439400;
					array[1] = -101921477;
					array[2] = -234148356;
					array[3] = 1877713753;
					array[4] = 1072099103;
					array[5] = -343275757;
					array[2] = array[3] ^ -1105655091;
					array[0] = array[3] ^ -677176471;
					array[4] ^= 15913831;
					int[] array2 = new int[5];
					array2[0] = -2126440682;
					array2[1] = 2065810429;
					array2[2] = 1557075106;
					array2[3] = -1240121179;
					array2[4] = -1527163754;
					array2[0] = array[1] ^ -695494236;
					array2[2] = array2[4] ^ 0x304C40B4;
					array2[4] = array2[2] ^ -304740611;
					array2[3] = array2[1] ^ 0xC41CB52;
					int num11 = array2[0] ^ -212211900;
					num = (int)((num4 * 2139376013) ^ 0x175EA8CE) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _002F_003F_005E_0040_002D_005E_0028_0021(ObservableObject P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -146354774;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(-((-1336593089 * 735097615 + 1042732640 * -74846683 + (-1234183064 - -2021296294) - ~(713529089 * -1488905281 * -1172270121)) * -1132886791 - (-(-1834525568 + -728683300 - (1277889300 + -1214608096)) - 771520823 * (-477207533 ^ 0x29560F2) - (~(-1776334184 + -50181438) * -707773787 - ~(~-797985129 + 2058203120))) - ((num2 ^ (~((-1465236954 + ~(-2146633665 * ~(-2007078785 * -1587660606)) - (-1958592515 ^ (-(0x1C76F447 ^ -1818220960) - -342708897 + -497953537))) * -45798357) ^ (((-(-(-284427292 ^ 0x4DA7886A)) + ~(~673902456 + (-1301218008 ^ -1765977378) + -(535526178 + 1106037466) - ((0x5CCA12E9 ^ -1925808555) + (-573489835 - -789938553 - (-456775675 - -1071752305))))) ^ ((-655005906 ^ 0x3D3F2EE4) - -(-(-967801501 + 622101254) - -1942237896) + -(0x30CA8904 ^ 0x500CD75C))) + ((-(-410045047 * (-1003388498 ^ 0x4715FEE6 ^ (--1068270286 + --198299228))) + ((-(1967560940 + (-1627868656 - -709659618)) - (-(-1007981666) - -(1099994927 * 517897828))) ^ ~(-(1021115865 * 10822840)))) ^ ~(~(-(~(~-268001115)))))))) + (~710256815 * -1403675903 - (185326220 - -431571319 * 777793567)) + (~((-2142249547 - (~(1342699592 + 1446432300) - (-665054923 ^ -2055999396))) * 839052955) + ~(-(~(-(-466978411 - -616262360)) - (1137930270 - 1874118887 - (0x7FF4FE3F ^ -493254290)) * 553970335)))) - -231615535 * -422925466 * -1989247901))))) % 3;
					int num5 = 195831777;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0xBAC27E1;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2016521541;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = 2016521543 - num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1007687015;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ -946948758) * -630772261;
							num9 = ~(num9 ^ -1059285852);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.OnPropertyChanged(P_1);
					int[] array = new int[7];
					array[0] = -26435818;
					array[1] = 700463377;
					array[2] = 864775839;
					array[3] = -1567120313;
					array[4] = -12577512;
					array[5] = 1889922863;
					array[6] = 1919389541;
					array[2] = array[0] ^ -1806510076;
					array[0] = array[1] ^ 0x27E6669D;
					array[6] = array[2] ^ 0x3882E1B0;
					int[] array2 = new int[7];
					array2[0] = 890554068;
					array2[1] = -1454939058;
					array2[2] = 180304766;
					array2[3] = -1934119806;
					array2[4] = 710080343;
					array2[5] = 923856335;
					array2[6] = 593620450;
					array2[1] = array[5] ^ -1125832508;
					array2[0] ^= -2115984611;
					array2[6] = array2[2] ^ -1370689164;
					array2[0] ^= 1605172607;
					int num11 = array2[1] ^ 0x6D840F3A;
					num = ((int)num4 * -1499115611) ^ -2037550566 ^ num11;
				}
			}
		}
	}

	static void _0024_002A_0026_0024_002D_005E_0026_0024(ISettingsStore P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			P_0.Remove(P_1);
		}
	}

	static void _0026_0024_0028__0040_002F_005E_0040(ISettingsStore P_0, string P_1, bool P_2)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1982171388;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((-num2 ^ (-1941393281 * ((-(--1938331441) - (-1160580996 + (-422224501 ^ 0x45F92F36)) + 389918563 - -1686719775) * -1074778313) + (-274469817 + (0xAC9FE93 ^ (1356202950 - (-2069771317 + -590428559 + ~(-1813546382 * 1579012705))) ^ 0x5B2F4334)))) + (-(~(~(1529552040 - -79997149)) + (-873917979 * 374477299 - ((-1478264428 ^ 0xF04FD64) + 894624885 * 2023417758)) + ~(-(2038535927 - --1754938879))) - (527581367 + (-1471473990 ^ -2134112930)))) * 369404189)) % 3;
					int num5 = 209443258;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(num5 - -70591419 * 1821600695);
						num5 = -858319330 - num5 * -1609052367;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1865733559;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += 1865733561;
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
					P_0.SetBoolean(P_1, P_2);
					int[] array = new int[6];
					array[0] = -1168121369;
					array[1] = -2038946521;
					array[2] = 1503919736;
					array[3] = -2056682033;
					array[4] = 197961657;
					array[5] = -816909832;
					array[1] = array[0] ^ -1219136257;
					array[2] = array[4] ^ -1166647863;
					int[] array2 = new int[6] { 1714170203, -1252141770, -53712271, -1009326560, -126418247, -1702839742 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][3] ^ -1624985771;
					array2[2] = array2[1] ^ -1217799882;
					array2[0] = array2[5] ^ 0x2D7205FF;
					int num11 = array3[1][1] ^ 0x9AA4504;
					num = (int)((num4 * 1674601053) ^ 0x3C43B1D5) ^ num11;
				}
			}
		}
	}

	static string _0028_0026_003F_005E_005E_003F_0024_0040(IStringResourceService P_0, string P_1)
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
				int num = -593866590;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(-611614338 + -532168317) - -((-(~num2 ^ (--1903339503 + (~(1552013149 - -530653916 - 1558341900 - (~-1745617303 + (1188853163 + -1029387918))) - (-827914669 * -1449310592 + (-(~-1117314985) + 559119967 * -875966939 * -1870510833)) - ((~(~(--1252858335)) * 549785817) ^ (-8732233 * (-(-409589473 - -1597506187) - -1666738585 * --1350387357)))) + -(~(~(-21852322 ^ -1277491388)) - -258460313))) ^ (-(--472704871) + ~(~1518944804) + (-2123794176 ^ -1007400853) - (~(2023618183 + -1773829108) - -1645905616 - -646185280) + -43791429)) * -1862968581 + ~(~-259897131 + ~130696702 - -761487218)) - (1263778171 + 482685555)) ^ 0x39598A10)) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(~num5);
						num5 = ~1049801330 - num5 - 1747779484;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1061940734;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -1329133163 - ~num7;
						num7 = ~(num7 ^ 0x62DA4944);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1936625475;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= -2133194091;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.GetString(P_1);
					int[] array = new int[4];
					array[0] = -848488224;
					array[1] = 456761065;
					array[2] = -362523570;
					array[3] = 138282250;
					array[1] = array[0] ^ -1287233757;
					array[1] = array[0] ^ -1660426912;
					int[] array2 = new int[7];
					array2[0] = -861392316;
					array2[1] = -1557775814;
					array2[2] = 374666507;
					array2[3] = 169975625;
					array2[4] = -757416314;
					array2[5] = -1730887532;
					array2[6] = 800468995;
					array2[2] = array[3] ^ 0x3D63FD0B;
					array2[4] = array2[2] ^ -218905565;
					array2[1] ^= 357132987;
					array2[3] = array2[2] ^ 0x6C1012DC;
					int num11 = array2[2] ^ 0x502F4C4B;
					num = (int)((num4 * 103034165) ^ 0x702265C) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static AsyncTaskMethodBuilder _002A__0021_002A_0025_005E_0026_0024()
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
				int num = 1791293278;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(-(~(-(~num2 + -2039002582 * -18077533))) * -1225264511 + (~(1343562151 * 2097400479) - -(~-1877638240))) - --357511296) * 1252468257)) % 3;
					int num5 = 2111192514;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 ^= 0x21E67DC7;
						num5 = ~num5 * -1609545715;
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
							num9 = ~(~num9);
							num9 = ~(-num9);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = AsyncTaskMethodBuilder.Create();
					int[] array = new int[4];
					array[0] = -1271586897;
					array[1] = 1867527487;
					array[2] = 1838955781;
					array[3] = 1004113350;
					array[3] = array[0] ^ 0x734209BD;
					array[3] ^= -126583136;
					int[] array2 = new int[5] { 1626345608, 1317482296, 2043455003, 698783933, -1372111855 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][0] ^ 0x17D0AB07;
					array2[1] = array2[4] ^ 0x224A2CCE;
					array2[2] = array2[4] ^ 0x19C97DDF;
					int num11 = array3[1][3] ^ 0x5E85DC46;
					num = ((int)num4 * -434655260) ^ -220304828 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _002D_0029__002B_0023_003E__003E(IAuthenticationService P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -2095326864;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((num2 - -(-((-885827973 ^ -1091102355) + ~(0x588613E ^ -1167155501)) * -1921382675) * 324042005) * -1511833729) - (~(~(-221968717 ^ -1479604895)) - ~-1367168245))) % 3;
					int num5 = 1960692898;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * -1970215327 - -1229405384;
						num5 = ~num5 - 2075856172;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 149952709;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 149952708;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1699084990;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = 1699084990 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.SignOut();
					int[] array = new int[7];
					array[0] = -904935913;
					array[1] = 1331083531;
					array[2] = -775038404;
					array[3] = -1763575704;
					array[4] = 606591370;
					array[5] = -1827988496;
					array[6] = 2066634873;
					array[3] = array[6] ^ 0x4275A77D;
					array[5] = array[3] ^ -1555128232;
					int[] array2 = new int[4] { -1870892147, 1917945058, 1823144205, 1136588239 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][4] ^ 0x3E5189AA;
					array2[2] = array2[3] ^ -1513165206;
					array2[3] = array2[0] ^ -1392942610;
					int num11 = array3[1][1] ^ 0x431CF796;
					num = (int)((num4 * 382224442) ^ 0x91BCF704u) ^ num11;
				}
			}
		}
	}

	static void _0024_0023_002F_0026_005E_0024_003E_0021(AsyncRelayCommand P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1216254028;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(855060683 * (-1555057168 ^ (-1712592869 + (0x6FB034EE ^ -1311272926))) - ((((num2 ^ (((-1954963961 ^ ~(-(-(-1690521290 ^ 0x71C76D38))) ^ (-(1115437233 + ((0x69C21780 ^ 0x2A915CFA) + ~-1144071215)) * -1477729269)) - 1696354399 * -(0x73C6D54 ^ ~(-1590091527) ^ -1915227971) - (1351518888 - ~(~753068444 - (841564235 * -1621695517 + (630622236 + -1085303462)) * -614335203) + (~(-(-664169271 ^ 0x56AF5141)) - (-142401833 * (-358866864 ^ 0x3F13C5C0) + 1487343982)))) * 1652148845)) * -70222609) ^ --1487762203) + (-267180958 ^ (-((0x47361514 ^ -28979185) + ~-1151494750) + 571064071 + 876976585 * (-17734678 ^ (0x1DA45FA7 ^ --937193258))))) * 1846303631 + (0x6CDAC2F5 ^ -909655518) - ((0x610424E4 ^ -2079558465) - (2058018027 + 87040292))))) % 3;
					int num5 = 504523460;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 504523460;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -673214626;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 + --1555474580 + -1281016238;
						num7 = num7 - (0x1A6FA93C ^ 0x399A221C) - -665443468;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1289776851;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 1289776850;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.NotifyCanExecuteChanged();
					int[] array = new int[7];
					array[0] = -1333501637;
					array[1] = -1218332868;
					array[2] = -2134694140;
					array[3] = -1866619200;
					array[4] = 83505876;
					array[5] = 1228535581;
					array[6] = 1868639220;
					array[6] = array[3] ^ -631457182;
					array[4] = array[6] ^ 0x3E76A0EC;
					array[1] = array[2] ^ 0x71E19A32;
					int[] array2 = new int[7];
					array2[0] = -1314443611;
					array2[1] = 1834124200;
					array2[2] = 1866184623;
					array2[3] = -1958996808;
					array2[4] = 742623129;
					array2[5] = -1325184817;
					array2[6] = -1619903003;
					array2[2] = array[3] ^ -958280499;
					array2[4] = array2[2] ^ -1078167733;
					array2[6] = array2[1] ^ 0x23DC8099;
					int num11 = array2[2] ^ 0x2E929A7A;
					num = ((int)num4 * -841868132) ^ -147261992 ^ num11;
				}
			}
		}
	}
}
