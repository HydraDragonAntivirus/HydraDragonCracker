using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Pbt_003D;
using RikaNET.WinUI.ViewModels;
using Windows.ApplicationModel.DataTransfer;
using Windows.Foundation;
using Windows.Storage;
using WinRT;

namespace RikaNET.WinUI.Views;

public sealed class WorkspaceView : UserControl, IComponentConnector
{
	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CAssemblyDropZone_Drop_003Ed__7 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncVoidMethodBuilder _003C_003Et__builder;

		public DragEventArgs e;

		public WorkspaceView _003C_003E4__this;

		private TaskAwaiter<IReadOnlyList<IStorageItem>> _003C_003Eu__1;

		private TaskAwaiter _003C_003Eu__2;

		private void MoveNext()
		{
			int num = _003C_003E1__state;
			WorkspaceView workspaceView = _003C_003E4__this;
			try
			{
				if (num != 0)
				{
					goto IL_0023;
				}
				goto IL_3293;
				IL_0023:
				int num2 = 520913886;
				goto IL_0028;
				IL_0028:
				TaskAwaiter<IReadOnlyList<IStorageItem>> awaiter = default(TaskAwaiter<IReadOnlyList<IStorageItem>>);
				StorageFile storageFile = default(StorageFile);
				TaskAwaiter awaiter2 = default(TaskAwaiter);
				while (true)
				{
					int num3 = num2;
					uint num5;
					uint num4 = (num5 = (uint)((-(-879479374 ^ -724677538) ^ 0x627CE7D7 ^ 0xCD1DC5C) - (~(~((-(-1755145299) + 1744420509) ^ -552394730)) + (1733526128 - (2015739805 * (-114750734 ^ (-1449987957 * 239342665 - --757435119)) + -(-(-(~-115063101))))) - ~(num3 - 7452719 * -(-(-(-(1440275625 + -802413107 + -726508445) ^ 0x3FF2608B) ^ (1183817941 * (-(-2123309120 * -858771083) ^ -1611771528 ^ 0x472E7389)))))))) % 25;
					uint num6 = num4;
					int num7 = 1526708906;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += -1526708890;
					}
					if (num6 == (uint)num7)
					{
						break;
					}
					uint num9 = num4;
					int num10 = -3455077;
					_ = 0;
					for (int num11 = 0; num11 < 2; num11++)
					{
						num10 = (num10 ^ -1601583335) * -1856159541;
						num10 = -(num10 - (-2126535038 ^ -927807154));
					}
					if (num9 == (uint)num10)
					{
						int num12 = num;
						int[] array = new int[7] { -1883304223, -172568453, 509644013, -1953757687, 458951426, 1771593246, -10746506 };
						array[6] ^= -4801312;
						array[5] = array[1] ^ -1338017974;
						array[6] ^= -705101133;
						int[] array2 = new int[5] { 852604452, 664384768, -198914484, -787201630, -1403074307 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[4] = array3[0][2] ^ 0x2AE5F9DF;
						array2[3] = array2[1] ^ -751007289;
						array2[1] ^= -1395343019;
						int num13 = array3[1][4] ^ 0x37834E26;
						int[] array4 = new int[5];
						array4[0] = -179771556;
						array4[1] = 955963013;
						array4[2] = -881665396;
						array4[3] = 1951145756;
						array4[4] = -553145299;
						array4[3] = array4[4] ^ -1948919169;
						array4[3] = array4[2] ^ -1777973629;
						array4[3] = array4[0] ^ -1822215557;
						int[] array5 = new int[6] { -138472910, 1424576461, -1835084048, 852895085, -1402020511, -294618884 };
						int[][] array6 = new int[2][] { array4, array5 };
						array5[1] = array6[0][1] ^ 0x31CFD80C;
						array5[4] ^= -1967070689;
						array5[2] = array5[5] ^ 0x1FC563C4;
						int num14 = array6[1][1] ^ 0x6B25A42E;
						int num15 = (int)(num5 * 135545907) ^ -1386297663;
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
					int num19 = -13;
					_ = 0;
					for (int num20 = 0; num20 < 1; num20++)
					{
						num19 = ~num19;
					}
					if (num18 == (uint)num19)
					{
						awaiter = _002F__0023_0023_0028_0040_002B_005E(@_0040_002B__0026_0040_0029_(e)).GetAwaiter();
						int[] array7 = new int[7];
						array7[0] = -175566936;
						array7[1] = 186934332;
						array7[2] = -332037220;
						array7[3] = 229712962;
						array7[4] = -557261247;
						array7[5] = -395631102;
						array7[6] = 702749114;
						array7[1] = array7[0] ^ 0x66B95A56;
						array7[3] = array7[2] ^ 0x735BF187;
						int[] array8 = new int[5];
						array8[0] = -837516425;
						array8[1] = 469844444;
						array8[2] = -172997349;
						array8[3] = 1936309634;
						array8[4] = -2070522762;
						array8[1] = array7[0] ^ -1081707010;
						array8[0] ^= 264197415;
						array8[2] = array8[4] ^ 0x1198EA2A;
						int num21 = array8[1] ^ 0x3A69CC02;
						num2 = (int)((num5 * 2102776019) ^ 0x35DB07F6) ^ num21;
						continue;
					}
					uint num22 = num4;
					int num23 = 3;
					_ = 0;
					for (int num24 = 0; num24 < 2; num24++)
					{
						num23 = num23 - -1310332845 - -1945531492;
						num23 = ~num23;
					}
					if (num22 == (uint)num23)
					{
						bool ısCompleted = awaiter.IsCompleted;
						int[,] array9 = new int[4, 4];
						array9[0, 0] = -831610435;
						array9[0, 1] = -538743760;
						array9[0, 2] = 1533717124;
						array9[0, 3] = 1687559589;
						array9[1, 0] = -1924346769;
						array9[1, 1] = 170449569;
						array9[1, 2] = 1746932890;
						array9[1, 3] = -258813014;
						array9[2, 0] = -1348615047;
						array9[2, 1] = 264600379;
						array9[2, 2] = 517446943;
						array9[2, 3] = 1896494656;
						array9[3, 0] = -1943597046;
						array9[3, 1] = 1044854819;
						array9[3, 2] = 463705204;
						array9[3, 3] = 413490963;
						array9[1, 0] = array9[2, 2] ^ -130736508;
						array9[1, 2] = array9[3, 1] ^ -760945703;
						array9[1, 3] = array9[3, 2] ^ -1770594671;
						int num25 = array9[1, 3] ^ -1872870515;
						int[] array10 = new int[5];
						array10[0] = 2011465181;
						array10[1] = 1141523520;
						array10[2] = 1294052699;
						array10[3] = 292558294;
						array10[4] = 759286427;
						array10[2] = array10[1] ^ 0x773DC75A;
						array10[1] = array10[3] ^ 0x4C00EC50;
						int[] array11 = new int[7];
						array11[0] = 925798664;
						array11[1] = 1029250601;
						array11[2] = -19736834;
						array11[3] = -370277081;
						array11[4] = -1845427575;
						array11[5] = -397142025;
						array11[6] = 811897955;
						array11[0] = array10[3] ^ -317365560;
						array11[4] = array11[3] ^ -1082205678;
						array11[1] = array11[2] ^ 0x7BADCE9D;
						array11[5] = array11[3] ^ 0x7B39ECA2;
						int num26 = array11[0] ^ -453398979;
						int num27 = (int)(num5 * 1502462410) ^ -650857358;
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
					int num31 = 628388086;
					_ = 0;
					for (int num32 = 0; num32 < 1; num32++)
					{
						num31 *= -500255719;
					}
					if (num30 == (uint)num31)
					{
						num = (_003C_003E1__state = 0);
						int[,] array12 = new int[4, 3];
						array12[0, 0] = 1066156356;
						array12[0, 1] = 1413321577;
						array12[0, 2] = -1085146278;
						array12[1, 0] = 1224021124;
						array12[1, 1] = 1380191139;
						array12[1, 2] = -169616504;
						array12[2, 0] = -705414961;
						array12[2, 1] = 769775881;
						array12[2, 2] = 733639933;
						array12[3, 0] = -1397399080;
						array12[3, 1] = 1643204087;
						array12[3, 2] = 294518323;
						array12[0, 2] = array12[2, 0] ^ 0x19E68595;
						array12[3, 2] ^= 1154949719;
						array12[0, 1] = array12[2, 1] ^ -116867269;
						int num33 = array12[0, 1] ^ -1452044332;
						num2 = ((int)num5 * -1134213908) ^ 0x262FCEC8 ^ num33;
						continue;
					}
					uint num34 = num4;
					int num35 = 887755325;
					_ = 0;
					for (int num36 = 0; num36 < 2; num36++)
					{
						num35 = -1951554179 - num35 + -327451834;
						num35 = ~(num35 - (-944816733 + -1778066931));
					}
					if (num34 == (uint)num35)
					{
						_003C_003Eu__1 = awaiter;
						int[] array13 = new int[7];
						array13[0] = 1380915214;
						array13[1] = 832888491;
						array13[2] = 286797133;
						array13[3] = 1841459573;
						array13[4] = -961300175;
						array13[5] = 708031495;
						array13[6] = -1522439819;
						array13[6] = array13[1] ^ -2097955042;
						array13[0] = array13[4] ^ -24658469;
						int[] array14 = new int[5] { 2095802258, 1642661345, 166902631, -208329513, 435649948 };
						int[][] array15 = new int[2][] { array13, array14 };
						array14[0] = array15[0][2] ^ 0x5EE688B1;
						array14[1] = array14[0] ^ -2051669874;
						array14[2] = array14[3] ^ -798639704;
						array14[4] = array14[3] ^ -2021562604;
						int num37 = array15[1][0] ^ 0x4CC56703;
						num2 = ((int)num5 * -514642844) ^ 0x7690B3EC ^ num37;
						continue;
					}
					uint num38 = num4;
					int num39 = -1783302242;
					_ = 0;
					for (int num40 = 0; num40 < 2; num40++)
					{
						num39 = ~(num39 * 1777644091);
						num39 = ~num39 ^ 0x1E1CA536;
					}
					if (num38 == (uint)num39)
					{
						_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
						int[] array16 = new int[7];
						array16[0] = -1280354694;
						array16[1] = -810856163;
						array16[2] = 1413090945;
						array16[3] = 955698155;
						array16[4] = 1521132623;
						array16[5] = -1878183827;
						array16[6] = -220825484;
						array16[3] = array16[5] ^ 0x274E8894;
						array16[0] = array16[6] ^ -1443280372;
						int[] array17 = new int[4] { -2009055328, 1944026731, 1858902479, 1038986137 };
						int[][] array18 = new int[2][] { array16, array17 };
						array17[3] = array18[0][1] ^ -1997881485;
						array17[2] = array17[3] ^ 0x11C14EBF;
						array17[0] ^= -1170592254;
						int num41 = array18[1][3] ^ 0xDEB2AB2;
						num2 = (int)((num5 * 244456083) ^ 0xE1F474EEu) ^ num41;
						continue;
					}
					uint num42 = num4;
					int num43 = -1922809334;
					_ = 0;
					for (int num44 = 0; num44 < 2; num44++)
					{
						num43 = (num43 * -1245945063) ^ 0x398057BF;
						num43 = (460735153 * -1570154573 - num43) ^ 0x27AC3FAA;
					}
					if (num42 == (uint)num43)
					{
						return;
					}
					uint num45 = num4;
					int num46 = 1346365490;
					_ = 0;
					for (int num47 = 0; num47 < 2; num47++)
					{
						num46 = -551281745 - -num46;
						num46 = (num46 ^ 0x35AC3D2) - 84332036;
					}
					if (num45 == (uint)num46)
					{
						goto IL_3293;
					}
					uint num48 = num4;
					int num49 = -2021516415;
					_ = 0;
					for (int num50 = 0; num50 < 2; num50++)
					{
						num49 = ~num49 * -2066465319;
						num49 = (num49 + -158608345) ^ 0x65ED9D6B;
					}
					if (num48 == (uint)num49)
					{
						_003C_003Eu__1 = default(TaskAwaiter<IReadOnlyList<IStorageItem>>);
						int[] array19 = new int[4];
						array19[0] = 472848317;
						array19[1] = 177370464;
						array19[2] = -62295360;
						array19[3] = -1816873686;
						array19[2] = array19[1] ^ 0x5DC0E0F3;
						array19[3] = array19[2] ^ -1849587409;
						array19[1] = array19[0] ^ 0x2B86C8ED;
						int[] array20 = new int[5];
						array20[0] = 117688881;
						array20[1] = -132732350;
						array20[2] = 960784474;
						array20[3] = 403697620;
						array20[4] = 1966779591;
						array20[3] = array19[0] ^ 0x62A82CA4;
						array20[0] ^= -1019479640;
						array20[4] ^= 50614225;
						array20[4] = array20[3] ^ 0x5FAACF1E;
						int num51 = array20[3] ^ 0x45DAEDD5;
						num2 = ((int)num5 * -307440693) ^ 0x38A2A47D ^ num51;
						continue;
					}
					uint num52 = num4;
					int num53 = 765307159;
					_ = 0;
					for (int num54 = 0; num54 < 2; num54++)
					{
						num53 = -num53 - 1723645302;
						num53 = -1836547433 - num53 * 582943893;
					}
					if (num52 == (uint)num53)
					{
						num = (_003C_003E1__state = -1);
						int[,] array21 = new int[4, 4];
						array21[0, 0] = -2105584800;
						array21[0, 1] = 1633293376;
						array21[0, 2] = 1936656031;
						array21[0, 3] = 184829569;
						array21[1, 0] = -933465815;
						array21[1, 1] = 191249561;
						array21[1, 2] = 723566024;
						array21[1, 3] = -1750411961;
						array21[2, 0] = -84226190;
						array21[2, 1] = -526898955;
						array21[2, 2] = 851338943;
						array21[2, 3] = 2085661368;
						array21[3, 0] = 445303668;
						array21[3, 1] = -1673183985;
						array21[3, 2] = -126224424;
						array21[3, 3] = 1214956266;
						array21[3, 2] = array21[2, 2] ^ -1662226781;
						array21[2, 0] = array21[2, 1] ^ 0x250DE352;
						array21[1, 2] = array21[0, 1] ^ -1657356038;
						int num55 = array21[1, 2] ^ -504898094;
						num2 = (int)((num5 * 230531753) ^ 0xBD69ED5) ^ num55;
						continue;
					}
					uint num56 = num4;
					int num57 = 80326790;
					_ = 0;
					for (int num58 = 0; num58 < 1; num58++)
					{
						num57 -= 80326773;
					}
					if (num56 == (uint)num57)
					{
						storageFile = awaiter.GetResult().OfType<StorageFile>().FirstOrDefault();
						num2 = 1173242796;
						continue;
					}
					uint num59 = num4;
					int num60 = -903375593;
					_ = 0;
					for (int num61 = 0; num61 < 1; num61++)
					{
						num60 += 903375615;
					}
					if (num59 == (uint)num60)
					{
						workspaceView.ResetDropZoneVisuals();
						int[,] array22 = new int[4, 4];
						array22[0, 0] = -479765186;
						array22[0, 1] = -198454565;
						array22[0, 2] = -974847967;
						array22[0, 3] = 1598983390;
						array22[1, 0] = -1521042701;
						array22[1, 1] = 214666951;
						array22[1, 2] = 1656631978;
						array22[1, 3] = -1113932572;
						array22[2, 0] = 215990126;
						array22[2, 1] = -1891313219;
						array22[2, 2] = -865223747;
						array22[2, 3] = 1828314333;
						array22[3, 0] = -1546621437;
						array22[3, 1] = -1979675844;
						array22[3, 2] = -122897094;
						array22[3, 3] = -2080738927;
						array22[0, 1] = array22[3, 1] ^ -644321781;
						array22[0, 3] = array22[1, 2] ^ -232236005;
						array22[3, 0] = array22[2, 3] ^ -652971508;
						int num62 = array22[3, 0] ^ -1803311529;
						num2 = ((int)num5 * -1321167248) ^ -494322256 ^ num62;
						continue;
					}
					uint num63 = num4;
					int num64 = 23;
					_ = 0;
					for (int num65 = 0; num65 < 2; num65++)
					{
						num64 = -(~num64);
						num64 = 1431663990 - num64;
					}
					if (num63 == (uint)num64)
					{
						StorageFile storageFile2 = storageFile;
						int[,] array23 = new int[3, 4];
						array23[0, 0] = -1243215863;
						array23[0, 1] = -1339286921;
						array23[0, 2] = 1548357995;
						array23[0, 3] = 1921825088;
						array23[1, 0] = -313218087;
						array23[1, 1] = 146271838;
						array23[1, 2] = 604334042;
						array23[1, 3] = -1432547472;
						array23[2, 0] = -1692504626;
						array23[2, 1] = 153264168;
						array23[2, 2] = 560303945;
						array23[2, 3] = -843910981;
						array23[2, 3] = array23[0, 0] ^ 0x29D393C5;
						array23[1, 2] = array23[0, 2] ^ 0x2F36C4CF;
						array23[1, 2] = array23[1, 3] ^ 0x1177DC21;
						int num66 = array23[1, 2] ^ -1376420733;
						int[,] array24 = new int[4, 4];
						array24[0, 0] = -1432507236;
						array24[0, 1] = -89344332;
						array24[0, 2] = 310337996;
						array24[0, 3] = 1983835359;
						array24[1, 0] = -1189409007;
						array24[1, 1] = -2090023439;
						array24[1, 2] = 221499490;
						array24[1, 3] = 1155201220;
						array24[2, 0] = -1910316867;
						array24[2, 1] = 625835612;
						array24[2, 2] = -1118767915;
						array24[2, 3] = 667285073;
						array24[3, 0] = -962137787;
						array24[3, 1] = 99790533;
						array24[3, 2] = 1432900128;
						array24[3, 3] = 60964450;
						array24[2, 2] = array24[2, 1] ^ -2115023003;
						array24[1, 3] = array24[2, 3] ^ 0x5F664CC5;
						array24[0, 1] = array24[3, 1] ^ 0x1F4B2CA8;
						int num67 = array24[0, 1] ^ 0x7D82BFF6;
						int num68 = ((int)num5 * -541997914) ^ 0x74430B52;
						num66 ^= num68;
						num67 ^= num68;
						int num69;
						int num70;
						if ((object)storageFile2 != null)
						{
							num69 = num67;
							num70 = num69;
						}
						else
						{
							num69 = num66;
							num70 = num69;
						}
						num2 = num69 ^ num68;
						continue;
					}
					uint num71 = num4;
					int num72 = 1697794204;
					_ = 0;
					for (int num73 = 0; num73 < 2; num73++)
					{
						num72 = (num72 - (1011015409 + -362953187)) ^ 0x3D3FCF21;
						num72 = -(num72 * -1015763073);
					}
					if (num71 == (uint)num72)
					{
						awaiter2 = _003F_003E_003F_0021__005E_003D_002D(workspaceView.ViewModel.LoadAssemblyAsync(_002B_002F_005E_0021_002A_003F_0028_(storageFile)));
						int[] array25 = new int[5] { 887974493, 1096036242, 303115147, -1127886279, -1068878897 };
						array25[3] ^= -1663555930;
						array25[1] = array25[2] ^ -507901721;
						int[] array26 = new int[7];
						array26[0] = -858866736;
						array26[1] = -843411718;
						array26[2] = -1932675075;
						array26[3] = -281758713;
						array26[4] = -1612632798;
						array26[5] = -1575862203;
						array26[6] = -1782784721;
						array26[0] = array25[2] ^ 0x2BD8BA1C;
						array26[5] = array26[2] ^ 0x55567F;
						array26[2] = array26[3] ^ -1677712013;
						int num74 = array26[0] ^ 0x141B094F;
						num2 = ((int)num5 * -1199623504) ^ -1574075744 ^ num74;
						continue;
					}
					uint num75 = num4;
					int num76 = -1477644814;
					_ = 0;
					for (int num77 = 0; num77 < 2; num77++)
					{
						num76 = num76 - -1031064875 - 1335520287;
						num76 = num76 * 1117099185 - -1957662784;
					}
					if (num75 == (uint)num76)
					{
						bool ısCompleted2 = awaiter2.IsCompleted;
						int[,] array27 = new int[3, 3];
						array27[0, 0] = -595200976;
						array27[0, 1] = -319689697;
						array27[0, 2] = -945612075;
						array27[1, 0] = 570001712;
						array27[1, 1] = -162153514;
						array27[1, 2] = 1431569497;
						array27[2, 0] = 2131628943;
						array27[2, 1] = 1275875065;
						array27[2, 2] = 643536523;
						array27[1, 0] = array27[2, 2] ^ -1415039395;
						array27[1, 2] = array27[1, 1] ^ 0x1D1038CF;
						array27[0, 2] = array27[2, 0] ^ 0x217DA5DD;
						array27[0, 2] = array27[2, 0] ^ -1818742626;
						int num78 = array27[0, 2] ^ -1151891636;
						int[,] array28 = new int[3, 4];
						array28[0, 0] = -1492979924;
						array28[0, 1] = 765866581;
						array28[0, 2] = -278537660;
						array28[0, 3] = 708404417;
						array28[1, 0] = -286947883;
						array28[1, 1] = 1006219852;
						array28[1, 2] = 1365274155;
						array28[1, 3] = 125601357;
						array28[2, 0] = 726284645;
						array28[2, 1] = -841908211;
						array28[2, 2] = -85405232;
						array28[2, 3] = 1762905006;
						array28[1, 2] = array28[2, 2] ^ 0x4C15433A;
						array28[0, 0] = array28[1, 2] ^ 0x4F05AEB6;
						array28[1, 2] = array28[2, 0] ^ -1916637938;
						int num79 = array28[1, 2] ^ -743148555;
						int num80 = ((int)num5 * -1991335510) ^ -1222685654;
						num78 ^= num80;
						num79 ^= num80;
						int num81;
						int num82;
						if (!ısCompleted2)
						{
							num81 = num79;
							num82 = num81;
						}
						else
						{
							num81 = num78;
							num82 = num81;
						}
						num2 = num81 ^ num80;
						continue;
					}
					uint num83 = num4;
					int num84 = 747305851;
					_ = 0;
					for (int num85 = 0; num85 < 1; num85++)
					{
						num84 *= -212091319;
					}
					if (num83 == (uint)num84)
					{
						num = (_003C_003E1__state = 1);
						int[] array29 = new int[7];
						array29[0] = -403460475;
						array29[1] = -1318907097;
						array29[2] = -237330745;
						array29[3] = 1783927485;
						array29[4] = 2033260149;
						array29[5] = 1933343501;
						array29[6] = 989341410;
						array29[0] = array29[2] ^ -145788238;
						array29[0] ^= 131540907;
						array29[1] = array29[6] ^ -1336430227;
						int[] array30 = new int[4];
						array30[0] = -1500110747;
						array30[1] = -1861044380;
						array30[2] = 236690999;
						array30[3] = 1218976348;
						array30[1] = array29[5] ^ -1105250975;
						array30[0] ^= -255267056;
						array30[0] = array30[3] ^ 0x457ADC94;
						int num86 = array30[1] ^ -1314362362;
						num2 = ((int)num5 * -1134252137) ^ -1601215347 ^ num86;
						continue;
					}
					uint num87 = num4;
					int num88 = -330609324;
					_ = 0;
					for (int num89 = 0; num89 < 2; num89++)
					{
						num88 = (num88 - -1923947935) * -1941348585;
						num88 = -209311481 - num88 * -1616026513;
					}
					if (num87 == (uint)num88)
					{
						_003C_003Eu__2 = awaiter2;
						int[] array31 = new int[5];
						array31[0] = 158539967;
						array31[1] = 1154024245;
						array31[2] = -1355235847;
						array31[3] = -1881033544;
						array31[4] = -1913952854;
						array31[1] = array31[0] ^ 0x4654EDF;
						array31[1] = array31[4] ^ 0x7CD66B49;
						array31[1] = array31[0] ^ 0x7B58EBBB;
						int[] array32 = new int[5];
						array32[0] = 1437337282;
						array32[1] = -2051910463;
						array32[2] = -1037528465;
						array32[3] = -749324272;
						array32[4] = 791842557;
						array32[0] = array31[2] ^ -862991841;
						array32[4] = array32[3] ^ -651145471;
						array32[4] = array32[2] ^ -1041293264;
						int num90 = array32[0] ^ 0x4A1F8947;
						num2 = (int)((num5 * 1177256051) ^ 0xB3E7B09Du) ^ num90;
						continue;
					}
					uint num91 = num4;
					int num92 = 4;
					_ = 0;
					for (int num93 = 0; num93 < 2; num93++)
					{
						num92 += 717400096;
						num92 = 642182296 - 1292156236 - num92 - 356574005;
					}
					if (num91 == (uint)num92)
					{
						_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter2, ref this);
						int[] array33 = new int[7];
						array33[0] = -1269092325;
						array33[1] = 129236217;
						array33[2] = -1413553720;
						array33[3] = 1181857911;
						array33[4] = 1781051046;
						array33[5] = 299888615;
						array33[6] = -1464336258;
						array33[4] = array33[5] ^ 0x37239775;
						array33[2] = array33[3] ^ 0x1E54619D;
						int[] array34 = new int[4] { -482101002, -1025797784, 1805822545, -1734986297 };
						int[][] array35 = new int[2][] { array33, array34 };
						array34[3] = array35[0][0] ^ -995620177;
						array34[1] = array34[2] ^ -716019427;
						array34[2] ^= -1325532594;
						array34[0] = array34[2] ^ -1092664092;
						int num94 = array35[1][3] ^ 0x59308D88;
						num2 = ((int)num5 * -2141516182) ^ 0x68B4C5B0 ^ num94;
						continue;
					}
					uint num95 = num4;
					int num96 = 1771242961;
					_ = 0;
					for (int num97 = 0; num97 < 2; num97++)
					{
						num96 = ~num96 * -939139949;
						num96 = (num96 * -1344688669) ^ 0x228DE302;
					}
					if (num95 == (uint)num96)
					{
						return;
					}
					uint num98 = num4;
					int num99 = -6;
					_ = 0;
					for (int num100 = 0; num100 < 1; num100++)
					{
						num99 = ~num99;
					}
					if (num98 == (uint)num99)
					{
						awaiter2 = _003C_003Eu__2;
						num2 = 1871268329;
						continue;
					}
					uint num101 = num4;
					int num102 = 1595634078;
					_ = 0;
					for (int num103 = 0; num103 < 2; num103++)
					{
						num102 = num102 * 118094721 * -348332155;
						num102 = num102 ^ 0x21C1B1B9 ^ -9784151;
					}
					if (num101 == (uint)num102)
					{
						_003C_003Eu__2 = default(TaskAwaiter);
						int[] array36 = new int[5] { -1476345786, -1629158110, -177615889, 121165256, 1276032580 };
						array36[1] ^= 990462659;
						array36[4] = array36[0] ^ 0x2EA787BE;
						int[] array37 = new int[4];
						array37[0] = 214397396;
						array37[1] = 1545649890;
						array37[2] = 1484493754;
						array37[3] = 119309909;
						array37[1] = array36[0] ^ 0x3610C2F2;
						array37[2] = array37[1] ^ 0x4E869132;
						array37[3] = array37[2] ^ 0x6A1BF8EC;
						array37[2] = array37[3] ^ 0x36B5A0B6;
						int num104 = array37[1] ^ -1631781366;
						num2 = ((int)num5 * -1151815801) ^ -2126253488 ^ num104;
						continue;
					}
					uint num105 = num4;
					int num106 = 1426914720;
					_ = 0;
					for (int num107 = 0; num107 < 1; num107++)
					{
						num106 = 1426914744 - num106;
					}
					if (num105 == (uint)num106)
					{
						num = (_003C_003E1__state = -1);
						int[,] array38 = new int[4, 3];
						array38[0, 0] = 606512383;
						array38[0, 1] = -287250582;
						array38[0, 2] = 402424570;
						array38[1, 0] = 692260471;
						array38[1, 1] = 2107321465;
						array38[1, 2] = 1229010996;
						array38[2, 0] = -1051918281;
						array38[2, 1] = 558710745;
						array38[2, 2] = 193191059;
						array38[3, 0] = -94812934;
						array38[3, 1] = -1194983210;
						array38[3, 2] = -1249131499;
						array38[0, 0] = array38[0, 2] ^ -1468039656;
						array38[3, 1] = array38[0, 1] ^ 0xDA1F2F3;
						array38[0, 2] = array38[3, 0] ^ 0x3E8C12C6;
						int num108 = array38[0, 2] ^ -1827343775;
						num2 = ((int)num5 * -557606100) ^ 0x45B278A4 ^ num108;
						continue;
					}
					uint num109 = num4;
					int num110 = 1651683530;
					_ = 0;
					for (int num111 = 0; num111 < 1; num111++)
					{
						num110 -= 1651683529;
					}
					if (num109 == (uint)num110)
					{
						awaiter2.GetResult();
						num2 = 371175378;
						continue;
					}
					uint num112 = num4;
					int num113 = -1762904009;
					_ = 0;
					for (int num114 = 0; num114 < 2; num114++)
					{
						num113 = -num113;
						num113 = ~num113 - -881452013;
					}
					if (num112 == (uint)num113)
					{
					}
					goto end_IL_001a;
				}
				goto IL_0023;
				IL_3293:
				awaiter = _003C_003Eu__1;
				num2 = 187074882;
				goto IL_0028;
				end_IL_001a:;
			}
			catch (Exception exception)
			{
				while (true)
				{
					int num115 = 997364446;
					while (true)
					{
						int num3 = num115;
						uint num5;
						uint num4 = (num5 = (uint)((-(-879479374 ^ -724677538) ^ 0x627CE7D7 ^ 0xCD1DC5C) - (~(~((-(-1755145299) + 1744420509) ^ -552394730)) + (1733526128 - (2015739805 * (-114750734 ^ (-1449987957 * 239342665 - --757435119)) + -(-(-(~-115063101))))) - ~(num3 - 7452719 * -(-(-(-(1440275625 + -802413107 + -726508445) ^ 0x3FF2608B) ^ (1183817941 * (-(-2123309120 * -858771083) ^ -1611771528 ^ 0x472E7389)))))))) % 4;
						uint num116 = num4;
						int num117 = 2114162168;
						_ = 0;
						for (int num118 = 0; num118 < 2; num118++)
						{
							num117 = -num117 ^ 0x3FBF6817;
							num117 = (num117 ^ -622263493) + 1249880325;
						}
						if (num116 == (uint)num117)
						{
							break;
						}
						uint num119 = num4;
						int num120 = -3;
						_ = 0;
						for (int num121 = 0; num121 < 1; num121++)
						{
							num120 = -num120;
						}
						if (num119 != (uint)num120)
						{
							uint num122 = num4;
							int num123 = -2;
							_ = 0;
							for (int num124 = 0; num124 < 1; num124++)
							{
								num123 = ~num123;
							}
							if (num122 != (uint)num123)
							{
								uint num125 = num4;
								int num126 = 4;
								_ = 0;
								for (int num127 = 0; num127 < 2; num127++)
								{
									num126 = ~(-num126);
									num126 = ~(num126 ^ -1035673351);
								}
								if (num125 == (uint)num126)
								{
								}
								return;
							}
							_003C_003Et__builder.SetException(exception);
							int[] array39 = new int[6];
							array39[0] = 1787514184;
							array39[1] = 702349114;
							array39[2] = 1844535292;
							array39[3] = -1134759375;
							array39[4] = 1780348682;
							array39[5] = -129379799;
							array39[3] = array39[0] ^ 0x728EFFB2;
							array39[4] = array39[3] ^ 0x32B8443A;
							array39[0] = array39[4] ^ 0x1D3C247D;
							int[] array40 = new int[6];
							array40[0] = 1620193671;
							array40[1] = 201556607;
							array40[2] = -1315073821;
							array40[3] = -1911172453;
							array40[4] = -1906289913;
							array40[5] = 388589833;
							array40[5] = array39[1] ^ 0x4CB849CA;
							array40[0] = array40[4] ^ -1053959557;
							array40[0] = array40[4] ^ 0x1AE2E202;
							int num128 = array40[5] ^ 0x2CAD930F;
							num115 = (int)((num5 * 1582236910) ^ 0x42412ABE) ^ num128;
						}
						else
						{
							_003C_003E1__state = -2;
							int[] array41 = new int[5];
							array41[0] = -1246921722;
							array41[1] = 1188848808;
							array41[2] = -765153386;
							array41[3] = 585380317;
							array41[4] = 561307763;
							array41[0] = array41[4] ^ -873177737;
							array41[1] = array41[3] ^ 0x5B210C1B;
							array41[1] = array41[4] ^ -1309456931;
							int[] array42 = new int[6] { -1534771643, -1285611415, 332001434, 1148581427, 1993162087, 1600357263 };
							int[][] array43 = new int[2][] { array41, array42 };
							array42[2] = array43[0][2] ^ 0x2DCE5083;
							array42[0] = array42[1] ^ 0x4950E6A6;
							array42[4] = array42[1] ^ 0xC3A8ECA;
							int num129 = array43[1][2] ^ -1840325163;
							num115 = ((int)num5 * -1437357588) ^ 0x337B3164 ^ num129;
						}
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num130 = 1082694531;
				while (true)
				{
					int num3 = num130;
					uint num5;
					uint num4 = (num5 = (uint)((-(-879479374 ^ -724677538) ^ 0x627CE7D7 ^ 0xCD1DC5C) - (~(~((-(-1755145299) + 1744420509) ^ -552394730)) + (1733526128 - (2015739805 * (-114750734 ^ (-1449987957 * 239342665 - --757435119)) + -(-(-(~-115063101))))) - ~(num3 - 7452719 * -(-(-(-(1440275625 + -802413107 + -726508445) ^ 0x3FF2608B) ^ (1183817941 * (-(-2123309120 * -858771083) ^ -1611771528 ^ 0x472E7389)))))))) % 3;
					uint num131 = num4;
					int num132 = -942653890;
					_ = 0;
					for (int num133 = 0; num133 < 2; num133++)
					{
						num132 = -num132;
						num132 = (num132 ^ 0x643E693E) - -131491492;
					}
					if (num131 == (uint)num132)
					{
						break;
					}
					uint num134 = num4;
					int num135 = -1340096223;
					_ = 0;
					for (int num136 = 0; num136 < 2; num136++)
					{
						num135 = --236250669 - num135 + -113069382;
						num135 = ~(num135 * 97952941);
					}
					if (num134 != (uint)num135)
					{
						uint num137 = num4;
						int num138 = 1232093931;
						_ = 0;
						for (int num139 = 0; num139 < 1; num139++)
						{
							num138 -= 1232093931;
						}
						if (num137 == (uint)num138)
						{
						}
						return;
					}
					_003C_003Et__builder.SetResult();
					int[,] array44 = new int[4, 3];
					array44[0, 0] = 1788571773;
					array44[0, 1] = 1132441744;
					array44[0, 2] = -2096538713;
					array44[1, 0] = 396246862;
					array44[1, 1] = 191596268;
					array44[1, 2] = 16762187;
					array44[2, 0] = 570433072;
					array44[2, 1] = 912060843;
					array44[2, 2] = -157966998;
					array44[3, 0] = 1741383134;
					array44[3, 1] = -27508389;
					array44[3, 2] = 1933778246;
					array44[0, 2] = array44[0, 0] ^ 0x5DC49ED1;
					array44[1, 0] = array44[3, 0] ^ 0x23750ADB;
					array44[3, 0] = array44[3, 1] ^ 0x56435232;
					int num140 = array44[3, 0] ^ -2123459952;
					num130 = (int)((num5 * 1113751019) ^ 0x8F8DE6B2u) ^ num140;
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

		static DataPackageView @_0040_002B__0026_0040_0029_(DragEventArgs P_0)
		{
			DataPackageView dataView = default(DataPackageView);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 852639920;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(~num2 ^ -(~(-(-1770414885 * 1782281062)) + (-1009098010 ^ (-725210101 + 1366167497 - -1977883940)) + (-954382873 ^ -292094855) + (-666596984 ^ -(-(~(0x1F321781 ^ -877696373)))) - (553362867 * (1063831049 * (-909976410 ^ -934426024)) - ~(1560016251 + 1039420299 + (-1970474659 ^ -728696110) + 1745827483 + -(~(-1929800536 * 300310797)))))) * -1075433913)) % 3;
						int num5 = -4590;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = (num5 ^ 0x52E9D9BA) - -1873606879;
							num5 = -(num5 - (689458094 - 409676248));
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 2109852657;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 *= -537377431;
							num7 = ~(~num7);
						}
						if (num3 != (uint)num7)
						{
							int num9 = 16;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -num9 ^ -1075990716;
								num9 = ~(num9 ^ 0x106CFE33);
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						dataView = P_0.DataView;
						int[,] array = new int[3, 4];
						array[0, 0] = -374448077;
						array[0, 1] = -868080362;
						array[0, 2] = -709283218;
						array[0, 3] = 769885610;
						array[1, 0] = -1509642535;
						array[1, 1] = 142940554;
						array[1, 2] = 791558169;
						array[1, 3] = -1465549828;
						array[2, 0] = -973203250;
						array[2, 1] = 1396788720;
						array[2, 2] = 633612575;
						array[2, 3] = 171737396;
						array[2, 1] = array[1, 3] ^ 0x5EC516BC;
						array[0, 3] ^= -685043645;
						array[0, 0] = array[0, 1] ^ -1753009269;
						int num11 = array[0, 0] ^ 0x332BA52C;
						num = ((int)num4 * -414744507) ^ 0x537F6B8E ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return dataView;
		}

		static IAsyncOperation<IReadOnlyList<IStorageItem>> _002F__0023_0023_0028_0040_002B_005E(DataPackageView P_0)
		{
			IAsyncOperation<IReadOnlyList<IStorageItem>> storageItemsAsync = default(IAsyncOperation<IReadOnlyList<IStorageItem>>);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -96282627;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-553101671 * ~(0x41A3C2B3 ^ -834610527) + -567452437 - (((-137198635 * -(~((-(~(-605135495 * -1050884718)) ^ 0xC52DC3F) * -456611857)) - ~num2) ^ -((-(401666791 + 2132934911) ^ -1462799680) - -2115181754 - ~(-1641046856 + -924793149 + -2016044638 + (--404188268 ^ --1672603925)) - (0x7B960AF7 ^ 0x776F9AD9)) ^ ((-1819645931 ^ (--1548784150 * 691611747)) + -516035178)) - 64538945))) % 3;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 *= 1531499799;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1170291233;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 *= -108475935;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -3672314;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~(num9 ^ -530178686);
								num9 = num9 - ~1053385852 + 1514373061;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						storageItemsAsync = P_0.GetStorageItemsAsync();
						int[] array = new int[4];
						array[0] = -2100254710;
						array[1] = 1304460010;
						array[2] = 1441125049;
						array[3] = 1465742696;
						array[0] = array[2] ^ 0x60AE4D55;
						array[0] ^= 1897473861;
						int[] array2 = new int[4];
						array2[0] = 504761767;
						array2[1] = -1523683200;
						array2[2] = 602995114;
						array2[3] = -2064039646;
						array2[3] = array[3] ^ -1430958681;
						array2[0] = array2[1] ^ 0x277EA696;
						array2[0] ^= 261662189;
						array2[1] = array2[2] ^ 0x4F588782;
						int num11 = array2[3] ^ 0x1454A6C;
						num = ((int)num4 * -1358601371) ^ 0x7311A1E8 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return storageItemsAsync;
		}

		static string _002B_002F_005E_0021_002A_003F_0028_(StorageFile P_0)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				return P_0.Path;
			}
		}

		static TaskAwaiter _003F_003E_003F_0021__005E_003D_002D(Task P_0)
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
					int num = 999196610;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((~(~(~(~((num2 - (~(~(1813480469 * -(~(--1866429241)))) ^ -(0x5C7EDB55 ^ 0x13973645) ^ (576218682 - ((113293267 * -1307999256 + 973523765 * -160389899 * -1808493361 - (-(~1800279632) + (-1184893176 + 1425477243 * 1585789914))) ^ -(-(--839851627 ^ -1925083350)) ^ -1005859073)) ^ ((402190317 * ((0x3A09883B ^ -(-21821761 + 354610035) ^ (-1896007511 - (403866560 + 1761415226) + (--1949913947 + 1613858116))) + -132308661 * (1020182817 * (-1820547394 ^ -1669197933)) + (-(-(-(379369593 + 1155064770))) - ~2091114557))) ^ (68974443 * (-(~(-(-500683275 + 1577194762)) * -109405001) - -(--488834540))))) - -(-(-(~(2016505222 * -1511095725)) + (-188185845 ^ -1035022258 ^ -1704163156)) + (-66178987 - (-520453730 ^ -298742295) - -((0x4138FAB5 ^ 0x29A89D10) + (-2135657075 ^ -502664351))) + 739641534)) ^ (0x6F1D1BAE ^ ~(-(--1036369318))))) * 279103193)) ^ -1992463940) - 1561023071)) % 3;
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
						int num7 = 33;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -(num7 ^ 0x3107CB41);
							num7 = -(num7 ^ -776955409);
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1312136686;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 -= 1312136686;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						awaiter = P_0.GetAwaiter();
						int[] array = new int[4];
						array[0] = -860858478;
						array[1] = 1939305755;
						array[2] = -1459155085;
						array[3] = 1288819407;
						array[3] = array[1] ^ -865760863;
						array[1] = array[0] ^ -1804899333;
						int[] array2 = new int[4];
						array2[0] = -718137182;
						array2[1] = 1253353498;
						array2[2] = -1275009781;
						array2[3] = -77369240;
						array2[2] = array[0] ^ -343400471;
						array2[3] = array2[0] ^ -208011941;
						array2[0] ^= -71333867;
						int num11 = array2[2] ^ -656333300;
						num = (int)((num4 * 557677354) ^ 0x6135B1AC) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return awaiter;
		}
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private UserControl Root;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private Grid AssemblyDropZone;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private Border AssemblyDropSurface;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private Rectangle AssemblyDropOutline;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private bool _contentLoaded;

	public WorkspaceViewModel ViewModel { get; }

	public WorkspaceView()
	{
		while (true)
		{
			int num = -1735386846;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)((((~(-((-(-(~(~(-1267645715 * -258894120)))) + ((1766073637 * (1279093209 * -576587189 - -244884872 - ~(~(0x19C79694 ^ 0x46F19C19)))) ^ ((-2069463692 ^ -(~(-639627308 ^ 0xCC82176))) + -1911858297 * ~(~-1621301131)))) ^ ~((-1919662947 ^ 0x1B2E1FA1) + ((-(~(536939085 * -1999458770)) - (-1919428241 ^ 0x3FD5FFC7) * -94718907) ^ (530580457 - (~(1377005878 - -251611331) + 1539936589 * -169365536))))) - num2) - -1772430175 * (1807760044 + ~(199241 * 626716795) - ((179686077 - 2051821667) * -800662863 - (0x23B578C1 ^ -2061515469))) * 86915159 * 1725675623) * 1323768195 - -(~(-60943111 * (567069946 + -1988116555) - -(~-1330134643)))) ^ -306269193) - ~(0x1AD08A03 ^ -1505707270))) % 5;
				int num5 = 1895930577;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 = 1895930581 - num5;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 743570079;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 *= -102767587;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 385248218;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 -= 385248218;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -168617831;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = ~(~num11);
							num11 = num11 * -795516293 * 1307105385;
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
						_005E_003C_0026_002B_003E_0029_0026_0024((FrameworkElement)this, (object)ViewModel);
						int[] array = new int[4];
						array[0] = -1507300309;
						array[1] = -588326652;
						array[2] = -304753218;
						array[3] = -716457790;
						array[2] = array[1] ^ -1774642432;
						array[0] = array[3] ^ -669875255;
						int[] array2 = new int[7] { 2044833555, -271580653, 167883838, 69395892, 267408443, 1692249567, 1327788333 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[5] = array3[0][1] ^ -647794027;
						array2[4] ^= -1502647407;
						array2[6] ^= -811225775;
						array2[4] = array2[5] ^ -793860535;
						int num15 = array3[1][5] ^ -776571456;
						num = ((int)num4 * -769448465) ^ -1000363328 ^ num15;
					}
					else
					{
						InitializeComponent();
						int[] array4 = new int[7];
						array4[0] = 696063959;
						array4[1] = 1517598309;
						array4[2] = -1412830337;
						array4[3] = -827747576;
						array4[4] = -998928985;
						array4[5] = 1189181160;
						array4[6] = -384172641;
						array4[1] = array4[0] ^ 0x43A8B848;
						array4[5] = array4[0] ^ 0x4A74A2D6;
						array4[1] = array4[3] ^ -2011783600;
						int[] array5 = new int[4];
						array5[0] = -1717157250;
						array5[1] = -726666497;
						array5[2] = 1536338193;
						array5[3] = 2085767491;
						array5[2] = array4[0] ^ 0x168C83EE;
						array5[1] ^= 1153308368;
						array5[1] = array5[2] ^ 0x154D2301;
						array5[1] = array5[0] ^ 0x119B4CA9;
						int num16 = array5[2] ^ -849309474;
						num = ((int)num4 * -1047136862) ^ -747425572 ^ num16;
					}
				}
				else
				{
					ViewModel = AVZ_003D.TbG_003D.GetRequiredService<WorkspaceViewModel>();
					int[] array6 = new int[5];
					array6[0] = 402473748;
					array6[1] = -934206466;
					array6[2] = 655529248;
					array6[3] = -489027175;
					array6[4] = -616624244;
					array6[3] = array6[1] ^ -1292811908;
					array6[3] = array6[4] ^ -1486956500;
					int[] array7 = new int[5];
					array7[0] = 723391401;
					array7[1] = -1957008613;
					array7[2] = 1970676357;
					array7[3] = -530547750;
					array7[4] = 663902692;
					array7[0] = array6[1] ^ 0x6274F8EE;
					array7[1] = array7[0] ^ 0x565B9280;
					array7[4] = array7[0] ^ 0x6878477;
					array7[3] = array7[2] ^ -185571339;
					int num17 = array7[0] ^ 0x353DDC5D;
					num = (int)((num4 * 1048024074) ^ 0x13AF1496) ^ num17;
				}
			}
		}
	}

	private void AssemblyDropZone_DragOver(object sender, DragEventArgs e)
	{
		_003E_003F_0029_0024_003E_005E__005E(e, DataPackageOperation.Copy);
	}

	private void AssemblyDropZone_DragEnter(object sender, DragEventArgs e)
	{
		_003E_003F_0029_0024_003E_005E__005E(e, DataPackageOperation.Copy);
		while (true)
		{
			int num = -1863872726;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(((~(~-1358319391 * 415419783) + (-(0x7956A442 ^ 0x27459CCD) + ~-501233060) - ((-2087217863 ^ -357112004) - -1337003155) + (-1458796311 ^ -((-296934546 - 914648847) * 1315428007) ^ ~((0x57FCCDF3 ^ 0x11957A57) + -1782968581 - (-705353397 + -2120282587) * -317497341)) - ~(~num2) * 898235797 - (-(-1518209245 ^ -508767072) + 1778244330 + -615005309)) ^ -1294657613) * -642811425 + 1049603907 * 1842381711) * -1544221783)) % 5;
				int num5 = -1362962586;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = (-654120187 - num5) * -271228635;
					num5 = -num5;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -300975225;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 = -300975223 - num7;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1568745741;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 ^= 0x5D81290C;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -2069770477;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 -= -2069770481;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 121070830;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 ^= 0x73764ED;
							}
							if (num3 == (uint)num13)
							{
							}
							return;
						}
						_0029_0024_002B_005E_003D_003C_003E_003E((Shape)AssemblyDropOutline, 2.0);
						int[,] array = new int[4, 4];
						array[0, 0] = -1873701316;
						array[0, 1] = 917182370;
						array[0, 2] = -1510162842;
						array[0, 3] = -2099327425;
						array[1, 0] = -1269417940;
						array[1, 1] = 551167311;
						array[1, 2] = 463188603;
						array[1, 3] = -1499699752;
						array[2, 0] = -1748124300;
						array[2, 1] = -1013234841;
						array[2, 2] = 636902266;
						array[2, 3] = -2042682361;
						array[3, 0] = -2078732633;
						array[3, 1] = 1826957675;
						array[3, 2] = 1928002731;
						array[3, 3] = -1123747458;
						array[0, 1] = array[3, 3] ^ 0xBD0F3C6;
						array[1, 1] ^= -1541489861;
						array[1, 0] = array[0, 2] ^ -514009397;
						int num15 = array[1, 0] ^ 0x3237E788;
						num = (int)((num4 * 1142381917) ^ 0xA77B9AD3u) ^ num15;
					}
					else
					{
						_0024_0024_0024_0026_005E_0028_002D_003F((Shape)AssemblyDropOutline, (Brush)_003D_0028_0023_002F_005E_0029__005E(_0021_003F_003F_002B_0024_0024_005E_003F(_003F_002B_003E_005E_0026_0028_005E_0026()), (object)_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[2365 - 2110 + 49]));
						int[] array2 = new int[6];
						array2[0] = -979651426;
						array2[1] = -1824692278;
						array2[2] = -800582101;
						array2[3] = 83483654;
						array2[4] = 1811476820;
						array2[5] = -208711110;
						array2[0] = array2[4] ^ -1613858019;
						array2[4] = array2[2] ^ 0x194D9134;
						int[] array3 = new int[5];
						array3[0] = -1246360715;
						array3[1] = -967701893;
						array3[2] = 542061441;
						array3[3] = 1307285235;
						array3[4] = 333689531;
						array3[2] = array2[3] ^ -65947215;
						array3[3] = array3[0] ^ 0x719101EC;
						array3[3] = array3[4] ^ 0x6CC1BC4D;
						int num16 = array3[2] ^ -948895943;
						num = (int)((num4 * 149376304) ^ 0x7408F040) ^ num16;
					}
				}
				else
				{
					_003C_0024_0021_0026_0029_002A_005E_(AssemblyDropSurface, (Brush)_003D_0028_0023_002F_005E_0029__005E(_0021_003F_003F_002B_0024_0024_005E_003F(_003F_002B_003E_005E_0026_0028_005E_0026()), (object)_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[389 - 41 - 39 - 6]));
					int[,] array4 = new int[4, 4];
					array4[0, 0] = 420678140;
					array4[0, 1] = -1306717194;
					array4[0, 2] = -2045872935;
					array4[0, 3] = -1947861538;
					array4[1, 0] = -453504820;
					array4[1, 1] = -1695768039;
					array4[1, 2] = 590580426;
					array4[1, 3] = 865833188;
					array4[2, 0] = -456548101;
					array4[2, 1] = 1696592198;
					array4[2, 2] = -1929362047;
					array4[2, 3] = 1005380807;
					array4[3, 0] = 1675764171;
					array4[3, 1] = 1192364301;
					array4[3, 2] = 620710576;
					array4[3, 3] = -708455308;
					array4[0, 0] = array4[2, 3] ^ 0x2936DB9D;
					array4[2, 3] = array4[2, 0] ^ -900403008;
					array4[3, 3] = array4[1, 0] ^ 0x2E91DFE1;
					int num17 = array4[3, 3] ^ 0x7911540A;
					num = (int)((num4 * 384363904) ^ 0xD8E41880u) ^ num17;
				}
			}
		}
	}

	private void AssemblyDropZone_DragLeave(object sender, DragEventArgs e)
	{
		ResetDropZoneVisuals();
	}

	[AsyncStateMachine(typeof(_003CAssemblyDropZone_Drop_003Ed__7))]
	private void AssemblyDropZone_Drop(object sender, DragEventArgs e)
	{
		_003CAssemblyDropZone_Drop_003Ed__7 stateMachine = default(_003CAssemblyDropZone_Drop_003Ed__7);
		stateMachine._003C_003Et__builder = _002F_003D_0026_002A_003F_003D_0021_002A();
		while (true)
		{
			int num = -1821635111;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(-818534929 - (-(~(~(num2 * -1696300111 * 2022742287) ^ ~((457054995 * (-354384192 + -1767370647 * -658565572) - 536020104) ^ (-964064326 ^ ~(-708523633 ^ -818671124))))) ^ -1880798078) + (697890844 - -235927532)))) % 6;
				int num5 = -3;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 = -num5;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 403418281;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -(num7 * 465612603);
					num7 = ~(~num7);
				}
				if (num3 != (uint)num7)
				{
					int num9 = -74404467;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 ^= -74404471;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 570462258;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = 942422383 - (num11 - (-1332619738 ^ 0x689F0880));
							num11 = ~(num11 ^ --785233703);
						}
						if (num3 != (uint)num11)
						{
							int num13 = -1;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 = ~num13;
							}
							if (num3 != (uint)num13)
							{
								int num15 = -468779367;
								_ = 0;
								for (int num16 = 0; num16 < 2; num16++)
								{
									num15 = (num15 - -688588636) * 2045884891;
									num15 = -((-1075199655 ^ 0x1271E598) - num15);
								}
								if (num3 == (uint)num15)
								{
								}
								return;
							}
							stateMachine._003C_003Et__builder.Start(ref stateMachine);
							int[,] array = new int[4, 3];
							array[0, 0] = 1370545909;
							array[0, 1] = -1397426431;
							array[0, 2] = -1975571719;
							array[1, 0] = 1222854005;
							array[1, 1] = -141341096;
							array[1, 2] = 756185012;
							array[2, 0] = 1727799987;
							array[2, 1] = -132764565;
							array[2, 2] = 423107497;
							array[3, 0] = 579240186;
							array[3, 1] = 252157135;
							array[3, 2] = -1814304005;
							array[0, 1] = array[1, 0] ^ 0x6C2D9F4E;
							array[0, 0] = array[1, 1] ^ 0x4843617E;
							array[2, 1] = array[3, 0] ^ 0x492EB191;
							int num17 = array[2, 1] ^ -438827148;
							num = (int)((num4 * 463465876) ^ 0xF4717D78u) ^ num17;
						}
						else
						{
							stateMachine._003C_003E1__state = -1;
							int[] array2 = new int[6] { -416176016, 520217940, 331925692, -151316688, 1870206922, 1829914835 };
							array2[4] ^= -92068416;
							array2[5] = array2[0] ^ -1792085674;
							int[] array3 = new int[4];
							array3[0] = 1751949668;
							array3[1] = 577844485;
							array3[2] = -593427838;
							array3[3] = 561612078;
							array3[3] = array2[1] ^ -1504813729;
							array3[1] = array3[2] ^ -2140500656;
							array3[1] = array3[0] ^ -2005963885;
							int num18 = array3[3] ^ 0x372E9F67;
							num = (int)((num4 * 609672382) ^ 0xF66B616Cu) ^ num18;
						}
					}
					else
					{
						stateMachine.e = e;
						int[,] array4 = new int[4, 3];
						array4[0, 0] = 268372897;
						array4[0, 1] = -881092251;
						array4[0, 2] = 1085704877;
						array4[1, 0] = -1307603950;
						array4[1, 1] = -867943713;
						array4[1, 2] = 429863924;
						array4[2, 0] = 1590171697;
						array4[2, 1] = 354817050;
						array4[2, 2] = -1392320771;
						array4[3, 0] = 1639775268;
						array4[3, 1] = -385321737;
						array4[3, 2] = 1924796180;
						array4[0, 0] = array4[3, 0] ^ 0x26674F05;
						array4[2, 1] = array4[0, 0] ^ -183281653;
						array4[2, 2] = array4[3, 1] ^ 0x1473D6AD;
						int num19 = array4[2, 2] ^ 0x21E42A42;
						num = (int)((num4 * 1048505245) ^ 0x4F56AC90) ^ num19;
					}
				}
				else
				{
					stateMachine._003C_003E4__this = this;
					int[] array5 = new int[7];
					array5[0] = 660104876;
					array5[1] = -1819764814;
					array5[2] = -279879515;
					array5[3] = 2022944020;
					array5[4] = 1619550268;
					array5[5] = 1146724184;
					array5[6] = 545146710;
					array5[3] = array5[5] ^ -1841863704;
					array5[2] = array5[5] ^ -773382192;
					int[] array6 = new int[5] { -1347748234, -443673003, -262033284, -1992416176, -1603809595 };
					int[][] array7 = new int[2][] { array5, array6 };
					array6[0] = array7[0][0] ^ 0x597480DD;
					array6[2] ^= -830350920;
					array6[1] = array6[2] ^ 0x6D5B8920;
					int num20 = array7[1][0] ^ 0x5C5632E3;
					num = ((int)num4 * -115553407) ^ -839818763 ^ num20;
				}
			}
		}
	}

	private void UserControl_Loaded(object sender, RoutedEventArgs e)
	{
		ViewModel.RefreshSummary();
		ResetDropZoneVisuals();
	}

	private void ResetDropZoneVisuals()
	{
		_003C_0024_0021_0026_0029_002A_005E_(AssemblyDropSurface, (Brush)_003D_0028_0023_002F_005E_0029__005E(_0021_003F_003F_002B_0024_0024_005E_003F(_003F_002B_003E_005E_0026_0028_005E_0026()), (object)_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-464 + 158)]));
		while (true)
		{
			int num = -609455114;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(~((-(~((0x5BB4F2B6 ^ 0x43DF217E) * 446878335) - -659656140) + ~(-1667642199 + (-1659681253 ^ (~(-(--292607489) ^ (1159871133 * -1848902625)) - ~-230444409))) - num2) * 885430549 - (~(-385798619 ^ -1388046109) + (904697268 - 823928033 - (1696285202 + -1974139329) - ~(1227278834 * 781467259)) + (172917557 - ~(-206614781 ^ 0x7A155792) + 1612539531 * (1683903458 + -49548838 - (-2073751576 - -1181020093))) - 203673020 + ~-1707604230))) ^ (-(~1152349616 - (13017456 + 1718440094)) ^ 0x4D01C220))) % 4;
				int num5 = 1038737171;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 ^= 0x3DE9DF13;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 2147356159;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -(~num7);
					num7 = (num7 ^ --526279282) - -1330944142;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 2;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = num9 ^ -649758377 ^ 0x1DB5E56E;
						num9 ^= 0x4712DE7C;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -4;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 = ~num11;
						}
						if (num3 == (uint)num11)
						{
						}
						return;
					}
					_0029_0024_002B_005E_003D_003C_003E_003E((Shape)AssemblyDropOutline, 1.5);
					int[] array = new int[6];
					array[0] = -487686055;
					array[1] = 545908342;
					array[2] = -65956976;
					array[3] = 571305739;
					array[4] = -1992163180;
					array[5] = 251288413;
					array[3] = array[1] ^ 0x3E358FEC;
					array[3] ^= -654128624;
					array[0] = array[3] ^ -1689758152;
					int[] array2 = new int[6] { 1111659652, 518396625, -1666428405, -2035096691, 427730954, 1318438711 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][4] ^ 0xAED384F;
					array2[0] = array2[3] ^ 0xB6FA8E;
					array2[0] = array2[4] ^ -1244504169;
					array2[1] = array2[3] ^ 0xD73656F;
					int num13 = array3[1][4] ^ -1635067925;
					num = ((int)num4 * -1896193149) ^ 0x40730D1E ^ num13;
				}
				else
				{
					_0024_0024_0024_0026_005E_0028_002D_003F((Shape)AssemblyDropOutline, (Brush)_003D_0028_0023_002F_005E_0029__005E(_0021_003F_003F_002B_0024_0024_005E_003F(_003F_002B_003E_005E_0026_0028_005E_0026()), (object)_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x6DF8 ^ 0x6CCA]));
					int[] array4 = new int[6];
					array4[0] = 498791699;
					array4[1] = 2086345199;
					array4[2] = 427315437;
					array4[3] = 1000780547;
					array4[4] = 792642777;
					array4[5] = -2084868200;
					array4[5] = array4[3] ^ 0x7AA42ECE;
					array4[5] ^= -975929640;
					int[] array5 = new int[4] { -1927305896, -1868174015, -1336267465, 308320291 };
					int[][] array6 = new int[2][] { array4, array5 };
					array5[1] = array6[0][2] ^ -471430542;
					array5[0] = array5[1] ^ 0x323481F2;
					array5[3] = array5[2] ^ 0x51FE25B;
					int num14 = array6[1][1] ^ 0xEA7B00;
					num = ((int)num4 * -1102826449) ^ 0x7AD82183 ^ num14;
				}
			}
		}
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public void InitializeComponent()
	{
		if (_contentLoaded)
		{
			goto IL_000e;
		}
		goto IL_083a;
		IL_000e:
		int num = -120790437;
		goto IL_0013;
		IL_0013:
		Uri uri = default(Uri);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)(-((~(~(~(num2 * 1661096815))) ^ ((-(0x282BC09C ^ 0x1D7821F0) - (-532674565 * -527767290 - ((0x72B47FC1 ^ -1282262510) + -1369022290 * 1354214833))) * -463120699)) - (1509787807 * (-1455901376 - -931554961) + (0xD41A962 ^ 0x2D41A62D)) * -642378057 - (-1328738219 - ~1000204888)) * -401446343 * -1624053667)) % 6;
			int num5 = 442516312;
			_ = 0;
			for (int num6 = 0; num6 < 1; num6++)
			{
				num5 ^= 0x1A604358;
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = 407336527;
			_ = 0;
			for (int num8 = 0; num8 < 2; num8++)
			{
				num7 = ~(num7 * -65654159);
				num7 = num7 * 1967440629 + 1591123050;
			}
			if (num3 == (uint)num7)
			{
				return;
			}
			int num9 = -1995696470;
			_ = 0;
			for (int num10 = 0; num10 < 2; num10++)
			{
				num9 = ~num9 ^ 0x294B48E1;
				num9 = ~(num9 * 1323006119);
			}
			if (num3 != (uint)num9)
			{
				int num11 = -630397723;
				_ = 0;
				for (int num12 = 0; num12 < 2; num12++)
				{
					num11 = (num11 - (-1159675426 + -399493920)) * -968214359;
					num11 = (-1724305312 - num11) ^ 0xDC28660;
				}
				if (num3 != (uint)num11)
				{
					int num13 = -2088388730;
					_ = 0;
					for (int num14 = 0; num14 < 1; num14++)
					{
						num13 = -2088388728 - num13;
					}
					if (num3 != (uint)num13)
					{
						int num15 = -1024550527;
						_ = 0;
						for (int num16 = 0; num16 < 2; num16++)
						{
							num15 = num15 - (1735114582 + 818275133) + -1229302317;
							num15 = ~(~num15);
						}
						if (num3 == (uint)num15)
						{
						}
						return;
					}
					@___0026_002A_005E_002F_003D((object)this, uri, ComponentResourceLocation.Application);
					int[] array = new int[7];
					array[0] = -2044834520;
					array[1] = -349580712;
					array[2] = 484620648;
					array[3] = 1913239564;
					array[4] = 134838631;
					array[5] = -1474548078;
					array[6] = -810009750;
					array[6] = array[3] ^ -2063269452;
					array[2] ^= -1614541473;
					array[2] = array[0] ^ -510190882;
					int[] array2 = new int[4];
					array2[0] = 1068534500;
					array2[1] = 177157815;
					array2[2] = -311949133;
					array2[3] = 2082996541;
					array2[0] = array[5] ^ -1515832273;
					array2[3] = array2[1] ^ -1904931366;
					array2[3] = array2[0] ^ -1156303369;
					int num17 = array2[0] ^ -264033580;
					num = (int)((num4 * 476588936) ^ 0x61784320) ^ num17;
				}
				else
				{
					uri = new Uri(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-374 + 66)]);
					int[,] array3 = new int[3, 3];
					array3[0, 0] = -263793519;
					array3[0, 1] = -1820118871;
					array3[0, 2] = -753217678;
					array3[1, 0] = -401837046;
					array3[1, 1] = -210474469;
					array3[1, 2] = -606566335;
					array3[2, 0] = 245400129;
					array3[2, 1] = 1960864779;
					array3[2, 2] = -929552800;
					array3[0, 0] = array3[2, 1] ^ 0x47D354BE;
					array3[0, 1] ^= 722619001;
					array3[2, 2] = array3[0, 0] ^ 0x7557BCC5;
					array3[2, 2] = array3[0, 2] ^ 0x693543AC;
					int num18 = array3[2, 2] ^ -141889718;
					num = ((int)num4 * -1247101901) ^ 0x5B383347 ^ num18;
				}
				continue;
			}
			goto IL_083a;
		}
		goto IL_000e;
		IL_083a:
		_contentLoaded = true;
		num = 437605753;
		goto IL_0013;
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public void Connect(int connectionId, object target)
	{
		int num;
		uint num3;
		int num37;
		switch (connectionId)
		{
		default:
			num = 2037023206;
			goto IL_002c;
		case 4:
			AssemblyDropZone = target.As<Grid>();
			num = 1354533364;
			goto IL_002c;
		case 1:
			Root = target.As<UserControl>();
			num = -249464529;
			goto IL_002c;
		case 5:
			AssemblyDropSurface = target.As<Border>();
			num = -1308698023;
			goto IL_002c;
		case 2:
		case 3:
			_contentLoaded = true;
			num = 652345665;
			goto IL_002c;
		case 6:
			{
				AssemblyDropOutline = target.As<Rectangle>();
				num = -322067294;
				goto IL_002c;
			}
			IL_002c:
			while (true)
			{
				int num2 = num;
				uint num4;
				num3 = (num4 = (uint)(~(~(~(((0x34A8A3E0 ^ (-(233874218 - (-182174144 ^ -139988167) - (~(-345553592 + -1293832365) + -(-2140430996))) ^ ~(-2089893546))) + -1507571761 * -2014894338 + -(-(-(-1480939115 + (-1283926011 * -476001653 + -1962364793 * (1415213622 - -354294250)))) - -1456451487) - num2) ^ (-((~(-(24965765 + 941525781 + (-718514697 - 1660826285))) - -1079683947) ^ ((266838011 * -(2026407491 * -1156990287) * -487276093) ^ 0x69210E70)) - (((-393034497 * (-532754022 ^ 0x145EF204)) ^ -1833228541) + (-(-132545135 * (-420096679 + -1107967562)) + 1194129781 * ((76202912 - -1988358703) * -1260514299)) + ~(--1390258753 * -52553501 - 1115973333 - (1472315722 + 1312602763 - ~-1054186043 + (-704909124 - (0x718546B2 ^ -464441769)))) - (0x7C93A007 ^ ~((--952689849 ^ 0x5C6A82F9 ^ (0x6E2DAF9A ^ --2082334005)) - (2078765057 * -1806853952 + (-795117580 - (495136552 - 1999670940)))))))) - (-1950135167 * (-(-646768371 * 384241428) - (~-1527378830 + -581516465 * (1940416746 - -610883360))) - (-5630172 ^ -((0x5E6735B6 ^ -1624305642) - ~(~-1559638856))))) ^ 0x7E0E33BC) * -1481674103)) % 15;
				int num5 = 1434299402;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 ^= 0x557DAC07;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -96632130;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -(num7 ^ -624685296);
					num7 = -(num7 * -563231061);
				}
				if (num3 != (uint)num7)
				{
					int num9 = -13;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 = ~num9;
					}
					if (num3 == (uint)num9)
					{
						goto case 1;
					}
					int num11 = -1250793532;
					_ = 0;
					for (int num12 = 0; num12 < 2; num12++)
					{
						num11 = num11 * -996618023 * -4612183;
						num11 = num11 - ~-1310085042 + 1559495028;
					}
					if (num3 != (uint)num11)
					{
						int num13 = -2113992918;
						_ = 0;
						for (int num14 = 0; num14 < 1; num14++)
						{
							num13 ^= -2113992916;
						}
						if (num3 != (uint)num13)
						{
							int num15 = -1838293055;
							_ = 0;
							for (int num16 = 0; num16 < 2; num16++)
							{
								num15 = ~num15;
								num15 = (num15 + -1426436918) * -207225627;
							}
							if (num3 == (uint)num15)
							{
								goto case 4;
							}
							int num17 = 541106339;
							_ = 0;
							for (int num18 = 0; num18 < 2; num18++)
							{
								num17 = ~(-num17);
								num17 = ~num17 * -402401675;
							}
							if (num3 != (uint)num17)
							{
								int num19 = -444209397;
								_ = 0;
								for (int num20 = 0; num20 < 2; num20++)
								{
									num19 = -num19;
									num19 = -num19 - 1925378949;
								}
								if (num3 != (uint)num19)
								{
									int num21 = -8;
									_ = 0;
									for (int num22 = 0; num22 < 1; num22++)
									{
										num21 = ~num21;
									}
									if (num3 != (uint)num21)
									{
										int num23 = 2136259304;
										_ = 0;
										for (int num24 = 0; num24 < 1; num24++)
										{
											num23 ^= 0x7F54BAE0;
										}
										if (num3 != (uint)num23)
										{
											int num25 = -10;
											_ = 0;
											for (int num26 = 0; num26 < 1; num26++)
											{
												num25 = ~num25;
											}
											if (num3 != (uint)num25)
											{
												int num27 = -1933835528;
												_ = 0;
												for (int num28 = 0; num28 < 2; num28++)
												{
													num27 = -(~num27);
													num27 = ~num27 * 319242197;
												}
												if (num3 == (uint)num27)
												{
													int[] array = new int[5];
													array[0] = -903681414;
													array[1] = -1745846971;
													array[2] = 227742499;
													array[3] = -157582355;
													array[4] = -902243160;
													array[0] = array[2] ^ 0x452D4AA;
													array[2] = array[1] ^ -1730408133;
													int[] array2 = new int[4];
													array2[0] = 1905037017;
													array2[1] = 1712584403;
													array2[2] = 1892279275;
													array2[3] = -1235926867;
													array2[2] = array[4] ^ 0x69DB9B47;
													array2[1] ^= 262637471;
													array2[0] = array2[2] ^ 0x40FBC72D;
													array2[1] = array2[2] ^ 0x68DB9C73;
													int num29 = array2[2] ^ 0x4F2EE34D;
													num = (int)((num4 * 1824230463) ^ 0xC7185176u) ^ num29;
													continue;
												}
												goto IL_071d;
											}
											goto case 5;
										}
										int[] array3 = new int[4];
										array3[0] = 1068860176;
										array3[1] = 1627242973;
										array3[2] = -1417914327;
										array3[3] = 273427834;
										array3[0] = array3[2] ^ 0x7F833C1C;
										array3[2] = array3[3] ^ 0x65F0473A;
										array3[1] = array3[3] ^ 0x31A4E510;
										int[] array4 = new int[5] { 1899959689, -1279637178, -1449911751, -57467428, 2138752257 };
										int[][] array5 = new int[2][] { array3, array4 };
										array4[1] = array5[0][3] ^ -1665258211;
										array4[2] = array4[1] ^ 0x48A2DBBB;
										array4[3] = array4[2] ^ 0x467D15F4;
										int num30 = array5[1][1] ^ 0x603FA4C5;
										num = (int)((num4 * 1450824834) ^ 0x3140B608) ^ num30;
										continue;
									}
									_0023_002F_0040_002A_0026_002B_0024_0025((UIElement)AssemblyDropZone, (DragEventHandler)AssemblyDropZone_Drop);
									int[] array6 = new int[4] { -1790268514, 1738631638, -784910919, 2017186430 };
									array6[0] ^= -1675588601;
									array6[1] = array6[3] ^ -961523893;
									int[] array7 = new int[4] { 278005673, -674320384, -632302806, -1915077177 };
									int[][] array8 = new int[2][] { array6, array7 };
									array7[3] = array8[0][2] ^ 0x4509E6C4;
									array7[1] ^= 420808743;
									array7[1] = array7[2] ^ -1020900256;
									array7[1] = array7[3] ^ 0x7368654D;
									int num31 = array8[1][3] ^ -514584970;
									num = (int)((num4 * 1222228822) ^ 0x78273ABC) ^ num31;
									continue;
								}
								_005E_003E_005E_003C_002F_005E_0029_002B((UIElement)AssemblyDropZone, (DragEventHandler)AssemblyDropZone_DragOver);
								int[] array9 = new int[7];
								array9[0] = 899641066;
								array9[1] = 1413419607;
								array9[2] = -1177269219;
								array9[3] = -967303671;
								array9[4] = 1329221485;
								array9[5] = 1884471527;
								array9[6] = -2135550890;
								array9[6] = array9[0] ^ -888409814;
								array9[2] = array9[4] ^ -1727970720;
								array9[6] = array9[5] ^ 0x2A791084;
								int[] array10 = new int[7] { 91464777, 356472227, 1867044224, -845023777, -395842915, 1006493660, 218971009 };
								int[][] array11 = new int[2][] { array9, array10 };
								array10[0] = array11[0][3] ^ 0x751778DC;
								array10[3] = array10[1] ^ -823205372;
								array10[4] = array10[2] ^ -893102676;
								array10[3] = array10[6] ^ 0x174B7DDB;
								int num32 = array11[1][0] ^ -1551018756;
								num = ((int)num4 * -1022679519) ^ 0xE885553 ^ num32;
								continue;
							}
							_003E_005E_002A_005E_005E_002B_002D_0021((UIElement)AssemblyDropZone, (DragEventHandler)AssemblyDropZone_DragEnter);
							_0025_005E_0029_003F_0040_002B_003C_((UIElement)AssemblyDropZone, (DragEventHandler)AssemblyDropZone_DragLeave);
							int[,] array12 = new int[3, 4];
							array12[0, 0] = 515342002;
							array12[0, 1] = 1212348219;
							array12[0, 2] = 1272684071;
							array12[0, 3] = 48976885;
							array12[1, 0] = -1483874476;
							array12[1, 1] = -1732057906;
							array12[1, 2] = -1423740226;
							array12[1, 3] = -221108428;
							array12[2, 0] = 1289659944;
							array12[2, 1] = -935850021;
							array12[2, 2] = 1118173522;
							array12[2, 3] = -1650289816;
							array12[0, 1] = array12[2, 1] ^ 0x43287594;
							array12[0, 1] = array12[1, 3] ^ -1790985607;
							array12[2, 3] = array12[0, 2] ^ 0x37B2BD33;
							int num33 = array12[2, 3] ^ 0x37CC63EE;
							num = (int)((num4 * 652003725) ^ 0xC8111AA1u) ^ num33;
							continue;
						}
						int[] array13 = new int[7];
						array13[0] = 1128576737;
						array13[1] = -204594984;
						array13[2] = -1662218915;
						array13[3] = 64166113;
						array13[4] = -351997549;
						array13[5] = 1686278894;
						array13[6] = -1283021804;
						array13[3] = array13[4] ^ -726628152;
						array13[6] = array13[4] ^ -2104701139;
						int[] array14 = new int[7] { -1506967467, 157576662, -942123398, -1949001659, -1877896698, 362352908, 197383023 };
						int[][] array15 = new int[2][] { array13, array14 };
						array14[3] = array15[0][2] ^ 0x5D779506;
						array14[0] = array14[6] ^ -655708393;
						array14[2] = array14[0] ^ 0x1F0C7AE8;
						int num34 = array15[1][3] ^ 0x2D56BCF9;
						num = (int)((num4 * 1882045673) ^ 0x2E7DF912) ^ num34;
						continue;
					}
					_002F_005E_002A_0025_003F_002D_002B_005E((FrameworkElement)Root, (RoutedEventHandler)UserControl_Loaded);
					int[,] array16 = new int[4, 3]
					{
						{ -1381550721, -1885046088, -1487742560 },
						{ 611097446, 1474655172, 664827846 },
						{ 1036576364, -397328706, 1582698787 },
						{ 114633987, -1921628958, 292798541 }
					};
					array16[3, 1] ^= 2020813134;
					array16[1, 1] = array16[2, 2] ^ 0x7559596C;
					array16[0, 1] = array16[1, 0] ^ 0x6D4F8D32;
					int num35 = array16[0, 1] ^ 0xEC480B5;
					num = (int)((num4 * 1458574862) ^ 0x83405480u) ^ num35;
					continue;
				}
				int[] array17 = new int[5];
				array17[0] = -1964316151;
				array17[1] = -997271849;
				array17[2] = 768828501;
				array17[3] = 1520927590;
				array17[4] = -380317096;
				array17[1] = array17[4] ^ -2127615772;
				array17[3] = array17[0] ^ -381319217;
				int[] array18 = new int[7] { 1551007253, -1509546062, -486874748, -874805434, -1065458584, -799266416, -882621937 };
				int[][] array19 = new int[2][] { array17, array18 };
				array18[6] = array19[0][0] ^ -2019295686;
				array18[0] = array18[4] ^ -1841616339;
				array18[2] ^= 1578869665;
				array18[5] = array18[3] ^ 0x617EC818;
				int num36 = array19[1][6] ^ -511397743;
				num = (int)((num4 * 2025671222) ^ 0x22894C7A) ^ num36;
			}
			goto default;
			IL_071d:
			num37 = -1553173452;
			_ = 0;
			for (int num38 = 0; num38 < 2; num38++)
			{
				num37 = (num37 - (-130704875 + 1541297210)) * -994660941;
				num37 = (num37 + 486811445) ^ 0x210C2758;
			}
			if (num3 != (uint)num37)
			{
				int num39 = -493604859;
				_ = 0;
				for (int num40 = 0; num40 < 1; num40++)
				{
					num39 += 493604861;
				}
				if (num3 != (uint)num39)
				{
					int num41 = -1603166135;
					_ = 0;
					for (int num42 = 0; num42 < 2; num42++)
					{
						num41 = 650874057 - (num41 ^ -458881886);
						num41 = (num41 ^ 0x16018144) * 750054827;
					}
					if (num3 == (uint)num41)
					{
					}
					break;
				}
				goto case 2;
			}
			goto case 6;
		}
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public IComponentConnector GetBindingConnector(int connectionId, object target)
	{
		return null;
	}

	static void _005E_003C_0026_002B_003E_0029_0026_0024(FrameworkElement P_0, object P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 758853214;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((-(-(~((1003411965 - -216940643) * 1819974979))) - (-(570652899 * (-2036708419 * (-639197548 ^ 0x3FB3385A) * 811898705)) + (-(0x2687BF8B ^ 0x7ED61447) + -(~(-653237440 * 38211087))) * -1027726191 - (-(~(1518751145 * -262856746 - 1225662310)) - 323730963 * (~1802308277 + 523221401) - ~(--783871946))) * 1800448269 - num2 - -1183831075 * (((-286831480 - ~1341816969 + -1304736146 + 1795519783 * ~-922870761 + (~(-(-66398323 ^ 0x4B0DE457)) ^ -1569776588)) ^ 0x7B54A1AB) + ((~(-(0x536722F4 ^ -1410678655) ^ 0x1DB7DA9A) ^ (-1910253334 - -252737511 * (232750367 - -684431892))) + (-1599434485 * -(-1565340796 - -1020163607 * -1402372920) + 2063096557))) + ~-1258093404) ^ 0x647D6AD8) * -1827828899 * 1629819871 * 589409281 + (0x6C1A0C6A ^ 0x5595F019) + -69519868)) % 3;
					int num5 = 1111622817;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 += -1111622817;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 268715082;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 + 334369934;
						num7 = -num7 ^ -146993766;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1397091529;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= 2125075079;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.DataContext = P_1;
					int[] array = new int[4] { -2091554868, 289380886, -212289218, -548158852 };
					array[3] ^= -1487701152;
					array[0] ^= -250805289;
					int[] array2 = new int[4] { 463625213, 1550576569, -1951003351, -1521297419 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][2] ^ 0x3B5F3BC6;
					array2[3] ^= 50286014;
					array2[3] = array2[0] ^ -710392698;
					array2[0] = array2[3] ^ -1589037680;
					int num11 = array3[1][2] ^ -1815750191;
					num = (int)((num4 * 200694869) ^ 0xCCEE31C7u) ^ num11;
				}
			}
		}
	}

	static void _003E_003F_0029_0024_003E_005E__005E(DragEventArgs P_0, DataPackageOperation P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 106676445;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(-(~num2) * 657119385) ^ -(-604207726 + (-1115740146 - ~-496152674 * -1947181407))) - 1146647578 - 1055252899)) % 3;
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
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7;
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9;
							num9 = num9 - 214442930 * -557388979 - 2042420368;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.AcceptedOperation = P_1;
					int[] array = new int[5] { -2040451781, 2100318719, -432314572, -988720923, -1876311539 };
					array[2] ^= 1372530784;
					array[4] = array[0] ^ 0x328225B2;
					array[1] = array[0] ^ -129924698;
					int[] array2 = new int[7] { 1615367403, -1409071858, -5468597, -1982337917, 797576302, 1282703657, 1641415407 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[6] = array3[0][3] ^ -954400200;
					array2[5] = array2[3] ^ 0x6A5EB7FF;
					array2[1] = array2[3] ^ -988342705;
					int num11 = array3[1][6] ^ -1190127961;
					num = (int)((num4 * 1285365051) ^ 0x8E5E4181u) ^ num11;
				}
			}
		}
	}

	static Application _003F_002B_003E_005E_0026_0028_005E_0026()
	{
		Application current = default(Application);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1607530553;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-((~(~((~num2 ^ ~(-(((~-1375500671 - (1745714960 - 570104447) + -(-1992264535)) * 777995313) ^ (-(-349418449 - 571972281) ^ -1881542904 ^ 0x122CC8BA) ^ ((0x6BE62AC2 ^ 0x172B658D) - (0x164F1D9A ^ -(-542473186)))))) * 1625981863)) ^ (0x34C19CEB ^ -(-(-343725099)))) - 216968963 * (-1441455863 - 681567617) * -596759741 - (1197546997 + -849726999 - 2053917615 * -184162656))))) % 3;
					int num5 = -71578876;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -num5;
						num5 = (num5 ^ 0x6E62E81) + -1960600970;
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
						int num9 = 1520934986;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x5AA7A04A;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					current = Application.Current;
					int[,] array = new int[4, 3];
					array[0, 0] = -1084605235;
					array[0, 1] = -539665971;
					array[0, 2] = 726738619;
					array[1, 0] = 1543445972;
					array[1, 1] = 1457049037;
					array[1, 2] = 2076594524;
					array[2, 0] = -13624089;
					array[2, 1] = 997351111;
					array[2, 2] = -11138881;
					array[3, 0] = -189161196;
					array[3, 1] = 275064795;
					array[3, 2] = 168084092;
					array[3, 1] = array[2, 2] ^ -1623722725;
					array[2, 1] = array[0, 2] ^ 0x4E3D55CE;
					array[3, 2] = array[2, 2] ^ -1863452192;
					int num11 = array[3, 2] ^ 0x4A8BDD1E;
					num = (int)((num4 * 2128572293) ^ 0xB6BD88DDu) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return current;
	}

	static ResourceDictionary _0021_003F_003F_002B_0024_0024_005E_003F(Application P_0)
	{
		ResourceDictionary resources = default(ResourceDictionary);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -667778655;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((((((num2 ^ ((-(-(-649354060 + -1283417957 * -1804568799) - (-596346455 ^ -490707457) + (~(-(642663191 + -1783677062)) - -(~(1503061938 + -1608786110)))) - -1532261867 * 369076355) * -519284865 * -737669331)) + (((~(-1852553305 ^ ~(--2051561883)) * 1709644807) ^ (-35426967 ^ -(~(-1417319504 ^ 0x3E1F796F)) ^ ~(308240636 + 1717091369 + (-215710908 + 1478130693) + -(703091835 * 770748998)))) + (-573556395 * ~1576382647 - ((-1233081860 ^ 0xDA19949) + -203706018)) - (-1483540145 ^ -(~(-(0x38827A5 ^ -1389287259) * 1208537211) ^ -(-(~815893981) - (-458926476 * 1050251781 - --2015591370)))))) * -230406485 - (((-(-1489897893 ^ -987987465) + (~-711665093 + -1942452114 + ~(0x78ACB65B ^ -634463413))) ^ (-(~1164950253 - 1254407954) + 176973108)) - 1676376421)) * 1539967895 - ((~(--1725459407) - (0x1E42DC6D ^ -2058985480)) ^ 0x65A315F1) + (-1239299965 ^ -1223800261)) ^ 0x48218D5) - (-850831938 - -1052853857)))) % 3;
					int num5 = 841550115;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 841550115;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1827309478;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 - ~977380847) * -1445839131;
						num7 = (num7 - ~1758161267) ^ 0x7B402A18;
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
					resources = P_0.Resources;
					int[] array = new int[5];
					array[0] = 1074680186;
					array[1] = -1142889412;
					array[2] = 1097379609;
					array[3] = -1968404857;
					array[4] = -117432634;
					array[3] = array[4] ^ 0x2F2A93FA;
					array[2] = array[0] ^ -1030003685;
					array[2] = array[4] ^ -1124142126;
					int[] array2 = new int[7];
					array2[0] = -797798459;
					array2[1] = -2136296179;
					array2[2] = 792257706;
					array2[3] = -633004751;
					array2[4] = -22184479;
					array2[5] = 1762331470;
					array2[6] = 186330030;
					array2[4] = array[1] ^ 0x1109EDF7;
					array2[0] = array2[4] ^ 0x6526709B;
					array2[0] = array2[6] ^ -486287889;
					int num11 = array2[4] ^ 0x16F7AD5;
					num = ((int)num4 * -261131314) ^ 0x243856D6 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return resources;
	}

	static object _003D_0028_0023_002F_005E_0029__005E(ResourceDictionary P_0, object P_1)
	{
		object result = default(object);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1063187112;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((num2 - ((-1545754045 * -(--764028794) - ~(-1606834305 * ((-938836907 ^ (0x1ADA6D7F ^ ~(-980257238))) - ((-1701588389 ^ 0x502F0282) * -556012671 - ((-1428646219 + (-183194058 + -977063333)) ^ -1019690610))))) ^ ~(1572985747 * ((-(--1370198368 - (0x61D5500A ^ 0x360F2AF1)) + (-(-2073061002 - 1966473308) - (1940020445 + 349669291 - (601471199 - 1538548799)))) * 1802682605) + -1435464953 * ((-1382083122 ^ (-28700514 - (0x69A498AD ^ -1207231069))) + ((0x7EDC4404 ^ 0x529299F3) + (0x25558160 ^ -995485421)) + (~(~-2101789636) + ((0x79F4FF33 ^ -739436786) + -2117555408)) * 981212479)))) * -1939881541 * -527654901 - (-(-442323095 ^ -438829710) + -467270906))) % 3;
					int num5 = 419409406;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 ^ 0x737A0BA6) - 2049978187;
						num5 = (num5 ^ 0x7C112EC0) + -166037042;
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
						int num9 = 2110538798;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= -883477081;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0[P_1];
					int[] array = new int[4];
					array[0] = 493972821;
					array[1] = 859901675;
					array[2] = 684550365;
					array[3] = -480842040;
					array[0] = array[1] ^ -536032617;
					array[2] = array[3] ^ 0xB11AF53;
					array[0] ^= -1229794010;
					int[] array2 = new int[7] { -446376721, 340064092, -1778042810, -65203591, -647807349, -1796012545, -1381539366 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][1] ^ 0x49A5D710;
					array2[5] = array2[6] ^ 0x38BE48D4;
					array2[5] = array2[0] ^ 0x24CA1131;
					int num11 = array3[1][2] ^ -476540831;
					num = ((int)num4 * -754337249) ^ 0x66D16975 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _003C_0024_0021_0026_0029_002A_005E_(Border P_0, Brush P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			P_0.Background = P_1;
		}
	}

	static void _0024_0024_0024_0026_005E_0028_002D_003F(Shape P_0, Brush P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1977519197;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((-(~(-1324851403 * (1601510451 * (309719673 * (-119694239 ^ -606237552))) + ~(-(1464340876 * -368328979) ^ (-656374819 + 1413101883) ^ -48490576)) + ~(0x329EF839 ^ 0x1D86524A) + ~(-1192436976 - --1877022686 - (1474345611 - -1993419559 - ~2080433503) - ~(2110603419 * 952505953 + 1727557827 * -1538835179) - (47898659 + 1515443438) - (203667581 * (-1782531839 + ~(-650146861 - -746379425)) + (1194058653 * (-956935445 + (-1560322675 - 1364778073)) + 664122388)) - -1757995223 * -(-(-230540058 ^ -1515981672))) - num2 - ((985148299 * (885404329 * (-122159077 * 1450940756) - ~-1858152004 - 80196408 + (-509503480 ^ 0x97C37F6))) ^ -1685316630 ^ (-(-(2024710841 * (~(1461803497 * -65911719) + (--1968674643 + (0x795D614B ^ 0x5D432174))))) ^ ~(-(1053152851 + --1725338405) + (-(--1077805673) ^ 0x4ACDC4A8) - ((-(922132425 + -575359068) - -1229763540) ^ ((-496267905 ^ 0x46B4969A) - --56914991 + -1986575321)))))) - ~((-1377856057 ^ (-1285392986 - (733130552 - 627257082) + (0x592DAD0F ^ 0x1D303E79))) - -1495135180)) ^ 0x41A74779))) % 3;
					int num5 = 1895501098;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0x70FB0D2A;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 210326785;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 481274625;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1840132804;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 1840132802;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Stroke = P_1;
					int[] array = new int[5];
					array[0] = -326338758;
					array[1] = -58097640;
					array[2] = 343067724;
					array[3] = -1512160096;
					array[4] = 872946198;
					array[2] = array[4] ^ -2044563218;
					array[2] ^= -52275962;
					int[] array2 = new int[5] { -1934432696, -132182008, -175038770, 1836393399, 1460702238 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][4] ^ 0xD82D66C;
					array2[1] = array2[4] ^ -2069333038;
					array2[2] = array2[0] ^ 0x24581494;
					array2[4] = array2[1] ^ -885233584;
					int num11 = array3[1][0] ^ -1394141740;
					num = (int)((num4 * 773473777) ^ 0x5A062580) ^ num11;
				}
			}
		}
	}

	static void _0029_0024_002B_005E_003D_003C_003E_003E(Shape P_0, double P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 2006919158;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-538409617 - -(~(~((672026217 * (950989473 * ((~1205732893 - (510386721 - 1057714802 - -1341662065)) * -414793521)) - ((num2 + ~(-((-1161327595 + -(~1258950221 - (0x7B46F42D ^ -1769840492)) - 1095472728) ^ ((~1639141342 + -(~(-514266777 ^ -1363587940) * -448368749)) ^ ((0x10B64FE9 ^ ((-321786588 ^ -347575681) + (-553338102 ^ 0x964F88E))) - -85313555))))) * 106422907 - (~((-1079343754 ^ 0xFB7D375) - (-126978806 * -1904491573 + (-237452807 + 1228434027))) * 523513769 - (1829710327 + 164389369 - ~(--729843159 * -313733743 + ~-452075682))) * -1072740593)) * -898830407)) ^ -26900290))) % 3;
					int num5 = 688362538;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = --1582795021 - num5 + 907813029;
						num5 ^= 0x57EBCA1D;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -564640121;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -760373449;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -119697918;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(-1604859555 * -1747196055 - num9);
							num9 = (num9 - (2084320919 - 823678908)) * -743316609;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.StrokeThickness = P_1;
					int[,] array = new int[4, 4];
					array[0, 0] = -494062958;
					array[0, 1] = 1721105003;
					array[0, 2] = -663258493;
					array[0, 3] = 2116728279;
					array[1, 0] = -1071753414;
					array[1, 1] = -929036070;
					array[1, 2] = 1679257615;
					array[1, 3] = 1634210433;
					array[2, 0] = 88486890;
					array[2, 1] = -86325582;
					array[2, 2] = -1772780239;
					array[2, 3] = -1558436321;
					array[3, 0] = -1912780146;
					array[3, 1] = -988755446;
					array[3, 2] = 1980455916;
					array[3, 3] = 986815764;
					array[0, 0] = array[2, 2] ^ -2134760504;
					array[3, 0] = array[1, 1] ^ -280278870;
					array[1, 3] = array[0, 0] ^ 0xF56C915;
					array[0, 0] = array[1, 1] ^ -854046396;
					int num11 = array[0, 0] ^ -977013560;
					num = (int)((num4 * 1170323771) ^ 0xCD3D731) ^ num11;
				}
			}
		}
	}

	static AsyncVoidMethodBuilder _002F_003D_0026_002A_003F_003D_0021_002A()
	{
		AsyncVoidMethodBuilder result = default(AsyncVoidMethodBuilder);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1569272523;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(~(-(-((834412261 * ((((-1314912110 ^ -1870004068) - ~1086998731 + -(-596120367)) * 2128831293) ^ -1201577421)) ^ -647448123) + ((~(-515282597 * (0x4E068BC4 ^ 0x744EBA92) * -1993326967 + ~(~(1565509680 + -564747769)) + 2113751169 * (1034439001 - (-2031916868 + 1517768069) + (~1296701765 - -1107652528))) ^ 0x3A7A69C1) - (-389312944 + (-89104289 ^ -1766563948) - (0x1774B55D ^ (~(-(-481700110)) ^ (-(--1846820064) * -539009265))) - (-(-1317330204 ^ -(319034616 + -1249429980)) ^ (-2085611295 ^ ~(-(-313231045))) ^ (((0x77F08CEA ^ -1139361311) + (1665160936 + -875261435 + --1223575171)) * 318278573 + ~(-889854151 + 1967798073 + -211867613 - (--1653079795 ^ 0x5988ACBF)))))) - num2 - ~(~(-1945801354 + ((-268318071 * -((-843631662 ^ -288438500) * 642413481)) ^ -592713313)))) ^ (-644736591 * (506332305 + 1794370767 + (-576491547 ^ 0x42928201)) * -497178623 + --521008721 + -(1397680837 * 105586240))) - (423913317 + ~85580637 * -1074759941) - 1773666419 * (0x4007ED34 ^ -1807760117) - (1173698684 - 274172814 - (-3904515 + -153702809)))))) % 3;
					int num5 = 1484028052;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -num5;
						num5 = 1089565188 - (num5 - (112925871 - -202978564));
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7 + -1119094361;
						num7 = ~(-num7);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 445458628;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x1A8D28C4;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = AsyncVoidMethodBuilder.Create();
					int[,] array = new int[4, 3];
					array[0, 0] = 739233630;
					array[0, 1] = 2033651358;
					array[0, 2] = 270016061;
					array[1, 0] = 957616536;
					array[1, 1] = 1898985210;
					array[1, 2] = -1544716393;
					array[2, 0] = 401204343;
					array[2, 1] = -294315644;
					array[2, 2] = 552751623;
					array[3, 0] = -1160215052;
					array[3, 1] = 1845559980;
					array[3, 2] = 138295931;
					array[3, 0] = array[2, 2] ^ -1030660623;
					array[1, 0] ^= -1636304349;
					array[3, 0] = array[2, 0] ^ -539032057;
					int num11 = array[3, 0] ^ 0x43A662FE;
					num = (int)((num4 * 465460481) ^ 0x722441ED) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void @___0026_002A_005E_002F_003D(object P_0, Uri P_1, ComponentResourceLocation P_2)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 449079763;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~num2 ^ -(-(-(879571368 + ~(-(-(135135369 * -1258473369))))))) ^ (1090002262 + ~(((-1705608636 ^ -1592004699) + ~1703872525) * 568634631 - -(-1914837743 ^ 0x1B76D237))))) % 3;
					int num5 = -320931530;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 += 320931532;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1187783171;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -215876332 - -num7;
						num7 = 1777300290 - (num7 ^ -278439611);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 384932816;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 - (-1191339083 ^ -903673498));
							num9 *= -1714593303;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					Application.LoadComponent(P_0, P_1, P_2);
					int[] array = new int[6];
					array[0] = -697525926;
					array[1] = -1736070636;
					array[2] = -538947341;
					array[3] = -1510047641;
					array[4] = -1774112256;
					array[5] = 796876662;
					array[3] = array[1] ^ 0x57160ECF;
					array[4] = array[0] ^ 0xCCC3BE7;
					int[] array2 = new int[5];
					array2[0] = -1300926373;
					array2[1] = 92482473;
					array2[2] = -1359229593;
					array2[3] = -921722740;
					array2[4] = -486894094;
					array2[4] = array[5] ^ -398682138;
					array2[3] ^= -442541354;
					array2[1] = array2[2] ^ -905277797;
					array2[1] = array2[4] ^ 0x11678E64;
					int num11 = array2[4] ^ -1575165485;
					num = (int)((num4 * 312906857) ^ 0xE5E55336u) ^ num11;
				}
			}
		}
	}

	static void _002F_005E_002A_0025_003F_002D_002B_005E(FrameworkElement P_0, RoutedEventHandler P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1551602321;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(1479999819 - -((((~(-(1012698853 * ((-1674206484 + (0x2436473E ^ 0x177BAE01)) * 306943123) * -72956629 * 209737159) - -num2) ^ 0x566BE59D ^ -1068724065) * -144677719) ^ 0x5587E2F0) * -2093733297))) % 3;
					int num5 = 4;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -num5 ^ -430325036;
						num5 = ~num5 ^ -1477164992;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -83886587;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(num7 - (-643884493 ^ 0x685A1BE6));
						num7 = 1946379892 - (num7 ^ 0x4D5E66ED);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1964933846;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ --872151574) * -1987767399;
							num9 = ~(-num9);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Loaded += P_1;
					int[,] array = new int[4, 4]
					{
						{ -2116916163, 518240312, -1743470049, -1913605047 },
						{ -1256981638, 1587896091, -1713088533, 2075374428 },
						{ -1115639791, 277584547, 2100716403, -1817650749 },
						{ 1578650560, -996449773, 850173985, -2039193237 }
					};
					array[1, 3] ^= 1998231641;
					array[0, 3] = array[1, 1] ^ 0x76193E61;
					array[3, 3] = array[1, 3] ^ 0x5DF20B76;
					array[1, 1] = array[3, 0] ^ -1650675113;
					int num11 = array[1, 1] ^ 0x3CF0C8A6;
					num = (int)((num4 * 912997148) ^ 0x5C18C40) ^ num11;
				}
			}
		}
	}

	static void _003E_005E_002A_005E_005E_002B_002D_0021(UIElement P_0, DragEventHandler P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 2122350944;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~-1928905231 - ~(~((((-((-1872839338 ^ 0x7C6508A1) - (-173339937 * ~-1692468473 - -1724741481 * 2028091875) + -1272506718) ^ (-1099825431 ^ (-1163819870 ^ ~(~(-2130976564 - ~-1328273107))))) - (-391137937 * 1103310073 + (~(((-1661279766 ^ -1398668317) + (-1044999560 - -1156745426)) * 1545836945) - (156730671 + -1095110761) - 1822104617 * (0x60126818 ^ -1591254018))) - ~num2 + (~(~795467925 + (~-978587534 + ~1179786502)) + (0x3C3E048E ^ -963078235) + -(~-730473398)) * 197258175) * -589419273 - (-(((-2050269521 ^ 0xB360E2) - ~1185079237) * -1824228481) - -262854854)) ^ -((-1609760799 ^ -59659502) - -722381679 * (-603253609 - -1016623021))))))) % 3;
					int num5 = 125894144;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 ^ 0x54C58905);
						num5 = num5 - -1461257318 + -1527869478;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -16728191;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 ^ 0x3081E658) + 1037721573;
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1233213698;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 * -1780908393 * -1049744451;
							num9 = (num9 ^ -888340215) - -1697743043;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.DragEnter += P_1;
					int[] array = new int[4];
					array[0] = -989961198;
					array[1] = 525956865;
					array[2] = -1353130154;
					array[3] = 515273647;
					array[2] = array[1] ^ -2016892538;
					array[1] = array[2] ^ 0xAD8F3A;
					int[] array2 = new int[7] { -2019574245, -609397814, -1006532182, -1270136081, -219495733, -1653018547, -567649504 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][0] ^ -474738305;
					array2[6] = array2[0] ^ 0x4C95DF94;
					array2[0] = array2[6] ^ 0x607D5A9F;
					array2[3] = array2[4] ^ 0x475D81F;
					int num11 = array3[1][1] ^ 0x423A321A;
					num = (int)((num4 * 1627152405) ^ 0x4016FFC8) ^ num11;
				}
			}
		}
	}

	static void _0025_005E_0029_003F_0040_002B_003C_(UIElement P_0, DragEventHandler P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1947803360;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-1057936479 + 1987351026 - -(--946680072 - ~((~(-1993922102 + (~(162787227 * 2136654595) + -((-1629021810 ^ -873122957) * 387053693 + (-1420690248 + 207730091 + -93877537 * 1803152190)))) ^ (-875557979 * (-538535954 ^ ((-2072861986 + (-639683995 * -729681462 - -1088930799)) ^ ~(~(--1248730982)))) - ~912601173)) - (num2 - ~((-((0x486CDC72 ^ 0x6633112C) * 12508909) ^ 0xB2574E1) * -1808269021)) + -1373256617 * ~(-(-198644353 - --166829035 - ((-1665180644 ^ 0x7C780DC6) + -487057052 * 927676595) - -1684489245 * 617837525)))) * -1679793777 * -960643981) * 1214687645)) % 3;
					int num5 = -1352156720;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(~num5);
						num5 = ~num5 * 655014745;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2122746835;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x7E868BD1;
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
					P_0.DragLeave += P_1;
					int[] array = new int[4];
					array[0] = 139585083;
					array[1] = 1622607842;
					array[2] = 1385746731;
					array[3] = -1888829346;
					array[0] = array[2] ^ 0x7E1D3E85;
					array[0] ^= -911696824;
					int[] array2 = new int[5] { 694736468, 1864900113, -1302785306, 1001255483, 111239212 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][1] ^ -874566994;
					array2[4] = array2[2] ^ 0x1D1CDACB;
					array2[0] = array2[3] ^ -1972373554;
					array2[0] = array2[2] ^ 0x21607A2E;
					int num11 = array3[1][1] ^ -409921149;
					num = ((int)num4 * -1381978755) ^ 0x75B96F74 ^ num11;
				}
			}
		}
	}

	static void _005E_003E_005E_003C_002F_005E_0029_002B(UIElement P_0, DragEventHandler P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -511935165;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(-(~(~(num2 ^ (-(~(-944852117 * (-(-537010256 ^ 0x1F8554FC) + -(--277610576) - ((-754590946 - -376250037) * -97293803 - 217260007))) - ~(1076462907 - 1249674665)) - ((-((--801639623 ^ 0x4392ECB6) - -(-(-1513755447 - -667343903))) * -1298715359 + 564765468) ^ (-622001435 * -(492341330 + (0x6E1198B2 ^ -1154511999))))))) * -1563637161))) - (-1963472651 - -683963291 + -1763147747 * 1381563539))) % 3;
					int num5 = 15842972;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -num5;
						num5 = -(num5 - 2139562162);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1851539928;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -1851539930;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 345138290;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x14926473;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.DragOver += P_1;
					int[] array = new int[4];
					array[0] = 1887443942;
					array[1] = -85930028;
					array[2] = 576079089;
					array[3] = -590241424;
					array[3] = array[0] ^ 0xC3A1DD7;
					array[1] ^= 2104106993;
					array[2] = array[0] ^ 0x487768B;
					int[] array2 = new int[6];
					array2[0] = 26958761;
					array2[1] = 1764389576;
					array2[2] = 2014311643;
					array2[3] = -490126149;
					array2[4] = -2082336573;
					array2[5] = -221820576;
					array2[0] = array[0] ^ -1779079047;
					array2[5] = array2[1] ^ 0xBF2CCCF;
					array2[2] = array2[3] ^ -213704242;
					array2[3] = array2[1] ^ -1743755926;
					int num11 = array2[0] ^ -1463857155;
					num = ((int)num4 * -1101828354) ^ -1717235130 ^ num11;
				}
			}
		}
	}

	static void _0023_002F_0040_002A_0026_002B_0024_0025(UIElement P_0, DragEventHandler P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			P_0.Drop += P_1;
		}
	}
}
