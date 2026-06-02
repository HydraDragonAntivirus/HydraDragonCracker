using System;
using System.CodeDom.Compiler;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Markup;
using Pbt_003D;
using RikaNET.WinUI.ViewModels;
using WinRT;

namespace RikaNET.WinUI.Views;

public sealed class LoginView : UserControl, IComponentConnector
{
	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CUserControl_Loaded_003Ed__5 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncVoidMethodBuilder _003C_003Et__builder;

		public LoginView _003C_003E4__this;

		private TaskAwaiter _003C_003Eu__1;

		private void MoveNext()
		{
			int num = _003C_003E1__state;
			LoginView loginView = _003C_003E4__this;
			try
			{
				if (num != 0)
				{
					goto IL_0023;
				}
				goto IL_087b;
				IL_0023:
				int num2 = -896364961;
				goto IL_0028;
				IL_0028:
				TaskAwaiter awaiter = default(TaskAwaiter);
				while (true)
				{
					int num3 = num2;
					uint num5;
					uint num4 = (num5 = (uint)(-((((~(-(num3 - ((((~(-(-736621492 * -456456857)) ^ 0x7D8DB779) - -(-(-1504386592 * -8848759) ^ (-(~636212573) - (114230092 - -473464852)))) ^ (489744737 * (1748648135 * (-525500910 - (0x7DF576CD ^ 0x6C36BD7D))) - -(-(~(~-965887321)) - ~(-(~1245912984)))) ^ ((-1588115251 * ((-(-329255112 + -1847240148) ^ -2050062358) - ((0x5BD3DCCC ^ -1389793426) - (0x6D611D22 ^ -40893234))) - (((-696013811 + (~1041900198 - --614339916)) ^ 0xB1F4FFF) - ((-1546237905 ^ -1493017487) - -268488129))) * -1358373585)) + (~(-((-(602759393 - 1678450336) * -409204821) ^ 0x171B14BE)) - -(385211739 * ~(-(-1491284197 - -234058963) * 1927957457)) + (~(-1104084822 ^ (~(-1138130728 - -1446476898) - -998367143 * -1596657358 + -(~(-1289528520 ^ 0x19AEF347)))) ^ -(-(1112245367 + (-1276251134 ^ -1233500416)) - (-1694446131 - -647928124))))))) ^ ~((-1660251617 * --2081302447 * 1263532445) ^ -(~(0x5A9431F1 ^ -44745801)) ^ (~(700065280 - 1074141209) - -(0x4E2A639B ^ -230864990) - (-(-879185300 + -766519042) + -(~-76295346))))) - 1545101540 * 1707207439) ^ 0x6D5389F1) - (-1331679901 ^ -1815341903) + (0x2CFBFF1F ^ 0x7E371C73)) - 335502226)) % 11;
					uint num6 = num4;
					int num7 = 379190088;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(num7 ^ -1946135658);
						num7 = num7 * -94390289 - -850086650;
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
						num10 = -num10 ^ 0x3563C4E7;
						num10 = num10 ^ 0x5412C016 ^ 0x7BD400F2;
					}
					if (num9 == (uint)num10)
					{
						awaiter = _005E_002A_002D_002D_0021_003F_0021_005E(loginView.ViewModel.InitializeAsync());
						int[] array = new int[7] { -145431484, -652563308, -845606148, -824073083, -171803999, 1177647993, 668748325 };
						array[0] ^= -263361589;
						array[3] = array[6] ^ 0x4A139B4A;
						int[] array2 = new int[7];
						array2[0] = 1562620754;
						array2[1] = 471673438;
						array2[2] = 1443682308;
						array2[3] = 613987138;
						array2[4] = -642560356;
						array2[5] = 1928817238;
						array2[6] = 652189360;
						array2[6] = array[1] ^ -437959612;
						array2[4] = array2[5] ^ 0xF3BB92C;
						array2[0] ^= 1624419821;
						array2[4] = array2[3] ^ 0x7A62B3;
						int num12 = array2[6] ^ -739082075;
						num2 = (int)((num5 * 1608271531) ^ 0x229A3C52) ^ num12;
						continue;
					}
					uint num13 = num4;
					int num14 = 19124738;
					_ = 0;
					for (int num15 = 0; num15 < 2; num15++)
					{
						num14 = ~(num14 * 1582952371);
						num14 = ~(~num14);
					}
					if (num13 == (uint)num14)
					{
						bool ısCompleted = awaiter.IsCompleted;
						int[] array3 = new int[7] { -2079950037, -846232974, 188844701, -336695660, 1092307229, 299868571, 854109261 };
						array3[5] ^= 865180820;
						array3[1] ^= 1863682339;
						int[] array4 = new int[6] { -1798177376, -1706666440, 2039741795, -32109122, -478697339, -2001704479 };
						int[][] array5 = new int[2][] { array3, array4 };
						array4[2] = array5[0][2] ^ -1605006667;
						array4[4] = array4[3] ^ -317436202;
						array4[3] = array4[2] ^ 0x4FFB4DAB;
						array4[4] ^= -2009200384;
						int num16 = array5[1][2] ^ -2041435732;
						int[,] array6 = new int[4, 4];
						array6[0, 0] = 1363693648;
						array6[0, 1] = -87961627;
						array6[0, 2] = 1399725876;
						array6[0, 3] = -1755844905;
						array6[1, 0] = -1058328062;
						array6[1, 1] = 1617803683;
						array6[1, 2] = -2114744806;
						array6[1, 3] = 414185948;
						array6[2, 0] = -559618020;
						array6[2, 1] = 503683633;
						array6[2, 2] = 1147084840;
						array6[2, 3] = -2074087789;
						array6[3, 0] = -1362180041;
						array6[3, 1] = 1735810141;
						array6[3, 2] = -672626349;
						array6[3, 3] = 809436948;
						array6[1, 3] = array6[0, 0] ^ 0x61AFD1E7;
						array6[0, 2] ^= 1380810877;
						array6[3, 1] = array6[3, 2] ^ 0x19C329A8;
						array6[0, 3] = array6[1, 2] ^ 0x71DE18FB;
						int num17 = array6[0, 3] ^ 0x845B921;
						int num18 = (int)(num5 * 504969827) ^ -373597296;
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
					int num22 = -10;
					_ = 0;
					for (int num23 = 0; num23 < 1; num23++)
					{
						num22 = -num22;
					}
					if (num21 == (uint)num22)
					{
						num = (_003C_003E1__state = 0);
						_003C_003Eu__1 = awaiter;
						int[] array7 = new int[7];
						array7[0] = -1123370043;
						array7[1] = -792910382;
						array7[2] = 507907031;
						array7[3] = -1136815080;
						array7[4] = -1501118257;
						array7[5] = -729749600;
						array7[6] = -1769959383;
						array7[1] = array7[4] ^ -855185787;
						array7[4] = array7[5] ^ 0x69A3B352;
						int[] array8 = new int[4] { -1593956986, 777859311, 1986205302, -1913134093 };
						int[][] array9 = new int[2][] { array7, array8 };
						array8[0] = array9[0][6] ^ 0x77F0E4E1;
						array8[3] = array8[1] ^ -1756220320;
						array8[1] = array8[2] ^ 0x122845F6;
						int num24 = array9[1][0] ^ 0xDA822B6;
						num2 = (int)((num5 * 1947124155) ^ 0xD26B9F97u) ^ num24;
						continue;
					}
					uint num25 = num4;
					int num26 = -3;
					_ = 0;
					for (int num27 = 0; num27 < 1; num27++)
					{
						num26 = ~num26;
					}
					if (num25 == (uint)num26)
					{
						_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
						int[] array10 = new int[7];
						array10[0] = 1583690518;
						array10[1] = -1876263180;
						array10[2] = -289100404;
						array10[3] = 1533003487;
						array10[4] = -1457203496;
						array10[5] = 1351325352;
						array10[6] = -1074505151;
						array10[5] = array10[6] ^ -976533136;
						array10[2] ^= -1577023037;
						array10[2] = array10[4] ^ -1471407139;
						int[] array11 = new int[5] { -337740567, 578107260, -690572953, 829490442, 426552706 };
						int[][] array12 = new int[2][] { array10, array11 };
						array11[0] = array12[0][0] ^ 0x5D22824F;
						array11[3] = array11[0] ^ 0x731EE9C1;
						array11[2] = array11[4] ^ 0x5F05EBE7;
						int num28 = array12[1][0] ^ -622980925;
						num2 = ((int)num5 * -1235824880) ^ -2043352464 ^ num28;
						continue;
					}
					uint num29 = num4;
					int num30 = -7;
					_ = 0;
					for (int num31 = 0; num31 < 1; num31++)
					{
						num30 = ~num30;
					}
					if (num29 == (uint)num30)
					{
						return;
					}
					uint num32 = num4;
					int num33 = 0;
					_ = 0;
					for (int num34 = 0; num34 < 1; num34++)
					{
						num33 *= -565437225;
					}
					if (num32 == (uint)num33)
					{
						goto IL_087b;
					}
					uint num35 = num4;
					int num36 = 2041508009;
					_ = 0;
					for (int num37 = 0; num37 < 2; num37++)
					{
						num36 = (num36 * 2143673091) ^ -661678425;
						num36 = -(num36 ^ 0x48699C1C);
					}
					if (num35 == (uint)num36)
					{
						_003C_003Eu__1 = default(TaskAwaiter);
						int[,] array13 = new int[3, 4]
						{
							{ -348103171, -1366788586, 1432881446, 1721767536 },
							{ 1473991939, -1974922434, 1383908014, -89404557 },
							{ -136027556, -1893500249, 752615449, -472555116 }
						};
						array13[2, 1] ^= -567672731;
						array13[1, 1] = array13[1, 0] ^ -1233438913;
						array13[2, 2] ^= -792603603;
						array13[1, 3] = array13[0, 2] ^ 0x1207DFE;
						int num38 = array13[1, 3] ^ 0x4CC9905A;
						num2 = (int)((num5 * 483692783) ^ 0x180F0B13) ^ num38;
						continue;
					}
					uint num39 = num4;
					int num40 = -690887981;
					_ = 0;
					for (int num41 = 0; num41 < 1; num41++)
					{
						num40 *= -1655025647;
					}
					if (num39 == (uint)num40)
					{
						num = (_003C_003E1__state = -1);
						int[] array14 = new int[4];
						array14[0] = -1737745816;
						array14[1] = 1873298852;
						array14[2] = 340961376;
						array14[3] = -1170302460;
						array14[2] = array14[0] ^ -1284763337;
						array14[3] = array14[0] ^ -1990296262;
						array14[2] ^= 1971265374;
						int[] array15 = new int[6] { -1223835468, 423540074, -769119377, 806414528, 1840004350, 793415285 };
						int[][] array16 = new int[2][] { array14, array15 };
						array15[0] = array16[0][1] ^ 0x4159A0C;
						array15[2] = array15[1] ^ -1438428176;
						array15[5] = array15[0] ^ 0xA253B17;
						int num42 = array16[1][0] ^ 0x46FBF62C;
						num2 = (int)((num5 * 564992194) ^ 0xCA61BCA6u) ^ num42;
						continue;
					}
					uint num43 = num4;
					int num44 = -791518552;
					_ = 0;
					for (int num45 = 0; num45 < 1; num45++)
					{
						num44 ^= -791518545;
					}
					if (num43 == (uint)num44)
					{
						awaiter.GetResult();
						num2 = -1197387168;
						continue;
					}
					uint num46 = num4;
					int num47 = -487482374;
					_ = 0;
					for (int num48 = 0; num48 < 1; num48++)
					{
						num47 ^= -487482381;
					}
					if (num46 == (uint)num47)
					{
					}
					goto end_IL_001a;
				}
				goto IL_0023;
				IL_087b:
				awaiter = _003C_003Eu__1;
				num2 = -701583992;
				goto IL_0028;
				end_IL_001a:;
			}
			catch (Exception exception)
			{
				while (true)
				{
					int num49 = -200755709;
					while (true)
					{
						int num3 = num49;
						uint num5;
						uint num4 = (num5 = (uint)(-((((~(-(num3 - ((((~(-(-736621492 * -456456857)) ^ 0x7D8DB779) - -(-(-1504386592 * -8848759) ^ (-(~636212573) - (114230092 - -473464852)))) ^ (489744737 * (1748648135 * (-525500910 - (0x7DF576CD ^ 0x6C36BD7D))) - -(-(~(~-965887321)) - ~(-(~1245912984)))) ^ ((-1588115251 * ((-(-329255112 + -1847240148) ^ -2050062358) - ((0x5BD3DCCC ^ -1389793426) - (0x6D611D22 ^ -40893234))) - (((-696013811 + (~1041900198 - --614339916)) ^ 0xB1F4FFF) - ((-1546237905 ^ -1493017487) - -268488129))) * -1358373585)) + (~(-((-(602759393 - 1678450336) * -409204821) ^ 0x171B14BE)) - -(385211739 * ~(-(-1491284197 - -234058963) * 1927957457)) + (~(-1104084822 ^ (~(-1138130728 - -1446476898) - -998367143 * -1596657358 + -(~(-1289528520 ^ 0x19AEF347)))) ^ -(-(1112245367 + (-1276251134 ^ -1233500416)) - (-1694446131 - -647928124))))))) ^ ~((-1660251617 * --2081302447 * 1263532445) ^ -(~(0x5A9431F1 ^ -44745801)) ^ (~(700065280 - 1074141209) - -(0x4E2A639B ^ -230864990) - (-(-879185300 + -766519042) + -(~-76295346))))) - 1545101540 * 1707207439) ^ 0x6D5389F1) - (-1331679901 ^ -1815341903) + (0x2CFBFF1F ^ 0x7E371C73)) - 335502226)) % 4;
						uint num50 = num4;
						int num51 = -1532407454;
						_ = 0;
						for (int num52 = 0; num52 < 2; num52++)
						{
							num51 = ~num51 - 782981457;
							num51 = ~num51 ^ 0x21A14202;
						}
						if (num50 == (uint)num51)
						{
							break;
						}
						uint num53 = num4;
						int num54 = -491032322;
						_ = 0;
						for (int num55 = 0; num55 < 2; num55++)
						{
							num54 = ~(num54 ^ 0x6B2E571E);
							num54 = ~num54 * -890851745;
						}
						if (num53 != (uint)num54)
						{
							uint num56 = num4;
							int num57 = 656285969;
							_ = 0;
							for (int num58 = 0; num58 < 2; num58++)
							{
								num57 = num57 * -718885507 - -991256157;
								num57 = (num57 ^ -808981540) - 1711564841;
							}
							if (num56 != (uint)num57)
							{
								uint num59 = num4;
								int num60 = -4;
								_ = 0;
								for (int num61 = 0; num61 < 1; num61++)
								{
									num60 = ~num60;
								}
								if (num59 == (uint)num60)
								{
								}
								return;
							}
							_003C_003Et__builder.SetException(exception);
							int[] array17 = new int[7];
							array17[0] = -474542480;
							array17[1] = -1801425984;
							array17[2] = -729440049;
							array17[3] = 1881435040;
							array17[4] = 594393264;
							array17[5] = 158435990;
							array17[6] = -1518562595;
							array17[2] = array17[0] ^ -59114201;
							array17[2] = array17[0] ^ -777542320;
							array17[0] = array17[6] ^ 0x29E787A6;
							int[] array18 = new int[4] { 1430218567, 1119251805, -1930986721, 363198352 };
							int[][] array19 = new int[2][] { array17, array18 };
							array18[1] = array19[0][6] ^ -779044694;
							array18[2] ^= 1304286300;
							array18[0] = array18[1] ^ 0x7E6F49BD;
							array18[2] ^= 1050834758;
							int num62 = array19[1][1] ^ 0x456FFDF1;
							num49 = ((int)num5 * -564341689) ^ 0x24807AAB ^ num62;
						}
						else
						{
							_003C_003E1__state = -2;
							int[,] array20 = new int[3, 3];
							array20[0, 0] = 751078703;
							array20[0, 1] = -1726115266;
							array20[0, 2] = -1492131684;
							array20[1, 0] = 366852417;
							array20[1, 1] = 159668621;
							array20[1, 2] = -1177278058;
							array20[2, 0] = -90964217;
							array20[2, 1] = -1757382177;
							array20[2, 2] = -944606458;
							array20[2, 1] = array20[2, 0] ^ -134373525;
							array20[0, 1] = array20[1, 1] ^ -1970443032;
							array20[1, 0] = array20[2, 2] ^ 0x14F09145;
							array20[2, 1] = array20[1, 2] ^ -1147892442;
							int num63 = array20[2, 1] ^ -1070549416;
							num49 = ((int)num5 * -1833765625) ^ -1565810722 ^ num63;
						}
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num64 = 236413476;
				while (true)
				{
					int num3 = num64;
					uint num5;
					uint num4 = (num5 = (uint)(-((((~(-(num3 - ((((~(-(-736621492 * -456456857)) ^ 0x7D8DB779) - -(-(-1504386592 * -8848759) ^ (-(~636212573) - (114230092 - -473464852)))) ^ (489744737 * (1748648135 * (-525500910 - (0x7DF576CD ^ 0x6C36BD7D))) - -(-(~(~-965887321)) - ~(-(~1245912984)))) ^ ((-1588115251 * ((-(-329255112 + -1847240148) ^ -2050062358) - ((0x5BD3DCCC ^ -1389793426) - (0x6D611D22 ^ -40893234))) - (((-696013811 + (~1041900198 - --614339916)) ^ 0xB1F4FFF) - ((-1546237905 ^ -1493017487) - -268488129))) * -1358373585)) + (~(-((-(602759393 - 1678450336) * -409204821) ^ 0x171B14BE)) - -(385211739 * ~(-(-1491284197 - -234058963) * 1927957457)) + (~(-1104084822 ^ (~(-1138130728 - -1446476898) - -998367143 * -1596657358 + -(~(-1289528520 ^ 0x19AEF347)))) ^ -(-(1112245367 + (-1276251134 ^ -1233500416)) - (-1694446131 - -647928124))))))) ^ ~((-1660251617 * --2081302447 * 1263532445) ^ -(~(0x5A9431F1 ^ -44745801)) ^ (~(700065280 - 1074141209) - -(0x4E2A639B ^ -230864990) - (-(-879185300 + -766519042) + -(~-76295346))))) - 1545101540 * 1707207439) ^ 0x6D5389F1) - (-1331679901 ^ -1815341903) + (0x2CFBFF1F ^ 0x7E371C73)) - 335502226)) % 3;
					uint num65 = num4;
					int num66 = -3;
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
					int num69 = -2139090907;
					_ = 0;
					for (int num70 = 0; num70 < 2; num70++)
					{
						num69 += -1375059074 - 1747388428;
						num69 = -num69 ^ -103019470;
					}
					if (num68 != (uint)num69)
					{
						uint num71 = num4;
						int num72 = -1;
						_ = 0;
						for (int num73 = 0; num73 < 1; num73++)
						{
							num72 = ~num72;
						}
						if (num71 == (uint)num72)
						{
						}
						return;
					}
					_003C_003Et__builder.SetResult();
					int[] array21 = new int[5];
					array21[0] = 1848981630;
					array21[1] = -262176727;
					array21[2] = -294125802;
					array21[3] = -1505843996;
					array21[4] = 1173911410;
					array21[1] = array21[4] ^ -2000981680;
					array21[1] = array21[4] ^ 0xC1F2A32;
					int[] array22 = new int[4];
					array22[0] = 1278938058;
					array22[1] = -644346501;
					array22[2] = -1046079521;
					array22[3] = -654714935;
					array22[3] = array21[0] ^ -647704340;
					array22[2] = array22[1] ^ -22706962;
					array22[0] = array22[2] ^ -735709884;
					int num74 = array22[3] ^ 0x96C6A7E;
					num64 = (int)((num5 * 1319022942) ^ 0xF3EAECBEu) ^ num74;
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

		static TaskAwaiter _005E_002A_002D_002D_0021_003F_0021_005E(Task P_0)
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
					int num = 1448075719;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~((~(((-((--248208542 ^ -(-1169934854 ^ 0x29131668)) - -num2) - -(-1129858952 ^ (~(-1140963004 * -1218314095) - -162429857 * -1097344759))) ^ ~(-(~(1499887209 * -1594048317)))) + (-1278109816 ^ 0x521A94C8)) - ~817840531) ^ 0x3C6F8A1))) % 3;
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
							int num9 = -471959526;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 ^= -471959528;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						awaiter = P_0.GetAwaiter();
						int[] array = new int[4] { 524033006, 989850341, 955171755, -1915454962 };
						array[3] ^= 1377826287;
						array[0] = array[3] ^ 0x6A86370C;
						int[] array2 = new int[5];
						array2[0] = 491718526;
						array2[1] = 770422929;
						array2[2] = 1309020152;
						array2[3] = 509811270;
						array2[4] = -1214971610;
						array2[4] = array[1] ^ -142236322;
						array2[3] = array2[2] ^ -1141501408;
						array2[3] = array2[2] ^ 0x3313F106;
						int num11 = array2[4] ^ -388459827;
						num = (int)((num4 * 1136507300) ^ 0x2974E2AC) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return awaiter;
		}
	}

	private bool _isRevealed;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private UserControl Root;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private PasswordBox LicensePasswordBox;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private Button RevealButton;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private FontIcon RevealIcon;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private bool _contentLoaded;

	public LoginViewModel ViewModel { get; }

	public LoginView()
	{
		while (true)
		{
			int num = -1769961813;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(2019156361 * 1664918129 - -1269285357 * -295977286 - (((~(-(num2 ^ (-(~(610373494 + (-(0x1D7CB874 ^ --719022087) + (2032390481 * (1776700133 * 1665407765) + (-553233212 + --1717158803)) + -2102781797))) - (-(-1192136585 ^ -(~(-(2098922853 - 1160657572))) ^ 0x3B80B5D2) + (-479730491 * (-1742506036 + ~(-1725840054 ^ 0x399D86A2) * -165788379) + (~(-251753584 ^ -(-2018910687)) - ~(~(--325059269) * -2104638219)) - (((-2029238180 ^ 0x263C568B) + (-760933453 ^ -(-1012947527)) - ~((0x6CC04078 ^ -980083544) + -(-1958291298 ^ 0x13B1C4E6))) ^ (~(~(-(367162731 * -383248707))) ^ (1347458644 - (-(349984647 - -1277675822) ^ (--2128170165 - ~1769923433)))))))))) ^ ((-776567110 ^ 0xFED748B) - -(506573287 * (0x5466447D ^ -1830218845)))) - ((~-1913078628 * -153359529 * 1318381989 + ((-1649798264 ^ -347467974) + ((-1423182500 ^ -1296349997) - -1598139464))) ^ 0x60B7EBBA)) * -654080303 + -755530051))) % 5;
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
					num7 = ~num7;
					num7 = ~num7 ^ -288009156;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1564370037;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 = 1564370039 - num9;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 988230400;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = -(num11 ^ -1039606177);
							num11 *= -1152105653;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 460751561;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 = 460751564 - num13;
							}
							if (num3 == (uint)num13)
							{
							}
							return;
						}
						__003D_003C_002D_0025_003E_003E_002F((FrameworkElement)this, (object)ViewModel);
						int[] array = new int[7];
						array[0] = -1810880179;
						array[1] = 293270153;
						array[2] = -524930303;
						array[3] = 1534691152;
						array[4] = 1770706151;
						array[5] = -1381502645;
						array[6] = 97823805;
						array[5] = array[6] ^ -1577575282;
						array[0] = array[6] ^ 0x3B07A523;
						int[] array2 = new int[6] { 713590990, 1983606921, 1293884830, 1262034620, 1547714234, -1776467921 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][4] ^ -1439884949;
						array2[5] ^= 1165254607;
						array2[3] = array2[5] ^ 0x183E5D9F;
						array2[0] = array2[2] ^ -280973993;
						int num15 = array3[1][1] ^ -438745813;
						num = (int)((num4 * 1395610599) ^ 0xFCA27380u) ^ num15;
					}
					else
					{
						InitializeComponent();
						int[] array4 = new int[5] { 390583319, -959986212, 421875001, -1914065338, -19565357 };
						array4[2] ^= -1308109130;
						array4[0] ^= -610851993;
						int[] array5 = new int[7] { -1096067923, -638108981, -566275436, 1471117090, -853787496, -1925957519, 691002833 };
						int[][] array6 = new int[2][] { array4, array5 };
						array5[5] = array6[0][4] ^ 0x2BAF87E3;
						array5[2] = array5[3] ^ -1355571968;
						array5[1] = array5[6] ^ -1006465479;
						array5[0] = array5[4] ^ 0x2E2C328B;
						int num16 = array6[1][5] ^ 0x4798665D;
						num = ((int)num4 * -476892073) ^ 0x54157D08 ^ num16;
					}
				}
				else
				{
					ViewModel = AVZ_003D.TbG_003D.GetRequiredService<LoginViewModel>();
					int[,] array7 = new int[4, 3];
					array7[0, 0] = 1080158592;
					array7[0, 1] = 603154650;
					array7[0, 2] = -923080409;
					array7[1, 0] = 57883200;
					array7[1, 1] = -1229102556;
					array7[1, 2] = -59453865;
					array7[2, 0] = -2055641235;
					array7[2, 1] = -879728203;
					array7[2, 2] = 868018314;
					array7[3, 0] = -433802162;
					array7[3, 1] = -1621818300;
					array7[3, 2] = 1508334959;
					array7[3, 2] = array7[3, 1] ^ 0x4CC033E9;
					array7[0, 1] = array7[0, 2] ^ 0x2DEEEDF;
					array7[1, 0] = array7[3, 2] ^ 0x4BDEAF6E;
					array7[0, 0] = array7[1, 2] ^ 0x5E50EA;
					int num17 = array7[0, 0] ^ 0x4DC99398;
					num = ((int)num4 * -1379698362) ^ -714701572 ^ num17;
				}
			}
		}
	}

	[AsyncStateMachine(typeof(_003CUserControl_Loaded_003Ed__5))]
	private void UserControl_Loaded(object sender, RoutedEventArgs e)
	{
		_003CUserControl_Loaded_003Ed__5 stateMachine = default(_003CUserControl_Loaded_003Ed__5);
		stateMachine._003C_003Et__builder = _0028_0023_002F_0023_0040_003D_0023_003F();
		while (true)
		{
			int num = 1256214718;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(1250211485 - (-451854648 + -1069508481)) - ~(1378782656 - -993368297) - (~(num2 - (-783244491 * (-(-(28553984 - -1317304151)) - (-38679174 ^ 0x3AED33C4)) - ((-584154247 - 1683476084 - 263082382 + ~(0x45961A7A ^ 0x7AC42C89)) * -209835227 - (-(0x563CAF88 ^ 0x4AB14079) + ~(-(-1634528085 - 1398643223)))) - -(-2107318215 - -(~(~1669247050) * 1779037145)) - (-(~(-1281131659 * (-590505673 * (-1712957481 + -766363758))) - -799976255) - (687612405 * (~624583799 * -378396689 + (0x638EFFA4 ^ --637367133)) - (-(0x43DA13B7 ^ -1123035406) - -1707373192) - ((-(-988508533 * -1987737183) ^ 0x558C2E1A) + (971674391 * (-125624535 + -1253607618) + (-350959028 - 771556939 * -659054481) - ~(-2062749273 * -1671565707) * 200541829)))) - ((-1116606209 * (-719013121 ^ ~(1821120239 * -(1139460200 + 2056554438)))) ^ --1567657194) * 106971837) - -(~181778602 * 1965836547 - ((-1120827621 ^ 0x54E9ADFE) - (376404705 - -1029177566) - -346773108))) ^ (-(-(-396313685 + 535235520 + (0x7270A48 ^ 0x7D6BEB99) + -(-1280209468 + -1172792557))) ^ -509556747) ^ ((0x19266B8E ^ -(-1762598733)) - 440119515)) + 152828102)) % 5;
				int num5 = -1193197307;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 += 1193197311;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -84150551;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = ~(1308107144 - num7);
					num7 = (num7 ^ --2100417138) - -1766581300;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -962277782;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 ^= -962277784;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -1403244355;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 *= -1747629419;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -27179616;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = num13 * -1439447587 - 2015157416;
								num13 = -num13 * -1536014999;
							}
							if (num3 == (uint)num13)
							{
							}
							return;
						}
						stateMachine._003C_003Et__builder.Start(ref stateMachine);
						int[] array = new int[7];
						array[0] = -2019221381;
						array[1] = 882128135;
						array[2] = -1832927909;
						array[3] = -259408432;
						array[4] = -276610065;
						array[5] = 1343523105;
						array[6] = -115769657;
						array[6] = array[0] ^ 0x6159E67C;
						array[4] ^= 1897366889;
						array[6] = array[0] ^ -1273874983;
						int[] array2 = new int[5];
						array2[0] = -21421012;
						array2[1] = 1296667689;
						array2[2] = -8911774;
						array2[3] = -255305911;
						array2[4] = 1222861975;
						array2[2] = array[0] ^ -1645260615;
						array2[0] = array2[3] ^ 0x5C24F337;
						array2[1] = array2[0] ^ -892933589;
						array2[0] = array2[1] ^ 0x5748396;
						int num15 = array2[2] ^ 0x49D6355D;
						num = ((int)num4 * -1433228209) ^ -1710029827 ^ num15;
					}
					else
					{
						stateMachine._003C_003E1__state = -1;
						int[,] array3 = new int[3, 4]
						{
							{ -759244478, -438114224, 540126477, -2074558108 },
							{ 292436903, -1803580608, -1943258300, 1607565718 },
							{ -434755419, -1017222731, 1430156805, -516874673 }
						};
						array3[2, 3] ^= 726764961;
						array3[1, 3] = array3[0, 3] ^ -630663079;
						array3[2, 1] = array3[1, 0] ^ 0x4C2649A3;
						int num16 = array3[2, 1] ^ -1371821595;
						num = ((int)num4 * -936479440) ^ 0x119DF00 ^ num16;
					}
				}
				else
				{
					stateMachine._003C_003E4__this = this;
					int[,] array4 = new int[4, 4];
					array4[0, 0] = 210011303;
					array4[0, 1] = -523365292;
					array4[0, 2] = 281039512;
					array4[0, 3] = 1968592201;
					array4[1, 0] = 1941923595;
					array4[1, 1] = 1140779001;
					array4[1, 2] = 300717433;
					array4[1, 3] = 87559497;
					array4[2, 0] = 269392343;
					array4[2, 1] = -384955871;
					array4[2, 2] = -670670616;
					array4[2, 3] = -1011475109;
					array4[3, 0] = 1196603515;
					array4[3, 1] = -2088213682;
					array4[3, 2] = -1797029341;
					array4[3, 3] = 1885193691;
					array4[0, 0] = array4[1, 2] ^ 0xF1E36C0;
					array4[1, 1] = array4[3, 0] ^ 0x25D06B90;
					array4[1, 0] = array4[0, 3] ^ 0x28EFF9AF;
					int num17 = array4[1, 0] ^ -604497816;
					num = ((int)num4 * -620835710) ^ -1687523264 ^ num17;
				}
			}
		}
	}

	private void RevealButton_Tapped(object sender, TappedRoutedEventArgs e)
	{
		_isRevealed = !_isRevealed;
		while (true)
		{
			int num = 1127176747;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(((~(num2 - (-(482277015 * ~(~(-(-78657933 + 156371664)) + ((-273882900 * -2107168679 - --1236075212) ^ (-21669875 ^ 0x49114073)))) + (~(-469966226 ^ -(-2068435484 ^ 0x5A3F6475)) - (((-(~1462655190) ^ 0x2ABDEAE8) + ~(--1214747111 + (-1764589882 - 1102521904))) ^ (-314792655 * -(0x3B3952B ^ 0x85D3A08))) + (((~(--1725593521) * 2060910851) ^ (--2067263712 ^ -807391260 ^ -(0x4A952BE3 ^ -1922870997))) + (-(--1558614178 - (0x3018796F ^ -916232534)) ^ -(827071845 - -1342261318 + --1800781127))) * 1887921593)) * -1518537367) * 1365811045) ^ -((1264955592 * -1108872281 + 449306722 - (0x33E8898E ^ --2067550124)) * -1951557021 - ((-(-1279387354 + -488109297) ^ --302993233) + (-588385684 - -1661605141 + ~-928037227 + -1525793046))) ^ (~(-1675759659 ^ 0x5BC5CB83) + -660520955 - (-1586481578 ^ 0x4CEED7A9))) * -195913471 * -415709879) ^ --1230410768 ^ 0x10DF312F)) % 7;
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
				int num7 = -538280779;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 *= 1300355089;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -2105182657;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 -= -2105182661;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 352370158;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = -782280304 - -num11;
							num11 = (num11 + -1451974431 * 931098858) * 1501911953;
						}
						if (num3 == (uint)num11)
						{
							_0021_002D_003E_0024_003F_0023_005E_005E(RevealIcon, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x420B ^ 0x4322))]);
							return;
						}
						int num13 = -7;
						_ = 0;
						for (int num14 = 0; num14 < 1; num14++)
						{
							num13 = ~num13;
						}
						if (num3 != (uint)num13)
						{
							int num15 = -182117155;
							_ = 0;
							for (int num16 = 0; num16 < 2; num16++)
							{
								num15 ^= 0x5CBC3ADA;
								num15 = (num15 - ~-391424660) * -2099377189;
							}
							if (num3 != (uint)num15)
							{
								int num17 = 3;
								_ = 0;
								for (int num18 = 0; num18 < 2; num18++)
								{
									num17 = ~num17;
									num17 = ~(~num17);
								}
								if (num3 == (uint)num17)
								{
								}
								return;
							}
							_0021_002D_003E_0024_003F_0023_005E_005E(RevealIcon, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x9E80 ^ 0x9FAA]);
							int[,] array = new int[3, 4];
							array[0, 0] = 1772966875;
							array[0, 1] = 1028317517;
							array[0, 2] = -3297062;
							array[0, 3] = -1757815136;
							array[1, 0] = -1796814935;
							array[1, 1] = 397805434;
							array[1, 2] = 1361861684;
							array[1, 3] = 1802289376;
							array[2, 0] = 195993009;
							array[2, 1] = -1535084669;
							array[2, 2] = 2047585328;
							array[2, 3] = 551043296;
							array[0, 2] = array[1, 3] ^ 0x4A68BEB;
							array[2, 3] = array[0, 0] ^ -1578609265;
							array[0, 3] = array[2, 0] ^ -2069631758;
							int num19 = array[0, 3] ^ -772605743;
							num = (int)((num4 * 569624782) ^ 0x23BAAFBC) ^ num19;
						}
						else
						{
							_003C_0023_005E_002F_0029_003F_003C_002A(LicensePasswordBox, PasswordRevealMode.Hidden);
							num = -1926661679;
						}
					}
					else
					{
						_003C_0023_005E_002F_0029_003F_003C_002A(LicensePasswordBox, PasswordRevealMode.Visible);
						int[] array2 = new int[7];
						array2[0] = 626732665;
						array2[1] = 1928112007;
						array2[2] = -2070308349;
						array2[3] = 2047096060;
						array2[4] = -2131420789;
						array2[5] = -1938973139;
						array2[6] = -1952593577;
						array2[4] = array2[3] ^ 0x23E6FF4D;
						array2[6] = array2[4] ^ -687378831;
						int[] array3 = new int[4];
						array3[0] = -1169644508;
						array3[1] = 895465861;
						array3[2] = 109469205;
						array3[3] = -1725888039;
						array3[0] = array2[3] ^ -1632030148;
						array3[1] = array3[2] ^ 0x4A611082;
						array3[2] ^= -1813334134;
						int num20 = array3[0] ^ -859466331;
						num = ((int)num4 * -2059443309) ^ 0x67F96176 ^ num20;
					}
				}
				else
				{
					bool isRevealed = _isRevealed;
					int[] array4 = new int[7];
					array4[0] = 1071526190;
					array4[1] = 461352803;
					array4[2] = -1436809255;
					array4[3] = -92788947;
					array4[4] = -1862204089;
					array4[5] = -1762918049;
					array4[6] = -2044488764;
					array4[0] = array4[4] ^ 0x5FF95299;
					array4[1] = array4[4] ^ 0x786A97EF;
					array4[6] = array4[4] ^ -1823831656;
					int[] array5 = new int[7];
					array5[0] = 1135340899;
					array5[1] = 1308030319;
					array5[2] = 62148620;
					array5[3] = 1053470365;
					array5[4] = -919320343;
					array5[5] = 1263064919;
					array5[6] = -2080613098;
					array5[5] = array4[2] ^ 0x4D67402E;
					array5[1] = array5[0] ^ 0x256A91CF;
					array5[4] = array5[3] ^ -448508908;
					int num21 = array5[5] ^ 0x4600B7BD;
					int[,] array6 = new int[4, 3];
					array6[0, 0] = -1783758975;
					array6[0, 1] = -108750424;
					array6[0, 2] = 1755471582;
					array6[1, 0] = -358530925;
					array6[1, 1] = 1899532288;
					array6[1, 2] = -1854524205;
					array6[2, 0] = -436771719;
					array6[2, 1] = -1872597654;
					array6[2, 2] = -281745316;
					array6[3, 0] = -1913189809;
					array6[3, 1] = -350137770;
					array6[3, 2] = -1461147689;
					array6[2, 1] = array6[3, 1] ^ 0x1734CBC0;
					array6[2, 1] = array6[0, 1] ^ 0x42C71A44;
					array6[0, 0] ^= 369239382;
					array6[3, 1] = array6[0, 1] ^ 0x4E4D1310;
					int num22 = array6[3, 1] ^ -1117392023;
					int num23 = (int)((num4 * 641965387) ^ 0x2E93B720);
					num21 ^= num23;
					num22 ^= num23;
					int num24;
					int num25;
					if (isRevealed)
					{
						num24 = num22;
						num25 = num24;
					}
					else
					{
						num24 = num21;
						num25 = num24;
					}
					num = num24 ^ num23;
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
		goto IL_043f;
		IL_000e:
		int num = 739476224;
		goto IL_0013;
		IL_0013:
		Uri uri = default(Uri);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)(-(~(~(-(~(~(-(-(~(-1195491839 * -98894865)) * 937971589)) + 242046475 - (num2 - -(-669181458 + ~-508553451) * 1611152917) * 1394874535 - 2062307805) + -((0x1EFD32DE ^ 0x42AED0D4) * -119323471))))))) % 6;
			int num5 = -597615576;
			_ = 0;
			for (int num6 = 0; num6 < 1; num6++)
			{
				num5 = -597615576 - num5;
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = -1071499309;
			_ = 0;
			for (int num8 = 0; num8 < 1; num8++)
			{
				num7 -= -1071499311;
			}
			if (num3 == (uint)num7)
			{
				return;
			}
			int num9 = -574343515;
			_ = 0;
			for (int num10 = 0; num10 < 1; num10++)
			{
				num9 *= 1762705709;
			}
			if (num3 != (uint)num9)
			{
				int num11 = 2012369934;
				_ = 0;
				for (int num12 = 0; num12 < 2; num12++)
				{
					num11 = -(num11 ^ -1466108948);
					num11 = ~num11 * 1661919913;
				}
				if (num3 != (uint)num11)
				{
					int num13 = 1275124356;
					_ = 0;
					for (int num14 = 0; num14 < 1; num14++)
					{
						num13 ^= 0x4C00DA87;
					}
					if (num3 != (uint)num13)
					{
						int num15 = 5;
						_ = 0;
						for (int num16 = 0; num16 < 2; num16++)
						{
							num15 = -(~num15);
							num15 = ~num15 - 1499832573;
						}
						if (num3 == (uint)num15)
						{
						}
						return;
					}
					_0021_003D_0026_0023_003C_003E_003F_003D((object)this, uri, ComponentResourceLocation.Application);
					int[] array = new int[6];
					array[0] = 1765532218;
					array[1] = -1818702927;
					array[2] = -1770487168;
					array[3] = 1351885706;
					array[4] = -2098711190;
					array[5] = 818913853;
					array[5] = array[4] ^ -836390448;
					array[1] = array[2] ^ 0x2E507029;
					int[] array2 = new int[4];
					array2[0] = 2126773267;
					array2[1] = -364605256;
					array2[2] = 158816013;
					array2[3] = 1588355627;
					array2[0] = array[0] ^ 0x65EDA9C8;
					array2[3] ^= -820069502;
					array2[1] = array2[2] ^ 0x5ED6BCB;
					int num17 = array2[0] ^ 0x70835269;
					num = (int)((num4 * 1852644651) ^ 0x2A81D88B) ^ num17;
				}
				else
				{
					uri = new Uri(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[3819 - 3541 + 21]);
					int[] array3 = new int[6] { 1970594815, -495201961, 2107223059, 387479969, 1228102658, 1970015307 };
					array3[2] ^= 1781212843;
					array3[3] = array3[4] ^ 0x42CF9022;
					int[] array4 = new int[5];
					array4[0] = -1833130230;
					array4[1] = -308849873;
					array4[2] = -1902728568;
					array4[3] = 498988600;
					array4[4] = -518816280;
					array4[3] = array3[5] ^ 0x74024898;
					array4[4] ^= 1212108685;
					array4[2] = array4[3] ^ 0x4BC73D61;
					int num18 = array4[3] ^ -1411499804;
					num = (int)((num4 * 1035582386) ^ 0x6635348) ^ num18;
				}
				continue;
			}
			goto IL_043f;
		}
		goto IL_000e;
		IL_043f:
		_contentLoaded = true;
		num = 527835740;
		goto IL_0013;
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public void Connect(int connectionId, object target)
	{
		int num;
		switch (connectionId)
		{
		default:
			num = 540082667;
			goto IL_0024;
		case 3:
			RevealButton = target.As<Button>();
			_0023_0021_0024_0026_003D_0026_002D_003D((UIElement)RevealButton, (TappedEventHandler)RevealButton_Tapped);
			num = 1975257569;
			goto IL_0024;
		case 1:
			Root = target.As<UserControl>();
			num = 1445984802;
			goto IL_0024;
		case 2:
			LicensePasswordBox = target.As<PasswordBox>();
			num = 1703616080;
			goto IL_0024;
		case 4:
			{
				RevealIcon = target.As<FontIcon>();
				num = -1911468081;
				goto IL_0024;
			}
			IL_0024:
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(-num2 - -((-1152030151 ^ ((-(-(398455472 - 1179765471)) + ~(-1404205353 * (0x3B4D8E1D ^ 0x1AAF75CA))) ^ (-(2108915109 * 1821258271 * -964907279) + -(~(-2093908445))))) + 1227942845 * (~-989897200 - (-(-233431836 - -1669245619) ^ 0x53C6FBAB)) * -1131110323) + (2147022889 + (~(-760735788 + ~716878502) + (0x7C33CFF9 ^ -141764614)) - -(-1592023511 * ~(-1067302937 - 1399642715 - 1025322033 * -35706066)) - (~(-392240399 + ~-255848344) - ~(0x4EFE3D00 ^ --174663959) + ~(0x5EDBE02A ^ -740290955)) * -2059515503) + 1631122717 * (((-935635218 + -2136228223 - -455237764 + -(895692619 * -2000713372)) ^ -1834209298) + (1521646007 + ~(~1405428716)) * 1451455253)))) % 12;
				int num5 = -857590053;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = num5 * -1937585653 + -1518633665;
					num5 = ~(1693288568 * 1261297231 - num5);
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1825062492;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 -= 1825062486;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 10;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = ~num9 ^ 0x384E3773;
						num9 = ~(num9 ^ -2124934704);
					}
					if (num3 == (uint)num9)
					{
						goto case 1;
					}
					int num11 = -1;
					_ = 0;
					for (int num12 = 0; num12 < 1; num12++)
					{
						num11 = -num11;
					}
					if (num3 != (uint)num11)
					{
						int num13 = -1281672443;
						_ = 0;
						for (int num14 = 0; num14 < 1; num14++)
						{
							num13 -= -1281672447;
						}
						if (num3 != (uint)num13)
						{
							int num15 = 332061575;
							_ = 0;
							for (int num16 = 0; num16 < 1; num16++)
							{
								num15 *= -1198532735;
							}
							if (num3 == (uint)num15)
							{
								goto case 2;
							}
							int num17 = 17739307;
							_ = 0;
							for (int num18 = 0; num18 < 1; num18++)
							{
								num17 ^= 0x10EAE28;
							}
							if (num3 != (uint)num17)
							{
								int num19 = 963457224;
								_ = 0;
								for (int num20 = 0; num20 < 2; num20++)
								{
									num19 = (~1292031433 - num19) * 1158423779;
									num19 = -num19 ^ -2083623314;
								}
								if (num3 == (uint)num19)
								{
									goto case 3;
								}
								int num21 = 0;
								_ = 0;
								for (int num22 = 0; num22 < 2; num22++)
								{
									num21 *= 235234785;
									num21 = -(-num21);
								}
								if (num3 != (uint)num21)
								{
									int num23 = -1292801229;
									_ = 0;
									for (int num24 = 0; num24 < 2; num24++)
									{
										num23 *= -1808042087;
										num23 = -num23 ^ -110816973;
									}
									if (num3 != (uint)num23)
									{
										int num25 = -928477298;
										_ = 0;
										for (int num26 = 0; num26 < 2; num26++)
										{
											num25 = -(num25 * -504850549);
											num25 = (num25 - (1601340684 + -566685931)) * 2109419255;
										}
										if (num3 != (uint)num25)
										{
											int num27 = 1867320097;
											_ = 0;
											for (int num28 = 0; num28 < 2; num28++)
											{
												num27 = -num27 * 267641387;
												num27 = 1598594708 - 1958329907 - num27;
											}
											if (num3 == (uint)num27)
											{
											}
											return;
										}
										_contentLoaded = true;
										num = 1024300318;
										continue;
									}
									goto case 4;
								}
								int[] array = new int[4];
								array[0] = 1622466688;
								array[1] = 1684778006;
								array[2] = 798084813;
								array[3] = -1203593097;
								array[3] = array[0] ^ -853382054;
								array[3] = array[0] ^ 0x70CC279C;
								array[3] = array[1] ^ -836474819;
								int[] array2 = new int[6] { -898035503, -227231295, 138265577, -101805765, -794566552, 2031749045 };
								int[][] array3 = new int[2][] { array, array2 };
								array2[3] = array3[0][0] ^ 0x76894DD4;
								array2[5] = array2[3] ^ 0x6976098F;
								array2[1] = array2[3] ^ 0x5B519886;
								int num29 = array3[1][3] ^ -1741888869;
								num = (int)((num4 * 1285529920) ^ 0x57E98F00) ^ num29;
								continue;
							}
							int[,] array4 = new int[4, 3];
							array4[0, 0] = 1878441559;
							array4[0, 1] = -399143709;
							array4[0, 2] = -498545826;
							array4[1, 0] = 800312201;
							array4[1, 1] = -365992497;
							array4[1, 2] = -979921108;
							array4[2, 0] = -801914125;
							array4[2, 1] = 557173461;
							array4[2, 2] = -1033330451;
							array4[3, 0] = -12760859;
							array4[3, 1] = 396736214;
							array4[3, 2] = -1972962170;
							array4[3, 0] = array4[3, 1] ^ 0x6BA313FD;
							array4[2, 0] = array4[1, 0] ^ -1767068271;
							array4[2, 2] = array4[1, 2] ^ -780341005;
							array4[1, 0] = array4[2, 1] ^ 0x30C523C7;
							int num30 = array4[1, 0] ^ -1612601635;
							num = ((int)num4 * -117246434) ^ 0x99AE86A ^ num30;
							continue;
						}
						int[,] array5 = new int[4, 3];
						array5[0, 0] = -2038144377;
						array5[0, 1] = -1547358518;
						array5[0, 2] = -1967878314;
						array5[1, 0] = 1859260004;
						array5[1, 1] = -167167006;
						array5[1, 2] = 756687179;
						array5[2, 0] = -44162938;
						array5[2, 1] = 999058190;
						array5[2, 2] = 909510145;
						array5[3, 0] = -55326083;
						array5[3, 1] = -1606200394;
						array5[3, 2] = -1298058160;
						array5[2, 1] = array5[0, 1] ^ 0x6036639E;
						array5[1, 1] = array5[0, 0] ^ -462241076;
						array5[3, 0] = array5[1, 2] ^ -1922170346;
						int num31 = array5[3, 0] ^ 0x2E656C92;
						num = (int)((num4 * 1535947569) ^ 0xBA18A984u) ^ num31;
						continue;
					}
					_002B_005E___0025_005E_0024_0023((FrameworkElement)Root, (RoutedEventHandler)UserControl_Loaded);
					int[] array6 = new int[5];
					array6[0] = -590084158;
					array6[1] = 238863643;
					array6[2] = -1736928202;
					array6[3] = -1177235703;
					array6[4] = -2112585659;
					array6[0] = array6[4] ^ 0x61A6522B;
					array6[2] = array6[3] ^ -336026616;
					array6[3] = array6[2] ^ 0x36A42870;
					int[] array7 = new int[5];
					array7[0] = -913722777;
					array7[1] = 1923633118;
					array7[2] = -1210498214;
					array7[3] = 2066885812;
					array7[4] = -1252305032;
					array7[4] = array6[4] ^ 0x3838DCB4;
					array7[2] = array7[3] ^ 0x5DF9DE1E;
					array7[0] = array7[2] ^ 0x22CD38EE;
					array7[3] = array7[4] ^ 0x4183DD35;
					int num32 = array7[4] ^ -2072185240;
					num = (int)((num4 * 1728237453) ^ 0x7F401569) ^ num32;
					continue;
				}
				int[] array8 = new int[5];
				array8[0] = -795274200;
				array8[1] = 1292758527;
				array8[2] = 590944620;
				array8[3] = -34255465;
				array8[4] = -624306946;
				array8[2] = array8[1] ^ 0x2635087D;
				array8[2] = array8[3] ^ 0x15EB3E65;
				int[] array9 = new int[4];
				array9[0] = 1723443740;
				array9[1] = -1753714778;
				array9[2] = -1932181609;
				array9[3] = -1442893859;
				array9[0] = array8[4] ^ -801377577;
				array9[1] = array9[2] ^ -1608726709;
				array9[3] = array9[2] ^ 0x53CC8744;
				int num33 = array9[0] ^ -2065471002;
				num = (int)((num4 * 2127358652) ^ 0x4312EC28) ^ num33;
			}
			goto default;
		}
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public IComponentConnector GetBindingConnector(int connectionId, object target)
	{
		return null;
	}

	static void __003D_003C_002D_0025_003E_003E_002F(FrameworkElement P_0, object P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1035822598;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(-(num2 ^ (360532385 * (-868503393 * ~(-(-(-(~-983467714)) * 739730711) ^ ((-1026962069 - (0x4131DF0B ^ 0x30A30CAD)) ^ ((-(336254221 * -232025593) - 114709134 * 800132579) ^ (-(~975918342) - 1340093299 * 972969593)))))) ^ ((0x49247E45 ^ -157389896) - ((461939290 - --204594287 - (-374966182 - 1948481344) * -1158698669) ^ 0x15867C44) + (-(-992123154 + 738392631) + ~(--613130954) - (1693333260 - (0x263291AE ^ -42865639)) - -(1228948389 * ((-838584255 ^ -494553167) + -952183351))) + ((-425339087 ^ (-1689191091 * 1589714735 + (-887441300 * -1342793591 - -1650129022) - (-453258725 + (--1985651114 - --1640822813)))) - -(-(767514133 * -1108833953))) + -555943183 * ((-1628850934 ^ -1981110872) - (-2032419683 * -2109667739 - (-902034672 - 945222820 + ~1615090356) + (~(740004803 * -1933930773) + -462952064)) - 814134839)))) * 1136172615) * -114644299 * 687760519)) % 3;
					int num5 = -72783376;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = 1109171720 - ~num5;
						num5 = 1074703615 - -num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(num7 ^ -190849263);
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -266796884;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9 - -2036106515;
							num9 = -num9 * -1788215275;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.DataContext = P_1;
					int[] array = new int[4] { 694749544, -871364180, 1410275824, 237667749 };
					array[3] ^= -1261929891;
					array[2] = array[1] ^ 0x4B6FE79F;
					int[] array2 = new int[5];
					array2[0] = -340011429;
					array2[1] = -186514121;
					array2[2] = 409865053;
					array2[3] = -1685166218;
					array2[4] = 130508585;
					array2[4] = array[0] ^ 0x78208CE0;
					array2[1] = array2[2] ^ 0x1C119E0B;
					array2[0] = array2[3] ^ -1234435661;
					int num11 = array2[4] ^ -1079771709;
					num = (int)((num4 * 383270775) ^ 0xAE68355Du) ^ num11;
				}
			}
		}
	}

	static AsyncVoidMethodBuilder _0028_0023_002F_0023_0040_003D_0023_003F()
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
				int num = -1007731625;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(num2 - -(-((-869737607 * ~(-296245859 ^ -1415410336) + -(2005361487 * -(-524996190 + -821187307))) ^ (-(1059945501 * -984234825 + 2046014275) * 1588893405)) - ~(-(~((0x690B9AF ^ 0x6458C836) + (0x3F756DE1 ^ 0x4CC8B482))) - -(1323026157 * 445152107)))) + (-644967009 * ~(1246365479 * 486649645) - 178403689)) ^ ((0xD5CAD4F ^ -(-918042745 ^ -1581705544)) - (~(~1995785983) + ~840845016 + 1397298791)))) % 3;
					int num5 = -1332081684;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 + 935809251;
						num5 = -num5 - 545633555;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -267919359;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 ^= --384703714;
						num7 = (num7 ^ -519259630) + 1411296656;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 ^= -476323184;
							num9 = -(-num9);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = AsyncVoidMethodBuilder.Create();
					int[] array = new int[7];
					array[0] = 266166566;
					array[1] = 1252599866;
					array[2] = 577897489;
					array[3] = -1637134869;
					array[4] = -1263438449;
					array[5] = 1882321803;
					array[6] = 1146526735;
					array[1] = array[0] ^ -156349670;
					array[0] = array[1] ^ 0x1319313D;
					array[4] ^= -808263945;
					int[] array2 = new int[7];
					array2[0] = 1813492723;
					array2[1] = -626459149;
					array2[2] = -1197562549;
					array2[3] = -1271956801;
					array2[4] = 1628044153;
					array2[5] = -571704803;
					array2[6] = 563669667;
					array2[3] = array[5] ^ 0x6B3A745C;
					array2[4] = array2[6] ^ 0x4C6C87D9;
					array2[0] = array2[1] ^ 0x4CFA14CE;
					array2[2] = array2[4] ^ 0x69A43E42;
					int num11 = array2[3] ^ 0x78BAAC66;
					num = ((int)num4 * -1190210579) ^ -1217608442 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _003C_0023_005E_002F_0029_003F_003C_002A(PasswordBox P_0, PasswordRevealMode P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 589551250;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-1016645329 + 490943694 - ~(~(-((1365799919 * -208939900 - (~(num2 + ((0x3795F1B ^ (~(-1859389130 ^ -217138945) - ((~-949291624 - --1865348777) ^ -(653098650 - -126832579) ^ (-(-1746628432) ^ -(780575029 * -299089925))) + ((0x4C50418E ^ (-(1884398079 - -2011691129) - 362100727)) + -1166609437 * (~-702421194 * 1440663723))) ^ (-(0x7F1649D1 ^ (-(-(-1044654949 * -806070816)) * 190825043)) + (1607886614 - ~(-1355318397 * -(-82275479 + 1531712539)) - ~-1633007626))) + 78703909 * -164827512)) ^ -(2135883205 * (((-752692609 - (-706495317 + -1560873198)) ^ -1653739868) - 849393285 * 2126020076 - (-(0x386972FB ^ -1733221733) - --1787507942))))) * -1597290605))) - -224828823)) % 3;
					int num5 = 1637308776;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * -719909579 * -866403115;
						num5 = ~num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1224109016;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 + (0x3A9F1F03 ^ 0x364406EE) + -1955585135;
						num7 = (num7 ^ -1153736825) * 730008483;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -132693999;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ --591469543) - 1791056142;
							num9 -= -1824388738 + 17254427;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.PasswordRevealMode = P_1;
					int[] array = new int[7];
					array[0] = -869265636;
					array[1] = 1671867750;
					array[2] = 522164943;
					array[3] = 1378833289;
					array[4] = 487344662;
					array[5] = -835409486;
					array[6] = -995357610;
					array[5] = array[2] ^ 0x1D580959;
					array[4] ^= -1254008623;
					array[0] ^= -1407035090;
					int[] array2 = new int[6];
					array2[0] = 1228542296;
					array2[1] = -1406442735;
					array2[2] = -1770926785;
					array2[3] = -1345647217;
					array2[4] = 1760543102;
					array2[5] = -283816467;
					array2[4] = array[1] ^ 0x67ACA8D3;
					array2[3] = array2[0] ^ 0x3E8AFBA0;
					array2[0] ^= -530788545;
					array2[2] = array2[3] ^ -954115259;
					int num11 = array2[4] ^ -722221372;
					num = ((int)num4 * -373314279) ^ -369982303 ^ num11;
				}
			}
		}
	}

	static void _0021_002D_003E_0024_003F_0023_005E_005E(FontIcon P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -800511472;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(((~((((1348073437 * -(858358867 * (-1217697231 * -502491746 + ~-1509932887 + 1371116258))) ^ ~(~(-((1768694737 + 1266845509 + --1623315259) * -1088969329)))) - ((num2 ^ -(((0x798F11A9 ^ -(-1412075164) ^ (~(-2077617795 ^ 0x52A06D56) + --510522876 * -1245325523)) - ~(-633931596 + (-742224425 ^ 0x7F6318EA)) * 1606946985 - -(~(-(1794062737 * 2023422599 + (592695855 + 179556524)))) + (-2101505605 + -1310952277 * ((~(-750247095) - -(0x4445940E ^ -451921390)) ^ -1252164851))) * -1597751201)) - ~((-1426882777 * ~((746107343 * --1403066553) ^ 0x66D50A27)) ^ (-564887969 * -((-103712047 + (-1161174383 + 438416191)) ^ -1721929874) + (0x21232EB4 ^ 0x56575AF6))))) * -211114551 - (-(-835189441 ^ -1211127654) - ~(0x732F8D20 ^ 0x5FA2775F) + -2115061133)) - (0x2ABDBF8D ^ -(639087747 - -520296762))) * 1526136129) ^ -54664070))) % 3;
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
					int num7 = -2;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 410512353;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 *= 2147133089;
							num9 = (num9 * -1849110719) ^ -469924877;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Glyph = P_1;
					int[] array = new int[4];
					array[0] = -1346540137;
					array[1] = -452156797;
					array[2] = 1546808294;
					array[3] = 1404307328;
					array[1] = array[3] ^ 0x6AB16C03;
					array[1] = array[2] ^ -1537792739;
					array[1] ^= 948992068;
					int[] array2 = new int[5];
					array2[0] = 112108945;
					array2[1] = 1098059350;
					array2[2] = 1487837932;
					array2[3] = 1805155882;
					array2[4] = -1854639459;
					array2[3] = array[0] ^ 0x1A5E04B;
					array2[2] = array2[3] ^ -552572467;
					array2[1] = array2[2] ^ -1865214603;
					int num11 = array2[3] ^ 0x1A2DC217;
					num = (int)((num4 * 2096658838) ^ 0x5A05629E) ^ num11;
				}
			}
		}
	}

	static void _0021_003D_0026_0023_003C_003E_003F_003D(object P_0, Uri P_1, ComponentResourceLocation P_2)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1911656863;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-1637218009 * (-(-145826185 + -1314442931 * 175758634) + ~(--2000525465 ^ 0x5C27DE7A)) - ~(-(-num2 + (-1114875697 * -123294559 - ~2008651570 + (~(-306298279 - (~(72256301 + -332072059) + -(-1709225952)) - -902868317) + ~(1976174811 * (~(1012347542 * -1579701639 * -604568175) + (0x24FF7E62 ^ (-1432632811 * 1460468249))))))))) * 1334050713 * 2100849057)) % 3;
					int num5 = -34088628;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= -34088626;
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
					Application.LoadComponent(P_0, P_1, P_2);
					int[,] array = new int[4, 3];
					array[0, 0] = -2006486141;
					array[0, 1] = 759393048;
					array[0, 2] = 1239563448;
					array[1, 0] = 258777597;
					array[1, 1] = -1105470813;
					array[1, 2] = 1291466945;
					array[2, 0] = -225897415;
					array[2, 1] = -1911687455;
					array[2, 2] = -859119384;
					array[3, 0] = -82567751;
					array[3, 1] = 1979626606;
					array[3, 2] = 2143278289;
					array[3, 0] = array[1, 0] ^ 0x53F7C83B;
					array[3, 1] = array[0, 2] ^ 0x22E4A6FC;
					array[2, 2] = array[0, 0] ^ -1323088355;
					int num11 = array[2, 2] ^ -1935070527;
					num = ((int)num4 * -1861350438) ^ -110611920 ^ num11;
				}
			}
		}
	}

	static void _002B_005E___0025_005E_0024_0023(FrameworkElement P_0, RoutedEventHandler P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1422627144;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(-num2)) * 337181583)) % 3;
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
					int num7 = -629572911;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -629572912;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 794231521;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x2F5702E3;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Loaded += P_1;
					int[,] array = new int[3, 4];
					array[0, 0] = -466427042;
					array[0, 1] = -736563470;
					array[0, 2] = -390212085;
					array[0, 3] = -1036563403;
					array[1, 0] = 77897070;
					array[1, 1] = 1959855294;
					array[1, 2] = 1451116113;
					array[1, 3] = -1081685770;
					array[2, 0] = -1795231394;
					array[2, 1] = 2086082312;
					array[2, 2] = -668233057;
					array[2, 3] = -766091202;
					array[2, 0] = array[0, 3] ^ 0x2F28B98;
					array[1, 0] = array[2, 3] ^ 0x5E2B39DD;
					array[2, 1] = array[2, 3] ^ 0x7AB45F8C;
					array[0, 2] = array[2, 2] ^ -1475155760;
					int num11 = array[0, 2] ^ 0x5641012E;
					num = ((int)num4 * -1231961925) ^ 0x6954AF5D ^ num11;
				}
			}
		}
	}

	static void _0023_0021_0024_0026_003D_0026_002D_003D(UIElement P_0, TappedEventHandler P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 231009678;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(((num2 ^ (-1085176215 * (~(1893791182 + -(-(~((0xAF01329 ^ -1578944384) + 326036539)))) - ((-(163839587 * -1379889106) ^ -1264938863 ^ (-(-295785408 ^ 0x5B41C80D) - (-909335972 - 717104059 - (1360522438 - -1429581984) + (~1570870448 + --566300362)))) - (~-2000239150 - -948389823) - (-(-(~(-583576179 * (-660590559 * 1064385885)))) ^ (-(~(1197476891 * -1419790316)) + (-795133520 - (-1562743473 - ~-1586225236) * -1063871821))))))) - (-(-(~(-1291567662 * 1098845867 + (0x22065A46 ^ 0x3690385B)))) - 2082410625 * (221629569 * -((-2136944157 ^ -998722609) - -(-1711654441 * -1313953196)) * 1281501953)) - ((0x1F5C5F62 ^ (~(-(1563802513 - -721607341)) ^ 0x5EFB3DA4) ^ ((-(-(~-145942905)) ^ (-(-205560737 - 444547176) ^ 0x5ADF79E6)) + (-(1127148382 + -45453946 * 971597837) + -(2128302903 - -2104126068 - -1318580367)))) - ~(-1627970196 - (-1828843429 ^ ~(--1381636469 * -907730103)))) - (~((-2047387505 + 1110978750) * -1434670323) - -((301147132 - 376363994) * 1054103623) - -1977040777 * (~(-1813901575 * -1489241289) - (-2093308896 + -377637846)) + -550979551 * (--1041212717 - (~(-808426486 + -1702933777) + -12392751)))) * 219070055 * -89575725 * -344612543))) % 3;
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
					int num7 = 1454326316;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x56AF422E;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 154111159;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 - 1368727204 * -279342847) ^ 0x757B37CD;
							num9 = -(num9 * 63335149);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Tapped += P_1;
					int[] array = new int[5];
					array[0] = 992531930;
					array[1] = 1094619165;
					array[2] = -1069470148;
					array[3] = -684575080;
					array[4] = -1042112214;
					array[2] = array[4] ^ -240430209;
					array[0] = array[2] ^ -1802044418;
					array[4] = array[3] ^ 0x7B1ECC16;
					int[] array2 = new int[7] { 673180920, 1800478398, -793839389, -1143724660, -348276560, -2021184310, 1596675932 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][3] ^ 0x5478737A;
					array2[1] ^= -1222468148;
					array2[4] = array2[1] ^ 0x27D52A48;
					int num11 = array3[1][0] ^ -1910841712;
					num = (int)((num4 * 2104646312) ^ 0x1C8DBCB0) ^ num11;
				}
			}
		}
	}
}
