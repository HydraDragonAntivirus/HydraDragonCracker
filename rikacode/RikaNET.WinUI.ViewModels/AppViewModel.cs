using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Pbt_003D;
using RikaNET.Core.Models;
using Windows.Foundation;

namespace RikaNET.WinUI.ViewModels;

public sealed class AppViewModel : ObservableObject
{
	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CShowResetHwidConfirmationAsync_003Ed__81 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder<bool> _003C_003Et__builder;

		private TaskAwaiter<ContentDialogResult> _003C_003Eu__1;

		private unsafe void MoveNext()
		{
			int num = _003C_003E1__state;
			bool result = default(bool);
			try
			{
				if (num != 0)
				{
					goto IL_0016;
				}
				goto IL_1583;
				IL_0016:
				int num2 = 1905421439;
				goto IL_001b;
				IL_001b:
				TaskAwaiter<ContentDialogResult> awaiter = default(TaskAwaiter<ContentDialogResult>);
				while (true)
				{
					int num3 = num2;
					uint num5;
					uint num4 = (num5 = (uint)((~((-1926857391 - (-849669490 - --717680530)) * 1722754007) - -(~(num3 ^ ((~1334327401 + -(803774367 * (~((--388017388 + 965233242) ^ 0x5F3A736E) * 1883220817))) * -1778132901)) - (0x2891E2BA ^ ((-(-(-1369945635 ^ -606831242) + -(1381503451 + 1205521680)) + -95726137) ^ ~((0x41913838 ^ 0x2A5EFC5D) * -2112720053 - (~(--1128275199) ^ -(-2092597657 * 644207055))))))) * -2136450001)) % 12;
					uint num6 = num4;
					int num7 = 1006429698;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 ^ 0x51F86A41) + -1284919615;
						num7 = -(~num7);
					}
					if (num6 == (uint)num7)
					{
						break;
					}
					uint num9 = num4;
					int num10 = 130453175;
					_ = 0;
					for (int num11 = 0; num11 < 1; num11++)
					{
						num10 *= -406640833;
					}
					if (num9 == (uint)num10)
					{
						ContentDialog contentDialog = new ContentDialog();
						_003F_0024_005E_0029_003F_0024_002F_0024(contentDialog, (object)_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(321 + sizeof(int)) ^ sizeof(Guid)]);
						_002D_002D_0021_0040_003E_0040_0040_0028((ContentControl)contentDialog, (object)_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0xE94 ^ 0xFC2))]);
						_003F_005E_003C_0040_0024_0029_005E_002D(contentDialog, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xAD58 ^ 0xAC0F]);
						_005E_0021_002D_0026_0023_003E_003F_003F(contentDialog, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x6F0 ^ 0x7A8]);
						_0028_0029__0024_0024_002F_003E_003F(contentDialog, ContentDialogButton.Close);
						Window? mainWindowInstance = AVZ_003D.Yrv_003D;
						@_0026_002B_003E_002B_002B_003F_003F((UIElement)contentDialog, ((object)mainWindowInstance != null) ? __0023_0024___0029__002A(_0029_0029_0029_002F_0025_005E_0024_0026(mainWindowInstance)) : null);
						awaiter = _003E_0025_002D_0026_002B_0023_0028_005E(contentDialog).GetAwaiter();
						num2 = 449518252;
						continue;
					}
					uint num12 = num4;
					int num13 = 7634898;
					_ = 0;
					for (int num14 = 0; num14 < 2; num14++)
					{
						num13 = -num13 + 830115088;
						num13 = (num13 ^ -95010625) - 1310102932;
					}
					if (num12 == (uint)num13)
					{
						bool ısCompleted = awaiter.IsCompleted;
						int[] array = new int[7];
						array[0] = 227202327;
						array[1] = -1055209270;
						array[2] = -1079599897;
						array[3] = 2023300541;
						array[4] = 1781620743;
						array[5] = -408720028;
						array[6] = -1802395767;
						array[5] = array[2] ^ 0x53A0B45A;
						array[5] = array[2] ^ -1664301766;
						int[] array2 = new int[5];
						array2[0] = -388399802;
						array2[1] = 1481621444;
						array2[2] = 1203050265;
						array2[3] = -1299751259;
						array2[4] = 880010442;
						array2[2] = array[1] ^ -644006012;
						array2[4] = array2[1] ^ 0x6FB0C236;
						array2[1] ^= -526939059;
						array2[0] = array2[3] ^ -163435134;
						int num15 = array2[2] ^ 0x7D9015B6;
						int[,] array3 = new int[4, 3]
						{
							{ 549650548, -1637722156, -1617779313 },
							{ 865290326, 196983480, 319404699 },
							{ 1507333633, 808104804, -472971449 },
							{ 822080396, -1286711476, 608212505 }
						};
						array3[0, 1] ^= 1954184070;
						array3[1, 1] = array3[2, 1] ^ 0xBFCDE47;
						array3[2, 2] = array3[1, 2] ^ 0x5DE9F6A3;
						int num16 = array3[2, 2] ^ -1480448283;
						int num17 = ((int)num5 * -188807411) ^ -968897568;
						num15 ^= num17;
						num16 ^= num17;
						int num18;
						int num19;
						if (!ısCompleted)
						{
							num18 = num16;
							num19 = num18;
						}
						else
						{
							num18 = num15;
							num19 = num18;
						}
						num2 = num18 ^ num17;
						continue;
					}
					uint num20 = num4;
					int num21 = 1983869155;
					_ = 0;
					for (int num22 = 0; num22 < 2; num22++)
					{
						num21 = -1844642950 - (num21 - (-854729761 + -1021338583));
						num21 = num21 * -1820938507 * 744533173;
					}
					if (num20 == (uint)num21)
					{
						num = (_003C_003E1__state = 0);
						int[] array4 = new int[4] { -16798161, -943377818, -1095747220, -112129360 };
						array4[3] ^= -2037781903;
						array4[0] ^= -1609179586;
						array4[2] ^= -659776363;
						int[] array5 = new int[7];
						array5[0] = 450199794;
						array5[1] = 895528170;
						array5[2] = 1191897799;
						array5[3] = -1978925321;
						array5[4] = -290290932;
						array5[5] = 1181826743;
						array5[6] = -1816688466;
						array5[6] = array4[1] ^ 0x4CE5689D;
						array5[0] = array5[3] ^ -440129373;
						array5[4] = array5[5] ^ 0x3935C2B1;
						array5[1] = array5[2] ^ 0x8DFB133;
						int num23 = array5[6] ^ 0x58F7E2FA;
						num2 = (int)((num5 * 1783112222) ^ 0xEE68C7E2u) ^ num23;
						continue;
					}
					uint num24 = num4;
					int num25 = -1626935319;
					_ = 0;
					for (int num26 = 0; num26 < 1; num26++)
					{
						num25 ^= -1626935326;
					}
					if (num24 == (uint)num25)
					{
						_003C_003Eu__1 = awaiter;
						int[,] array6 = new int[4, 4];
						array6[0, 0] = -265246312;
						array6[0, 1] = 102833552;
						array6[0, 2] = 1270465880;
						array6[0, 3] = 1991515923;
						array6[1, 0] = 125613419;
						array6[1, 1] = 1343331807;
						array6[1, 2] = 1563341716;
						array6[1, 3] = 1662860345;
						array6[2, 0] = -102894696;
						array6[2, 1] = 2038144475;
						array6[2, 2] = 492828825;
						array6[2, 3] = 1504584446;
						array6[3, 0] = 2042674814;
						array6[3, 1] = 41571694;
						array6[3, 2] = -628967079;
						array6[3, 3] = 147133459;
						array6[3, 1] = array6[0, 0] ^ -469541024;
						array6[0, 2] = array6[1, 1] ^ 0x35712CA3;
						array6[3, 0] = array6[1, 3] ^ -967214910;
						array6[1, 2] = array6[1, 1] ^ -1807118633;
						int num27 = array6[1, 2] ^ -1122738682;
						num2 = ((int)num5 * -475926717) ^ 0x3C4E29B1 ^ num27;
						continue;
					}
					uint num28 = num4;
					int num29 = -1593614025;
					_ = 0;
					for (int num30 = 0; num30 < 1; num30++)
					{
						num29 -= -1593614027;
					}
					if (num28 == (uint)num29)
					{
						_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
						int[,] array7 = new int[3, 3];
						array7[0, 0] = -1253810600;
						array7[0, 1] = -1865741267;
						array7[0, 2] = 1369767851;
						array7[1, 0] = -1689150384;
						array7[1, 1] = -361468383;
						array7[1, 2] = 654188689;
						array7[2, 0] = -392582585;
						array7[2, 1] = 1916952132;
						array7[2, 2] = -189727059;
						array7[1, 1] = array7[2, 0] ^ 0x5FBB57AE;
						array7[2, 1] = array7[0, 2] ^ 0x6F9720BF;
						array7[0, 2] = array7[1, 2] ^ 0x11CA64AA;
						int num31 = array7[0, 2] ^ 0x360CDE20;
						num2 = ((int)num5 * -1674505239) ^ -674512242 ^ num31;
						continue;
					}
					uint num32 = num4;
					int num33 = 193444583;
					_ = 0;
					for (int num34 = 0; num34 < 1; num34++)
					{
						num33 *= -1740137421;
					}
					if (num32 == (uint)num33)
					{
						return;
					}
					uint num35 = num4;
					int num36 = 797913880;
					_ = 0;
					for (int num37 = 0; num37 < 1; num37++)
					{
						num36 ^= 0x2F8F3319;
					}
					if (num35 == (uint)num36)
					{
						goto IL_1583;
					}
					uint num38 = num4;
					int num39 = -1821014155;
					_ = 0;
					for (int num40 = 0; num40 < 1; num40++)
					{
						num39 += 1821014165;
					}
					if (num38 == (uint)num39)
					{
						_003C_003Eu__1 = default(TaskAwaiter<ContentDialogResult>);
						int[] array8 = new int[7];
						array8[0] = -1310517222;
						array8[1] = -1489326134;
						array8[2] = -9199757;
						array8[3] = 755657379;
						array8[4] = -1607363270;
						array8[5] = -1299417750;
						array8[6] = -884519070;
						array8[2] = array8[1] ^ 0x36263D35;
						array8[2] = array8[0] ^ -941442159;
						int[] array9 = new int[5] { 935248762, 2094917709, 1227987055, -1425088808, -634799347 };
						int[][] array10 = new int[2][] { array8, array9 };
						array9[2] = array10[0][3] ^ -1508128390;
						array9[0] = array9[4] ^ 0x6B49B971;
						array9[3] = array9[1] ^ -639366072;
						int num41 = array10[1][2] ^ -312981139;
						num2 = (int)((num5 * 661416158) ^ 0xB8B43D24u) ^ num41;
						continue;
					}
					uint num42 = num4;
					int num43 = -721019782;
					_ = 0;
					for (int num44 = 0; num44 < 2; num44++)
					{
						num43 = -num43 - 1403564008;
						num43 = (num43 ^ 0x1697F7C7) - 527152674;
					}
					if (num42 == (uint)num43)
					{
						num = (_003C_003E1__state = -1);
						int[,] array11 = new int[4, 3];
						array11[0, 0] = 1514349041;
						array11[0, 1] = 2147400179;
						array11[0, 2] = -1319225225;
						array11[1, 0] = -2069786922;
						array11[1, 1] = -1372704784;
						array11[1, 2] = 1220255977;
						array11[2, 0] = 1370335688;
						array11[2, 1] = 2085314588;
						array11[2, 2] = 1726152460;
						array11[3, 0] = -114103896;
						array11[3, 1] = 2087210554;
						array11[3, 2] = 1098807577;
						array11[0, 0] = array11[2, 0] ^ 0xE9FC4FF;
						array11[1, 0] ^= 914562517;
						array11[2, 1] = array11[3, 1] ^ -1181474685;
						array11[2, 2] = array11[3, 1] ^ 0x3417163F;
						int num45 = array11[2, 2] ^ 0x2D68BAFD;
						num2 = (int)((num5 * 1432198251) ^ 0xA38861A8u) ^ num45;
						continue;
					}
					uint num46 = num4;
					int num47 = 1052839066;
					_ = 0;
					for (int num48 = 0; num48 < 2; num48++)
					{
						num47 = num47 * -601025077 - -2106908954;
						num47 = -(num47 - -73458405);
					}
					if (num46 == (uint)num47)
					{
						result = awaiter.GetResult() == ContentDialogResult.Primary;
						num2 = 561142689;
						continue;
					}
					uint num49 = num4;
					int num50 = 626309306;
					_ = 0;
					for (int num51 = 0; num51 < 1; num51++)
					{
						num50 ^= 0x2554B8BD;
					}
					if (num49 == (uint)num50)
					{
					}
					goto end_IL_000d;
				}
				goto IL_0016;
				IL_1583:
				awaiter = _003C_003Eu__1;
				num2 = 613845118;
				goto IL_001b;
				end_IL_000d:;
			}
			catch (Exception exception)
			{
				while (true)
				{
					int num52 = -1367272041;
					while (true)
					{
						int num3 = num52;
						uint num5;
						uint num4 = (num5 = (uint)((~((-1926857391 - (-849669490 - --717680530)) * 1722754007) - -(~(num3 ^ ((~1334327401 + -(803774367 * (~((--388017388 + 965233242) ^ 0x5F3A736E) * 1883220817))) * -1778132901)) - (0x2891E2BA ^ ((-(-(-1369945635 ^ -606831242) + -(1381503451 + 1205521680)) + -95726137) ^ ~((0x41913838 ^ 0x2A5EFC5D) * -2112720053 - (~(--1128275199) ^ -(-2092597657 * 644207055))))))) * -2136450001)) % 4;
						uint num53 = num4;
						int num54 = 0;
						_ = 0;
						for (int num55 = 0; num55 < 1; num55++)
						{
							num54 = -num54;
						}
						if (num53 == (uint)num54)
						{
							break;
						}
						uint num56 = num4;
						int num57 = 276862001;
						_ = 0;
						for (int num58 = 0; num58 < 2; num58++)
						{
							num57 = (1466929394 + 1883113759 - num57) ^ -1630782252;
							num57 = num57 ^ 0x792EE824 ^ 0x598B9E28;
						}
						if (num56 != (uint)num57)
						{
							uint num59 = num4;
							int num60 = -3;
							_ = 0;
							for (int num61 = 0; num61 < 1; num61++)
							{
								num60 = ~num60;
							}
							if (num59 != (uint)num60)
							{
								uint num62 = num4;
								int num63 = -426099200;
								_ = 0;
								for (int num64 = 0; num64 < 1; num64++)
								{
									num63 ^= -426099197;
								}
								if (num62 == (uint)num63)
								{
								}
								return;
							}
							_003C_003Et__builder.SetException(exception);
							int[] array12 = new int[5] { 807145888, -1175483520, -1441271339, 336230032, -207700330 };
							array12[1] ^= 601485247;
							array12[1] = array12[2] ^ 0x1E89DB8C;
							int[] array13 = new int[4];
							array13[0] = 710357305;
							array13[1] = -1711873314;
							array13[2] = 684023780;
							array13[3] = -599863238;
							array13[0] = array12[2] ^ -1328629793;
							array13[3] = array13[0] ^ 0x7B874EA;
							array13[3] ^= 1035912953;
							int num65 = array13[0] ^ -607149989;
							num52 = ((int)num5 * -391508898) ^ 0x5F7488CC ^ num65;
						}
						else
						{
							_003C_003E1__state = -2;
							int[] array14 = new int[5];
							array14[0] = 1800644461;
							array14[1] = 1772872118;
							array14[2] = 1266516899;
							array14[3] = 1373119963;
							array14[4] = 732511473;
							array14[3] = array14[1] ^ 0x7C9C2CAC;
							array14[0] = array14[1] ^ -206856271;
							int[] array15 = new int[5];
							array15[0] = 1222824255;
							array15[1] = 945444417;
							array15[2] = -565358183;
							array15[3] = 1703453970;
							array15[4] = 147173688;
							array15[2] = array14[1] ^ -115890133;
							array15[3] = array15[2] ^ -700943554;
							array15[0] = array15[4] ^ 0x20E1E718;
							int num66 = array15[2] ^ -896347953;
							num52 = (int)((num5 * 1539772963) ^ 0xD4F0F68Fu) ^ num66;
						}
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num67 = 488296926;
				while (true)
				{
					int num3 = num67;
					uint num5;
					uint num4 = (num5 = (uint)((~((-1926857391 - (-849669490 - --717680530)) * 1722754007) - -(~(num3 ^ ((~1334327401 + -(803774367 * (~((--388017388 + 965233242) ^ 0x5F3A736E) * 1883220817))) * -1778132901)) - (0x2891E2BA ^ ((-(-(-1369945635 ^ -606831242) + -(1381503451 + 1205521680)) + -95726137) ^ ~((0x41913838 ^ 0x2A5EFC5D) * -2112720053 - (~(--1128275199) ^ -(-2092597657 * 644207055))))))) * -2136450001)) % 3;
					uint num68 = num4;
					int num69 = 0;
					_ = 0;
					for (int num70 = 0; num70 < 1; num70++)
					{
						num69 *= 64984457;
					}
					if (num68 == (uint)num69)
					{
						break;
					}
					uint num71 = num4;
					int num72 = -1027119012;
					_ = 0;
					for (int num73 = 0; num73 < 1; num73++)
					{
						num72 ^= -1027119010;
					}
					if (num71 != (uint)num72)
					{
						uint num74 = num4;
						int num75 = 1123345797;
						_ = 0;
						for (int num76 = 0; num76 < 2; num76++)
						{
							num75 = num75 - -173049456 + -734722354;
							num75 = ~(~num75);
						}
						if (num74 == (uint)num75)
						{
						}
						return;
					}
					_003C_003Et__builder.SetResult(result);
					int[] array16 = new int[5];
					array16[0] = 375576349;
					array16[1] = -438765921;
					array16[2] = 1857280402;
					array16[3] = -1380101550;
					array16[4] = -1150841132;
					array16[4] = array16[3] ^ 0xBB85036;
					array16[3] = array16[1] ^ -1176502589;
					int[] array17 = new int[7] { 1163456891, -422272655, -198272684, -829046006, 88412769, -847382696, 678641600 };
					int[][] array18 = new int[2][] { array16, array17 };
					array17[3] = array18[0][0] ^ 0x5E13F53A;
					array17[1] = array17[0] ^ -1694013652;
					array17[5] = array17[2] ^ -1056224030;
					array17[5] = array17[1] ^ 0x56EC4F17;
					int num77 = array18[1][3] ^ -930650081;
					num67 = (int)((num5 * 1907899197) ^ 0x17CF24F6) ^ num77;
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

		static void _003F_0024_005E_0029_003F_0024_002F_0024(ContentDialog P_0, object P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1612109402;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(~(num2 ^ (-(-((0x50A5E945 ^ -((-1878597011 + -614740935) * -1308943641)) + (-(-(1570805418 - 565630242)) - (~-2101027360 + (1514104176 - 2032537139) + ~-1883857884 * -1262251501))) ^ (-(-(~189525463 - 1307165393)) * 1608902469)) * 1321617737))) - (~((-(-690356378 ^ -603302099) * 1452280049) ^ 0x4916A576) ^ (-(985176890 * -67847213 * 914187599 + ~(-1211302476 - -1411275596)) - -1334664171 * ((-843750334 ^ 0x184B16BD) - -836772985 * 1881508539))) - ((0x2D88DFBE ^ -254462956) * -1036818993 + (-(--1536876913) + 142209871 - -(1618099191 - -238384340 - -391218870))))) % 3;
						int num5 = 2;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -(num5 - ~-1716971456);
							num5 = ~(-num5);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -45193979;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 += 45193980;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 0;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -(~num9);
								num9 = ~-1880184947 - num9 + 380782112;
							}
							if (num3 == (uint)num9)
							{
							}
							return;
						}
						P_0.Title = P_1;
						int[] array = new int[6];
						array[0] = -895850517;
						array[1] = 1572126813;
						array[2] = -179543139;
						array[3] = -199938266;
						array[4] = -1040496959;
						array[5] = 2131660702;
						array[1] = array[2] ^ -881246032;
						array[4] = array[1] ^ -1447208861;
						int[] array2 = new int[5];
						array2[0] = -2135195338;
						array2[1] = -1713450356;
						array2[2] = 368935662;
						array2[3] = 468733904;
						array2[4] = -593366109;
						array2[2] = array[2] ^ -4651770;
						array2[0] = array2[2] ^ -1064228377;
						array2[1] = array2[2] ^ 0x5613C6D6;
						int num11 = array2[2] ^ 0x5BA43D15;
						num = (int)((num4 * 1722607689) ^ 0x434D8B84) ^ num11;
					}
				}
			}
		}

		static void _002D_002D_0021_0040_003E_0040_0040_0028(ContentControl P_0, object P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 1846931368;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((615213067 + -1645383832 - ~(~(~(num2 - -(-(852508126 + (734901931 + (-(581277052 * 2008224551) + ~1191478090))))) ^ (~(709463123 * -940668573) - (-(-(-(-634767241 * 2111111723))) - -687721070 + -152854084)) ^ ~(-(~(-2001815933) - (--860416727 - ~437586312)) + ~(1457440067 + (0x44059096 ^ -1698903915)))) ^ -(-(582168347 * 1894762981)) ^ ((-41728064 ^ -12733427) + (-261099892 ^ -623512655)))) ^ -169860404)) % 3;
						int num5 = 1601325830;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 ^= 0x5F724B04;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 418218299;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 = 418218300 - num7;
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
						P_0.Content = P_1;
						int[] array = new int[4];
						array[0] = -1995360408;
						array[1] = -930240475;
						array[2] = 1838248940;
						array[3] = -1290444872;
						array[3] = array[1] ^ -1980981804;
						array[2] = array[0] ^ 0x507D6EAA;
						int[] array2 = new int[6];
						array2[0] = 7855674;
						array2[1] = 536659798;
						array2[2] = -505571200;
						array2[3] = 1483866376;
						array2[4] = 1716040435;
						array2[5] = 1298458276;
						array2[5] = array[0] ^ 0x56E11088;
						array2[4] = array2[2] ^ 0x3AE85BDA;
						array2[3] = array2[2] ^ -1383767992;
						int num11 = array2[5] ^ 0x5E2D3B76;
						num = ((int)num4 * -1447993539) ^ 0x2D79AA60 ^ num11;
					}
				}
			}
		}

		static void _003F_005E_003C_0040_0024_0029_005E_002D(ContentDialog P_0, string P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -10652433;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(~((num2 ^ (-(~(--2016593293)) ^ (-((-2126010304 ^ (-392817203 + -2119667477 * -1931110710 - (--2129039466 + (-1734566539 - -523949437)))) * -1604319513) * -772221493 - 1231836187 * -(~((-986366280 ^ -197547848) - (-1449983075 - 354627494 + --1974181233) - ~(1025735817 * --1145529746)))))) - (~(-(~(-661079762 + -73033569 - (0x32F14907 ^ -1204236042)) - ((0x31685BA1 ^ -1943952650) - -718374832)) * 503218745) - (--1293411150 + -1305741036))) - ((-(-(-86805029 ^ 0x57890ACF)) - (-(~-1476702435) ^ -190366404 ^ -(-1183151808 - -1106066786 * 1038892587))) ^ ((-1856862170 ^ 0x5B04EB12) + (-1314380362 - (-1534040719 + (--2131612545 ^ -86255424))))) + --1527851751) - -(~(39432604 + -2146741272)))) % 3;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = num5 - ~-21970347 - 1176372297;
							num5 = -(num5 - ~1403792240);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1327687787;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 += -1327687786;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1374291964;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 -= -1374291966;
							}
							if (num3 == (uint)num9)
							{
							}
							return;
						}
						P_0.PrimaryButtonText = P_1;
						int[] array = new int[6];
						array[0] = 647641495;
						array[1] = 822196806;
						array[2] = 1599518929;
						array[3] = -1871812244;
						array[4] = 17699001;
						array[5] = -1379495820;
						array[4] = array[1] ^ -1270555801;
						array[0] = array[4] ^ -676936162;
						array[0] = array[1] ^ 0x35769BA2;
						int[] array2 = new int[6] { -2090887475, 1005890748, -963363651, -1847476061, 1373019481, 942725593 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[2] = array3[0][5] ^ -1282248168;
						array2[0] = array2[2] ^ 0x28E15620;
						array2[4] = array2[0] ^ 0x54B81B2B;
						array2[0] ^= 701330720;
						int num11 = array3[1][2] ^ -310531658;
						num = ((int)num4 * -1958361444) ^ -1562293664 ^ num11;
					}
				}
			}
		}

		static void _005E_0021_002D_0026_0023_003E_003F_003F(ContentDialog P_0, string P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1392763788;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(1091942866 - (~(975600256 - ~(((num2 ^ (1973723721 * (310927611 * (~(-1907889734 * -209978257) + (-1939508043 + ~(2114286789 - -965986262) - (-(1627335673 - -2082058403) - (-1089655056 + 660198612 - 208208982)))) - -(-938997401 * (-1198698315 * ~(-(-893408135 - -59057785)))) + ((-1191442179 * -(1297951223 * ((-1444241858 ^ -886393306) * -1409053287))) ^ -2131510257)))) * -916556725 + -1420563774) ^ (-787658353 ^ (1399172221 * ~(-(524519138 - 1890548295) + -1931087259)))) + ~(~(2081527535 * 2138230880))) + -872079515 * -1636919281))) % 3;
						int num5 = -377691438;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 = -377691438 - num5;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -717380832;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 -= -717380834;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1275876447;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~num9 + 873003324;
								num9 = -1797242511 - 115176037 - num9;
							}
							if (num3 == (uint)num9)
							{
							}
							return;
						}
						P_0.CloseButtonText = P_1;
						int[,] array = new int[3, 3];
						array[0, 0] = -1905627846;
						array[0, 1] = 1962216905;
						array[0, 2] = -726396630;
						array[1, 0] = -2039082426;
						array[1, 1] = 1849694927;
						array[1, 2] = 731377978;
						array[2, 0] = -85979892;
						array[2, 1] = 1592350131;
						array[2, 2] = 1249741929;
						array[0, 2] = array[1, 2] ^ 0x2F384638;
						array[2, 1] = array[2, 2] ^ 0x46CCC885;
						array[2, 1] = array[2, 0] ^ 0x685F3257;
						int num11 = array[2, 1] ^ -2065424810;
						num = (int)((num4 * 11000656) ^ 0x382EBF30) ^ num11;
					}
				}
			}
		}

		static void _0028_0029__0024_0024_002F_003E_003F(ContentDialog P_0, ContentDialogButton P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 582379188;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(-(-(-1058257037 - -1671193454) + (-1129857236 - 1798942708 - ~834329720)) - (~(~(~(num2 - -(0x11BCE244 ^ (248986091 * (332599675 * (-565284679 * (-167088439 * -171442543))) + (-(-(1737123279 - 2109659019 + -372768081 * 1652395493)) - -693889724) + --1386455125))))) + ((-805530519 + -(-493217707 ^ -1538340139)) ^ -655713210))) ^ 0x78639390)) % 3;
						int num5 = -67117184;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 -= 354171048 - -1495089097;
							num5 = -(num5 ^ -2021256630);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -410649922;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = (num7 ^ -1794411495) + 1142024810;
							num7 = (num7 * 125532253) ^ -744835958;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1508940353;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 *= 1545369025;
							}
							if (num3 == (uint)num9)
							{
							}
							return;
						}
						P_0.DefaultButton = P_1;
						int[] array = new int[4] { -1999743349, 1096657482, 286375599, -608179128 };
						array[1] ^= 847590711;
						array[2] = array[0] ^ 0x316E61B6;
						array[0] = array[2] ^ -1029315732;
						int[] array2 = new int[6] { -611419652, -1157767753, 553761587, 1706209780, 2015957559, 76001719 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[4] = array3[0][3] ^ -1098355298;
						array2[3] = array2[5] ^ -1521184014;
						array2[0] = array2[2] ^ -1776549661;
						int num11 = array3[1][4] ^ 0x7B3CE6ED;
						num = (int)((num4 * 998810055) ^ 0x283F1E4) ^ num11;
					}
				}
			}
		}

		static UIElement _0029_0029_0029_002F_0025_005E_0024_0026(Window P_0)
		{
			UIElement content = default(UIElement);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 2111039847;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~((((-num2 + -((-1898992068 ^ (-((--1190641978 - (444891340 - -823891799)) * 1530567815) - -85398030)) + (-((--1277179762 ^ -411895669) + (904159179 - 1183847054 - 1538133445) + (417287074 + 1839575439 + (0x561A33A9 ^ -904564013) + (-1076677426 + 1080334768) * -147705815)) + 620617691 * -(-576735287 * (987666431 * 1711976062) - ~(1128152613 * 336061021))))) * 1250667691 * -2038069645 - ~(-(-((-546484725 ^ 0x35A2C676) * -1916953515))) - -1590521543 * (-1289970891 ^ -111847500)) ^ 0x3D99BBFB) * -2142731383 - (-1096793670 - -365171693)))) % 3;
						int num5 = -18766741;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 -= -18766741;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1685382561;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = num7 + (-241001453 ^ -128034064) + -959503120;
							num7 = ~num7 * 317317107;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1265598524;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 ^= -1265598522;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						content = P_0.Content;
						int[] array = new int[6];
						array[0] = 1730687162;
						array[1] = 293956872;
						array[2] = -53959935;
						array[3] = -1668055494;
						array[4] = -152305281;
						array[5] = -1100489273;
						array[3] = array[2] ^ 0x18637886;
						array[4] = array[5] ^ -2142322144;
						array[3] ^= 2086927237;
						int[] array2 = new int[4];
						array2[0] = 1698523215;
						array2[1] = 739897248;
						array2[2] = 1927295012;
						array2[3] = -1783446412;
						array2[0] = array[5] ^ 0x774E7783;
						array2[1] ^= 2134608372;
						array2[3] = array2[1] ^ 0x78A76843;
						int num11 = array2[0] ^ 0x79EA7EB2;
						num = (int)((num4 * 1406929949) ^ 0x67295982) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return content;
		}

		static XamlRoot __0023_0024___0029__002A(UIElement P_0)
		{
			XamlRoot xamlRoot = default(XamlRoot);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 1631640474;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(-(0x7D79AC58 ^ (-(-1847548147 * 118043318) ^ -1218142513)) - (-(-num2 - -((1384031559 * -(~(~(1242024732 * 1321300043)) + ((0x40332212 ^ -2093730306) + (~1121448557 + (-1584934700 - 227429091))))) ^ -484168113)) + ~(-59325914 ^ (1113202145 + (1171307942 + -(0x6EB46F24 ^ 0x36B8B608)))))) - -1129355826 * -1109606347 + 1590037763 * -1625293221)) % 3;
						int num5 = 862486856;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 ^= 0x3368814A;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -1176602023;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 -= -1176602024;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -8;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 ^= -1223897284;
								num9 = -num9;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						xamlRoot = P_0.XamlRoot;
						int[] array = new int[4];
						array[0] = 1994776601;
						array[1] = -2145829257;
						array[2] = -751016451;
						array[3] = 1523171330;
						array[2] = array[3] ^ 0x2BEDCE89;
						array[0] = array[2] ^ -1900765292;
						int[] array2 = new int[6] { -1319333614, -857541140, 1628689117, 943927853, 289237724, 2134211959 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[4] = array3[0][1] ^ 0x20C767BD;
						array2[5] = array2[1] ^ -268812935;
						array2[3] ^= 1384520034;
						int num11 = array3[1][4] ^ -1033528074;
						num = ((int)num4 * -1700853092) ^ -1046373628 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return xamlRoot;
		}

		static void @_0026_002B_003E_002B_002B_003F_003F(UIElement P_0, XamlRoot P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 921637850;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(~(-((~(-1835051626 ^ -1056345470) - ((-num2 ^ (-(~51211877) - ((-121188387 * (-850407239 * ((-(-1316966503) - 283782442) ^ 0x29FCF232))) ^ -(-656512330 - -(~1318404688))))) - -1290036889 * (-(0x305C6069 ^ 0x34EAF9E1) * -236898167))) ^ (741311527 * (-851167633 ^ 0x3BFFAF0) + (-117655749 ^ (-(1499681203 - -1181301724) ^ 0x82EE9EC))))) * -1890269911) - -672163462)) % 3;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 *= -1702148051;
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
							int num9 = -593488811;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 ^= -593488812;
							}
							if (num3 == (uint)num9)
							{
							}
							return;
						}
						P_0.XamlRoot = P_1;
						int[] array = new int[6] { -2146892655, -1057743269, -2026950886, 810574114, 1877939137, 1308134268 };
						array[5] ^= -1169228335;
						array[5] ^= -226681915;
						int[] array2 = new int[4];
						array2[0] = 333421144;
						array2[1] = -1848539412;
						array2[2] = 60586506;
						array2[3] = 58233078;
						array2[1] = array[3] ^ 0x30727FA6;
						array2[0] = array2[2] ^ -565915533;
						array2[3] = array2[2] ^ -149599549;
						int num11 = array2[1] ^ -586485484;
						num = ((int)num4 * -1104915304) ^ 0x32F882C8 ^ num11;
					}
				}
			}
		}

		static IAsyncOperation<ContentDialogResult> _003E_0025_002D_0026_002B_0023_0028_005E(ContentDialog P_0)
		{
			IAsyncOperation<ContentDialogResult> result = default(IAsyncOperation<ContentDialogResult>);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -41016624;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(((~(~(~(1172884112 + (-1178730011 ^ (-6102824 ^ -826562491))) ^ -565949978) - ~(num2 * -1378512975)) * 1920774489) ^ -951550188) - --432498615 * -1767212623) * -1036602879 * 1177619483)) % 3;
						int num5 = -1903760084;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 ^= -1903760082;
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
							int num9 = 531166346;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = num9 * 1236171753 - -796085834;
								num9 -= 2122471588 - -1395501511;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.ShowAsync();
						int[] array = new int[5];
						array[0] = 964405800;
						array[1] = 605226582;
						array[2] = -1657572779;
						array[3] = -1023914106;
						array[4] = -423125329;
						array[2] = array[3] ^ 0x2F36BCD0;
						array[3] ^= 466571961;
						int[] array2 = new int[6];
						array2[0] = 1091575269;
						array2[1] = 1679057939;
						array2[2] = 1042290421;
						array2[3] = 467874924;
						array2[4] = 64386945;
						array2[5] = -1370204883;
						array2[1] = array[1] ^ 0x14C69B2D;
						array2[4] = array2[5] ^ -774612575;
						array2[3] = array2[0] ^ -901976132;
						array2[5] = array2[4] ^ 0x31A58532;
						int num11 = array2[1] ^ 0x2EED084C;
						num = ((int)num4 * -507129179) ^ 0xE33731E ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}
	}

	private string _currentAssemblyName = string.Empty;

	private string _currentLicenseDisplay = string.Empty;

	private string _currentLicenseFull = string.Empty;

	private ShellSection _currentSection;

	private bool _hasLoadedAssembly;

	private bool _isAuthenticated;

	private int _selectedMethodCount;

	private string _shellHeader = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-552 + 243)];

	private string _shellSubheader = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xB8B ^ 0xABE];

	private string _titlebarSubtitle = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[2359 - 2063 + 14];

	private bool _updateAvailable;

	private string _updateMessage = string.Empty;

	private string _updateUrl = string.Empty;

	private string _windowTitle = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[2959 - 2702 + 54];

	private int? _licenseRemainingDays;

	private string? _licensePlanType;

	public ObservableCollection<ActivityEntry> ActivityEntries { get; } = new ObservableCollection<ActivityEntry>();

	public string CurrentAssemblyName
	{
		get
		{
			return _currentAssemblyName;
		}
		private set
		{
			SetProperty(ref _currentAssemblyName, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xE4D ^ 0xF75]);
		}
	}

	public string CurrentLicenseDisplay
	{
		get
		{
			return _currentLicenseDisplay;
		}
		private set
		{
			SetProperty(ref _currentLicenseDisplay, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xD2C ^ 0xC15]);
		}
	}

	public string CurrentLicenseFull
	{
		get
		{
			return _currentLicenseFull;
		}
		private set
		{
			SetProperty(ref _currentLicenseFull, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[3304 - 3051 + 61]);
		}
	}

	public unsafe ShellSection CurrentSection
	{
		get
		{
			return _currentSection;
		}
		private set
		{
			if (!SetProperty(ref _currentSection, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x710 ^ 0x71D]))
			{
				return;
			}
			while (true)
			{
				int num = 1882663369;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-1231110479 * 544983523) - ~((--1352687982 - (~(num2 + ((-183127593 * (722573249 * (((-982568101 ^ 0x1D0C37F4) - -318237867 + ~(1587196818 - 835178545) + 387041351 * ~(-1987927829 - -1060731754) - 483439840) ^ -550611624))) ^ (~(0x7E96E0B ^ ~(-(1189536587 * -2106356302)) ^ ((--2058719452 - ~-741986687 + (0x27E0F060 ^ -642341130) * 101977895 - -514917045 * (0xABF6D0B ^ --1413386157)) ^ 0x3AA2386B)) * 1883352099)) + ((((0x250EACC ^ 0x69949C06) - 783509097 + -(-887948351 ^ 0x388978FC)) ^ (-233297728 ^ ((-1972320431 - ~-1559694483) ^ 0x6C41971)) ^ (-(1850217415 * -1467616416) ^ 0x2F0B523E)) - 897358523 * ((-(-902399311 ^ -651476246) ^ -(~-1885652695)) * -400570039) + ((-1331892169 * -(~(~(0x38DA59C6 ^ 0x3DDC33ED) - 603009090))) ^ (-(-(-1535249151 + (1040465694 - 1739304690) - -(-285017923 * -2128457713))) ^ (1611973145 * (-(~-2005344286) - -1180520560 * -498531269 + ~-1327555376)))))) + ~(~((0x1D8DC867 ^ 0x2E8178B5) - -819698873)))) * 160914179))) % 5;
					int num5 = -20572015;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 += 20572019;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 455168093;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x1B21505C;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 513103184;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (-1070299647 * -494617121 - num9) * 1976771591;
							num9 = -num9 - 874515057;
						}
						if (num3 != (uint)num9)
						{
							int num11 = -1117312580;
							_ = 0;
							for (int num12 = 0; num12 < 2; num12++)
							{
								num11 = (num11 + 497959195 * -68283087) * -1061830845;
								num11 = ~num11 + -1311417105;
							}
							if (num3 != (uint)num11)
							{
								int num13 = -1865302601;
								_ = 0;
								for (int num14 = 0; num14 < 1; num14++)
								{
									num13 ^= -1865302604;
								}
								if (num3 == (uint)num13)
								{
								}
								return;
							}
							_0026_0025_003C_0021_0021_0024_0025_002F((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4189 - 3936 + 64]);
							int[] array = new int[4];
							array[0] = -535964320;
							array[1] = 148252603;
							array[2] = -2106568436;
							array[3] = 1817550731;
							array[0] = array[3] ^ -1677774936;
							array[2] ^= 698380936;
							int[] array2 = new int[4] { 2019041118, -1879759980, -2018202738, 769817788 };
							int[][] array3 = new int[2][] { array, array2 };
							array2[1] = array3[0][1] ^ -405914790;
							array2[3] = array2[1] ^ -1053487058;
							array2[3] ^= -1920654685;
							array2[3] ^= -1526744135;
							int num15 = array3[1][1] ^ -1600105986;
							num = ((int)num4 * -1747957251) ^ 0x18F1852E ^ num15;
						}
						else
						{
							_0026_0025_003C_0021_0021_0024_0025_002F((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(296 + sizeof(int)) ^ sizeof(Guid)]);
							int[,] array4 = new int[4, 4];
							array4[0, 0] = -789876183;
							array4[0, 1] = 789254591;
							array4[0, 2] = 2121650176;
							array4[0, 3] = 556877097;
							array4[1, 0] = 1493360637;
							array4[1, 1] = 1472783115;
							array4[1, 2] = -1660402854;
							array4[1, 3] = -1768081532;
							array4[2, 0] = 1240762735;
							array4[2, 1] = 1639376008;
							array4[2, 2] = 547773154;
							array4[2, 3] = -378693913;
							array4[3, 0] = -508611127;
							array4[3, 1] = -582103306;
							array4[3, 2] = -829784207;
							array4[3, 3] = 1530225706;
							array4[0, 2] = array4[2, 0] ^ 0x16291443;
							array4[3, 3] = array4[2, 0] ^ 0x1E188CF;
							array4[0, 2] = array4[2, 1] ^ -761184659;
							array4[2, 3] = array4[3, 0] ^ -551796070;
							int num16 = array4[2, 3] ^ -990718096;
							num = ((int)num4 * -117326868) ^ 0x282D6468 ^ num16;
						}
					}
					else
					{
						_0026_0025_003C_0021_0021_0024_0025_002F((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x494F ^ 0x4874]);
						int[] array5 = new int[6];
						array5[0] = 957128330;
						array5[1] = -493009248;
						array5[2] = -1552581970;
						array5[3] = 1362177204;
						array5[4] = -264134020;
						array5[5] = -554530696;
						array5[1] = array5[4] ^ -690043186;
						array5[3] = array5[2] ^ -1437297904;
						int[] array6 = new int[7];
						array6[0] = -1730049206;
						array6[1] = 140702596;
						array6[2] = -203649237;
						array6[3] = 1129834626;
						array6[4] = -831171967;
						array6[5] = 2111887200;
						array6[6] = 1068438802;
						array6[0] = array5[4] ^ 0x211CA715;
						array6[6] = array6[5] ^ -960108504;
						array6[4] ^= -1050647097;
						int num17 = array6[0] ^ -701739150;
						num = ((int)num4 * -1675102589) ^ -1421017176 ^ num17;
					}
				}
			}
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
			SetProperty(ref _hasLoadedAssembly, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[349 - 6 - 16 - 9]);
		}
	}

	public unsafe bool IsAuthenticated
	{
		get
		{
			return _isAuthenticated;
		}
		private set
		{
			if (!SetProperty(ref _isAuthenticated, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x3BB8 ^ 0x3BB6]))
			{
				return;
			}
			while (true)
			{
				int num = -348586258;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-685731491 * ~-1457532771 - ((-2055541703 * (-1039168077 * -312964974) - (0x3D4AC53E ^ -1172013677) * 645994567) ^ 0xEE97168) - (-(num2 ^ (1934986089 - ((((259084306 - (1684946923 + 1336828292 - --54813472)) ^ -2048337693) * 1337684437) ^ ((-1870860131 - 1470099046 + 369386401 * -1110537659 + ((-279423470 ^ 0x2BD3CC7D) + (-809631095 - -1186910490)) - ((-464120479 + 682957632) ^ 0x7AF5CBEB)) * 1203444021)) - -(~((2012122321 - 981498309 - ((--1004022283 - 2068392404) ^ (-37008504 ^ -881234183))) * 1061943837)) - (1619472437 * (-1082090305 * (-761049966 * -1375243729) - (~-1446471828 * -545158093 + (-503900471 + ~-1118871880))) - ((-(593509940 * 947314819 - (1574666016 - -815999904)) * -1159517113) ^ ((-(1132617345 - -346071093) - (-865305198 ^ -502323635)) ^ -1956368759)) + (311567800 - (-(1990308806 * -787592517) ^ 0x353FDA58 ^ ((-182775774 - 1844137619 - --1722368947) ^ -43060516)) - 769863348) + (-399426089 * ((-927549843 * (706787571 - -(1064602797 * -1595061381))) ^ -1495261695) + 258961817 * (~(-1141735544 ^ -1628988757) + 379791242))))) + -1885083337 * 132932645) - ~((140195027 - 1196681030 - -355689959 + ~(-1335460276)) ^ 0x12BE7B18)))) % 3;
					int num5 = 1032853303;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = 1032853303 - num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 417102842;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -1692825771;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -990880439;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 - ~-8622038) ^ -892634441;
							num9 = -(num9 * -1823216189);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					_0026_0025_003C_0021_0021_0024_0025_002F((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(299 + sizeof(int)) ^ sizeof(Guid)]);
					int[,] array = new int[4, 3];
					array[0, 0] = -1491261896;
					array[0, 1] = 912677616;
					array[0, 2] = 331912659;
					array[1, 0] = -1921461697;
					array[1, 1] = 967436285;
					array[1, 2] = 896069573;
					array[2, 0] = 215145308;
					array[2, 1] = -138447732;
					array[2, 2] = -1110641566;
					array[3, 0] = -1914619279;
					array[3, 1] = -1438517522;
					array[3, 2] = 1783293064;
					array[1, 1] = array[1, 0] ^ -1504849656;
					array[2, 1] ^= 1774454211;
					array[3, 0] = array[1, 1] ^ -807999211;
					array[2, 2] = array[2, 0] ^ -300566699;
					int num11 = array[2, 2] ^ 0x517C81FF;
					num = ((int)num4 * -151744633) ^ 0x67B708EC ^ num11;
				}
			}
		}
	}

	public bool IsMethodsSelected => CurrentSection == ShellSection.Methods;

	public bool IsSettingsSelected => CurrentSection == ShellSection.Settings;

	public bool IsSignedOut => !IsAuthenticated;

	public bool IsWorkspaceSelected => CurrentSection == ShellSection.Workspace;

	public int SelectedMethodCount
	{
		get
		{
			return _selectedMethodCount;
		}
		private set
		{
			SetProperty(ref _selectedMethodCount, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xDBA ^ 0xCFA]);
		}
	}

	public string ShellHeader
	{
		get
		{
			return _shellHeader;
		}
		private set
		{
			SetProperty(ref _shellHeader, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x4B9 ^ 0x5F8]);
		}
	}

	public string ShellSubheader
	{
		get
		{
			return _shellSubheader;
		}
		private set
		{
			SetProperty(ref _shellSubheader, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[2013 - 1747 + 56]);
		}
	}

	public bool UpdateAvailable
	{
		get
		{
			return _updateAvailable;
		}
		private set
		{
			SetProperty(ref _updateAvailable, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-733 + 409)]);
		}
	}

	public string UpdateMessage
	{
		get
		{
			return _updateMessage;
		}
		private set
		{
			SetProperty(ref _updateMessage, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[2792 - 2502 + 34]);
		}
	}

	public string UpdateUrl
	{
		get
		{
			return _updateUrl;
		}
		private set
		{
			SetProperty(ref _updateUrl, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xFE9 ^ 0xEAC]);
		}
	}

	public string TitlebarSubtitle
	{
		get
		{
			return _titlebarSubtitle;
		}
		private set
		{
			SetProperty(ref _titlebarSubtitle, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x7D19 ^ 0x7C5F))]);
		}
	}

	public string WindowTitle
	{
		get
		{
			return _windowTitle;
		}
		private set
		{
			SetProperty(ref _windowTitle, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-502 + 489)]);
		}
	}

	public int? LicenseRemainingDays
	{
		get
		{
			return _licenseRemainingDays;
		}
		private set
		{
			SetProperty(ref _licenseRemainingDays, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0xB872 ^ 0xB935))]);
		}
	}

	public string? LicensePlanType
	{
		get
		{
			return _licensePlanType;
		}
		private set
		{
			SetProperty(ref _licensePlanType, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x4F2 ^ 0x5BA))]);
		}
	}

	public string LicenseExpiryDisplay
	{
		get
		{
			if (!_licenseRemainingDays.HasValue)
			{
				goto IL_0013;
			}
			goto IL_078c;
			IL_0013:
			int num = -2033185226;
			goto IL_0018;
			IL_0018:
			DefaultInterpolatedStringHandler defaultInterpolatedStringHandler = default(DefaultInterpolatedStringHandler);
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-((~(-num2) ^ ~(~(-249292916 + (-(~-1215719978 - -2006381760) + (~(--2044035043) - 2144127347))))) * 2039896307) ^ (-1177728217 * -1765375539 * -87176873 + (-2024770635 ^ 0x3C022A52) - -(-726435403 - (-1801689345 - -1125567749))))) % 6;
				int num5 = -1161454581;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = (num5 * 1431426625) ^ 0x58544933;
					num5 = -num5 - -176231524;
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
					int num9 = -1389275203;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = -1727150296 - (num9 ^ -265549365);
						num9 = -(num9 * -472666485);
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
							int num13 = -1988056964;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = ~(num13 * -711918473);
								num13 = -num13 * -333877711;
							}
							if (num3 != (uint)num13)
							{
								int num15 = 817909902;
								_ = 0;
								for (int num16 = 0; num16 < 2; num16++)
								{
									num15 = (475075467 + -1677931109 - num15) ^ -501557344;
									num15 = ~num15;
								}
								if (num3 != (uint)num15)
								{
								}
								return defaultInterpolatedStringHandler.ToStringAndClear();
							}
							defaultInterpolatedStringHandler.AppendLiteral(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x92D ^ 0x867]);
							int[] array = new int[5];
							array[0] = -427564556;
							array[1] = 1585304039;
							array[2] = -1662461157;
							array[3] = -1171195674;
							array[4] = -479664825;
							array[3] = array[4] ^ 0x2C83A1C5;
							array[1] ^= 1290361511;
							array[4] = array[3] ^ -304356804;
							int[] array2 = new int[4];
							array2[0] = -3819511;
							array2[1] = 1244610069;
							array2[2] = 154063366;
							array2[3] = -1761519778;
							array2[3] = array[0] ^ 0x5515D809;
							array2[2] ^= -2037177938;
							array2[0] = array2[3] ^ -809184140;
							array2[1] = array2[3] ^ 0x1CA41441;
							int num17 = array2[3] ^ -109396975;
							num = (int)((num4 * 1599273026) ^ 0x3980785C) ^ num17;
						}
						else
						{
							defaultInterpolatedStringHandler.AppendFormatted(_licenseRemainingDays.Value);
							int[] array3 = new int[5];
							array3[0] = -507297001;
							array3[1] = -484287385;
							array3[2] = -57734482;
							array3[3] = 360730677;
							array3[4] = 202708223;
							array3[2] = array3[4] ^ -1761862374;
							array3[4] = array3[1] ^ -1642381207;
							array3[1] = array3[0] ^ -384030176;
							int[] array4 = new int[6];
							array4[0] = -1477775359;
							array4[1] = 780030399;
							array4[2] = -2023368771;
							array4[3] = -1439268252;
							array4[4] = 549813643;
							array4[5] = 880396646;
							array4[5] = array3[0] ^ 0x1D2EADEF;
							array4[1] = array4[0] ^ 0x29728874;
							array4[0] = array4[3] ^ -404109606;
							int num18 = array4[5] ^ 0x61A19D84;
							num = ((int)num4 * -1869697118) ^ -1305473546 ^ num18;
						}
						continue;
					}
					goto IL_078c;
				}
				return _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-561 + 231)];
			}
			goto IL_0013;
			IL_078c:
			defaultInterpolatedStringHandler = new DefaultInterpolatedStringHandler(15, 1);
			num = 838017195;
			goto IL_0018;
		}
	}

	public unsafe string LicensePlanDisplay
	{
		get
		{
			if (_0026_003E_002F_0026_0023_0026_0024_0021(_licensePlanType))
			{
				goto IL_0013;
			}
			goto IL_03a0;
			IL_0013:
			int num = -1592442551;
			goto IL_0018;
			IL_0018:
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)(((-(num2 * 1753719007) * -816322527) ^ ~((-1791792324 ^ --1160371192) - 1206656397)) - -(-1631185820 ^ -(-586919277 * -772171488)))) % 4;
			int num5 = -1;
			_ = 0;
			for (int num6 = 0; num6 < 1; num6++)
			{
				num5 = ~num5;
			}
			if (num3 == (uint)num5)
			{
				goto IL_0013;
			}
			int num7 = -1;
			_ = 0;
			for (int num8 = 0; num8 < 1; num8++)
			{
				num7 = -num7;
			}
			char reference = default(char);
			if (num3 != (uint)num7)
			{
				int num9 = -98501636;
				_ = 0;
				for (int num10 = 0; num10 < 1; num10++)
				{
					num9 += 98501639;
				}
				if (num3 != (uint)num9)
				{
					int num11 = -1313843510;
					_ = 0;
					for (int num12 = 0; num12 < 2; num12++)
					{
						num11 = num11 ^ -1565609918 ^ 0x15031D43;
						num11 = (num11 ^ -614297885) * -1173837027;
					}
					if (num3 != (uint)num11)
					{
					}
					return _002A_0029_0026_005E_0029_003D_002D_002F(new ReadOnlySpan<char>(in reference), _002D_003E_003C_003E_0029_0025_002A_002A(_003D_0028_003C_002D_0024_0040_002A_0029(_002F__003F_0024_002A_002B_005E_002A(_licensePlanType, 1))));
				}
				goto IL_03a0;
			}
			return _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(341 + sizeof(int)) ^ sizeof(Guid)];
			IL_03a0:
			reference = _003D_0040_003C__0025_0028_0024_002D(_0026_003E_003E_0028_005E_005E_002F_0025(_licensePlanType, 0));
			num = 1395956194;
			goto IL_0018;
		}
	}

	public AppViewModel()
	{
		while (true)
		{
			int num = -1296944667;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)((((-((num2 - (-(-485789735 * -(~(-(0x24F5653D ^ 0x38CA0956))) + ~(0x15AACA33 ^ -(~(-1327511409 - -1856091045)))) ^ -((2100116028 + (~(-(-720112257 - 1443528934)) + 1878193400)) ^ -1681670330) ^ ~(~(-2059359639 ^ ~(-350683371))))) ^ (-1442279721 * (((-(2091989530 + -1608855934 - 555945218) ^ (-133968014 - ~(--215760240))) - -(~(1034633097 * -753098531) + ~1270342778)) ^ (-(-1664164974 ^ -807981204) ^ ((0x785B301F ^ --1613764863) - (-233261015 ^ 0x4DD734BB)) ^ 0x7391B675)) + -999102973 * -1163641433)) ^ -(-1836357884 ^ ((-674171934 ^ --864640497) - -604324790 + (2112169601 * (1751999262 + -565787668) + -841960246)))) - ~(~(~(0x11D73129 ^ -1540567010) + (-98092558 + 1702949944 - 49324177 * -482904239))) - 1815024625 - ((-1319433219 + -1545835069) ^ -561073677)) * -1486799509 + (0x3C712262 ^ -919227170)) ^ -757048596)) % 4;
				int num5 = 0;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 *= 632364113;
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
					int num9 = 1867052159;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 *= -1070046595;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -3;
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
					ApplySignedOutHeader();
					int[] array = new int[5];
					array[0] = 1744231241;
					array[1] = -2133175073;
					array[2] = -1010776619;
					array[3] = 88415793;
					array[4] = -840672217;
					array[0] = array[2] ^ 0x60C44075;
					array[1] = array[0] ^ 0x6B39AB04;
					int[] array2 = new int[4] { 1167623910, -108625412, 1163512214, -1808926378 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][3] ^ 0x4195F546;
					array2[1] = array2[0] ^ -1126516492;
					array2[1] = array2[2] ^ 0x53968DEE;
					int num13 = array3[1][3] ^ 0x63461E2F;
					num = ((int)num4 * -2004546310) ^ -2141857458 ^ num13;
				}
				else
				{
					Navigate(ShellSection.Workspace);
					int[] array4 = new int[6];
					array4[0] = -394002845;
					array4[1] = -2145682235;
					array4[2] = -120893508;
					array4[3] = -253588432;
					array4[4] = 451971110;
					array4[5] = 1453610332;
					array4[3] = array4[4] ^ -802780253;
					array4[2] = array4[0] ^ 0x1CB63B7A;
					array4[2] ^= 921445362;
					int[] array5 = new int[6] { -246470969, 163558799, 182549216, 1765340140, -1482832882, -1621241640 };
					int[][] array6 = new int[2][] { array4, array5 };
					array5[3] = array6[0][5] ^ 0x613ADEB;
					array5[4] = array5[5] ^ -324675270;
					array5[0] = array5[2] ^ 0x37DFC999;
					int num14 = array6[1][3] ^ 0x68DAFCBC;
					num = ((int)num4 * -967256847) ^ 0x34BD2E01 ^ num14;
				}
			}
		}
	}

	public void AddActivity(string message, SeverityLevel level)
	{
		ObservableCollection<ActivityEntry> activityEntries = ActivityEntries;
		ActivityEntry activityEntry = new ActivityEntry();
		_003E_0025_0029_002D__0024_003D_003C(activityEntry, level);
		_0029_0028_003E_002F_0025_005E_005E_002B(activityEntry, message);
		_0023_0028_003F_002F_005E_002A_002F_0021(activityEntry, _003C_0025_005E_0029_003C_0025_0024_002D());
		activityEntries.Insert(0, activityEntry);
		while (true)
		{
			int num = -257396234;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)((-(~(0x5393AFD1 ^ 0x52AEFB8F)) - num2 * 898421873 - (~(~((-355181836 ^ -623057007) + (2044986476 + 1249046661 - (-1537067198 - 1683634166) + -2107843055))) - 1288149609) - -176984203 * ((1247253443 * (-1822384052 ^ -1192913735) - 1304792724) * 1992292253) - -348312 - (-(~-1862468714 - -1164973917 * 99908761) + -1868748251 * (--1333713224 + (0x524A6BF2 ^ 0x147799CD))) + -731787836) ^ (-1419091392 + ~-1238733732) ^ -2062376248 ^ -1179997344)) % 5;
				int num5 = 1048089368;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 -= 1048089365;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -1000195994;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -(-num7);
					num7 = (num7 - (-805745359 ^ 0x1C83B637)) * 1730830309;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1580325811;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 ^= 0x5E31DBB2;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 0;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 = -num11;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 1759370362;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 -= 1759370358;
							}
							if (num3 == (uint)num13)
							{
							}
							return;
						}
						int num15;
						if (ActivityEntries.Count <= 8)
						{
							num = 112871670;
							num15 = num;
						}
						else
						{
							num = -1537823828;
							num15 = num;
						}
					}
					else
					{
						ActivityEntries.RemoveAt(ActivityEntries.Count - 1);
						num = -442891275;
					}
				}
				else
				{
					int[] array = new int[4] { -825717385, -1149628238, 1968430664, -2032354058 };
					array[3] ^= 386925186;
					array[3] = array[1] ^ 0x6BF34D4;
					array[3] = array[1] ^ 0x4E172E36;
					int[] array2 = new int[4] { 1460942928, -752203240, -818096475, 1861618580 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][2] ^ 0x32357AA9;
					array2[2] = array2[3] ^ -701331223;
					array2[3] = array2[0] ^ -357349503;
					array2[3] = array2[1] ^ -1425773208;
					int num16 = array3[1][1] ^ -1560500460;
					num = ((int)num4 * -1702021353) ^ 0x7C212AD8 ^ num16;
				}
			}
		}
	}

	[AsyncStateMachine(typeof(_003CShowResetHwidConfirmationAsync_003Ed__81))]
	public Task<bool> ShowResetHwidConfirmationAsync()
	{
		_003CShowResetHwidConfirmationAsync_003Ed__81 stateMachine = default(_003CShowResetHwidConfirmationAsync_003Ed__81);
		stateMachine._003C_003Et__builder = AsyncTaskMethodBuilder<bool>.Create();
		while (true)
		{
			int num = 1019170649;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-((-1526504243 - (-(-(-1542043531 - ~(--2002096976)) - ~(-1282949215 ^ (-1888876625 + -500960340))) - ~(~(-2128694341 * (-254239082 * 47073377)) - ~(-(-615433743 ^ -1340604284)) * -874199435) - -(num2 * 1451762679)) + (-26586385 ^ (149779845 - (-899006239 - -444818479) + -(~464481354)) ^ -971786819)) ^ ((-1555931387 ^ (--1005327424 ^ -1169000709)) + ((0x3EAB429B ^ -1029706654) - -1699143967 * 591860307) * 1442077715)))) % 4;
				int num5 = 1727348747;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = -(num5 * 523506953);
					num5 = -num5 * 455649659;
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
						num9 = 1466046141 - ~num9;
						num9 = 1608450191 - -1173987267 - num9 - 350355085;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 416290592;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 -= 416290590;
						}
						if (num3 != (uint)num11)
						{
						}
						return stateMachine._003C_003Et__builder.Task;
					}
					stateMachine._003C_003Et__builder.Start(ref stateMachine);
					int[] array = new int[5];
					array[0] = -2145114643;
					array[1] = 1213654652;
					array[2] = 923883181;
					array[3] = 106112687;
					array[4] = -1865035558;
					array[4] = array[0] ^ 0x143557D8;
					array[4] = array[1] ^ -1144991479;
					array[3] = array[4] ^ 0x43269DDC;
					int[] array2 = new int[7] { -91749560, 132806358, 1928603623, -2056504285, -576653096, 1102835349, -768049093 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][2] ^ 0x28A32FE7;
					array2[2] = array2[0] ^ 0x6C5E6230;
					array2[6] = array2[5] ^ 0x48E611AC;
					int num13 = array3[1][0] ^ -1187299062;
					num = (int)((num4 * 2049986795) ^ 0xA6D137DCu) ^ num13;
				}
				else
				{
					stateMachine._003C_003E1__state = -1;
					int[] array4 = new int[5];
					array4[0] = 699278408;
					array4[1] = 471703616;
					array4[2] = -1959541362;
					array4[3] = 306522683;
					array4[4] = -1068581679;
					array4[0] = array4[4] ^ 0x1E6FD57B;
					array4[3] = array4[0] ^ 0x71A6FCAB;
					array4[4] ^= 564027272;
					int[] array5 = new int[7] { -1988730256, -2005590183, 989098197, 68018152, 1439029744, 1767478082, -587010636 };
					int[][] array6 = new int[2][] { array4, array5 };
					array5[4] = array6[0][1] ^ 0x7E45852;
					array5[0] = array5[3] ^ 0x35021010;
					array5[6] = array5[0] ^ -225497047;
					array5[2] ^= 1129092061;
					int num14 = array6[1][4] ^ 0x47B7E470;
					num = (int)((num4 * 5539032) ^ 0xF2321238u) ^ num14;
				}
			}
		}
	}

	public void Navigate(ShellSection section)
	{
		CurrentSection = section;
		while (true)
		{
			int num = -866542778;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(-(~((num2 - ~(-(-(1237292723 - ((((-1368666147 * -1670678993) ^ -156799967) * 1427046873) ^ -(1464340628 - 1374212089 * 546784671 + ((-203738295 ^ -1845509441) - --766162153))))))) ^ (((~(-(636314529 * 1008523979)) + -(0x5DD344C7 ^ -1867390457)) ^ -((-1596595527 + -52656856) * -1325509949 * 285070093) ^ -((0x12F34831 ^ -1545477214) + -(-2085828532) * 488455911)) - -1516190474 - (-1321929763 - ~(-(~(-(1574447573 + 1305342457) - (194837294 - 842287869 - ~-382611217))))))))))) % 19;
				int num5 = 805802546;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = num5 - 1725900009 - 287604642;
					num5 = ~num5 ^ 0x5FB7C979;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -7;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 = -num7;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1060115553;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 *= 881061625;
						num9 = ~num9 + -804762705;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 1236714158;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 ^= 0x49B6C2BC;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 1073774626;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = 1523554250 - (num13 - ~-1777247292);
								num13 = -num13 ^ -536924595;
							}
							if (num3 != (uint)num13)
							{
								int num15 = 1766831938;
								_ = 0;
								for (int num16 = 0; num16 < 2; num16++)
								{
									num15 = -num15 * -1300567443;
									num15 = ~(num15 * -1499738463);
								}
								if (num3 != (uint)num15)
								{
									int num17 = -2045263312;
									_ = 0;
									for (int num18 = 0; num18 < 2; num18++)
									{
										num17 = (num17 - (1707905555 - -335615955)) ^ 0x46D78CBE;
										num17 = (num17 * 1340241277) ^ -1798885972;
									}
									if (num3 != (uint)num17)
									{
										int num19 = -10;
										_ = 0;
										for (int num20 = 0; num20 < 1; num20++)
										{
											num19 = ~num19;
										}
										if (num3 != (uint)num19)
										{
											int num21 = -1681263550;
											_ = 0;
											for (int num22 = 0; num22 < 2; num22++)
											{
												num21 = -num21;
												num21 = -(num21 * -859886479);
											}
											if (num3 == (uint)num21)
											{
												return;
											}
											int num23 = 623325855;
											_ = 0;
											for (int num24 = 0; num24 < 2; num24++)
											{
												num23 = ~(num23 * -1243979191);
												num23 = ~(num23 * -71743127);
											}
											if (num3 != (uint)num23)
											{
												int num25 = -2079876911;
												_ = 0;
												for (int num26 = 0; num26 < 2; num26++)
												{
													num25 = (num25 + ~-1376011180) ^ 0x142C3112;
													num25 = -(-num25);
												}
												if (num3 != (uint)num25)
												{
													int num27 = -1513192268;
													_ = 0;
													for (int num28 = 0; num28 < 2; num28++)
													{
														num27 = (num27 - -363667018) * 1040109173;
														num27 = (num27 - (1604702897 + 977411871)) ^ -1557433181;
													}
													if (num3 != (uint)num27)
													{
														int num29 = -11;
														_ = 0;
														for (int num30 = 0; num30 < 1; num30++)
														{
															num29 = ~num29;
														}
														if (num3 != (uint)num29)
														{
															int num31 = 5;
															_ = 0;
															for (int num32 = 0; num32 < 2; num32++)
															{
																num31 = -(num31 + (-770325918 ^ 0x3970C446));
																num31 = ~(~num31);
															}
															if (num3 == (uint)num31)
															{
																return;
															}
															int num33 = 2126234412;
															_ = 0;
															for (int num34 = 0; num34 < 2; num34++)
															{
																num33 = ~(num33 * 610218923);
																num33 = (num33 * -2103198431) ^ 0x66ED554;
															}
															if (num3 != (uint)num33)
															{
																int num35 = -13;
																_ = 0;
																for (int num36 = 0; num36 < 1; num36++)
																{
																	num35 = ~num35;
																}
																if (num3 != (uint)num35)
																{
																	int num37 = 264142029;
																	_ = 0;
																	for (int num38 = 0; num38 < 2; num38++)
																	{
																		num37 = -(num37 ^ -1046575010);
																		num37 = -num37 - 114407024;
																	}
																	if (num3 != (uint)num37)
																	{
																		int num39 = 2124015169;
																		_ = 0;
																		for (int num40 = 0; num40 < 2; num40++)
																		{
																			num39 = ~num39 * -44697645;
																			num39 = ~num39;
																		}
																		if (num3 != (uint)num39)
																		{
																			int num41 = -1701210685;
																			_ = 0;
																			for (int num42 = 0; num42 < 1; num42++)
																			{
																				num41 = -1701210682 - num41;
																			}
																			if (num3 == (uint)num41)
																			{
																			}
																			return;
																		}
																		TitlebarSubtitle = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x182FE ^ 0x183B3))];
																		int[] array = new int[6] { -482177856, 1807568097, 591131674, -2032226642, -1212817301, -1408693292 };
																		array[3] ^= 346106675;
																		array[0] = array[3] ^ 0x2A1E2F7C;
																		int[] array2 = new int[5] { -467967506, -847826466, -1894656145, -1845612378, -514571965 };
																		int[][] array3 = new int[2][] { array, array2 };
																		array2[4] = array3[0][5] ^ -1491665373;
																		array2[1] = array2[4] ^ 0x68EA0137;
																		array2[2] ^= -72959456;
																		int num43 = array3[1][4] ^ -1464988237;
																		num = (int)((num4 * 936928119) ^ 0x707AFDE4) ^ num43;
																	}
																	else
																	{
																		ShellSubheader = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x7C05 ^ 0x7D55))];
																		int[] array4 = new int[7];
																		array4[0] = 1208042689;
																		array4[1] = 559696828;
																		array4[2] = 1537529400;
																		array4[3] = -1305408994;
																		array4[4] = -1622572336;
																		array4[5] = -616431806;
																		array4[6] = 1587965126;
																		array4[5] = array4[6] ^ 0x16A92D83;
																		array4[1] ^= -1422790643;
																		int[] array5 = new int[4];
																		array5[0] = -1394764511;
																		array5[1] = 1471373914;
																		array5[2] = -2081444218;
																		array5[3] = 281418820;
																		array5[0] = array4[4] ^ -1834595070;
																		array5[3] = array5[2] ^ -1175166747;
																		array5[2] = array5[1] ^ 0x14D24F7B;
																		int num44 = array5[0] ^ -642963251;
																		num = ((int)num4 * -1717064246) ^ 0x7B479464 ^ num44;
																	}
																}
																else
																{
																	ShellHeader = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x1C7C ^ 0x1D33];
																	int[] array6 = new int[6] { -981722241, -1490226333, -1835382032, -1555202121, 318197689, 493166008 };
																	array6[0] ^= 382517430;
																	array6[0] = array6[2] ^ -226940518;
																	array6[3] = array6[2] ^ -1607109977;
																	int[] array7 = new int[7] { -1094399970, -463296209, -1554244724, -1840795534, -1625705179, 703509289, -1672377067 };
																	int[][] array8 = new int[2][] { array6, array7 };
																	array7[3] = array8[0][5] ^ -7309234;
																	array7[6] = array7[5] ^ 0x6A3DC150;
																	array7[4] = array7[6] ^ 0xC6E1881;
																	array7[5] = array7[3] ^ 0x6E30193A;
																	int num45 = array8[1][3] ^ 0x3B18093F;
																	num = (int)((num4 * 1931834989) ^ 0x9482DB63u) ^ num45;
																}
															}
															else
															{
																WindowTitle = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x11537 ^ 0x11400))];
																num = -669584372;
															}
														}
														else
														{
															TitlebarSubtitle = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xC98 ^ 0xDD5];
															int[,] array9 = new int[3, 3];
															array9[0, 0] = 1481302051;
															array9[0, 1] = 169565225;
															array9[0, 2] = 869478561;
															array9[1, 0] = -645633899;
															array9[1, 1] = -759836733;
															array9[1, 2] = 1660348339;
															array9[2, 0] = 168059606;
															array9[2, 1] = 771753564;
															array9[2, 2] = -2130019205;
															array9[2, 2] = array9[2, 1] ^ -1763141801;
															array9[2, 0] = array9[1, 2] ^ 0x45B2E90F;
															array9[1, 1] = array9[2, 2] ^ 0x1D4B075;
															array9[2, 2] = array9[0, 2] ^ 0x5C5FD640;
															int num46 = array9[2, 2] ^ -1072340704;
															num = ((int)num4 * -1046991248) ^ -1138594992 ^ num46;
														}
													}
													else
													{
														ShellSubheader = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x6296 ^ 0x63D8];
														int[] array10 = new int[5] { 1824605268, -985285867, 1293597417, 1100827469, -1362970885 };
														array10[2] ^= 2138534022;
														array10[3] ^= 954342821;
														array10[4] = array10[1] ^ 0x5EAB2423;
														int[] array11 = new int[7];
														array11[0] = 183295692;
														array11[1] = 1545575776;
														array11[2] = 419574195;
														array11[3] = 1541325357;
														array11[4] = -1542614802;
														array11[5] = 2088413164;
														array11[6] = 122373688;
														array11[5] = array10[1] ^ -1671792355;
														array11[0] = array11[2] ^ -2005546611;
														array11[1] = array11[0] ^ 0x79C58455;
														int num47 = array11[5] ^ 0x74F3508;
														num = (int)((num4 * 1457059579) ^ 0xC32727A0u) ^ num47;
													}
												}
												else
												{
													ShellHeader = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[122 - 42 - 31 - 38];
													int[] array12 = new int[7] { 860040573, 132985089, 424554966, 371125002, -1806275182, 37285798, 1689153627 };
													array12[0] ^= 1647312937;
													array12[4] = array12[5] ^ -314541477;
													array12[1] = array12[3] ^ -2036923458;
													int[] array13 = new int[6];
													array13[0] = -1617419527;
													array13[1] = -285018053;
													array13[2] = -1100120597;
													array13[3] = 1653967206;
													array13[4] = 1671709434;
													array13[5] = -816481723;
													array13[0] = array12[5] ^ -851275657;
													array13[5] = array13[4] ^ -2051003825;
													array13[5] = array13[4] ^ -736012998;
													array13[5] = array13[2] ^ 0x58A0B39;
													int num48 = array13[0] ^ 0x63A2BBB2;
													num = (int)((num4 * 1536169536) ^ 0xA3F49B00u) ^ num48;
												}
											}
											else
											{
												WindowTitle = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-735 + 423)];
												num = -1324568369;
											}
										}
										else
										{
											TitlebarSubtitle = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-517 + 183)];
											int[] array14 = new int[4];
											array14[0] = 839127747;
											array14[1] = 1627933707;
											array14[2] = 55095256;
											array14[3] = 1831153509;
											array14[0] = array14[3] ^ 0xED97EE1;
											array14[2] = array14[3] ^ 0xC680B65;
											array14[2] ^= 1502027042;
											int[] array15 = new int[6] { 938743722, 348061153, -782288942, 837368146, 1866865002, -129027920 };
											int[][] array16 = new int[2][] { array14, array15 };
											array15[4] = array16[0][3] ^ 0x5B17E26D;
											array15[3] = array15[2] ^ -1527306016;
											array15[3] = array15[5] ^ 0x356EE041;
											array15[5] = array15[4] ^ 0x6A347CE2;
											int num49 = array16[1][4] ^ -2039652466;
											num = (int)((num4 * 870038130) ^ 0x42E3A334) ^ num49;
										}
									}
									else
									{
										ShellSubheader = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x570 ^ 0x43C))];
										int[] array17 = new int[5];
										array17[0] = -2120714231;
										array17[1] = -1623038598;
										array17[2] = -1099964643;
										array17[3] = 1831899667;
										array17[4] = -1314028442;
										array17[1] = array17[0] ^ 0x214D2FED;
										array17[2] = array17[0] ^ -1296142568;
										int[] array18 = new int[7] { 563968015, -457929326, -1069715145, -480382287, -2126031785, 89372842, 1992074648 };
										int[][] array19 = new int[2][] { array17, array18 };
										array18[3] = array19[0][0] ^ -312134008;
										array18[0] = array18[5] ^ -114533885;
										array18[4] = array18[2] ^ 0x33EE7CF4;
										array18[5] = array18[1] ^ 0x17BB19AB;
										int num50 = array19[1][3] ^ -1098219928;
										num = (int)((num4 * 142213544) ^ 0x1351A8A8) ^ num50;
									}
								}
								else
								{
									ShellHeader = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[400 - 45 - 13 - 11];
									int[,] array20 = new int[4, 3];
									array20[0, 0] = 834296928;
									array20[0, 1] = 1389322276;
									array20[0, 2] = -1916129270;
									array20[1, 0] = -119023167;
									array20[1, 1] = -916086026;
									array20[1, 2] = -1941112368;
									array20[2, 0] = 691725934;
									array20[2, 1] = -1531693906;
									array20[2, 2] = 1750820591;
									array20[3, 0] = -533020339;
									array20[3, 1] = -980054731;
									array20[3, 2] = 95816642;
									array20[0, 2] = array20[3, 0] ^ 0x5CE1A734;
									array20[0, 2] = array20[2, 2] ^ -1946410310;
									array20[2, 2] = array20[1, 2] ^ -689037912;
									int num51 = array20[2, 2] ^ -749975142;
									num = ((int)num4 * -1347094053) ^ -930470032 ^ num51;
								}
							}
							else
							{
								WindowTitle = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-721 + 409)];
								num = -1680637517;
							}
						}
						else
						{
							int[] array21 = new int[7];
							array21[0] = 935391968;
							array21[1] = -490960996;
							array21[2] = 2003320474;
							array21[3] = 303477916;
							array21[4] = 383500697;
							array21[5] = -2104611466;
							array21[6] = -98880340;
							array21[6] = array21[5] ^ -1876663728;
							array21[6] = array21[2] ^ -305539539;
							int[] array22 = new int[6] { 1705446024, -592137656, 524676681, 738966574, 2026641278, -957855527 };
							int[][] array23 = new int[2][] { array21, array22 };
							array22[3] = array23[0][5] ^ -1403248487;
							array22[4] = array22[0] ^ -1888690520;
							array22[1] = array22[4] ^ -1064336323;
							array22[1] = array22[3] ^ -165607160;
							int num52 = array23[1][3] ^ 0x5B795474;
							num = ((int)num4 * -869068293) ^ 0x4DD0252F ^ num52;
						}
					}
					else
					{
						int[] array24 = new int[5];
						array24[0] = 1292975963;
						array24[1] = -988564108;
						array24[2] = -1736436098;
						array24[3] = -982256191;
						array24[4] = -1615044431;
						array24[2] = array24[0] ^ -445786795;
						array24[2] = array24[3] ^ 0x6B971447;
						array24[1] = array24[3] ^ -1844120340;
						int[] array25 = new int[6] { -1268124272, -10285022, -1786796233, 97511501, 578494484, 469077710 };
						int[][] array26 = new int[2][] { array24, array25 };
						array25[3] = array26[0][0] ^ -1490502548;
						array25[1] ^= 1674060698;
						array25[1] = array25[0] ^ -2028186898;
						array25[5] = array25[1] ^ -980485055;
						int num53 = array26[1][3] ^ 0x570ABCFA;
						int[] array27 = new int[6];
						array27[0] = -941670626;
						array27[1] = 1204881897;
						array27[2] = -279452835;
						array27[3] = 969275327;
						array27[4] = -702415668;
						array27[5] = 1958174426;
						array27[0] = array27[5] ^ 0x15C2F464;
						array27[5] = array27[4] ^ 0x3AEAAB3;
						array27[4] ^= 2072386687;
						int[] array28 = new int[7];
						array28[0] = -1687540532;
						array28[1] = 525813497;
						array28[2] = 304972008;
						array28[3] = 815356581;
						array28[4] = 892746424;
						array28[5] = 144115669;
						array28[6] = -1726164392;
						array28[3] = array27[1] ^ 0x765997D2;
						array28[4] ^= -2051864107;
						array28[2] = array28[0] ^ 0x69FF3ABD;
						int num54 = array28[3] ^ -1244299899;
						int num55 = ((int)num4 * -1418254729) ^ -956543940;
						num53 ^= num55;
						num54 ^= num55;
						int num56;
						int num57;
						if (section != ShellSection.Settings)
						{
							num56 = num54;
							num57 = num56;
						}
						else
						{
							num56 = num53;
							num57 = num56;
						}
						num = num56 ^ num55;
					}
				}
				else
				{
					int[] array29 = new int[7];
					array29[0] = -1902283745;
					array29[1] = 1300099208;
					array29[2] = 1978124753;
					array29[3] = -1875561533;
					array29[4] = 471455120;
					array29[5] = -2128897556;
					array29[6] = 193435879;
					array29[3] = array29[4] ^ -369646674;
					array29[3] ^= -1584014178;
					array29[2] = array29[5] ^ -437931316;
					int[] array30 = new int[5] { -567856588, 473801048, -261110118, -875021723, 1132579707 };
					int[][] array31 = new int[2][] { array29, array30 };
					array30[1] = array31[0][5] ^ 0x19789468;
					array30[2] = array30[3] ^ 0x5F00C47B;
					array30[4] ^= -1751558921;
					int num58 = array31[1][1] ^ 0x10E38DAD;
					int[] array32 = new int[4];
					array32[0] = 601332699;
					array32[1] = 982511386;
					array32[2] = 1312867702;
					array32[3] = -2063446128;
					array32[1] = array32[3] ^ 0x28F749BF;
					array32[2] = array32[1] ^ 0x421E7E9D;
					int[] array33 = new int[7] { -1880763085, -168863640, -304250981, -674439516, 395770774, -893408331, 2125424894 };
					int[][] array34 = new int[2][] { array32, array33 };
					array33[4] = array34[0][3] ^ 0x50FF9F4;
					array33[3] ^= -271886602;
					array33[5] = array33[1] ^ -1186365180;
					array33[6] = array33[5] ^ -1343939195;
					int num59 = array34[1][4] ^ 0x3F6CA6C3;
					int num60 = ((int)num4 * -312631223) ^ 0x434E9F2D;
					num58 ^= num60;
					num59 ^= num60;
					int num61;
					int num62;
					if (section != ShellSection.Methods)
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
		}
	}

	public void SetAuthenticated(string license)
	{
		IsAuthenticated = true;
		while (true)
		{
			int num = -904990232;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(~(~(-(num2 - (-(~(644206417 * (~867776728 - (-455871769 ^ -626910396) - (-1137225448 ^ --307479384)) + ~-2001706380) ^ -416657931) ^ ((0xDBFF4D ^ (-((--1570931378 + -2040016113 * 590668504) ^ 0x12FCB543) + (-803245949 - -327995070 + -(~-1124920599) - 643755943 * ~(-604975147 - -1630381685)) - ~(-1714748919))) + -(((216454229 + -(1784257148 - 1250002991) + ~(-(1210894726 + -350645448))) * -196577285) ^ (1353769961 + (1206516249 - -377595332 - -1450880116 - --254739704) + -877533886)))) - (-475009355 * -120090309 + (-2132762478 - -(~(-1746712832) - (-135122942 - (0x72383C20 ^ 0x7DE871BA)) - ~((-645976830 ^ -449461975) * -634663679) + ((-781509025 ^ 0x27EDD29A) + ((-1010730582 * -1553112047) ^ (-862364207 * -62126403)))))) - (0x59B1F51E ^ ((~-3425462 + (-1615733107 ^ ~(-215755371 - (-1680653491 - -697462767)))) ^ ~(-(~(-495622336 ^ -878181108)))))) - ~((~(2053410644 - 255375256) + (-941072540 ^ 0xFC4AF8A)) * -190498589)))) - (-1585879312 - -882214519) - -176008463)) % 7;
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
				int num7 = -1620261878;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = ~num7 - -524319655;
					num7 = -(num7 * -1902836667);
				}
				if (num3 != (uint)num7)
				{
					int num9 = 271753774;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 -= 271753769;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 1384749713;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = num11 - (-1146322442 ^ -639763617) - 1585056399;
							num11 = (num11 - (572281452 - -1900420446)) * -812528029;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 1377611945;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 += -1377611942;
							}
							if (num3 != (uint)num13)
							{
								int num15 = 4;
								_ = 0;
								for (int num16 = 0; num16 < 2; num16++)
								{
									num15 = -(~num15);
									num15 ^= 0x2BB4A529;
								}
								if (num3 != (uint)num15)
								{
									int num17 = -360621662;
									_ = 0;
									for (int num18 = 0; num18 < 2; num18++)
									{
										num17 = ~num17;
										num17 = num17 * -1028580843 * -952645475;
									}
									if (num3 == (uint)num17)
									{
									}
									return;
								}
								Navigate(ShellSection.Workspace);
								int[] array = new int[6];
								array[0] = 956527691;
								array[1] = -939932029;
								array[2] = 1210717141;
								array[3] = 2131397005;
								array[4] = -1949434272;
								array[5] = 857812261;
								array[4] = array[3] ^ -2093910650;
								array[4] = array[0] ^ -505377227;
								int[] array2 = new int[7];
								array2[0] = 872782274;
								array2[1] = -773735593;
								array2[2] = 1815172272;
								array2[3] = 2095825715;
								array2[4] = 231429387;
								array2[5] = 1673225898;
								array2[6] = -1676337474;
								array2[6] = array[3] ^ 0x539CF778;
								array2[5] = array2[6] ^ -1630527565;
								array2[4] = array2[1] ^ 0x2804E170;
								array2[5] = array2[2] ^ -1319197295;
								int num19 = array2[6] ^ -253539965;
								num = ((int)num4 * -259723177) ^ -1427961306 ^ num19;
							}
							else
							{
								UpdateUrl = string.Empty;
								int[] array3 = new int[6];
								array3[0] = -1493607522;
								array3[1] = -1435729932;
								array3[2] = 1625169577;
								array3[3] = -914732977;
								array3[4] = 316493866;
								array3[5] = -636936725;
								array3[0] = array3[2] ^ 0x4C212142;
								array3[2] = array3[4] ^ 0x4EA74EC6;
								array3[3] = array3[5] ^ 0x3207BE0C;
								int[] array4 = new int[4];
								array4[0] = -1797585286;
								array4[1] = 1953478799;
								array4[2] = -1063701401;
								array4[3] = -791962516;
								array4[3] = array3[5] ^ -153870427;
								array4[2] = array4[0] ^ 0x9635A08;
								array4[0] = array4[3] ^ 0x4D960011;
								int num20 = array4[3] ^ 0x8115FDB;
								num = ((int)num4 * -474462578) ^ 0x6FA361A2 ^ num20;
							}
						}
						else
						{
							UpdateMessage = string.Empty;
							int[] array5 = new int[5];
							array5[0] = 1026808672;
							array5[1] = 565468817;
							array5[2] = -1397874634;
							array5[3] = -1779135185;
							array5[4] = -1317077107;
							array5[3] = array5[4] ^ 0x485DA4DA;
							array5[4] = array5[2] ^ -157054326;
							array5[1] = array5[4] ^ -1152192785;
							int[] array6 = new int[5];
							array6[0] = -1623058118;
							array6[1] = -2015117999;
							array6[2] = -1771702209;
							array6[3] = -417393788;
							array6[4] = 782011266;
							array6[0] = array5[0] ^ -1151076898;
							array6[1] ^= -994063642;
							array6[1] = array6[0] ^ -1438309724;
							int num21 = array6[0] ^ 0x6A3783CC;
							num = (int)((num4 * 215355495) ^ 0x4DA2F013) ^ num21;
						}
					}
					else
					{
						UpdateAvailable = false;
						int[,] array7 = new int[3, 4];
						array7[0, 0] = -161283044;
						array7[0, 1] = -729469359;
						array7[0, 2] = -405748698;
						array7[0, 3] = 2127223241;
						array7[1, 0] = 1236288402;
						array7[1, 1] = -1308289182;
						array7[1, 2] = 1840559057;
						array7[1, 3] = 1207156118;
						array7[2, 0] = 1983053420;
						array7[2, 1] = 1470198209;
						array7[2, 2] = 1264902008;
						array7[2, 3] = 673586656;
						array7[0, 0] = array7[2, 2] ^ -2502161;
						array7[2, 1] = array7[1, 3] ^ -169263269;
						array7[2, 2] = array7[1, 0] ^ 0x6C40C9C;
						array7[0, 1] = array7[0, 3] ^ -708853881;
						int num22 = array7[0, 1] ^ 0x42750B8E;
						num = ((int)num4 * -766218480) ^ -117669968 ^ num22;
					}
				}
				else
				{
					CurrentLicenseDisplay = BuildMaskedLicense(license);
					int[] array8 = new int[6];
					array8[0] = 1256837714;
					array8[1] = -711069338;
					array8[2] = 1829374566;
					array8[3] = -2031917344;
					array8[4] = -1298275555;
					array8[5] = 1906914895;
					array8[4] = array8[0] ^ 0x401CD7DE;
					array8[5] = array8[3] ^ 0x6749A1E9;
					array8[4] = array8[3] ^ -1116887278;
					int[] array9 = new int[5] { -2029063879, 319390811, -2113777385, 715321591, -2073175083 };
					int[][] array10 = new int[2][] { array8, array9 };
					array9[3] = array10[0][3] ^ -472948398;
					array9[0] = array9[3] ^ 0x1A23835;
					array9[2] = array9[1] ^ 0x40397CDF;
					array9[0] = array9[2] ^ -2131532701;
					int num23 = array10[1][3] ^ 0x45C9BC44;
					num = ((int)num4 * -1878998629) ^ -372374257 ^ num23;
				}
			}
		}
	}

	public void SetAuthenticated(string license, int? remainingDays, string? planType)
	{
		IsAuthenticated = true;
		while (true)
		{
			int num = -68828169;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(((-(~(((num2 ^ ~(((279386375 * (-1556488209 * 1978109073 - (-732236342 - 1534841122 + (1454933506 + -1255457937) + -(-604559204 - -2091185873))) + (((0x16CB949D ^ -292695415) + -(-415405445 * 290299193)) * 1539975333 - (-1758418381 + (511084129 - (-1071290075 + -1953198664))) * -1869367363)) ^ -141066751) * -1602295325)) - ((0x559E7DAB ^ -424076265) + ~(-(~(--183710125)) ^ 0x4D6CCF5F) - (-323151635 * -1402134437 + -1167043362)) * 747266629) * 706473313) - -598422699 * -484100049) - -1333541329 * (21437951 * (-1639552544 - 265731936))) * -1240368537) ^ 0x7C2C7C7))) % 11;
				int num5 = -585706;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = -(num5 ^ -53394457);
					num5 = -(num5 + --392923364);
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 907455874;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 += -907455873;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 9;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = ~(-num9);
						num9 = ~num9 - 1119739687;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -3;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 = ~num11;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -1073289969;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = (num13 + ~-411353579) ^ -1048822059;
								num13 = 166965132 - (num13 ^ --1884267535);
							}
							if (num3 != (uint)num13)
							{
								int num15 = -293159016;
								_ = 0;
								for (int num16 = 0; num16 < 2; num16++)
								{
									num15 = num15 * -1546390921 - 1293683073;
									num15 = (num15 ^ 0x603D0A50) - -1677444228;
								}
								if (num3 != (uint)num15)
								{
									int num17 = -1509692280;
									_ = 0;
									for (int num18 = 0; num18 < 2; num18++)
									{
										num17 = -(~num17);
										num17 = -(1528047747 + -135410242 - num17);
									}
									if (num3 != (uint)num17)
									{
										int num19 = 4;
										_ = 0;
										for (int num20 = 0; num20 < 2; num20++)
										{
											num19 += 0x5AF1177E ^ -1408481025;
											num19 = -num19 - 468130546;
										}
										if (num3 != (uint)num19)
										{
											int num21 = 485637519;
											_ = 0;
											for (int num22 = 0; num22 < 1; num22++)
											{
												num21 -= 485637509;
											}
											if (num3 != (uint)num21)
											{
												int num23 = 1764791785;
												_ = 0;
												for (int num24 = 0; num24 < 1; num24++)
												{
													num23 *= -1695818819;
												}
												if (num3 != (uint)num23)
												{
													int num25 = 1295205415;
													_ = 0;
													for (int num26 = 0; num26 < 2; num26++)
													{
														num25 = -num25 ^ 0x7164A3CC;
														num25 *= -619623507;
													}
													if (num3 == (uint)num25)
													{
													}
													return;
												}
												_0026_0025_003C_0021_0021_0024_0025_002F((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xA430 ^ 0xA562]);
												Navigate(ShellSection.Workspace);
												int[] array = new int[4];
												array[0] = 575063677;
												array[1] = -7049596;
												array[2] = -334371274;
												array[3] = 777014044;
												array[1] = array[3] ^ 0x43AA4DEC;
												array[0] = array[2] ^ 0x775FA26F;
												array[1] = array[2] ^ -909228536;
												int[] array2 = new int[4] { 439197056, -1187794141, -413161441, -197647316 };
												int[][] array3 = new int[2][] { array, array2 };
												array2[1] = array3[0][2] ^ -262964855;
												array2[2] = array2[0] ^ 0x2667EAE5;
												array2[2] = array2[1] ^ 0x6F5CDC95;
												int num27 = array3[1][1] ^ -1336764285;
												num = (int)((num4 * 1214833771) ^ 0xF5D04AB4u) ^ num27;
											}
											else
											{
												_0026_0025_003C_0021_0021_0024_0025_002F((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[460 - 37 - 47 - 39]);
												int[,] array4 = new int[3, 4];
												array4[0, 0] = 1626774131;
												array4[0, 1] = -1951981415;
												array4[0, 2] = 365752946;
												array4[0, 3] = 1671760398;
												array4[1, 0] = 1176701543;
												array4[1, 1] = 369246149;
												array4[1, 2] = -1363671837;
												array4[1, 3] = -868487880;
												array4[2, 0] = -444403931;
												array4[2, 1] = 1798994036;
												array4[2, 2] = 802920773;
												array4[2, 3] = -2085684120;
												array4[1, 1] = array4[2, 3] ^ -722852242;
												array4[2, 2] = array4[0, 0] ^ 0x1EEBB018;
												array4[2, 3] = array4[1, 3] ^ -633601222;
												int num28 = array4[2, 3] ^ 0x398B722D;
												num = ((int)num4 * -1494217538) ^ -759891742 ^ num28;
											}
										}
										else
										{
											UpdateUrl = string.Empty;
											int[] array5 = new int[6];
											array5[0] = -767801470;
											array5[1] = -279608304;
											array5[2] = -647320845;
											array5[3] = -1335265851;
											array5[4] = 19541644;
											array5[5] = 1257894327;
											array5[5] = array5[1] ^ -880206522;
											array5[2] = array5[5] ^ 0x33FBE023;
											int[] array6 = new int[7] { -576551399, -1921430738, 480308076, -507075094, 1350956767, -445094871, 1098979256 };
											int[][] array7 = new int[2][] { array5, array6 };
											array6[5] = array7[0][0] ^ 0x16A5E244;
											array6[6] = array6[5] ^ -1353356426;
											array6[3] = array6[5] ^ 0x567A271;
											array6[0] = array6[4] ^ 0x49346C5B;
											int num29 = array7[1][5] ^ -786808740;
											num = (int)((num4 * 531675602) ^ 0x2233F912) ^ num29;
										}
									}
									else
									{
										UpdateMessage = string.Empty;
										int[,] array8 = new int[4, 4];
										array8[0, 0] = 1292492012;
										array8[0, 1] = 1571412701;
										array8[0, 2] = 1273662005;
										array8[0, 3] = 302384567;
										array8[1, 0] = -475052870;
										array8[1, 1] = 23034007;
										array8[1, 2] = 2010732229;
										array8[1, 3] = -1382411699;
										array8[2, 0] = -2122447936;
										array8[2, 1] = 950269323;
										array8[2, 2] = 1921025;
										array8[2, 3] = -918465284;
										array8[3, 0] = 1839304354;
										array8[3, 1] = 1174089704;
										array8[3, 2] = -2063580656;
										array8[3, 3] = 347261899;
										array8[1, 2] = array8[3, 1] ^ 0x47E4C90;
										array8[3, 1] = array8[0, 0] ^ -1936724282;
										array8[2, 3] = array8[0, 3] ^ 0x3FDB0DA2;
										int num30 = array8[2, 3] ^ 0x3670759D;
										num = ((int)num4 * -1410188958) ^ -453825906 ^ num30;
									}
								}
								else
								{
									UpdateAvailable = false;
									int[,] array9 = new int[4, 3];
									array9[0, 0] = -405731588;
									array9[0, 1] = -552926380;
									array9[0, 2] = -481180864;
									array9[1, 0] = 1960672264;
									array9[1, 1] = -1242873384;
									array9[1, 2] = 1893896502;
									array9[2, 0] = -1604618620;
									array9[2, 1] = 1745190150;
									array9[2, 2] = -81324961;
									array9[3, 0] = -610322014;
									array9[3, 1] = -1509227846;
									array9[3, 2] = -986488261;
									array9[1, 0] = array9[0, 2] ^ -105558784;
									array9[0, 1] = array9[1, 2] ^ 0x73916697;
									array9[1, 2] = array9[2, 2] ^ 0x2AB02A2C;
									array9[2, 0] = array9[2, 1] ^ -153062313;
									int num31 = array9[2, 0] ^ 0x4DEA6CB3;
									num = ((int)num4 * -1958353239) ^ -2137434 ^ num31;
								}
							}
							else
							{
								LicensePlanType = planType;
								int[,] array10 = new int[3, 4];
								array10[0, 0] = 490029240;
								array10[0, 1] = -564171734;
								array10[0, 2] = -1551961417;
								array10[0, 3] = 1944347457;
								array10[1, 0] = 227454758;
								array10[1, 1] = 702639902;
								array10[1, 2] = -1619228778;
								array10[1, 3] = 1642927187;
								array10[2, 0] = -1455895906;
								array10[2, 1] = -643686705;
								array10[2, 2] = 349767576;
								array10[2, 3] = 1705474693;
								array10[1, 1] = array10[0, 0] ^ 0x36F9D4BB;
								array10[2, 2] = array10[0, 1] ^ 0x498AD28A;
								array10[1, 3] = array10[2, 1] ^ -584372629;
								int num32 = array10[1, 3] ^ -1096251183;
								num = (int)((num4 * 447554182) ^ 0xC7A0BC38u) ^ num32;
							}
						}
						else
						{
							LicenseRemainingDays = remainingDays;
							int[,] array11 = new int[3, 4];
							array11[0, 0] = -509105966;
							array11[0, 1] = 186288084;
							array11[0, 2] = 65835596;
							array11[0, 3] = 1062051838;
							array11[1, 0] = 664460186;
							array11[1, 1] = -621787990;
							array11[1, 2] = 265336972;
							array11[1, 3] = -862587224;
							array11[2, 0] = 421939811;
							array11[2, 1] = -31163324;
							array11[2, 2] = 463356406;
							array11[2, 3] = -260293846;
							array11[0, 2] = array11[2, 1] ^ 0x19F3F253;
							array11[0, 1] = array11[0, 3] ^ 0x6E0B663C;
							array11[0, 2] = array11[0, 0] ^ -891281839;
							int num33 = array11[0, 2] ^ 0x4A145CC4;
							num = ((int)num4 * -1792219517) ^ 0x4410800C ^ num33;
						}
					}
					else
					{
						CurrentLicenseFull = license;
						int[] array12 = new int[6];
						array12[0] = -1887423753;
						array12[1] = 76999531;
						array12[2] = 167230604;
						array12[3] = 793084384;
						array12[4] = 2046510579;
						array12[5] = -1798889797;
						array12[0] = array12[5] ^ 0x3CB81D02;
						array12[3] ^= 1849757132;
						int[] array13 = new int[5] { -2043983310, 1151762099, -740082349, 24394090, -1815168497 };
						int[][] array14 = new int[2][] { array12, array13 };
						array13[1] = array14[0][5] ^ 0x9BFD8C;
						array13[0] = array13[3] ^ 0x6A99BFBA;
						array13[4] = array13[0] ^ 0x28EAE2DE;
						int num34 = array14[1][1] ^ -1094438112;
						num = (int)((num4 * 517979289) ^ 0x8628DE80u) ^ num34;
					}
				}
				else
				{
					CurrentLicenseDisplay = BuildMaskedLicense(license);
					int[,] array15 = new int[3, 3];
					array15[0, 0] = 42324736;
					array15[0, 1] = -199743631;
					array15[0, 2] = 606360206;
					array15[1, 0] = 1307741271;
					array15[1, 1] = -1938896791;
					array15[1, 2] = -1144301934;
					array15[2, 0] = 596260393;
					array15[2, 1] = 1278179214;
					array15[2, 2] = 307662777;
					array15[1, 2] = array15[1, 0] ^ -1596323734;
					array15[1, 0] = array15[0, 2] ^ 0x9ACA938;
					array15[0, 2] = array15[0, 1] ^ -1220902339;
					int num35 = array15[0, 2] ^ 0x7E0AC9AF;
					num = ((int)num4 * -1147895494) ^ 0x2A9FBB28 ^ num35;
				}
			}
		}
	}

	public void SetUpdateState(string message, string? updateUrl)
	{
		UpdateAvailable = !_0026_003E_002F_0026_0023_0026_0024_0021(updateUrl);
		while (true)
		{
			int num = -1066094309;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(-(-(num2 + ((-383645711 * (0x132FFD6E ^ 0x72824FAB) + ~(~((-643708773 * (--1592961224 - (-1608609440 + 1777091879))) ^ 0x26575B49) ^ ~(((0x688F2AEB ^ 0x6CC6FD9) - 1689978432 - -(-1828649308 + -542312184)) ^ -592520829))) ^ -(-1442821927 * (-1655071575 * ~(-(--961050773) + (1403750729 + -1048241553) * 1416934437) + (~(-1621845585 - 1664591707 * 1754969868 + ((0x7FF01EE2 ^ -32880376) - ~1682247548)) + --1032018007))))) ^ (120506635 * -(-(-1400240249 * -1514432527 - (716954989 - 551507199) + --467839950 * -1725861473) ^ -686935155)))))) % 4;
				int num5 = 1739958387;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 ^= 0x67B5A873;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -28189;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -num7 ^ -2041423047;
					num7 = num7 + -1965788387 * -1507663545 - 298373886;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 2010559670;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 *= 1964918227;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -1;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 = -num11;
						}
						if (num3 == (uint)num11)
						{
						}
						return;
					}
					UpdateUrl = updateUrl ?? string.Empty;
					num = -1504381983;
				}
				else
				{
					UpdateMessage = message;
					int[] array = new int[6];
					array[0] = 906749396;
					array[1] = -692702531;
					array[2] = -1344966571;
					array[3] = -2028899110;
					array[4] = 981641830;
					array[5] = 942551749;
					array[4] = array[1] ^ -705460475;
					array[3] = array[4] ^ 0x39234637;
					array[5] ^= -296026489;
					int[] array2 = new int[7];
					array2[0] = 436425541;
					array2[1] = 1676894863;
					array2[2] = 364225080;
					array2[3] = -922211118;
					array2[4] = 1115720568;
					array2[5] = 1740153163;
					array2[6] = -1864091841;
					array2[3] = array[1] ^ 0x4103DC5;
					array2[4] = array2[5] ^ 0x3B8A4AD7;
					array2[4] = array2[0] ^ -832886497;
					array2[6] = array2[2] ^ 0x52826D78;
					int num13 = array2[3] ^ -1355654044;
					num = (int)((num4 * 1207611453) ^ 0x45A8AFCB) ^ num13;
				}
			}
		}
	}

	public void SetWorkspaceSummary(string assemblyName, bool isLoaded)
	{
		HasLoadedAssembly = isLoaded;
		while (true)
		{
			int num = 1329066610;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(~(~(~(-num2)))) ^ -2075334477)) % 5;
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
				int num7 = -87210845;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = num7 - (0x670B0299 ^ 0x48E9D2C0) - -1642668059;
					num7 = num7 - ~-1011069000 - 1932083659;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 ^= -1712203294;
						num9 = num9 ^ -823218465 ^ 0x722A7406;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 1849228558;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = -924614279 - ~num11;
							num11 = ~(~num11);
						}
						if (num3 != (uint)num11)
						{
							int num13 = 4;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = num13 - -1955106970 + -2025305238;
								num13 = -(num13 + -1417932485);
							}
							if (num3 == (uint)num13)
							{
							}
							return;
						}
						SelectedMethodCount = 0;
						int[,] array = new int[3, 4];
						array[0, 0] = -556727810;
						array[0, 1] = -1725178990;
						array[0, 2] = 1883051719;
						array[0, 3] = 751756848;
						array[1, 0] = 1412025563;
						array[1, 1] = 1729315121;
						array[1, 2] = 781280308;
						array[1, 3] = -2039121065;
						array[2, 0] = -1916669898;
						array[2, 1] = -1094539316;
						array[2, 2] = 1982472589;
						array[2, 3] = -664105976;
						array[1, 0] = array[1, 1] ^ -994635167;
						array[0, 3] = array[1, 2] ^ -674161304;
						array[2, 3] = array[0, 2] ^ 0x1E87AD0D;
						int num15 = array[2, 3] ^ 0x7BFA9B6B;
						num = ((int)num4 * -1576132939) ^ -1375468929 ^ num15;
						continue;
					}
					int[,] array2 = new int[3, 3];
					array2[0, 0] = -641818390;
					array2[0, 1] = 321110179;
					array2[0, 2] = 2038493096;
					array2[1, 0] = 324072592;
					array2[1, 1] = 206158998;
					array2[1, 2] = 730745140;
					array2[2, 0] = -316111991;
					array2[2, 1] = -1825251469;
					array2[2, 2] = -540569653;
					array2[2, 1] = array2[2, 2] ^ -923627131;
					array2[1, 0] = array2[0, 2] ^ 0x528BF552;
					array2[1, 2] = array2[1, 1] ^ 0x785D8652;
					int num16 = array2[1, 2] ^ 0x61541A65;
					int[] array3 = new int[7] { 414419249, -1470754350, -2090316827, -521049505, -2090500200, -1825913194, 1633209336 };
					array3[6] ^= 2020403527;
					array3[3] ^= -1119153669;
					int[] array4 = new int[7];
					array4[0] = -1227533294;
					array4[1] = 1733073201;
					array4[2] = -1147539819;
					array4[3] = -1475556010;
					array4[4] = 972980669;
					array4[5] = 1971423393;
					array4[6] = 841654480;
					array4[6] = array3[5] ^ -169703678;
					array4[1] = array4[4] ^ -1949310665;
					array4[5] = array4[1] ^ 0x1AC7A489;
					int num17 = array4[6] ^ 0x583FE25;
					int num18 = (int)(num4 * 105418673) ^ -456918468;
					num16 ^= num18;
					num17 ^= num18;
					int num19;
					int num20;
					if (!isLoaded)
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
				else
				{
					CurrentAssemblyName = (isLoaded ? assemblyName : string.Empty);
					num = 1578770354;
				}
			}
		}
	}

	public void SignOut()
	{
		IsAuthenticated = false;
		while (true)
		{
			int num = -298328967;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(-(-(~num2)) + (1385469161 - ~(--275178889 ^ 0x31467424))))) % 13;
				int num5 = 12586906;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~(num5 ^ -162138476);
					num5 = ~num5 - -803084870;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1121065279;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 *= -633579841;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -809506292;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = (num9 + (-1073589529 - -1633646793)) * -1791436683;
						num9 = (num9 + (-671015701 + 601509990)) ^ -1509744900;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -460105027;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 -= ~-1247580582;
							num11 = num11 - 1780199989 - 1037134211;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -779411980;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 *= -6062721;
							}
							if (num3 != (uint)num13)
							{
								int num15 = -5;
								_ = 0;
								for (int num16 = 0; num16 < 1; num16++)
								{
									num15 = -num15;
								}
								if (num3 != (uint)num15)
								{
									int num17 = -1962929600;
									_ = 0;
									for (int num18 = 0; num18 < 2; num18++)
									{
										num17 = -num17 + -989337315;
										num17 = -(num17 ^ 0x2A7B760B);
									}
									if (num3 != (uint)num17)
									{
										int num19 = -4;
										_ = 0;
										for (int num20 = 0; num20 < 1; num20++)
										{
											num19 = -num19;
										}
										if (num3 != (uint)num19)
										{
											int num21 = 38076491;
											_ = 0;
											for (int num22 = 0; num22 < 2; num22++)
											{
												num21 = --2087871324 - num21 - -1720100787;
												num21 = (num21 - 1900941135 * 598754000) ^ -551382857;
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
													int num25 = 1844051998;
													_ = 0;
													for (int num26 = 0; num26 < 1; num26++)
													{
														num25 = 1844052007 - num25;
													}
													if (num3 != (uint)num25)
													{
														int num27 = -8;
														_ = 0;
														for (int num28 = 0; num28 < 1; num28++)
														{
															num27 = ~num27;
														}
														if (num3 != (uint)num27)
														{
															int num29 = 2013043202;
															_ = 0;
															for (int num30 = 0; num30 < 2; num30++)
															{
																num29 = ~num29 + 17923509;
																num29 = -num29 * 568220319;
															}
															if (num3 == (uint)num29)
															{
															}
															return;
														}
														ApplySignedOutHeader();
														int[,] array = new int[3, 3];
														array[0, 0] = -314668228;
														array[0, 1] = 369783449;
														array[0, 2] = 775579672;
														array[1, 0] = 890398759;
														array[1, 1] = -2048307752;
														array[1, 2] = 1534197584;
														array[2, 0] = -652927985;
														array[2, 1] = -396519337;
														array[2, 2] = -1251839516;
														array[2, 2] = array[0, 2] ^ 0x1AABA508;
														array[0, 0] = array[1, 2] ^ 0x7E8E03FC;
														array[2, 1] = array[1, 2] ^ -1324324635;
														int num31 = array[2, 1] ^ 0x3F695559;
														num = (int)((num4 * 1207444956) ^ 0x48D153C4) ^ num31;
													}
													else
													{
														Navigate(ShellSection.Workspace);
														int[] array2 = new int[7] { 1530240403, -2100502073, 35737985, -85451216, -352962044, 662726389, 276697127 };
														array2[0] ^= 482576205;
														array2[6] ^= 1725738278;
														array2[3] = array2[0] ^ 0x131A0D8F;
														int[] array3 = new int[5];
														array3[0] = 1758881165;
														array3[1] = -1824503544;
														array3[2] = 1463389036;
														array3[3] = -551517551;
														array3[4] = 1307717535;
														array3[2] = array2[1] ^ 0x716233B9;
														array3[4] = array3[2] ^ -762179658;
														array3[4] ^= 490479814;
														int num32 = array3[2] ^ 0x3D288710;
														num = (int)((num4 * 47994037) ^ 0xB223BADDu) ^ num32;
													}
												}
												else
												{
													_0026_0025_003C_0021_0021_0024_0025_002F((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4061 - 3755 + 32]);
													int[] array4 = new int[7];
													array4[0] = 2110497605;
													array4[1] = 201441708;
													array4[2] = -140040996;
													array4[3] = -3272983;
													array4[4] = 453979080;
													array4[5] = 709763429;
													array4[6] = 2126685927;
													array4[5] = array4[2] ^ 0x2D8BB391;
													array4[2] = array4[3] ^ -1433725766;
													int[] array5 = new int[6];
													array5[0] = -1311881281;
													array5[1] = 1353163550;
													array5[2] = -1867891283;
													array5[3] = 75826287;
													array5[4] = -243662049;
													array5[5] = 2055040923;
													array5[4] = array4[3] ^ -2132964340;
													array5[2] = array5[1] ^ -1168905668;
													array5[2] = array5[3] ^ 0x40956B6D;
													array5[0] = array5[5] ^ 0x57A4AB72;
													int num33 = array5[4] ^ -1851246651;
													num = (int)((num4 * 1263229174) ^ 0xBE7268C) ^ num33;
												}
											}
											else
											{
												_0026_0025_003C_0021_0021_0024_0025_002F((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[368 - 6 - 7 - 18]);
												int[] array6 = new int[5];
												array6[0] = 1452057883;
												array6[1] = -589791775;
												array6[2] = 1619031411;
												array6[3] = 1932421846;
												array6[4] = -307501663;
												array6[3] = array6[0] ^ -270067299;
												array6[3] = array6[0] ^ -1947134883;
												array6[0] ^= 123331766;
												int[] array7 = new int[6];
												array7[0] = -1454103486;
												array7[1] = -1056648168;
												array7[2] = -1790700447;
												array7[3] = -1241097550;
												array7[4] = -918462081;
												array7[5] = -833478377;
												array7[1] = array6[1] ^ -922163299;
												array7[5] = array7[1] ^ 0x465CDF3B;
												array7[3] = array7[1] ^ -2049573445;
												int num34 = array7[1] ^ -459073803;
												num = (int)((num4 * 173446702) ^ 0x7DA6C4B0) ^ num34;
											}
										}
										else
										{
											CurrentAssemblyName = string.Empty;
											int[] array8 = new int[5] { 400483632, -212049320, 942041548, 437286612, -1802185544 };
											array8[2] ^= -1174251244;
											array8[4] = array8[2] ^ -716762411;
											int[] array9 = new int[7] { -478320274, -127156523, 1131190148, 1686989933, 702433755, -1836877106, -1989651251 };
											int[][] array10 = new int[2][] { array8, array9 };
											array9[6] = array10[0][3] ^ 0x4F3FCBE3;
											array9[3] = array9[0] ^ -1673105468;
											array9[3] = array9[2] ^ 0x2976B9A1;
											int num35 = array10[1][6] ^ -2102898488;
											num = ((int)num4 * -1248798016) ^ 0x3EA84A00 ^ num35;
										}
									}
									else
									{
										HasLoadedAssembly = false;
										int[,] array11 = new int[3, 4];
										array11[0, 0] = 2143634329;
										array11[0, 1] = 183796446;
										array11[0, 2] = -451382377;
										array11[0, 3] = -2138165022;
										array11[1, 0] = 866311918;
										array11[1, 1] = -626351536;
										array11[1, 2] = 1561316063;
										array11[1, 3] = -2031494152;
										array11[2, 0] = 309990515;
										array11[2, 1] = 2048871269;
										array11[2, 2] = -927452464;
										array11[2, 3] = -801374178;
										array11[0, 0] = array11[2, 2] ^ -1141859019;
										array11[1, 2] = array11[0, 2] ^ -1961532423;
										array11[2, 2] = array11[2, 3] ^ 0x274C32C8;
										int num36 = array11[2, 2] ^ -1983983911;
										num = (int)((num4 * 321665947) ^ 0xEE7D1F7Au) ^ num36;
									}
								}
								else
								{
									SelectedMethodCount = 0;
									int[] array12 = new int[5] { 1137953318, 499349860, -1473827236, 647391602, -1592200196 };
									array12[0] ^= 1513928799;
									array12[3] = array12[0] ^ 0x4F8A950A;
									int[] array13 = new int[5];
									array13[0] = 467612349;
									array13[1] = -1714417317;
									array13[2] = 107472139;
									array13[3] = 1798919801;
									array13[4] = 93544983;
									array13[1] = array12[2] ^ -1426757441;
									array13[3] = array13[0] ^ -771695037;
									array13[3] ^= 272780124;
									array13[3] = array13[4] ^ 0x37679F65;
									int num37 = array13[1] ^ -982299834;
									num = ((int)num4 * -1855717509) ^ -999802968 ^ num37;
								}
							}
							else
							{
								LicensePlanType = null;
								int[] array14 = new int[7];
								array14[0] = 41868130;
								array14[1] = 243750080;
								array14[2] = 1205830897;
								array14[3] = 1903160802;
								array14[4] = 1668316277;
								array14[5] = 545325427;
								array14[6] = 2132750280;
								array14[5] = array14[0] ^ 0x53230EFC;
								array14[6] = array14[4] ^ -250499050;
								array14[1] = array14[4] ^ -2126863778;
								int[] array15 = new int[7] { -294729189, 1908893229, 580314246, 551133021, 1657586058, -1383671433, 1817831002 };
								int[][] array16 = new int[2][] { array14, array15 };
								array15[6] = array16[0][0] ^ 0x31FAC04A;
								array15[3] = array15[5] ^ -1980483578;
								array15[4] = array15[6] ^ -1604886649;
								array15[5] = array15[2] ^ 0x3D6D5201;
								int num38 = array16[1][6] ^ -1226984921;
								num = (int)((num4 * 1530433883) ^ 0xA4D6A397u) ^ num38;
							}
						}
						else
						{
							LicenseRemainingDays = null;
							int[,] array17 = new int[3, 4];
							array17[0, 0] = 1919222607;
							array17[0, 1] = 1641247477;
							array17[0, 2] = -1678731044;
							array17[0, 3] = 156506743;
							array17[1, 0] = -2089146120;
							array17[1, 1] = 379595517;
							array17[1, 2] = 1203535265;
							array17[1, 3] = -1825287442;
							array17[2, 0] = 1264366629;
							array17[2, 1] = -903075483;
							array17[2, 2] = -104049117;
							array17[2, 3] = 644929936;
							array17[1, 0] = array17[0, 0] ^ -1396947748;
							array17[0, 1] = array17[1, 0] ^ -1551276508;
							array17[1, 1] = array17[0, 3] ^ 0x33EF9CB5;
							array17[2, 1] = array17[2, 0] ^ -1163132974;
							int num39 = array17[2, 1] ^ 0x29359DFB;
							num = (int)((num4 * 1655925122) ^ 0xEB2E0C4Cu) ^ num39;
						}
					}
					else
					{
						CurrentLicenseFull = string.Empty;
						int[] array18 = new int[5];
						array18[0] = -1166923389;
						array18[1] = -649690584;
						array18[2] = -1196703625;
						array18[3] = 1030122849;
						array18[4] = 486181267;
						array18[0] = array18[3] ^ 0x2ED507CA;
						array18[0] = array18[2] ^ 0x10E101C0;
						array18[0] = array18[2] ^ 0x4D326624;
						int[] array19 = new int[4] { 421233288, 639322936, -1782049454, 1071118571 };
						int[][] array20 = new int[2][] { array18, array19 };
						array19[3] = array20[0][4] ^ 0x4352E8B5;
						array19[1] = array19[2] ^ 0x53D24094;
						array19[1] = array19[0] ^ 0x258AF8FA;
						int num40 = array20[1][3] ^ -934782693;
						num = ((int)num4 * -1282048305) ^ 0x342D32F1 ^ num40;
					}
				}
				else
				{
					CurrentLicenseDisplay = string.Empty;
					int[] array21 = new int[6];
					array21[0] = 978121462;
					array21[1] = 1174626457;
					array21[2] = 288175507;
					array21[3] = -194989528;
					array21[4] = -2100328595;
					array21[5] = -345158359;
					array21[1] = array21[3] ^ -1419509970;
					array21[5] = array21[1] ^ 0x74373147;
					int[] array22 = new int[4] { -81243817, 1376302963, 847586087, -320114581 };
					int[][] array23 = new int[2][] { array21, array22 };
					array22[3] = array23[0][4] ^ -2671485;
					array22[1] = array22[2] ^ 0x7A1F218F;
					array22[2] = array22[0] ^ -1633995399;
					int num41 = array23[1][3] ^ -817269960;
					num = ((int)num4 * -1029690021) ^ 0x77AF6156 ^ num41;
				}
			}
		}
	}

	public void UpdateMethodSelectionCount(int count)
	{
		SelectedMethodCount = count;
	}

	private static string BuildMaskedLicense(string license)
	{
		if (@_0024_0024_0026_005E_005E_002A_002B(license) > 8)
		{
			uint num2;
			int num4;
			do
			{
				int num = 554246160;
				uint num3;
				num2 = (num3 = (uint)(-(num ^ (615408937 * ~(-875433429 * (-((0x351318A ^ 0x24C2BDF8) - -(-1370908492 - 93531836) + -(~(1962769216 + 1810055858))) - (-250952181 * (1424308402 + (-290493697 + 1975837352)) + ((0x59A869F2 ^ -954606410) + ~1771955953 - (~1658842556 - 48769873 * -1689327112)) - (-(0xDB24889 ^ -1981624791) + 95293172 - -1193642265))))) ^ (((~(--2076435805) + -1729775256) ^ ((-2052983589 * (-(1353126761 - -1560419054) - ~(--1238998730))) ^ -1751162319)) * 578237829 * 300565983)) - ~(--1191692634))) % 3;
				num4 = 0;
				_ = 0;
				for (int num5 = 0; num5 < 1; num5++)
				{
					num4 *= -2131134813;
				}
			}
			while (num2 == (uint)num4);
			int num6 = 1003345866;
			_ = 0;
			for (int num7 = 0; num7 < 2; num7++)
			{
				num6 = -((0x53D4657A ^ 0x545DD1C6) - num6);
				num6 = (num6 ^ -662377837) - 1322884534;
			}
			if (num2 == (uint)num6)
			{
				string text = _0021_0026_0029_0040__005E_0021_003E(license, 0, 4);
				string obj = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-456 + 116)];
				int num8 = @_0024_0024_0026_005E_005E_002A_002B(license);
				int num9 = num8 - 4;
				return _0028_002D_002B_0021_003F_0025__003C(text, obj, _0021_0026_0029_0040__005E_0021_003E(license, num9, num8 - num9));
			}
			int num10 = 1;
			_ = 0;
			for (int num11 = 0; num11 < 2; num11++)
			{
				num10 = ~(-num10);
				num10 = -(num10 ^ -590648463);
			}
			if (num2 == (uint)num10)
			{
			}
		}
		return license;
	}

	private unsafe void ApplySignedOutHeader()
	{
		WindowTitle = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x1033 ^ 0x1104];
		while (true)
		{
			int num = 804967636;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~((-(num2 + (-(1646172014 * -755700963) ^ (-(-(~(~(-586521741 * 1922955831 - (196476575 + 1838353866))))) - (0x5DD14773 ^ -(~(-1682976951 ^ 0x63C97AB9)))) ^ ~(-1350448723 * -1406513692 + -(724007547 * -(201124843 * (641315069 * (1347637183 + 1773163918))))))) ^ 0x538635E6) * -783396979))) % 5;
				int num5 = -1158286590;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~(num5 * -773935531);
					num5 = (num5 + ~-1233879658) * -1887143585;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -783280323;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = 391640161 - ~num7;
					num7 = ~(~num7);
				}
				if (num3 != (uint)num7)
				{
					int num9 = -32;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = ~(~num9);
						num9 = -(num9 ^ 0x8FE1670);
					}
					if (num3 != (uint)num9)
					{
						int num11 = 3353644;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 += --1777762353;
							num11 = -60080436 - num11 * -332651399;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 1534592553;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 *= 469164619;
							}
							if (num3 == (uint)num13)
							{
							}
							return;
						}
						TitlebarSubtitle = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0xA5B2 ^ 0xA484))];
						int[] array = new int[5];
						array[0] = 393175859;
						array[1] = 570406378;
						array[2] = 2024191560;
						array[3] = -1039882446;
						array[4] = 612319608;
						array[2] = array[0] ^ 0x68E1F1D5;
						array[0] = array[2] ^ 0x50A119C9;
						int[] array2 = new int[7];
						array2[0] = 1258478509;
						array2[1] = 216890526;
						array2[2] = -1018693194;
						array2[3] = -215210630;
						array2[4] = -1715953207;
						array2[5] = -709589592;
						array2[6] = 629602218;
						array2[6] = array[4] ^ -432603372;
						array2[5] = array2[6] ^ -205065309;
						array2[1] ^= -1660867964;
						int num15 = array2[6] ^ -2019687490;
						num = ((int)num4 * -102261534) ^ -1267816452 ^ num15;
					}
					else
					{
						ShellSubheader = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(320 + sizeof(int)) ^ sizeof(Guid)];
						int[,] array3 = new int[3, 3];
						array3[0, 0] = -575074808;
						array3[0, 1] = -911790258;
						array3[0, 2] = -664114532;
						array3[1, 0] = 2025742008;
						array3[1, 1] = 1788381579;
						array3[1, 2] = 1436402688;
						array3[2, 0] = 301163527;
						array3[2, 1] = -1976678096;
						array3[2, 2] = -1046534261;
						array3[1, 2] = array3[0, 0] ^ -2026564291;
						array3[2, 1] = array3[2, 0] ^ -540620766;
						array3[2, 2] = array3[1, 0] ^ -974344038;
						int num16 = array3[2, 2] ^ -1688254287;
						num = (int)((num4 * 357052778) ^ 0xAD15931Eu) ^ num16;
					}
				}
				else
				{
					ShellHeader = _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-424 + 113)];
					int[] array4 = new int[7];
					array4[0] = 1248302297;
					array4[1] = 2125594801;
					array4[2] = 1814889462;
					array4[3] = -1642479765;
					array4[4] = -543584728;
					array4[5] = 118564229;
					array4[6] = 2098654629;
					array4[0] = array4[5] ^ 0x14572363;
					array4[0] = array4[5] ^ -1994449022;
					int[] array5 = new int[7];
					array5[0] = 1766719347;
					array5[1] = -360966615;
					array5[2] = -159066801;
					array5[3] = 59092412;
					array5[4] = 1784597284;
					array5[5] = -1999839092;
					array5[6] = -1967233490;
					array5[5] = array4[4] ^ 0x35198E24;
					array5[6] ^= 1441222421;
					array5[4] = array5[1] ^ 0x44EB7A26;
					array5[4] = array5[6] ^ 0x191452B0;
					int num17 = array5[5] ^ -411202064;
					num = (int)((num4 * 864995286) ^ 0x8438C6F2u) ^ num17;
				}
			}
		}
	}

	static void _0026_0025_003C_0021_0021_0024_0025_002F(ObservableObject P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1888965069;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-((((~((-(~(-409357798 ^ 0xE0DA6FB)) + (-620336047 * (-1639656275 * --146552658) - ~(605877349 * (1588281609 * 373734456) + (~(~(-(2107365066 - -890459741))) ^ 0x4060AFDB))) - num2) ^ (((-210688260 ^ -(-(~715177153))) + ~(-(-(1131404991 + -131379202 * 1347699209))) + (~(~(564916053 * -808116059)) + ~((-726906405 + 1735477930) * 861149471) + (-1551171516 + --778244624 - ((0x6F1775B1 ^ -1723642915) + -1955183066) - 1819790458) - -389581247 * 1299979315)) ^ -986715977)) * -1731160623) ^ (((0x9FD20AF ^ -1619883212) + -(--853480374)) * -1511190845 + -1662165651 * ((-219249168 ^ 0x7AE376C) * 1254794341 - ~(-1131208216 ^ 0x95DB84D)))) - 1864764069 * (-(~1470627684) - -(530754965 - 1256140463))) ^ (583172419 * (0x203CD404 ^ -1317215390))) - -967448389) * 1440411247)) % 3;
					int num5 = 2081950374;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 ^ 0x5C44324D) - 2070932814;
						num5 = (num5 + (1029304840 - 659881965)) ^ 0x41EF0A68;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(num7 + (-1066857730 + 1968201956));
						num7 = ~(1354169811 * 1837475063 - num7);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -909163092;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -909163092;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.OnPropertyChanged(P_1);
					int[] array = new int[6];
					array[0] = -1597589237;
					array[1] = 1254250051;
					array[2] = 1371069953;
					array[3] = 1965107858;
					array[4] = -514693393;
					array[5] = -227445352;
					array[5] = array[0] ^ -722728624;
					array[5] = array[2] ^ -1730425890;
					int[] array2 = new int[4];
					array2[0] = -1547788124;
					array2[1] = 1196628901;
					array2[2] = 660962627;
					array2[3] = -674617521;
					array2[1] = array[0] ^ -920602444;
					array2[0] = array2[1] ^ -1107136384;
					array2[3] = array2[1] ^ 0x71CB0C97;
					int num11 = array2[1] ^ 0x27A2D95F;
					num = (int)((num4 * 295438247) ^ 0xBC52A2CFu) ^ num11;
				}
			}
		}
	}

	static bool _0026_003E_002F_0026_0023_0026_0024_0021(string P_0)
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
				int num = 1113750673;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((num2 - ~(~(-(-(-(--1207062248 - (-1069719066 - 1715138219)) - 2051497573))) - (140761117 + (~(-471393563 - -2085130139 - ~1431253016 + 943683377 * -762404913 + (0x34FB582A ^ (-451180897 * --282783814))) + (1406911386 - (--207292332 ^ -1886613163) + (-1228346949 - -(~-1347865700)) - -1541504471))))) * -969013499) + (~(~(-732725336 - -1159227031) + 466343689 + -291024713) - 1787013662))) % 3;
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
					int num7 = 893258686;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x353E0BBC;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1165231019;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9 ^ -703819585;
							num9 = (num9 * -1128209625) ^ -2083599729;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = string.IsNullOrWhiteSpace(P_0);
					int[] array = new int[6];
					array[0] = -147377837;
					array[1] = 485040009;
					array[2] = -1638317720;
					array[3] = 597602316;
					array[4] = 168779939;
					array[5] = -1264271169;
					array[1] = array[5] ^ -905221788;
					array[0] = array[1] ^ -760227044;
					int[] array2 = new int[5] { -444199872, -1245812540, 1934840480, 1646296783, -1537997827 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][3] ^ -1986655842;
					array2[4] = array2[2] ^ -2052331493;
					array2[4] = array2[1] ^ 0x62F33D33;
					int num11 = array3[1][3] ^ 0x144D5206;
					num = ((int)num4 * -659614865) ^ -1396415923 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static char _0026_003E_003E_0028_005E_005E_002F_0025(string P_0, int P_1)
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
				int num = -1395942148;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(num2 + ~((-(-1085802858 + --1064411173 - (167908108 - -454863683 + -45130745 * -1363380787) + 54124447 + -(-1941079747 + (208565359 * 2117286934 - 1859057871))) ^ -(-(~-2028594804))) * 1896765833)) * 632946253) ^ (~(-(-444000415 ^ 0x3F7383BC) - -(-643135440 ^ 0x140972E7)) - (809507368 + ~(~(~-453691006)) + (-(-(1784543021 * 2095163277)) ^ (634298583 * (-991499034 + (0x1A05B07F ^ 0x5F5E3FDE)))))) ^ 0x2BBA7893)) % 3;
					int num5 = 524336244;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -1041687101 + -279894817 - num5 + 1997354695;
						num5 = ~(num5 - (-1411918741 + 1825523397));
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1032127434;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -343485459;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2146680855;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (-530114723 - 1605996052 - num9) ^ 0x23B81EC1;
							num9 = 265452804 + 810873873 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0[P_1];
					int[] array = new int[4] { 1059653599, 54010056, 1811451325, 1045089899 };
					array[2] ^= 210273825;
					array[3] ^= 905160153;
					array[3] = array[1] ^ 0x5E3F73CB;
					int[] array2 = new int[5];
					array2[0] = -1543879351;
					array2[1] = 388216374;
					array2[2] = -1342458075;
					array2[3] = -1083243383;
					array2[4] = 1763462791;
					array2[3] = array[1] ^ 0x6CBCCDAD;
					array2[2] ^= -1496909883;
					array2[2] = array2[3] ^ -246381420;
					array2[1] = array2[0] ^ 0x3B5C1D62;
					int num11 = array2[3] ^ -158729792;
					num = (int)((num4 * 1575867802) ^ 0xCB5A8A00u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static char _003D_0040_003C__0025_0028_0024_002D(char P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return char.ToUpper(P_0);
		}
	}

	static string _002F__003F_0024_002A_002B_005E_002A(string P_0, int P_1)
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
				int num = 1061656551;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(-(-(((num2 - (~(0x6F62E58A ^ -1234980732) * -495450935 - ((-(-1177197876 - 1427466073) + -(-1179688131 * 1803537014) + (~(-(0x1441AD36 ^ 0x36A1C463)) - ((-589706892 ^ -762028360) + -1821626672 * 62758419 * -449068335) - (1584488494 - ~(~-1544930189 - 358704890 - (-1197907461 ^ 0x99CCA5))))) ^ -954350772))) ^ (~(-2110539411 * ~(-(~-1522808338)) - -(~((0x4AFB86C8 ^ -1604864132) - --246309423)) + (~(-1861512532 * 1693544279) - ~-63034096 + ~(605940915 - 1077883752) * 1624939417 + (~(0x3EAA884D ^ -1102617417) - 1872993625 * ~(-1350832206 - -1640768241)))) * -766664859)) * -1072862433) * 854109435) * 264001493)) ^ 0x3A11829B)) % 3;
					int num5 = -944103776;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * 574031987 - -1029469615;
						num5 = ~num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -259997375;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7 ^ 0x1108820D;
						num7 = (num7 - (-518287314 - 1482321553)) ^ -35361859;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -453136117;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = -453136115 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.Substring(P_1);
					int[,] array = new int[3, 3];
					array[0, 0] = -1493042957;
					array[0, 1] = -2013026440;
					array[0, 2] = 1695287571;
					array[1, 0] = 1760714829;
					array[1, 1] = -798071573;
					array[1, 2] = -1101863473;
					array[2, 0] = -209300192;
					array[2, 1] = -1168675913;
					array[2, 2] = -452533154;
					array[1, 2] = array[0, 2] ^ 0x1DF0F4CA;
					array[1, 0] ^= 1545245840;
					array[1, 1] = array[0, 0] ^ -1933291789;
					int num11 = array[1, 1] ^ 0x30028319;
					num = (int)((num4 * 571071436) ^ 0x48D3CF58) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string _003D_0028_003C_002D_0024_0040_002A_0029(string P_0)
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
				int num = 963065905;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(-num2) + -(-414441596)) * 1421695737)) % 3;
					int num5 = 465162724;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 *= 1100977389;
						num5 = (num5 ^ -1983012067) * -1439545369;
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
						int num9 = 1698984264;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 *= 777639339;
							num9 = 1046978379 - (num9 + ~-693254872);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.ToLower();
					int[] array = new int[5];
					array[0] = 1749684975;
					array[1] = 1361517320;
					array[2] = 1964152635;
					array[3] = 1647578329;
					array[4] = 959942577;
					array[0] = array[2] ^ -1096795156;
					array[1] = array[4] ^ -336998290;
					int[] array2 = new int[7] { -391693819, -2111024284, -977293983, -941060694, -966616838, -1417662607, -2145258770 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[5] = array3[0][2] ^ -1918356838;
					array2[0] = array2[2] ^ -1021418227;
					array2[4] = array2[0] ^ 0xDB56AB3;
					array2[3] = array2[6] ^ 0x6344CD07;
					int num11 = array3[1][5] ^ -1476041245;
					num = (int)((num4 * 451262798) ^ 0x506CEE06) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static ReadOnlySpan<char> _002D_003E_003C_003E_0029_0025_002A_002A(string P_0)
	{
		ReadOnlySpan<char> result = default(ReadOnlySpan<char>);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1965279763;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((num2 + ~((407966793 * ~(-(-(-1572020417 * -1034678711))) + ~(~(-1320769123 ^ -1780590816) - ((-1356322379 ^ -703502004) - --2112954957) - ~(-311735356 * -1647965161)) - 1986220388) ^ (-(-865440820 + -(0x5D6E60C5 ^ 0x255302B2)) + (((-(0x6243ADD5 ^ -914241756) - ~(-1462591821 ^ -645541039) + (-(~831128636) - (-630084583 ^ -220666952))) ^ 0x7BFF2FBC) + (-(~-575320736) + (-1993216070 + -1330480951 + (-771100433 ^ 0x3AA3B627)) - (0x3C28CB8F ^ 0x6CD40FB8)) * 752553603)))) * 1881693131 * -58143765 - (~(470908579 * (-(1050613846 + -1936406987) + -(-1569786131 + -614048937))) - (-1838848061 + (-592708412 ^ 0x1D460A7F) - -(-(1627386795 * -2000677608)) - (--944011842 - (71479203 + 1769144737 * --1091716989)))))) % 3;
					int num5 = -2;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(~num5);
						num5 = -(num5 ^ --1714474181);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = 1942232272 - (num7 - 568534870);
						num7 = num7 - 9282034 * 1303661601 + -1695541707;
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
					result = P_0;
					int[] array = new int[6];
					array[0] = 1211006479;
					array[1] = 955304282;
					array[2] = -980434798;
					array[3] = 446431337;
					array[4] = 1338276123;
					array[5] = 1069526955;
					array[3] = array[0] ^ -261007559;
					array[1] = array[5] ^ 0x7475B984;
					array[3] = array[0] ^ -199151669;
					int[] array2 = new int[6];
					array2[0] = 934176476;
					array2[1] = -2021427275;
					array2[2] = 577037343;
					array2[3] = 1477747298;
					array2[4] = -377415892;
					array2[5] = -1498425645;
					array2[4] = array[5] ^ -1607690887;
					array2[1] = array2[2] ^ -1158012621;
					array2[5] = array2[2] ^ 0x5C3CFA2A;
					array2[3] = array2[0] ^ -708876323;
					int num11 = array2[4] ^ 0x2D8DF4BE;
					num = (int)((num4 * 213124561) ^ 0x25D15F08) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string _002A_0029_0026_005E_0029_003D_002D_002F(ReadOnlySpan<char> P_0, ReadOnlySpan<char> P_1)
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
				int num = -1984780742;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(-(~(-1152877814 - 1357029815 * -78777467 * 588895067 + (-1753948176 + 2129208246 - 1662909799 * 1811324769 - -1306082933) - (1835577469 * ~1082757138 - (0x7FF04654 ^ -1893531880) - ~(--978082020 * 1147957505))))) - ~num2 - (~(-421144793 ^ (-(425944649 * -1209275576) ^ -1074528389)) - -(-(131955275 - -863361410 + 1285982423 - -(637276655 * 1682979512))) + -8227134) - (0x168D1DD3 ^ -(~58846906 - (0x290FC2C7 ^ 0x216239E5)) ^ (1848531051 * (~-1330759977 * -1913540639) - (-(-(595695568 + 1620487924)) ^ 0x18E4EB9)))) * -1995225285 * 266720121)) % 3;
					int num5 = 1566025536;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 * -314447893) ^ -1400139515;
						num5 = (num5 * -808577267) ^ 0x4EC202A1;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(num7 - (1978429914 - -935903172));
						num7 = -(-num7);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 817030;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ -140201335) - 1226922748;
							num9 = -((-1031443171 ^ -394153125) - num9);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = string.Concat(P_0, P_1);
					int[,] array = new int[4, 4];
					array[0, 0] = -922277603;
					array[0, 1] = 684850051;
					array[0, 2] = -808499566;
					array[0, 3] = -828287826;
					array[1, 0] = 1813208001;
					array[1, 1] = -1598413661;
					array[1, 2] = -493039419;
					array[1, 3] = -1256895796;
					array[2, 0] = -1244258817;
					array[2, 1] = -697260716;
					array[2, 2] = 1576154648;
					array[2, 3] = -931245022;
					array[3, 0] = 1514634717;
					array[3, 1] = -1484947400;
					array[3, 2] = -707635780;
					array[3, 3] = 1087132686;
					array[1, 1] = array[3, 0] ^ -1624824599;
					array[1, 1] = array[3, 1] ^ 0x3C173862;
					array[3, 2] = array[0, 1] ^ 0x6F805E58;
					array[1, 1] = array[2, 3] ^ 0x1D3CCCA3;
					int num11 = array[1, 1] ^ 0x77AE2E9E;
					num = ((int)num4 * -1849879488) ^ 0x7DF26AC0 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _003E_0025_0029_002D__0024_003D_003C(ActivityEntry P_0, SeverityLevel P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 62517571;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((((~(-(~(num2 + -(-(~1526289236)) * 13240637) * -1279866835)) - -203602578) * -392878447 - (-1663940409 - -361825175 + (-604403237 + 1522832187))) ^ 0x3D94F7A1) - -2030478912)) % 3;
					int num5 = -2105354043;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= -2105354043;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 304047765;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x121F6694;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 17638352;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x10D23D2;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Level = P_1;
					int[] array = new int[5];
					array[0] = -346614941;
					array[1] = -1706833353;
					array[2] = 551975600;
					array[3] = -828650002;
					array[4] = -1447317814;
					array[4] = array[0] ^ 0x1F29557;
					array[4] ^= 406648617;
					int[] array2 = new int[6];
					array2[0] = 1850953046;
					array2[1] = 155704499;
					array2[2] = 968809483;
					array2[3] = 1952294754;
					array2[4] = 721780365;
					array2[5] = -488264759;
					array2[1] = array[3] ^ -1594979023;
					array2[4] = array2[3] ^ -2018482525;
					array2[3] = array2[5] ^ 0x4A240209;
					array2[2] = array2[5] ^ 0x4807F210;
					int num11 = array2[1] ^ 0x5FCBFD1;
					num = (int)((num4 * 266844788) ^ 0xD0FEF76Cu) ^ num11;
				}
			}
		}
	}

	static void _0029_0028_003E_002F_0025_005E_005E_002B(ActivityEntry P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1935660338;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-((((-num2 ^ (-413542009 * (-1274921131 ^ 0x1E812992) + 201080995 * (784598241 * (~-1084545049 - ~(-(-1459045319 ^ -293304084))))) ^ ~(-(0x3AA43C84 ^ ~(-(-2107690415 + 433087084 - -1279565540))))) * 1446500999 * -1274578929 + -1433682389) ^ (-(-1377362977 * 745995793) + 326668890)) * -1715992021)))) % 3;
					int num5 = 499122076;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 - (-397262759 - -1591582130)) ^ 0x4E27BF3C;
						num5 = (num5 ^ 0x24E98B91) - -806083129;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1219277869;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -1841316955;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1104909140;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= -1104909138;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Message = P_1;
					int[,] array = new int[3, 3];
					array[0, 0] = 349748487;
					array[0, 1] = -1576448669;
					array[0, 2] = -345098113;
					array[1, 0] = -257682356;
					array[1, 1] = 1238508290;
					array[1, 2] = -1051001730;
					array[2, 0] = 154231218;
					array[2, 1] = 285418050;
					array[2, 2] = -631390441;
					array[2, 0] = array[1, 2] ^ -1734272643;
					array[2, 2] ^= 621542880;
					array[2, 2] ^= -1659263843;
					array[2, 0] = array[1, 1] ^ 0x2B183BFC;
					int num11 = array[2, 0] ^ -27516505;
					num = ((int)num4 * -1191557541) ^ 0x547344F0 ^ num11;
				}
			}
		}
	}

	static DateTime _003C_0025_005E_0029_003C_0025_0024_002D()
	{
		DateTime now = default(DateTime);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 280310683;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(num2 * -990203273 - ((-654428688 - (~(823228161 * 607273602) + -(--191343736 ^ -1206089909)) * 512528285 - 540547675) ^ (-1295259221 * ((578703735 * -((539339557 - (-1941707716 - 1248858523)) * -1414945937)) ^ ((0x53F7AC8E ^ 0x47034EF8) + 1131655269 * (-826156080 + 736999803) + (--792301009 + 95877075 * 715614071 - 1406346447 * 58926016) + (209015 - -719519754 + --532407769 - (0xE21C5D3 ^ 0x2CA37129)) * -890232797))))) ^ -(1944707705 + (-619101758 - 1060202985 + (0x41BFFE62 ^ 0x4973CF85) - -(--1625582643 + -1923064417 * 1948815826))))) % 3;
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
					int num7 = -1060896216;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -1060896218;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1620946959;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 ^= --757602263;
							num9 = num9 - (-1533482115 + 1469759562) + -1250260900;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					now = DateTime.Now;
					int[] array = new int[7];
					array[0] = -738944242;
					array[1] = -773965743;
					array[2] = 689796350;
					array[3] = -242744451;
					array[4] = -1681258130;
					array[5] = -1424344379;
					array[6] = 1715175087;
					array[6] = array[0] ^ 0x5886AA0C;
					array[2] = array[6] ^ 0x5F3EB993;
					int[] array2 = new int[6];
					array2[0] = 1767610272;
					array2[1] = -260062446;
					array2[2] = 1354270697;
					array2[3] = -1283547131;
					array2[4] = -1008510224;
					array2[5] = 545754871;
					array2[4] = array[5] ^ 0x72C231A7;
					array2[1] = array2[2] ^ 0x52022F0E;
					array2[5] = array2[1] ^ -873434177;
					array2[0] = array2[2] ^ -1862396960;
					int num11 = array2[4] ^ 0x691A24C0;
					num = ((int)num4 * -567949259) ^ 0xC66326 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return now;
	}

	static void _0023_0028_003F_002F_005E_002A_002F_0021(ActivityEntry P_0, DateTime P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1276587031;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-((num2 - -(~(~(~(~((0x7FDE3238 ^ 0x24B7C1DB) + (~1002557090 - -1836311976))) ^ 0x6CC8DBA5))) - -1386152417 * (2008052200 + (1582629515 * -1025289024 - ~(1042846977 + -897237395)) + ((-1558615169 ^ 0x76B49876) + ~(-((-1655065543 ^ 0x15B21269) + --424494904))) + ~-608582573) - (-1981042419 * (0x7455FA46 ^ (~(1326208222 * 1230368233 + (709687035 + -1612728898)) + ~(-(~1339671367)))) - (980898163 * ~(-1805395933 * (1253579393 * (-1370111453 * 425392363))) + ((0x53343F1F ^ (-79365381 ^ -84354490)) + (1187441809 - -644565682 - 1227920148 - ~(-1383941657 * -1162420529)) + (-584289046 ^ 0x49CB9A49) * 1005705739)))) * -278143709) * -732645315) ^ -327784418)) % 3;
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
					int num7 = 1671689806;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 - -1800453015 * -2100069189) ^ 0x10FF788B;
						num7 = -(num7 * 338587085);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2053242179;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x7A61FD42;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Timestamp = P_1;
					int[] array = new int[5];
					array[0] = -741486920;
					array[1] = 413330914;
					array[2] = 470501786;
					array[3] = 2063794894;
					array[4] = -1005164735;
					array[4] = array[1] ^ -1904156129;
					array[3] = array[1] ^ 0x2866DC11;
					array[4] = array[1] ^ -403808575;
					int[] array2 = new int[7];
					array2[0] = -1730103400;
					array2[1] = -306490926;
					array2[2] = 1549266976;
					array2[3] = 1219448739;
					array2[4] = -640450798;
					array2[5] = -1865938093;
					array2[6] = -913279796;
					array2[4] = array[0] ^ 0x279E9DF1;
					array2[5] ^= 62220576;
					array2[5] = array2[3] ^ 0x788FCC9F;
					int num11 = array2[4] ^ 0x496EA244;
					num = (int)((num4 * 2146912641) ^ 0x6071D39A) ^ num11;
				}
			}
		}
	}

	static int @_0024_0024_0026_005E_005E_002A_002B(string P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return P_0.Length;
		}
	}

	static string _0021_0026_0029_0040__005E_0021_003E(string P_0, int P_1, int P_2)
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
				int num = -1019346289;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-((-(~(~-720316332)) - -((-((0x3171E9EE ^ 0x469A8DF0) + 1380534519) + ~(-288996951 * -(-(1279585755 + -498466818 * -806569925))) - -num2) * -948703871) * -1694205109) ^ -2059333553) * -439135205))) % 3;
					int num5 = 2;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 ^= -2051865792;
						num5 = ~num5 ^ -772731069;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 802747061;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 802747060;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1607875470;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 - --546541985) * 817272293;
							num9 = 232816980 - num9 * 1190850923;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.Substring(P_1, P_2);
					int[] array = new int[4];
					array[0] = 1980214866;
					array[1] = -880924977;
					array[2] = 1774671191;
					array[3] = 1119677673;
					array[3] = array[1] ^ 0x6BD0B969;
					array[1] = array[0] ^ -444862981;
					int[] array2 = new int[5] { -1396444381, -1057167738, 1236174244, -2110769348, 733741848 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][0] ^ -1516866322;
					array2[4] = array2[2] ^ -1008779787;
					array2[3] = array2[0] ^ -578526270;
					int num11 = array3[1][2] ^ -307004813;
					num = (int)((num4 * 155885022) ^ 0x9251D038u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string _0028_002D_002B_0021_003F_0025__003C(string P_0, string P_1, string P_2)
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
				int num = 147681381;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(((num2 - -(1197707103 * (-1975178204 ^ 0x4CE506E) + ((~(0x22FA2F2E ^ --490913108) + (-(~2132132379) - (0x64B8D917 ^ --1640507409)) + -1543326351 - -1911174288) ^ 0x6EE99FDC))) ^ 0x2150182E) * -13970439 + ((-(~(1732187089 - -852387192) - (-1296307702 + 1744112456 - ~-1362578646)) * 1796966793) ^ (910679398 - -406337733 * (1138293051 + -1087457117 + -188918406)))))) % 3;
					int num5 = -2088746768;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 ^ 0x7678F8C9) - -1787187597;
						num5 = -1463800513 - num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -324624818;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= -324624817;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1351786400;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 * 876358903);
							num9 = ~num9 + -531497804;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0 + P_1 + P_2;
					int[] array = new int[7];
					array[0] = 1408737999;
					array[1] = -1954853432;
					array[2] = 305826335;
					array[3] = -1034062366;
					array[4] = -60741925;
					array[5] = -1582641534;
					array[6] = 1346869779;
					array[1] = array[6] ^ -331638510;
					array[3] ^= 14824092;
					array[0] = array[6] ^ -1887608547;
					int[] array2 = new int[7] { -1546111446, 797014257, -2070038306, -1139938633, -1196341727, 1112798636, -278833695 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[5] = array3[0][2] ^ 0x7CD1C40;
					array2[0] = array2[4] ^ 0x34D9B1C1;
					array2[0] = array2[5] ^ 0x73051CF6;
					int num11 = array3[1][5] ^ -1870008466;
					num = (int)((num4 * 722004888) ^ 0x412580B0) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}
}
