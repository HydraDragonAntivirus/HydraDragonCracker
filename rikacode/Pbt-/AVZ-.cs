using System;
using System.CodeDom.Compiler;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Markup;
using Microsoft.Windows.AppLifecycle;
using RikaNET.Core.Services;
using RikaNET.WinUI;
using RikaNET.WinUI.RikaNET_WinUI_XamlTypeInfo;
using RikaNET.WinUI.ViewModels;
using Windows.ApplicationModel.Activation;
using Windows.Foundation;
using Windows.Storage;
using wkj_003D;

namespace Pbt_003D;

public class AVZ_003D : Application, IXamlMetadataProvider
{
	[CompilerGenerated]
	private sealed class _003C_003Ec__DisplayClass14_0
	{
		[StructLayout(LayoutKind.Auto)]
		private struct _003C_003COnAppActivated_003Eb__0_003Ed : IAsyncStateMachine
		{
			public int _003C_003E1__state;

			public AsyncVoidMethodBuilder _003C_003Et__builder;

			public _003C_003Ec__DisplayClass14_0 _003C_003E4__this;

			private TaskAwaiter _003C_003Eu__1;

			private void MoveNext()
			{
				int num = _003C_003E1__state;
				_003C_003Ec__DisplayClass14_0 _003C_003Ec__DisplayClass14_1 = _003C_003E4__this;
				try
				{
					if (num != 0)
					{
						goto IL_0023;
					}
					goto IL_0ef4;
					IL_0023:
					int num2 = -254914903;
					goto IL_0028;
					IL_0028:
					TaskAwaiter awaiter = default(TaskAwaiter);
					while (true)
					{
						int num3 = num2;
						uint num5;
						uint num4 = (num5 = (uint)(~(~((849573075 * (0x504E200B ^ -929490096) + (1501260020 + (731952609 - 726176466) + -(1489606701 + -764384637)) - (~(~num3 + (-(-1066365340 ^ 0x3BDCCCF) - ((-55938527 * -1051912488 - (~(0x495BFE8A ^ 0x141418F7) + -(45824084 + (0x6FE3BFD8 ^ 0x38E96297)))) ^ (1474076823 + -(-673331979 * -412088295))) + ~(-(500591404 + -745935181)))) + ((~(-1481162472 ^ 0x5056911F) - (0xEDE7226 ^ (-2049784917 ^ --284802439)) + -1761155659 * ~(-900426535 * -352551557) * -2027252215) ^ -1894592934) - (~(0x17753DF9 ^ -1313679194) - (-129852905 ^ 0x2B827132) - (-((-1251707858 - 1507297919) * 31477489) - -(0x55DCDE94 ^ -459371307))))) * 41530471)) * -1578651631)) % 13;
						uint num6 = num4;
						int num7 = 9;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -(~num7);
							num7 = ~num7 ^ 0x38F90001;
						}
						if (num6 == (uint)num7)
						{
							break;
						}
						uint num9 = num4;
						int num10 = 7;
						_ = 0;
						for (int num11 = 0; num11 < 2; num11++)
						{
							num10 = ~(num10 + --67358115);
							num10 = -1264460022 - -num10;
						}
						if (num9 == (uint)num10)
						{
							_003C_003Ec__DisplayClass14_1.mainWindow.xHA_003D();
							int[] array = new int[5] { -2130828776, -1236254020, 2004381034, 1092682637, -1872166277 };
							array[4] ^= -596793625;
							array[2] = array[3] ^ 0x5E850023;
							int[] array2 = new int[7];
							array2[0] = 1523287333;
							array2[1] = -1902557703;
							array2[2] = 1267592354;
							array2[3] = -1751904738;
							array2[4] = 797450144;
							array2[5] = 438578966;
							array2[6] = 2145659121;
							array2[2] = array[1] ^ -503382717;
							array2[4] = array2[6] ^ -453031041;
							array2[4] ^= 1675576031;
							array2[0] = array2[2] ^ -1000782815;
							int num12 = array2[2] ^ -836293689;
							num2 = (int)((num5 * 824554186) ^ 0xF32CB958u) ^ num12;
							continue;
						}
						uint num13 = num4;
						int num14 = -1629518593;
						_ = 0;
						for (int num15 = 0; num15 < 1; num15++)
						{
							num14 ^= -1629518594;
						}
						if (num13 == (uint)num14)
						{
							awaiter = _0025_003D_003C_0025_003F_0040_0024_0029(_003C_003Ec__DisplayClass14_1.mainWindow.igp_003D());
							int[] array3 = new int[4];
							array3[0] = -1321437853;
							array3[1] = 460423844;
							array3[2] = 1463777893;
							array3[3] = -2101349982;
							array3[1] = array3[2] ^ -294275780;
							array3[0] = array3[1] ^ 0x481B8DBD;
							array3[3] = array3[0] ^ -756954651;
							int[] array4 = new int[7];
							array4[0] = 159648065;
							array4[1] = -2055344940;
							array4[2] = -637193115;
							array4[3] = -40069339;
							array4[4] = 63500277;
							array4[5] = -1215147786;
							array4[6] = -1044429331;
							array4[2] = array3[2] ^ 0x4F03DC61;
							array4[3] = array4[5] ^ -1841332362;
							array4[0] ^= -795330886;
							int num16 = array4[2] ^ 0x4DCA3F84;
							num2 = (int)((num5 * 1157156335) ^ 0x81B773ADu) ^ num16;
							continue;
						}
						uint num17 = num4;
						int num18 = -1656183974;
						_ = 0;
						for (int num19 = 0; num19 < 1; num19++)
						{
							num18 ^= -1656183976;
						}
						if (num17 == (uint)num18)
						{
							bool ısCompleted = awaiter.IsCompleted;
							int[] array5 = new int[7];
							array5[0] = 640609904;
							array5[1] = -311664201;
							array5[2] = 1589082334;
							array5[3] = 258506281;
							array5[4] = -1212413151;
							array5[5] = 161321438;
							array5[6] = -1006576065;
							array5[3] = array5[4] ^ 0x48FBBB86;
							array5[1] ^= 102961923;
							array5[4] = array5[5] ^ 0x7D0E89D;
							int[] array6 = new int[4];
							array6[0] = -2000093480;
							array6[1] = -866953794;
							array6[2] = -1786190182;
							array6[3] = -1291778422;
							array6[2] = array5[2] ^ -1664946223;
							array6[3] = array6[1] ^ -378070695;
							array6[1] = array6[2] ^ -800344421;
							array6[0] ^= -955841261;
							int num20 = array6[2] ^ -1028578501;
							int[] array7 = new int[4];
							array7[0] = 364902089;
							array7[1] = -2063294851;
							array7[2] = 987028046;
							array7[3] = 847333315;
							array7[3] = array7[0] ^ -687638897;
							array7[1] = array7[3] ^ -679939865;
							array7[2] ^= 1830624396;
							int[] array8 = new int[7];
							array8[0] = 36462255;
							array8[1] = 970028496;
							array8[2] = -911663751;
							array8[3] = 335176451;
							array8[4] = -1179271180;
							array8[5] = 1489322876;
							array8[6] = 367964041;
							array8[6] = array7[0] ^ 0x5C0491B5;
							array8[1] = array8[6] ^ 0x2B0B474A;
							array8[1] = array8[0] ^ 0x20923CB4;
							array8[1] = array8[0] ^ 0x4111A054;
							int num21 = array8[6] ^ -847328279;
							int num22 = (int)(num5 * 1340817174) ^ -2057987150;
							num20 ^= num22;
							num21 ^= num22;
							int num23;
							int num24;
							if (!ısCompleted)
							{
								num23 = num21;
								num24 = num23;
							}
							else
							{
								num23 = num20;
								num24 = num23;
							}
							num2 = num23 ^ num22;
							continue;
						}
						uint num25 = num4;
						int num26 = 2081871456;
						_ = 0;
						for (int num27 = 0; num27 < 2; num27++)
						{
							num26 = -num26 ^ 0x15F64881;
							num26 = num26 * 717072145 - -1333032693;
						}
						if (num25 == (uint)num26)
						{
							num = (_003C_003E1__state = 0);
							int[] array9 = new int[4] { 1290726455, -1396566396, 1219596758, 328420783 };
							array9[0] ^= -846394288;
							array9[0] = array9[3] ^ -1513348387;
							array9[0] = array9[2] ^ 0x41CB8225;
							int[] array10 = new int[4];
							array10[0] = 1548733838;
							array10[1] = -582843668;
							array10[2] = -2147308741;
							array10[3] = -1821289618;
							array10[3] = array9[3] ^ -1947126546;
							array10[0] = array10[2] ^ -738393199;
							array10[2] = array10[1] ^ -830191496;
							array10[0] = array10[3] ^ 0x7F6A2B66;
							int num28 = array10[3] ^ 0x26568504;
							num2 = (int)((num5 * 978631660) ^ 0x463DAF60) ^ num28;
							continue;
						}
						uint num29 = num4;
						int num30 = -1262260415;
						_ = 0;
						for (int num31 = 0; num31 < 1; num31++)
						{
							num30 -= -1262260418;
						}
						if (num29 == (uint)num30)
						{
							_003C_003Eu__1 = awaiter;
							int[] array11 = new int[7];
							array11[0] = 1628552141;
							array11[1] = 586024373;
							array11[2] = -1398966290;
							array11[3] = -707376974;
							array11[4] = -1675465362;
							array11[5] = -209053113;
							array11[6] = 63809636;
							array11[2] = array11[3] ^ -1923000100;
							array11[2] = array11[5] ^ -122719558;
							array11[4] = array11[6] ^ -1675969739;
							int[] array12 = new int[4] { -1342947438, -922474798, -1647445007, 428603731 };
							int[][] array13 = new int[2][] { array11, array12 };
							array12[1] = array13[0][3] ^ 0x3B83B143;
							array12[2] ^= 663603679;
							array12[0] = array12[1] ^ -1103551672;
							array12[2] = array12[0] ^ -419922551;
							int num32 = array13[1][1] ^ 0x31F0D9D3;
							num2 = (int)((num5 * 754074378) ^ 0x1087C030) ^ num32;
							continue;
						}
						uint num33 = num4;
						int num34 = -634878843;
						_ = 0;
						for (int num35 = 0; num35 < 2; num35++)
						{
							num34 = (num34 ^ -1547152184) * -808440065;
							num34 = -1434085604 - (~1608955938 - num34);
						}
						if (num33 == (uint)num34)
						{
							_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
							int[] array14 = new int[7];
							array14[0] = 619141538;
							array14[1] = 1690482663;
							array14[2] = -1351643828;
							array14[3] = -1747515252;
							array14[4] = -714165675;
							array14[5] = 1333501433;
							array14[6] = 1761294574;
							array14[4] = array14[6] ^ 0x437D8D3F;
							array14[0] = array14[4] ^ 0x66CA82B4;
							int[] array15 = new int[7] { 1583855190, 2080670128, -1671994463, 1927164891, 538013204, -700484487, -320214619 };
							int[][] array16 = new int[2][] { array14, array15 };
							array15[4] = array16[0][2] ^ 0x77674451;
							array15[2] = array15[6] ^ -1562702129;
							array15[6] = array15[5] ^ -474926470;
							int num36 = array16[1][4] ^ 0x7BF5A72E;
							num2 = (int)((num5 * 865092024) ^ 0x461E5DD8) ^ num36;
							continue;
						}
						uint num37 = num4;
						int num38 = 669616566;
						_ = 0;
						for (int num39 = 0; num39 < 2; num39++)
						{
							num38 = ~num38 + -849828112;
							num38 = num38 * -468023173 * -1972861735;
						}
						if (num37 == (uint)num38)
						{
							return;
						}
						uint num40 = num4;
						int num41 = 586015624;
						_ = 0;
						for (int num42 = 0; num42 < 1; num42++)
						{
							num41 = 586015630 - num41;
						}
						if (num40 == (uint)num41)
						{
							goto IL_0ef4;
						}
						uint num43 = num4;
						int num44 = 1131299553;
						_ = 0;
						for (int num45 = 0; num45 < 2; num45++)
						{
							num44 = -num44 + 565649772;
							num44 = -num44;
						}
						if (num43 == (uint)num44)
						{
							_003C_003Eu__1 = default(TaskAwaiter);
							int[] array17 = new int[6] { -418182664, 939481464, 1106965967, 1850828017, -893741022, 1493261124 };
							array17[4] ^= 140700994;
							array17[1] = array17[3] ^ -1106101750;
							int[] array18 = new int[4];
							array18[0] = -119779415;
							array18[1] = -95951238;
							array18[2] = 768443396;
							array18[3] = -2105817087;
							array18[1] = array17[0] ^ 0x83F8678;
							array18[3] ^= 656950140;
							array18[3] = array18[2] ^ -725710287;
							int num46 = array18[1] ^ 0x271D9031;
							num2 = (int)((num5 * 208707939) ^ 0x95BDD5E4u) ^ num46;
							continue;
						}
						uint num47 = num4;
						int num48 = -793833976;
						_ = 0;
						for (int num49 = 0; num49 < 2; num49++)
						{
							num48 = num48 * -1100272769 - -856526855;
							num48 -= ~-1998158140;
						}
						if (num47 == (uint)num48)
						{
							num = (_003C_003E1__state = -1);
							int[,] array19 = new int[3, 3];
							array19[0, 0] = 2082575488;
							array19[0, 1] = -35795440;
							array19[0, 2] = -265350591;
							array19[1, 0] = -259454000;
							array19[1, 1] = -1777099318;
							array19[1, 2] = 178111955;
							array19[2, 0] = 1345728782;
							array19[2, 1] = -571230787;
							array19[2, 2] = -1612085473;
							array19[1, 2] = array19[1, 1] ^ 0x28A526CA;
							array19[0, 1] = array19[0, 2] ^ 0x50754D2F;
							array19[1, 2] = array19[1, 1] ^ -339340003;
							array19[1, 0] = array19[0, 2] ^ -1170264327;
							int num50 = array19[1, 0] ^ 0x4AD4888C;
							num2 = ((int)num5 * -1000476646) ^ 0x7E87A368 ^ num50;
							continue;
						}
						uint num51 = num4;
						int num52 = 1145029663;
						_ = 0;
						for (int num53 = 0; num53 < 1; num53++)
						{
							num52 -= 1145029659;
						}
						if (num51 == (uint)num52)
						{
							awaiter.GetResult();
							num2 = 930094465;
							continue;
						}
						uint num54 = num4;
						int num55 = -916329016;
						_ = 0;
						for (int num56 = 0; num56 < 2; num56++)
						{
							num55 = 1809223403 - (num55 - --902373315);
							num55 = 1037613663 * 691263633 - num55;
						}
						if (num54 == (uint)num55)
						{
						}
						goto end_IL_001a;
					}
					goto IL_0023;
					IL_0ef4:
					awaiter = _003C_003Eu__1;
					num2 = -2019311431;
					goto IL_0028;
					end_IL_001a:;
				}
				catch (Exception exception)
				{
					while (true)
					{
						int num57 = 882304115;
						while (true)
						{
							int num3 = num57;
							uint num5;
							uint num4 = (num5 = (uint)(~(~((849573075 * (0x504E200B ^ -929490096) + (1501260020 + (731952609 - 726176466) + -(1489606701 + -764384637)) - (~(~num3 + (-(-1066365340 ^ 0x3BDCCCF) - ((-55938527 * -1051912488 - (~(0x495BFE8A ^ 0x141418F7) + -(45824084 + (0x6FE3BFD8 ^ 0x38E96297)))) ^ (1474076823 + -(-673331979 * -412088295))) + ~(-(500591404 + -745935181)))) + ((~(-1481162472 ^ 0x5056911F) - (0xEDE7226 ^ (-2049784917 ^ --284802439)) + -1761155659 * ~(-900426535 * -352551557) * -2027252215) ^ -1894592934) - (~(0x17753DF9 ^ -1313679194) - (-129852905 ^ 0x2B827132) - (-((-1251707858 - 1507297919) * 31477489) - -(0x55DCDE94 ^ -459371307))))) * 41530471)) * -1578651631)) % 4;
							uint num58 = num4;
							int num59 = 0;
							_ = 0;
							for (int num60 = 0; num60 < 2; num60++)
							{
								num59 = num59 ^ 0x4EFD3E ^ 0x4F30470E;
								num59 = ~num59;
							}
							if (num58 == (uint)num59)
							{
								break;
							}
							uint num61 = num4;
							int num62 = 560411266;
							_ = 0;
							for (int num63 = 0; num63 < 2; num63++)
							{
								num62 = ~(num62 * -1347111657);
								num62 = ~(num62 * 432321869);
							}
							if (num61 != (uint)num62)
							{
								uint num64 = num4;
								int num65 = -2104308678;
								_ = 0;
								for (int num66 = 0; num66 < 1; num66++)
								{
									num65 -= -2104308681;
								}
								if (num64 != (uint)num65)
								{
									uint num67 = num4;
									int num68 = -2;
									_ = 0;
									for (int num69 = 0; num69 < 1; num69++)
									{
										num68 = ~num68;
									}
									if (num67 == (uint)num68)
									{
									}
									return;
								}
								_003C_003Et__builder.SetException(exception);
								int[] array20 = new int[6] { -463209356, -1803791114, -379871207, -284539679, 1765742960, -431202207 };
								array20[2] ^= 719131715;
								array20[1] = array20[4] ^ 0x2669ACB8;
								int[] array21 = new int[7];
								array21[0] = -960666153;
								array21[1] = -724986886;
								array21[2] = -929410432;
								array21[3] = -318816602;
								array21[4] = -779744600;
								array21[5] = 1620209324;
								array21[6] = -989813614;
								array21[3] = array20[4] ^ 0x5C0A43A1;
								array21[1] = array21[0] ^ -2016041;
								array21[4] = array21[3] ^ -276988339;
								int num70 = array21[3] ^ -1849745569;
								num57 = ((int)num5 * -1493725371) ^ -1823234961 ^ num70;
							}
							else
							{
								_003C_003E1__state = -2;
								int[] array22 = new int[7];
								array22[0] = -177891210;
								array22[1] = 830217849;
								array22[2] = -132456201;
								array22[3] = -993756742;
								array22[4] = 1508460718;
								array22[5] = 211070116;
								array22[6] = -1415527276;
								array22[2] = array22[0] ^ 0x186423C1;
								array22[5] = array22[6] ^ -1764748200;
								int[] array23 = new int[6];
								array23[0] = 1867283035;
								array23[1] = -1233532423;
								array23[2] = -2061152798;
								array23[3] = 1864681979;
								array23[4] = -46942835;
								array23[5] = 474023167;
								array23[4] = array22[6] ^ 0x647B42B4;
								array23[5] = array23[1] ^ -1691363315;
								array23[3] = array23[0] ^ 0x144C0F76;
								array23[0] ^= -620953698;
								int num71 = array23[4] ^ -352157672;
								num57 = ((int)num5 * -690278914) ^ 0x270BEAD4 ^ num71;
							}
						}
					}
				}
				_003C_003E1__state = -2;
				while (true)
				{
					int num72 = -1240742243;
					while (true)
					{
						int num3 = num72;
						uint num5;
						uint num4 = (num5 = (uint)(~(~((849573075 * (0x504E200B ^ -929490096) + (1501260020 + (731952609 - 726176466) + -(1489606701 + -764384637)) - (~(~num3 + (-(-1066365340 ^ 0x3BDCCCF) - ((-55938527 * -1051912488 - (~(0x495BFE8A ^ 0x141418F7) + -(45824084 + (0x6FE3BFD8 ^ 0x38E96297)))) ^ (1474076823 + -(-673331979 * -412088295))) + ~(-(500591404 + -745935181)))) + ((~(-1481162472 ^ 0x5056911F) - (0xEDE7226 ^ (-2049784917 ^ --284802439)) + -1761155659 * ~(-900426535 * -352551557) * -2027252215) ^ -1894592934) - (~(0x17753DF9 ^ -1313679194) - (-129852905 ^ 0x2B827132) - (-((-1251707858 - 1507297919) * 31477489) - -(0x55DCDE94 ^ -459371307))))) * 41530471)) * -1578651631)) % 3;
						uint num73 = num4;
						int num74 = -88753242;
						_ = 0;
						for (int num75 = 0; num75 < 1; num75++)
						{
							num74 *= 620397147;
						}
						if (num73 == (uint)num74)
						{
							break;
						}
						uint num76 = num4;
						int num77 = 1;
						_ = 0;
						for (int num78 = 0; num78 < 2; num78++)
						{
							num77 = ~(~num77);
							num77 = ~(num77 + (0x492179F4 ^ -1112652451));
						}
						if (num76 != (uint)num77)
						{
							uint num79 = num4;
							int num80 = 1135028528;
							_ = 0;
							for (int num81 = 0; num81 < 2; num81++)
							{
								num80 = -(-num80);
								num80 = (num80 - ~-1436004918) * 924316815;
							}
							if (num79 == (uint)num80)
							{
							}
							return;
						}
						_003C_003Et__builder.SetResult();
						int[] array24 = new int[6];
						array24[0] = -1849725419;
						array24[1] = 1461620016;
						array24[2] = 83486992;
						array24[3] = -283141238;
						array24[4] = -666757081;
						array24[5] = 57576527;
						array24[1] = array24[4] ^ 0x1007056F;
						array24[1] = array24[0] ^ 0x4EB83848;
						array24[0] = array24[5] ^ -1231404184;
						int[] array25 = new int[7];
						array25[0] = -630765149;
						array25[1] = -1895749019;
						array25[2] = 1251998554;
						array25[3] = 865711017;
						array25[4] = -1211308424;
						array25[5] = -2002931859;
						array25[6] = 1534331916;
						array25[2] = array24[3] ^ -1559424850;
						array25[5] = array25[1] ^ 0x4D045B99;
						array25[6] = array25[1] ^ 0x4A8DA0B0;
						array25[1] = array25[4] ^ -1030557337;
						int num82 = array25[2] ^ 0x29907CEF;
						num72 = (int)((num5 * 1792167952) ^ 0xD1BFF500u) ^ num82;
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

			static TaskAwaiter _0025_003D_003C_0025_003F_0040_0024_0029(Task P_0)
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
						int num = 1964499587;
						while (true)
						{
							int num2 = num;
							uint num4;
							uint num3 = (num4 = (uint)(~(-974014070 - -(-((-(~(-(num2 - ~(-949274645 * (~(--1385825573) - -(1175426491 - 1351904263 - 40586231 * 36447112) - ~(0x5AF479D7 ^ 0x698503E5) * -535076855) + ~(~(1469939153 * (-1723921257 * (-834371737 + 1858964800)))) * -479625057 + ~((-(1404119827 * (-763333293 + ~951404714)) ^ 0x650FC27E) + 2068119942))))) ^ (-((-1331956566 ^ 0x425FF274) + (-880930928 - 1099644499 + 1063355277)) + 817184706)) - (~(--765613885) + ~(680278043 + -1103456141) - -140512229)))))) % 3;
							int num5 = 0;
							_ = 0;
							for (int num6 = 0; num6 < 1; num6++)
							{
								num5 *= 1035700527;
							}
							if (num3 == (uint)num5)
							{
								break;
							}
							int num7 = -1835512490;
							_ = 0;
							for (int num8 = 0; num8 < 2; num8++)
							{
								num7 = num7 * 37435899 - 106909408;
								num7 = ~(1033786177 * 989484486 - num7);
							}
							if (num3 != (uint)num7)
							{
								int num9 = -946855534;
								_ = 0;
								for (int num10 = 0; num10 < 1; num10++)
								{
									num9 += 946855535;
								}
								if (num3 == (uint)num9)
								{
								}
								goto end_IL_0007;
							}
							awaiter = P_0.GetAwaiter();
							int[] array = new int[4];
							array[0] = -170746735;
							array[1] = 642808934;
							array[2] = 1231204209;
							array[3] = 1796607287;
							array[1] = array[3] ^ -1245613939;
							array[1] = array[2] ^ 0x61A28765;
							int[] array2 = new int[5];
							array2[0] = 1477935050;
							array2[1] = 502310442;
							array2[2] = 1912667772;
							array2[3] = -1734616302;
							array2[4] = 707782206;
							array2[4] = array[0] ^ -1494722912;
							array2[1] ^= 962298851;
							array2[2] = array2[0] ^ 0x390216B1;
							array2[0] = array2[2] ^ 0x35E3C68D;
							int num11 = array2[4] ^ -774978140;
							num = ((int)num4 * -1657732581) ^ -53539411 ^ num11;
						}
						continue;
						end_IL_0007:
						break;
					}
				}
				return awaiter;
			}
		}

		public eie_003D mainWindow;

		[AsyncStateMachine(typeof(_003C_003COnAppActivated_003Eb__0_003Ed))]
		internal void _003COnAppActivated_003Eb__0()
		{
			_003C_003COnAppActivated_003Eb__0_003Ed stateMachine = default(_003C_003COnAppActivated_003Eb__0_003Ed);
			stateMachine._003C_003Et__builder = _002F_0021_0021_0025_0028_005E_005E_0040();
			while (true)
			{
				int num = -1189091813;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(-(~(~num2 ^ ((-1586269963 * -1831086947 + (1200728269 * 455648427 - 1233721337 + ~(210354569 + 1843705615) - (1951223655 - ~(0x518F30A1 ^ 0x17BCE585)) + ~(0x69B3E5C6 ^ (-1718888531 ^ --105067017)) - 889215065 * (-504380714 ^ 0x5D1B5AD9))) * -2051668715))) * 438662249) - (-531686211 - (-978390973 + -647968462) + (-201547128 ^ 0x2233829B)) + -(-936529989 + -398454505) + (-20870597 - 1439315074)) ^ -1780630560)) % 5;
					int num5 = 1693395534;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -num5 ^ 0x656A2866;
						num5 = (num5 * 1099893303) ^ 0x46FD53F;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 + -1861854801 - 1918164970;
						num7 = ~num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2063628266;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x7B0077EE;
						}
						if (num3 != (uint)num9)
						{
							int num11 = 2;
							_ = 0;
							for (int num12 = 0; num12 < 2; num12++)
							{
								num11 = ~(-num11);
								num11 ^= 0x3CF93550;
							}
							if (num3 != (uint)num11)
							{
								int num13 = 1313365818;
								_ = 0;
								for (int num14 = 0; num14 < 1; num14++)
								{
									num13 ^= 0x4E485F39;
								}
								if (num3 == (uint)num13)
								{
								}
								return;
							}
							stateMachine._003C_003Et__builder.Start(ref stateMachine);
							int[] array = new int[4];
							array[0] = 2056358064;
							array[1] = 1062940202;
							array[2] = -534714860;
							array[3] = 455312862;
							array[2] = array[1] ^ 0x689F8FCD;
							array[1] ^= -1951353519;
							array[3] = array[0] ^ 0x5FA5D9BB;
							int[] array2 = new int[7] { -409477160, -1896157214, 374426380, -1482284437, -176901488, 585124338, -579506676 };
							int[][] array3 = new int[2][] { array, array2 };
							array2[5] = array3[0][0] ^ -1602637302;
							array2[4] ^= -1412684748;
							array2[2] = array2[6] ^ -395140540;
							array2[1] = array2[4] ^ 0x282D050A;
							int num15 = array3[1][5] ^ -421858489;
							num = (int)((num4 * 1734720828) ^ 0x4749AD4) ^ num15;
						}
						else
						{
							stateMachine._003C_003E1__state = -1;
							int[] array4 = new int[6];
							array4[0] = -1950254752;
							array4[1] = 1037296049;
							array4[2] = -416731642;
							array4[3] = 1170323098;
							array4[4] = -1090771678;
							array4[5] = -1986259661;
							array4[5] = array4[3] ^ -1048864411;
							array4[1] = array4[3] ^ -888928888;
							int[] array5 = new int[6] { -1320715890, 525443869, -1912188987, -695311262, -1248457665, -1128568295 };
							int[][] array6 = new int[2][] { array4, array5 };
							array5[2] = array6[0][0] ^ 0x6AF0271B;
							array5[5] = array5[0] ^ 0x76BE3580;
							array5[1] = array5[2] ^ 0x1E5A231D;
							int num16 = array6[1][2] ^ -22015245;
							num = ((int)num4 * -506887681) ^ 0x5414D5FE ^ num16;
						}
					}
					else
					{
						stateMachine._003C_003E4__this = this;
						int[,] array7 = new int[4, 3];
						array7[0, 0] = -437614745;
						array7[0, 1] = 931654563;
						array7[0, 2] = -1208280739;
						array7[1, 0] = -2121776168;
						array7[1, 1] = -522953410;
						array7[1, 2] = 223446202;
						array7[2, 0] = -797701009;
						array7[2, 1] = -917142142;
						array7[2, 2] = 1252146613;
						array7[3, 0] = 283457480;
						array7[3, 1] = 1544707241;
						array7[3, 2] = -1334919240;
						array7[2, 2] = array7[2, 0] ^ 0x456CFAAA;
						array7[2, 0] = array7[2, 2] ^ -797802567;
						array7[3, 1] = array7[0, 2] ^ -654674926;
						int num17 = array7[3, 1] ^ -1587985880;
						num = (int)((num4 * 1557086641) ^ 0xD2A02F86u) ^ num17;
					}
				}
			}
		}

		static AsyncVoidMethodBuilder _002F_0021_0021_0025_0028_005E_005E_0040()
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
					int num = -1933307797;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((-(num2 + (((-241799105 ^ (786773191 * (543516686 - -(-1729967521 + -474313793 - (-1675775557 + 1926494167)))) ^ (-448618037 * ((-174537448 ^ 0x126A9DCC) * 1495107323) * -1357498037)) - (~((0x2B6D729D ^ -(1116283053 + 416295908)) + ~(~-1447288758 * 1587882649) + (-(1580973433 * 806877531 + -62232304 * 940106865) + (~(--1365776506) - (-1824692484 - -1870300387 * 666074002)))) + (-(~(-(897344325 + 1456284440 + (-119215098 + 2111476683)))) ^ -1648619))) ^ ~((-1044510427 * -(((~-1049857669 + --1675506686) ^ -1625279348) - ~(-1195148477 * (0x6F094AD0 ^ -483577525)))) ^ (((-(~-236321256 - (380275210 - -719829810)) - ~(-697781260 ^ 0x49633777)) ^ -1118595266) - ~(-(182239046 + 1168551784 + (0x174293E8 ^ 0x3143BE22)) - ((-2139411474 + -1678545743) * 260019779 + ~(590014820 - 1173112310))))))) - -1616710094) * -792571883)) % 3;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 *= -598009497;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 2;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~(num7 ^ 0x6A2FF086);
							num7 = num7 ^ -240006590 ^ -1426011353;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1275604229;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = 100508720 - (num9 - (0x40D5338B ^ 0x6CB21B4));
								num9 = -num9 ^ -638033635;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = AsyncVoidMethodBuilder.Create();
						int[,] array = new int[4, 4];
						array[0, 0] = -954785532;
						array[0, 1] = 192807271;
						array[0, 2] = -2092304473;
						array[0, 3] = -335509951;
						array[1, 0] = 553859121;
						array[1, 1] = -1890144434;
						array[1, 2] = 1683021254;
						array[1, 3] = -183092670;
						array[2, 0] = -863435478;
						array[2, 1] = 1721934148;
						array[2, 2] = 1217936126;
						array[2, 3] = -715914232;
						array[3, 0] = 1617885259;
						array[3, 1] = 143637449;
						array[3, 2] = -1094055466;
						array[3, 3] = -1156119097;
						array[3, 0] = array[0, 2] ^ -42958942;
						array[3, 3] = array[2, 0] ^ -534497305;
						array[0, 3] = array[0, 1] ^ -630066046;
						array[1, 2] = array[2, 2] ^ -571776603;
						int num11 = array[1, 2] ^ -881690009;
						num = (int)((num4 * 1278418255) ^ 0xD299D0DEu) ^ num11;
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
	private struct _003CRedirectActivationToAsync_003Ed__15 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder _003C_003Et__builder;

		public AppInstance keyInstance;

		public AppActivationArguments activationArguments;

		private TaskAwaiter _003C_003Eu__1;

		private void MoveNext()
		{
			int num = _003C_003E1__state;
			try
			{
				if (num != 0)
				{
					goto IL_0016;
				}
				goto IL_0b78;
				IL_0016:
				int num2 = 1572324390;
				goto IL_001b;
				IL_001b:
				TaskAwaiter awaiter = default(TaskAwaiter);
				while (true)
				{
					int num3 = num2;
					uint num5;
					uint num4 = (num5 = (uint)((-1742507980 ^ --1304353371) - (~(~(((481920643 * -(0x1490B6F8 ^ ((-126230211 * ~(--736969911)) ^ ~(-(~1844380711))))) ^ (-(-540791289) * 1280452293)) - ~num3) - (-1679780799 - (2030138865 + ~-592241546))) ^ -(-(0x276C2E30 ^ 0x26BBD78E) - ~(~87951897)) ^ 0x519A25D0))) % 13;
					uint num6 = num4;
					int num7 = -11;
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
					int num10 = 646840626;
					_ = 0;
					for (int num11 = 0; num11 < 1; num11++)
					{
						num10 -= 646840622;
					}
					if (num9 == (uint)num10)
					{
						awaiter = _005E_002B_0023__002B_0028_0029_002D(_002D_0029_003F_0026_002D_005E_0028_002B(keyInstance, activationArguments));
						int[] array = new int[5];
						array[0] = 780053302;
						array[1] = -723918740;
						array[2] = 650567685;
						array[3] = 892230605;
						array[4] = -857769020;
						array[0] = array[1] ^ -646207030;
						array[0] = array[1] ^ -1668430385;
						array[4] = array[2] ^ -78481174;
						int[] array2 = new int[7] { 762922894, 1339923519, -1216219351, 790485075, 1722129883, 2102617143, 38241019 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][1] ^ -1241566234;
						array2[3] = array2[5] ^ 0x5AA23C36;
						array2[6] = array2[1] ^ 0x3B3E7A49;
						array2[3] = array2[6] ^ -772776518;
						int num12 = array3[1][1] ^ 0x49EBCC1;
						num2 = (int)((num5 * 971266950) ^ 0x30EAAF48) ^ num12;
						continue;
					}
					uint num13 = num4;
					int num14 = 1358956587;
					_ = 0;
					for (int num15 = 0; num15 < 2; num15++)
					{
						num14 = -1285201835 - -1432343758 - num14 + 249224444;
						num14 = (num14 - 458886821 * -1459452841) ^ 0x28893534;
					}
					if (num13 == (uint)num14)
					{
						bool ısCompleted = awaiter.IsCompleted;
						int[] array4 = new int[5];
						array4[0] = 701346241;
						array4[1] = -825525265;
						array4[2] = -2127240714;
						array4[3] = 1726915396;
						array4[4] = 685492392;
						array4[2] = array4[3] ^ 0x33370BFF;
						array4[1] = array4[0] ^ 0x1587684C;
						int[] array5 = new int[4] { -520104224, 615107457, 1086494741, 444897087 };
						int[][] array6 = new int[2][] { array4, array5 };
						array5[0] = array6[0][4] ^ 0x72132228;
						array5[3] = array5[2] ^ 0x754C4D1;
						array5[2] = array5[3] ^ 0x990A4F7;
						array5[2] = array5[1] ^ 0x59E57C8E;
						int num16 = array6[1][0] ^ 0x85037D8;
						int[,] array7 = new int[4, 3];
						array7[0, 0] = 106969865;
						array7[0, 1] = -1639774906;
						array7[0, 2] = -2073136218;
						array7[1, 0] = -1158608060;
						array7[1, 1] = -1459645842;
						array7[1, 2] = 1310474182;
						array7[2, 0] = -65611021;
						array7[2, 1] = -644158609;
						array7[2, 2] = -205968943;
						array7[3, 0] = -1395253473;
						array7[3, 1] = -1960343075;
						array7[3, 2] = -1071685072;
						array7[0, 1] = array7[1, 0] ^ -734668891;
						array7[3, 0] = array7[2, 1] ^ 0x326C8777;
						array7[3, 1] ^= -5047490;
						array7[0, 2] = array7[2, 2] ^ -2133104840;
						int num17 = array7[0, 2] ^ 0x5DE915FC;
						int num18 = (int)((num5 * 103093193) ^ 0x2C9B729);
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
						num22 = ~num22;
					}
					if (num21 == (uint)num22)
					{
						num = (_003C_003E1__state = 0);
						int[] array8 = new int[4];
						array8[0] = -650671859;
						array8[1] = 535646852;
						array8[2] = 1351690542;
						array8[3] = 1723065514;
						array8[1] = array8[3] ^ -197635827;
						array8[0] = array8[2] ^ 0x5A686DC8;
						int[] array9 = new int[6] { -1100719159, -128165685, 798402485, -1345841359, -2002537192, -1656818956 };
						int[][] array10 = new int[2][] { array8, array9 };
						array9[2] = array10[0][3] ^ -358525446;
						array9[0] = array9[5] ^ -2025399965;
						array9[3] = array9[2] ^ -1941681790;
						int num24 = array10[1][2] ^ -683662018;
						num2 = (int)((num5 * 1653894211) ^ 0xC02FFC91u) ^ num24;
						continue;
					}
					uint num25 = num4;
					int num26 = 1173864938;
					_ = 0;
					for (int num27 = 0; num27 < 1; num27++)
					{
						num26 *= 1973248535;
					}
					if (num25 == (uint)num26)
					{
						_003C_003Eu__1 = awaiter;
						int[,] array11 = new int[3, 4];
						array11[0, 0] = 2054849636;
						array11[0, 1] = -1876150254;
						array11[0, 2] = -1729689837;
						array11[0, 3] = 1767171796;
						array11[1, 0] = -2007339065;
						array11[1, 1] = -1069824489;
						array11[1, 2] = -1572202034;
						array11[1, 3] = 990763192;
						array11[2, 0] = -443968409;
						array11[2, 1] = 619047564;
						array11[2, 2] = -1816250890;
						array11[2, 3] = 607244662;
						array11[0, 0] = array11[1, 1] ^ 0x3A46F10A;
						array11[1, 0] = array11[1, 3] ^ -160427464;
						array11[1, 3] = array11[2, 0] ^ 0x6AF0C5DF;
						array11[2, 0] = array11[0, 2] ^ 0x1BC0DA15;
						int num28 = array11[2, 0] ^ -568561506;
						num2 = (int)((num5 * 1067613494) ^ 0xDA039458u) ^ num28;
						continue;
					}
					uint num29 = num4;
					int num30 = 8;
					_ = 0;
					for (int num31 = 0; num31 < 2; num31++)
					{
						num30 = ~num30 + -1855854600;
						num30 = 1825917509 - -num30;
					}
					if (num29 == (uint)num30)
					{
						_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
						int[] array12 = new int[5] { 1313045405, -435233657, 1830427080, -1653936935, -1686724080 };
						array12[4] ^= 1016455023;
						array12[4] = array12[2] ^ 0x6E08C859;
						array12[4] = array12[2] ^ -958484666;
						int[] array13 = new int[6] { -192913367, 1329949790, 1802439002, 967287421, 438136984, -1020967876 };
						int[][] array14 = new int[2][] { array12, array13 };
						array13[4] = array14[0][1] ^ -1199048491;
						array13[3] = array13[1] ^ 0x48BE8501;
						array13[5] = array13[1] ^ 0x61E0F182;
						int num32 = array14[1][4] ^ 0x7ED52418;
						num2 = ((int)num5 * -1918189530) ^ 0x6FA28874 ^ num32;
						continue;
					}
					uint num33 = num4;
					int num34 = -1668830169;
					_ = 0;
					for (int num35 = 0; num35 < 2; num35++)
					{
						num34 = ~(num34 - -1613411223);
						num34 = -num34 - 778996139;
					}
					if (num33 == (uint)num34)
					{
						return;
					}
					uint num36 = num4;
					int num37 = 21573788;
					_ = 0;
					for (int num38 = 0; num38 < 1; num38++)
					{
						num37 *= 25897669;
					}
					if (num36 == (uint)num37)
					{
						goto IL_0b78;
					}
					uint num39 = num4;
					int num40 = -631479185;
					_ = 0;
					for (int num41 = 0; num41 < 1; num41++)
					{
						num40 -= -631479190;
					}
					if (num39 == (uint)num40)
					{
						_003C_003Eu__1 = default(TaskAwaiter);
						int[] array15 = new int[4];
						array15[0] = 485020283;
						array15[1] = -418507153;
						array15[2] = -1505752924;
						array15[3] = 1372558759;
						array15[1] = array15[0] ^ 0x691BE28F;
						array15[1] = array15[2] ^ 0x42921F88;
						int[] array16 = new int[6] { 1767552580, 219920474, -954707295, 544959804, -1330891066, 953631485 };
						int[][] array17 = new int[2][] { array15, array16 };
						array16[1] = array17[0][2] ^ 0x37BE88CA;
						array16[5] = array16[1] ^ -1568464887;
						array16[3] = array16[4] ^ -1887406466;
						int num42 = array17[1][1] ^ 0x60CA291D;
						num2 = (int)((num5 * 1583318755) ^ 0x16D02793) ^ num42;
						continue;
					}
					uint num43 = num4;
					int num44 = 1812757696;
					_ = 0;
					for (int num45 = 0; num45 < 2; num45++)
					{
						num44 ^= -1510957755;
						num44 = ~(~-929441637 - num44);
					}
					if (num43 == (uint)num44)
					{
						num = (_003C_003E1__state = -1);
						int[] array18 = new int[4] { -113870140, -1333498050, -1538223260, -1688470239 };
						array18[1] ^= 872356743;
						array18[2] ^= 1535936436;
						int[] array19 = new int[5] { -2002656382, -234215807, -1264995361, 360830255, 59135538 };
						int[][] array20 = new int[2][] { array18, array19 };
						array19[3] = array20[0][0] ^ 0x332E5C1A;
						array19[2] = array19[3] ^ 0x1B291464;
						array19[4] = array19[3] ^ -601978562;
						array19[1] = array19[0] ^ -1338307066;
						int num46 = array20[1][3] ^ -1736377466;
						num2 = ((int)num5 * -250435209) ^ -744134273 ^ num46;
						continue;
					}
					uint num47 = num4;
					int num48 = -1094267822;
					_ = 0;
					for (int num49 = 0; num49 < 1; num49++)
					{
						num48 *= 500667929;
					}
					if (num47 == (uint)num48)
					{
						awaiter.GetResult();
						num2 = -221169336;
						continue;
					}
					uint num50 = num4;
					int num51 = 7;
					_ = 0;
					for (int num52 = 0; num52 < 2; num52++)
					{
						num51 = -(num51 ^ -1882653068);
						num51 = -num51 ^ 0x4CD06239;
					}
					if (num50 == (uint)num51)
					{
						__005E_002A_0029_002B_0025__003D(_003E_005E_003E_003D_0029_003D_002A_002F());
						int[] array21 = new int[6];
						array21[0] = -297180049;
						array21[1] = 1679043475;
						array21[2] = 21809672;
						array21[3] = -1375921473;
						array21[4] = 998318265;
						array21[5] = 1573942510;
						array21[3] = array21[5] ^ 0x63179D74;
						array21[3] = array21[2] ^ -913263997;
						int[] array22 = new int[5];
						array22[0] = 944204481;
						array22[1] = -1064771853;
						array22[2] = -379467339;
						array22[3] = -2001754165;
						array22[4] = -1849054208;
						array22[0] = array21[4] ^ 0x5D186A85;
						array22[3] = array22[2] ^ -691675929;
						array22[3] = array22[0] ^ 0xC7303D0;
						int num53 = array22[0] ^ 0x439C66E6;
						num2 = ((int)num5 * -862193493) ^ -671236230 ^ num53;
						continue;
					}
					uint num54 = num4;
					int num55 = 268926510;
					_ = 0;
					for (int num56 = 0; num56 < 1; num56++)
					{
						num55 *= -368506045;
					}
					if (num54 == (uint)num55)
					{
					}
					goto end_IL_000d;
				}
				goto IL_0016;
				IL_0b78:
				awaiter = _003C_003Eu__1;
				num2 = -2076371941;
				goto IL_001b;
				end_IL_000d:;
			}
			catch (Exception exception)
			{
				while (true)
				{
					int num57 = -156923004;
					while (true)
					{
						int num3 = num57;
						uint num5;
						uint num4 = (num5 = (uint)((-1742507980 ^ --1304353371) - (~(~(((481920643 * -(0x1490B6F8 ^ ((-126230211 * ~(--736969911)) ^ ~(-(~1844380711))))) ^ (-(-540791289) * 1280452293)) - ~num3) - (-1679780799 - (2030138865 + ~-592241546))) ^ -(-(0x276C2E30 ^ 0x26BBD78E) - ~(~87951897)) ^ 0x519A25D0))) % 4;
						uint num58 = num4;
						int num59 = 0;
						_ = 0;
						for (int num60 = 0; num60 < 1; num60++)
						{
							num59 = -num59;
						}
						if (num58 == (uint)num59)
						{
							break;
						}
						uint num61 = num4;
						int num62 = -389310955;
						_ = 0;
						for (int num63 = 0; num63 < 1; num63++)
						{
							num62 += 389310957;
						}
						if (num61 != (uint)num62)
						{
							uint num64 = num4;
							int num65 = -553596211;
							_ = 0;
							for (int num66 = 0; num66 < 2; num66++)
							{
								num65 = ~num65 - 395197464;
								num65 = -num65 + -118399359;
							}
							if (num64 != (uint)num65)
							{
								uint num67 = num4;
								int num68 = -283794941;
								_ = 0;
								for (int num69 = 0; num69 < 2; num69++)
								{
									num68 = -(-num68);
									num68 = (num68 ^ 0x35329A22) * 417989741;
								}
								if (num67 == (uint)num68)
								{
								}
								return;
							}
							_003C_003Et__builder.SetException(exception);
							int[] array23 = new int[7];
							array23[0] = -394610604;
							array23[1] = -1846988238;
							array23[2] = 415682626;
							array23[3] = 1627407382;
							array23[4] = 1575000724;
							array23[5] = -116696225;
							array23[6] = 262582795;
							array23[1] = array23[5] ^ 0x3F4D7B8C;
							array23[5] = array23[6] ^ -48623752;
							int[] array24 = new int[5] { -671438032, -946188680, -1759075079, -958998715, 584824205 };
							int[][] array25 = new int[2][] { array23, array24 };
							array24[3] = array25[0][3] ^ -1478601570;
							array24[4] = array24[2] ^ -424803090;
							array24[4] = array24[2] ^ 0x4510FF68;
							int num70 = array25[1][3] ^ 0x5338EAAD;
							num57 = (int)((num5 * 1418645686) ^ 0x49EE4C36) ^ num70;
						}
						else
						{
							_003C_003E1__state = -2;
							int[] array26 = new int[4];
							array26[0] = -1735163801;
							array26[1] = 453856096;
							array26[2] = 1998549426;
							array26[3] = -966922421;
							array26[2] = array26[1] ^ -1537036716;
							array26[2] = array26[3] ^ -746787198;
							int[] array27 = new int[5];
							array27[0] = -1315237062;
							array27[1] = 1586211167;
							array27[2] = 79727182;
							array27[3] = 1059822332;
							array27[4] = -376204091;
							array27[1] = array26[0] ^ -1252893049;
							array27[3] = array27[2] ^ -525995222;
							array27[4] = array27[1] ^ -963627855;
							array27[0] = array27[4] ^ -989573866;
							int num71 = array27[1] ^ 0x91FA08B;
							num57 = ((int)num5 * -583743236) ^ -281892520 ^ num71;
						}
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num72 = 1710761953;
				while (true)
				{
					int num3 = num72;
					uint num5;
					uint num4 = (num5 = (uint)((-1742507980 ^ --1304353371) - (~(~(((481920643 * -(0x1490B6F8 ^ ((-126230211 * ~(--736969911)) ^ ~(-(~1844380711))))) ^ (-(-540791289) * 1280452293)) - ~num3) - (-1679780799 - (2030138865 + ~-592241546))) ^ -(-(0x276C2E30 ^ 0x26BBD78E) - ~(~87951897)) ^ 0x519A25D0))) % 3;
					uint num73 = num4;
					int num74 = -460564206;
					_ = 0;
					for (int num75 = 0; num75 < 1; num75++)
					{
						num74 = -460564204 - num74;
					}
					if (num73 == (uint)num74)
					{
						break;
					}
					uint num76 = num4;
					int num77 = 72104641;
					_ = 0;
					for (int num78 = 0; num78 < 2; num78++)
					{
						num77 = (num77 - ~-454445187) * -2008530367;
						num77 = ~(num77 - (-754909986 + -1047568074));
					}
					if (num76 != (uint)num77)
					{
						uint num79 = num4;
						int num80 = -2;
						_ = 0;
						for (int num81 = 0; num81 < 2; num81++)
						{
							num80 = num80 ^ 0x5BCC1E04 ^ 0x32267F9C;
							num80 = -(~num80);
						}
						if (num79 == (uint)num80)
						{
						}
						return;
					}
					_003C_003Et__builder.SetResult();
					int[,] array28 = new int[4, 4];
					array28[0, 0] = 1017650681;
					array28[0, 1] = 1415288052;
					array28[0, 2] = 1110140237;
					array28[0, 3] = -550996169;
					array28[1, 0] = -981706994;
					array28[1, 1] = -944996774;
					array28[1, 2] = 807405503;
					array28[1, 3] = -597746565;
					array28[2, 0] = -1199556753;
					array28[2, 1] = 584015350;
					array28[2, 2] = 227578859;
					array28[2, 3] = 592445506;
					array28[3, 0] = 1338224497;
					array28[3, 1] = -110907026;
					array28[3, 2] = -2098189422;
					array28[3, 3] = 752507135;
					array28[1, 3] = array28[1, 1] ^ 0x7401000A;
					array28[1, 3] = array28[1, 0] ^ 0x57444146;
					array28[1, 3] = array28[2, 3] ^ -1343737287;
					array28[0, 2] = array28[3, 0] ^ 0x67F0FE0;
					int num82 = array28[0, 2] ^ -1304545744;
					num72 = (int)((num5 * 729141904) ^ 0xF57D46F0u) ^ num82;
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

		static IAsyncAction _002D_0029_003F_0026_002D_005E_0028_002B(AppInstance P_0, AppActivationArguments P_1)
		{
			IAsyncAction result = default(IAsyncAction);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -226960206;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(-(((-num2 + -(~(-1065687639 * -(--1801625030 - (-1850063963 + -860503471) - (-1657065463 + (0x418BDB20 ^ 0x75F255D9))) - -(-(-(--2116741807 - ~1406049696)))))) ^ (1387338055 * -(2135105119 * ~(-849852750 ^ 0x2FDC0784)))) * 264478003)) ^ 0x4ABC3256 ^ -1343287976)) % 3;
						int num5 = 2;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -(num5 + ~1523854829);
							num5 = -(-num5);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -1938170191;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 ^= -1938170192;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -8368104;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = (num9 ^ 0x51C378D5) + -203150545;
								num9 = -num9;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.RedirectActivationToAsync(P_1);
						int[] array = new int[4] { -1592827407, -728430562, -509522117, 1784586413 };
						array[0] ^= -677147574;
						array[0] = array[1] ^ 0x532E3CAD;
						int[] array2 = new int[4];
						array2[0] = -1538728418;
						array2[1] = 1633107598;
						array2[2] = -750928096;
						array2[3] = -1762141331;
						array2[2] = array[1] ^ 0x42EB43BE;
						array2[3] = array2[2] ^ 0x5CD67A65;
						array2[1] = array2[2] ^ 0x575A6943;
						int num11 = array2[2] ^ 0x44DECC4C;
						num = ((int)num4 * -432205439) ^ 0x39E126D4 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static TaskAwaiter _005E_002B_0023__002B_0028_0029_002D(IAsyncAction P_0)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				return P_0.GetAwaiter();
			}
		}

		static Process _003E_005E_003E_003D_0029_003D_002A_002F()
		{
			Process currentProcess = default(Process);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 619346295;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((~((num2 + -(~((-942660953 ^ 0x5672676B) * -1500379739) - ~(~(1542598186 + -(-2097276489 * -(0x3DF5A6DF ^ 0x588848DB))))) + (~91999369 - ((-2013135653 ^ -261375324) + (0x642F9029 ^ ~(~(--710679739 + ~1872008270))) - ~((~(282118106 * 1609933263) + -1328523393) * 214180495 * -1352420125))) + -(-(681625460 + (~(0x2631CAD5 ^ -549038240) - (0x7FEF3989 ^ -132064347) + (-1061785636 ^ (--1044827086 ^ -1735310547)))))) * -1110403221) + ~(-(-1772663185 * 1689450051) ^ 0x37DEA3B7) - (0x220368D8 ^ -(~-1697015749))) * 1600098771 - -1114495297 * -495320818 - -1821299164)) % 3;
						int num5 = 2081721956;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = (num5 ^ -1750593926) * 1043722315;
							num5 = -num5 ^ 0x6899C799;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 524009;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = (num7 ^ --1849333859) - 605255509;
							num7 = -(~num7);
						}
						if (num3 != (uint)num7)
						{
							int num9 = 2042328430;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 *= 1484669703;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						currentProcess = Process.GetCurrentProcess();
						int[] array = new int[7];
						array[0] = 459652131;
						array[1] = -1759154323;
						array[2] = -17338819;
						array[3] = -39812100;
						array[4] = 151484738;
						array[5] = 697779029;
						array[6] = -935193365;
						array[5] = array[3] ^ -494916104;
						array[5] = array[1] ^ 0x6B7E5FB9;
						int[] array2 = new int[5];
						array2[0] = 1161165917;
						array2[1] = 1982484566;
						array2[2] = -876178342;
						array2[3] = 412647139;
						array2[4] = 2035168806;
						array2[0] = array[1] ^ 0x3D5DB942;
						array2[3] ^= -718299386;
						array2[4] = array2[1] ^ -279712312;
						int num11 = array2[0] ^ 0x4DD0A571;
						num = (int)((num4 * 1831011220) ^ 0xF97F7020u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return currentProcess;
		}

		static void __005E_002A_0029_002B_0025__003D(Process P_0)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				P_0.Kill();
			}
		}
	}

	[CompilerGenerated]
	private sealed class _003CSplitCommandLine_003Ed__19 : IEnumerable<string>, IEnumerable, IEnumerator<string>, IEnumerator, IDisposable
	{
		private int _003C_003E1__state;

		private string _003C_003E2__current;

		private int _003C_003El__initialThreadId;

		private string arguments;

		public string _003C_003E3__arguments;

		private List<char> _003Ccurrent_003E5__2;

		private bool _003CinQuotes_003E5__3;

		private string _003C_003E7__wrap3;

		private int _003C_003E7__wrap4;

		string IEnumerator<string>.Current
		{
			[DebuggerHidden]
			get
			{
				return _003C_003E2__current;
			}
		}

		object IEnumerator.Current
		{
			[DebuggerHidden]
			get
			{
				return _003C_003E2__current;
			}
		}

		[DebuggerHidden]
		public _003CSplitCommandLine_003Ed__19(int _003C_003E1__state)
		{
			while (true)
			{
				int num = 717551780;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~((-num2 - -(146788579 * (~((--2135795379 + (-893389818 - 1528354533) + -1500246838) * -732724159) * -999181709)) - -1078935651 * -737772780) * 1305607033) * 698604667))) % 3;
					int num5 = -1279531567;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -1279531567 - num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1372461517;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 18580731;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 461404166;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 - (-2081644181 - -41225993));
							num9 = (num9 ^ -154444690) - -1888868353;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					this._003C_003E1__state = _003C_003E1__state;
					_003C_003El__initialThreadId = _002F_0023_0024_002D_0025_002B_0028_0021();
					int[,] array = new int[3, 4];
					array[0, 0] = 1102857747;
					array[0, 1] = -831466880;
					array[0, 2] = 1207595154;
					array[0, 3] = 753708548;
					array[1, 0] = -718280363;
					array[1, 1] = -1623882229;
					array[1, 2] = -2139515916;
					array[1, 3] = 128366223;
					array[2, 0] = -1655777019;
					array[2, 1] = -12462828;
					array[2, 2] = 554208334;
					array[2, 3] = 747098430;
					array[2, 2] = array[0, 3] ^ -1460137763;
					array[2, 2] = array[2, 3] ^ -1545798221;
					array[1, 2] = array[0, 0] ^ 0x4ADF2C18;
					array[1, 2] = array[0, 1] ^ 0x1D421A95;
					int num11 = array[1, 2] ^ 0x4B49CCA3;
					num = ((int)num4 * -1453459107) ^ -891921255 ^ num11;
				}
			}
		}

		[DebuggerHidden]
		void IDisposable.Dispose()
		{
			_003Ccurrent_003E5__2 = null;
			while (true)
			{
				int num = 2087055119;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-1489920432 - -(~(((((-(930296273 - -1882120855) ^ 0x4B425909) - (-1234819204 - -92284508 + (-2012764260 + 2009409515)) * 390641199) * 680801055 - (0x683B2EBD ^ -1193660628)) ^ (((-938133035 ^ (-242180822 ^ -673138306)) - 1814984207) * -1650287113 * -1013469171)) - (~num2 - ~(-111383149 + ~(((--1105077116 + (1570876569 - 1426967393)) ^ -(~319182912)) * 949696287)) * 1116502451)) * -219647071 + --423081635)) ^ 0x1E97156 ^ 0x1F7580C1)) % 4;
					int num5 = -1777312522;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= -1777312523;
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
						int num9 = -1120324533;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -1120324534;
						}
						if (num3 != (uint)num9)
						{
							int num11 = 1010771669;
							_ = 0;
							for (int num12 = 0; num12 < 1; num12++)
							{
								num11 ^= 0x3C3F26D5;
							}
							if (num3 == (uint)num11)
							{
							}
							return;
						}
						_003C_003E1__state = -2;
						int[] array = new int[5] { 1125522417, -1050341637, -1923712298, 1397140460, -1521245510 };
						array[3] ^= 516732059;
						array[4] ^= 64127985;
						int[] array2 = new int[5] { 942910766, -1508552294, -874961069, -1904280734, -934569156 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][2] ^ 0x5C9B144F;
						array2[4] = array2[1] ^ -287487819;
						array2[4] = array2[1] ^ -1084333379;
						array2[4] = array2[0] ^ 0x614B8178;
						int num13 = array3[1][1] ^ -755008372;
						num = (int)((num4 * 94557459) ^ 0xD9C5A30Fu) ^ num13;
					}
					else
					{
						_003C_003E7__wrap3 = null;
						int[] array4 = new int[6];
						array4[0] = 1877619557;
						array4[1] = 495509007;
						array4[2] = -743678583;
						array4[3] = -15213367;
						array4[4] = -87975135;
						array4[5] = 1683506295;
						array4[3] = array4[4] ^ 0x70980875;
						array4[4] = array4[3] ^ -501130154;
						array4[0] = array4[4] ^ -416383917;
						int[] array5 = new int[5] { 1650818954, 848002680, 1916121500, 1066627480, 1780844711 };
						int[][] array6 = new int[2][] { array4, array5 };
						array5[4] = array6[0][5] ^ 0x5CF18FA3;
						array5[3] = array5[2] ^ 0x58B88850;
						array5[2] = array5[1] ^ 0x1C64C831;
						array5[3] = array5[2] ^ 0x7A5B4B77;
						int num14 = array6[1][4] ^ -1426458358;
						num = (int)((num4 * 967606341) ^ 0x2307AFBE) ^ num14;
					}
				}
			}
		}

		private bool MoveNext()
		{
			int num = _003C_003E1__state;
			char c = default(char);
			while (true)
			{
				int num2 = 1647194145;
				while (true)
				{
					int num3 = num2;
					uint num5;
					uint num4 = (num5 = (uint)(-(-1416061873 - 384093000 - (0x7690FFFD ^ -1362181201)) - ~(-2061453323 + (0x302234FC ^ 0x264FF98A)) - ~(~(num3 - -(81907991 * -1281369657))) * -742651929 * 1826846513)) % 33;
					int num6 = -1608622064;
					_ = 0;
					for (int num7 = 0; num7 < 2; num7++)
					{
						num6 = -(-num6);
						num6 = num6 * 1451238981 - -524221325;
					}
					if (num4 == (uint)num6)
					{
						break;
					}
					int num8 = 1159122805;
					_ = 0;
					for (int num9 = 0; num9 < 2; num9++)
					{
						num8 = num8 * 248324555 * 1452916735;
						num8 = (num8 * 393820589) ^ 0x444C14C8;
					}
					if (num4 != (uint)num8)
					{
						int num10 = 1115820055;
						_ = 0;
						for (int num11 = 0; num11 < 2; num11++)
						{
							num10 = -(319403066 * 958432355 - num10);
							num10 = (num10 + -307222859) ^ -895568802;
						}
						if (num4 == (uint)num10)
						{
							return false;
						}
						int num12 = 450391423;
						_ = 0;
						for (int num13 = 0; num13 < 2; num13++)
						{
							num12 = num12 * 568459167 + 518767587;
							num12 = (num12 + ~435952237) ^ -871624781;
						}
						if (num4 == (uint)num12)
						{
							goto IL_1bf8;
						}
						int num14 = -17;
						_ = 0;
						for (int num15 = 0; num15 < 1; num15++)
						{
							num14 = ~num14;
						}
						if (num4 == (uint)num14)
						{
							bool num16 = _002B_002B_0029_0021_0026__003C_0021(arguments);
							int[,] array = new int[3, 3]
							{
								{ 878606117, -1749568351, 1555907616 },
								{ 476607444, 2089084467, -754771564 },
								{ -434046720, -1898846479, -836581653 }
							};
							array[0, 1] ^= 1574599538;
							array[0, 1] = array[0, 2] ^ -561449950;
							array[2, 2] = array[0, 1] ^ 0x6409A28C;
							array[0, 0] = array[2, 0] ^ -1457637896;
							int num17 = array[0, 0] ^ -92400382;
							int[] array2 = new int[5];
							array2[0] = 80676466;
							array2[1] = -787716543;
							array2[2] = -1709415674;
							array2[3] = 847247240;
							array2[4] = -81516336;
							array2[2] = array2[3] ^ 0x1CC4E03E;
							array2[0] = array2[2] ^ 0xE0D2024;
							array2[3] = array2[2] ^ 0x56EC8FFF;
							int[] array3 = new int[4];
							array3[0] = -201898431;
							array3[1] = -1700471869;
							array3[2] = -2147440771;
							array3[3] = 1189040793;
							array3[1] = array2[1] ^ 0x2CCF9460;
							array3[0] = array3[3] ^ 0x52F2DE09;
							array3[3] = array3[2] ^ 0x48E35C7F;
							int num18 = array3[1] ^ -1581431689;
							int num19 = ((int)num5 * -870220840) ^ 0x4CCF3D08;
							num17 ^= num19;
							num18 ^= num19;
							int num20;
							int num21;
							if (num16)
							{
								num20 = num18;
								num21 = num20;
							}
							else
							{
								num20 = num17;
								num21 = num20;
							}
							num2 = num20 ^ num19;
							continue;
						}
						int num22 = -32;
						_ = 0;
						for (int num23 = 0; num23 < 1; num23++)
						{
							num22 = -num22;
						}
						if (num4 == (uint)num22)
						{
							return false;
						}
						int num24 = 24;
						_ = 0;
						for (int num25 = 0; num25 < 2; num25++)
						{
							num24 = -40158568 + 2145168323 - num24;
							num24 = num24 + -845204063 * 1327577243 - 544440867;
						}
						if (num4 == (uint)num24)
						{
							_003Ccurrent_003E5__2 = new List<char>();
							num2 = 760568549;
							continue;
						}
						int num26 = -1505984731;
						_ = 0;
						for (int num27 = 0; num27 < 2; num27++)
						{
							num26 = 1206145985 - (num26 ^ 0x31D7AF82);
							num26 = (num26 + (-951924165 - -2010576638)) * 1746182203;
						}
						if (num4 == (uint)num26)
						{
							_003CinQuotes_003E5__3 = false;
							int[] array4 = new int[5];
							array4[0] = 30200761;
							array4[1] = 518872901;
							array4[2] = 191142010;
							array4[3] = -715768756;
							array4[4] = -1394775263;
							array4[2] = array4[4] ^ -1151478554;
							array4[4] = array4[3] ^ -1647584218;
							array4[4] = array4[2] ^ 0x3A8436F1;
							int[] array5 = new int[5];
							array5[0] = -2016990043;
							array5[1] = -1360867142;
							array5[2] = -243038087;
							array5[3] = 317990797;
							array5[4] = 439353520;
							array5[3] = array4[1] ^ -1068317849;
							array5[4] ^= -859412445;
							array5[2] = array5[0] ^ -2025381635;
							array5[2] ^= 1275118568;
							int num28 = array5[3] ^ 0x1C575B64;
							num2 = ((int)num5 * -1970825344) ^ -1658478208 ^ num28;
							continue;
						}
						int num29 = -318565251;
						_ = 0;
						for (int num30 = 0; num30 < 1; num30++)
						{
							num29 *= -1980595593;
						}
						if (num4 == (uint)num29)
						{
							_003C_003E7__wrap3 = arguments;
							int[] array6 = new int[5] { -1303276938, 16309209, 1908518159, 1108158931, -1716184252 };
							array6[2] ^= 1659292923;
							array6[1] = array6[3] ^ 0x480D36;
							array6[2] = array6[1] ^ -614378145;
							int[] array7 = new int[4];
							array7[0] = 909811237;
							array7[1] = -508840252;
							array7[2] = -98404665;
							array7[3] = 342151933;
							array7[2] = array6[3] ^ 0x7DEB017E;
							array7[0] = array7[1] ^ -804019214;
							array7[0] = array7[1] ^ 0x4952DDD0;
							int num31 = array7[2] ^ 0x393A611E;
							num2 = (int)((num5 * 1595626312) ^ 0x91395230u) ^ num31;
							continue;
						}
						int num32 = 70263387;
						_ = 0;
						for (int num33 = 0; num33 < 2; num33++)
						{
							num32 += --1549720367;
							num32 = (num32 + (-529291860 - 971379128)) ^ 0x5C488D0;
						}
						if (num4 == (uint)num32)
						{
							_003C_003E7__wrap4 = 0;
							int[] array8 = new int[6];
							array8[0] = -1907851165;
							array8[1] = -1178962144;
							array8[2] = -1087630954;
							array8[3] = -687857588;
							array8[4] = 2139232725;
							array8[5] = -1002743015;
							array8[4] = array8[5] ^ 0xE832720;
							array8[2] = array8[0] ^ 0x3586D31F;
							int[] array9 = new int[7] { -1091443081, -757421500, 404456874, -1527142553, 23879306, -30228385, -177762097 };
							int[][] array10 = new int[2][] { array8, array9 };
							array9[5] = array10[0][3] ^ -1582662593;
							array9[6] = array9[3] ^ 0x38012BAD;
							array9[1] ^= -264272285;
							array9[3] = array9[2] ^ 0x235EC9DE;
							int num34 = array10[1][5] ^ 0x375467B9;
							num2 = (int)((num5 * 305690989) ^ 0x394B9C0F) ^ num34;
							continue;
						}
						int num35 = 1690170214;
						_ = 0;
						for (int num36 = 0; num36 < 1; num36++)
						{
							num35 -= 1690170212;
						}
						if (num4 == (uint)num35)
						{
							c = _0026_0029_002A_003D_0025_005E_003D_0029(_003C_003E7__wrap3, _003C_003E7__wrap4);
							num2 = -103319022;
							continue;
						}
						int num37 = -7;
						_ = 0;
						for (int num38 = 0; num38 < 1; num38++)
						{
							num37 = ~num37;
						}
						if (num4 == (uint)num37)
						{
							char num39 = c;
							int[,] array11 = new int[4, 4];
							array11[0, 0] = -211607621;
							array11[0, 1] = -869750975;
							array11[0, 2] = 385493899;
							array11[0, 3] = 71529418;
							array11[1, 0] = 966950138;
							array11[1, 1] = 2145618942;
							array11[1, 2] = 580949585;
							array11[1, 3] = -2048654588;
							array11[2, 0] = -1062653665;
							array11[2, 1] = -1061009507;
							array11[2, 2] = 1770097546;
							array11[2, 3] = -1676286596;
							array11[3, 0] = 138763935;
							array11[3, 1] = 658643374;
							array11[3, 2] = 1842068889;
							array11[3, 3] = -1235728908;
							array11[0, 0] = array11[2, 0] ^ 0x2DE40CB2;
							array11[3, 1] = array11[0, 2] ^ 0xD27CF49;
							array11[0, 0] = array11[1, 1] ^ 0x49C91AC0;
							array11[0, 1] = array11[3, 3] ^ -1697743998;
							int num40 = array11[0, 1] ^ 0x5BBE4D42;
							int[] array12 = new int[4] { -883959681, 745871217, -1564709722, -1570844174 };
							array12[2] ^= 561612068;
							array12[2] = array12[3] ^ -1157321285;
							int[] array13 = new int[6];
							array13[0] = -701756849;
							array13[1] = 153918954;
							array13[2] = -59709008;
							array13[3] = 1875410725;
							array13[4] = 1953548446;
							array13[5] = -1440401204;
							array13[4] = array12[0] ^ -1917287434;
							array13[2] = array13[0] ^ -1514227086;
							array13[5] = array13[2] ^ 0x6A1F9847;
							int num41 = array13[4] ^ 0x2832E7B5;
							int num42 = (int)((num5 * 1751867964) ^ 0x1DCDBE78);
							num40 ^= num42;
							num41 ^= num42;
							int num43;
							int num44;
							if (num39 == '"')
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
						int num45 = -983867654;
						_ = 0;
						for (int num46 = 0; num46 < 2; num46++)
						{
							num45 = num45 - (-2069213208 ^ 0x1182CA92) - -183734045;
							num45 = num45 + (1361259580 + 1086401530) - 1784484168;
						}
						if (num4 == (uint)num45)
						{
							_003CinQuotes_003E5__3 = !_003CinQuotes_003E5__3;
							int[] array14 = new int[6];
							array14[0] = 142813684;
							array14[1] = 654132871;
							array14[2] = 296601173;
							array14[3] = -730117461;
							array14[4] = 1194727869;
							array14[5] = -1822444860;
							array14[5] = array14[4] ^ -2014367233;
							array14[4] = array14[0] ^ -555732263;
							array14[0] = array14[2] ^ 0x3CE00D0F;
							int[] array15 = new int[5] { -1637370889, 2044622703, 2122901044, -327359175, 41577913 };
							int[][] array16 = new int[2][] { array14, array15 };
							array15[1] = array16[0][1] ^ -1611252734;
							array15[4] = array15[2] ^ -817062187;
							array15[0] = array15[2] ^ 0x3070834;
							int num47 = array16[1][1] ^ -404300502;
							num2 = (int)((num5 * 1681344951) ^ 0x5226AA4) ^ num47;
							continue;
						}
						int num48 = 0;
						_ = 0;
						for (int num49 = 0; num49 < 2; num49++)
						{
							num48 = ~(num48 ^ -1229843283);
							num48 = ~(~num48);
						}
						if (num4 == (uint)num48)
						{
							int[] array17 = new int[6] { -685716144, 1871375999, 1755453456, 362618719, 1037978568, 148697494 };
							array17[2] ^= -1884470513;
							array17[2] = array17[1] ^ -529977324;
							int[] array18 = new int[5] { 1347166018, -1428367200, -549570243, -1371651090, -11210849 };
							int[][] array19 = new int[2][] { array17, array18 };
							array18[4] = array19[0][0] ^ 0x467809D8;
							array18[1] = array18[3] ^ -687413186;
							array18[0] = array18[4] ^ 0x34EDBC08;
							int num50 = array19[1][4] ^ 0x385E714D;
							num2 = ((int)num5 * -684579899) ^ 0x469AA623 ^ num50;
							continue;
						}
						int num51 = -1702007997;
						_ = 0;
						for (int num52 = 0; num52 < 2; num52++)
						{
							num51 = ~num51 * -1188390715;
							num51 -= 2055592042;
						}
						if (num4 == (uint)num51)
						{
							int num53;
							if (_002F__0025_005E_005E_002A_002A_003D(c))
							{
								num2 = 616262737;
								num53 = num2;
							}
							else
							{
								num2 = -565028814;
								num53 = num2;
							}
							continue;
						}
						int num54 = -1267457904;
						_ = 0;
						for (int num55 = 0; num55 < 1; num55++)
						{
							num54 -= -1267457923;
						}
						if (num4 == (uint)num54)
						{
							bool num56 = _003CinQuotes_003E5__3;
							int[] array20 = new int[7];
							array20[0] = 2007399972;
							array20[1] = -754218054;
							array20[2] = -1221735297;
							array20[3] = 679681347;
							array20[4] = -72808902;
							array20[5] = -1714887172;
							array20[6] = -281957559;
							array20[5] = array20[1] ^ 0x2ECF43D6;
							array20[5] = array20[2] ^ 0x3EC90324;
							int[] array21 = new int[4];
							array21[0] = 1528379447;
							array21[1] = 187651443;
							array21[2] = 1669091074;
							array21[3] = -1142361550;
							array21[1] = array20[2] ^ 0x3F03AE3C;
							array21[0] = array21[3] ^ 0x5CB7411E;
							array21[3] = array21[2] ^ -1162420122;
							array21[2] = array21[3] ^ -1131256287;
							int num57 = array21[1] ^ 0x567C3A71;
							int[] array22 = new int[6];
							array22[0] = 852818847;
							array22[1] = 60311945;
							array22[2] = -1203384811;
							array22[3] = -389349986;
							array22[4] = 181550803;
							array22[5] = 572516487;
							array22[1] = array22[0] ^ 0x645C5700;
							array22[2] = array22[5] ^ -1354698871;
							array22[1] = array22[0] ^ 0x542E6726;
							int[] array23 = new int[6] { 718955913, 1203875028, -1087427355, -1578136181, 1613634891, 2144444466 };
							int[][] array24 = new int[2][] { array22, array23 };
							array23[5] = array24[0][5] ^ -258050774;
							array23[1] = array23[3] ^ 0x41D3AF81;
							array23[2] = array23[5] ^ 0x22D03F60;
							array23[1] = array23[4] ^ 0x4E84CFEB;
							int num58 = array24[1][5] ^ -1156615425;
							int num59 = ((int)num5 * -469914983) ^ 0x34177D1;
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
							num2 = num60 ^ num59;
							continue;
						}
						int num62 = -23;
						_ = 0;
						for (int num63 = 0; num63 < 1; num63++)
						{
							num62 = ~num62;
						}
						if (num4 == (uint)num62)
						{
							int count = _003Ccurrent_003E5__2.Count;
							int[] array25 = new int[4];
							array25[0] = -202838239;
							array25[1] = -310950389;
							array25[2] = -332139109;
							array25[3] = 857947093;
							array25[3] = array25[1] ^ -1960108288;
							array25[3] = array25[0] ^ 0x24692A3C;
							array25[2] = array25[3] ^ -1931611912;
							int[] array26 = new int[6] { 1727068024, -682020477, -1391149109, 1853779827, 1201023971, 257644300 };
							int[][] array27 = new int[2][] { array25, array26 };
							array26[1] = array27[0][0] ^ 0x2A1E935B;
							array26[2] = array26[3] ^ -620252697;
							array26[0] = array26[2] ^ 0x5777992E;
							array26[2] = array26[3] ^ 0x323CB0A4;
							int num64 = array27[1][1] ^ 0x70F0C9BF;
							int[,] array28 = new int[4, 4];
							array28[0, 0] = -1009200508;
							array28[0, 1] = 671915909;
							array28[0, 2] = -1546966355;
							array28[0, 3] = 1155020235;
							array28[1, 0] = 2024154510;
							array28[1, 1] = 510548711;
							array28[1, 2] = -1791188132;
							array28[1, 3] = -1784224811;
							array28[2, 0] = 2095450255;
							array28[2, 1] = 1392486099;
							array28[2, 2] = -1075366311;
							array28[2, 3] = -507401703;
							array28[3, 0] = -1918437147;
							array28[3, 1] = 729078642;
							array28[3, 2] = 504621962;
							array28[3, 3] = -1718966664;
							array28[3, 1] = array28[3, 0] ^ -653766946;
							array28[0, 1] = array28[2, 0] ^ -1662427890;
							array28[2, 0] = array28[2, 2] ^ -1861856834;
							int num65 = array28[2, 0] ^ -1563210761;
							int num66 = ((int)num5 * -1612409031) ^ -1815690958;
							num64 ^= num66;
							num65 ^= num66;
							int num67;
							int num68;
							if (count > 0)
							{
								num67 = num65;
								num68 = num67;
							}
							else
							{
								num67 = num64;
								num68 = num67;
							}
							num2 = num67 ^ num66;
							continue;
						}
						int num69 = -793496533;
						_ = 0;
						for (int num70 = 0; num70 < 2; num70++)
						{
							num69 += 0x700D93CF ^ 0x52EE9F79;
							num69 = (num69 + -2504261) * -177347783;
						}
						if (num4 == (uint)num69)
						{
							_003C_003E2__current = new string(_003Ccurrent_003E5__2.ToArray());
							int[,] array29 = new int[4, 3];
							array29[0, 0] = -1624662465;
							array29[0, 1] = -1341486255;
							array29[0, 2] = 335627695;
							array29[1, 0] = -545369703;
							array29[1, 1] = 169055147;
							array29[1, 2] = 278588339;
							array29[2, 0] = 257654336;
							array29[2, 1] = -344399655;
							array29[2, 2] = 2065848053;
							array29[3, 0] = -492533677;
							array29[3, 1] = -55483587;
							array29[3, 2] = -1592169926;
							array29[3, 2] = array29[3, 1] ^ -792957863;
							array29[3, 0] = array29[2, 1] ^ -1531578044;
							array29[0, 0] = array29[0, 2] ^ -1351874865;
							array29[3, 2] = array29[3, 1] ^ 0x7273E95F;
							int num71 = array29[3, 2] ^ -1010770051;
							num2 = (int)((num5 * 886788296) ^ 0x1CD71380) ^ num71;
							continue;
						}
						int num72 = -642629872;
						_ = 0;
						for (int num73 = 0; num73 < 2; num73++)
						{
							num72 = ~(-num72);
							num72 = -(num72 * 1458985691);
						}
						if (num4 == (uint)num72)
						{
							_003C_003E1__state = 1;
							int[] array30 = new int[5];
							array30[0] = 4904225;
							array30[1] = 561617588;
							array30[2] = -1112156252;
							array30[3] = 1348988864;
							array30[4] = -1932868929;
							array30[0] = array30[4] ^ 0x720600B7;
							array30[2] ^= 124728926;
							int[] array31 = new int[5] { -236595691, 1938087684, -363104026, 266412675, 1994101372 };
							int[][] array32 = new int[2][] { array30, array31 };
							array31[2] = array32[0][3] ^ -712910152;
							array31[0] = array31[1] ^ 0x69406501;
							array31[4] = array31[0] ^ 0x66A1B56B;
							int num74 = array32[1][2] ^ -1969475892;
							num2 = (int)((num5 * 545735543) ^ 0x6AD11D11) ^ num74;
							continue;
						}
						int num75 = -2146876591;
						_ = 0;
						for (int num76 = 0; num76 < 2; num76++)
						{
							num75 = ~(num75 - ~-1308165605);
							num75 = (num75 - (-1419085794 - -1888693857)) ^ -1041976921;
						}
						if (num4 == (uint)num75)
						{
							return true;
						}
						int num77 = 929369612;
						_ = 0;
						for (int num78 = 0; num78 < 2; num78++)
						{
							num77 += --1949341554;
							num77 = num77 + -998341569 + -1415684787;
						}
						if (num4 != (uint)num77)
						{
							int num79 = -4;
							_ = 0;
							for (int num80 = 0; num80 < 1; num80++)
							{
								num79 = -num79;
							}
							if (num4 != (uint)num79)
							{
								int num81 = 16694449;
								_ = 0;
								for (int num82 = 0; num82 < 1; num82++)
								{
									num81 = 16694475 - num81;
								}
								if (num4 != (uint)num81)
								{
									int num83 = 31;
									_ = 0;
									for (int num84 = 0; num84 < 2; num84++)
									{
										num83 = ~num83 + -567248022;
										num83 = -(~num83);
									}
									if (num4 != (uint)num83)
									{
										int num85 = 751411204;
										_ = 0;
										for (int num86 = 0; num86 < 1; num86++)
										{
											num85 -= 751411190;
										}
										if (num4 != (uint)num85)
										{
											int num87 = 1143111889;
											_ = 0;
											for (int num88 = 0; num88 < 2; num88++)
											{
												num87 = -(-346539403 * -430963673 - num87);
												num87 = ~num87 ^ -342792096;
											}
											if (num4 != (uint)num87)
											{
												int num89 = -11;
												_ = 0;
												for (int num90 = 0; num90 < 1; num90++)
												{
													num89 = ~num89;
												}
												if (num4 != (uint)num89)
												{
													int num91 = 1585893252;
													_ = 0;
													for (int num92 = 0; num92 < 1; num92++)
													{
														num91 -= 1585893243;
													}
													if (num4 != (uint)num91)
													{
														int num93 = -30;
														_ = 0;
														for (int num94 = 0; num94 < 1; num94++)
														{
															num93 = ~num93;
														}
														if (num4 != (uint)num93)
														{
															int num95 = -299487482;
															_ = 0;
															for (int num96 = 0; num96 < 2; num96++)
															{
																num95 = -(num95 * -428590839);
																num95 = 1214107925 - (num95 ^ -1361422374);
															}
															if (num4 != (uint)num95)
															{
																int num97 = 11;
																_ = 0;
																for (int num98 = 0; num98 < 2; num98++)
																{
																	num97 = -353070365 - ((-1427317407 ^ -1137607275) - num97);
																	num97 = -(num97 + (0x406835EA ^ 0x25586E0A));
																}
																if (num4 != (uint)num97)
																{
																	int num99 = 1069749674;
																	_ = 0;
																	for (int num100 = 0; num100 < 1; num100++)
																	{
																		num99 = 1069749689 - num99;
																	}
																	if (num4 != (uint)num99)
																	{
																		int num101 = 20;
																		_ = 0;
																		for (int num102 = 0; num102 < 2; num102++)
																		{
																			num101 = -503033427 - ~num101;
																			num101 = ~(num101 - (0x52F337CE ^ 0x5B4199A2));
																		}
																		if (num4 != (uint)num101)
																		{
																		}
																		return false;
																	}
																	goto IL_16e3;
																}
																return true;
															}
															_003C_003E1__state = 2;
															int[] array33 = new int[5];
															array33[0] = 657380359;
															array33[1] = -1514545954;
															array33[2] = -1243958901;
															array33[3] = -1976980282;
															array33[4] = -1638768562;
															array33[0] = array33[1] ^ -1152895662;
															array33[2] = array33[1] ^ -1984809367;
															int[] array34 = new int[5] { 1168612251, 1282962556, -178376161, -615678294, -904942642 };
															int[][] array35 = new int[2][] { array33, array34 };
															array34[1] = array35[0][1] ^ 0x6362E529;
															array34[2] = array34[4] ^ 0x4691EF6C;
															array34[3] = array34[4] ^ -560134525;
															array34[3] = array34[0] ^ -568342522;
															int num103 = array35[1][1] ^ -1984053244;
															num2 = (int)((num5 * 2113286470) ^ 0x5097D41C) ^ num103;
															continue;
														}
														_003C_003E2__current = new string(_003Ccurrent_003E5__2.ToArray());
														int[,] array36 = new int[4, 3];
														array36[0, 0] = 1893359985;
														array36[0, 1] = 861722641;
														array36[0, 2] = -1365876289;
														array36[1, 0] = -2141830765;
														array36[1, 1] = -1328102645;
														array36[1, 2] = -1950112501;
														array36[2, 0] = 1604842423;
														array36[2, 1] = 841007382;
														array36[2, 2] = 1521657383;
														array36[3, 0] = -2118805137;
														array36[3, 1] = 1391528739;
														array36[3, 2] = -1573060671;
														array36[1, 1] = array36[2, 1] ^ 0x7856EAAA;
														array36[3, 1] = array36[2, 1] ^ -1324528888;
														array36[0, 1] = array36[2, 0] ^ -1314437205;
														int num104 = array36[0, 1] ^ 0x3B65F876;
														num2 = ((int)num5 * -311704110) ^ 0x411F4CBA ^ num104;
														continue;
													}
													int count2 = _003Ccurrent_003E5__2.Count;
													int[] array37 = new int[4];
													array37[0] = 373420357;
													array37[1] = 695492637;
													array37[2] = 1150838120;
													array37[3] = -839878269;
													array37[3] = array37[1] ^ 0x37AE8EF5;
													array37[3] = array37[2] ^ 0x5B44BAD2;
													array37[2] ^= 1627901660;
													int[] array38 = new int[5] { 1370914707, -1861303764, 1375683956, 1487370634, 1212128734 };
													int[][] array39 = new int[2][] { array37, array38 };
													array38[3] = array39[0][0] ^ 0x65CA0D67;
													array38[1] = array38[2] ^ 0x301CBEDB;
													array38[2] = array38[3] ^ 0x4E222EB4;
													int num105 = array39[1][3] ^ -1971002959;
													int[] array40 = new int[5];
													array40[0] = -694568441;
													array40[1] = 918761807;
													array40[2] = 855535982;
													array40[3] = 1854200147;
													array40[4] = -755184467;
													array40[0] = array40[1] ^ 0x17415F5E;
													array40[2] = array40[0] ^ 0x1B60CE34;
													int[] array41 = new int[4];
													array41[0] = 1720577902;
													array41[1] = -2116926501;
													array41[2] = -1330605879;
													array41[3] = 1849762696;
													array41[3] = array40[4] ^ 0x63CDD38A;
													array41[2] = array41[3] ^ -1947204132;
													array41[0] = array41[2] ^ 0x22899604;
													int num106 = array41[3] ^ 0x2D7C63EA;
													int num107 = ((int)num5 * -282315889) ^ 0x4C9E5D86;
													num105 ^= num107;
													num106 ^= num107;
													int num108;
													int num109;
													if (count2 > 0)
													{
														num108 = num106;
														num109 = num108;
													}
													else
													{
														num108 = num105;
														num109 = num108;
													}
													num2 = num108 ^ num107;
													continue;
												}
												_003C_003E7__wrap3 = null;
												int[] array42 = new int[4];
												array42[0] = -1765490784;
												array42[1] = 672211518;
												array42[2] = -1509542228;
												array42[3] = -1715751673;
												array42[3] = array42[1] ^ 0x57DD2168;
												array42[2] = array42[3] ^ 0xAA3F929;
												array42[1] = array42[0] ^ -1454991984;
												int[] array43 = new int[6] { -722289896, 817761112, -1415189029, -1874511770, 847854358, -1803877201 };
												int[][] array44 = new int[2][] { array42, array43 };
												array43[2] = array44[0][0] ^ 0x1FF36E57;
												array43[0] = array43[1] ^ 0x7098070C;
												array43[5] ^= 1864445202;
												int num110 = array44[1][2] ^ -1099149539;
												num2 = ((int)num5 * -625132262) ^ -1682370132 ^ num110;
												continue;
											}
											int num111;
											if (_003C_003E7__wrap4 >= _003C__0040_0024_005E_0026_003F_0025(_003C_003E7__wrap3))
											{
												num2 = 238089950;
												num111 = num2;
											}
											else
											{
												num2 = 71604165;
												num111 = num2;
											}
											continue;
										}
										_003C_003E7__wrap4++;
										num2 = 1107180490;
										continue;
									}
									_003Ccurrent_003E5__2.Add(c);
									num2 = -1459178043;
									continue;
								}
								int[] array45 = new int[4];
								array45[0] = 1872695676;
								array45[1] = -1063676076;
								array45[2] = -476657021;
								array45[3] = 157460525;
								array45[3] = array45[0] ^ 0x5C659B24;
								array45[0] = array45[1] ^ -936109537;
								array45[0] = array45[1] ^ 0x21CC8693;
								int[] array46 = new int[4] { 1480570256, -2059758331, -1991304224, 1137821887 };
								int[][] array47 = new int[2][] { array45, array46 };
								array46[2] = array47[0][1] ^ 0x6A4CB44F;
								array46[3] = array46[2] ^ 0x1BFBF0AF;
								array46[3] = array46[2] ^ 0xB29BD6E;
								int num112 = array47[1][2] ^ 0x3D396DE;
								num2 = ((int)num5 * -1739624648) ^ -233072304 ^ num112;
								continue;
							}
							_003Ccurrent_003E5__2.Clear();
							int[] array48 = new int[5];
							array48[0] = 1808063576;
							array48[1] = 1254737926;
							array48[2] = -1754934373;
							array48[3] = 1006185262;
							array48[4] = -1055708451;
							array48[0] = array48[2] ^ 0x6D154886;
							array48[0] ^= 954927677;
							int[] array49 = new int[6] { -916937653, -1473354416, 1697495960, -2113226035, 2009468670, -191556290 };
							int[][] array50 = new int[2][] { array48, array49 };
							array49[0] = array50[0][3] ^ 0x620E6738;
							array49[4] = array49[5] ^ 0x2C0EF8DD;
							array49[3] = array49[5] ^ -289418023;
							array49[3] = array49[5] ^ -371797210;
							int num113 = array50[1][0] ^ -464792928;
							num2 = ((int)num5 * -911948477) ^ 0x427D9B2E ^ num113;
							continue;
						}
					}
					else
					{
						switch (num)
						{
						case 1:
							break;
						case 2:
							goto IL_16e3;
						case 0:
							goto IL_1bf8;
						default:
							goto IL_3be5;
						}
					}
					_003C_003E1__state = -1;
					num2 = -1243187958;
					continue;
					IL_3be5:
					int[] array51 = new int[7];
					array51[0] = 1735852041;
					array51[1] = -2037574949;
					array51[2] = 564183800;
					array51[3] = -248174847;
					array51[4] = -264816543;
					array51[5] = 1719334671;
					array51[6] = 1031062004;
					array51[5] = array51[1] ^ 0x36D55F4C;
					array51[6] = array51[1] ^ -1176379685;
					int[] array52 = new int[7];
					array52[0] = -1918833445;
					array52[1] = 2021691006;
					array52[2] = -652721523;
					array52[3] = 481232245;
					array52[4] = 690274069;
					array52[5] = -690927114;
					array52[6] = -662662280;
					array52[6] = array51[1] ^ -74175395;
					array52[3] ^= -1693100197;
					array52[2] = array52[3] ^ 0x7CFC786E;
					int num114 = array52[6] ^ 0x2CE09BF1;
					num2 = (int)((num5 * 365587117) ^ 0x38320B55) ^ num114;
					continue;
					IL_16e3:
					_003C_003E1__state = -1;
					num2 = -116449901;
					continue;
					IL_1bf8:
					_003C_003E1__state = -1;
					num2 = -2098246885;
				}
			}
		}

		bool IEnumerator.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			return this.MoveNext();
		}

		[DebuggerHidden]
		void IEnumerator.Reset()
		{
			throw new NotSupportedException();
		}

		[DebuggerHidden]
		IEnumerator<string> IEnumerable<string>.GetEnumerator()
		{
			if (_003C_003E1__state == -2)
			{
				goto IL_0013;
			}
			goto IL_08ad;
			IL_0013:
			int num = -1551938595;
			goto IL_0018;
			IL_0018:
			uint num3;
			_003CSplitCommandLine_003Ed__19 _003CSplitCommandLine_003Ed__20 = default(_003CSplitCommandLine_003Ed__19);
			while (true)
			{
				int num2 = num;
				uint num4;
				num3 = (num4 = (uint)((((num2 - ~(~(2027322359 * (163769447 + -302848415 - ~((0x6F3F7286 ^ 0x304273DB) * 244012247))))) * 1262846433 - -(210844160 * -1552124437) + ~(((-(-225727845 * -1719395117) - (-978318395 ^ -1280645857)) ^ ((0x325E2FD5 ^ -1402347038) + --1956242084 + (~1099382447 - (-958857220 - 751979126)))) + (-1221933223 ^ (-(~-761549167) ^ (1576250136 * 1934910827 - --1389130373))))) * 979233325 * -820019583) ^ -1575631062)) % 7;
				int num5 = 1072725312;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~(num5 ^ -537491437);
					num5 = ~num5 - 510178977;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -1482787462;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = num7 - (0x61E6F198 ^ 0x6028AC6) + 336937124;
					num7 = ~(~num7);
				}
				if (num3 != (uint)num7)
				{
					int num9 = 2;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = 1386013539 - (num9 - (1658159929 - 1524543129));
						num9 = -(~num9);
					}
					if (num3 != (uint)num9)
					{
						int num11 = 1572897;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = (num11 ^ -1550511174) - -2035771897;
							num11 = -num11 - 1525482010;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 85498183;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = num13 - (1534969350 + 1905752792) - 896994243;
								num13 = ~(-num13);
							}
							if (num3 == (uint)num13)
							{
								int[] array = new int[4] { -908012783, 1870698616, -1710661169, 2079026260 };
								array[0] ^= -745795136;
								array[0] = array[1] ^ 0x53F7D3F1;
								int[] array2 = new int[4] { -216529019, 231829792, -1670917258, -1552536412 };
								int[][] array3 = new int[2][] { array, array2 };
								array2[2] = array3[0][2] ^ 0x483482A2;
								array2[1] = array2[3] ^ 0x74819FD4;
								array2[0] ^= 2045140421;
								int num15 = array3[1][2] ^ 0x55C18D89;
								num = ((int)num4 * -280653809) ^ 0x40EBE870 ^ num15;
								continue;
							}
							goto IL_0336;
						}
						_003CSplitCommandLine_003Ed__20 = this;
						int[] array4 = new int[6];
						array4[0] = 1068681804;
						array4[1] = 61730540;
						array4[2] = -780768663;
						array4[3] = 1035147538;
						array4[4] = -971374745;
						array4[5] = -2054449821;
						array4[1] = array4[0] ^ 0x1FD35E76;
						array4[5] = array4[1] ^ -1592439358;
						int[] array5 = new int[4] { 279819800, 1823293700, 335440436, -420525369 };
						int[][] array6 = new int[2][] { array4, array5 };
						array5[1] = array6[0][0] ^ -1935672855;
						array5[2] = array5[3] ^ -322037026;
						array5[3] ^= -1412068387;
						int num16 = array6[1][1] ^ 0xF4EECE2;
						num = (int)((num4 * 382222122) ^ 0xD444D91Cu) ^ num16;
						continue;
					}
					_003C_003E1__state = 0;
					int[] array7 = new int[4];
					array7[0] = 591754905;
					array7[1] = 1007750740;
					array7[2] = 1096850034;
					array7[3] = -1314768431;
					array7[2] = array7[3] ^ 0x23575AB3;
					array7[0] = array7[2] ^ 0x5C0F5F7E;
					array7[2] ^= -224205045;
					int[] array8 = new int[5] { 1731496484, -18961351, 1016012125, 1374689548, -905735519 };
					int[][] array9 = new int[2][] { array7, array8 };
					array8[1] = array9[0][3] ^ -1838827860;
					array8[3] = array8[1] ^ -821692745;
					array8[3] = array8[0] ^ -866905727;
					int num17 = array9[1][1] ^ 0x7094DD6C;
					num = ((int)num4 * -123420647) ^ -58087393 ^ num17;
					continue;
				}
				int num18 = _003C_003El__initialThreadId;
				int num19 = _002F_0023_0024_002D_0025_002B_0028_0021();
				int[] array10 = new int[5];
				array10[0] = -550430991;
				array10[1] = 89772888;
				array10[2] = -1431952954;
				array10[3] = -1632087128;
				array10[4] = 863403691;
				array10[4] = array10[0] ^ -1998449217;
				array10[4] = array10[0] ^ 0x41C73694;
				int[] array11 = new int[6];
				array11[0] = -7886151;
				array11[1] = 1444591706;
				array11[2] = 1608412402;
				array11[3] = -617771949;
				array11[4] = -2027799005;
				array11[5] = -821622843;
				array11[4] = array10[1] ^ 0x3D47A60;
				array11[3] = array11[4] ^ 0x14C79565;
				array11[0] ^= -1987933431;
				array11[0] = array11[4] ^ -1688539692;
				int num20 = array11[4] ^ -439741861;
				int[] array12 = new int[6];
				array12[0] = 1474212626;
				array12[1] = 286400736;
				array12[2] = 2133885848;
				array12[3] = 128819284;
				array12[4] = 545647754;
				array12[5] = -1199355150;
				array12[4] = array12[5] ^ -137072333;
				array12[0] = array12[4] ^ -1310056061;
				int[] array13 = new int[7] { 33862184, 1886782402, -240787790, -819607458, 413715548, 605166484, 105357771 };
				int[][] array14 = new int[2][] { array12, array13 };
				array13[2] = array14[0][1] ^ -1873830879;
				array13[5] ^= 974800831;
				array13[0] = array13[5] ^ -468802031;
				int num21 = array14[1][2] ^ -1601198089;
				int num22 = (int)((num4 * 601531803) ^ 0x3C613D06);
				num20 ^= num22;
				num21 ^= num22;
				int num23;
				int num24;
				if (num18 == num19)
				{
					num23 = num21;
					num24 = num23;
				}
				else
				{
					num23 = num20;
					num24 = num23;
				}
				num = num23 ^ num22;
			}
			goto IL_0013;
			IL_0336:
			int num25 = 1056046828;
			_ = 0;
			for (int num26 = 0; num26 < 1; num26++)
			{
				num25 *= -321884813;
			}
			if (num3 != (uint)num25)
			{
				int num27 = -2;
				_ = 0;
				for (int num28 = 0; num28 < 1; num28++)
				{
					num27 = ~num27;
				}
				if (num3 != (uint)num27)
				{
				}
				_003CSplitCommandLine_003Ed__20.arguments = _003C_003E3__arguments;
				return _003CSplitCommandLine_003Ed__20;
			}
			goto IL_08ad;
			IL_08ad:
			_003CSplitCommandLine_003Ed__20 = new _003CSplitCommandLine_003Ed__19(0);
			num = -2013499676;
			goto IL_0018;
		}

		[DebuggerHidden]
		IEnumerator IEnumerable.GetEnumerator()
		{
			return ((IEnumerable<string>)this).GetEnumerator();
		}

		static int _002F_0023_0024_002D_0025_002B_0028_0021()
		{
			int currentManagedThreadId = default(int);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 1869570118;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(((num2 ^ ~(~(-1724521910 + (-(-609478131 * ~1774836112 - (-1767207799 ^ -562336188)) - -1511525271 * -811355813 - ((-2027158587 ^ ((-1944904311 + --1656386639) ^ -1034207483)) + -1356899236)))) ^ (-119904303 * ~(541325387 * (260380151 * (0x23089300 ^ 0x5C8C482D) + (1650337373 * 479372369 + -1814462702 * 1063926875) - -72693214)) - -1714708942) ^ ((0x5D01CD67 ^ ~(~(-1303496590))) - ~(~(~(-599555753 ^ 0x1C488DB))) - -900521997 * ((0x16CA2DDB ^ -832011374) + (-(-698466285 + 978800479) ^ -531204799)) - (-(-1212429421 + 1442453134 - ~1679644355 + (0x70B849C6 ^ -755744611) + ((0x762D4606 ^ 0x239F7434) + -(1093459987 - 1084999628))) ^ (-749969490 - (-(-756813565 - 1901248759) - (-1845451775 - (-776627729 + -1602609978))) - 2135311639)))) * 1507832661 + ((1075605959 + -(~576841796 * -475507545)) ^ -1883056582) - -475114409 * -605710669) ^ 0x2C2DD7B1 ^ (477843843 * --379514974))) % 3;
						int num5 = -1461417848;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = ~(num5 ^ -1684188792);
							num5 = (num5 * -1488581175) ^ -667020776;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -1018883633;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 ^= -1018883634;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1919238376;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = (num9 * -625919389) ^ -99142949;
								num9 = ~(~num9);
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						currentManagedThreadId = Environment.CurrentManagedThreadId;
						int[] array = new int[5] { -2113369724, 2144379269, 566887927, -542082457, -1456308699 };
						array[4] ^= 712111470;
						array[4] = array[3] ^ 0x227E5EB;
						array[4] ^= -573878369;
						int[] array2 = new int[5] { -1504002053, 995063746, 419759271, -1897451819, -54818664 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[0] = array3[0][1] ^ 0x7B9F2929;
						array2[1] = array2[2] ^ -1230475838;
						array2[3] = array2[4] ^ -2126983866;
						int num11 = array3[1][0] ^ -1364759153;
						num = (int)((num4 * 999928759) ^ 0xE308DAE2u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return currentManagedThreadId;
		}

		static bool _002B_002B_0029_0021_0026__003C_0021(string P_0)
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
					int num = -1783106562;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(((((-num2 * 409545411 * -955451631) ^ (0x7883877A ^ (1215037057 * ((--1867830420 + (1748736667 - 329823832) - ~269847616) ^ 0x57CFC8F6))) ^ (712057219 * -918189416 * 559263585 - ~(-(1023800702 * -1532796421) ^ -523924835))) - -(-(-2023155295 * (318630147 - -516111630))) - ((-1674182453 - 1169412232) * 456016335 + (0x57563F4C ^ -490574478))) * 1046145911 * -522026057) ^ -944508195)) % 3;
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
						int num7 = -419115219;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 *= -1344940501;
							num7 = (num7 - -1952370309 * 1339011929) ^ -106652808;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1688711140;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 ^= -1688711138;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = string.IsNullOrWhiteSpace(P_0);
						int[] array = new int[6];
						array[0] = -1552072400;
						array[1] = 1376916662;
						array[2] = -1714139167;
						array[3] = -1723160511;
						array[4] = -490257400;
						array[5] = -313994045;
						array[0] = array[1] ^ 0x54D40305;
						array[3] = array[1] ^ -867269735;
						int[] array2 = new int[5] { 2021105093, 124123076, 1160129448, 561609039, 510161093 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[3] = array3[0][5] ^ 0x271A8846;
						array2[4] ^= 1908386877;
						array2[0] = array2[3] ^ -1359644917;
						int num11 = array3[1][3] ^ -2113053698;
						num = (int)((num4 * 1741491123) ^ 0xCDAE0895u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static char _0026_0029_002A_003D_0025_005E_003D_0029(string P_0, int P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				return P_0[P_1];
			}
		}

		static bool _002F__0025_005E_005E_002A_002A_003D(char P_0)
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
					int num = -2063163191;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(((-((((num2 * 1558652787 - ((0x19C54864 ^ ((((-90139599 * --1232738935) ^ 0x518BE7B2) + 689426248 + ((-1206732836 ^ -2030618306) - ~(--58272434 + ~-958420292))) ^ (-(-(0x56A25F8 ^ 0x2F340292)) + -875833528 + ((1734135841 * -(~-45810727)) ^ ~(-(~-996952996)))))) - (185749749 - 1643840085 * -155373271))) ^ (-(-(-1164378571 ^ 0xBB3675B) + 1729146512) - ~(0x4E84D6FE ^ 0x7938EC1D) * 1930673829)) - ~(-121808346 ^ -1689660875)) * -1250103743 * -1627275799) * 381212917) ^ 0x456EE498) * 1564984849)) % 3;
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
							int num9 = -661276531;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 ^= -661276531;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = char.IsWhiteSpace(P_0);
						int[,] array = new int[4, 4];
						array[0, 0] = 432177342;
						array[0, 1] = -862063733;
						array[0, 2] = 1824047412;
						array[0, 3] = 699215712;
						array[1, 0] = 2056859518;
						array[1, 1] = 1335453572;
						array[1, 2] = 1376610460;
						array[1, 3] = -962791831;
						array[2, 0] = -1590906139;
						array[2, 1] = 1066174801;
						array[2, 2] = 1553798533;
						array[2, 3] = 455330705;
						array[3, 0] = -1882650547;
						array[3, 1] = 1329522681;
						array[3, 2] = -147247945;
						array[3, 3] = 1262893459;
						array[1, 1] = array[0, 1] ^ -1746110879;
						array[0, 1] = array[0, 0] ^ -217618787;
						array[1, 2] = array[2, 2] ^ 0x1C41E5A8;
						int num11 = array[1, 2] ^ -1253767026;
						num = ((int)num4 * -37739047) ^ -1554847454 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static int _003C__0040_0024_005E_0026_003F_0025(string P_0)
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
					int num = -1228707840;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(-(~(-(~(-num2)) - (-(119239545 * -1909814152) - ((--839125790 - (2009281558 - 43678406) + (1026987983 + 1417984698 + ~-2096618612) + 897254591) ^ ((-590733333 ^ -2049923108) - ~(-1799927898) - ~(-(--304573148)))))))) ^ 0x751E7B07)) % 3;
						int num5 = -956282782;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -(num5 ^ 0x533B02AE);
							num5 = ~num5 + 494852563;
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
							int num9 = 942603470;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 ^= 0x382EFCCE;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						length = P_0.Length;
						int[,] array = new int[4, 4];
						array[0, 0] = 207747550;
						array[0, 1] = 910722418;
						array[0, 2] = -1196863475;
						array[0, 3] = 1068956272;
						array[1, 0] = 349880786;
						array[1, 1] = -2019676527;
						array[1, 2] = 185667232;
						array[1, 3] = 2140604961;
						array[2, 0] = 282107397;
						array[2, 1] = 1009800580;
						array[2, 2] = 298767274;
						array[2, 3] = 229310546;
						array[3, 0] = -1941847577;
						array[3, 1] = 794506968;
						array[3, 2] = 1577779547;
						array[3, 3] = -1855326805;
						array[3, 3] = array[2, 3] ^ -1835996650;
						array[1, 3] = array[3, 2] ^ -2082228960;
						array[2, 2] = array[3, 2] ^ 0x48583A4B;
						array[3, 0] = array[3, 1] ^ -338896205;
						int num11 = array[3, 0] ^ -1984907633;
						num = ((int)num4 * -293222158) ^ 0x60EA63B8 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return length;
		}
	}

	private readonly bool ZwQ_003D;

	private static string? fJa_003D;

	[CompilerGenerated]
	private static IServiceProvider zCC_003D;

	[CompilerGenerated]
	private static Window? LZP_003D;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private bool DnV_003D;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private XamlMetaDataProvider lkm_003D;

	public static IServiceProvider TbG_003D
	{
		[CompilerGenerated]
		get
		{
			return zCC_003D;
		}
		[CompilerGenerated]
		private set
		{
			zCC_003D = value;
		}
	}

	public static Window? Yrv_003D
	{
		[CompilerGenerated]
		get
		{
			return LZP_003D;
		}
		[CompilerGenerated]
		private set
		{
			LZP_003D = value;
		}
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	private XamlMetaDataProvider Xtc_003D
	{
		get
		{
			if (lkm_003D == null)
			{
				uint num3;
				while (true)
				{
					int num = 240658483;
					while (true)
					{
						int num2 = num;
						uint num4;
						num3 = (num4 = (uint)(~(~(-num2 + -(~(-598858017 + (-(~(~-1414201017)) ^ -2106667057)) - (520632779 + 1149178611 * (0x7C020F5 ^ 0x364A58DB))))))) % 3;
						int num5 = 1503701212;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 = 1503701212 - num5;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 6;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -(num7 ^ -1752778990);
							num7 = -(num7 ^ 0x4391F5A1);
						}
						if (num3 != (uint)num7)
						{
							goto end_IL_000e;
						}
						lkm_003D = new XamlMetaDataProvider();
						int[,] array = new int[3, 3];
						array[0, 0] = -379082368;
						array[0, 1] = -1407949395;
						array[0, 2] = -708811526;
						array[1, 0] = -1355922887;
						array[1, 1] = 1868313922;
						array[1, 2] = -1410291508;
						array[2, 0] = -1591162143;
						array[2, 1] = -1740379425;
						array[2, 2] = 218480060;
						array[1, 2] = array[2, 1] ^ -1506509174;
						array[0, 2] = array[1, 0] ^ -90230039;
						array[2, 0] = array[1, 1] ^ -88618823;
						array[0, 1] = array[2, 1] ^ 0x69BE161A;
						int num9 = array[0, 1] ^ -943627899;
						num = ((int)num4 * -1198175214) ^ -675533648 ^ num9;
					}
					continue;
					end_IL_000e:
					break;
				}
				int num10 = -1;
				_ = 0;
				for (int num11 = 0; num11 < 1; num11++)
				{
					num10 = -num10;
				}
				if (num3 == (uint)num10)
				{
				}
			}
			return lkm_003D;
		}
	}

	public AVZ_003D()
	{
		AppInstance appInstance = default(AppInstance);
		AppActivationArguments appActivationArguments = default(AppActivationArguments);
		AppInstance appInstance2 = default(AppInstance);
		while (true)
		{
			int num = -1975211802;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(~(-(0x1E917E32 ^ -745682163) - -(~(~(num2 + -((~(~(--1167805896) - -1422971977 * -2122347906 * -1842488811 - ~((-1385858759 - -1973691759) * 295024303)) ^ 0x5B9D6135) + -(-1087703880 + (-23155271 - ~-2146465693 - -1133216233 * -1097647869 - -1853286337)) - 1140234823 * 2142412915)) + ~(~((0xED35A41 ^ --1302756990 ^ (--295501606 - --1113058958)) + 1819738391 + (-1055610802 * -1896432807 * 2132534841 + -(-1992789984 - -302119123 - --881976857))))) - ~(-1779321942 ^ 0x49EC63F2)))) * -1646378321)) % 13;
				int num5 = 6;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = -(-num5);
					num5 = -(-num5);
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 125960692;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -num7 ^ -107682143;
					num7 = 1522577649 - (num7 - -771889097);
				}
				if (num3 != (uint)num7)
				{
					int num9 = 292633804;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 ^= 0x11713CCC;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 650359412;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 += -650359411;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 1842395837;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 *= 553579539;
							}
							if (num3 != (uint)num13)
							{
								int num15 = -1176696747;
								_ = 0;
								for (int num16 = 0; num16 < 2; num16++)
								{
									num15 = (num15 * -845769941) ^ -1683461798;
									num15 = num15 * -1376983341 * 1760708569;
								}
								if (num3 != (uint)num15)
								{
									int num17 = 130126402;
									_ = 0;
									for (int num18 = 0; num18 < 1; num18++)
									{
										num17 ^= 0x7C19248;
									}
									if (num3 != (uint)num17)
									{
										int num19 = 9;
										_ = 0;
										for (int num20 = 0; num20 < 2; num20++)
										{
											num19 = ~(num19 - --15089748);
											num19 = -(-num19);
										}
										if (num3 != (uint)num19)
										{
											int num21 = 24433524;
											_ = 0;
											for (int num22 = 0; num22 < 2; num22++)
											{
												num21 = -(~num21);
												num21 *= -398511001;
											}
											if (num3 != (uint)num21)
											{
												int num23 = -971095047;
												_ = 0;
												for (int num24 = 0; num24 < 2; num24++)
												{
													num23 = num23 ^ -768846584 ^ -182604977;
													num23 = ~(num23 + ~204922404);
												}
												if (num3 == (uint)num23)
												{
													return;
												}
												int num25 = -3;
												_ = 0;
												for (int num26 = 0; num26 < 1; num26++)
												{
													num25 = ~num25;
												}
												if (num3 != (uint)num25)
												{
													int num27 = -1977974165;
													_ = 0;
													for (int num28 = 0; num28 < 2; num28++)
													{
														num27 = (1474497092 + -1256582553 - num27) ^ 0x6AA61774;
														num27 = num27 ^ -112066964 ^ -725966749;
													}
													if (num3 != (uint)num27)
													{
														int num29 = -9;
														_ = 0;
														for (int num30 = 0; num30 < 1; num30++)
														{
															num29 = ~num29;
														}
														if (num3 == (uint)num29)
														{
														}
														return;
													}
													_002A_0028_003E_002B_003D_003E_003E_(appInstance, (EventHandler<AppActivationArguments>)yJf_003D);
													num = 840148964;
												}
												else
												{
													aPe_003D(appActivationArguments);
													num = -2009050204;
												}
											}
											else
											{
												zFd_003D(appInstance2, appActivationArguments);
												int[,] array = new int[3, 4];
												array[0, 0] = 460647841;
												array[0, 1] = 1774308078;
												array[0, 2] = 989851414;
												array[0, 3] = 1724500702;
												array[1, 0] = 1358427170;
												array[1, 1] = 1807893608;
												array[1, 2] = 783682911;
												array[1, 3] = 1421817111;
												array[2, 0] = -328973865;
												array[2, 1] = 1128187199;
												array[2, 2] = 351819544;
												array[2, 3] = -1835505240;
												array[2, 1] = array[1, 2] ^ -8913186;
												array[2, 0] = array[1, 2] ^ -171867380;
												array[1, 1] = array[0, 0] ^ -351333813;
												array[2, 1] = array[0, 0] ^ 0x3C1A1B55;
												int num31 = array[2, 1] ^ 0x11F583;
												num = ((int)num4 * -1686764780) ^ 0x48796E1C ^ num31;
											}
										}
										else
										{
											ZwQ_003D = true;
											int[,] array2 = new int[3, 4];
											array2[0, 0] = -1066847336;
											array2[0, 1] = -1060237300;
											array2[0, 2] = -2047408461;
											array2[0, 3] = 210277454;
											array2[1, 0] = 1431106731;
											array2[1, 1] = 1611131105;
											array2[1, 2] = 2066210303;
											array2[1, 3] = -1981342163;
											array2[2, 0] = -1139350017;
											array2[2, 1] = -992356400;
											array2[2, 2] = -390803058;
											array2[2, 3] = 1130733639;
											array2[0, 2] = array2[1, 2] ^ -675557524;
											array2[0, 0] = array2[0, 2] ^ -637836427;
											array2[2, 3] = array2[0, 3] ^ 0x496150C8;
											array2[2, 2] = array2[1, 2] ^ -869787942;
											int num32 = array2[2, 2] ^ -475299562;
											num = (int)((num4 * 1283618621) ^ 0x8CF47E87u) ^ num32;
										}
									}
									else
									{
										bool num33 = _0021_003D_003E_003D_0023_002B_002D_0024(appInstance2);
										int[,] array3 = new int[3, 4];
										array3[0, 0] = -341012208;
										array3[0, 1] = -257980516;
										array3[0, 2] = 583633295;
										array3[0, 3] = 199497644;
										array3[1, 0] = 2020394949;
										array3[1, 1] = 1162263633;
										array3[1, 2] = -965500832;
										array3[1, 3] = -1274550635;
										array3[2, 0] = -812364977;
										array3[2, 1] = -432870861;
										array3[2, 2] = -1820235904;
										array3[2, 3] = 1745032012;
										array3[2, 3] = array3[0, 0] ^ -581587455;
										array3[0, 3] = array3[0, 0] ^ -1637921058;
										array3[0, 2] ^= -1391894164;
										array3[0, 3] = array3[0, 0] ^ -1175238159;
										int num34 = array3[0, 3] ^ -1507607151;
										int[,] array4 = new int[4, 4];
										array4[0, 0] = -454974725;
										array4[0, 1] = -542944435;
										array4[0, 2] = -1671891114;
										array4[0, 3] = 678349803;
										array4[1, 0] = -679078632;
										array4[1, 1] = 374535625;
										array4[1, 2] = 1599055412;
										array4[1, 3] = -278207271;
										array4[2, 0] = -228137510;
										array4[2, 1] = -397715041;
										array4[2, 2] = -454599555;
										array4[2, 3] = 101389355;
										array4[3, 0] = 1205453411;
										array4[3, 1] = -1239399496;
										array4[3, 2] = -117178732;
										array4[3, 3] = -1885817843;
										array4[1, 0] = array4[1, 1] ^ 0x576E450A;
										array4[1, 1] = array4[1, 3] ^ -225305389;
										array4[2, 1] = array4[0, 2] ^ 0x184FD5BD;
										array4[0, 1] = array4[3, 1] ^ -347025496;
										int num35 = array4[0, 1] ^ -104753557;
										int num36 = ((int)num4 * -1723891436) ^ -213847360;
										num34 ^= num36;
										num35 ^= num36;
										int num37;
										int num38;
										if (!num33)
										{
											num37 = num35;
											num38 = num37;
										}
										else
										{
											num37 = num34;
											num38 = num37;
										}
										num = num37 ^ num36;
									}
								}
								else
								{
									appInstance2 = _005E_0025_0024_0029_003E_003C_0026_(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-464 + 458)]);
									int[] array5 = new int[5];
									array5[0] = 1563432827;
									array5[1] = -158981613;
									array5[2] = -950363466;
									array5[3] = 1213048634;
									array5[4] = -1743031312;
									array5[4] = array5[3] ^ -1705557174;
									array5[3] = array5[0] ^ 0xFCBA3B2;
									array5[1] = array5[3] ^ 0x6841D6A0;
									int[] array6 = new int[6];
									array6[0] = -1574970216;
									array6[1] = 738994592;
									array6[2] = 1566990006;
									array6[3] = -1686046621;
									array6[4] = -1912669929;
									array6[5] = 759876376;
									array6[0] = array5[2] ^ -1534370418;
									array6[4] = array6[1] ^ -729391884;
									array6[5] = array6[1] ^ 0x6BC37F17;
									int num39 = array6[0] ^ -482064234;
									num = (int)((num4 * 571135571) ^ 0xBEB6827Au) ^ num39;
								}
							}
							else
							{
								appActivationArguments = __002D_0040_0024_0028_0040_0021_003D(appInstance);
								int[,] array7 = new int[4, 3];
								array7[0, 0] = 485844381;
								array7[0, 1] = 139029766;
								array7[0, 2] = 1063775362;
								array7[1, 0] = 2044549207;
								array7[1, 1] = 1684632763;
								array7[1, 2] = 642013665;
								array7[2, 0] = 82067425;
								array7[2, 1] = -754624298;
								array7[2, 2] = -1040895811;
								array7[3, 0] = 1092697992;
								array7[3, 1] = 328012495;
								array7[3, 2] = -291796034;
								array7[1, 2] = array7[1, 1] ^ 0x7D03CEB7;
								array7[1, 1] = array7[3, 1] ^ 0x2B986B3B;
								array7[0, 2] = array7[2, 1] ^ -837804371;
								int num40 = array7[0, 2] ^ 0x3884D0DB;
								num = ((int)num4 * -1132857933) ^ -1650656459 ^ num40;
							}
						}
						else
						{
							appInstance = _0024_003D_0024_0028_002B_0024_0021_005E();
							int[] array8 = new int[6];
							array8[0] = -1783141217;
							array8[1] = -2029621225;
							array8[2] = -2103473328;
							array8[3] = 2042942258;
							array8[4] = 1030990436;
							array8[5] = -119029223;
							array8[5] = array8[2] ^ -172658507;
							array8[5] = array8[0] ^ 0x38A73A4C;
							int[] array9 = new int[7];
							array9[0] = 2082494919;
							array9[1] = 531777893;
							array9[2] = -12286965;
							array9[3] = -2093008266;
							array9[4] = 829251631;
							array9[5] = -104616726;
							array9[6] = -2047326342;
							array9[1] = array8[4] ^ -1567669448;
							array9[4] = array9[5] ^ -130043223;
							array9[0] = array9[5] ^ 0x657FB338;
							int num41 = array9[1] ^ 0x2629A20B;
							num = (int)((num4 * 583782626) ^ 0x67BA746C) ^ num41;
						}
					}
					else
					{
						TbG_003D = aAd_003D();
						int[,] array10 = new int[3, 4];
						array10[0, 0] = -1147746206;
						array10[0, 1] = -1982875107;
						array10[0, 2] = 1464455640;
						array10[0, 3] = 1126195537;
						array10[1, 0] = 1288026665;
						array10[1, 1] = -714005363;
						array10[1, 2] = -213416743;
						array10[1, 3] = -1015661000;
						array10[2, 0] = 2145872592;
						array10[2, 1] = -258697752;
						array10[2, 2] = 842359227;
						array10[2, 3] = -648862554;
						array10[1, 2] = array10[1, 3] ^ -1356954059;
						array10[1, 1] = array10[1, 2] ^ -2093075321;
						array10[2, 1] = array10[2, 3] ^ -667723067;
						int num42 = array10[2, 1] ^ -1355640437;
						num = (int)((num4 * 1277897793) ^ 0x31EEE63C) ^ num42;
					}
				}
				else
				{
					vjV_003D();
					int[,] array11 = new int[4, 4];
					array11[0, 0] = 505508395;
					array11[0, 1] = 1170768711;
					array11[0, 2] = -1390633517;
					array11[0, 3] = -1433877681;
					array11[1, 0] = -199973799;
					array11[1, 1] = -1375760062;
					array11[1, 2] = 1153211200;
					array11[1, 3] = 895983996;
					array11[2, 0] = 1853410867;
					array11[2, 1] = 969327116;
					array11[2, 2] = 40697311;
					array11[2, 3] = -1180401093;
					array11[3, 0] = -910409448;
					array11[3, 1] = -918258521;
					array11[3, 2] = -1235577537;
					array11[3, 3] = -117499622;
					array11[2, 0] = array11[1, 3] ^ 0x3FAF2930;
					array11[0, 3] = array11[1, 1] ^ -1530206441;
					array11[2, 3] = array11[1, 0] ^ 0x334DB70E;
					array11[2, 3] = array11[2, 2] ^ -2001580984;
					int num43 = array11[2, 3] ^ -1782903627;
					num = (int)((num4 * 1450659849) ^ 0x93BBCBF8u) ^ num43;
				}
			}
		}
	}

	public static bool rSb_003D(out string? Qqg_003D)
	{
		Qqg_003D = fJa_003D;
		while (true)
		{
			int num = -32789380;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~-758969371 - ~(num2 ^ ~(652635769 * -(-1730597922 - (-811818895 + 519019764 - (1208146438 - -2008740526) - (-1237844568 - 621662791 - ~871455597) + 1073672201 * ~(1602713080 + 1307876066))) * 1487992637)) * -1840076337 * 1644756229)) % 6;
				int num5 = 683167772;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = (num5 ^ 0x6196647) + -388613861;
					num5 = ~num5 * 1914774053;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -5;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 = -num7;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 268434688;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = (num9 ^ -1402985566) + -999709055;
						num9 = -num9;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -1982845877;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = (num11 ^ -1656580085) * -558219565;
							num11 = -(num11 + 1814665103 * -612001369);
						}
						if (num3 == (uint)num11)
						{
							return false;
						}
						int num13 = -1311690906;
						_ = 0;
						for (int num14 = 0; num14 < 2; num14++)
						{
							num13 = num13 * 876254897 - 1398668541;
							num13 = (num13 ^ -281900004) * -1552456815;
						}
						if (num3 != (uint)num13)
						{
							int num15 = 891946555;
							_ = 0;
							for (int num16 = 0; num16 < 2; num16++)
							{
								num15 = -1549292172 - (num15 - --315330733);
								num15 = ~num15 - 1679934715;
							}
							if (num3 != (uint)num15)
							{
							}
							return true;
						}
						fJa_003D = null;
						num = 419007282;
					}
					else
					{
						Qqg_003D = null;
						int[,] array = new int[4, 3];
						array[0, 0] = -1271747891;
						array[0, 1] = -720881128;
						array[0, 2] = -583910;
						array[1, 0] = -574527290;
						array[1, 1] = 1368803620;
						array[1, 2] = 1372772524;
						array[2, 0] = 1472222557;
						array[2, 1] = -1852902106;
						array[2, 2] = -458622959;
						array[3, 0] = -1955402136;
						array[3, 1] = 580968987;
						array[3, 2] = 761760746;
						array[3, 2] = array[2, 1] ^ 0x1DCC7A;
						array[0, 2] = array[2, 1] ^ 0x3C5A6B9B;
						array[1, 1] = array[1, 2] ^ 0x713B2EF0;
						array[1, 1] = array[1, 0] ^ 0x571DD02A;
						int num17 = array[1, 1] ^ 0x21B33DE6;
						num = ((int)num4 * -1709723135) ^ 0x55AD471E ^ num17;
					}
				}
				else
				{
					bool num18 = _0025_0023_002F_0040_002A_0023_003C_0024(Qqg_003D);
					int[] array2 = new int[7];
					array2[0] = -403239365;
					array2[1] = 987169731;
					array2[2] = 1644622068;
					array2[3] = 1334544368;
					array2[4] = 1255313271;
					array2[5] = -1864554454;
					array2[6] = 1466516505;
					array2[6] = array2[2] ^ -1629120826;
					array2[0] = array2[5] ^ -549920825;
					array2[6] = array2[2] ^ -108811670;
					int[] array3 = new int[7];
					array3[0] = -1042062633;
					array3[1] = -1882694906;
					array3[2] = 1995110201;
					array3[3] = -1046473453;
					array3[4] = -1956080675;
					array3[5] = 1347878243;
					array3[6] = 898816799;
					array3[1] = array2[4] ^ -181459432;
					array3[4] = array3[0] ^ -17032120;
					array3[3] ^= -1059078796;
					int num19 = array3[1] ^ -1479789566;
					int[] array4 = new int[7];
					array4[0] = -188498900;
					array4[1] = -1057460963;
					array4[2] = -310451632;
					array4[3] = 317098125;
					array4[4] = 365234124;
					array4[5] = -2093346769;
					array4[6] = 1448282580;
					array4[0] = array4[2] ^ 0x16280B0C;
					array4[3] ^= -1473013227;
					array4[4] = array4[3] ^ 0x5C6CA660;
					int[] array5 = new int[5];
					array5[0] = 1232496957;
					array5[1] = -979356208;
					array5[2] = 1719697953;
					array5[3] = 1034038775;
					array5[4] = -902875945;
					array5[0] = array4[1] ^ 0x7F1883CE;
					array5[4] = array5[3] ^ -1572451793;
					array5[2] ^= -1549420148;
					int num20 = array5[0] ^ 0x45B140C2;
					int num21 = ((int)num4 * -308624890) ^ -1051349974;
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

	protected override void OnLaunched(Microsoft.UI.Xaml.LaunchActivatedEventArgs tqa_003D)
	{
		if (ZwQ_003D)
		{
			goto IL_000e;
		}
		goto IL_0528;
		IL_000e:
		int num = 173582757;
		goto IL_0013;
		IL_0013:
		eie_003D eie_003D2 = default(eie_003D);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)(~((-(-(-(num2 ^ (-(2010578368 - -(~(-(635740327 - 99811391 - 1104268445 * 567680123))) - (813680358 - -1448165647 * ~(-34986350 + -1638387860 - 1453878377 * 914047277) + -((-439527837 ^ (-1437042822 ^ -851281605)) - (-(-1203428768 + -2118129861) + (1366804907 - --2111891911))))) * 882008603)) * 438820209) ^ ~(~(265186107 * 1540137714) - (--1258601071 ^ (1582293607 * -41089036))) ^ ~(--1515955099 + -1994098110 + ~1251671964 * 99935441)) - 483218512 * 1358702857 * 1157202969) ^ -499697340))) % 10;
			int num5 = -469380590;
			_ = 0;
			for (int num6 = 0; num6 < 2; num6++)
			{
				num5 = ~(num5 + (2015847848 + 386774351));
				num5 ^= -222041109;
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = 7;
			_ = 0;
			for (int num8 = 0; num8 < 2; num8++)
			{
				num7 = num7 + (1754595287 + -1530231728) - 2137514966;
				num7 = -num7;
			}
			if (num3 == (uint)num7)
			{
				return;
			}
			int num9 = -1776108311;
			_ = 0;
			for (int num10 = 0; num10 < 1; num10++)
			{
				num9 += 1776108319;
			}
			if (num3 != (uint)num9)
			{
				int num11 = -1449980208;
				_ = 0;
				for (int num12 = 0; num12 < 2; num12++)
				{
					num11 = num11 + (0x5CCA51A ^ -1893588576) - 1677000478;
					num11 = num11 - (-1272083935 + 1797097575) + -1551366777;
				}
				if (num3 != (uint)num11)
				{
					int num13 = 191341973;
					_ = 0;
					for (int num14 = 0; num14 < 1; num14++)
					{
						num13 ^= 0xB67A597;
					}
					if (num3 != (uint)num13)
					{
						int num15 = -37716993;
						_ = 0;
						for (int num16 = 0; num16 < 1; num16++)
						{
							num15 *= 103777279;
						}
						if (num3 != (uint)num15)
						{
							int num17 = 218095917;
							_ = 0;
							for (int num18 = 0; num18 < 2; num18++)
							{
								num17 = (num17 - (-726463718 ^ -1851945381)) ^ -1185724855;
								num17 = -1230007571 - -num17;
							}
							if (num3 != (uint)num17)
							{
								int num19 = -1878016499;
								_ = 0;
								for (int num20 = 0; num20 < 2; num20++)
								{
									num19 = (num19 ^ -107420923) + 1302342718;
									num19 = -num19 + 24860984;
								}
								if (num3 == (uint)num19)
								{
									return;
								}
								int num21 = 1414881725;
								_ = 0;
								for (int num22 = 0; num22 < 1; num22++)
								{
									num21 *= -40702403;
								}
								if (num3 != (uint)num21)
								{
									int num23 = -113051132;
									_ = 0;
									for (int num24 = 0; num24 < 2; num24++)
									{
										num23 = num23 * 1081504311 - 706185574;
										num23 = num23 + -2109190732 + 326676506;
									}
									if (num3 == (uint)num23)
									{
									}
									return;
								}
								_0026_003F_0021_002F_005E_0024_0028_0028(Yrv_003D);
								num = -202968264;
							}
							else
							{
								eie_003D2.xHA_003D();
								int[] array = new int[5] { 963206919, 1282668484, 926998214, 227362285, -1578013000 };
								array[1] ^= 549010417;
								array[4] ^= -1910106670;
								array[3] = array[1] ^ -1606881318;
								int[] array2 = new int[6];
								array2[0] = 1514575421;
								array2[1] = 1973211318;
								array2[2] = -1673595493;
								array2[3] = -201353994;
								array2[4] = 1151397640;
								array2[5] = 622219613;
								array2[2] = array[0] ^ -2027889049;
								array2[5] = array2[4] ^ -1796842321;
								array2[3] = array2[5] ^ -1448042457;
								array2[0] = array2[1] ^ -1991785717;
								int num25 = array2[2] ^ -1805747565;
								num = (int)((num4 * 6483141) ^ 0xB84D95E9u) ^ num25;
							}
						}
						else
						{
							eie_003D obj = eie_003D2;
							int[,] array3 = new int[4, 3];
							array3[0, 0] = 1357194512;
							array3[0, 1] = -210491950;
							array3[0, 2] = 2014415118;
							array3[1, 0] = 623892227;
							array3[1, 1] = 1994993618;
							array3[1, 2] = 1674080964;
							array3[2, 0] = -1640084338;
							array3[2, 1] = -1306332993;
							array3[2, 2] = -590485954;
							array3[3, 0] = 1561273776;
							array3[3, 1] = 2134198845;
							array3[3, 2] = 55849658;
							array3[2, 0] = array3[1, 0] ^ -542211017;
							array3[2, 1] = array3[1, 1] ^ -2133683974;
							array3[3, 0] = array3[0, 0] ^ 0x2A24AC14;
							array3[2, 0] = array3[2, 2] ^ 0x3ADB5F9E;
							int num26 = array3[2, 0] ^ -1073648227;
							int[] array4 = new int[7] { 638683696, -565143009, 1662367792, -101973095, 1164210718, -176001217, 536297844 };
							array4[5] ^= 59218571;
							array4[3] ^= 720337704;
							int[] array5 = new int[7];
							array5[0] = 132435657;
							array5[1] = -380923411;
							array5[2] = 270536268;
							array5[3] = 665045625;
							array5[4] = 1661888141;
							array5[5] = -1340418004;
							array5[6] = -1140895631;
							array5[5] = array4[1] ^ -1016472538;
							array5[3] = array5[4] ^ -1985380347;
							array5[6] = array5[3] ^ -1547222421;
							array5[6] = array5[1] ^ 0x38683C38;
							int num27 = array5[5] ^ 0x28A133D8;
							int num28 = ((int)num4 * -777512342) ^ -671191210;
							num26 ^= num28;
							num27 ^= num28;
							int num29;
							int num30;
							if ((object)obj != null)
							{
								num29 = num27;
								num30 = num29;
							}
							else
							{
								num29 = num26;
								num30 = num29;
							}
							num = num29 ^ num28;
						}
					}
					else
					{
						eie_003D2 = Yrv_003D as eie_003D;
						num = -568816753;
					}
				}
				else
				{
					Yrv_003D = TbG_003D.GetRequiredService<eie_003D>();
					int[] array6 = new int[6] { 1076003259, 316195314, 268845694, -1371325037, -1779205187, 1941423944 };
					array6[3] ^= 869318622;
					array6[1] ^= -2014065964;
					array6[3] = array6[4] ^ 0x52BDF2CC;
					int[] array7 = new int[6] { -1012407015, 1019751241, 136660650, 1511942797, -1493520652, 2098456607 };
					int[][] array8 = new int[2][] { array6, array7 };
					array7[0] = array8[0][5] ^ 0x1A1E43CB;
					array7[5] = array7[3] ^ -2117605185;
					array7[5] = array7[0] ^ 0xCB50AFE;
					int num31 = array8[1][0] ^ -1497617993;
					num = ((int)num4 * -1587696424) ^ 0x4FD09B0 ^ num31;
				}
				continue;
			}
			goto IL_0528;
		}
		goto IL_000e;
		IL_0528:
		int num32;
		if ((object)Yrv_003D == null)
		{
			num = 1960446436;
			num32 = num;
		}
		else
		{
			num = -820662988;
			num32 = num;
		}
		goto IL_0013;
	}

	private static IServiceProvider aAd_003D()
	{
		ServiceCollection serviceCollection = new ServiceCollection();
		serviceCollection.AddSingleton<wgc_003D>();
		serviceCollection.AddSingleton<ISettingsStore, yYs_003D>();
		serviceCollection.AddSingleton<IStringResourceService, ijv_003D>();
		serviceCollection.AddSingleton<ILauncherService, Bpe_003D>();
		serviceCollection.AddSingleton<IFilePickerService, irS_003D>();
		serviceCollection.AddSingleton<Dhr_003D>();
		((IServiceCollection)serviceCollection).AddSingleton((Func<IServiceProvider, IAuthenticationService>)((IServiceProvider provider) => provider.GetRequiredService<Dhr_003D>()));
		serviceCollection.AddSingleton<IAssemblyWorkspaceService, cma_003D>();
		serviceCollection.AddSingleton<IProtectionService, sEp_003D>();
		serviceCollection.AddSingleton<AppViewModel>();
		serviceCollection.AddSingleton<LoginViewModel>();
		serviceCollection.AddSingleton<WorkspaceViewModel>();
		serviceCollection.AddSingleton<MethodsViewModel>();
		serviceCollection.AddSingleton<SettingsViewModel>();
		serviceCollection.AddSingleton<eie_003D>();
		return _002A_0029_0028_005E_0025_002A_003F_0024((IServiceCollection)serviceCollection);
	}

	private static void yJf_003D(object? MSA_003D, AppActivationArguments lFr_003D)
	{
		_003C_003Ec__DisplayClass14_0 CS_0024_003C_003E8__locals4 = new _003C_003Ec__DisplayClass14_0();
		Window mainWindowInstance = default(Window);
		while (true)
		{
			int num = 1460872722;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(~(-(~(-(-(num2 + ((~-1901940778 - (~(1790651349 * -2079980469 + ((-809218195 ^ 0x7F9515E9) - (17965382 + -31915285 - (1110103 + -336100389))) + -(-1618016558 - (-1727932936 ^ 0x13C2C57B))) ^ (-1055081798 ^ -(~(~-88458243 + --1467988418) ^ (-(719746166 + 1401347458) ^ 0x3A81C85F))))) ^ -(((-(~(339542113 - -2076050426)) + (-415731065 - -557216164 + (1690206693 - 1264834713) + -(-709875825 * 1725662570))) * 704957397 - -(0x79CA498D ^ ((0x78E88853 ^ -1499272290) * -1030957647))) ^ -(-1919934483 - -1982839483 * -(~-644689236) + -1136920194)))) * -479690133) - -272107556 * -368104071)) ^ 0x767D1C41)))) % 8;
				int num5 = 1835863302;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 += -1835863297;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 23267217;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = num7 - 1554210073 - 1674435212;
					num7 ^= 0x534E5C34;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -525397118;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = num9 + (0x2B3201D4 ^ -540300066) - 1699821260;
						num9 = -(~num9);
					}
					if (num3 != (uint)num9)
					{
						int num11 = 1413646800;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = (num11 * -676541975) ^ -1387577967;
							num11 = -(~num11);
						}
						if (num3 != (uint)num11)
						{
							int num13 = -592362130;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = ~num13 * -1921663959;
								num13 = num13 * -583352691 * 1592405089;
							}
							if (num3 != (uint)num13)
							{
								int num15 = -4;
								_ = 0;
								for (int num16 = 0; num16 < 1; num16++)
								{
									num15 = ~num15;
								}
								if (num3 == (uint)num15)
								{
									return;
								}
								int num17 = -2;
								_ = 0;
								for (int num18 = 0; num18 < 1; num18++)
								{
									num17 = ~num17;
								}
								if (num3 != (uint)num17)
								{
									int num19 = 1563183715;
									_ = 0;
									for (int num20 = 0; num20 < 1; num20++)
									{
										num19 = 1563183721 - num19;
									}
									if (num3 == (uint)num19)
									{
									}
									return;
								}
								_003C_003F__005E_005E_0023_003F_0026(_002B_0024_0023_0021_0029_002B_0029_0026((Window)CS_0024_003C_003E8__locals4.mainWindow), (DispatcherQueueHandler)([AsyncStateMachine(typeof(_003C_003Ec__DisplayClass14_0._003C_003COnAppActivated_003Eb__0_003Ed))] () =>
								{
									_003C_003Ec__DisplayClass14_0._003C_003COnAppActivated_003Eb__0_003Ed stateMachine = default(_003C_003Ec__DisplayClass14_0._003C_003COnAppActivated_003Eb__0_003Ed);
									stateMachine._003C_003Et__builder = _003C_003Ec__DisplayClass14_0._002F_0021_0021_0025_0028_005E_005E_0040();
									while (true)
									{
										int num29 = -1189091813;
										while (true)
										{
											int num30 = num29;
											uint num32;
											uint num31 = (num32 = (uint)((~(-(~(~num30 ^ ((-1586269963 * -1831086947 + (1200728269 * 455648427 - 1233721337 + ~(210354569 + 1843705615) - (1951223655 - ~(0x518F30A1 ^ 0x17BCE585)) + ~(0x69B3E5C6 ^ (-1718888531 ^ --105067017)) - 889215065 * (-504380714 ^ 0x5D1B5AD9))) * -2051668715))) * 438662249) - (-531686211 - (-978390973 + -647968462) + (-201547128 ^ 0x2233829B)) + -(-936529989 + -398454505) + (-20870597 - 1439315074)) ^ -1780630560)) % 5;
											int num33 = 1693395534;
											_ = 0;
											for (int num34 = 0; num34 < 2; num34++)
											{
												num33 = -num33 ^ 0x656A2866;
												num33 = (num33 * 1099893303) ^ 0x46FD53F;
											}
											if (num31 == (uint)num33)
											{
												break;
											}
											int num35 = 1;
											_ = 0;
											for (int num36 = 0; num36 < 2; num36++)
											{
												num35 = num35 + -1861854801 - 1918164970;
												num35 = ~num35;
											}
											if (num31 != (uint)num35)
											{
												int num37 = 2063628266;
												_ = 0;
												for (int num38 = 0; num38 < 1; num38++)
												{
													num37 ^= 0x7B0077EE;
												}
												if (num31 != (uint)num37)
												{
													int num39 = 2;
													_ = 0;
													for (int num40 = 0; num40 < 2; num40++)
													{
														num39 = ~(-num39);
														num39 ^= 0x3CF93550;
													}
													if (num31 != (uint)num39)
													{
														int num41 = 1313365818;
														_ = 0;
														for (int num42 = 0; num42 < 1; num42++)
														{
															num41 ^= 0x4E485F39;
														}
														if (num31 == (uint)num41)
														{
														}
														return;
													}
													stateMachine._003C_003Et__builder.Start(ref stateMachine);
													int[] array13 = new int[4];
													array13[0] = 2056358064;
													array13[1] = 1062940202;
													array13[2] = -534714860;
													array13[3] = 455312862;
													array13[2] = array13[1] ^ 0x689F8FCD;
													array13[1] ^= -1951353519;
													array13[3] = array13[0] ^ 0x5FA5D9BB;
													int[] array14 = new int[7] { -409477160, -1896157214, 374426380, -1482284437, -176901488, 585124338, -579506676 };
													int[][] array15 = new int[2][] { array13, array14 };
													array14[5] = array15[0][0] ^ -1602637302;
													array14[4] ^= -1412684748;
													array14[2] = array14[6] ^ -395140540;
													array14[1] = array14[4] ^ 0x282D050A;
													int num43 = array15[1][5] ^ -421858489;
													num29 = (int)((num32 * 1734720828) ^ 0x4749AD4) ^ num43;
												}
												else
												{
													stateMachine._003C_003E1__state = -1;
													int[] array16 = new int[6];
													array16[0] = -1950254752;
													array16[1] = 1037296049;
													array16[2] = -416731642;
													array16[3] = 1170323098;
													array16[4] = -1090771678;
													array16[5] = -1986259661;
													array16[5] = array16[3] ^ -1048864411;
													array16[1] = array16[3] ^ -888928888;
													int[] array17 = new int[6] { -1320715890, 525443869, -1912188987, -695311262, -1248457665, -1128568295 };
													int[][] array18 = new int[2][] { array16, array17 };
													array17[2] = array18[0][0] ^ 0x6AF0271B;
													array17[5] = array17[0] ^ 0x76BE3580;
													array17[1] = array17[2] ^ 0x1E5A231D;
													int num44 = array18[1][2] ^ -22015245;
													num29 = ((int)num32 * -506887681) ^ 0x5414D5FE ^ num44;
												}
											}
											else
											{
												stateMachine._003C_003E4__this = CS_0024_003C_003E8__locals4;
												int[,] array19 = new int[4, 3];
												array19[0, 0] = -437614745;
												array19[0, 1] = 931654563;
												array19[0, 2] = -1208280739;
												array19[1, 0] = -2121776168;
												array19[1, 1] = -522953410;
												array19[1, 2] = 223446202;
												array19[2, 0] = -797701009;
												array19[2, 1] = -917142142;
												array19[2, 2] = 1252146613;
												array19[3, 0] = 283457480;
												array19[3, 1] = 1544707241;
												array19[3, 2] = -1334919240;
												array19[2, 2] = array19[2, 0] ^ 0x456CFAAA;
												array19[2, 0] = array19[2, 2] ^ -797802567;
												array19[3, 1] = array19[0, 2] ^ -654674926;
												int num45 = array19[3, 1] ^ -1587985880;
												num29 = (int)((num32 * 1557086641) ^ 0xD2A02F86u) ^ num45;
											}
										}
									}
								}));
								num = 329127305;
							}
							else
							{
								eie_003D obj = CS_0024_003C_003E8__locals4.mainWindow;
								int[] array = new int[7];
								array[0] = -2040622387;
								array[1] = 653615169;
								array[2] = -657847455;
								array[3] = -456137730;
								array[4] = 174486053;
								array[5] = 299597626;
								array[6] = -756410247;
								array[3] = array[2] ^ 0x5659B936;
								array[6] = array[5] ^ 0x3CA75BD3;
								array[2] = array[4] ^ -2090953238;
								int[] array2 = new int[4] { 436764828, 2053626838, 359073874, 1925033207 };
								int[][] array3 = new int[2][] { array, array2 };
								array2[0] = array3[0][5] ^ -1727155092;
								array2[3] = array2[1] ^ -2141055975;
								array2[3] = array2[2] ^ 0x6BF2C2AE;
								array2[2] = array2[0] ^ -193108722;
								int num21 = array3[1][0] ^ -1606551914;
								int[] array4 = new int[4] { -1703824353, -1417694170, -1255580409, 1036883411 };
								array4[1] ^= 1699032425;
								array4[0] ^= 8494274;
								array4[3] = array4[2] ^ 0x450F23C7;
								int[] array5 = new int[6] { -877762944, -665717954, -2020938913, -1139681307, 1253150293, -2105423842 };
								int[][] array6 = new int[2][] { array4, array5 };
								array5[4] = array6[0][2] ^ -2042004795;
								array5[3] = array5[4] ^ -1667029939;
								array5[5] ^= 235035478;
								array5[0] = array5[3] ^ 0x52F7D70A;
								int num22 = array6[1][4] ^ 0x4359CD9C;
								int num23 = ((int)num4 * -1481905511) ^ -542504054;
								num21 ^= num23;
								num22 ^= num23;
								int num24;
								int num25;
								if ((object)obj == null)
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
						else
						{
							CS_0024_003C_003E8__locals4.mainWindow = mainWindowInstance as eie_003D;
							int[] array7 = new int[7];
							array7[0] = 1822242274;
							array7[1] = -856224509;
							array7[2] = -1431108548;
							array7[3] = -197506676;
							array7[4] = 1924828330;
							array7[5] = 1251568974;
							array7[6] = 2105590196;
							array7[6] = array7[5] ^ -1026627915;
							array7[3] = array7[5] ^ 0x7A6BC54D;
							int[] array8 = new int[4];
							array8[0] = 2011609827;
							array8[1] = 215744814;
							array8[2] = -293077160;
							array8[3] = 1602055610;
							array8[0] = array7[4] ^ 0x1BE15670;
							array8[3] = array8[0] ^ -1335699003;
							array8[2] ^= -630955296;
							array8[3] = array8[1] ^ 0x4E6B186;
							int num26 = array8[0] ^ -2137539025;
							num = (int)((num4 * 2028441253) ^ 0xF4C9256Cu) ^ num26;
						}
					}
					else
					{
						mainWindowInstance = Yrv_003D;
						int[,] array9 = new int[3, 4];
						array9[0, 0] = 82070902;
						array9[0, 1] = 641856130;
						array9[0, 2] = -34649404;
						array9[0, 3] = -1875618502;
						array9[1, 0] = 639587046;
						array9[1, 1] = -591371882;
						array9[1, 2] = 829021361;
						array9[1, 3] = -1421163030;
						array9[2, 0] = 547599780;
						array9[2, 1] = 531322426;
						array9[2, 2] = 1945229394;
						array9[2, 3] = 1033938769;
						array9[2, 0] = array9[0, 1] ^ -731785951;
						array9[2, 3] = array9[1, 0] ^ 0x1B38D0C1;
						array9[0, 2] ^= 617499052;
						array9[2, 3] = array9[1, 1] ^ 0x4C9E8878;
						int num27 = array9[2, 3] ^ -261740939;
						num = ((int)num4 * -19614752) ^ -753741824 ^ num27;
					}
				}
				else
				{
					aPe_003D(lFr_003D);
					int[] array10 = new int[7] { -1574694595, -1840240430, 1685188152, -540198706, 1219630717, -1139391900, -2061173130 };
					array10[4] ^= -1582156562;
					array10[6] = array10[1] ^ -1379178987;
					int[] array11 = new int[4] { 251976492, -1683987395, 1555696060, 1441300204 };
					int[][] array12 = new int[2][] { array10, array11 };
					array11[1] = array12[0][2] ^ 0x4F9B9AF7;
					array11[0] = array11[2] ^ 0xFFE47EC;
					array11[2] ^= 1096396583;
					int num28 = array12[1][1] ^ -1827542552;
					num = ((int)num4 * -645920571) ^ -1558835373 ^ num28;
				}
			}
		}
	}

	[AsyncStateMachine(typeof(_003CRedirectActivationToAsync_003Ed__15))]
	private static Task zFd_003D(AppInstance rrF_003D, AppActivationArguments zYf_003D)
	{
		_003CRedirectActivationToAsync_003Ed__15 stateMachine = default(_003CRedirectActivationToAsync_003Ed__15);
		stateMachine._003C_003Et__builder = _002F_002F_002A_002D_0040_0024_0024_0025();
		while (true)
		{
			int num = 2144615218;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(~(num2 + -(-553275147 * (-(-66524267 * 698419342 * 670144613 + (((-1314757895 ^ -1147566978) - -2067373549) ^ -(--1219364756 - -1778671995))) - 137661851))) * -1763596295))) % 6;
				int num5 = 2112885844;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 += -2112885840;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 45803545;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = (num7 - ~-2119308900) * 1220136937;
					num7 = -673807462 - (num7 - (0x5CA342AB ^ -1835281777));
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1669332493;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = (num9 ^ -674548972) + -552125630;
						num9 = ~num9 - -1301006334;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 820362629;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 *= -1687152153;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -275050384;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 -= ~-1074385723;
								num13 = ~(935572732 - num13);
							}
							if (num3 != (uint)num13)
							{
								int num15 = -1427699598;
								_ = 0;
								for (int num16 = 0; num16 < 2; num16++)
								{
									num15 = ~(num15 - --994895011);
									num15 = -1492282846 - (num15 - 659543887 * 30399369);
								}
								if (num3 != (uint)num15)
								{
								}
								return stateMachine._003C_003Et__builder.Task;
							}
							stateMachine._003C_003Et__builder.Start(ref stateMachine);
							int[] array = new int[6];
							array[0] = -502273467;
							array[1] = 799003912;
							array[2] = 165874909;
							array[3] = -941392937;
							array[4] = -1704487783;
							array[5] = 2038748594;
							array[2] = array[4] ^ -1877457712;
							array[0] = array[2] ^ 0x2479D752;
							int[] array2 = new int[4];
							array2[0] = -149969196;
							array2[1] = -1487870367;
							array2[2] = -224031630;
							array2[3] = 217353681;
							array2[2] = array[3] ^ 0x7107ED45;
							array2[0] = array2[1] ^ -1904188293;
							array2[0] = array2[2] ^ 0xF78AC4F;
							array2[1] = array2[2] ^ 0x42F9C4D;
							int num17 = array2[2] ^ 0x2F0D6925;
							num = ((int)num4 * -1550038283) ^ 0x2AE2339E ^ num17;
						}
						else
						{
							stateMachine._003C_003E1__state = -1;
							int[] array3 = new int[7];
							array3[0] = -206538247;
							array3[1] = 1632281409;
							array3[2] = -509359060;
							array3[3] = 1150178834;
							array3[4] = 1311170019;
							array3[5] = -905383295;
							array3[6] = 1200073988;
							array3[1] = array3[3] ^ 0x34D957A0;
							array3[4] = array3[5] ^ -19183393;
							int[] array4 = new int[6];
							array4[0] = -1019785547;
							array4[1] = 1249440632;
							array4[2] = 1519391354;
							array4[3] = -1836449406;
							array4[4] = -1459155602;
							array4[5] = 165398227;
							array4[2] = array3[5] ^ -1815641750;
							array4[3] = array4[0] ^ -1876481042;
							array4[1] ^= 253071468;
							int num18 = array4[2] ^ -1300871884;
							num = (int)((num4 * 703519055) ^ 0xC4396D93u) ^ num18;
						}
					}
					else
					{
						stateMachine.activationArguments = zYf_003D;
						int[] array5 = new int[7];
						array5[0] = -14384163;
						array5[1] = 1505372870;
						array5[2] = -1923139204;
						array5[3] = -1776836153;
						array5[4] = -1673833146;
						array5[5] = 773175918;
						array5[6] = 1691553839;
						array5[3] = array5[6] ^ -1457258065;
						array5[5] ^= -596062842;
						array5[2] = array5[4] ^ -1755202494;
						int[] array6 = new int[7] { 568932206, -1117333537, 999636248, 2138529421, 1585907299, -103471297, 679139865 };
						int[][] array7 = new int[2][] { array5, array6 };
						array6[1] = array7[0][6] ^ 0x285E9197;
						array6[4] ^= 609081569;
						array6[4] = array6[3] ^ 0x6CE7AC75;
						int num19 = array7[1][1] ^ -515992874;
						num = (int)((num4 * 1523249967) ^ 0xEEE5FECBu) ^ num19;
					}
				}
				else
				{
					stateMachine.keyInstance = rrF_003D;
					int[,] array8 = new int[4, 4];
					array8[0, 0] = -182552349;
					array8[0, 1] = -1603405712;
					array8[0, 2] = -1808850716;
					array8[0, 3] = -210341816;
					array8[1, 0] = 1266053469;
					array8[1, 1] = -1280123715;
					array8[1, 2] = -1858472973;
					array8[1, 3] = -913757282;
					array8[2, 0] = 231199778;
					array8[2, 1] = 963045139;
					array8[2, 2] = -1388779442;
					array8[2, 3] = -1104065908;
					array8[3, 0] = 1959365241;
					array8[3, 1] = 933711398;
					array8[3, 2] = 24078211;
					array8[3, 3] = -1829878672;
					array8[0, 2] = array8[3, 1] ^ 0x6AB5D8A5;
					array8[0, 2] = array8[2, 1] ^ -2011073480;
					array8[2, 1] = array8[2, 2] ^ 0xA5AA818;
					array8[1, 0] = array8[2, 0] ^ 0x3AEA2B21;
					int num20 = array8[1, 0] ^ 0x4C128455;
					num = (int)((num4 * 66544984) ^ 0x58885058) ^ num20;
				}
			}
		}
	}

	private static void aPe_003D(AppActivationArguments VTs_003D)
	{
		string text = mgE_003D(VTs_003D);
		while (true)
		{
			int num = 1896813852;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(~(-(-(-(-(-(-num2))) ^ (2095163861 * (-(-1137864767 + -1615393756) - -(-2003956725 ^ 0x1E7315B6) + ~(-(-805295523 + 1677120694)))))))) ^ -1862669259)) % 4;
				int num5 = 1581056120;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 ^= 0x5E3D007A;
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
					int num9 = 2035713206;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = (num9 + 305570330) ^ -1164766976;
						num9 = 554441354 - ~num9;
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
					fJa_003D = text;
					int[] array = new int[7];
					array[0] = -519970493;
					array[1] = 9828705;
					array[2] = -1744351902;
					array[3] = 1467604410;
					array[4] = -1887771645;
					array[5] = 2082224167;
					array[6] = -206921071;
					array[0] = array[1] ^ 0x7236C7EE;
					array[1] ^= 1326142776;
					array[5] = array[4] ^ 0x319299B1;
					int[] array2 = new int[7];
					array2[0] = 1768046495;
					array2[1] = -1492278145;
					array2[2] = -1256149566;
					array2[3] = -83431352;
					array2[4] = 802840111;
					array2[5] = 479687577;
					array2[6] = 518304991;
					array2[5] = array[3] ^ 0x274B9018;
					array2[0] = array2[6] ^ 0x20522C1E;
					array2[2] = array2[5] ^ 0x1EFB6170;
					int num13 = array2[5] ^ 0x6D414E7C;
					num = (int)((num4 * 1918598782) ^ 0x4AA97540) ^ num13;
					continue;
				}
				bool num14 = _0025_0023_002F_0040_002A_0023_003C_0024(text);
				int[] array3 = new int[6];
				array3[0] = -1141839294;
				array3[1] = -607555218;
				array3[2] = -543194969;
				array3[3] = 643268641;
				array3[4] = -703637546;
				array3[5] = -2122974050;
				array3[5] = array3[0] ^ 0x7004779D;
				array3[5] = array3[2] ^ -910687296;
				array3[2] = array3[5] ^ -240392823;
				int[] array4 = new int[4];
				array4[0] = -495362193;
				array4[1] = 1751286467;
				array4[2] = -1309029422;
				array4[3] = 1994769165;
				array4[2] = array3[4] ^ 0x3A97DC15;
				array4[1] = array4[2] ^ 0x7462AF94;
				array4[3] = array4[2] ^ 0x3A30B0AE;
				array4[3] = array4[2] ^ -1291362910;
				int num15 = array4[2] ^ -236222435;
				int[] array5 = new int[6];
				array5[0] = -1269149861;
				array5[1] = 226009339;
				array5[2] = 2013230763;
				array5[3] = 990173260;
				array5[4] = 1549970927;
				array5[5] = -1423295583;
				array5[3] = array5[5] ^ -1725291255;
				array5[3] ^= 535630792;
				array5[0] = array5[4] ^ -718034593;
				int[] array6 = new int[4] { 337488328, 1144624376, -1417536110, -40490578 };
				int[][] array7 = new int[2][] { array5, array6 };
				array6[0] = array7[0][5] ^ -122065625;
				array6[1] = array6[3] ^ 0x8BB94D2;
				array6[3] = array6[1] ^ -1780197917;
				array6[3] = array6[1] ^ 0x55CF9F09;
				int num16 = array7[1][0] ^ 0x76CCEF61;
				int num17 = (int)((num4 * 839559446) ^ 0x1447D652);
				num15 ^= num17;
				num16 ^= num17;
				int num18;
				int num19;
				if (!num14)
				{
					num18 = num16;
					num19 = num18;
				}
				else
				{
					num18 = num15;
					num19 = num18;
				}
				num = num18 ^ num17;
			}
		}
	}

	private static string? mgE_003D(AppActivationArguments Ifh_003D)
	{
		if (_002B_002D_003F_003F_003C_002B_0026_002F(Ifh_003D) == ExtendedActivationKind.File)
		{
			goto IL_0013;
		}
		goto IL_145b;
		IL_0013:
		int num = -1456856336;
		goto IL_0018;
		IL_0018:
		ILaunchActivatedEventArgs e = default(ILaunchActivatedEventArgs);
		string result = default(string);
		string current = default(string);
		StorageFile storageFile = default(StorageFile);
		IFileActivatedEventArgs e2 = default(IFileActivatedEventArgs);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)(-(-(-(-(num2 ^ ((-(-(~(~-1627438737))) + ~((-1818555216 ^ (2053061409 * (-142039652 - -767741268 + -1595863623))) + -572537678 - (-(0x7454C1D6 ^ 0x52436B40) + -(983901196 - -2112476994 + (0xE21D9E7 ^ 0x71F05051)) - 1969581026))) ^ ((-1046280911 ^ 0x51226AF8) + -2111048803 - (~(0x758E1ACE ^ (-2055796044 + 293200877 - 725038220 + -(--139054366) - ((0x7B0B3B3 ^ 0x3FB417B1) + ~(453424028 + 1178951204)))) - -(~1383943231)))))) * 843024939) - --1523444313) * -401139789)) % 13;
			uint num5 = num3;
			int num6 = -8;
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
			int num9 = 8;
			_ = 0;
			for (int num10 = 0; num10 < 2; num10++)
			{
				num9 = ~num9 ^ 0x59D618A1;
				num9 ^= -1705724974;
			}
			if (num8 != (uint)num9)
			{
				uint num11 = num3;
				int num12 = -847190046;
				_ = 0;
				for (int num13 = 0; num13 < 2; num13++)
				{
					num12 -= -1368189827 ^ -1662129875;
					num12 = num12 + ~-1377304791 - -2043054218;
				}
				if (num11 != (uint)num12)
				{
					uint num14 = num3;
					int num15 = 1496122280;
					_ = 0;
					for (int num16 = 0; num16 < 2; num16++)
					{
						num15 = num15 * -160080801 - -2078644854;
						num15 = num15 * 1532859085 - 217482441;
					}
					if (num14 != (uint)num15)
					{
						uint num17 = num3;
						int num18 = 285780954;
						_ = 0;
						for (int num19 = 0; num19 < 1; num19++)
						{
							num18 *= -864686161;
						}
						object yMF_003D;
						if (num17 != (uint)num18)
						{
							uint num20 = num3;
							int num21 = 1829718127;
							_ = 0;
							for (int num22 = 0; num22 < 1; num22++)
							{
								num21 ^= 0x6D0F486E;
							}
							if (num20 != (uint)num21)
							{
								uint num23 = num3;
								int num24 = 2003271304;
								_ = 0;
								for (int num25 = 0; num25 < 1; num25++)
								{
									num24 -= 2003271295;
								}
								if (num23 != (uint)num24)
								{
									uint num26 = num3;
									int num27 = 872814767;
									_ = 0;
									for (int num28 = 0; num28 < 2; num28++)
									{
										num27 -= --1209603048;
										num27 = num27 - 50832907 - -824028573;
									}
									if (num26 != (uint)num27)
									{
										uint num29 = num3;
										int num30 = 10;
										_ = 0;
										for (int num31 = 0; num31 < 2; num31++)
										{
											num30 = -(-num30);
											num30 = 2120106921 - (num30 + ~-1339861853);
										}
										if (num29 != (uint)num30)
										{
											uint num32 = num3;
											int num33 = 0;
											_ = 0;
											for (int num34 = 0; num34 < 1; num34++)
											{
												num33 = -num33;
											}
											if (num32 != (uint)num33)
											{
												uint num35 = num3;
												int num36 = -5;
												_ = 0;
												for (int num37 = 0; num37 < 1; num37++)
												{
													num36 = -num36;
												}
												if (num35 == (uint)num36)
												{
													goto IL_145b;
												}
												uint num38 = num3;
												int num39 = -11;
												_ = 0;
												for (int num40 = 0; num40 < 1; num40++)
												{
													num39 = -num39;
												}
												if (num38 != (uint)num39)
												{
													uint num41 = num3;
													int num42 = -5;
													_ = 0;
													for (int num43 = 0; num43 < 1; num43++)
													{
														num42 = ~num42;
													}
													if (num41 != (uint)num42)
													{
													}
													IEnumerator<string> enumerator = srG_003D(_0021_005E_0029_002F_003E_003D_002B_0024(e)).GetEnumerator();
													try
													{
														uint num68;
														int num69;
														do
														{
															int num44;
															int num45;
															if (!__002D_002A_002B___003E_0040((IEnumerator)enumerator))
															{
																num44 = 860099742;
																num45 = num44;
															}
															else
															{
																num44 = 553192497;
																num45 = num44;
															}
															while (true)
															{
																num2 = num44;
																num3 = (num4 = (uint)(-(-(-(-(num2 ^ ((-(-(~(~-1627438737))) + ~((-1818555216 ^ (2053061409 * (-142039652 - -767741268 + -1595863623))) + -572537678 - (-(0x7454C1D6 ^ 0x52436B40) + -(983901196 - -2112476994 + (0xE21D9E7 ^ 0x71F05051)) - 1969581026))) ^ ((-1046280911 ^ 0x51226AF8) + -2111048803 - (~(0x758E1ACE ^ (-2055796044 + 293200877 - 725038220 + -(--139054366) - ((0x7B0B3B3 ^ 0x3FB417B1) + ~(453424028 + 1178951204)))) - -(~1383943231)))))) * 843024939) - --1523444313) * -401139789)) % 7;
																uint num46 = num3;
																int num47 = 620830395;
																_ = 0;
																for (int num48 = 0; num48 < 2; num48++)
																{
																	num47 = ~(-num47);
																	num47 = num47 * -1499975151 + 2096498917;
																}
																if (num46 == (uint)num47)
																{
																	num44 = 553192497;
																	continue;
																}
																uint num49 = num3;
																int num50 = -1440034071;
																_ = 0;
																for (int num51 = 0; num51 < 2; num51++)
																{
																	num50 = ~(num50 * 27191155);
																	num50 = 1480777523 - (num50 ^ -19302224);
																}
																if (num49 != (uint)num50)
																{
																	uint num52 = num3;
																	int num53 = -5;
																	_ = 0;
																	for (int num54 = 0; num54 < 1; num54++)
																	{
																		num53 = -num53;
																	}
																	if (num52 != (uint)num53)
																	{
																		uint num55 = num3;
																		int num56 = -1;
																		_ = 0;
																		for (int num57 = 0; num57 < 1; num57++)
																		{
																			num56 = ~num56;
																		}
																		if (num55 != (uint)num56)
																		{
																			break;
																		}
																		result = current;
																		int[] array = new int[6];
																		array[0] = -1605521233;
																		array[1] = -1396892049;
																		array[2] = -230682207;
																		array[3] = 670842447;
																		array[4] = 1991484762;
																		array[5] = -1607754831;
																		array[2] = array[5] ^ 0x5F30BB2F;
																		array[1] ^= 748163966;
																		int[] array2 = new int[5] { -380913292, 969133554, 1238988956, -532265400, 2146780732 };
																		int[][] array3 = new int[2][] { array, array2 };
																		array2[1] = array3[0][4] ^ -1417450136;
																		array2[0] = array2[4] ^ 0x4C9507F4;
																		array2[0] = array2[1] ^ 0x4C031E1E;
																		array2[3] ^= 444888860;
																		int num58 = array3[1][1] ^ -2130558693;
																		num44 = ((int)num4 * -1180037574) ^ 0x1605F4F2 ^ num58;
																		continue;
																	}
																	bool num59 = diZ_003D(current);
																	int[] array4 = new int[6];
																	array4[0] = -765057534;
																	array4[1] = 980804926;
																	array4[2] = -854725955;
																	array4[3] = -53675351;
																	array4[4] = 362673926;
																	array4[5] = 1862584339;
																	array4[1] = array4[0] ^ -1636972933;
																	array4[4] = array4[2] ^ 0x30E01564;
																	int[] array5 = new int[4];
																	array5[0] = -911419260;
																	array5[1] = -970147566;
																	array5[2] = 788699094;
																	array5[3] = 284327970;
																	array5[0] = array4[2] ^ -1952910312;
																	array5[3] = array5[2] ^ 0x37AF410C;
																	array5[1] = array5[3] ^ 0x9E0E008;
																	array5[1] ^= 2104198751;
																	int num60 = array5[0] ^ 0x76EFB839;
																	int[,] array6 = new int[3, 3];
																	array6[0, 0] = 1460306838;
																	array6[0, 1] = -905582126;
																	array6[0, 2] = 1776963535;
																	array6[1, 0] = -758810438;
																	array6[1, 1] = -865356714;
																	array6[1, 2] = -1378638460;
																	array6[2, 0] = 1095857839;
																	array6[2, 1] = 333497650;
																	array6[2, 2] = -1655238771;
																	array6[2, 1] = array6[2, 2] ^ -440676514;
																	array6[2, 2] = array6[0, 0] ^ -1491413615;
																	array6[1, 1] = array6[0, 0] ^ 0x483DA084;
																	int num61 = array6[1, 1] ^ -2027138440;
																	int num62 = (int)(num4 * 1856571474) ^ -286787078;
																	num60 ^= num62;
																	num61 ^= num62;
																	int num63;
																	int num64;
																	if (num59)
																	{
																		num63 = num61;
																		num64 = num63;
																	}
																	else
																	{
																		num63 = num60;
																		num64 = num63;
																	}
																	num44 = num63 ^ num62;
																}
																else
																{
																	current = enumerator.Current;
																	num44 = -24738558;
																}
															}
															uint num65 = num3;
															int num66 = 265850148;
															_ = 0;
															for (int num67 = 0; num67 < 2; num67++)
															{
																num66 = -(num66 + -132925072);
																num66 = -num66;
															}
															if (num65 != (uint)num66)
															{
																num68 = num3;
																num69 = 6;
																_ = 0;
																for (int num70 = 0; num70 < 2; num70++)
																{
																	num69 = ~(-num69);
																	num69 = ~(num69 - -363093532);
																}
																continue;
															}
															return result;
														}
														while (num68 == (uint)num69);
														uint num71 = num3;
														int num72 = -3;
														_ = 0;
														for (int num73 = 0; num73 < 1; num73++)
														{
															num72 = ~num72;
														}
														if (num71 == (uint)num72)
														{
														}
													}
													finally
													{
														if (enumerator != null)
														{
															while (true)
															{
																int num74 = -1810092126;
																while (true)
																{
																	num2 = num74;
																	num3 = (num4 = (uint)(-(-(-(-(num2 ^ ((-(-(~(~-1627438737))) + ~((-1818555216 ^ (2053061409 * (-142039652 - -767741268 + -1595863623))) + -572537678 - (-(0x7454C1D6 ^ 0x52436B40) + -(983901196 - -2112476994 + (0xE21D9E7 ^ 0x71F05051)) - 1969581026))) ^ ((-1046280911 ^ 0x51226AF8) + -2111048803 - (~(0x758E1ACE ^ (-2055796044 + 293200877 - 725038220 + -(--139054366) - ((0x7B0B3B3 ^ 0x3FB417B1) + ~(453424028 + 1178951204)))) - -(~1383943231)))))) * 843024939) - --1523444313) * -401139789)) % 3;
																	uint num75 = num3;
																	int num76 = -473463538;
																	_ = 0;
																	for (int num77 = 0; num77 < 1; num77++)
																	{
																		num76 ^= -473463538;
																	}
																	if (num75 == (uint)num76)
																	{
																		break;
																	}
																	uint num78 = num3;
																	int num79 = -506207459;
																	_ = 0;
																	for (int num80 = 0; num80 < 1; num80++)
																	{
																		num79 -= -506207460;
																	}
																	if (num78 != (uint)num79)
																	{
																		uint num81 = num3;
																		int num82 = 1836085792;
																		_ = 0;
																		for (int num83 = 0; num83 < 1; num83++)
																		{
																			num82 += -1836085790;
																		}
																		if (num81 == (uint)num82)
																		{
																		}
																		goto end_IL_1f43;
																	}
																	____0024_0029_003C_005E_0029((IDisposable)enumerator);
																	int[] array7 = new int[5] { 1822881208, -1630657624, 1186488690, 1806133349, -836201968 };
																	array7[0] ^= 674228358;
																	array7[3] = array7[1] ^ 0x9B3506D;
																	array7[4] ^= -2033492042;
																	int[] array8 = new int[6];
																	array8[0] = -592272674;
																	array8[1] = -1374559516;
																	array8[2] = 773529087;
																	array8[3] = 1127113473;
																	array8[4] = 1386137858;
																	array8[5] = -923751883;
																	array8[3] = array7[1] ^ 0x18F73143;
																	array8[5] = array8[4] ^ -1903750010;
																	array8[2] = array8[0] ^ 0x30C2CDB5;
																	array8[2] = array8[0] ^ -831282443;
																	int num84 = array8[3] ^ 0x1B453386;
																	num74 = ((int)num4 * -917546299) ^ 0x666369 ^ num84;
																}
																continue;
																end_IL_1f43:
																break;
															}
														}
													}
												}
												else
												{
													e = _002F_003C_002B_0026__003E_002A_002F(Ifh_003D) as ILaunchActivatedEventArgs;
													if (e != null)
													{
														int[] array9 = new int[6] { -250776264, -2106477071, -1825398119, -441290125, 780416211, 2004281686 };
														array9[1] ^= -1731885467;
														array9[1] = array9[4] ^ -71912086;
														int[] array10 = new int[5];
														array10[0] = -1991757030;
														array10[1] = -5450528;
														array10[2] = -150387078;
														array10[3] = 649681560;
														array10[4] = 791513122;
														array10[4] = array9[0] ^ 0x5CABEF45;
														array10[2] = array10[0] ^ -1535352581;
														array10[3] = array10[4] ^ -194680351;
														int num85 = array10[4] ^ 0x127C1FE;
														num = ((int)num4 * -1066100139) ^ 0x61C7B888 ^ num85;
														continue;
													}
												}
												goto IL_231b;
											}
											return _003D_0028_0029_0021_003C_0024_002B_002D(storageFile);
										}
										return null;
									}
									int num86;
									if ((object)storageFile == null)
									{
										num = -575306398;
										num86 = num;
									}
									else
									{
										num = -1472984862;
										num86 = num;
									}
									continue;
								}
								return null;
							}
							yMF_003D = null;
						}
						else
						{
							if ((object)storageFile == null)
							{
								int[,] array11 = new int[4, 3];
								array11[0, 0] = 1232348387;
								array11[0, 1] = 1676097793;
								array11[0, 2] = -2054127264;
								array11[1, 0] = -1031109279;
								array11[1, 1] = -565938370;
								array11[1, 2] = 2105461587;
								array11[2, 0] = -1427505694;
								array11[2, 1] = 159492898;
								array11[2, 2] = -1415498081;
								array11[3, 0] = 1340212358;
								array11[3, 1] = 2056831851;
								array11[3, 2] = -1410067123;
								array11[3, 1] = array11[2, 2] ^ -486783752;
								array11[0, 0] = array11[3, 1] ^ -605443398;
								array11[1, 2] = array11[2, 2] ^ -1904758580;
								array11[2, 0] = array11[3, 2] ^ 0x7121382F;
								int num87 = array11[2, 0] ^ 0x7E1450AA;
								num = ((int)num4 * -735166151) ^ 0x340A4ECB ^ num87;
								continue;
							}
							yMF_003D = _003D_0028_0029_0021_003C_0024_002B_002D(storageFile);
						}
						int num88;
						if (!diZ_003D((string?)yMF_003D))
						{
							num = 706392152;
							num88 = num;
						}
						else
						{
							num = 512708764;
							num88 = num;
						}
					}
					else
					{
						storageFile = @_005E_0029_0028_005E_0040_003F_0024(e2).FirstOrDefault() as StorageFile;
						int[] array12 = new int[5];
						array12[0] = -1496440616;
						array12[1] = -1442834809;
						array12[2] = 49099412;
						array12[3] = 1437921277;
						array12[4] = -2082775262;
						array12[3] = array12[2] ^ -445862973;
						array12[4] = array12[3] ^ -1331584324;
						array12[0] ^= -2011443596;
						int[] array13 = new int[7];
						array13[0] = -1996010267;
						array13[1] = -163342541;
						array13[2] = -147228434;
						array13[3] = 149638357;
						array13[4] = -239439422;
						array13[5] = 1406062224;
						array13[6] = -627879937;
						array13[1] = array12[1] ^ -800884762;
						array13[0] = array13[1] ^ -1431182753;
						array13[2] = array13[6] ^ 0x672358E9;
						array13[3] = array13[2] ^ -1332593721;
						int num89 = array13[1] ^ -689629231;
						num = (int)((num4 * 639579029) ^ 0xA754E436u) ^ num89;
					}
				}
				else
				{
					IFileActivatedEventArgs e3 = e2;
					int[] array14 = new int[6];
					array14[0] = -237113486;
					array14[1] = -281209553;
					array14[2] = -2073877586;
					array14[3] = -1877674637;
					array14[4] = -679654280;
					array14[5] = -1833635370;
					array14[1] = array14[4] ^ 0x2136B0D8;
					array14[3] = array14[2] ^ 0x5B6EB86A;
					int[] array15 = new int[5];
					array15[0] = 1468670756;
					array15[1] = 1260222464;
					array15[2] = 19213370;
					array15[3] = 1742512150;
					array15[4] = -993304697;
					array15[1] = array14[4] ^ -894230810;
					array15[3] = array15[0] ^ 0xF9082D1;
					array15[2] = array15[0] ^ -1880615495;
					array15[2] ^= 1577993056;
					int num90 = array15[1] ^ 0x5DC1131F;
					int[] array16 = new int[4];
					array16[0] = 1278719906;
					array16[1] = -110912345;
					array16[2] = -1709514971;
					array16[3] = -2081496602;
					array16[0] = array16[3] ^ -111852045;
					array16[2] = array16[3] ^ -2178809;
					array16[3] = array16[1] ^ 0x50F17256;
					int[] array17 = new int[7] { 1973235795, -868257475, 809387080, -394137392, 1719618441, -602495456, -103492634 };
					int[][] array18 = new int[2][] { array16, array17 };
					array17[0] = array18[0][1] ^ -1652577385;
					array17[1] ^= 1287884077;
					array17[5] ^= 184081253;
					array17[4] = array17[0] ^ 0x7E35BC5C;
					int num91 = array18[1][0] ^ 0x6387139B;
					int num92 = ((int)num4 * -1833966094) ^ 0xEBC08CC;
					num90 ^= num92;
					num91 ^= num92;
					int num93;
					int num94;
					if (e3 != null)
					{
						num93 = num91;
						num94 = num93;
					}
					else
					{
						num93 = num90;
						num94 = num93;
					}
					num = num93 ^ num92;
				}
			}
			else
			{
				e2 = _002F_003C_002B_0026__003E_002A_002F(Ifh_003D) as IFileActivatedEventArgs;
				int[] array19 = new int[5] { 1857946058, -994749254, -427397137, 1832576015, 1969104423 };
				array19[0] ^= -1992862146;
				array19[1] = array19[4] ^ -2137739886;
				int[] array20 = new int[5];
				array20[0] = -1415321699;
				array20[1] = 1987432293;
				array20[2] = 248545525;
				array20[3] = -831091454;
				array20[4] = -1410201341;
				array20[0] = array19[3] ^ 0x3CFD8CA0;
				array20[1] ^= 1667653602;
				array20[4] = array20[2] ^ -173709100;
				int num95 = array20[0] ^ -841093540;
				num = (int)((num4 * 208432937) ^ 0x3BFEBC5B) ^ num95;
			}
		}
		goto IL_0013;
		IL_231b:
		return null;
		IL_145b:
		if (_002B_002D_003F_003F_003C_002B_0026_002F(Ifh_003D) == ExtendedActivationKind.Launch)
		{
			num = 2068722821;
			goto IL_0018;
		}
		goto IL_231b;
	}

	private static bool diZ_003D(string? YMF_003D)
	{
		if (!_0025_0023_002F_0040_002A_0023_003C_0024(YMF_003D))
		{
			string text = default(string);
			string text2 = default(string);
			string text3 = default(string);
			while (true)
			{
				int num = -1862008143;
				uint num3;
				while (true)
				{
					int num2 = num;
					uint num4;
					num3 = (num4 = (uint)(~(~(-(-((num2 + ~((-976674444 - ~(~1876623843) - (0x20490918 ^ ~(~(-(~894393320) - (1501730541 + (329311289 + 1614142505)))))) * 104306985) - (((-1663294363 ^ -(~2121151865)) + ~(-111642511 ^ (1527059063 * (-1161278457 ^ 0x4116B9BF) + (-(876231010 + 73224639) - -(~-1194078524))))) ^ (1080656856 + (~-1025025777 * 863151119 - (-1283658813 + ~(712631354 + -738822546))) - -(-1161128683 * 666523179) - -(-(~(-(-1951472729))) ^ 0x5E75CFC3)))) * -747549025))) * 587801143) * 2119625963 - 1473321347)) % 12;
					int num5 = -1740039197;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= -1740039196;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1733758915;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(-1104463677 - num7);
						num7 = -1971343130 - ~num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 205396880;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 - -1527062765);
							num9 = (num9 ^ -965266487) + 911414655;
						}
						if (num3 == (uint)num9)
						{
							goto end_IL_000e;
						}
						int num11 = -2128559843;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = ~(-1325663886 - num11);
							num11 = (num11 ^ -1549084718) * 129204783;
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
								int num15 = -33292331;
								_ = 0;
								for (int num16 = 0; num16 < 2; num16++)
								{
									num15 = -(~num15);
									num15 = (num15 ^ -23994432) - 620848619;
								}
								if (num3 != (uint)num15)
								{
									int num17 = -1516238827;
									_ = 0;
									for (int num18 = 0; num18 < 2; num18++)
									{
										num17 = num17 - -1218073639 * 1587712030 - 786484936;
										num17 = -num17 ^ 0x57D45628;
									}
									if (num3 != (uint)num17)
									{
										int num19 = 1316994538;
										_ = 0;
										for (int num20 = 0; num20 < 1; num20++)
										{
											num19 *= 142171485;
										}
										if (num3 != (uint)num19)
										{
											int num21 = 67634438;
											_ = 0;
											for (int num22 = 0; num22 < 2; num22++)
											{
												num21 = -(num21 + 392058295 * -1343690415);
												num21 = ~(num21 ^ 0x3DB9F57A);
											}
											if (num3 != (uint)num21)
											{
												int num23 = 93703464;
												_ = 0;
												for (int num24 = 0; num24 < 1; num24++)
												{
													num23 -= 93703456;
												}
												if (num3 == (uint)num23)
												{
													bool num25 = ___0029_002B_0025_0024_003E_0021(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x2DC6 ^ 0x2DC0))], StringComparison.OrdinalIgnoreCase);
													int[] array = new int[4];
													array[0] = 1013366886;
													array[1] = -90022907;
													array[2] = 2051646207;
													array[3] = -1016387684;
													array[0] = array[1] ^ -88190120;
													array[3] ^= 12245944;
													array[0] = array[3] ^ -852624484;
													int[] array2 = new int[5];
													array2[0] = -189263868;
													array2[1] = 1909699444;
													array2[2] = 911427180;
													array2[3] = 1565210347;
													array2[4] = -507393700;
													array2[1] = array[1] ^ 0x5083D4D3;
													array2[2] = array2[3] ^ 0x5C23CF19;
													array2[3] = array2[4] ^ 0x66E85576;
													int num26 = array2[1] ^ 0x315BCE1A;
													int[] array3 = new int[6];
													array3[0] = -1306203040;
													array3[1] = 1272459833;
													array3[2] = -2064830758;
													array3[3] = 930638073;
													array3[4] = -1482809164;
													array3[5] = 1932124007;
													array3[5] = array3[0] ^ -696187357;
													array3[3] = array3[4] ^ 0x23554E78;
													int[] array4 = new int[6];
													array4[0] = 722538378;
													array4[1] = 1742386138;
													array4[2] = 951256405;
													array4[3] = 1963887062;
													array4[4] = -560735125;
													array4[5] = -362819664;
													array4[4] = array3[4] ^ -1631300173;
													array4[1] = array4[0] ^ -1618428788;
													array4[2] = array4[3] ^ 0x108FB952;
													int num27 = array4[4] ^ -1869094659;
													int num28 = (int)((num4 * 521564519) ^ 0x64C5D6BC);
													num26 ^= num28;
													num27 ^= num28;
													int num29;
													int num30;
													if (!num25)
													{
														num29 = num27;
														num30 = num29;
													}
													else
													{
														num29 = num26;
														num30 = num29;
													}
													num = num29 ^ num28;
													continue;
												}
												goto IL_0554;
											}
											text = _0028_0023_003F_0024_003F_0021_003E_(text2);
											num = -124821964;
											continue;
										}
										return false;
									}
									bool num31 = ___0029_002B_0025_0024_003E_0021(text2, _002D_0028_0029_0025_0029_0028_0023_005E(text3), StringComparison.OrdinalIgnoreCase);
									int[] array5 = new int[7];
									array5[0] = -812976938;
									array5[1] = -350441340;
									array5[2] = -1407221559;
									array5[3] = 966097725;
									array5[4] = 1297885306;
									array5[5] = 1151149141;
									array5[6] = -499661802;
									array5[3] = array5[2] ^ 0x865B5FF;
									array5[1] = array5[0] ^ -625457952;
									int[] array6 = new int[6] { 360829227, -541736603, 960075868, -1504826746, 1513158674, 732972542 };
									int[][] array7 = new int[2][] { array5, array6 };
									array6[0] = array7[0][5] ^ 0x362073F9;
									array6[4] = array6[1] ^ 0x339F460A;
									array6[3] = array6[1] ^ 0x79B17F3;
									array6[3] = array6[0] ^ 0x289E1607;
									int num32 = array7[1][0] ^ -856761246;
									int[,] array8 = new int[3, 4];
									array8[0, 0] = -80873420;
									array8[0, 1] = -15377114;
									array8[0, 2] = -1470828165;
									array8[0, 3] = 456163483;
									array8[1, 0] = 1156027056;
									array8[1, 1] = -1059512231;
									array8[1, 2] = 466067836;
									array8[1, 3] = 1137407380;
									array8[2, 0] = 883377950;
									array8[2, 1] = -563093902;
									array8[2, 2] = -742407295;
									array8[2, 3] = -392254263;
									array8[2, 1] = array8[1, 3] ^ -271866341;
									array8[1, 1] = array8[0, 1] ^ 0x2ABF5BC5;
									array8[0, 1] ^= -303971793;
									array8[0, 2] = array8[2, 2] ^ 0x6FC92892;
									int num33 = array8[0, 2] ^ 0x4E21C8E5;
									int num34 = (int)(num4 * 318822907) ^ -1102099089;
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
									continue;
								}
								bool num37 = _0025_0023_002F_0040_002A_0023_003C_0024(text3);
								int[,] array9 = new int[3, 4]
								{
									{ -995074032, 337984393, 2146474430, 2144224279 },
									{ -1632319347, -1638404839, -1747674183, -1077060976 },
									{ 792075400, -1832397832, -883608926, -228905785 }
								};
								array9[0, 0] ^= -1592789511;
								array9[0, 3] = array9[1, 1] ^ 0x30A13740;
								array9[1, 1] ^= 1910499668;
								array9[1, 0] = array9[2, 2] ^ 0x43D4ADD0;
								int num38 = array9[1, 0] ^ 0x36D214BC;
								int[,] array10 = new int[4, 4];
								array10[0, 0] = 1456253775;
								array10[0, 1] = 1685449476;
								array10[0, 2] = 930487741;
								array10[0, 3] = -1358889020;
								array10[1, 0] = -1638532568;
								array10[1, 1] = 1324491590;
								array10[1, 2] = 1269087617;
								array10[1, 3] = 102861392;
								array10[2, 0] = -269587534;
								array10[2, 1] = 1443339831;
								array10[2, 2] = 861609211;
								array10[2, 3] = 1065382450;
								array10[3, 0] = -1945733366;
								array10[3, 1] = -1205249050;
								array10[3, 2] = -1822179929;
								array10[3, 3] = -1306898241;
								array10[0, 3] = array10[2, 0] ^ -1963962778;
								array10[1, 1] = array10[3, 3] ^ 0x1FDDB86A;
								array10[0, 3] = array10[0, 0] ^ -44821308;
								int num39 = array10[0, 3] ^ 0xA69452C;
								int num40 = (int)((num4 * 1503370006) ^ 0x58A0E806);
								num38 ^= num40;
								num39 ^= num40;
								int num41;
								int num42;
								if (!num37)
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
								continue;
							}
							text3 = _002D_0021_0040_0023__005E_0040_0025();
							int[] array11 = new int[7];
							array11[0] = 287762535;
							array11[1] = 1855536029;
							array11[2] = -2127208289;
							array11[3] = 934314851;
							array11[4] = 1198443960;
							array11[5] = -1466915625;
							array11[6] = 408944944;
							array11[5] = array11[6] ^ 0x1A4414DD;
							array11[6] ^= -635302621;
							array11[2] = array11[1] ^ 0x6ED96B1B;
							int[] array12 = new int[5] { 1116975964, 162490427, -329258545, 1317204359, 345565026 };
							int[][] array13 = new int[2][] { array11, array12 };
							array12[4] = array13[0][1] ^ -369737440;
							array12[0] = array12[2] ^ -1477658952;
							array12[1] = array12[4] ^ -878528825;
							array12[1] = array12[2] ^ 0x647E3E5B;
							int num43 = array13[1][4] ^ 0x5F618D56;
							num = ((int)num4 * -588919661) ^ -2044098091 ^ num43;
							continue;
						}
						text2 = _002D_0028_0029_0025_0029_0028_0023_005E(_0026_0026_005E_005E_003C_005E_002D_0024(_0023_0024_005E_002D_005E_0029_0040_0028(YMF_003D), '"'));
						num = 477181957;
						continue;
					}
					bool num44 = _003E_002D_0023_0026_0040_005E_0023_002F(YMF_003D);
					int[,] array14 = new int[4, 4];
					array14[0, 0] = 188219301;
					array14[0, 1] = -1336650796;
					array14[0, 2] = 1956422703;
					array14[0, 3] = -649418590;
					array14[1, 0] = 777847378;
					array14[1, 1] = 298764236;
					array14[1, 2] = -1349368268;
					array14[1, 3] = -959554011;
					array14[2, 0] = 1142390436;
					array14[2, 1] = -1471321133;
					array14[2, 2] = 112730768;
					array14[2, 3] = -983084182;
					array14[3, 0] = 1743433192;
					array14[3, 1] = -1971458678;
					array14[3, 2] = -1161147637;
					array14[3, 3] = 1498052996;
					array14[3, 3] = array14[3, 0] ^ 0x30275A4A;
					array14[3, 2] = array14[0, 3] ^ 0x59022F8B;
					array14[2, 3] = array14[3, 2] ^ -1759398063;
					array14[1, 0] = array14[2, 0] ^ -493296155;
					int num45 = array14[1, 0] ^ 0xFBB7962;
					int[] array15 = new int[5];
					array15[0] = -1968378662;
					array15[1] = -1238592579;
					array15[2] = 266554332;
					array15[3] = 1533383745;
					array15[4] = -1321758440;
					array15[1] = array15[3] ^ 0x5C21B987;
					array15[4] ^= -1058418706;
					int[] array16 = new int[5] { -424958672, -535622818, 1659087385, 1807547082, 1994148600 };
					int[][] array17 = new int[2][] { array15, array16 };
					array16[2] = array17[0][0] ^ 0x3721C43E;
					array16[1] = array16[3] ^ 0x3DE3113;
					array16[4] = array16[2] ^ -446956583;
					array16[1] ^= -2104873213;
					int num46 = array17[1][2] ^ -1847165812;
					int num47 = (int)((num4 * 682470368) ^ 0x14D294A0);
					num45 ^= num47;
					num46 ^= num47;
					int num48;
					int num49;
					if (!num44)
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
				continue;
				IL_0554:
				int num50 = -409770914;
				_ = 0;
				for (int num51 = 0; num51 < 2; num51++)
				{
					num50 = ~num50 ^ 0x6469837;
					num50 = (num50 ^ 0x2D77895D) * 1581341477;
				}
				if (num3 != (uint)num50)
				{
					int num52 = 1656523228;
					_ = 0;
					for (int num53 = 0; num53 < 2; num53++)
					{
						num52 = ~(num52 - (-1416294484 + 783245148));
						num52 = -(num52 + (420222221 - 1106394920));
					}
					if (num3 != (uint)num52)
					{
					}
					return true;
				}
				return ___0029_002B_0025_0024_003E_0021(text, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4191 - 4275 + 91], StringComparison.OrdinalIgnoreCase);
				continue;
				end_IL_000e:
				break;
			}
		}
		return false;
	}

	[IteratorStateMachine(typeof(_003CSplitCommandLine_003Ed__19))]
	private static IEnumerable<string> srG_003D(string PFE_003D)
	{
		//yield-return decompiler failed: Missing enumeratorCtor.Body
		return new _003CSplitCommandLine_003Ed__19(-2)
		{
			_003C_003E3__arguments = PFE_003D
		};
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public void vjV_003D()
	{
		if (DnV_003D)
		{
			goto IL_000e;
		}
		goto IL_05ea;
		IL_000e:
		int num = 496514497;
		goto IL_0013;
		IL_0013:
		Uri uri = default(Uri);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)((((num2 - ((~(-(-709752325) * 543132577 + (-1054319819 ^ -1493590810) - (~(1282338897 * -287649755) - ~(-765200556 + -38075653) + -(--702590184))) + 170208612 + (~(253936843 - -319536391 * (-862661107 - 114823465 * (127998677 * -272656451))) - (~(~88544143) + ~(-594460403 - (-(-833844619 - -1591802300) - (0x4B466B0 ^ --464611052)))))) ^ (-141953972 ^ (-1146750563 ^ (-1397863225 * (-(-(-1891597519 + -1903363658)) - ~1476353352) - ~(-424703971 * ~(~1283983559) + ~(-(--1081380164)))))))) ^ (-420799021 * (523199723 * ~(--1437534748)))) * -1186977259 - (((~1534587302 - ~-1705453452 + -(-153199503 * 1496797866) + (-450554172 * 1667801729 + -662772863 * (-1873310400 - -277371806))) ^ -1674807296) + (~(0x70C544E0 ^ ((-1329749628 ^ 0x36B9989E) + --1868104101)) - 755947627)) - -717305943 - ~(-(~1768441801) * -1588320455)) ^ -998318763)) % 6;
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
			int num7 = -1704100529;
			_ = 0;
			for (int num8 = 0; num8 < 2; num8++)
			{
				num7 = -num7 * 1674631715;
				num7 = -1617620638 - -num7;
			}
			if (num3 == (uint)num7)
			{
				return;
			}
			int num9 = -677999969;
			_ = 0;
			for (int num10 = 0; num10 < 2; num10++)
			{
				num9 = ~(-num9);
				num9 = -(num9 * 52948167);
			}
			if (num3 != (uint)num9)
			{
				int num11 = -452965338;
				_ = 0;
				for (int num12 = 0; num12 < 2; num12++)
				{
					num11 = (num11 ^ -1333574451) + -911713522;
					num11 = 390603644 - (num11 ^ 0x23E01EE6);
				}
				if (num3 != (uint)num11)
				{
					int num13 = -995228266;
					_ = 0;
					for (int num14 = 0; num14 < 1; num14++)
					{
						num13 = -995228264 - num13;
					}
					if (num3 != (uint)num13)
					{
						int num15 = 1;
						_ = 0;
						for (int num16 = 0; num16 < 2; num16++)
						{
							num15 = ~(-num15);
							num15 = ~num15;
						}
						if (num3 == (uint)num15)
						{
						}
						return;
					}
					_0021_0024_003D_002D_003E_002F_0028_003D((object)this, uri);
					int[] array = new int[5];
					array[0] = 1182179643;
					array[1] = 1828784153;
					array[2] = -1414776382;
					array[3] = -1531127868;
					array[4] = 125239082;
					array[0] = array[2] ^ 0x794C06EA;
					array[4] = array[3] ^ 0x6D9EFCA2;
					int[] array2 = new int[5];
					array2[0] = 870969184;
					array2[1] = 1878889564;
					array2[2] = -880759226;
					array2[3] = 1942645973;
					array2[4] = 2098787835;
					array2[4] = array[1] ^ -1528383635;
					array2[3] = array2[2] ^ -1843926288;
					array2[1] ^= -1006530871;
					int num17 = array2[4] ^ -1188195481;
					num = ((int)num4 * -2124993795) ^ -1054913600 ^ num17;
				}
				else
				{
					uri = new Uri(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4630 - 4633 + 11]);
					int[,] array3 = new int[3, 3]
					{
						{ -96410075, 974572403, -934424229 },
						{ 1889275592, 1449114046, 1416000838 },
						{ 1315401108, -899481039, -1647304490 }
					};
					array3[2, 0] ^= 753873479;
					array3[2, 1] = array3[0, 1] ^ -297146052;
					array3[1, 2] = array3[2, 2] ^ 0x5E31F3E;
					int num18 = array3[1, 2] ^ 0x1F1291AC;
					num = (int)((num4 * 1633054834) ^ 0x4439BF5C) ^ num18;
				}
				continue;
			}
			goto IL_05ea;
		}
		goto IL_000e;
		IL_05ea:
		DnV_003D = true;
		num = -1103537946;
		goto IL_0013;
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public IXamlType GetXamlType(Type LMc_003D)
	{
		return Xtc_003D.GetXamlType(LMc_003D);
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public IXamlType GetXamlType(string kmD_003D)
	{
		return Xtc_003D.GetXamlType(kmD_003D);
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public XmlnsDefinition[] GetXmlnsDefinitions()
	{
		return Xtc_003D.GetXmlnsDefinitions();
	}

	static AppInstance _0024_003D_0024_0028_002B_0024_0021_005E()
	{
		AppInstance current = default(AppInstance);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -121722510;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(-(~(-(~(~(num2 - ~(~((((-(-1193080315) - (-1498876910 ^ 0xC31DC5C) + ~1654992978) * -1579852357) ^ -1553665935) * -1864812023)))) * 25719671)) * 885083149))))) % 3;
					int num5 = -905033660;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= -905033658;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1229977977;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7 - -414448587;
						num7 = ~(num7 * -1208442249);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 *= -630095369;
							num9 = -num9 * 547683251;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					current = AppInstance.GetCurrent();
					int[] array = new int[7] { -1566092361, -1264145299, 406368986, -1435702192, 1955469325, -1262763442, -580224680 };
					array[4] ^= 348240463;
					array[4] = array[0] ^ 0x56AB9AF9;
					array[6] = array[5] ^ -864772086;
					int[] array2 = new int[4] { 185763298, -284251136, 1297434810, 831969653 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][3] ^ -771443325;
					array2[1] = array2[3] ^ 0x1896FFEC;
					array2[3] = array2[2] ^ -562047087;
					array2[3] = array2[1] ^ -708622683;
					int num11 = array3[1][0] ^ -1274237870;
					num = ((int)num4 * -376214329) ^ -1337086100 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return current;
	}

	static AppActivationArguments __002D_0040_0024_0028_0040_0021_003D(AppInstance P_0)
	{
		AppActivationArguments activatedEventArgs = default(AppActivationArguments);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1849151315;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((-num2 ^ 0x1BECFD9A) + ~-1176312283) * -1601229323)) % 3;
					int num5 = -1540008189;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= -1540008189;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1643681200;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 ^ 0x60EFDC49) * 1089846753;
						num7 = ~(num7 - -1521019297 * 1415135271);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -920991368;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -920991369;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					activatedEventArgs = P_0.GetActivatedEventArgs();
					int[] array = new int[5] { -2123490319, -578387163, 495221632, 83682805, 1901090799 };
					array[2] ^= -1196689900;
					array[0] = array[2] ^ 0x39B96DF7;
					array[4] = array[1] ^ -361188888;
					int[] array2 = new int[4];
					array2[0] = 471924625;
					array2[1] = 1131282020;
					array2[2] = -512297634;
					array2[3] = -2048666967;
					array2[0] = array[3] ^ 0x1722226C;
					array2[1] ^= 1338715402;
					array2[2] = array2[0] ^ 0x559C5473;
					int num11 = array2[0] ^ 0x630F0AAA;
					num = (int)((num4 * 156094747) ^ 0x72EE43B9) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return activatedEventArgs;
	}

	static AppInstance _005E_0025_0024_0029_003E_003C_0026_(string P_0)
	{
		AppInstance result = default(AppInstance);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1083187069;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(num2 - (-(~(935632105 * (1559926899 * (~(-1303173488) * 2112766529))) ^ ((~(-(0x393AE13C ^ 0x4E8A0A7)) + -855556796) * 1328953597)) ^ ~(((-(1788956127 + 1582941225) ^ (-1751335668 ^ 0x6A1ED8C9)) - 1009467750 - (-978556049 * (-1108915231 * -1190910581) * 256481597 + -(-(1452052540 - 530112402)))) * -1091627403 - -1392145358)) - ~(-616353021 ^ ~(~(~(0x2A07C29A ^ -464491788)) * -1130380349))) - 1316761166))) % 3;
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
					int num7 = 201082326;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(num7 - -1385257175);
						num7 = ~(num7 + -661685311);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2047649338;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = 2047649339 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = AppInstance.FindOrRegisterForKey(P_0);
					int[] array = new int[4];
					array[0] = 992062801;
					array[1] = 1009613751;
					array[2] = -255712515;
					array[3] = 892877233;
					array[1] = array[3] ^ -1967281135;
					array[2] = array[1] ^ -543992607;
					int[] array2 = new int[7] { 1178422170, -1811719891, -542786750, 718722339, 1103504997, 1387178043, -1894193754 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][0] ^ 0x6E955E7A;
					array2[1] = array2[2] ^ 0x7E3D03ED;
					array2[1] = array2[4] ^ -1538470193;
					int num11 = array3[1][4] ^ 0x5F02E18E;
					num = ((int)num4 * -1785859126) ^ 0x497427C0 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static bool _0021_003D_003E_003D_0023_002B_002D_0024(AppInstance P_0)
	{
		bool ısCurrent = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -735306083;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-1164621737 * (-2085894962 ^ 0x63CDAB52) - (~(-(1646585113 + (-774539418 ^ ~(--1995811248)) - -(--2021037998)) - -(num2 * 1832507005) * -1946209593) + 2145089328) * -110579893) * -792444471)) % 3;
					int num5 = 1308737436;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 * -1332950429;
						num5 = (num5 ^ 0x65ED1339) - 1298550757;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1095565182;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(~num7);
						num7 = num7 * 258891541 * 1259446627;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1380383929;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -1726774885 - num9 * 953195861;
							num9 = -(~num9);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ısCurrent = P_0.IsCurrent;
					int[] array = new int[6];
					array[0] = 646419536;
					array[1] = 541601520;
					array[2] = -180466054;
					array[3] = 1880496270;
					array[4] = 1508011721;
					array[5] = 87878662;
					array[3] = array[2] ^ 0x229F82A1;
					array[0] = array[2] ^ 0x478B40D4;
					array[3] = array[2] ^ 0xA9CF61B;
					int[] array2 = new int[4];
					array2[0] = -1586978617;
					array2[1] = -1316299199;
					array2[2] = 1408184548;
					array2[3] = 1961215934;
					array2[1] = array[4] ^ 0x75FC8E70;
					array2[3] = array2[2] ^ -1486977976;
					array2[2] = array2[0] ^ 0x685B9908;
					array2[0] ^= -2127787482;
					int num11 = array2[1] ^ -1271637816;
					num = ((int)num4 * -39765135) ^ 0x5E57DDA4 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ısCurrent;
	}

	static void _002A_0028_003E_002B_003D_003E_003E_(AppInstance P_0, EventHandler<AppActivationArguments> P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1490506857;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(2070294863 + -1273283704 - (-852303598 + 2101767125) + -(-1013240539 ^ -1372181852)) - -((562039495 * (1250395225 * 2119241989) - (-(-(((-((-247787438 ^ -373814281) - -1131954030) ^ 0x74A69A64) * -964059047 * 734740967) ^ ((0x76942537 ^ ((0x5DA5878F ^ -577362693) + (122047380 * 798393525 - (-479764437 - -1843470915 + -669339089)))) + (0x6A74A22A ^ (((779908048 + --444912853) ^ 0x6C7BF8C1) * -293847919))))) - num2) - ~(1293008323 + 1834880064)) * -1348792403) - (-892737822 ^ -652074291)))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= 1243816589;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1140648247;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(num7 - (0x444A233A ^ -617128589));
						num7 = num7 * -2028062311 + -1857834331;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(-num9);
							num9 ^= -739352683;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Activated += P_1;
					int[,] array = new int[3, 4];
					array[0, 0] = -1925214969;
					array[0, 1] = 2010760157;
					array[0, 2] = -1654654704;
					array[0, 3] = 2134966572;
					array[1, 0] = 1072037954;
					array[1, 1] = -1501199327;
					array[1, 2] = 1618865310;
					array[1, 3] = 1748970724;
					array[2, 0] = 1091594128;
					array[2, 1] = 195265011;
					array[2, 2] = -1052130819;
					array[2, 3] = 521088253;
					array[1, 0] = array[2, 0] ^ -449673003;
					array[2, 3] = array[1, 3] ^ 0x5F5DB0C2;
					array[1, 0] = array[2, 1] ^ -457700104;
					array[2, 1] = array[2, 2] ^ -84905798;
					int num11 = array[2, 1] ^ -349838722;
					num = ((int)num4 * -221590059) ^ 0x5184E640 ^ num11;
				}
			}
		}
	}

	static bool _0025_0023_002F_0040_002A_0023_003C_0024(string P_0)
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
				int num = 617538584;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-((-(num2 * 1178997181) ^ ~(~(-(~(-(943566763 + (1294337069 - 432715414))))))) + -(-1500598631 ^ ~(-231296501) ^ -1811745207 ^ ((-1291621185 + (-1725590076 ^ --1093699728)) ^ -717667139)) + ~(-1510148299 ^ (-1944193090 + (-725256694 * -1866412331 - -316893790)))) ^ (-1650007389 ^ (707901481 * 164607992 + -792441431))) * -1434665367 * -1286311473)) % 3;
					int num5 = -820473350;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= 1696076885;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1747028722;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= -1747028721;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(~num9);
							num9 = ~num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = string.IsNullOrWhiteSpace(P_0);
					int[,] array = new int[4, 3];
					array[0, 0] = 114595157;
					array[0, 1] = 538166515;
					array[0, 2] = 115634301;
					array[1, 0] = 617540263;
					array[1, 1] = -1396872652;
					array[1, 2] = -622419839;
					array[2, 0] = -2084248813;
					array[2, 1] = 2055670692;
					array[2, 2] = -1577470091;
					array[3, 0] = 37606697;
					array[3, 1] = -2054920315;
					array[3, 2] = 1568425978;
					array[3, 0] = array[1, 0] ^ -1736163596;
					array[2, 0] = array[3, 1] ^ -129436082;
					array[1, 0] = array[1, 1] ^ 0x1FB0538;
					int num11 = array[1, 0] ^ -1561905155;
					num = ((int)num4 * -1491439886) ^ 0x43E01C86 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _0026_003F_0021_002F_005E_0024_0028_0028(Window P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 291167268;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(~((((-63635237 - 1949215186 + (-1568680643 + -785117371) + --914320388) ^ (-(401808000 - 2141389463) + ~1469547967) ^ 0xAE82E2) - (~(~(num2 * -550985045)) - -(-958863786 - -1813632678))) * -1012081115) * 772777103)))) % 3;
					int num5 = 2118698075;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = 2118698077 - num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2113104170;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x7DF3692B;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 607903985;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x243BE0F1;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Activate();
					int[,] array = new int[4, 4];
					array[0, 0] = 1909975328;
					array[0, 1] = 888682149;
					array[0, 2] = 1625380021;
					array[0, 3] = 856739820;
					array[1, 0] = 584518845;
					array[1, 1] = -179614087;
					array[1, 2] = 1228931437;
					array[1, 3] = 726317495;
					array[2, 0] = 1476835932;
					array[2, 1] = -1608451431;
					array[2, 2] = 19488079;
					array[2, 3] = -1127868326;
					array[3, 0] = 1023037181;
					array[3, 1] = -769432909;
					array[3, 2] = 1438171503;
					array[3, 3] = -1404686518;
					array[3, 2] = array[1, 1] ^ 0x46E8A636;
					array[3, 1] = array[1, 0] ^ -1614248986;
					array[2, 0] = array[1, 1] ^ 0x70358EA2;
					int num11 = array[2, 0] ^ 0x5107A24D;
					num = (int)((num4 * 83315519) ^ 0xC03E07B5u) ^ num11;
				}
			}
		}
	}

	static ServiceProvider _002A_0029_0028_005E_0025_002A_003F_0024(IServiceCollection P_0)
	{
		ServiceProvider result = default(ServiceProvider);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1197170788;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~((~num2 * 868846169 - (~(~287448434 - -(--734239541) - ~(1874429442 + 66035001 - (1246659401 + -997148060) + ~(~648474153))) ^ (((~(~793098930 - -1767837549 * 165625171) - 678875243 * -(-827999995 * -1317477123)) ^ (-535296953 * (-(0x24EB3E83 ^ -1522804937) ^ -1257569941))) * -1511768809)) - ((-(-(~1113747491 - 853204824)) - 2114901761 * 43598163) ^ -(-(-374891194 + -972546596 - (1242699612 - -147885286) + (829913372 - -1307697523 * -1500022772))))) ^ (-2013885962 * -990792961 - -568333431 * 803831501 - ~(~(-(-1112047874 * -113300271))))) * 1192975703 * -1943929755) - -700117038)) % 3;
					int num5 = -947050938;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(~num5);
						num5 = 473525469 - -num5;
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
						int num9 = 894755349;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = 894755349 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.BuildServiceProvider();
					int[] array = new int[7];
					array[0] = 623987600;
					array[1] = -296877683;
					array[2] = -1902137677;
					array[3] = 1484551035;
					array[4] = -1629637609;
					array[5] = 691872102;
					array[6] = -1112878185;
					array[5] = array[3] ^ -400369738;
					array[6] = array[0] ^ -1076770248;
					int[] array2 = new int[5] { 666595636, -1598093088, 1226195392, 279093885, 1131620110 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][2] ^ -1635612498;
					array2[2] = array2[1] ^ 0x79488F54;
					array2[2] ^= -42946721;
					array2[2] = array2[3] ^ 0x44A1C193;
					int num11 = array3[1][4] ^ 0x1358915;
					num = ((int)num4 * -707757790) ^ -423516720 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static DispatcherQueue _002B_0024_0023_0021_0029_002B_0029_0026(Window P_0)
	{
		DispatcherQueue dispatcherQueue = default(DispatcherQueue);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 841038224;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(873836867 * ~(-1131985660 ^ 0x49C3DF05) - (~(~(num2 * -1373461135 - (-(~(-(-1232257211 * 558823608)) * 26622161 * -723055353) ^ (~(-(1675003445 * -860713217) - (-1068532746 + -1491553185 - -1418636133) - ((0xE9EC59C ^ -523913417) + -(~270616494))) - ~(0x58BCE387 ^ -2030815826))) * 2111906931)) ^ ((--1294882613 ^ ((--1215584658 ^ -713453544) - ~(~29921248))) + (-376195057 * -1393984788 - ~-480551429 - -(-(~-1014766946))))) - (-168223429 - 82836079) * -1494653725 * 1406547967)) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= 1549241725;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 79273368;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -688519440 - (-897017583 - num7);
						num7 = -(~1899348821 - num7);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 588333793;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= 1567850785;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					dispatcherQueue = P_0.DispatcherQueue;
					int[] array = new int[6];
					array[0] = 214939388;
					array[1] = -1982003658;
					array[2] = -1045530586;
					array[3] = -1059595914;
					array[4] = -1853930765;
					array[5] = 1915235513;
					array[2] = array[5] ^ 0x4D1BBFEF;
					array[3] = array[1] ^ 0x3B40BB5F;
					int[] array2 = new int[7];
					array2[0] = 628364557;
					array2[1] = -1440152047;
					array2[2] = 1578431359;
					array2[3] = -1848920585;
					array2[4] = -2063963358;
					array2[5] = 302655898;
					array2[6] = 1919963974;
					array2[4] = array[0] ^ -588536322;
					array2[0] = array2[3] ^ -571602987;
					array2[1] = array2[3] ^ -2093349898;
					int num11 = array2[4] ^ -649986138;
					num = ((int)num4 * -452795329) ^ -1567216569 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return dispatcherQueue;
	}

	static bool _003C_003F__005E_005E_0023_003F_0026(DispatcherQueue P_0, DispatcherQueueHandler P_1)
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
				int num = 1180206432;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~-1944577898 - ((~(-(~(num2 * 462143859) + 1252428883 * ((0xD3A3B1F ^ (0x3184F4B5 ^ (--541175018 - 1410507386) ^ 0x10971A33)) * 1761667097))) * -5487605) ^ -(-1358792844 ^ 0x420B9C0B)) * 108132637) * -1134533761)) % 3;
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
					int num7 = -1740556961;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(num7 - -1272768851 * 637111883);
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1955539460;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -1169713917 - -num9;
							num9 = ~(-num9);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.TryEnqueue(P_1);
					int[,] array = new int[4, 3];
					array[0, 0] = 1316937854;
					array[0, 1] = 908578722;
					array[0, 2] = 438873039;
					array[1, 0] = 1358083067;
					array[1, 1] = -2040794875;
					array[1, 2] = 612244745;
					array[2, 0] = 692110702;
					array[2, 1] = -1832146393;
					array[2, 2] = 601577594;
					array[3, 0] = 1171886571;
					array[3, 1] = 171153811;
					array[3, 2] = -425466257;
					array[2, 0] = array[0, 2] ^ -1552533628;
					array[3, 0] = array[3, 2] ^ 0x184B6A9A;
					array[0, 1] = array[3, 1] ^ -482837956;
					array[3, 0] = array[1, 1] ^ -776260768;
					int num11 = array[3, 0] ^ 0x7F8DDA2F;
					num = ((int)num4 * -424867936) ^ 0x24E86CA0 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static AsyncTaskMethodBuilder _002F_002F_002A_002D_0040_0024_0024_0025()
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
				int num = 1826619930;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(num2 * 1970940923) + ~(-(~(-(-2144506374 ^ 0x70152228))))))) % 3;
					int num5 = 1962063596;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 1962063596;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2031374147;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 2094937451;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2038437387;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x79801609;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = AsyncTaskMethodBuilder.Create();
					int[] array = new int[5];
					array[0] = 1265647522;
					array[1] = -1575822213;
					array[2] = -1876939211;
					array[3] = 1763664295;
					array[4] = 962696901;
					array[4] = array[3] ^ -1265972264;
					array[0] = array[3] ^ 0x40143446;
					array[4] = array[1] ^ -792439777;
					int[] array2 = new int[6];
					array2[0] = 1675794929;
					array2[1] = -1052470897;
					array2[2] = -1460316798;
					array2[3] = 1152960379;
					array2[4] = -1689948496;
					array2[5] = -195596173;
					array2[0] = array[3] ^ 0x4968B6A8;
					array2[1] = array2[4] ^ -966029059;
					array2[5] ^= -1361189314;
					array2[5] = array2[1] ^ 0x741D831A;
					int num11 = array2[0] ^ 0x6558B60;
					num = ((int)num4 * -1020791777) ^ 0x3EA77012 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static ExtendedActivationKind _002B_002D_003F_003F_003C_002B_0026_002F(AppActivationArguments P_0)
	{
		ExtendedActivationKind kind = default(ExtendedActivationKind);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1625346250;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(num2 ^ ~((-((--1448326115 ^ -1943121177 ^ 0x9CC593D) + (-1263558522 - ~(-216694264 ^ -78042433))) ^ 0x44AFA331 ^ (-(1355868711 * -(-(-392697530))) ^ (~(1141080740 * -441464055 - 553575806) * -914234021 - (~((1098121474 + -533538294) * 797049457) - ~(-(1752742637 + 1256605645)))))) + ~(-1846877317 ^ ((-421145931 ^ 0x564AC291) + ((2064515956 - -349306412) * 1139416009 + (-234172420 - -1903562474 - --1125563796) + ((--1811156992 - (0x6390D970 ^ 0x64A0464A)) ^ -1181160906)))))) * 1971358809 - (-857154397 - ~(~((--1739968320 ^ 0x3EE20B5E) * -1614443121)))) * 1793323943)) % 3;
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
					int num7 = -117346351;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = 1323828791 - (num7 + (-1251454331 - 624463725));
						num7 = ~(num7 * 1035465173);
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
					kind = P_0.Kind;
					int[] array = new int[6];
					array[0] = -779190798;
					array[1] = 959101553;
					array[2] = 1847933211;
					array[3] = 2005414709;
					array[4] = -1904930936;
					array[5] = -2063156455;
					array[1] = array[2] ^ 0x2E10D2D9;
					array[2] = array[4] ^ -1808102702;
					array[0] = array[3] ^ 0x3A9CD1B;
					int[] array2 = new int[7];
					array2[0] = 443811204;
					array2[1] = 187575436;
					array2[2] = 32147781;
					array2[3] = 407617622;
					array2[4] = -6975019;
					array2[5] = -580192909;
					array2[6] = -1001267915;
					array2[4] = array[4] ^ 0x67CFA93F;
					array2[3] = array2[0] ^ -1063510301;
					array2[3] = array2[0] ^ -1400898961;
					array2[3] = array2[2] ^ 0x1423D52B;
					int num11 = array2[4] ^ 0x68114653;
					num = (int)((num4 * 1804647700) ^ 0x19E404C8) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return kind;
	}

	static object _002F_003C_002B_0026__003E_002A_002F(AppActivationArguments P_0)
	{
		object data = default(object);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 33805545;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((~(-998483960 - ~(-num2 - (-(~(72759193 * -819239661)) - 228063835 * (-1748875171 * -(-197412165 * (-596016606 * -967119415))))) * -847628873) ^ 0x20D30F4F) - --1942297120))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(num5 * -656489911);
						num5 = -num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 601977463;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = 601977464 - num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1627369504;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 ^= -795711245;
							num9 = 332994108 - (num9 + (-394579116 - -1087680516));
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					data = P_0.Data;
					int[] array = new int[7] { 611363280, 290770914, -1440380606, -1329356968, 444040915, -261371435, -97074839 };
					array[0] ^= -421700090;
					array[2] = array[1] ^ -1686537424;
					array[0] ^= -1049218575;
					int[] array2 = new int[5] { 475622699, -1616999291, 1101139329, 487374862, -607508714 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][3] ^ -452011890;
					array2[3] = array2[2] ^ 0x1BB9DBDC;
					array2[2] = array2[1] ^ 0x6609E1F9;
					array2[0] = array2[4] ^ -552706458;
					int num11 = array3[1][1] ^ -1268723460;
					num = (int)((num4 * 1611734410) ^ 0x867B2BC4u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return data;
	}

	static IReadOnlyList<IStorageItem> @_005E_0029_0028_005E_0040_003F_0024(IFileActivatedEventArgs P_0)
	{
		IReadOnlyList<IStorageItem> files = default(IReadOnlyList<IStorageItem>);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1605382316;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-447463557 - ~(-(num2 - ((1293933265 * ~(~(((-(1701538385 - -314710578) + -(1193470521 * -665416729)) ^ -(-487372090 * -1923840023)) - ~(~(~(-442671887 ^ 0x5796B02A)))))) ^ -(-(~(~(~(~(269501833 * (-1196732480 ^ -2008642319))))))))) * -1452476063) * -1350799677 - -401789517 * (-52087025 - 1392992195 + -583783525 * -183187949)))) % 3;
					int num5 = 2;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 ^ -241928468;
						num5 = ~(num5 ^ 0x7F7D5E94);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 3;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(-num7);
						num7 = -(-num7);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= -1231629137;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					files = P_0.Files;
					int[] array = new int[5];
					array[0] = -1289096349;
					array[1] = 1871082201;
					array[2] = -1036222728;
					array[3] = 1432004824;
					array[4] = -821438773;
					array[1] = array[0] ^ 0x30FB56BC;
					array[1] = array[4] ^ -381271370;
					array[1] = array[4] ^ 0x37CE1346;
					int[] array2 = new int[5] { -212787864, 1999702486, -215494422, 100263693, 1137782318 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][0] ^ 0x478225EF;
					array2[0] = array2[2] ^ -1240624875;
					array2[0] = array2[3] ^ 0x2C5A7FC8;
					array2[1] = array2[4] ^ 0x38839F91;
					int num11 = array3[1][2] ^ -1457624764;
					num = (int)((num4 * 169721381) ^ 0x66D320D2) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return files;
	}

	static string _003D_0028_0029_0021_003C_0024_002B_002D(StorageFile P_0)
	{
		string path = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1024691745;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(-(num2 - (~(~((-(-446389441) - (-(--2001267908) - (-40421916 ^ 0x638BC2CD))) * 824461323 + (~(416470575 * (1404020580 * -1304981521 * 1708674221)) + (-1973905616 + -2000296402 - ~(-1718803590 ^ 0x6238162E) + -956862052)))) - -(-1554127527 * (-198786415 * (768521401 * -1222605239 + 835325407 * 651124922)) + (~(982237409 * 741562963) - -1102450140) - (1066350897 - ((-1384990882 ^ -1078142369) + -((0x40C2D26F ^ 0x3C9B66A) * 955274569))) + (~(-(~(1140323774 - -989296953 + 1943888511 * -2039158184))) - (-(--833006472 ^ 0x5AA7C201) - (-(~1358226451 + (0x8F4B5A2 ^ 0x8BE3909)) + -1005121812)))))) * -1789697523) * 1106409467 + (~(-(-1054456877 ^ -517200809)) ^ 0x16C80ADE)))) % 3;
					int num5 = 1264660417;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 += -1264660417;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -117183655;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -1125667607;
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
					path = P_0.Path;
					int[] array = new int[6] { -582850364, -604206289, -1370439511, 505418884, 777054803, 1086737991 };
					array[3] ^= -1591009180;
					array[1] = array[5] ^ 0x70EA097C;
					int[] array2 = new int[5];
					array2[0] = 315903503;
					array2[1] = 852845502;
					array2[2] = -2099909755;
					array2[3] = 910999171;
					array2[4] = -897580565;
					array2[0] = array[2] ^ 0x1A876833;
					array2[2] ^= 1183759044;
					array2[1] = array2[3] ^ -117493407;
					array2[1] = array2[2] ^ 0x47BABF48;
					int num11 = array2[0] ^ -1848768521;
					num = (int)((num4 * 499573993) ^ 0x4BD3EB91) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return path;
	}

	static string _0021_005E_0029_002F_003E_003D_002B_0024(ILaunchActivatedEventArgs P_0)
	{
		string arguments = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1797392212;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-212837428 + 1862584987 - (-(-(-(-(num2 ^ (--819778492 ^ ((((--1994978051 - -671004763 * 816964457) ^ -(-588433280 ^ 0x58F8722A)) * 1855051479) ^ -2046144936) ^ ~(-(733748487 * -2078845042)) ^ -(~(~(~(0x3B4E147F ^ --342908727) ^ -(-377347703 ^ 0x737BE1C0)) - (0x338146B7 ^ (609509457 - -(-20149237 ^ --589731939))))))) * 655971217) + -1792194037 * (58101165 * (1571228172 + -424195163) + 1343161391 * 364280969 + (-(-875443049 * 500324976) + (-1674415913 * -32467098 + ~112536975))))) ^ 0x383201E1)))) % 3;
					int num5 = 903862672;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 -= -1779906201 ^ 0xC5E0878;
						num5 = 2126959703 - -num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 939528202;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 + -1672098058 - 1622716595;
						num7 = (num7 ^ -738199560) + -112608135;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1155216084;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 1155216083;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					arguments = P_0.Arguments;
					int[] array = new int[7];
					array[0] = -1584042959;
					array[1] = -1708390987;
					array[2] = -1331666524;
					array[3] = -1332514356;
					array[4] = -1122239731;
					array[5] = -225814868;
					array[6] = -278013704;
					array[4] = array[2] ^ -1885361232;
					array[2] = array[0] ^ -361267837;
					int[] array2 = new int[6];
					array2[0] = -307901413;
					array2[1] = 1674601810;
					array2[2] = -1405876215;
					array2[3] = 1398257745;
					array2[4] = 1721952264;
					array2[5] = -1148600985;
					array2[0] = array[1] ^ 0x488C34CB;
					array2[1] = array2[0] ^ -1437904706;
					array2[2] = array2[4] ^ 0x1F2904F5;
					int num11 = array2[0] ^ 0x3EF8FAB8;
					num = ((int)num4 * -1767357674) ^ 0xD593668 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return arguments;
	}

	static bool __002D_002A_002B___003E_0040(IEnumerator P_0)
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
				int num = -491922569;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((num2 ^ -((~(-(1832489002 - -1110569980)) ^ -2120367297 ^ 0x23B51463) + (~(-(~(-1448390164 ^ 0x14560D70))) ^ 0x1941CB68) - ((-437568810 ^ -(-904176036 + -1485610506 + -1467671118 * -808344113)) + -831071380 + -679906414) + (~(-1105831072 * -333282769) + -694578495 * -743279739))) - ~(~(-1343881617 * ~(~((-316353403 ^ 0x5B064866) + 534425115) - (-658490867 - 522370509 + (0x1F16314C ^ -1477270358) - 1134851217 * -800679571)))) + -1754803613 * -903657181 + ((-1494607063 ^ ((-797632488 ^ -1520702162) + (5728024 - -736743924) * -419532017 - (-(-1635316871) + -1899057129))) - ~(-957552289 ^ 0x6201BFF4))))) % 3;
					int num5 = -1692479686;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= -1695459659;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 790642873;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 - -1886680998) ^ 0x48679903;
						num7 = ~(-num7);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -806788208;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 += -33413703;
							num9 = (num9 * -1014816641) ^ 0x2797976D;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.MoveNext();
					int[,] array = new int[3, 3]
					{
						{ 1658231479, -586708131, 1330859936 },
						{ 486824426, -936074402, -454417703 },
						{ -934435581, 2098776219, 1112198831 }
					};
					array[0, 0] ^= -1137848482;
					array[2, 2] = array[2, 0] ^ -1874016883;
					array[0, 0] = array[1, 0] ^ -567300286;
					array[2, 2] = array[1, 2] ^ 0x306356C6;
					int num11 = array[2, 2] ^ 0x1B4D880D;
					num = (int)((num4 * 2008779764) ^ 0xEC68C684u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void ____0024_0029_003C_005E_0029(IDisposable P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -572403987;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(~(-num2 ^ ~(~((0x7A9338E7 ^ -694699241) - (-1459559502 + (0x18D3D678 ^ 0x5C64189E) * -83604757))) ^ (1837296784 - ((-1336393389 - ~(1433317083 * --84465089)) ^ (-((-2019978130 - 2036161983) * -1896891779) + (0x398519C9 ^ -(1310851882 + 1245582526))) ^ (-814564421 * ((-1250994025 ^ (-112551853 * --2033147058)) + (-(1916551047 + 659647301) + ((0x5B72E456 ^ -1836934025) + (1968414283 + -1303991124)))))))))))) % 3;
					int num5 = -1855740626;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 ^ 0x67BBE9DF) + 917107239;
						num5 = ~(num5 * -283610015);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1598589727;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = -1598589725 - num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1718494936;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = 1718494937 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Dispose();
					int[] array = new int[7];
					array[0] = -966930485;
					array[1] = 1397438277;
					array[2] = 1398099814;
					array[3] = -1738112103;
					array[4] = 686835830;
					array[5] = -1937233719;
					array[6] = 1732825832;
					array[1] = array[2] ^ 0x424CED61;
					array[2] = array[1] ^ -786881254;
					int[] array2 = new int[4] { 2009820381, 1866382286, 1478038882, 1388212604 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][6] ^ 0x7711D4F1;
					array2[3] = array2[0] ^ -1032941434;
					array2[2] = array2[0] ^ -1312507753;
					array2[3] = array2[2] ^ -1034441708;
					int num11 = array3[1][1] ^ -1446406827;
					num = ((int)num4 * -1792830893) ^ -878378109 ^ num11;
				}
			}
		}
	}

	static bool _003E_002D_0023_0026_0040_005E_0023_002F(string P_0)
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
				int num = -1130348719;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((-((~(-(~num2 + (~(~(~(--887807443))) + ~((0x2A87723 ^ 0x115EAF85) * -927588449 - 416166654) + -70282389 * ~(-(-936265178 + -2055491468) - -(664263205 * -745021547)) + ~(~(-312741032 - 970700514 + (-779369909 * 882691513 - -2018501327 - ~(~101614834)))) - ~(-159161979 * (-2089780447 * -(0x49282487 ^ 0x559E0B2A) - 1254518843))))) * 1815907293) ^ (-(-1890419519 - -1311147421) + (~(0x530B3F1E ^ -842107056) + (-1349045458 ^ -2111387910)))) + -(--259761244)) ^ -117119635))) % 3;
					int num5 = -613215245;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= -613215245;
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
						int num9 = -1212997721;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9 - -778183944;
							num9 = ~num9 - -1384682805;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = File.Exists(P_0);
					int[] array = new int[5] { -1239644344, -503543695, 1494459271, 1635680719, -1753327821 };
					array[4] ^= 379925912;
					array[4] = array[1] ^ 0x6EDF1BB1;
					int[] array2 = new int[6];
					array2[0] = 948448351;
					array2[1] = 1766423121;
					array2[2] = -2069990784;
					array2[3] = 159135921;
					array2[4] = 645424238;
					array2[5] = 1694388558;
					array2[0] = array[2] ^ 0xBA85382;
					array2[3] = array2[2] ^ -760011044;
					array2[4] = array2[5] ^ 0x2ABC372D;
					array2[2] ^= -222265760;
					int num11 = array2[0] ^ 0x4FC1FA1C;
					num = ((int)num4 * -816513021) ^ -1116121894 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string _0023_0024_005E_002D_005E_0029_0040_0028(string P_0)
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
				int num = -200191296;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(((-num2 + (-(~(-1419085168)) * -1709228301 - (-2139997041 + -1724043448 - (-385618476 + 836774607 - 973394908 - -(--1721088032))) + -(--5011900 ^ -990290778 ^ (-1981288017 * -758957899 + -1116614616)) * -913079035 - ((-(-(-1091814840)) + 1121321512 - ~361659598) ^ ((~1951700828 - 1374584241) * 747031233 - (~(~(0x3D6DB92A ^ -64932779)) + (-492022798 ^ -1541497649))))) * 1854389135 - (1917016350 - --1572470591) - -2098010369 - -881728078) * 2020106583 - -1799213951) ^ -540463192)))) % 3;
					int num5 = 134872580;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 - -33335902) ^ 0x4138CABD;
						num5 = num5 - ~1588708006 - 634072731;
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
						int num9 = -1193942526;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 -= 763778272 * 1745337671;
							num9 = (num9 * 280387009) ^ 0x52890026;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.Trim();
					int[] array = new int[4];
					array[0] = -1338669352;
					array[1] = -1875827793;
					array[2] = -2139716140;
					array[3] = 1043755278;
					array[2] = array[0] ^ -1697391407;
					array[2] = array[0] ^ 0x53487D35;
					int[] array2 = new int[7];
					array2[0] = 84865171;
					array2[1] = 606159302;
					array2[2] = -1913984780;
					array2[3] = -1225301527;
					array2[4] = 784187211;
					array2[5] = -2092062575;
					array2[6] = 832574905;
					array2[1] = array[0] ^ -32753067;
					array2[2] = array2[5] ^ -235374932;
					array2[3] = array2[1] ^ 0x72802F67;
					array2[5] = array2[1] ^ -126934065;
					int num11 = array2[1] ^ 0x1D6C75FF;
					num = (int)((num4 * 1027074815) ^ 0xD56CB404u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string _0026_0026_005E_005E_003C_005E_002D_0024(string P_0, char P_1)
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
				int num = 1931048504;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(~(~(-num2 - ((((1890091302 * -1415971555 - ~-787849287 + (--1469862105 ^ -2001317208)) * 585123717 + ~-307944902) * 303606337 - -1920820983 * -121972937) ^ ((((-929810262 ^ -1152313103) + --882189299) ^ 0x6043BB15) * -320558983 * -1898940041 - ((-1792850782 ^ 0x16D094DD) + (~(--242698783) ^ -(-373398511))) * -547128967 + (-(-1827267801 * -714837033) - 705733005 * -794467883)))))) ^ -((-1982940075 ^ -1288308979) + (-234576532 + -829815420 + (0x2D3998B8 ^ -790217633)))) * -334666733 + ~(-1154038986 * -89933749))) % 3;
					int num5 = 2114878532;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(-num5);
						num5 = (num5 ^ -1193889512) + 1344958678;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 123942824;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x76337AA;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2117212949;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9 ^ 0x155421FC;
							num9 = num9 * -773853557 - -72482529;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.Trim(P_1);
					int[] array = new int[5] { 922684097, 672950169, 1772972436, 1653131678, 115146665 };
					array[4] ^= -1895674893;
					array[3] = array[0] ^ -176751328;
					array[1] = array[3] ^ 0x21D7A4E6;
					int[] array2 = new int[4];
					array2[0] = 2062191408;
					array2[1] = -181153904;
					array2[2] = 1335916966;
					array2[3] = -464166662;
					array2[0] = array[2] ^ 0x71F3AEF1;
					array2[1] ^= 1891468606;
					array2[3] = array2[1] ^ 0x31AAB4BA;
					int num11 = array2[0] ^ -510897227;
					num = (int)((num4 * 1672083492) ^ 0xCA5CE8E8u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string _002D_0028_0029_0025_0029_0028_0023_005E(string P_0)
	{
		string fullPath = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1713207872;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~((-(num2 * 28980533 - -((((~(-(~-1500337892)) ^ -255972372) + (-2096482158 ^ (-669761114 * 1595759289 - (-13995941 - 1122892669 * -905601155)))) * 892034075) ^ -(~((396644461 * -(~-626875742)) ^ ~(-(-1895364964 + 569062224)))))) * 1810454751 + -2056213526 - -(513055501 * -857425733 - -1129300815)) * 251411861) - -251742320))) % 3;
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
					int num7 = 1654208231;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 * -427162157;
						num7 = num7 + -1005123358 - 609416347;
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
					fullPath = Path.GetFullPath(P_0);
					int[] array = new int[4];
					array[0] = -1514906345;
					array[1] = -639601551;
					array[2] = 1288791365;
					array[3] = 987189372;
					array[1] = array[3] ^ -2041459891;
					array[1] = array[0] ^ 0x4B33A02;
					int[] array2 = new int[4] { -199987675, -1946797454, 803239769, -1206779950 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][3] ^ 0x7DC3C045;
					array2[2] = array2[1] ^ 0x23B3717C;
					array2[3] ^= -1563129345;
					array2[1] = array2[0] ^ -489264338;
					int num11 = array3[1][0] ^ 0x4E2B0F5D;
					num = ((int)num4 * -19339331) ^ 0x6202D646 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return fullPath;
	}

	static string _002D_0021_0040_0023__005E_0040_0025()
	{
		string processPath = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -518284640;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(~num2) * 591219091) ^ -530479484)) % 3;
					int num5 = 1530457310;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= -1095784305;
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
						int num9 = 1381728810;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9 * 82259075;
							num9 = -(-num9);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					processPath = Environment.ProcessPath;
					int[] array = new int[5] { 200871441, -36940500, 2139597323, -1644390054, -2107293088 };
					array[4] ^= -1333234874;
					array[3] = array[4] ^ -1915488594;
					int[] array2 = new int[7] { 207695545, -1570642839, -1928580391, -2020480728, -477841283, 1552102910, 1527229714 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][1] ^ -35737877;
					array2[1] = array2[3] ^ -1261574039;
					array2[3] ^= 1914269723;
					int num11 = array3[1][4] ^ 0x6418115B;
					num = (int)((num4 * 441988579) ^ 0x49F0FD05) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return processPath;
	}

	static bool ___0029_002B_0025_0024_003E_0021(string P_0, string P_1, StringComparison P_2)
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
				int num = -1748400219;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((-((-(~-805252840) - -246655115) ^ 0x5F95073B) + (1769637259 * -(~(-77174517 ^ -1041195423)) + (-2116648305 - -(0x7A338D8 ^ -661453764))) - (num2 * 2041374625 - ~(-(-(-(~(-2053211190 ^ 0x4768D78D) + -(-(~-1064421101))))))) * -2036844341) ^ -417073564) - -1251643645)) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= -187255649;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1616285110;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 1202895533;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1835746233;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 * 263801545 - -2041446326;
							num9 = ~num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = string.Equals(P_0, P_1, P_2);
					int[] array = new int[5] { -559324708, 1599718093, 703106831, 448711817, 63517236 };
					array[3] ^= 675012917;
					array[1] = array[2] ^ 0x52737696;
					int[] array2 = new int[6];
					array2[0] = 1760987242;
					array2[1] = 722248172;
					array2[2] = -1462859718;
					array2[3] = 2099908950;
					array2[4] = -1538203419;
					array2[5] = 1320499857;
					array2[0] = array[0] ^ 0x2FF74E6A;
					array2[3] = array2[0] ^ -1169744608;
					array2[4] = array2[1] ^ -1658651792;
					int num11 = array2[0] ^ 0x41A30642;
					num = ((int)num4 * -42697702) ^ 0x2C8F28A0 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string _0028_0023_003F_0024_003F_0021_003E_(string P_0)
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
				int num = 595131271;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(~(-num2) * -1621357195 + -544836739 * ((~(-21060781 * (0x7CE97C70 ^ 0x2DE973DE)) - 806973650) * -1130320681) - -((-617134872 - -245832937 - -149344284 - ~315034445) ^ 0x1DFE52EF) - (-((-339604105 ^ 0x7101325E) + ~-1303160751) - ((-125513439 ^ 0x5CF4221C) + -413403902 * -968393963)))) * -1583990051)) % 3;
					int num5 = 22668302;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 - (1974360744 - 28445123));
						num5 = (1284419825 - 321737084 - num5) ^ -682423112;
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
						int num9 = 420240898;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ -1215399672) - -642598661;
							num9 = ~num9 - -1635163138;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					extension = Path.GetExtension(P_0);
					int[,] array = new int[4, 3];
					array[0, 0] = -601942000;
					array[0, 1] = -667987718;
					array[0, 2] = 112188476;
					array[1, 0] = -1458805511;
					array[1, 1] = -2019525345;
					array[1, 2] = 1232525413;
					array[2, 0] = 1728959009;
					array[2, 1] = 429267081;
					array[2, 2] = 2041064149;
					array[3, 0] = -1327894998;
					array[3, 1] = -1602361499;
					array[3, 2] = 1935151892;
					array[1, 1] = array[3, 1] ^ -130315098;
					array[2, 1] = array[1, 1] ^ 0x5622D41C;
					array[1, 1] = array[0, 2] ^ -1567981144;
					int num11 = array[1, 1] ^ 0x39B7F9DA;
					num = (int)((num4 * 660627850) ^ 0x9936FD22u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return extension;
	}

	static void _0021_0024_003D_002D_003E_002F_0028_003D(object P_0, Uri P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1957768494;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((~(~(~(~-70022107 * 182781165)) - num2 - (-499943025 * (-(-(-2027858039 + (294081907 + -144828988))) - (~(950840395 * 848602267) - -406677163 * --2106908020 + 1866161494)) - ~(((1541525921 + 684443326 - -1229693301) ^ 0x64F77249 ^ 0x7FCED260) - (0x15FE382E ^ 0x725B6C97)) - 37233879 * ((~(-(~(-932411245 + 2087828063))) ^ (-1874297800 * 1047519707 + ~-614933744 - ~(1192173540 + -1994497327) + -(-1147669782 + (-2021967019 ^ 0x64D9480E)))) * -1777902139))) ^ -1125627584) - 1465685897 * (~-1224738958 - -1279645973 * -1656938051 + -1343429770) - -2100998027) ^ (-(0x725906A3 ^ -1385517234) ^ ~(--1718748606)))) % 3;
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
					int num7 = 1274895061;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -1803088259;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9;
							num9 = num9 - (0x151BB79F ^ 0x7E4F4512) - 592207893;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					Application.LoadComponent(P_0, P_1);
					int[] array = new int[6];
					array[0] = 1935277769;
					array[1] = 723881822;
					array[2] = -317497603;
					array[3] = -216057031;
					array[4] = -279486216;
					array[5] = -987715193;
					array[0] = array[3] ^ -1776500035;
					array[1] = array[0] ^ 0x52C5B820;
					array[2] = array[3] ^ -1859975315;
					int[] array2 = new int[5];
					array2[0] = 1625974669;
					array2[1] = -141354901;
					array2[2] = -330155130;
					array2[3] = -1989736298;
					array2[4] = 924490155;
					array2[0] = array[4] ^ 0x3FB1E7BB;
					array2[4] = array2[0] ^ -1041669078;
					array2[2] = array2[1] ^ -1850557323;
					int num11 = array2[0] ^ -436575528;
					num = ((int)num4 * -523411182) ^ -2022126990 ^ num11;
				}
			}
		}
	}
}
