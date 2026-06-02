using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using RikaNET.Core.Models;
using RikaNET.Core.Services;
using RikaNET.WinUI.Services;

namespace wkj_003D;

public sealed class sEp_003D : IProtectionService
{
	private sealed record UploadTicket(string EncryptedFileReference, string FileId, string ApiKey)
	{
		[CompilerGenerated]
		private Type EqualityContract
		{
			[CompilerGenerated]
			get
			{
				return _002D_002F__003E_0025_002B_0028_003D(typeof(UploadTicket).TypeHandle);
			}
		}

		[CompilerGenerated]
		public override string ToString()
		{
			StringBuilder stringBuilder = new StringBuilder();
			while (true)
			{
				int num = 1378180752;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(2002800282 - -485660265 - (-(~((~(-925239599 - (-(-12248031 * ((-1462526487 ^ 0x27FB6D91) + 1324847019) - -(~(--537391443))) ^ -1043296721 ^ (-360491469 * (-(~(--1311834319 - 1015731242)) * 610679851)))) - num2 - -1846893437 * (((-(~(0x2C2FED8D ^ 0x7664034A)) - (-1784942035 + 1117620506 - (1696397048 - 850584517) - --437752336)) ^ 0x455214B6 ^ (~(~2086245155 * 2011953055 + -(-1775598415 * 1646401393)) + 1027851644)) * 1370628415)) * -642735643 + ((0x2FB7FE02 ^ -(~(-1170310169 - (-815050970 ^ -1284258442)))) - (-431494064 ^ 0xAABFBA0))) - --122990023) + (-870251769 - -1699259703)) + 2077692354)) % 6;
					int num5 = 690710792;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0x292B690C;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1978413873;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -1978413874;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 371667724;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 - (-846013660 ^ 0x36B9ACB7)) ^ 0x6A8C2572;
							num9 = num9 - ~-1779261228 - -1512135335;
						}
						if (num3 != (uint)num9)
						{
							int num11 = -1466762345;
							_ = 0;
							for (int num12 = 0; num12 < 2; num12++)
							{
								num11 = (num11 ^ -1702024408) * -121320429;
								num11 = ~num11 * 1221011951;
							}
							if (num3 != (uint)num11)
							{
								int num13 = 0;
								_ = 0;
								for (int num14 = 0; num14 < 2; num14++)
								{
									num13 = num13 * 230915185 * 1918808707;
									num13 *= 1519684183;
								}
								if (num3 != (uint)num13)
								{
									int num15 = -486539259;
									_ = 0;
									for (int num16 = 0; num16 < 2; num16++)
									{
										num15 = ~(num15 ^ 0x696A1F3F);
										num15 = 812308484 - (num15 + 1183858514 * -718526957);
									}
									if (num3 != (uint)num15)
									{
									}
									return _005E_002F_0023_0028_0026_0026_0028_((object)stringBuilder);
								}
								_002D_0021_003C_0029_0023_0024_003F_0029(stringBuilder, '}');
								num = 2066479682;
							}
							else
							{
								_002D_0021_003C_0029_0023_0024_003F_0029(stringBuilder, ' ');
								int[] array = new int[5];
								array[0] = 2029673903;
								array[1] = -529792161;
								array[2] = 542684695;
								array[3] = 177732371;
								array[4] = 1930738728;
								array[3] = array[0] ^ -2032670832;
								array[4] = array[0] ^ -1498010755;
								int[] array2 = new int[4] { 1285090561, -1278137542, -30094434, 1357161145 };
								int[][] array3 = new int[2][] { array, array2 };
								array2[1] = array3[0][1] ^ 0x7644CDD0;
								array2[0] = array2[2] ^ -110796048;
								array2[2] = array2[0] ^ -348312330;
								int num17 = array3[1][1] ^ -670482796;
								num = (int)((num4 * 763826395) ^ 0xDC51D121u) ^ num17;
							}
						}
						else
						{
							_0024_002B_002F_0028_002A_0040__003E(stringBuilder, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x81A5 ^ 0x8041))]);
							bool num18 = PrintMembers(stringBuilder);
							int[] array4 = new int[4] { -1306884482, -1732505999, 720398151, -263987943 };
							array4[0] ^= -218011003;
							array4[2] = array4[0] ^ -1863102385;
							array4[0] = array4[3] ^ -1438580661;
							int[] array5 = new int[5];
							array5[0] = 18368501;
							array5[1] = 1893157095;
							array5[2] = 1558018833;
							array5[3] = 390454759;
							array5[4] = -1566183499;
							array5[1] = array4[1] ^ -962040219;
							array5[4] ^= 2069028997;
							array5[3] ^= -1422110675;
							int num19 = array5[1] ^ 0x1035900F;
							int[] array6 = new int[4];
							array6[0] = -1809330395;
							array6[1] = 1499767741;
							array6[2] = -1620242214;
							array6[3] = 1285265956;
							array6[1] = array6[3] ^ 0x67528720;
							array6[1] ^= -1236805326;
							int[] array7 = new int[5] { -1780708744, -1768413068, -719476406, 1843841952, -1724613836 };
							int[][] array8 = new int[2][] { array6, array7 };
							array7[0] = array8[0][3] ^ -1463257958;
							array7[3] ^= 22331834;
							array7[2] = array7[0] ^ 0x345BF350;
							int num20 = array8[1][0] ^ -1384590540;
							int num21 = (int)((num4 * 1293746184) ^ 0x74505D0);
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
					else
					{
						_0024_002B_002F_0028_002A_0040__003E(stringBuilder, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-949 + 465)]);
						int[] array9 = new int[4];
						array9[0] = -456962601;
						array9[1] = 320677747;
						array9[2] = 858566354;
						array9[3] = 158014955;
						array9[0] = array9[2] ^ 0x2B843BAC;
						array9[0] = array9[3] ^ -1717947046;
						int[] array10 = new int[7];
						array10[0] = -1791907823;
						array10[1] = 1053789999;
						array10[2] = 924637127;
						array10[3] = 1600656575;
						array10[4] = 1792168537;
						array10[5] = -234320450;
						array10[6] = 1540591008;
						array10[0] = array9[2] ^ -795428109;
						array10[5] = array10[4] ^ 0x4EFD583A;
						array10[2] = array10[1] ^ 0x3ED11E5F;
						array10[5] = array10[3] ^ 0x3DF2C7E;
						int num24 = array10[0] ^ -527678172;
						num = ((int)num4 * -392291424) ^ -79399520 ^ num24;
					}
				}
			}
		}

		[CompilerGenerated]
		private bool PrintMembers(StringBuilder builder)
		{
			@_0028_003C_003C_003E_002F_002B_003C();
			while (true)
			{
				int num = -1232470080;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(((-num2 - -(-(-(-(-(-1282265022 - 1844713517)))) - -(~(-2048698671 * ~-622445036)) * 248053577 - ~((-415402548 ^ ~((0x399F54E2 ^ 0x395129F) + --1561197989)) * -7566135)) - ((-1349496939 * (--615814908 - -797255346) - (~(1970276812 - 540253576) + ~(-1620399059 + 1512033292)) - -1896868148) ^ 0x1B22EDB0 ^ 0x7BA07A74)) ^ ((((0x72DF26AD ^ -(0x6B705914 ^ 0x4829D092)) + (-1180794169 - (-890194369 ^ -618348425) - ~(-662709109))) * -22792571) ^ (-1696180891 - ~(--514420068 ^ -403867730)))) - (-55283226 + (79271461 + (-1181659436 ^ 0x35093403)))) * 1101182515)) % 8;
					int num5 = 196617;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~854374704 - num5 + -1999496680;
						num5 = -num5 ^ 0x2B7E7FAD;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -922827156;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -922827163;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1878850654;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 * 82523089 * 2015148663;
							num9 = num9 - -608037301 - 640084984;
						}
						if (num3 != (uint)num9)
						{
							int num11 = -1923176757;
							_ = 0;
							for (int num12 = 0; num12 < 1; num12++)
							{
								num11 += 1923176759;
							}
							if (num3 != (uint)num11)
							{
								int num13 = -316589431;
								_ = 0;
								for (int num14 = 0; num14 < 2; num14++)
								{
									num13 = (num13 + -1577000682) * -246617865;
									num13 = num13 - 954810502 * 1426959733 + 1569999311;
								}
								if (num3 != (uint)num13)
								{
									int num15 = -354171845;
									_ = 0;
									for (int num16 = 0; num16 < 2; num16++)
									{
										num15 = -(num15 * 1819525707);
										num15 = ~(num15 - -486725767);
									}
									if (num3 != (uint)num15)
									{
										int num17 = 632345163;
										_ = 0;
										for (int num18 = 0; num18 < 1; num18++)
										{
											num17 += -632345163;
										}
										if (num3 != (uint)num17)
										{
											int num19 = -446023348;
											_ = 0;
											for (int num20 = 0; num20 < 2; num20++)
											{
												num19 = (num19 - (-625020691 - 1035489913)) * -1851184595;
												num19 = (num19 - -814931353) ^ -1047976743;
											}
											if (num3 != (uint)num19)
											{
											}
											return true;
										}
										_0028_0024_002F_0023_002D_0024_0024_003F(builder, (object)ApiKey);
										int[] array = new int[7];
										array[0] = -64800417;
										array[1] = 1037946756;
										array[2] = 689668270;
										array[3] = -751646199;
										array[4] = -736179139;
										array[5] = 1656906434;
										array[6] = -731476462;
										array[5] = array[4] ^ 0x15D68AC2;
										array[4] = array[0] ^ -935025407;
										int[] array2 = new int[7];
										array2[0] = -1151773133;
										array2[1] = -443208402;
										array2[2] = 1429111259;
										array2[3] = -42153514;
										array2[4] = -1132620939;
										array2[5] = 791343040;
										array2[6] = -1731061759;
										array2[3] = array[0] ^ 0x772F58;
										array2[5] = array2[2] ^ 0x6DCF6BA1;
										array2[2] = array2[5] ^ 0x2D346031;
										int num21 = array2[3] ^ -2118374864;
										num = ((int)num4 * -511132362) ^ -2082757600 ^ num21;
									}
									else
									{
										_0024_002B_002F_0028_002A_0040__003E(builder, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[4569 - 4181 + 99]);
										int[,] array3 = new int[4, 3];
										array3[0, 0] = -1787159801;
										array3[0, 1] = 2036646149;
										array3[0, 2] = -850425670;
										array3[1, 0] = 1923407055;
										array3[1, 1] = -1807489108;
										array3[1, 2] = -1976280705;
										array3[2, 0] = 1680344253;
										array3[2, 1] = 163778908;
										array3[2, 2] = 1509513007;
										array3[3, 0] = -1106063264;
										array3[3, 1] = 162257374;
										array3[3, 2] = 1510258164;
										array3[3, 1] = array3[1, 2] ^ 0x74299C10;
										array3[2, 1] = array3[3, 1] ^ -144929079;
										array3[3, 1] = array3[1, 0] ^ 0x3217F1A1;
										array3[2, 0] = array3[0, 0] ^ -1696775067;
										int num22 = array3[2, 0] ^ -2079709047;
										num = ((int)num4 * -682044338) ^ 0xDD3AECA ^ num22;
									}
								}
								else
								{
									_0028_0024_002F_0023_002D_0024_0024_003F(builder, (object)FileId);
									int[,] array4 = new int[4, 4];
									array4[0, 0] = -867131495;
									array4[0, 1] = 124930126;
									array4[0, 2] = 587160454;
									array4[0, 3] = -1924074433;
									array4[1, 0] = -993461161;
									array4[1, 1] = 86421683;
									array4[1, 2] = -1153281304;
									array4[1, 3] = -203889087;
									array4[2, 0] = 721930921;
									array4[2, 1] = 515740326;
									array4[2, 2] = -1567666907;
									array4[2, 3] = 1833459525;
									array4[3, 0] = 979076949;
									array4[3, 1] = 1654496206;
									array4[3, 2] = -1259240379;
									array4[3, 3] = -740984407;
									array4[0, 1] = array4[1, 3] ^ 0x39D760FB;
									array4[2, 3] = array4[3, 1] ^ -1533039687;
									array4[1, 1] = array4[3, 2] ^ -460332042;
									int num23 = array4[1, 1] ^ -411229841;
									num = ((int)num4 * -1872597092) ^ -208885380 ^ num23;
								}
							}
							else
							{
								_0024_002B_002F_0028_002A_0040__003E(builder, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[523 - 12 - 17 - 8]);
								int[,] array5 = new int[3, 3];
								array5[0, 0] = -1191619117;
								array5[0, 1] = -1806822994;
								array5[0, 2] = 1841894713;
								array5[1, 0] = -1114416140;
								array5[1, 1] = 824047233;
								array5[1, 2] = -2022110862;
								array5[2, 0] = -529262429;
								array5[2, 1] = 826818555;
								array5[2, 2] = -1885178338;
								array5[0, 0] = array5[0, 1] ^ -924526192;
								array5[1, 0] = array5[2, 1] ^ 0x219F70EC;
								array5[1, 1] = array5[2, 0] ^ 0x4395ED87;
								int num24 = array5[1, 1] ^ -1742687290;
								num = (int)((num4 * 1866580316) ^ 0x4E7BAFD8) ^ num24;
							}
						}
						else
						{
							_0028_0024_002F_0023_002D_0024_0024_003F(builder, (object)EncryptedFileReference);
							int[] array6 = new int[4];
							array6[0] = -1051339458;
							array6[1] = 18135093;
							array6[2] = -281729955;
							array6[3] = 654751634;
							array6[2] = array6[1] ^ -629703115;
							array6[3] = array6[1] ^ -1056941538;
							int[] array7 = new int[7];
							array7[0] = -1683003280;
							array7[1] = 1620899674;
							array7[2] = -1348831696;
							array7[3] = 1038562272;
							array7[4] = 682783523;
							array7[5] = -1399247395;
							array7[6] = 1413215419;
							array7[2] = array6[1] ^ 0x263E4321;
							array7[6] = array7[3] ^ 0x676C925A;
							array7[0] ^= -665019669;
							array7[4] = array7[6] ^ -1668513396;
							int num25 = array7[2] ^ 0x6B2818C9;
							num = (int)((num4 * 1825712139) ^ 0x7CCA2F0A) ^ num25;
						}
					}
					else
					{
						_0024_002B_002F_0028_002A_0040__003E(builder, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xF96 ^ 0xE73]);
						int[] array8 = new int[6];
						array8[0] = -269237878;
						array8[1] = 423091420;
						array8[2] = 1580564174;
						array8[3] = -2017848388;
						array8[4] = 1929359268;
						array8[5] = -708709898;
						array8[5] = array8[3] ^ 0x49FEEB5B;
						array8[0] = array8[4] ^ 0x601C0413;
						array8[0] = array8[5] ^ 0x27A3BB14;
						int[] array9 = new int[6];
						array9[0] = 357844954;
						array9[1] = -1296598640;
						array9[2] = 711079394;
						array9[3] = 1080508602;
						array9[4] = 1162053340;
						array9[5] = 1031010498;
						array9[5] = array8[1] ^ 0x42559D69;
						array9[1] = array9[5] ^ -78733439;
						array9[3] ^= 1812486257;
						array9[1] = array9[2] ^ -305560789;
						int num26 = array9[5] ^ -1146725572;
						num = ((int)num4 * -679805286) ^ 0x67CE8486 ^ num26;
					}
				}
			}
		}

		[CompilerGenerated]
		public bool Equals(UploadTicket? other)
		{
			if ((object)this != other)
			{
				uint num3;
				while (true)
				{
					int num = -185967887;
					while (true)
					{
						int num2 = num;
						uint num4;
						num3 = (num4 = (uint)((-(~((num2 ^ ~(456095263 * -(((-(-1060781721 ^ -1253481380) - -901247342) ^ -1907907408) - -1161288052) - (~-1103285392 - 1820794209))) * 1540198367)) - ((125325944 - ~1424221314 - 969069685) * -2007380945 - 1385172618)) * -1647794941 * 1987971063)) % 8;
						int num5 = 1197280467;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -(num5 ^ -1882260345);
							num5 = (num5 ^ --748205519) * -1542651929;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 850930012;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 ^= 0x32B8295E;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -923247119;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -1722946225 - num9 * -1576370993;
								num9 = -num9 + -1755039482;
							}
							if (num3 != (uint)num9)
							{
								int num11 = -2015401994;
								_ = 0;
								for (int num12 = 0; num12 < 2; num12++)
								{
									num11 ^= -1446179865;
									num11 = -659513413 - (-1280878872 - 252183899 - num11);
								}
								if (num3 != (uint)num11)
								{
									int num13 = -503367111;
									_ = 0;
									for (int num14 = 0; num14 < 1; num14++)
									{
										num13 = -503367107 - num13;
									}
									if (num3 != (uint)num13)
									{
										goto end_IL_000d;
									}
									bool num15 = EqualityComparer<string>.Default.Equals(FileId, other.FileId);
									int[] array = new int[5];
									array[0] = 1421701107;
									array[1] = 931376276;
									array[2] = 694980883;
									array[3] = 299535148;
									array[4] = 308246258;
									array[3] = array[4] ^ 0x5AE375AB;
									array[3] = array[2] ^ 0x63B389;
									int[] array2 = new int[4];
									array2[0] = -2114509991;
									array2[1] = -831705699;
									array2[2] = -1953636700;
									array2[3] = -208911484;
									array2[2] = array[1] ^ 0x6B52C7B2;
									array2[3] = array2[2] ^ 0x2A9F667C;
									array2[1] = array2[0] ^ 0x33AFD861;
									int num16 = array2[2] ^ -1344423566;
									int[,] array3 = new int[4, 4];
									array3[0, 0] = -1919593856;
									array3[0, 1] = -619334289;
									array3[0, 2] = 1724076490;
									array3[0, 3] = -767970325;
									array3[1, 0] = 1203830444;
									array3[1, 1] = 287417861;
									array3[1, 2] = 831907221;
									array3[1, 3] = 1852131323;
									array3[2, 0] = -424725503;
									array3[2, 1] = -642565752;
									array3[2, 2] = -870428548;
									array3[2, 3] = -737742468;
									array3[3, 0] = -1819964876;
									array3[3, 1] = -699684242;
									array3[3, 2] = -1978170048;
									array3[3, 3] = -1351909589;
									array3[2, 2] = array3[2, 0] ^ -866502252;
									array3[3, 3] = array3[2, 0] ^ -2130809749;
									array3[1, 2] = array3[3, 2] ^ -536410642;
									array3[1, 3] = array3[2, 3] ^ 0x2ABA71B6;
									int num17 = array3[1, 3] ^ -1628176284;
									int num18 = (int)(num4 * 689119740) ^ -1410365520;
									num16 ^= num18;
									num17 ^= num18;
									int num19;
									int num20;
									if (num15)
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
									bool num21 = EqualityComparer<string>.Default.Equals(EncryptedFileReference, other.EncryptedFileReference);
									int[] array4 = new int[6];
									array4[0] = -1237830930;
									array4[1] = -1571830429;
									array4[2] = -1168598519;
									array4[3] = 572943918;
									array4[4] = -975650170;
									array4[5] = -628493513;
									array4[5] = array4[3] ^ 0x68E61F7D;
									array4[3] = array4[2] ^ -833088641;
									array4[0] = array4[5] ^ 0x302E034B;
									int[] array5 = new int[6] { -683906914, 926321632, 691454698, -1639075616, -1276043432, 1437062490 };
									int[][] array6 = new int[2][] { array4, array5 };
									array5[0] = array6[0][2] ^ -1780244363;
									array5[1] = array5[5] ^ 0x223F4904;
									array5[3] = array5[2] ^ 0x5DA18FD1;
									array5[1] = array5[5] ^ 0x1775CA49;
									int num22 = array6[1][0] ^ -591927256;
									int[] array7 = new int[7];
									array7[0] = 1967086812;
									array7[1] = 770952133;
									array7[2] = -1478113742;
									array7[3] = -1263219547;
									array7[4] = 1909942944;
									array7[5] = 291106101;
									array7[6] = -882039344;
									array7[2] = array7[4] ^ 0x381305C2;
									array7[5] = array7[3] ^ -960492905;
									array7[5] = array7[1] ^ -761281689;
									int[] array8 = new int[4] { -468459950, 590283342, 868186039, -1899599034 };
									int[][] array9 = new int[2][] { array7, array8 };
									array8[2] = array9[0][6] ^ 0x7B59090C;
									array8[3] ^= -1265784201;
									array8[3] = array8[0] ^ 0x4C58EF70;
									int num23 = array9[1][2] ^ -921040633;
									int num24 = ((int)num4 * -1557289860) ^ 0x289503A8;
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
									num = num25 ^ num24;
								}
							}
							else
							{
								bool num27 = _0024_002A__003C_003C_005E_002F_0040(EqualityContract, other.EqualityContract);
								int[,] array10 = new int[3, 4];
								array10[0, 0] = 641065007;
								array10[0, 1] = 1141480430;
								array10[0, 2] = -1459636541;
								array10[0, 3] = -927843108;
								array10[1, 0] = 227821124;
								array10[1, 1] = 997965393;
								array10[1, 2] = 671233929;
								array10[1, 3] = 362252564;
								array10[2, 0] = 827605702;
								array10[2, 1] = 1678012094;
								array10[2, 2] = -2051564722;
								array10[2, 3] = 1616493241;
								array10[2, 1] = array10[1, 1] ^ -1551087310;
								array10[0, 2] = array10[1, 1] ^ 0x62669115;
								array10[0, 0] = array10[2, 3] ^ -1499420364;
								int num28 = array10[0, 0] ^ 0x35F5C1D9;
								int[,] array11 = new int[4, 4];
								array11[0, 0] = 198184894;
								array11[0, 1] = -1783022875;
								array11[0, 2] = -1658496868;
								array11[0, 3] = -965923255;
								array11[1, 0] = -1067405982;
								array11[1, 1] = -1670662802;
								array11[1, 2] = -402993088;
								array11[1, 3] = 91307385;
								array11[2, 0] = 863406439;
								array11[2, 1] = 1931135177;
								array11[2, 2] = -1005335920;
								array11[2, 3] = 408520461;
								array11[3, 0] = -1508510439;
								array11[3, 1] = -438183733;
								array11[3, 2] = 1280087805;
								array11[3, 3] = -502637603;
								array11[0, 0] = array11[3, 0] ^ -1203639251;
								array11[3, 1] = array11[1, 3] ^ -695444920;
								array11[1, 0] = array11[3, 2] ^ 0x4638CD86;
								array11[3, 0] = array11[0, 3] ^ 0x778EDF16;
								int num29 = array11[3, 0] ^ -199820486;
								int num30 = (int)(num4 * 1568716615) ^ -1315730041;
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
								num = num31 ^ num30;
							}
						}
						else
						{
							int[] array12 = new int[6];
							array12[0] = 1353014904;
							array12[1] = 82817880;
							array12[2] = 1659322473;
							array12[3] = -2034760757;
							array12[4] = -1420808689;
							array12[5] = 64365486;
							array12[3] = array12[4] ^ -707709340;
							array12[5] = array12[3] ^ 0x3BBE2B50;
							array12[1] = array12[2] ^ 0x43EC0A63;
							int[] array13 = new int[7] { 1964496696, 1296116627, -1999132116, -1239778583, -1596517424, -1149393157, -1537920726 };
							int[][] array14 = new int[2][] { array12, array13 };
							array13[0] = array14[0][4] ^ 0x636E03D9;
							array13[1] = array13[2] ^ 0x25C9C559;
							array13[6] = array13[1] ^ -120629828;
							array13[1] = array13[0] ^ -371530049;
							int num33 = array14[1][0] ^ 0x3B32FF82;
							int[,] array15 = new int[3, 3];
							array15[0, 0] = 111335867;
							array15[0, 1] = 1250136892;
							array15[0, 2] = 1711948252;
							array15[1, 0] = -1843845615;
							array15[1, 1] = 543622607;
							array15[1, 2] = -1517482498;
							array15[2, 0] = 1896767334;
							array15[2, 1] = 2043840911;
							array15[2, 2] = 810777746;
							array15[1, 0] = array15[0, 0] ^ -2045525912;
							array15[1, 0] = array15[2, 2] ^ 0x33F163;
							array15[2, 0] = array15[0, 1] ^ 0x1F3B4A4B;
							int num34 = array15[2, 0] ^ 0x46E248A5;
							int num35 = ((int)num4 * -264673660) ^ -841542840;
							num33 ^= num35;
							num34 ^= num35;
							int num36;
							int num37;
							if ((object)other != null)
							{
								num36 = num34;
								num37 = num36;
							}
							else
							{
								num36 = num33;
								num37 = num36;
							}
							num = num36 ^ num35;
						}
					}
					continue;
					end_IL_000d:
					break;
				}
				int num38 = 1488529284;
				_ = 0;
				for (int num39 = 0; num39 < 1; num39++)
				{
					num38 += -1488529279;
				}
				if (num3 == (uint)num38)
				{
					return EqualityComparer<string>.Default.Equals(ApiKey, other.ApiKey);
				}
				int num40 = -695587869;
				_ = 0;
				for (int num41 = 0; num41 < 2; num41++)
				{
					num40 = (num40 * -701709917) ^ -683696607;
					num40 = (num40 - -1891165843) ^ -636655264;
				}
				if (num3 == (uint)num40)
				{
					return false;
				}
				int num42 = 0;
				_ = 0;
				for (int num43 = 0; num43 < 2; num43++)
				{
					num42 = -(num42 ^ -86594829);
					num42 = num42 ^ -207160517 ^ -1813539062;
				}
				if (num3 == (uint)num42)
				{
				}
			}
			return true;
		}

		[CompilerGenerated]
		private UploadTicket(UploadTicket original)
		{
			while (true)
			{
				int num = 868917260;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(-1795444813 * ~(1596548699 * (--414928498 ^ 0x567DD857) + (0x77C7514E ^ -1199490065) + (-(-(~1709808424)) + (-938970767 + 609159494 - (0x5D95F96A ^ 0x7230BFAF) - (0x52D275E ^ 0x5EA950DC))) + -(-(~(-1710386917 ^ 0x215A5EB4)) - -(--1749471018 + -1459357904 * -299014871))) - ~num2 - -1499587897 * (0x6A23E2D6 ^ (~1103848638 - (1910805651 - (-1104140782 - -1199826293)) + (-791358629 + -(--61000901)) - (-603506871 - ((-1851621055 ^ 0x44C956A6) - (-340112704 ^ 0x3406D787)))))) + (-1723764390 + ~301363997 - (-2048147347 ^ 0x29376781) + (0x5E63D81E ^ -868657238) - 552929827 * -(~-1096290739 * -1477064715))) ^ (-(494542842 - -884488917 - (1520397621 + -954129863)) ^ -2120088164))) % 4;
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
					int num7 = -1246877135;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 * -633678521;
						num7 = (num7 ^ 0x3AB69EFE) * -1655239919;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1504379498;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -1504379500;
						}
						if (num3 != (uint)num9)
						{
							int num11 = 0;
							_ = 0;
							for (int num12 = 0; num12 < 1; num12++)
							{
								num11 *= -371068981;
							}
							if (num3 == (uint)num11)
							{
							}
							return;
						}
						FileId = original.FileId;
						ApiKey = original.ApiKey;
						int[,] array = new int[3, 4];
						array[0, 0] = -1269948808;
						array[0, 1] = 1864279647;
						array[0, 2] = 1821895280;
						array[0, 3] = 1801651547;
						array[1, 0] = 138314319;
						array[1, 1] = -1831344672;
						array[1, 2] = -1061256931;
						array[1, 3] = -1822330579;
						array[2, 0] = 456127383;
						array[2, 1] = 298105433;
						array[2, 2] = 1763606115;
						array[2, 3] = -530666352;
						array[1, 0] = array[0, 3] ^ -2063257134;
						array[2, 3] = array[0, 2] ^ 0x1E66E733;
						array[0, 0] = array[1, 1] ^ 0x2CA67DF;
						array[2, 1] = array[0, 2] ^ -2138469633;
						int num13 = array[2, 1] ^ -1089176180;
						num = ((int)num4 * -12992649) ^ 0x7A613706 ^ num13;
					}
					else
					{
						EncryptedFileReference = original.EncryptedFileReference;
						int[] array2 = new int[4];
						array2[0] = -696914089;
						array2[1] = 1030996285;
						array2[2] = 356538605;
						array2[3] = 2055641418;
						array2[0] = array2[3] ^ 0x666828B9;
						array2[0] ^= -483374396;
						int[] array3 = new int[7] { -173519058, 583679865, 1363911006, 893994575, -1073804846, 731839026, -1212886800 };
						int[][] array4 = new int[2][] { array2, array3 };
						array3[6] = array4[0][1] ^ 0x2BCA90BA;
						array3[0] = array3[4] ^ -1339204979;
						array3[4] = array3[1] ^ -306378892;
						array3[4] = array3[5] ^ -23205058;
						int num14 = array4[1][6] ^ 0x7705E782;
						num = ((int)num4 * -250103922) ^ 0x6048084E ^ num14;
					}
				}
			}
		}

		[CompilerGenerated]
		public void Deconstruct(out string EncryptedFileReference, out string FileId, out string ApiKey)
		{
			EncryptedFileReference = this.EncryptedFileReference;
			while (true)
			{
				int num = 274704266;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(-(-(-num2) - (102098995 - -(-1108040209 * (-1450495009 - -1649601365 - --557100942) + -(--1472628423 ^ -683952937) - ~(-(0x63A2033E ^ 0x57971F74) + -(~1062708496))))) * 415197091) - 874090701 * (-1785922165 * 1198154365 + (-1686677980 ^ 0x116FE20F))) ^ ~(--616765379))) % 4;
					int num5 = 2;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 ^ -1313009709);
						num5 = -(num5 ^ --2115653216);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -283116527;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 += 0x74E9D5D4 ^ -1378204326;
						num7 = 257321229 - (num7 ^ 0x1A916388);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1719960123;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(-num9);
							num9 = num9 * 1155229927 * 141942355;
						}
						if (num3 != (uint)num9)
						{
							int num11 = -304849474;
							_ = 0;
							for (int num12 = 0; num12 < 2; num12++)
							{
								num11 = num11 + 691585112 * 1632789131 + 328164442;
								num11 += -1977641916 + 1539619003;
							}
							if (num3 == (uint)num11)
							{
							}
							return;
						}
						ApiKey = this.ApiKey;
						int[] array = new int[4];
						array[0] = -456135332;
						array[1] = 34539957;
						array[2] = 819770353;
						array[3] = -38579451;
						array[2] = array[3] ^ -114894103;
						array[1] = array[2] ^ 0x2282F868;
						array[2] = array[1] ^ -648386491;
						int[] array2 = new int[7] { 37091365, 158018356, 352728184, 1048334242, -1493173214, 268854161, 90489882 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[6] = array3[0][3] ^ -275075209;
						array2[3] ^= -382744027;
						array2[0] = array2[5] ^ -1096316043;
						int num13 = array3[1][6] ^ 0x3A5FB6B5;
						num = (int)((num4 * 1372306328) ^ 0x92D6AB28u) ^ num13;
					}
					else
					{
						FileId = this.FileId;
						int[] array4 = new int[7];
						array4[0] = 1528978308;
						array4[1] = -983040683;
						array4[2] = -1147625698;
						array4[3] = -1195304740;
						array4[4] = 1925462959;
						array4[5] = 73450955;
						array4[6] = -1331642298;
						array4[2] = array4[1] ^ 0x505E335;
						array4[6] = array4[2] ^ -1422527816;
						int[] array5 = new int[6] { -89235577, -2106459611, 1241404988, -123812126, 431950047, 1529151049 };
						int[][] array6 = new int[2][] { array4, array5 };
						array5[2] = array6[0][5] ^ -1555714777;
						array5[5] = array5[2] ^ -1893649653;
						array5[0] = array5[3] ^ 0x31ED242;
						array5[3] = array5[2] ^ 0x7DAEEA42;
						int num14 = array6[1][2] ^ -1510593752;
						num = ((int)num4 * -857849052) ^ 0x5E9565E4 ^ num14;
					}
				}
			}
		}

		static Type _002D_002F__003E_0025_002B_0028_003D(RuntimeTypeHandle P_0)
		{
			Type typeFromHandle = default(Type);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 418351396;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(((~(-(num2 + -(~((~((0x77689D1A ^ 0xAF4C34D) - ((0x3FC1C2B1 ^ -1981648787) * 803934491 + -(~959997365))) ^ 0x731B1CF6) * 844488917)) - (-((-762723229 ^ ~(-602031026 ^ --62319709)) - -639496184 * -1074232715) ^ (982358397 + (0x2E090610 ^ (1022234049 * (-1158097550 - (185572116 - -597814926))) ^ 0xFCB5A66) + -(0x10B4702A ^ (~-148769106 * -1051647901 - 1207554259 - ~(--48067034 - ~1566679370))))))) ^ (((-588275750 ^ --194612585) - ~(~-1190046717) - ~(-(-1083303250))) ^ (-(~(-665224744 - -1458668629)) * -1801762393))) * 1323515447) ^ 0x4031BA39) ^ 0x39C9871E ^ 0x4E3981DA)) % 3;
						int num5 = 826208284;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 -= 66734930;
							num5 = ~num5 * -970746067;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 ^= -2099746522;
							num7 ^= -751473521;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1537973596;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = (num9 + 285476671) ^ 0x2A2BAD66;
								num9 *= -1592376359;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						typeFromHandle = Type.GetTypeFromHandle(P_0);
						int[] array = new int[5];
						array[0] = -680590422;
						array[1] = -1912217760;
						array[2] = -791289645;
						array[3] = -1117754946;
						array[4] = -962977036;
						array[0] = array[3] ^ -822325547;
						array[3] = array[4] ^ 0x4628484F;
						int[] array2 = new int[7];
						array2[0] = 1941301304;
						array2[1] = 1588371051;
						array2[2] = 1500344894;
						array2[3] = 38435557;
						array2[4] = 1866126154;
						array2[5] = -1606072651;
						array2[6] = -1165432890;
						array2[0] = array[1] ^ -1376607035;
						array2[4] = array2[6] ^ -668860347;
						array2[1] = array2[0] ^ -232274322;
						array2[3] = array2[1] ^ 0x224B9DC3;
						int num11 = array2[0] ^ 0x27207B7;
						num = (int)((num4 * 107968013) ^ 0x7C41BEB8) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return typeFromHandle;
		}

		static StringBuilder _0024_002B_002F_0028_002A_0040__003E(StringBuilder P_0, string P_1)
		{
			StringBuilder result = default(StringBuilder);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 430152159;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((((-((-67497019 ^ -1213895682) - (-1905851798 ^ 0x1407B982)) - (-(num2 + ~(-1714499513 * 742155869 + -563648369 + (1225747789 * (-1711573413 * (0x124283C0 ^ 0x72EBC39C)) + (~(2064952236 - (-806578972 + (-1457312754 + 1336775375)) + -1660062060) + ~(~(~(-662362829 * 925436731 + (-1145291960 - 202969405))))))) - (-(-(~(-631264457 - (-1581234922 ^ 0x6C493499)))) - (-647340823 ^ (1133702661 * ~((-647491759 + --1115460082) * -26105681)))) * 117054809) - ((-1568643669 * ((-187468459 - 1750604324 + --1250785301 - -1290765862) ^ -592106142)) ^ (129729901 * (0x5EE12F5B ^ -(-1799723445 * 207010515 + (-817678027 - 1174279085))))) - 1284092996)) ^ -1632021538) * -1790839327 - (-1300178262 + 1118965240)) * 1698427625)) % 3;
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
						int num7 = 132944685;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~num7;
							num7 = ~(num7 - ~-2081011307);
						}
						if (num3 != (uint)num7)
						{
							int num9 = 0;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~(~num9);
								num9 = ~(num9 - 1157734194);
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.Append(P_1);
						int[] array = new int[4];
						array[0] = -1354512112;
						array[1] = -1945752628;
						array[2] = -732528185;
						array[3] = -107418457;
						array[0] = array[2] ^ 0x54875625;
						array[0] ^= -1478673789;
						array[3] ^= -631595874;
						int[] array2 = new int[6] { 1134728483, -1599635985, -981016028, 1292631650, -2044858465, 318638061 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[5] = array3[0][1] ^ -1732221266;
						array2[4] = array2[0] ^ 0x1F2DCC5C;
						array2[4] = array2[0] ^ -479764964;
						int num11 = array3[1][5] ^ -461791614;
						num = ((int)num4 * -1724417806) ^ -1557679656 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static StringBuilder _002D_0021_003C_0029_0023_0024_003F_0029(StringBuilder P_0, char P_1)
		{
			StringBuilder result = default(StringBuilder);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -47823602;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-((-(~(~(-num2) - (-(-(-(494511619 + 312884240 - (999919619 - 2129853048)))) + (1033021083 * ~(--1794711985 * -1194135663) + (0x78E71072 ^ -(~-712463073 - (1339244538 + -962651256)))) - (-(-(--106253033) * 1720053045 + -692768395 * (1262010171 * 1068379203) * 619040753) + ((0x5EFBE9BE ^ -(~1774455116 + (-140553044 - 58049609))) - ~-641808889))))) + (1590210815 - --704351315)) * 1999373773) * -1878469691 * 1791140289)) % 3;
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
						int num7 = 58941505;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = (num7 - -1423679463) * 1688121545;
							num7 -= 638546503 + 946530944;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -842981418;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 *= 178200771;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.Append(P_1);
						int[] array = new int[4];
						array[0] = -2137240714;
						array[1] = 1891697332;
						array[2] = 178544446;
						array[3] = -1197640746;
						array[2] = array[3] ^ 0x5BED44E1;
						array[1] = array[0] ^ 0x72EF305C;
						int[] array2 = new int[6];
						array2[0] = -388494219;
						array2[1] = 2136661804;
						array2[2] = -1421237789;
						array2[3] = 1069498135;
						array2[4] = 1290681628;
						array2[5] = -1395417114;
						array2[2] = array[3] ^ -209423926;
						array2[3] = array2[5] ^ -903364156;
						array2[1] = array2[2] ^ -1534942974;
						int num11 = array2[2] ^ -289360814;
						num = ((int)num4 * -1158774585) ^ -63472308 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static string _005E_002F_0023_0028_0026_0026_0028_(object P_0)
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
					int num = 41048278;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(-(~(-(--241125498)) - (((num2 * -189214981 * 1342675351) ^ ((-(-((1422682736 - -221466261) * -1029644201 - -(-1433980224 ^ 0x675AA87B))) ^ 0x4A331BA8) - (0x4CF7D607 ^ -1379278447) * -653241503) ^ -(~(1765957107 + (0x764F7E88 ^ 0x4809A45E) + (-1761060351 + 322716587)) * 1254425063)) - ~(-(--1729002616 - (0x2BB4664E ^ 0x473AA035))) - -((~1271380760 - (469789507 - 1998180190)) * -1809671883)) + ((0x6C88BD34 ^ -258703321) + (1807325339 - -2023180558)))))) % 3;
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
						int num7 = 240403590;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 -= -87735417;
							num7 = num7 * 44453443 + -625700040;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 352359503;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -num9 - 2143268379;
								num9 = (num9 - (-1631862210 ^ 0x6879CA31)) ^ -1426227671;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.ToString();
						int[,] array = new int[4, 3];
						array[0, 0] = -1867584733;
						array[0, 1] = 1306647791;
						array[0, 2] = 911095108;
						array[1, 0] = -1195346569;
						array[1, 1] = -1291263618;
						array[1, 2] = -921524092;
						array[2, 0] = -2107286423;
						array[2, 1] = -690101582;
						array[2, 2] = -426165381;
						array[3, 0] = -94580136;
						array[3, 1] = -1910528536;
						array[3, 2] = -30342032;
						array[0, 0] = array[1, 0] ^ 0x7565B5F3;
						array[0, 1] ^= -1467059997;
						array[3, 2] ^= 20033733;
						array[3, 2] = array[2, 1] ^ -949104787;
						int num11 = array[3, 2] ^ -371776942;
						num = (int)((num4 * 270003464) ^ 0xD1AF0298u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static void @_0028_003C_003C_003E_002F_002B_003C()
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				RuntimeHelpers.EnsureSufficientExecutionStack();
			}
		}

		static StringBuilder _0028_0024_002F_0023_002D_0024_0024_003F(StringBuilder P_0, object P_1)
		{
			StringBuilder result = default(StringBuilder);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 1616211669;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-((((-num2 + -1005964171 * (-(-(-813011086 - -(-573178533))) - -460912029 + -(~(-1456971029 * -(-276188580 - -331628042)) + ((0x786FC96A ^ (-481573556 ^ 0x3A16E75D)) - -536991947)))) * 685117913) ^ -1507081552) * 2135455427 * 1076072167))) % 3;
						int num5 = 1718433120;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -(num5 - -1560269633);
							num5 = -num5 * 1464490335;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 443207317;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 *= 1853656253;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 217450482;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = num9 ^ -280627839 ^ 0x7088F358;
								num9 = ~num9 + -645479416;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.Append(P_1);
						int[] array = new int[7] { -605973065, -1607643090, 275693638, -1318532085, 282919861, 2015408951, 1197943125 };
						array[6] ^= -1769247122;
						array[5] = array[2] ^ 0x5B8142E5;
						array[1] = array[2] ^ -976194772;
						int[] array2 = new int[6] { 1678481484, -1355183722, -2051656088, -753580537, 357805940, -1209905714 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[3] = array3[0][4] ^ -138236729;
						array2[4] ^= -1528784316;
						array2[2] = array2[3] ^ 0x5E335D11;
						array2[1] = array2[0] ^ -1133578498;
						int num11 = array3[1][3] ^ -1877219174;
						num = ((int)num4 * -1529517288) ^ 0x822F250 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static bool _0024_002A__003C_003C_005E_002F_0040(Type P_0, Type P_1)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				return P_0 == P_1;
			}
		}
	}

	private static class PixeldrainClient
	{
		[StructLayout(LayoutKind.Auto)]
		[CompilerGenerated]
		private struct _003CDeleteFileAsync_003Ed__2 : IAsyncStateMachine
		{
			public int _003C_003E1__state;

			public AsyncTaskMethodBuilder _003C_003Et__builder;

			public string apiKey;

			public string fileId;

			public CancellationToken cancellationToken;

			private HttpClient _003Cclient_003E5__2;

			private ConfiguredTaskAwaitable<HttpResponseMessage>.ConfiguredTaskAwaiter _003C_003Eu__1;

			[MethodImpl(MethodImplOptions.NoInlining)]
			private void MoveNext()
			{
				object[] array = default(object[]);
				try
				{
					array = new object[1] { this };
					_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YjMzNjNmOGIAAo9VBgAFnAA=", array);
				}
				finally
				{
					this = (_003CDeleteFileAsync_003Ed__2)array[0];
				}
			}

			void IAsyncStateMachine.MoveNext()
			{
				//ILSpy generated this explicit interface implementation from .override directive in MoveNext
				this.MoveNext();
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			[DebuggerHidden]
			private void SetStateMachine(IAsyncStateMachine stateMachine)
			{
				object[] array = default(object[]);
				try
				{
					array = new object[2] { this, stateMachine };
					_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NjRlYDJhZjIEBq93AgQBmQQ=", array);
				}
				finally
				{
					this = (_003CDeleteFileAsync_003Ed__2)array[0];
				}
			}

			void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
			{
				//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
				this.SetStateMachine(stateMachine);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static Encoding _002B_0025_0040_003F_002B_0021_003D_003E()
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[0];
				return (Encoding)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZjJlZjAwNGUDAZzABQMGnQM=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static string _002D_005E_0029_005E_0023_0029_0021_0029(string P_0, string P_1)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
				return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NmRnOWA1MDcBA6GABwEEngE=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static byte[] _003D_003F_002B_002B_0028_0025_0023_0023(Encoding P_0, string P_1)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
				return (byte[])_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NTc0MGA6YTcCAKPcBAIHogI=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static string _002D_003C_0029_003D_0025_003E__005E(byte[] P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZjMzY2I4YWYAAqNyBgAFoQA=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static HttpRequestHeaders _003F_002A_0029_003F_002F_0040_005E_002F(HttpClient P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				return (HttpRequestHeaders)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Y2U1MjlhMWMAAqR6BgAFogA=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static void _005E_003F_003D__0024_0026_0026_0026(HttpRequestHeaders P_0, AuthenticationHeaderValue P_1)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZWM/P2QzMGMGBKO7AAYDpQY=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static string _003D_002B_002A_005E_0040_0024_002F_0026(string P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZDM3OWM5YmQAAqcqBgAFpAA=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static Task<HttpResponseMessage> _0023_005E_0025_002F__0021_002B_003F(HttpClient P_0, string P_1, CancellationToken P_2)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { P_0, P_1, P_2 };
				return (Task<HttpResponseMessage>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OGptPG9qPjMLCaNvDQsOrgs=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static bool _0028_002B_0040_003E_0021_0024_002B_002D(HttpResponseMessage P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("M2A/MTMwMjUGBK+RAAYDoAY=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static void _002F_003D_0026_002B_002B_002D_0024_005E(IDisposable P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YjVpN2ZpNDNRU/uSV1FU9lE=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}
		}

		[StructLayout(LayoutKind.Auto)]
		[CompilerGenerated]
		private struct _003CUploadFileAsync_003Ed__1 : IAsyncStateMachine
		{
			public int _003C_003E1__state;

			public AsyncTaskMethodBuilder<UploadTicket> _003C_003Et__builder;

			public string[] apiKeys;

			public byte[] fileBytes;

			public string uploadKey;

			public CancellationToken cancellationToken;

			private string _003CselectedApiKey_003E5__2;

			private HttpClient _003Cclient_003E5__3;

			private ByteArrayContent _003Ccontent_003E5__4;

			private HttpResponseMessage _003Cresponse_003E5__5;

			private ConfiguredTaskAwaitable<HttpResponseMessage>.ConfiguredTaskAwaiter _003C_003Eu__1;

			private ConfiguredTaskAwaitable<string>.ConfiguredTaskAwaiter _003C_003Eu__2;

			[MethodImpl(MethodImplOptions.NoInlining)]
			private void MoveNext()
			{
				object[] array = default(object[]);
				try
				{
					array = new object[1] { this };
					_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZGFnamZmYTZSUBkjVFJX+lI=", array);
				}
				finally
				{
					this = (_003CUploadFileAsync_003Ed__1)array[0];
				}
			}

			void IAsyncStateMachine.MoveNext()
			{
				//ILSpy generated this explicit interface implementation from .override directive in MoveNext
				this.MoveNext();
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			[DebuggerHidden]
			private void SetStateMachine(IAsyncStateMachine stateMachine)
			{
				object[] array = default(object[]);
				try
				{
					array = new object[2] { this, stateMachine };
					_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NTFnYmthMGZTUdiiVVNW+lM=", array);
				}
				finally
				{
					this = (_003CUploadFileAsync_003Ed__1)array[0];
				}
			}

			void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
			{
				//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
				this.SetStateMachine(stateMachine);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static Random _002A_0024_0024_002D_002A_002B_002F_003D()
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[0];
				return (Random)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YzQzZzYzZjNQUiRDVlBV+lA=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static int __0023_003C_0024_002F_0021_0026_005E(Random P_0, int P_1)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
				return (int)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("M2BkNzY2MDECAHbTBAIHqQI=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static string _005E_003F_0023_002D_0025_002B_005E_(string P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YjUxNjc3N2IAAnYOBgAFrAA=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static Guid _0021_003E_0021_002A_002F_005E_003E_()
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[0];
				return (Guid)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZWZgNDw1MmEEBnLSAgQBqQQ=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static TimeSpan _005E_005E__002A_0021_005E_0029_003F(double P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				return (TimeSpan)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MTY1YT0xNjUEBnOcAgQBqgQ=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static void _003D_0028_0025_002F_0028_002D_003E_002F(HttpClient P_0, TimeSpan P_1)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Y2JrYTZkYjFSUCr1VFJX/VI=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static void _0026_0040_0026_003C_0029_002A_0021_003F(HttpClient P_0, long P_1)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NmA0bDdmZmNVVyw0U1VQ5VU=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static Encoding _002F_0029_002D_002D_002B_0029_003F_005E()
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[0];
				return (Encoding)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NWNlZjgxZDUAAnq2BgAFsQA=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static string _002A_0025_0021_005E__0024_0025_0026(string P_0, string P_1)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
				return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Y2M3azBjMTFSUCkmVFJX4FI=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static byte[] _002A_0026_005E_003F_0026_002A_0040_002A(Encoding P_0, string P_1)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
				return (byte[])_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MGVnZmw1NmRUVigiUlRR51Q=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static string _0021_0024_0040_003E_005E_0021_0021_002B(byte[] P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZmVlMDQ3NjNVVygdU1VQ4VU=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static HttpRequestHeaders _002F_003D__002B_0026_002F_0025_0024(HttpClient P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				return (HttpRequestHeaders)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NWdhYDIyMmJXVSnDUVdS4lc=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static void _002D_0024__0025_002B_003F_0026_002A(HttpRequestHeaders P_0, AuthenticationHeaderValue P_1)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZDEyYGVkNjRQUtBeVlBV5lA=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static HttpContentHeaders _002F_0024_002A_0024_0028_0025_0029_0029(HttpContent P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				return (HttpContentHeaders)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZjZiYGFkaTZQUtFcVlBV51A=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static void _0028_0025_002B_0028_0028_0021_0026_002A(HttpContentHeaders P_0, MediaTypeHeaderValue P_1)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NGA3MzAwMTIGBIRPAAYDvgY=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static string _0024_0028_0021_003F_0029_002D_0021_(string P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NTYzY2RhYjIHBYQEAQcCvgc=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static Task<HttpResponseMessage> @_003C_0024_0026_002F_003F_003F_0024(HttpClient P_0, string P_1, HttpContent P_2, CancellationToken P_3)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[4] { P_0, P_1, P_2, P_3 };
				return (Task<HttpResponseMessage>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZTBlMDZgNGEEBofPAgQBvgQ=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static HttpResponseMessage _003F_003C_005E_005E_002D_002F_0023_003D(HttpResponseMessage P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				return (HttpResponseMessage)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YWYzNW9mZDdWVNN2UFZT7VY=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static HttpContent _0025_0021_0024_0040_005E_003F_003E_002D(HttpResponseMessage P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				return (HttpContent)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MmVsZmU2NWZUVtLWUlRR6FQ=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static Task<string> _003D_0023_0040_0024_003E_0029_002F_0025(HttpContent P_0, CancellationToken P_1)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
				return (Task<string>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MzMzZGVkZGNQUtexVlBV7VA=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static JsonDocument _0024_002F_0023_003C_0021_0023_002B_002B(string P_0, JsonDocumentOptions P_1)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
				return (JsonDocument)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YzxpYmw/PjlaWNNVXFpf5Fo=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static JsonElement _0028_002A_002B_003D_0040_002A_003C_005E(JsonDocument P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				return (JsonElement)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Mz9jZGM1PjQHBY0jAQcCuAc=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}

			[MethodImpl(MethodImplOptions.NoInlining)]
			static void _0026_002A_002D_0028_0029_0024_0025_0025(IDisposable P_0)
			{
				object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OW5qbjdrOTYPDYROCQ8Kzw8=", _0024_0029_0024_002A_0021_002F_0021_005E);
			}
		}

		private const string XorKey = "{C1B8DA14-46C7-45F6-95C2-EAB1146DF091}";

		[MethodImpl(MethodImplOptions.NoInlining)]
		[AsyncStateMachine(typeof(_003CUploadFileAsync_003Ed__1))]
		public static Task<UploadTicket> UploadFileAsync(byte[] fileBytes, string uploadKey, string[] apiKeys, CancellationToken cancellationToken)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[4] { fileBytes, uploadKey, apiKeys, cancellationToken };
			return (Task<UploadTicket>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MTw7bWtoMTgJC0DUDwkMnQk=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		[AsyncStateMachine(typeof(_003CDeleteFileAsync_003Ed__2))]
		public static Task DeleteFileAsync(string fileId, string apiKey, CancellationToken cancellationToken)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { fileId, apiKey, cancellationToken };
			return (Task)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZGRmNzFhNmYCAI6oBAIHlwI=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		private static byte[] Xor(byte[] input, string key)
		{
			byte[] array = _0028_0024_0021_0024_0026_003D_003F_003E(_0023_0026_002A_005E_0026_003E_0024_003C(), key);
			byte[] array2 = new byte[input.Length];
			for (int i = 0; i < input.Length; i++)
			{
				array2[i] = (byte)(input[i] ^ array[i % array.Length]);
			}
			return array2;
		}

		private static string XorToBase64(string input, string key)
		{
			return _003C_0026_0028_005E_003E_003C_003F_003E(Xor(_0028_0024_0021_0024_0026_003D_003F_003E(_0023_0026_002A_005E_0026_003E_0024_003C(), input), key));
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static AsyncTaskMethodBuilder _0023_0029__003C_0028_005E_003D_002F()
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[0];
			return (AsyncTaskMethodBuilder)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Yzc3YjJjZDBTUd3AVVNWy1M=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		static Encoding _0023_0026_002A_005E_0026_003E_0024_003C()
		{
			Encoding uTF = default(Encoding);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1692397735;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(~(-(~(-(-(~num2)))) + ~401464394)) * -874090451 - -1489162775)) % 3;
						int num5 = 178174362;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 ^= 0x156E0AAB;
							num5 = num5 * 1147567009 + 787179997;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 370250905;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~(-num7);
							num7 = (num7 + -70389071) * 1386831507;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1317243161;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 += -1317243161;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						uTF = Encoding.UTF8;
						int[,] array = new int[4, 4]
						{
							{ 575868628, -123582814, 913641651, -635936275 },
							{ -566535408, 1195251552, -652444871, -429147756 },
							{ -317574546, 223763093, -1299820416, -162044409 },
							{ -613305659, 1697746592, -80882992, -328479675 }
						};
						array[3, 1] ^= -450011092;
						array[0, 0] = array[3, 1] ^ 0x5C8D3267;
						array[3, 2] = array[2, 0] ^ 0x31F8F99A;
						int num11 = array[3, 2] ^ -1031032829;
						num = ((int)num4 * -59161459) ^ -7315737 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return uTF;
		}

		static byte[] _0028_0024_0021_0024_0026_003D_003F_003E(Encoding P_0, string P_1)
		{
			byte[] bytes = default(byte[]);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 1496585260;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(((-(~(((1949791675 + ((--2053752495 + (~-1087582735 * -1465093873 - (-428055247 ^ -64094652))) ^ 0x709A44D8)) ^ -((-((-1905997161 ^ -1522048899) * 1501706077) ^ 0x60EF3AB6) - 2007195647 * -1177138460)) * 1578916071 - -num2)) ^ -1025609911) - ~(--168852863 ^ -1378621144 ^ --1647145049) + -603787614 + -1654976942) * -1597694347))) % 3;
						int num5 = 1227918368;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = ~num5 - -594691597;
							num5 = -num5 ^ 0x136798CF;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -2147411955;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~num7;
							num7 = (num7 - 1074246730) ^ 0x5841AF06;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 2;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~num9;
								num9 = ~(~num9);
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						bytes = P_0.GetBytes(P_1);
						int[] array = new int[4] { -1981707917, -1448921558, -1561585152, 1878531359 };
						array[3] ^= -1160575238;
						array[3] = array[1] ^ -361587463;
						int[] array2 = new int[6];
						array2[0] = -2132558733;
						array2[1] = -1781788022;
						array2[2] = -1639755148;
						array2[3] = -315894271;
						array2[4] = 1918075805;
						array2[5] = -1243844210;
						array2[1] = array[1] ^ -607047759;
						array2[5] = array2[4] ^ 0x7694795D;
						array2[5] = array2[2] ^ -2094057909;
						int num11 = array2[1] ^ -866876332;
						num = (int)((num4 * 611786737) ^ 0xEAAA0531u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return bytes;
		}

		static string _003C_0026_0028_005E_003E_003C_003F_003E(byte[] P_0)
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
					int num = -1295752714;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((-2144614367 ^ 0x493EAB4A) - -(-(((~(~(-1869106808)) * -400002493) ^ 0x5A962BB) - (num2 * -1350649781 - -(~(-(~((-1342159492 ^ 0x7FEEFC50) - -133601140)) ^ (-(~(-(~-1219970163))) * 1266389679)))) * 128159679) * -731537905 + -902934601))) % 3;
						int num5 = -1643382328;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = ~num5 ^ 0x590E4D2E;
							num5 = num5 - ~-1180873660 + -125933882;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 2;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~num7;
							num7 ^= --2055847183;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 329823898;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 ^= 0x13A8B69B;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = Convert.ToBase64String(P_0);
						int[] array = new int[6];
						array[0] = 959029595;
						array[1] = -852191257;
						array[2] = -1438892956;
						array[3] = -2015027730;
						array[4] = 567975757;
						array[5] = 1301380811;
						array[4] = array[5] ^ -792061660;
						array[5] = array[3] ^ 0x669F831F;
						int[] array2 = new int[7] { -487597168, -1169718742, -623758948, 674268469, 516755188, -1218922471, -460717218 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[6] = array3[0][3] ^ -843721186;
						array2[4] = array2[6] ^ 0x21B8D8F5;
						array2[3] = array2[4] ^ -2083929265;
						array2[5] = array2[0] ^ -1978752124;
						int num11 = array3[1][6] ^ 0x68E71C25;
						num = (int)((num4 * 696991060) ^ 0xCBE3CEB8u) ^ num11;
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
	private struct _003CCheckStateAsync_003Ed__5 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder<string> _003C_003Et__builder;

		public HttpClient client;

		public string url;

		public CancellationToken cancellationToken;

		private HttpResponseMessage _003Cresponse_003E5__2;

		private ConfiguredTaskAwaitable<HttpResponseMessage>.ConfiguredTaskAwaiter _003C_003Eu__1;

		private ConfiguredTaskAwaitable<string>.ConfiguredTaskAwaiter _003C_003Eu__2;

		private void MoveNext()
		{
			int num = _003C_003E1__state;
			string result2 = default(string);
			try
			{
				if (num != 0)
				{
					goto IL_0016;
				}
				goto IL_1d5e;
				IL_0016:
				int num2 = 481031182;
				goto IL_001b;
				IL_001b:
				ConfiguredTaskAwaitable<HttpResponseMessage> configuredTaskAwaitable = default(ConfiguredTaskAwaitable<HttpResponseMessage>);
				ConfiguredTaskAwaitable<HttpResponseMessage>.ConfiguredTaskAwaiter awaiter = default(ConfiguredTaskAwaitable<HttpResponseMessage>.ConfiguredTaskAwaiter);
				HttpResponseMessage result = default(HttpResponseMessage);
				ConfiguredTaskAwaitable<string> configuredTaskAwaitable2 = default(ConfiguredTaskAwaitable<string>);
				ConfiguredTaskAwaitable<string>.ConfiguredTaskAwaiter awaiter2 = default(ConfiguredTaskAwaitable<string>.ConfiguredTaskAwaiter);
				while (true)
				{
					int num3 = num2;
					uint num5;
					uint num4 = (num5 = (uint)(~(-(-(-(~(~num3))) * 1736572573) - ((0x1558887E ^ -294699096) + ((0x5793098B ^ 0x6A863F65) - -1854777519)) - (--107630942 - (202435772 + -643735750)) - -577256631))) % 14;
					uint num6 = num4;
					int num7 = -721545848;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7;
						num7 = (-2090961095 ^ 0x16DE8205) - num7;
					}
					if (num6 == (uint)num7)
					{
						break;
					}
					uint num9 = num4;
					int num10 = 1107479549;
					_ = 0;
					for (int num11 = 0; num11 < 1; num11++)
					{
						num10 ^= 0x4202CBFA;
					}
					if (num9 == (uint)num10)
					{
						int num12 = num;
						int[,] array = new int[4, 4];
						array[0, 0] = 1987549503;
						array[0, 1] = -450013492;
						array[0, 2] = -715848734;
						array[0, 3] = -580089557;
						array[1, 0] = -218661119;
						array[1, 1] = -464459946;
						array[1, 2] = -330273038;
						array[1, 3] = -1539098709;
						array[2, 0] = 2105350916;
						array[2, 1] = 167648376;
						array[2, 2] = -510317382;
						array[2, 3] = 1088128725;
						array[3, 0] = -1856654744;
						array[3, 1] = 232298394;
						array[3, 2] = 1154124257;
						array[3, 3] = -1784113431;
						array[1, 2] = array[3, 0] ^ -1089867516;
						array[3, 3] = array[0, 2] ^ -139675062;
						array[0, 0] = array[1, 0] ^ 0x3458850;
						int num13 = array[0, 0] ^ -1277333830;
						int[,] array2 = new int[4, 4];
						array2[0, 0] = 1336274080;
						array2[0, 1] = 537925552;
						array2[0, 2] = -1797267281;
						array2[0, 3] = -1816489734;
						array2[1, 0] = 285534162;
						array2[1, 1] = -294219044;
						array2[1, 2] = -320890966;
						array2[1, 3] = 1810847068;
						array2[2, 0] = -1377025186;
						array2[2, 1] = -1609376775;
						array2[2, 2] = 302361358;
						array2[2, 3] = -711441400;
						array2[3, 0] = 1934028196;
						array2[3, 1] = 841473930;
						array2[3, 2] = 557642700;
						array2[3, 3] = 1929649624;
						array2[3, 1] = array2[1, 3] ^ 0x534A096F;
						array2[0, 2] = array2[3, 2] ^ -850964363;
						array2[0, 0] = array2[2, 2] ^ -342645769;
						int num14 = array2[0, 0] ^ -1847958220;
						int num15 = (int)(num5 * 1888795548) ^ -984230980;
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
					int num19 = 545263690;
					_ = 0;
					for (int num20 = 0; num20 < 2; num20++)
					{
						num19 = num19 - 177949190 + -1469802321;
						num19 = ~(num19 ^ 0x50462821);
					}
					if (num18 == (uint)num19)
					{
						configuredTaskAwaitable = _005E_002B_003D_003E_003C_003D_002A_002A(client, url, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
						int[] array3 = new int[6];
						array3[0] = -333576532;
						array3[1] = 619061054;
						array3[2] = -1505721624;
						array3[3] = 806934098;
						array3[4] = 250536618;
						array3[5] = 942404820;
						array3[2] = array3[5] ^ 0xBFD565D;
						array3[1] = array3[4] ^ 0x4D360AB6;
						array3[1] = array3[4] ^ -663073744;
						int[] array4 = new int[7] { 1518333809, -146463693, 1219847342, -2019318163, 629487517, -346309040, 2031824591 };
						int[][] array5 = new int[2][] { array3, array4 };
						array4[4] = array5[0][5] ^ -495686340;
						array4[2] = array4[4] ^ 0x28A85574;
						array4[3] = array4[4] ^ -931566279;
						int num21 = array5[1][4] ^ -1450858662;
						num2 = ((int)num5 * -1167303181) ^ 0x3BBF50D4 ^ num21;
						continue;
					}
					uint num22 = num4;
					int num23 = 1033459089;
					_ = 0;
					for (int num24 = 0; num24 < 2; num24++)
					{
						num23 = ~(num23 * -1067756963);
						num23 = (num23 - (504943691 - 402820422)) * -1453293559;
					}
					if (num22 == (uint)num23)
					{
						awaiter = configuredTaskAwaitable.GetAwaiter();
						int[] array6 = new int[6];
						array6[0] = -1296431810;
						array6[1] = 1158811453;
						array6[2] = -627266711;
						array6[3] = 506944277;
						array6[4] = -738861229;
						array6[5] = -1513925;
						array6[3] = array6[1] ^ 0x6FAB323E;
						array6[5] ^= -397479273;
						array6[2] = array6[5] ^ -1782061734;
						int[] array7 = new int[4];
						array7[0] = -1349831856;
						array7[1] = 594421729;
						array7[2] = -740350852;
						array7[3] = -916189939;
						array7[1] = array6[1] ^ -1996657049;
						array7[0] = array7[3] ^ -475571271;
						array7[0] = array7[1] ^ -1829344902;
						int num25 = array7[1] ^ -1490874424;
						num2 = ((int)num5 * -1214725773) ^ 0x497E0C97 ^ num25;
						continue;
					}
					uint num26 = num4;
					int num27 = 1560799811;
					_ = 0;
					for (int num28 = 0; num28 < 2; num28++)
					{
						num27 = -(num27 + 941892344);
						num27 = -num27 - -425191404;
					}
					if (num26 == (uint)num27)
					{
						bool ısCompleted = awaiter.IsCompleted;
						int[,] array8 = new int[3, 3];
						array8[0, 0] = 1850183081;
						array8[0, 1] = -779490633;
						array8[0, 2] = -500880914;
						array8[1, 0] = -795601290;
						array8[1, 1] = 1436658848;
						array8[1, 2] = 245552132;
						array8[2, 0] = -1846595407;
						array8[2, 1] = 1349527548;
						array8[2, 2] = -1985383453;
						array8[2, 1] = array8[2, 0] ^ 0x598D72D6;
						array8[0, 2] = array8[1, 2] ^ -43737851;
						array8[0, 1] = array8[2, 2] ^ -560051739;
						int num29 = array8[0, 1] ^ -334544535;
						int[] array9 = new int[7];
						array9[0] = 355952724;
						array9[1] = 1451838420;
						array9[2] = 848829663;
						array9[3] = -77633213;
						array9[4] = -276339725;
						array9[5] = 2030479093;
						array9[6] = 1945723742;
						array9[6] = array9[2] ^ 0x295EC88C;
						array9[5] = array9[3] ^ -1333132823;
						int[] array10 = new int[5];
						array10[0] = 1456882327;
						array10[1] = 1062436740;
						array10[2] = -1108825522;
						array10[3] = 1302429891;
						array10[4] = 1877156660;
						array10[0] = array9[2] ^ -665761440;
						array10[2] = array10[4] ^ 0x76A3FCA5;
						array10[2] = array10[0] ^ 0x705EACF5;
						int num30 = array10[0] ^ -767647846;
						int num31 = ((int)num5 * -1146946990) ^ -1193889942;
						num29 ^= num31;
						num30 ^= num31;
						int num32;
						int num33;
						if (!ısCompleted)
						{
							num32 = num30;
							num33 = num32;
						}
						else
						{
							num32 = num29;
							num33 = num32;
						}
						num2 = num32 ^ num31;
						continue;
					}
					uint num34 = num4;
					int num35 = 346815000;
					_ = 0;
					for (int num36 = 0; num36 < 2; num36++)
					{
						num35 = (num35 ^ 0x3BF8279D) * -634596019;
						num35 = (num35 - (-1945514738 - -980510377)) ^ -969689495;
					}
					if (num34 == (uint)num35)
					{
						num = (_003C_003E1__state = 0);
						int[] array11 = new int[6];
						array11[0] = -1578829942;
						array11[1] = -495848444;
						array11[2] = -777536030;
						array11[3] = -809361567;
						array11[4] = -1003311424;
						array11[5] = -743828289;
						array11[3] = array11[4] ^ 0x794F4A0A;
						array11[4] = array11[2] ^ 0x492BC402;
						int[] array12 = new int[5] { 1967975139, 477686429, -588385507, 1524549616, -470531711 };
						int[][] array13 = new int[2][] { array11, array12 };
						array12[1] = array13[0][2] ^ 0x712ED17E;
						array12[4] = array12[1] ^ 0x758F0E30;
						array12[3] = array12[1] ^ 0xEF520A;
						int num37 = array13[1][1] ^ 0x2ACC1859;
						num2 = ((int)num5 * -398870351) ^ -1156734828 ^ num37;
						continue;
					}
					uint num38 = num4;
					int num39 = 702122791;
					_ = 0;
					for (int num40 = 0; num40 < 1; num40++)
					{
						num39 ^= 0x29D98B23;
					}
					if (num38 == (uint)num39)
					{
						_003C_003Eu__1 = awaiter;
						_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter, ref this);
						int[] array14 = new int[5] { 1198608540, -430745611, 1364965497, -1822466216, -1175702522 };
						array14[2] ^= -543363498;
						array14[0] = array14[2] ^ -176628814;
						array14[3] ^= -94573117;
						int[] array15 = new int[7];
						array15[0] = 1328696052;
						array15[1] = -1713487789;
						array15[2] = -1731353263;
						array15[3] = -1152372692;
						array15[4] = -1887441944;
						array15[5] = -4108549;
						array15[6] = 168250582;
						array15[1] = array14[1] ^ 0x56ACB343;
						array15[4] = array15[3] ^ -1836795643;
						array15[6] ^= 1681513932;
						array15[4] = array15[6] ^ -159492992;
						int num41 = array15[1] ^ 0x679C678E;
						num2 = (int)((num5 * 903604739) ^ 0x237960DC) ^ num41;
						continue;
					}
					uint num42 = num4;
					int num43 = -625473317;
					_ = 0;
					for (int num44 = 0; num44 < 2; num44++)
					{
						num43 = ~(-num43);
						num43 = -num43 * -474978551;
					}
					if (num42 == (uint)num43)
					{
						return;
					}
					uint num45 = num4;
					int num46 = -551554447;
					_ = 0;
					for (int num47 = 0; num47 < 2; num47++)
					{
						num46 *= -759764523;
						num46 = -924933314 - (num46 - (-1736724097 - -1488059342));
					}
					if (num45 == (uint)num46)
					{
						goto IL_1d5e;
					}
					uint num48 = num4;
					int num49 = 1451322593;
					_ = 0;
					for (int num50 = 0; num50 < 1; num50++)
					{
						num49 -= 1451322584;
					}
					if (num48 == (uint)num49)
					{
						_003C_003Eu__1 = default(ConfiguredTaskAwaitable<HttpResponseMessage>.ConfiguredTaskAwaiter);
						int[] array16 = new int[6];
						array16[0] = 644469358;
						array16[1] = 933388097;
						array16[2] = -1971403931;
						array16[3] = -1750741331;
						array16[4] = 1308092919;
						array16[5] = 1253914232;
						array16[0] = array16[2] ^ 0x2FDEAE7B;
						array16[0] = array16[1] ^ -631554916;
						array16[1] = array16[4] ^ -821535740;
						int[] array17 = new int[7] { 146854226, 1394318962, 2043546065, 2010191936, 1311796361, -349910122, -716652405 };
						int[][] array18 = new int[2][] { array16, array17 };
						array17[3] = array18[0][5] ^ 0x6A422954;
						array17[5] = array17[4] ^ -890456906;
						array17[6] ^= -1850722091;
						array17[0] = array17[4] ^ 0x3715DAE5;
						int num51 = array18[1][3] ^ 0x657CCDB9;
						num2 = (int)((num5 * 171057816) ^ 0x85C63028u) ^ num51;
						continue;
					}
					uint num52 = num4;
					int num53 = 23990215;
					_ = 0;
					for (int num54 = 0; num54 < 1; num54++)
					{
						num53 ^= 0x16E0FCB;
					}
					if (num52 == (uint)num53)
					{
						num = (_003C_003E1__state = -1);
						int[,] array19 = new int[3, 3];
						array19[0, 0] = -71043926;
						array19[0, 1] = 640326583;
						array19[0, 2] = -1965292407;
						array19[1, 0] = 2073252182;
						array19[1, 1] = -1981592451;
						array19[1, 2] = 415614450;
						array19[2, 0] = 115701074;
						array19[2, 1] = 714972784;
						array19[2, 2] = -1396712793;
						array19[2, 0] = array19[2, 1] ^ -480787817;
						array19[1, 2] = array19[2, 2] ^ 0x534F6B77;
						array19[2, 1] = array19[1, 1] ^ -827709177;
						array19[0, 1] = array19[0, 0] ^ 0x5710E134;
						int num55 = array19[0, 1] ^ 0x17EB6EF1;
						num2 = (int)((num5 * 176925564) ^ 0x3E5D7FF0) ^ num55;
						continue;
					}
					uint num56 = num4;
					int num57 = -11;
					_ = 0;
					for (int num58 = 0; num58 < 1; num58++)
					{
						num57 = ~num57;
					}
					if (num56 == (uint)num57)
					{
						result = awaiter.GetResult();
						num2 = 1207149014;
						continue;
					}
					uint num59 = num4;
					int num60 = 2011932866;
					_ = 0;
					for (int num61 = 0; num61 < 1; num61++)
					{
						num60 = 2011932871 - num60;
					}
					if (num59 == (uint)num60)
					{
						_003Cresponse_003E5__2 = result;
						int[,] array20 = new int[3, 4];
						array20[0, 0] = -645580051;
						array20[0, 1] = 1675014453;
						array20[0, 2] = 1123181515;
						array20[0, 3] = -1189980938;
						array20[1, 0] = 1478875661;
						array20[1, 1] = 1830419654;
						array20[1, 2] = 1520914071;
						array20[1, 3] = 2008547868;
						array20[2, 0] = -241232109;
						array20[2, 1] = -1424376616;
						array20[2, 2] = 193848328;
						array20[2, 3] = 1165021362;
						array20[0, 0] = array20[1, 3] ^ -1446592964;
						array20[0, 0] = array20[2, 3] ^ -613449767;
						array20[2, 2] = array20[1, 1] ^ -1003691715;
						array20[1, 1] = array20[2, 3] ^ -1916482650;
						int num62 = array20[1, 1] ^ -1965325569;
						num2 = (int)((num5 * 1702251360) ^ 0xA42A0F60u) ^ num62;
						continue;
					}
					uint num63 = num4;
					int num64 = -1358811260;
					_ = 0;
					for (int num65 = 0; num65 < 2; num65++)
					{
						num64 = num64 * 1575063921 - -303738422;
						num64 = -num64 ^ -821640131;
					}
					if (num63 != (uint)num64)
					{
					}
					try
					{
						if (num != 1)
						{
							goto IL_1d84;
						}
						goto IL_30c6;
						IL_1d84:
						int num66 = -433836548;
						goto IL_1d89;
						IL_1d89:
						while (true)
						{
							num3 = num66;
							num4 = (num5 = (uint)(~(-(-(-(~(~num3))) * 1736572573) - ((0x1558887E ^ -294699096) + ((0x5793098B ^ 0x6A863F65) - -1854777519)) - (--107630942 - (202435772 + -643735750)) - -577256631))) % 16;
							uint num67 = num4;
							int num68 = 616918232;
							_ = 0;
							for (int num69 = 0; num69 < 1; num69++)
							{
								num68 -= 616918218;
							}
							if (num67 == (uint)num68)
							{
								break;
							}
							uint num70 = num4;
							int num71 = -15;
							_ = 0;
							for (int num72 = 0; num72 < 1; num72++)
							{
								num71 = -num71;
							}
							if (num70 == (uint)num71)
							{
								HttpStatusCode num73 = _003F_003C_0024_003E_003E_0028_002D_0040(_003Cresponse_003E5__2);
								int[] array21 = new int[7];
								array21[0] = -1095752567;
								array21[1] = 634716125;
								array21[2] = 1841407631;
								array21[3] = 332670843;
								array21[4] = -756465890;
								array21[5] = 568027303;
								array21[6] = -1919023647;
								array21[3] = array21[1] ^ -811603891;
								array21[1] = array21[0] ^ -2127292490;
								array21[3] = array21[6] ^ -1017095284;
								int[] array22 = new int[4];
								array22[0] = 776107436;
								array22[1] = -1591606501;
								array22[2] = -526401817;
								array22[3] = -490451713;
								array22[2] = array21[6] ^ -1473757580;
								array22[1] ^= -1632175086;
								array22[0] = array22[3] ^ 0x2D99CFEF;
								int num74 = array22[2] ^ 0x4F1E4D7F;
								int[] array23 = new int[6];
								array23[0] = -771736074;
								array23[1] = 1292150755;
								array23[2] = -1200922245;
								array23[3] = -2038578378;
								array23[4] = 183517811;
								array23[5] = 1561494886;
								array23[1] = array23[0] ^ 0x6EE3A16C;
								array23[1] = array23[3] ^ 0x78ECD726;
								array23[1] = array23[4] ^ -2106283576;
								int[] array24 = new int[6] { 1393460318, 222692786, 1327474876, -1782874942, 1718732824, 2031100743 };
								int[][] array25 = new int[2][] { array23, array24 };
								array24[5] = array25[0][0] ^ -2135432546;
								array24[2] = array24[4] ^ 0xF7D4409;
								array24[2] = array24[3] ^ -1383436384;
								int num75 = array25[1][5] ^ 0x46147FC5;
								int num76 = ((int)num5 * -1762752927) ^ 0x37A0974F;
								num74 ^= num76;
								num75 ^= num76;
								int num77;
								int num78;
								if (num73 == (HttpStatusCode)522)
								{
									num77 = num75;
									num78 = num77;
								}
								else
								{
									num77 = num74;
									num78 = num77;
								}
								num66 = num77 ^ num76;
								continue;
							}
							uint num79 = num4;
							int num80 = -1742913319;
							_ = 0;
							for (int num81 = 0; num81 < 1; num81++)
							{
								num80 = -1742913307 - num80;
							}
							if (num79 == (uint)num80)
							{
								result2 = string.Empty;
								int[,] array26 = new int[3, 3];
								array26[0, 0] = -1270155755;
								array26[0, 1] = -1068281562;
								array26[0, 2] = -1338356416;
								array26[1, 0] = 1741295932;
								array26[1, 1] = -326801495;
								array26[1, 2] = 1428194388;
								array26[2, 0] = -563821937;
								array26[2, 1] = -482142975;
								array26[2, 2] = 1510228144;
								array26[2, 2] = array26[0, 1] ^ -1145714924;
								array26[1, 1] = array26[0, 0] ^ -1768572503;
								array26[0, 1] = array26[2, 0] ^ -994077464;
								int num82 = array26[0, 1] ^ -1187282012;
								num66 = (int)((num5 * 1174082407) ^ 0xB0067C24u) ^ num82;
								continue;
							}
							uint num83 = num4;
							int num84 = 22;
							_ = 0;
							for (int num85 = 0; num85 < 2; num85++)
							{
								num84 ^= --1696530297;
								num84 = -(~num84);
							}
							if (num83 != (uint)num84)
							{
								uint num86 = num4;
								int num87 = 1846009226;
								_ = 0;
								for (int num88 = 0; num88 < 1; num88++)
								{
									num87 ^= 0x6E07DD8F;
								}
								if (num86 == (uint)num87)
								{
									_0028_002B_002D_002F_0025_0040_002B_005E(_003Cresponse_003E5__2);
									num66 = 1134660149;
									continue;
								}
								uint num89 = num4;
								int num90 = 134328408;
								_ = 0;
								for (int num91 = 0; num91 < 2; num91++)
								{
									num90 = -num90 + 1261229100;
									num90 = ~num90 ^ -1176566443;
								}
								if (num89 == (uint)num90)
								{
									configuredTaskAwaitable2 = _002D_002F_003E_0029_0028_003F_002F_003E(_002A_003E_002F_0028_002F_0029_003E_0021(_003Cresponse_003E5__2), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
									int[] array27 = new int[5];
									array27[0] = 570993309;
									array27[1] = -541465581;
									array27[2] = -831033612;
									array27[3] = -602006200;
									array27[4] = 82974003;
									array27[4] = array27[3] ^ 0x71B5920B;
									array27[1] = array27[3] ^ 0x793D96E3;
									array27[1] ^= 1221896107;
									int[] array28 = new int[6] { -1791301225, -1489762422, -592991191, -652524879, -68045849, 1342069035 };
									int[][] array29 = new int[2][] { array27, array28 };
									array28[4] = array29[0][3] ^ 0x33075294;
									array28[0] = array28[1] ^ -1608698422;
									array28[3] = array28[2] ^ -222341103;
									int num92 = array29[1][4] ^ 0x32031203;
									num66 = ((int)num5 * -2039858127) ^ 0x7492C764 ^ num92;
									continue;
								}
								uint num93 = num4;
								int num94 = 1425642798;
								_ = 0;
								for (int num95 = 0; num95 < 2; num95++)
								{
									num94 = (num94 - (502782873 - -1652350633)) * 2074204421;
									num94 = ~(num94 + 1135116651);
								}
								if (num93 == (uint)num94)
								{
									awaiter2 = configuredTaskAwaitable2.GetAwaiter();
									int[] array30 = new int[5];
									array30[0] = -2036520012;
									array30[1] = -1650596483;
									array30[2] = -687451659;
									array30[3] = -1010502449;
									array30[4] = 1908014750;
									array30[0] = array30[2] ^ 0x19B538B0;
									array30[0] ^= -657585867;
									array30[4] = array30[3] ^ -169675188;
									int[] array31 = new int[5];
									array31[0] = -448882275;
									array31[1] = 2055536434;
									array31[2] = 1676211596;
									array31[3] = 970836849;
									array31[4] = -286912773;
									array31[2] = array30[3] ^ -1279223692;
									array31[0] = array31[3] ^ 0x7A9E44EC;
									array31[3] = array31[0] ^ -1358846504;
									array31[3] = array31[0] ^ 0x1B231A69;
									int num96 = array31[2] ^ -1988459328;
									num66 = ((int)num5 * -107291142) ^ -666092388 ^ num96;
									continue;
								}
								uint num97 = num4;
								int num98 = -395156;
								_ = 0;
								for (int num99 = 0; num99 < 2; num99++)
								{
									num98 = -num98 ^ 0x42A717DD;
									num98 = num98 - ~-1482539538 - -1571900895;
								}
								if (num97 == (uint)num98)
								{
									bool ısCompleted2 = awaiter2.IsCompleted;
									int[] array32 = new int[5];
									array32[0] = -1334053749;
									array32[1] = -1515218056;
									array32[2] = -574106705;
									array32[3] = 476039614;
									array32[4] = -523569054;
									array32[4] = array32[1] ^ 0x7203738F;
									array32[4] = array32[2] ^ -927025359;
									array32[1] = array32[0] ^ -1913956084;
									int[] array33 = new int[4] { -494640551, -1000215452, 753738108, -2118778265 };
									int[][] array34 = new int[2][] { array32, array33 };
									array33[2] = array34[0][0] ^ 0x504BE5E4;
									array33[1] = array33[0] ^ 0x75A9FCA6;
									array33[0] = array33[3] ^ 0x1873D4E8;
									int num100 = array34[1][2] ^ -304571474;
									int[] array35 = new int[5];
									array35[0] = -1075469976;
									array35[1] = 1907394456;
									array35[2] = 2055727695;
									array35[3] = -210486497;
									array35[4] = -145766098;
									array35[3] = array35[1] ^ 0x3F5F3A27;
									array35[0] = array35[1] ^ 0x5A3F826;
									array35[3] = array35[4] ^ 0x31BD10FB;
									int[] array36 = new int[7];
									array36[0] = -1162701704;
									array36[1] = -1884691429;
									array36[2] = 1206269704;
									array36[3] = -1360801399;
									array36[4] = 744585110;
									array36[5] = -1830534204;
									array36[6] = 1471944926;
									array36[2] = array35[1] ^ -1008160894;
									array36[4] = array36[1] ^ 0x56B861ED;
									array36[3] ^= -1019715900;
									array36[4] = array36[2] ^ 0x555634C1;
									int num101 = array36[2] ^ -880987501;
									int num102 = (int)(num5 * 538787902) ^ -156898980;
									num100 ^= num102;
									num101 ^= num102;
									int num103;
									int num104;
									if (!ısCompleted2)
									{
										num103 = num101;
										num104 = num103;
									}
									else
									{
										num103 = num100;
										num104 = num103;
									}
									num66 = num103 ^ num102;
									continue;
								}
								uint num105 = num4;
								int num106 = 858853460;
								_ = 0;
								for (int num107 = 0; num107 < 2; num107++)
								{
									num106 = (num106 ^ -13676558) * -614344561;
									num106 = num106 + (-1221482592 - 2069777191) - -498231052;
								}
								if (num105 == (uint)num106)
								{
									num = (_003C_003E1__state = 1);
									int[] array37 = new int[4] { 45393900, 2055721741, 717069818, -1668718464 };
									array37[3] ^= -1873919698;
									array37[2] = array37[3] ^ 0x38F87A3B;
									int[] array38 = new int[4];
									array38[0] = -851016665;
									array38[1] = 2029510348;
									array38[2] = 424967040;
									array38[3] = 1344107786;
									array38[3] = array37[1] ^ 0x5B8642EB;
									array38[0] = array38[1] ^ -1546362870;
									array38[1] = array38[0] ^ 0x6C51FA4B;
									int num108 = array38[3] ^ 0x3DAB07B6;
									num66 = ((int)num5 * -701557621) ^ -1420586568 ^ num108;
									continue;
								}
								uint num109 = num4;
								int num110 = -289413865;
								_ = 0;
								for (int num111 = 0; num111 < 2; num111++)
								{
									num110 *= 92665539;
									num110 = 1917921013 - (--1956434488 - num110);
								}
								if (num109 == (uint)num110)
								{
									_003C_003Eu__2 = awaiter2;
									int[] array39 = new int[7];
									array39[0] = -1580891787;
									array39[1] = -566453928;
									array39[2] = -33496890;
									array39[3] = -53963640;
									array39[4] = -1804338134;
									array39[5] = 105713828;
									array39[6] = 535456610;
									array39[3] = array39[2] ^ -964177155;
									array39[6] ^= 1096454532;
									int[] array40 = new int[7] { 541100326, 60072889, 1046894126, -776009594, -1925779009, 1122925372, 354573100 };
									int[][] array41 = new int[2][] { array39, array40 };
									array40[5] = array41[0][2] ^ 0xB8FBA4B;
									array40[6] ^= -1733569600;
									array40[3] = array40[6] ^ -81059376;
									array40[4] = array40[1] ^ 0x6B0D88E2;
									int num112 = array41[1][5] ^ 0x762DB7EF;
									num66 = ((int)num5 * -194438823) ^ 0x281D23BB ^ num112;
									continue;
								}
								uint num113 = num4;
								int num114 = -1380268627;
								_ = 0;
								for (int num115 = 0; num115 < 2; num115++)
								{
									num114 = -num114 * -151007969;
									num114 = -(num114 + (-705721058 + -360214707));
								}
								if (num113 == (uint)num114)
								{
									_003C_003Et__builder.AwaitUnsafeOnCompleted(ref awaiter2, ref this);
									return;
								}
								uint num116 = num4;
								int num117 = 129367621;
								_ = 0;
								for (int num118 = 0; num118 < 2; num118++)
								{
									num117 = (num117 - --1370213330) ^ 0xE27A1AA;
									num117 = -2115859904 - (num117 - -199194203 * -1122688621);
								}
								if (num116 == (uint)num117)
								{
									goto IL_30c6;
								}
								uint num119 = num4;
								int num120 = -12;
								_ = 0;
								for (int num121 = 0; num121 < 1; num121++)
								{
									num120 = ~num120;
								}
								if (num119 == (uint)num120)
								{
									_003C_003Eu__2 = default(ConfiguredTaskAwaitable<string>.ConfiguredTaskAwaiter);
									int[] array42 = new int[6];
									array42[0] = 1576586743;
									array42[1] = -397913408;
									array42[2] = -454422461;
									array42[3] = 198476634;
									array42[4] = -2122209979;
									array42[5] = -1863250227;
									array42[0] = array42[3] ^ 0x1BB0F221;
									array42[3] = array42[2] ^ 0x189C1D6B;
									int[] array43 = new int[7] { 1298912401, 2042470448, 2060620878, -581697289, 1951176654, 1640911856, 1967571920 };
									int[][] array44 = new int[2][] { array42, array43 };
									array43[1] = array44[0][5] ^ -1564359693;
									array43[3] ^= 1641376833;
									array43[4] = array43[1] ^ -453523070;
									int num122 = array44[1][1] ^ -1919618742;
									num66 = ((int)num5 * -1993708709) ^ -2010618359 ^ num122;
									continue;
								}
								uint num123 = num4;
								int num124 = 930008963;
								_ = 0;
								for (int num125 = 0; num125 < 1; num125++)
								{
									num124 = 930008970 - num124;
								}
								if (num123 == (uint)num124)
								{
									num = (_003C_003E1__state = -1);
									int[,] array45 = new int[3, 3];
									array45[0, 0] = 2042578167;
									array45[0, 1] = 688778236;
									array45[0, 2] = 2139886337;
									array45[1, 0] = -1294692244;
									array45[1, 1] = -861403022;
									array45[1, 2] = 566901300;
									array45[2, 0] = 1452160245;
									array45[2, 1] = -1420726593;
									array45[2, 2] = -968364325;
									array45[0, 1] = array45[1, 1] ^ -622614681;
									array45[1, 2] ^= 875318963;
									array45[1, 0] = array45[2, 2] ^ 0x709B2990;
									int num126 = array45[1, 0] ^ -1154200182;
									num66 = (int)((num5 * 32610903) ^ 0xEDAD0B21u) ^ num126;
									continue;
								}
								uint num127 = num4;
								int num128 = 0;
								_ = 0;
								for (int num129 = 0; num129 < 1; num129++)
								{
									num128 = -num128;
								}
								if (num127 == (uint)num128)
								{
									result2 = _0024_0025_002F_0026_0028_005E__002F(awaiter2.GetResult());
									num66 = -1828537314;
									continue;
								}
								uint num130 = num4;
								int num131 = -494085944;
								_ = 0;
								for (int num132 = 0; num132 < 1; num132++)
								{
									num131 += 494085953;
								}
								if (num130 == (uint)num131)
								{
								}
							}
							goto end_IL_1d76;
						}
						goto IL_1d84;
						IL_30c6:
						awaiter2 = _003C_003Eu__2;
						num66 = 1146196968;
						goto IL_1d89;
						end_IL_1d76:;
					}
					finally
					{
						if (num < 0)
						{
							while (true)
							{
								int num133 = -1443709297;
								while (true)
								{
									num3 = num133;
									num4 = (num5 = (uint)(~(-(-(-(~(~num3))) * 1736572573) - ((0x1558887E ^ -294699096) + ((0x5793098B ^ 0x6A863F65) - -1854777519)) - (--107630942 - (202435772 + -643735750)) - -577256631))) % 4;
									uint num134 = num4;
									int num135 = -1180889405;
									_ = 0;
									for (int num136 = 0; num136 < 1; num136++)
									{
										num135 -= -1180889408;
									}
									if (num134 == (uint)num135)
									{
										break;
									}
									uint num137 = num4;
									int num138 = -2142731442;
									_ = 0;
									for (int num139 = 0; num139 < 1; num139++)
									{
										num138 *= -238004713;
									}
									if (num137 != (uint)num138)
									{
										uint num140 = num4;
										int num141 = 657400331;
										_ = 0;
										for (int num142 = 0; num142 < 2; num142++)
										{
											num141 = -405303278 - -num141;
											num141 = num141 - ~2067478379 + -1990875267;
										}
										if (num140 != (uint)num141)
										{
											uint num143 = num4;
											int num144 = 710752036;
											_ = 0;
											for (int num145 = 0; num145 < 2; num145++)
											{
												num144 = ~num144 * -203056643;
												num144 = -num144 - -1901600805;
											}
											if (num143 == (uint)num144)
											{
											}
											goto end_IL_3c8a;
										}
										_003C__0024_002F_0026_0026_0021_003F((IDisposable)_003Cresponse_003E5__2);
										int[] array46 = new int[4] { 727145726, 501469137, -119306273, 227785938 };
										array46[3] ^= -1879960445;
										array46[3] = array46[2] ^ -782399752;
										array46[3] ^= -652682481;
										int[] array47 = new int[6] { -1161358755, -462581476, -1944513774, 446631742, -1128690900, -1659628608 };
										int[][] array48 = new int[2][] { array46, array47 };
										array47[3] = array48[0][0] ^ -1018692654;
										array47[2] ^= -865407583;
										array47[2] = array47[1] ^ -1242476494;
										array47[2] = array47[0] ^ 0x24D349F8;
										int num146 = array48[1][3] ^ -1090570271;
										num133 = (int)((num5 * 874270490) ^ 0x24B15FD2) ^ num146;
										continue;
									}
									HttpResponseMessage httpResponseMessage = _003Cresponse_003E5__2;
									int[] array49 = new int[5];
									array49[0] = -262263183;
									array49[1] = -1135900533;
									array49[2] = -225175801;
									array49[3] = 1010865853;
									array49[4] = -1838504285;
									array49[0] = array49[1] ^ 0x39FD5A8A;
									array49[4] = array49[2] ^ -546686899;
									array49[0] = array49[3] ^ 0x69273B58;
									int[] array50 = new int[6];
									array50[0] = -1161379819;
									array50[1] = -1433790774;
									array50[2] = 2139223007;
									array50[3] = -2109120186;
									array50[4] = -550839981;
									array50[5] = 1639300615;
									array50[2] = array49[1] ^ -199124420;
									array50[3] = array50[5] ^ -1789152021;
									array50[4] = array50[3] ^ 0x37387685;
									int num147 = array50[2] ^ 0x1E85827A;
									int[] array51 = new int[6];
									array51[0] = -1559704524;
									array51[1] = -2069810178;
									array51[2] = 1117105050;
									array51[3] = 764528569;
									array51[4] = 490171907;
									array51[5] = -2092253692;
									array51[4] = array51[2] ^ -1832211428;
									array51[3] = array51[5] ^ 0x5ED18BB4;
									int[] array52 = new int[6];
									array52[0] = -1337041631;
									array52[1] = 1371387952;
									array52[2] = 1634512953;
									array52[3] = -1447395088;
									array52[4] = 79692230;
									array52[5] = -339738017;
									array52[4] = array51[0] ^ -947512572;
									array52[3] ^= 1484712076;
									array52[3] ^= 1675892413;
									array52[1] = array52[4] ^ 0x126CF10E;
									int num148 = array52[4] ^ 0x11991502;
									int num149 = (int)(num5 * 1273747935) ^ -1642061462;
									num147 ^= num149;
									num148 ^= num149;
									int num150;
									int num151;
									if (httpResponseMessage != null)
									{
										num150 = num148;
										num151 = num150;
									}
									else
									{
										num150 = num147;
										num151 = num150;
									}
									num133 = num150 ^ num149;
								}
								continue;
								end_IL_3c8a:
								break;
							}
						}
					}
					goto end_IL_000d;
				}
				goto IL_0016;
				IL_1d5e:
				awaiter = _003C_003Eu__1;
				num2 = 2147428980;
				goto IL_001b;
				end_IL_000d:;
			}
			catch (Exception exception)
			{
				while (true)
				{
					int num152 = -1998025302;
					while (true)
					{
						int num3 = num152;
						uint num5;
						uint num4 = (num5 = (uint)(~(-(-(-(~(~num3))) * 1736572573) - ((0x1558887E ^ -294699096) + ((0x5793098B ^ 0x6A863F65) - -1854777519)) - (--107630942 - (202435772 + -643735750)) - -577256631))) % 5;
						uint num153 = num4;
						int num154 = 2104546200;
						_ = 0;
						for (int num155 = 0; num155 < 2; num155++)
						{
							num154 = (num154 * -1729796953) ^ -690936938;
							num154 = -1992210004 - (-1272644036 - num154);
						}
						if (num153 == (uint)num154)
						{
							break;
						}
						uint num156 = num4;
						int num157 = -528076156;
						_ = 0;
						for (int num158 = 0; num158 < 2; num158++)
						{
							num157 = (num157 - 321462467 * 1698626561) ^ -1787625288;
							num157 = num157 ^ -379801146 ^ -73665080;
						}
						if (num156 != (uint)num157)
						{
							uint num159 = num4;
							int num160 = 337228777;
							_ = 0;
							for (int num161 = 0; num161 < 1; num161++)
							{
								num160 *= 382227545;
							}
							if (num159 != (uint)num160)
							{
								uint num162 = num4;
								int num163 = 0;
								_ = 0;
								for (int num164 = 0; num164 < 2; num164++)
								{
									num163 = num163 ^ -267271776 ^ 0x6424F2DD;
									num163 = ~(-num163);
								}
								if (num162 != (uint)num163)
								{
									uint num165 = num4;
									int num166 = 1761001603;
									_ = 0;
									for (int num167 = 0; num167 < 2; num167++)
									{
										num166 = ~(2077865063 * -105000288 - num166);
										num166 = ~num166 * -2045550433;
									}
									if (num165 == (uint)num166)
									{
									}
									return;
								}
								_003C_003Et__builder.SetException(exception);
								int[] array53 = new int[4];
								array53[0] = 262894309;
								array53[1] = 198587421;
								array53[2] = 802771409;
								array53[3] = -1687655181;
								array53[0] = array53[1] ^ -493547760;
								array53[2] = array53[0] ^ -799112130;
								int[] array54 = new int[4];
								array54[0] = 923700261;
								array54[1] = -283568487;
								array54[2] = -1431630108;
								array54[3] = -1110654210;
								array54[3] = array53[3] ^ -1640366581;
								array54[2] ^= -1805825601;
								array54[2] = array54[3] ^ 0x4A8A65E4;
								int num168 = array54[3] ^ 0x6A4D9700;
								num152 = ((int)num5 * -978322463) ^ -290433401 ^ num168;
							}
							else
							{
								_003Cresponse_003E5__2 = null;
								int[] array55 = new int[7];
								array55[0] = 1256941675;
								array55[1] = 135481084;
								array55[2] = -227130816;
								array55[3] = -1144789739;
								array55[4] = -1642161905;
								array55[5] = -1582517717;
								array55[6] = -1665897061;
								array55[5] = array55[3] ^ 0x5BF2F9D7;
								array55[6] = array55[5] ^ -514939865;
								array55[6] = array55[5] ^ -397385689;
								int[] array56 = new int[5];
								array56[0] = 1379801217;
								array56[1] = -1406405324;
								array56[2] = -1586246395;
								array56[3] = -1359380178;
								array56[4] = 1936553906;
								array56[0] = array55[0] ^ -1647260741;
								array56[4] = array56[3] ^ -1323888143;
								array56[2] = array56[1] ^ -18957139;
								array56[1] = array56[3] ^ -1360275355;
								int num169 = array56[0] ^ 0x749634C4;
								num152 = (int)((num5 * 1400772084) ^ 0x79F8AD64) ^ num169;
							}
						}
						else
						{
							_003C_003E1__state = -2;
							int[,] array57 = new int[4, 3]
							{
								{ 11880925, -1163927961, -364262190 },
								{ -2075884109, 131419503, 2118483836 },
								{ 382098128, -1320164377, 1283979123 },
								{ 657079964, 505651289, -1630184935 }
							};
							array57[1, 2] ^= 859214088;
							array57[1, 0] = array57[0, 0] ^ -1110162464;
							array57[2, 2] = array57[2, 1] ^ 0x42A301F8;
							int num170 = array57[2, 2] ^ 0x2F7B786D;
							num152 = ((int)num5 * -727795113) ^ -965144749 ^ num170;
						}
					}
				}
			}
			_003C_003E1__state = -2;
			while (true)
			{
				int num171 = -479953833;
				while (true)
				{
					int num3 = num171;
					uint num5;
					uint num4 = (num5 = (uint)(~(-(-(-(~(~num3))) * 1736572573) - ((0x1558887E ^ -294699096) + ((0x5793098B ^ 0x6A863F65) - -1854777519)) - (--107630942 - (202435772 + -643735750)) - -577256631))) % 4;
					uint num172 = num4;
					int num173 = -2063367415;
					_ = 0;
					for (int num174 = 0; num174 < 1; num174++)
					{
						num173 ^= -2063367415;
					}
					if (num172 == (uint)num173)
					{
						break;
					}
					uint num175 = num4;
					int num176 = 175845254;
					_ = 0;
					for (int num177 = 0; num177 < 1; num177++)
					{
						num176 *= 789090539;
					}
					if (num175 != (uint)num176)
					{
						uint num178 = num4;
						int num179 = 1076207873;
						_ = 0;
						for (int num180 = 0; num180 < 2; num180++)
						{
							num179 = num179 ^ -1235805848 ^ 0x638527D6;
							num179 = 1884738676 - num179 * -70173825;
						}
						if (num178 != (uint)num179)
						{
							uint num181 = num4;
							int num182 = -1030425852;
							_ = 0;
							for (int num183 = 0; num183 < 1; num183++)
							{
								num182 += 1030425855;
							}
							if (num181 == (uint)num182)
							{
							}
							return;
						}
						_003C_003Et__builder.SetResult(result2);
						int[,] array58 = new int[4, 3];
						array58[0, 0] = 444968673;
						array58[0, 1] = 1994522333;
						array58[0, 2] = 1323614828;
						array58[1, 0] = -1530844263;
						array58[1, 1] = 774471167;
						array58[1, 2] = -814399678;
						array58[2, 0] = -1422749147;
						array58[2, 1] = 1143276707;
						array58[2, 2] = -1808165067;
						array58[3, 0] = -91077120;
						array58[3, 1] = 1300600710;
						array58[3, 2] = -208376897;
						array58[0, 0] = array58[2, 0] ^ 0x18B38EE5;
						array58[0, 0] = array58[1, 1] ^ 0x3A0F5237;
						array58[0, 0] = array58[3, 1] ^ -235155796;
						array58[1, 0] = array58[2, 2] ^ -1067834513;
						int num184 = array58[1, 0] ^ -93507166;
						num171 = ((int)num5 * -40467921) ^ 0x5728DB9B ^ num184;
					}
					else
					{
						_003Cresponse_003E5__2 = null;
						int[] array59 = new int[4];
						array59[0] = 1301023792;
						array59[1] = 324415287;
						array59[2] = -1197003691;
						array59[3] = 1555834776;
						array59[0] = array59[2] ^ -1280128192;
						array59[0] = array59[3] ^ -10860148;
						int[] array60 = new int[4];
						array60[0] = -1310978996;
						array60[1] = -1491821288;
						array60[2] = -402530360;
						array60[3] = -2092357380;
						array60[1] = array59[2] ^ 0x507E3CA9;
						array60[3] = array60[1] ^ 0x7E0AA445;
						array60[2] = array60[1] ^ -534977518;
						int num185 = array60[1] ^ 0x4BFF07A6;
						num171 = (int)((num5 * 2136733189) ^ 0x51C4D576) ^ num185;
					}
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

		static Task<HttpResponseMessage> _005E_002B_003D_003E_003C_003D_002A_002A(HttpClient P_0, string P_1, CancellationToken P_2)
		{
			Task<HttpResponseMessage> async = default(Task<HttpResponseMessage>);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -371705041;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(~(-((num2 - -485472913 * -(~((-(-1822020601) - (-2076186743 ^ -1788035149) - ~(~232578506 + 2097053739)) * -1535782305) - -(~((-1144885843 * ~(--205958007)) ^ ~(~(-1414131103)))))) ^ ((2087123567 * (1837351993 * (-(79777041 * -838846521) + -1489690975))) ^ -(-(~(-1141301787)) ^ (~(-1626085531) - -1915799248) ^ (-(--890968591) + -1944312024 + (-476866864 ^ -558865982))) ^ ((-754948194 ^ -561681005) - (~(~1279073763 * -261858729) - (-1720690250 ^ -1130061345) + (-(982246691 + -30358888) - (399325172 - 1867437866 + 1904129849 * 1555028588)) * 4035739 + ((0x7ECC5641 ^ ~(-(-1884796434 ^ -2122226154))) - -(-(~88704781)))))))) * -285464663) * -1914669995)) % 3;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 *= -1485959521;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -1942442090;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 += 1942442091;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 2;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = num9 - 1375251302 + -1988840336;
								num9 = -(num9 - 321836088);
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						async = P_0.GetAsync(P_1, P_2);
						int[,] array = new int[3, 4];
						array[0, 0] = -546009615;
						array[0, 1] = -1859851274;
						array[0, 2] = 1696157859;
						array[0, 3] = 812546831;
						array[1, 0] = 1151459587;
						array[1, 1] = -24660591;
						array[1, 2] = 1928313561;
						array[1, 3] = -932524732;
						array[2, 0] = -1665249000;
						array[2, 1] = 1669496076;
						array[2, 2] = 904902990;
						array[2, 3] = -1552106763;
						array[1, 2] = array[2, 2] ^ -425545969;
						array[2, 0] = array[2, 1] ^ 0x4B076DC3;
						array[2, 0] = array[0, 1] ^ -735104154;
						int num11 = array[2, 0] ^ -1513962834;
						num = ((int)num4 * -1573225096) ^ 0x625F6018 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return async;
		}

		static HttpStatusCode _003F_003C_0024_003E_003E_0028_002D_0040(HttpResponseMessage P_0)
		{
			HttpStatusCode statusCode = default(HttpStatusCode);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 49203415;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(-((-369927337 * -41602652 + (-(-(-407166059 * -530757970 - -740614469 * 1814598471)) * 1747572903 + -(~(-(230788924 + -1383103925 - -563762141)))) - (-(-(1986384867 * (1782616494 + -2021718452)) - ~(-622810987 ^ -129417514) - (-(-1534731335 ^ -423725029) ^ ~(-(--1680395649)))) - 1546497030) - -num2) ^ (~((0x659A15EB ^ 0x50005B86) + (-301859925 ^ (-1916185469 * -(~-1354692636)))) + -(-1408507184 * 732216927)) ^ (-(-(1888864915 * -159671733 - ~712211138 - 323442423 * (2048194116 * -916577005))) ^ ~(-(-1747061551 * -(0x253E0328 ^ -2074552753))))) * 1283068907))) % 3;
						int num5 = -717655624;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 -= -717655624;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -2127741117;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 *= 1131988331;
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
						statusCode = P_0.StatusCode;
						int[] array = new int[7];
						array[0] = -653587912;
						array[1] = -704946781;
						array[2] = -859455167;
						array[3] = 1777854183;
						array[4] = 1702542873;
						array[5] = 1271961844;
						array[6] = 1389691235;
						array[3] = array[6] ^ 0x15A8986F;
						array[0] = array[6] ^ -1057828696;
						array[4] ^= 2039489447;
						int[] array2 = new int[4] { -1464310372, -123138832, 2041289464, -803252641 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][5] ^ 0x6C01B179;
						array2[0] = array2[1] ^ 0x23FDAB70;
						array2[0] = array2[3] ^ 0x1C1DC001;
						int num11 = array3[1][1] ^ -1244037439;
						num = (int)((num4 * 1928771270) ^ 0x5DD0D576) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return statusCode;
		}

		static HttpResponseMessage _0028_002B_002D_002F_0025_0040_002B_005E(HttpResponseMessage P_0)
		{
			HttpResponseMessage result = default(HttpResponseMessage);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1149101527;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((-(~(-(-(~(num2 ^ (~(-((((0x2526434E ^ -678452136) - -(--398945151)) ^ -(1145608971 - (0x18927652 ^ -547085357))) + 962037224 * -2041225473) + -1445604223) * 62771479)) * -1217454073))) * 1567394329) + (1595025133 - -1359307160)) * 799063163)) % 3;
						int num5 = -1038171725;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 -= -1038171725;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -248725202;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 ^= -248725201;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -838467550;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = -num9 ^ 0x62F2FE7E;
								num9 = (num9 + 1516341853 * 62748474) ^ 0x75BFFA2;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.EnsureSuccessStatusCode();
						int[] array = new int[7] { -487228125, 1141748081, 2051516910, 1785501394, 306232561, 2088792365, -1694519785 };
						array[6] ^= -1314330186;
						array[4] = array[2] ^ -1327256171;
						array[5] = array[1] ^ -1034512949;
						int[] array2 = new int[5];
						array2[0] = -499390988;
						array2[1] = 618792175;
						array2[2] = 818882615;
						array2[3] = -935701713;
						array2[4] = -73441466;
						array2[4] = array[1] ^ -844321703;
						array2[3] = array2[4] ^ -1255794698;
						array2[0] = array2[4] ^ -1595456121;
						int num11 = array2[4] ^ -1991600602;
						num = ((int)num4 * -641232126) ^ 0x38399E4E ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static HttpContent _002A_003E_002F_0028_002F_0029_003E_0021(HttpResponseMessage P_0)
		{
			HttpContent content = default(HttpContent);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 1374766332;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((num2 + ~(~(0x5B8CA0BB ^ (-((--229688333 + (1323314801 - 1893761964)) * -451866717) * 203538107)) + ~(-458937008 ^ ~(-360085329 * -(-725502752 + 1641263351) + ~(~-861433250 - (1851442914 - -688097664))))) + ~(-(~(0x78283E11 ^ 0x6C3A325B)) ^ -(-274856666 ^ -11918798) ^ ((0x46B82887 ^ (-(1364524524 - -1363306231) - (-1353358826 ^ -1273729941))) + (571211580 - -((1143559369 - 1289840756) * -220222413))) ^ -(-((-1101527877 ^ (-149261049 - ~1424576115)) + (-(2061949794 + -395301369) + ((-1141936211 ^ 0x37B21272) + (-2031287474 - 2095044113)))))) + ~(-924640322 + -(-422750248 ^ (-(-743589713 * -1651298102) ^ 0x51D2C485))) - (~((-1602645947 ^ --1868648332) + ~(--147800028)) - ~(1770371269 * -((-1636780387 ^ 0x61650866) - (1315917374 + 237889658))))) ^ (-(0x773EACC3 ^ 0x26C1C7CD) - -882377858))) % 3;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 *= 1156924865;
							num5 = -num5;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -588442755;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = -(num7 ^ 0x1C74541D);
							num7 = ~(num7 * -1430408095);
						}
						if (num3 != (uint)num7)
						{
							int num9 = -978866336;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~num9 * 769433173;
								num9 = num9 * -1567786079 * 579087043;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						content = P_0.Content;
						int[,] array = new int[3, 3];
						array[0, 0] = -383809496;
						array[0, 1] = 1952678296;
						array[0, 2] = 1259395975;
						array[1, 0] = -2065949216;
						array[1, 1] = 1174563471;
						array[1, 2] = 689226221;
						array[2, 0] = -423624080;
						array[2, 1] = -273647632;
						array[2, 2] = -1567835634;
						array[0, 0] = array[2, 2] ^ -115737923;
						array[0, 0] = array[2, 2] ^ -1549660704;
						array[2, 2] = array[1, 2] ^ -1035348676;
						int num11 = array[2, 2] ^ -701905986;
						num = ((int)num4 * -1367397304) ^ 0xBC07810 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return content;
		}

		static Task<string> _002D_002F_003E_0029_0028_003F_002F_003E(HttpContent P_0, CancellationToken P_1)
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
					int num = 920876791;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~((((-495113741 - (-305888733 - -1144459828)) ^ 0x60751523) - -(-(-(~num2 ^ (((1167191245 * (2107761463 + -1981933505 - 2070225290 * -2057663667) * 105716403 - (-888442966 + ~-1363479399 - (-875686485 + -869982861) + (1181343561 + 674316632 - ~1491280765) * -1318255811)) ^ ((-1051867221 * 707370706 - ~-445864571 + (--1048779735 - ~-559924626) + -682956613) ^ -(558965827 * (-314639178 - -775603914) + -1028303892))) * 639079241 - ((~(-(-311150957)) ^ (-(-1999598384 * 550281253 - ~1798025619) - 627425603 * (-561361549 - 1924228171))) - ~(-1533804661 * -1073102856))))) + (-1745041604 ^ ((-1220923937 ^ -532643787) - ~(-1405695039))) * -1004008513)) * -2096007345 - -922677827))) % 3;
						int num5 = 390152802;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = num5 - (-1681297763 - -519483028) + 902222839;
							num5 = (num5 - 110840183) ^ 0x44E1E82;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = -1040784168;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = (num7 * 1585055699) ^ -130082383;
							num7 = num7 * -881524049 * -2026144425;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 958315981;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 = 958315982 - num9;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.ReadAsStringAsync(P_1);
						int[,] array = new int[4, 4];
						array[0, 0] = 1734866959;
						array[0, 1] = 1993951604;
						array[0, 2] = -863627406;
						array[0, 3] = -1200452650;
						array[1, 0] = -898928185;
						array[1, 1] = 758881188;
						array[1, 2] = 700283587;
						array[1, 3] = 367282827;
						array[2, 0] = -1869892830;
						array[2, 1] = -223560304;
						array[2, 2] = 205471050;
						array[2, 3] = 2088396064;
						array[3, 0] = 2081740008;
						array[3, 1] = 1694970865;
						array[3, 2] = 515632801;
						array[3, 3] = -367139837;
						array[0, 2] = array[0, 3] ^ 0x7058DC36;
						array[3, 2] = array[1, 0] ^ -861962915;
						array[1, 3] = array[3, 1] ^ -942802180;
						int num11 = array[1, 3] ^ 0x2DF07736;
						num = ((int)num4 * -511190472) ^ 0x529AB770 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static string _0024_0025_002F_0026_0028_005E__002F(string P_0)
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
					int num = -1523848689;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((~(num2 + -(518165957 * ~(-101212062 + 816975463 + ~(-1675700592 - (-1196966746 + 1348701426)) + --732091444 - -(-922013439 * ~(~(0x3AF43FE2 ^ -1473266696)))))) - (-(-(1674737922 - (-(~1815545267) ^ ~(-725159588)))) - (-(-976852287 ^ (1740691671 * (0x73E4B076 ^ 0x1708CE6) + -(--2015487873))) + -(((-1694293173 ^ 0xA02FD44) + (0x4F86F27F ^ -302303115)) * 635194175)))) * 1771061823)) % 3;
						int num5 = 0;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 *= 733059603;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 382503976;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 = 382503977 - num7;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 550564831;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 ^= 0x20D0F3DD;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						result = P_0.Trim();
						int[] array = new int[4];
						array[0] = -1542039310;
						array[1] = 1696911014;
						array[2] = 1441691774;
						array[3] = -1471506974;
						array[2] = array[3] ^ -1332937774;
						array[0] = array[1] ^ 0x39EF5C2C;
						int[] array2 = new int[7] { 117710105, 1801431638, 979114458, -1004321509, 1935404166, 33486311, 1857451064 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[5] = array3[0][3] ^ -1727478356;
						array2[1] = array2[5] ^ 0x6B4383AA;
						array2[3] = array2[4] ^ 0x39B39D0;
						array2[4] ^= 1934543768;
						int num11 = array3[1][5] ^ -112698920;
						num = (int)((num4 * 1663261172) ^ 0x7B08EAFC) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return result;
		}

		static void _003C__0024_002F_0026_0026_0021_003F(IDisposable P_0)
		{
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 848323306;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~((-(num2 ^ 0x5D6B04D2) + ((470690571 * -(~2055842657)) ^ -262474413)) ^ 0x328BA270 ^ -257857787))) % 3;
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
						int num7 = 2009726772;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 = 2009726773 - num7;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 528766392;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 ^= 0x24AE412C;
								num9 = ~(num9 * -502971479);
							}
							if (num3 == (uint)num9)
							{
							}
							return;
						}
						P_0.Dispose();
						int[,] array = new int[3, 4];
						array[0, 0] = 845505609;
						array[0, 1] = 532950047;
						array[0, 2] = -1533226173;
						array[0, 3] = 459514680;
						array[1, 0] = -101157646;
						array[1, 1] = -1114320259;
						array[1, 2] = 1967085268;
						array[1, 3] = 656025594;
						array[2, 0] = 42652301;
						array[2, 1] = -766399202;
						array[2, 2] = 328279269;
						array[2, 3] = -1580356022;
						array[0, 0] = array[2, 0] ^ -1239530992;
						array[0, 2] = array[0, 3] ^ 0x1654218C;
						array[2, 3] = array[2, 0] ^ 0x74319B15;
						array[1, 0] = array[0, 1] ^ 0x93E81A6;
						int num11 = array[1, 0] ^ 0x768ECF1D;
						num = ((int)num4 * -1332190525) ^ -125904075 ^ num11;
					}
				}
			}
		}
	}

	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CCleanupRemoteFilesAsync_003Ed__9 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder _003C_003Et__builder;

		public HttpClient client;

		public string baseUrl;

		public string tokenName;

		public CancellationToken cancellationToken;

		public UploadTicket uploadTicket;

		private ConfiguredTaskAwaitable<string>.ConfiguredTaskAwaiter _003C_003Eu__1;

		private ConfiguredTaskAwaitable.ConfiguredTaskAwaiter _003C_003Eu__2;

		[MethodImpl(MethodImplOptions.NoInlining)]
		private void MoveNext()
		{
			object[] array = default(object[]);
			try
			{
				array = new object[1] { this };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Ym44aGw/azlbWWrsXVtekVs=", array);
			}
			finally
			{
				this = (_003CCleanupRemoteFilesAsync_003Ed__9)array[0];
			}
		}

		void IAsyncStateMachine.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			this.MoveNext();
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		[DebuggerHidden]
		private void SetStateMachine(IAsyncStateMachine stateMachine)
		{
			object[] array = default(object[]);
			try
			{
				array = new object[2] { this, stateMachine };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OG44bT89PTQMDkRrCgwJxww=", array);
			}
			finally
			{
				this = (_003CCleanupRemoteFilesAsync_003Ed__9)array[0];
			}
		}

		void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
			this.SetStateMachine(stateMachine);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static string _0024_0028_002A_005E_003F_0024_0029_002A(string P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NTNjYGQ1ZWRRUxIOV1FUnVE=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static string _0024_0024_0024_005E_003D_0024_003D_002D(string P_0, string P_1, string P_2, string P_3)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[4] { P_0, P_1, P_2, P_3 };
			return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OGk/OTg7OzQMDkiICgwJwQw=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static Task<string> _003C_002F_005E_0021_0025_0025_003F_0028(HttpClient P_0, string P_1, CancellationToken P_2)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { P_0, P_1, P_2 };
			return (Task<string>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MjUyaGkwMmNRUxSGV1FUn1E=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static ConfiguredTaskAwaitable _005E_0024_003C_0026_0029_002F_003D_005E(Task P_0, bool P_1)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
			return (ConfiguredTaskAwaitable)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MGQ2N2Q1YTcHBUAOAQcCyAc=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}
	}

	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CStartProtectionJobAsync_003Ed__3 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder<string> _003C_003Et__builder;

		public string uploadKey;

		public string encryptedReference;

		public ProtectionRequest request;

		public sEp_003D _003C_003E4__this;

		public CancellationToken cancellationToken;

		private HttpClient _003Cclient_003E5__2;

		private MultipartFormDataContent _003Cform_003E5__3;

		private HttpResponseMessage _003Cresponse_003E5__4;

		private ConfiguredTaskAwaitable<HttpResponseMessage>.ConfiguredTaskAwaiter _003C_003Eu__1;

		private ConfiguredTaskAwaitable<string>.ConfiguredTaskAwaiter _003C_003Eu__2;

		[MethodImpl(MethodImplOptions.NoInlining)]
		private void MoveNext()
		{
			object[] array = default(object[]);
			try
			{
				array = new object[1] { this };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZjE1Zzo0N2QCA6rtBAIH5AI=", array);
			}
			finally
			{
				this = (_003CStartProtectionJobAsync_003Ed__3)array[0];
			}
		}

		void IAsyncStateMachine.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			this.MoveNext();
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		[DebuggerHidden]
		private void SetStateMachine(IAsyncStateMachine stateMachine)
		{
			object[] array = default(object[]);
			try
			{
				array = new object[2] { this, stateMachine };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YmY2MmVhYmUHBunrAQcC4Ac=", array);
			}
			finally
			{
				this = (_003CStartProtectionJobAsync_003Ed__3)array[0];
			}
		}

		void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
			this.SetStateMachine(stateMachine);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static void _0024_0023_0024_0028_0028_005E_003D_002A(MultipartFormDataContent P_0, HttpContent P_1, string P_2)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { P_0, P_1, P_2 };
			_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YjhoPWw9PjlbWoMIXVtes1s=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static string @_002A_002A_005E_002A_002F_0021_002F(ProtectionRequest P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Ymc3MWZjNjdVVIwkU1VQvFU=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static string _002F_003E_003D_0029_0026_005E_0029_0028(ProtectionRequest P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NTMzZDc5YzUAAdrqBgAF6gA=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static ProtectionOptions _003E_0021_005E_0025_0040_002B_0028_002B(ProtectionRequest P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (ProtectionOptions)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NWZpN2NjaGRRUIq9V1FUulE=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static bool _0023_002B_0023_003D_0024_0025_002F_0029(ProtectionOptions P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YzgyYDVjYmIBAN3sBwEE7QE=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static bool _0024_0024_005E_0021_003E_0028_0024_002D(ProtectionOptions P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZDNiNzZmYTZSU4+xVFJXv1I=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static bool _002A_003D_003E_003D_002D_0021__003D(ProtectionOptions P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NzJlMTA3NzcAAd6rBgAF7gA=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static AntiTamperMode _002D_002B_002D_0028_003D_0028_0026_(ProtectionOptions P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (AntiTamperMode)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MWY0NTgzNjEAAeAGBgAF7wA=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static bool _005E_003F_003F_003E_003C_002A_005E_002D(ProtectionOptions P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MDdiMjBgaWFRULGDV1FUoVE=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static bool _002F_0025__0023_0026_0029_003D_0026(ProtectionOptions P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NjBlZWRjYWNVVLTPU1VQpFU=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static bool @_002D_003F_0028_003E_003C_0024_0023(ProtectionOptions P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MzBhN2Y0MzQHBuVlAQcC9Qc=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static bool _0021_0028_0021_0028_002D_0028_003F_(ProtectionOptions P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Mj4yNz8+YDQGB+VqAAYD9QY=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static bool _002F_002A_0040_005E_002D_0024_002F_0021(ProtectionOptions P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OT8zPT47PDMKC+54DAoP/go=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static bool _003C_0023_003F_002A__002A_0026_0023(ProtectionOptions P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Mmo/b25uaDkLCu6LDQsO/gs=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static string _005E_005E_002A_0021_002D_002F_003E_0024(string P_0, string P_1)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
			return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZGhkNWBkYTVRULfWV1FUp1E=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static Task<HttpResponseMessage> _002F_003D_003E_005E_0026__0021_0029(HttpClient P_0, string P_1, HttpContent P_2, CancellationToken P_3)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[4] { P_0, P_1, P_2, P_3 };
			return (Task<HttpResponseMessage>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Y2NkNms0NzFSU7X4VFJXpVI=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static HttpContent _0028_0024_005E_005E_002A_003C_003C_002F(HttpResponseMessage P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (HttpContent)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Mz8wPj4zYDUGB+8pAAYD/gY=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static Task<string> _003C_003E_003D_002D_005E_002B_002D_003D(HttpContent P_0, CancellationToken P_1)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
			return (Task<string>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OTdtOj8/bDYPDuWsCQ8K9g8=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static bool @_005E__002A_0040_003E_005E_0024(string P_0, string P_1, StringComparison P_2)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { P_0, P_1, P_2 };
			return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YWE1amplNjJTUriPVVNWqVM=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static string[] _002D_002F_0040_0024_0028_002D_003C_0025(string P_0, char P_1, StringSplitOptions P_2)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { P_0, P_1, P_2 };
			return (string[])_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MTFiMTAyPTUEBekcAgQB/wQ=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static void _0023_002A_0024_002B_0040_0028_003C_0024(IDisposable P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MjQzZjVgNDEDAu0/BQMG/wM=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}
	}

	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CWaitForProtectedFileAsync_003Ed__4 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder<byte[]> _003C_003Et__builder;

		public sEp_003D _003C_003E4__this;

		public string tokenName;

		public CancellationToken cancellationToken;

		public IProgress<ProtectionProgress> progress;

		public UploadTicket uploadTicket;

		private HttpClient _003Cclient_003E5__2;

		private string _003CbaseUrl_003E5__3;

		private string _003CfileUrl_003E5__4;

		private ConfiguredTaskAwaitable<string>.ConfiguredTaskAwaiter _003C_003Eu__1;

		private ConfiguredTaskAwaitable<byte[]>.ConfiguredTaskAwaiter _003C_003Eu__2;

		private ConfiguredTaskAwaitable.ConfiguredTaskAwaiter _003C_003Eu__3;

		[MethodImpl(MethodImplOptions.NoInlining)]
		private void MoveNext()
		{
			object[] array = default(object[]);
			try
			{
				array = new object[1] { this };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Yz1pbGw4YjhbWqo+XVtepls=", array);
			}
			finally
			{
				this = (_003CWaitForProtectedFileAsync_003Ed__4)array[0];
			}
		}

		void IAsyncStateMachine.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			this.MoveNext();
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		[DebuggerHidden]
		private void SetStateMachine(IAsyncStateMachine stateMachine)
		{
			object[] array = default(object[]);
			try
			{
				array = new object[2] { this, stateMachine };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MWE2Z2BnZGFQUnlsVlBVrlA=", array);
			}
			finally
			{
				this = (_003CWaitForProtectedFileAsync_003Ed__4)array[0];
			}
		}

		void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
			this.SetStateMachine(stateMachine);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static TimeSpan _002B_0029_005E_003F_0025_0023_0025_005E(double P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (TimeSpan)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("M2IxYTEybmRXVU9uUVdSqFc=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static string @_0040_0024_0028_0021_003D_002A_002D(string P_0, string P_1)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
			return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MmdhYDRgYjEDARoGBQMFAwM=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static string _0021_0026_0026__003D_003C_0029_0023(string P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZWdsN2A3YTBVV0/eU1VTVFU=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static string @_0029__002B_002D_0040_002B_003D(string P_0, string P_1, string P_2)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { P_0, P_1, P_2 };
			return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NDdlZGQ0M2FVV06pU1VTV1U=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static string _0024_0026_003E_002B_0029_0023_003E_(string P_0, string P_1, string P_2, string P_3)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[4] { P_0, P_1, P_2, P_3 };
			return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OWxqaj06bDcODBMZCA4IDQ4=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static bool _003D_003E_002F_0026_0028_005E_0024_0029(string P_0, string P_1)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
			return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZDc3Y2I0ajZSUEwKVFJUVlI=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static void _0024_0026__003E_0040_0025__003F(ProtectionProgress P_0, string P_1)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
			_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NGg9PD4/aTkNDy0uCw0LCA0=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static void _0024_0024_003C_003C_002B_003D_003D_0021(ProtectionProgress P_0, double? P_1)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
			_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Nm1jNGdmNmNVV3RHU1VTU1U=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static bool _0029_0029_005E_003D_002F_003E_0023_005E(string P_0, string P_1, StringComparison P_2)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { P_0, P_1, P_2 };
			return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZGtqamVgYjZSUHDfVFJUVVI=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static Task<byte[]> _002B_003E_003F_002F_003F_0024_003D_003F(HttpClient P_0, string P_1, CancellationToken P_2)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { P_0, P_1, P_2 };
			return (Task<byte[]>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZmQ3YDA0MmMFByabAwUDDQU=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static TimeSpan _005E_0040_002D_005E__003F_002D_005E(double P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (TimeSpan)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NTxua2k9PDgNDyhJCw0LBA0=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static Task _003E_0024_002D_0026_002A_0021_005E_0024(TimeSpan P_0, CancellationToken P_1)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
			return (Task)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YmI8ND1lMmYEBiJoAgQCDgQ=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static ConfiguredTaskAwaitable _0023_002F_003F_005E_0021_0029_002B_0024(Task P_0, bool P_1)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
			return (ConfiguredTaskAwaitable)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MzQ0YjdnNWJRU3YhV1FXWlE=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static void _0024_002D_0025_0026_002A_002D_0024_003F(IDisposable P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("M2YyOzBhYTECACqOBAIEDgI=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}
	}

	private readonly Dhr_003D vvq_003D;

	public sEp_003D(Dhr_003D qaX_003D)
	{
		while (true)
		{
			int num = -1595993903;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(((-(-(~num2) - -755205649 * (-1802055961 * (-1892853761 * --676701286) + (((1368605975 - -91743528 - --70589056) ^ 0x66E0C979) + -1556091795 * (0x648509A7 ^ 0x958A950)) - (1950501369 + ~(~(~1184759962 - (1873795860 + -685957212)))))) + -(-605116425 * 1480065526 + -166871066 - ~(2014936127 * -481199305) - (1970520554 + (--516306255 ^ --1285890178))) - -(-489451279 ^ -1881029596) - (~745560488 * -1885785799 - ~-1966842589) + 342412306) ^ -1321064384) + 521833581)) % 3;
				int num5 = 1462725028;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = num5 * -1284614933 - 1288622467;
					num5 = (num5 - --1519169807) * 938846455;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -1411647445 - (num7 - -518517413);
					num7 = num7 - (0x59FE74AF ^ -295545667) - 826789930;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 2030035532;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 ^= 0x78FFE24E;
					}
					if (num3 == (uint)num9)
					{
					}
					return;
				}
				vvq_003D = qaX_003D;
				int[,] array = new int[4, 4];
				array[0, 0] = 1582276520;
				array[0, 1] = -1371965173;
				array[0, 2] = 468999009;
				array[0, 3] = -1078952674;
				array[1, 0] = -59195349;
				array[1, 1] = 2141209650;
				array[1, 2] = -1412409987;
				array[1, 3] = 169695790;
				array[2, 0] = 414331213;
				array[2, 1] = 1354761035;
				array[2, 2] = 1972601744;
				array[2, 3] = -949598676;
				array[3, 0] = -283327435;
				array[3, 1] = -1884132593;
				array[3, 2] = -157816477;
				array[3, 3] = 223484955;
				array[3, 0] = array[3, 3] ^ 0x467CE9E2;
				array[1, 1] = array[3, 2] ^ -811511558;
				array[2, 2] ^= 669528009;
				array[1, 1] = array[2, 3] ^ -65798209;
				int num11 = array[1, 1] ^ 0x54546826;
				num = (int)((num4 * 259638035) ^ 0x14EF341) ^ num11;
			}
		}
	}

	[AsyncStateMachine(typeof(_003CProtectAsync_003Ed__2))]
	public Task<ProtectionResult> ProtectAsync(ProtectionRequest XjF_003D, IProgress<ProtectionProgress> PBI_003D, CancellationToken QCO_003D)
	{
		_003CProtectAsync_003Ed__2 stateMachine = default(_003CProtectAsync_003Ed__2);
		stateMachine._003C_003Et__builder = AsyncTaskMethodBuilder<ProtectionResult>.Create();
		stateMachine._003C_003E4__this = this;
		while (true)
		{
			int num = 312524751;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~((-370417563 - ~(((~((num2 + (((0x568AACEA ^ -499670532) + (((-(550445623 * (1912065011 * 2053436617)) - -(1328903877 * (-783240149 * 1428505503))) ^ 0x20FE84FA) + ~(~(~(949700193 * (1208478153 + -415484131) - ~(-47523154 - 697654574)))))) ^ -(-((-384224265 * -(295373335 * --216865955 + -930368253)) ^ 0x1F41A4E5)))) * 1455354783) - ~(2093489861 * 643748092)) ^ -613399221) - ((~(0x79B19FF4 ^ -1085519693) - -(616693398 + 632526853)) ^ -41709711))) * 1957458101))) % 7;
				int num5 = 143656978;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = (num5 + ~1790304947) ^ -1709937716;
					num5 = num5 ^ 0x44CBF4F4 ^ -983011633;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1654582595;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = num7 * 1713053223 - 1797461814;
					num7 = -(650686883 * -1399986452 - num7);
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1613772806;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = (num9 ^ -1792872146) * -1438895099;
						num9 -= -630525465 ^ -1538185896;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 5;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = num11 ^ 0xDFD02E ^ 0x7D97DCDD;
							num11 = ~num11;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 0;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = num13 + --1246312684 + -1460303974;
								num13 = 2090337480 - (num13 - (-1380003153 ^ 0x4295FC66));
							}
							if (num3 != (uint)num13)
							{
								int num15 = -1078535374;
								_ = 0;
								for (int num16 = 0; num16 < 1; num16++)
								{
									num15 ^= -1078535372;
								}
								if (num3 != (uint)num15)
								{
									int num17 = -1911029617;
									_ = 0;
									for (int num18 = 0; num18 < 2; num18++)
									{
										num17 = -196374240 - (num17 ^ -2108967128);
										num17 = ~(num17 - (0x25531D31 ^ 0xBAC43F3));
									}
									if (num3 != (uint)num17)
									{
									}
									return stateMachine._003C_003Et__builder.Task;
								}
								stateMachine._003C_003Et__builder.Start(ref stateMachine);
								int[,] array = new int[4, 3];
								array[0, 0] = -1187764531;
								array[0, 1] = -1647732470;
								array[0, 2] = 1007381741;
								array[1, 0] = 435885740;
								array[1, 1] = -1686477126;
								array[1, 2] = -1979956902;
								array[2, 0] = 211014639;
								array[2, 1] = 1670281087;
								array[2, 2] = 2132387126;
								array[3, 0] = 444286344;
								array[3, 1] = -1769268677;
								array[3, 2] = -1146438827;
								array[0, 2] = array[2, 0] ^ 0x4B747128;
								array[0, 1] = array[0, 2] ^ 0x366C5CE0;
								array[0, 2] ^= -195143588;
								array[2, 1] = array[2, 2] ^ -430920113;
								int num19 = array[2, 1] ^ -1223133060;
								num = ((int)num4 * -833927266) ^ -926778810 ^ num19;
							}
							else
							{
								stateMachine._003C_003E1__state = -1;
								int[] array2 = new int[5] { -1928737462, 218299998, 1573767441, 19731324, 455034009 };
								array2[1] ^= 821025643;
								array2[4] = array2[0] ^ 0x3E703169;
								array2[4] = array2[0] ^ 0x4AD43ED5;
								int[] array3 = new int[6];
								array3[0] = -1799967644;
								array3[1] = -1447372242;
								array3[2] = -806881317;
								array3[3] = 792993469;
								array3[4] = -149471349;
								array3[5] = -1209612171;
								array3[0] = array2[3] ^ 0x30900CAE;
								array3[1] ^= -818037306;
								array3[3] ^= -665869379;
								int num20 = array3[0] ^ 0x5678CF2A;
								num = (int)((num4 * 176158737) ^ 0x23516D51) ^ num20;
							}
						}
						else
						{
							stateMachine.cancellationToken = QCO_003D;
							int[] array4 = new int[4] { 536235619, -32378549, -402905640, -1568933892 };
							array4[2] ^= -1671043217;
							array4[2] ^= 586505200;
							array4[2] = array4[3] ^ -1581966252;
							int[] array5 = new int[4] { 1619556412, -748468801, -1501899919, 343383626 };
							int[][] array6 = new int[2][] { array4, array5 };
							array5[2] = array6[0][0] ^ 0x581BE39C;
							array5[3] = array5[2] ^ 0x42588766;
							array5[0] = array5[1] ^ -198348887;
							array5[1] = array5[0] ^ -382117411;
							int num21 = array6[1][2] ^ -785038453;
							num = (int)((num4 * 1518389149) ^ 0x30D080A9) ^ num21;
						}
					}
					else
					{
						stateMachine.progress = PBI_003D;
						int[] array7 = new int[4] { -846574477, -160651084, -1158307315, 454826144 };
						array7[2] ^= 96299367;
						array7[3] = array7[2] ^ 0x1D851F2B;
						array7[2] = array7[0] ^ 0x4F10140D;
						int[] array8 = new int[5];
						array8[0] = -414557423;
						array8[1] = 1597758395;
						array8[2] = -1485893132;
						array8[3] = -45909237;
						array8[4] = -788712804;
						array8[2] = array7[0] ^ 0x2FDAAD59;
						array8[3] = array8[1] ^ 0x363F6DAB;
						array8[0] = array8[4] ^ -230542793;
						int num22 = array8[2] ^ -1611088638;
						num = ((int)num4 * -1047377887) ^ 0x93B4B16 ^ num22;
					}
				}
				else
				{
					stateMachine.request = XjF_003D;
					int[] array9 = new int[6];
					array9[0] = -806305232;
					array9[1] = 772342278;
					array9[2] = -701140843;
					array9[3] = -97195369;
					array9[4] = 546727609;
					array9[5] = -1728633909;
					array9[4] = array9[2] ^ 0x4CAD566E;
					array9[4] ^= -554019981;
					int[] array10 = new int[5] { -375586643, 870625491, 1009058689, -1924773846, -2066351505 };
					int[][] array11 = new int[2][] { array9, array10 };
					array10[0] = array11[0][0] ^ -2079964095;
					array10[3] = array10[2] ^ -270102931;
					array10[4] = array10[0] ^ 0x51B82E05;
					int num23 = array11[1][0] ^ 0x5FAAE944;
					num = ((int)num4 * -1813588398) ^ -1141649888 ^ num23;
				}
			}
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[AsyncStateMachine(typeof(_003CStartProtectionJobAsync_003Ed__3))]
	private Task<string> aYN_003D(ProtectionRequest kJK_003D, string CQh_003D, string KhA_003D, CancellationToken Fgc_003D)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[5] { this, kJK_003D, CQh_003D, KhA_003D, Fgc_003D };
		return (Task<string>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZG1jY2VlZTBUVfNgUlRRPlQ=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[AsyncStateMachine(typeof(_003CWaitForProtectedFileAsync_003Ed__4))]
	private Task<byte[]?> blA_003D(string RXr_003D, UploadTicket YIA_003D, IProgress<ProtectionProgress> JSk_003D, CancellationToken rHt_003D)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[5] { this, RXr_003D, YIA_003D, JSk_003D, rHt_003D };
		return (Task<byte[]>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("M2FgbmYyY2RXVriaUVdSPFc=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[AsyncStateMachine(typeof(_003CCheckStateAsync_003Ed__5))]
	private static Task<string> Drd_003D(HttpClient NAL_003D, string qNk_003D, CancellationToken PBV_003D)
	{
		_003CCheckStateAsync_003Ed__5 stateMachine = default(_003CCheckStateAsync_003Ed__5);
		stateMachine._003C_003Et__builder = AsyncTaskMethodBuilder<string>.Create();
		while (true)
		{
			int num = -674878658;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~((~(-(num2 * 1055838635 * -305439419 - ((-915555487 ^ (-1644845115 + 65556617 * (-915711685 + (-722625285 - 722054897) + -(--1752062211)))) + (-(--1195589328 + -33684916 - (-2130979216 ^ -548174147) * -333718969) + ((-1494621976 + 1608207059 - (-1049814100 + -130918122)) * -1436495451 - (-(~-1011330406) - (-2050391105 ^ 0x7C678231)) + ~(1459892278 - (805850322 + 1141078275)) * 775618657))) + ((-(-(-1629361729)) - 338616430 + (((-15571788 ^ 0x4C4658B3) - --1369102213 * 794464293) ^ -1685944908)) ^ ~(-(-424163185 + -987324798 + (~-1365855926 + ~344626547)))))) * -823074169 * -1985993255) ^ -2030088044))) % 7;
				int num5 = -4;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 = ~num5;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -1453055866;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -num7;
					num7 = -(num7 * 2120280225);
				}
				if (num3 != (uint)num7)
				{
					int num9 = -1583900579;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 ^= -1583900579;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -1087003861;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 -= -1087003863;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 1053938430;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 ^= 0x3ED1D2FA;
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
									int num17 = 2095487401;
									_ = 0;
									for (int num18 = 0; num18 < 2; num18++)
									{
										num17 = -(num17 * 97200823);
										num17 = (num17 ^ --373711443) + -2066426483;
									}
									if (num3 != (uint)num17)
									{
									}
									return stateMachine._003C_003Et__builder.Task;
								}
								stateMachine._003C_003Et__builder.Start(ref stateMachine);
								int[] array = new int[4] { -1947959812, 1957799345, 1923617134, 1035419528 };
								array[0] ^= -1060689855;
								array[1] ^= 803547906;
								array[1] ^= 163009849;
								int[] array2 = new int[6];
								array2[0] = 383370806;
								array2[1] = -1163251068;
								array2[2] = 418310610;
								array2[3] = 3449013;
								array2[4] = 1201925789;
								array2[5] = 1716540171;
								array2[3] = array[3] ^ -1847718325;
								array2[0] = array2[1] ^ -1254579388;
								array2[2] = array2[1] ^ -538186376;
								int num19 = array2[3] ^ 0x3F257A38;
								num = (int)((num4 * 192080793) ^ 0xD0D9463Du) ^ num19;
							}
							else
							{
								stateMachine._003C_003E1__state = -1;
								int[] array3 = new int[5] { -1270319151, 1053968345, -351760704, 1054620793, -1999139905 };
								array3[4] ^= 153258155;
								array3[0] = array3[2] ^ -1293486357;
								int[] array4 = new int[6];
								array4[0] = 522203301;
								array4[1] = 1569133419;
								array4[2] = -947057307;
								array4[3] = 852110768;
								array4[4] = 139935742;
								array4[5] = 1140476187;
								array4[1] = array3[2] ^ 0x529DFD95;
								array4[2] = array4[3] ^ -2179561;
								array4[0] ^= -1031889422;
								array4[3] = array4[5] ^ -1821121574;
								int num20 = array4[1] ^ -570902895;
								num = (int)((num4 * 1739918771) ^ 0xA3C9B2D4u) ^ num20;
							}
						}
						else
						{
							stateMachine.cancellationToken = PBV_003D;
							int[] array5 = new int[6];
							array5[0] = -268532256;
							array5[1] = 451031851;
							array5[2] = -1755466955;
							array5[3] = -700276258;
							array5[4] = -1730147624;
							array5[5] = -401159973;
							array5[4] = array5[2] ^ -260007975;
							array5[3] = array5[2] ^ 0x3DD47040;
							int[] array6 = new int[7];
							array6[0] = -603130754;
							array6[1] = -1923478630;
							array6[2] = 1350620297;
							array6[3] = 709514710;
							array6[4] = 541284611;
							array6[5] = 1383124697;
							array6[6] = 1652780861;
							array6[5] = array5[0] ^ -813045542;
							array6[2] ^= 1129275754;
							array6[3] = array6[1] ^ -1878065584;
							array6[4] = array6[5] ^ 0x3A13415D;
							int num21 = array6[5] ^ -855592465;
							num = (int)((num4 * 1516659953) ^ 0x107EA36F) ^ num21;
						}
					}
					else
					{
						stateMachine.url = qNk_003D;
						int[] array7 = new int[7];
						array7[0] = -257846789;
						array7[1] = 905745580;
						array7[2] = 2087461268;
						array7[3] = -1896352448;
						array7[4] = -442474866;
						array7[5] = -1244195687;
						array7[6] = 592735403;
						array7[0] = array7[5] ^ -737341728;
						array7[0] = array7[6] ^ -1380872183;
						array7[0] = array7[6] ^ 0x26DE0A97;
						int[] array8 = new int[4];
						array8[0] = 1460609041;
						array8[1] = -317870758;
						array8[2] = 917334032;
						array8[3] = -1804160684;
						array8[1] = array7[1] ^ 0x4BBF0847;
						array8[2] = array8[1] ^ -1552381784;
						array8[3] ^= 1840593617;
						int num22 = array8[1] ^ -564315759;
						num = (int)((num4 * 920488521) ^ 0x9AEF980Au) ^ num22;
					}
				}
				else
				{
					stateMachine.client = NAL_003D;
					int[] array9 = new int[4];
					array9[0] = -1078272578;
					array9[1] = 2038598207;
					array9[2] = 1527095898;
					array9[3] = 2077267918;
					array9[2] = array9[0] ^ -310846836;
					array9[2] ^= -1358347510;
					array9[0] = array9[2] ^ 0x136D7AE2;
					int[] array10 = new int[7];
					array10[0] = 1276256780;
					array10[1] = 396309648;
					array10[2] = 1947480497;
					array10[3] = 602818255;
					array10[4] = 1117934168;
					array10[5] = -1474412021;
					array10[6] = -1522893413;
					array10[0] = array9[3] ^ -33196305;
					array10[5] = array10[0] ^ -217056271;
					array10[1] ^= -1825273170;
					array10[1] = array10[6] ^ -206119655;
					int num23 = array10[0] ^ -278780130;
					num = ((int)num4 * -593383320) ^ 0xC5910B8 ^ num23;
				}
			}
		}
	}

	private static HttpClient UAl_003D(TimeSpan? DPC_003D = null)
	{
		HttpClient httpClient = new HttpClient();
		_002F_003E_003C_0024_003F_002A_002D_002A(httpClient, DPC_003D ?? _002D_0040_002A_005E_002B_0023_0023_003C(5.0));
		_003F_003F__005E_0024_0028_003E_003C(httpClient, 2147483647L);
		_002F_003E_005E_0040_0040_0040_0023_002B(_002B_0028_002B_0025_0024_005E__0021(httpClient)).ParseAdd(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x1B9C ^ 0x1A48]);
		return httpClient;
	}

	private static string llb_003D(AntiTamperMode Qpg_003D)
	{
		if (Qpg_003D != AntiTamperMode.Jit)
		{
			uint num2;
			int num4;
			do
			{
				int num = -1695359793;
				uint num3;
				num2 = (num3 = (uint)(((1361496581 - (~((1975416565 + (-859535122 ^ ((-1957415625 * 1350648557 + --2001999083) ^ -1877501903))) ^ (-((1075901790 - 7618063 - --1211780119) * 175306317) + (~(--1618026568 * 312484249) - (~-2133760580 + ~-1912432781) * -616706965))) * 500002349 - (num - -(~(~(-(-(-1359789935 * (-140808961 * 80977407)))) ^ -687270002)) * 679628171) - (0x5F024999 ^ ((-(-(~-1453192845)) + (382101322 + --917262943 - -(642559470 + 448158726))) ^ -2073530696 ^ ~((-1928570814 * 361069975 - 1818112485 * 79995157 - -134080776) ^ -1280176029))))) * -1852655289 + 966694530) * 1858601511)) % 3;
				num4 = -1;
				_ = 0;
				for (int num5 = 0; num5 < 1; num5++)
				{
					num4 = ~num4;
				}
			}
			while (num2 == (uint)num4);
			int num6 = 2;
			_ = 0;
			for (int num7 = 0; num7 < 2; num7++)
			{
				num6 = ~num6 - -1451456761;
				num6 = ~(~num6);
			}
			if (num2 == (uint)num6)
			{
				return _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[519 - 9 - 27 - 2];
			}
			int num8 = -2;
			_ = 0;
			for (int num9 = 0; num9 < 1; num9++)
			{
				num8 = ~num8;
			}
			if (num2 == (uint)num8)
			{
			}
		}
		return _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x611 ^ 0x7F3];
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static string MUb_003D()
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[0];
		return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YToyYWcxOmMCACgBBAIHbQI=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[AsyncStateMachine(typeof(_003CCleanupRemoteFilesAsync_003Ed__9))]
	private static Task Ncv_003D(HttpClient kTX_003D, string XsA_003D, string hDV_003D, UploadTicket Cnx_003D, CancellationToken bZD_003D)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[5] { kTX_003D, XsA_003D, hDV_003D, Cnx_003D, bZD_003D };
		return (Task)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MjU1Y2U4OTMBAy4vBwEEcQE=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	static TimeSpan _002D_0040_002A_005E_002B_0023_0023_003C(double P_0)
	{
		TimeSpan result = default(TimeSpan);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -140793685;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(((-num2 - -((-1115474785 ^ (-(-(-(~-1857898166))) + 857847318)) - -1483113410)) * 324831927) ^ (~(--182497641 - ~(~(-1078311277 ^ 0x342FD872))) - (((~(-984814405 + -2078896880) - -(~-476769829)) ^ (-39042120 - -856348625 * (-555870625 * 1603957807))) + ((-1364338391 ^ (-1677200932 + --1391899765)) - (-(149797553 * 253558388) - (-2139176300 * -884101931 - ~-646860480)))))))) % 3;
					int num5 = -118809912;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -num5 - 59404958;
						num5 = ~num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1385028280;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -1385028281;
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
					result = TimeSpan.FromMinutes(P_0);
					int[] array = new int[7];
					array[0] = 352068534;
					array[1] = -725009215;
					array[2] = -1752824162;
					array[3] = 168050758;
					array[4] = 1251950053;
					array[5] = -359494433;
					array[6] = -221222241;
					array[6] = array[3] ^ -402675041;
					array[6] = array[3] ^ 0x1773F4A8;
					int[] array2 = new int[7];
					array2[0] = 1739431880;
					array2[1] = 1209309182;
					array2[2] = 352308484;
					array2[3] = -1131959675;
					array2[4] = -925673310;
					array2[5] = -183387858;
					array2[6] = -557854836;
					array2[2] = array[0] ^ -1378463823;
					array2[0] = array2[5] ^ 0x6504E9EC;
					array2[6] = array2[1] ^ 0x533E844C;
					array2[5] = array2[2] ^ 0x63631A24;
					int num11 = array2[2] ^ -2092229616;
					num = ((int)num4 * -1326675040) ^ -454601056 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _002F_003E_003C_0024_003F_002A_002D_002A(HttpClient P_0, TimeSpan P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1703514772;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((((((0x3776DF78 ^ (2002714320 - (0x61B60B3 ^ (35516587 * -(-224086841 * 8564436))))) - (-num2 ^ (-(-402885425 ^ (-(~-874460569) ^ -229464073)) - -148640035 - -(~((~(--288370599) ^ -930162407) - -1649274612) + ~((-606929354 + -844249731 - --736670241) * -442861487 + (-2107803947 + 525263042 - ((-1885486586 ^ -1637662161) + (-1278958014 - -1364885430)))))))) * -651180127) ^ -1009403981 ^ -201403864 ^ -851963559) * 1591196869) ^ 0x47534B98))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(num5 + --58959981);
						num5 = -(-num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -816057054;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= -816057056;
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
					P_0.Timeout = P_1;
					int[] array = new int[4];
					array[0] = 104624805;
					array[1] = 575813790;
					array[2] = 915306784;
					array[3] = 1319148363;
					array[3] = array[1] ^ 0x7E6FA19E;
					array[2] = array[0] ^ 0x16CFB9E9;
					array[2] = array[0] ^ -1246507338;
					int[] array2 = new int[7] { -1968714576, -435810004, -1936357149, 2070310509, -1850277108, -1530882216, -1885501884 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][0] ^ -602486336;
					array2[6] = array2[4] ^ 0x52C7C51A;
					array2[2] = array2[3] ^ -2097774264;
					int num11 = array3[1][0] ^ -1630360106;
					num = (int)((num4 * 454450316) ^ 0x2364A26C) ^ num11;
				}
			}
		}
	}

	static void _003F_003F__005E_0024_0028_003E_003C(HttpClient P_0, long P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1362515051;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(num2 ^ (((-(~(-1208217793 + -812996369 + (-115014187 ^ 0x79205F1F) + (-1221294981 ^ -855120259)) + (~(0x6A5EA113 ^ 0x47338CE6) - -448108665)) + (~-72236707 - (~(0x5B79B5EA ^ 0x518A3129) + -(1368031428 + -1592588331 - (-1058222797 ^ -1819154579)) * -109500601))) ^ (2086546401 * (-(-(-2106504524)) ^ (-673567875 * -(0x712B48B2 ^ -(-332498735)))))) + ~(-1696825681)) ^ (-(~((-(878870836 - -1173590846) ^ -50254711 ^ ((-1699772196 - -355166313) ^ -(-260139804 + 1887554740))) + ~(-(-522745076 - 840317972)))) - ~205719849 * -827492769)) ^ ((~(-1728493539 - -334160497 * -1311376374) + (0x5799CA3 ^ -1444954570) + (-812575488 + -1116612084 - (-1088123577 - -1990304499) + 1917115890 + (0x1AE39001 ^ -646640986))) ^ -2057727639)) * 771193561)) % 3;
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
						num7 = ~(-num7);
						num7 = -(num7 - (-1410464749 + -1718909355));
					}
					if (num3 != (uint)num7)
					{
						int num9 = 512041412;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9 + -1579292569;
							num9 = 779569066 - -1680084955 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.MaxResponseContentBufferSize = P_1;
					int[,] array = new int[4, 4];
					array[0, 0] = 1993850113;
					array[0, 1] = 1535236459;
					array[0, 2] = 634370600;
					array[0, 3] = 1564364791;
					array[1, 0] = -671754083;
					array[1, 1] = 234831638;
					array[1, 2] = -1807698671;
					array[1, 3] = -1099517249;
					array[2, 0] = -978642042;
					array[2, 1] = 1427475818;
					array[2, 2] = -876241682;
					array[2, 3] = -83412191;
					array[3, 0] = 451918974;
					array[3, 1] = 1442410177;
					array[3, 2] = 1632381395;
					array[3, 3] = 947198506;
					array[3, 1] = array[2, 2] ^ -1023305879;
					array[2, 3] = array[1, 3] ^ 0x7272D6EA;
					array[1, 0] = array[0, 2] ^ -1660099454;
					array[0, 2] = array[0, 3] ^ 0x62DCFB05;
					int num11 = array[0, 2] ^ 0x28025AE3;
					num = ((int)num4 * -697649985) ^ -955635401 ^ num11;
				}
			}
		}
	}

	static HttpRequestHeaders _002B_0028_002B_0025_0024_005E__0021(HttpClient P_0)
	{
		HttpRequestHeaders defaultRequestHeaders = default(HttpRequestHeaders);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1850390932;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(~(num2 ^ ((~(-(~(~(-1044129152)))) ^ (-489420866 ^ (-(1202449269 * -1566553073 - (-127489097 - 1660198483)) * 2037989495 + (0x27682B8 ^ 0x62375E4C) - (-1065552930 + ((0x3C779787 ^ -283460886) + (--532913414 + (-1061609185 - -1006726931)) * -423828665))))) - -830940485 * (151340723 + (-2043542105 ^ ((-635635542 + 1872260229 + (0x60085B16 ^ -507003699) + -(-1960305696 + -1353540288)) * 1235547573) ^ ((~(58822597 * 1951806853) + -(-635016099 + 436884684)) ^ -(-813516791 - -529662862 - (-2136450098 - -1532293018)) ^ 0x6BD4B47C))))) * 1414984175 * -1497179055 * -941812611)) ^ 0x74FC4D2C)) % 3;
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
					int num7 = 1013100141;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 273451877;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1426685200;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 1426685200;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					defaultRequestHeaders = P_0.DefaultRequestHeaders;
					int[,] array = new int[3, 4];
					array[0, 0] = -1056117846;
					array[0, 1] = -273777801;
					array[0, 2] = -2071884763;
					array[0, 3] = -1867956692;
					array[1, 0] = -1057936963;
					array[1, 1] = 567086690;
					array[1, 2] = 1022368670;
					array[1, 3] = 1392213114;
					array[2, 0] = -1334757453;
					array[2, 1] = -1806517744;
					array[2, 2] = -993967241;
					array[2, 3] = 2142892554;
					array[2, 3] = array[1, 0] ^ 0x7EFCAC29;
					array[0, 1] = array[0, 0] ^ 0x25B21BB2;
					array[0, 0] = array[2, 0] ^ -1455525541;
					int num11 = array[0, 0] ^ 0x3C99FC3B;
					num = (int)((num4 * 479457146) ^ 0x655AD7EE) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return defaultRequestHeaders;
	}

	static HttpHeaderValueCollection<ProductInfoHeaderValue> _002F_003E_005E_0040_0040_0040_0023_002B(HttpRequestHeaders P_0)
	{
		HttpHeaderValueCollection<ProductInfoHeaderValue> userAgent = default(HttpHeaderValueCollection<ProductInfoHeaderValue>);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 812715601;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~((-((num2 + (-(~(-448460783 ^ 0x7ACF29EB)) - (~((-(~(-978348811 * (-286627405 + -303121353))) - (-136743772 + (1563927204 - (1429793956 - -1589388000)))) ^ ((895701339 * -(--911914337 - (-262357975 - 1631022942))) ^ ((-1228675168 - -(609468366 + -704363767)) * 306722217))) + (~(~(-(~-1178736050 + -431477816) - -((1165385027 - -415068086) * 1037564497))) ^ ((-1925751890 ^ (0x24920388 ^ (0x64014EC2 ^ -(315220212 - 1761085445)))) + 607130981 * ~(0x62AEE0DA ^ -1298235135)))))) * -1647050481) * 1564352043 * 2124735733) ^ -1095883439) - -(-1404903453) - ~1390493540))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 - (-726920022 - 1364888269) + -1595311973;
						num5 = -num5 - -229939673;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -247303794;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 += -1940275087 * -1381244807;
						num7 = (num7 - (-375273237 - 121558672)) * -802318779;
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
					userAgent = P_0.UserAgent;
					int[] array = new int[7];
					array[0] = 1458307886;
					array[1] = 104330376;
					array[2] = -1644279363;
					array[3] = 716684113;
					array[4] = -1690913125;
					array[5] = 2050236532;
					array[6] = -591021488;
					array[4] = array[0] ^ 0x5E0E5CBB;
					array[2] ^= -1871106851;
					array[4] = array[2] ^ -97808030;
					int[] array2 = new int[5];
					array2[0] = 1835299780;
					array2[1] = 209587925;
					array2[2] = -1867036087;
					array2[3] = 1082905539;
					array2[4] = -1315703203;
					array2[4] = array[3] ^ -1884384055;
					array2[0] = array2[4] ^ -248225140;
					array2[2] = array2[3] ^ -2095614802;
					int num11 = array2[4] ^ -362155217;
					num = ((int)num4 * -1140813594) ^ -1939523158 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return userAgent;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static WindowsIdentity _0023_0021_002A_002F_003C_0024_003E_003D()
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[0];
		return (WindowsIdentity)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NGJmMDcyNjQAAitiBgAFdgA=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static SecurityIdentifier _003C_0025_003D_005E_002D_0025_002F_0025(WindowsIdentity P_0)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
		return (SecurityIdentifier)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OW4+aWpra2ZfXXN/WV9aKF8=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static string _005E_003D_002A_0024_002B_005E_003C_0024(IdentityReference P_0)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
		return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZjJoaWdkNDZQUny4VlBVKFA=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static string _005E_003D_005E_0021_0028__0026_003E()
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[0];
		return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Zjs7b21pZzlfXXEvWV9aJl8=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static AsyncTaskMethodBuilder _003D_0024_003E_0023_0021_005E_0024_002D()
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[0];
		return (AsyncTaskMethodBuilder)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NzM0MGAzNDEGBDbzAAYDfAY=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}
}
