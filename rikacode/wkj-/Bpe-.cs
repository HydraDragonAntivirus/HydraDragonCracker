using System;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using RikaNET.Core.Services;
using RikaNET.WinUI.Services;

namespace wkj_003D;

public sealed class Bpe_003D : ILauncherService
{
	[AsyncStateMachine(typeof(_003CLaunchUriAsync_003Ed__0))]
	public Task LaunchUriAsync(Uri EAj_003D)
	{
		_003CLaunchUriAsync_003Ed__0 stateMachine = default(_003CLaunchUriAsync_003Ed__0);
		stateMachine._003C_003Et__builder = _002A_0024_0021_003D_002B_003D_0024_002A();
		while (true)
		{
			int num = -1675784366;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-((-(~(~(((~(-(-973214288)) ^ -2059932537) + (~(-(~-1940034399)) ^ -740094458) + ~(-(1764585298 - 1638259983 + 1180490817) - (~(-960366347 ^ 0x60B3CCFB) + (~-1206525280 - -104077008))) + ((0x665EA86 ^ 0x359C46C3) + (-(702594080 - -1425126311) - -335467459 * 1772216593 * -1005937173 + -1994324485 * (0x7396A135 ^ 0xAF7A874) - ~-1334338190)) + ((~(-947757523 * (1836322564 - 1460174119)) + ~-477835432 + (-1727718958 ^ -344473833 ^ -701278117) * -1287347383 + (4698619 + -707123500)) ^ ((-26499833 * (-1420033796 ^ (--1411611304 * -127433973)) - (-(835826705 - 732550749 - --806913458) + (-1143119021 * -288464724 * -1696160521 + (-99300207 ^ -551134685)))) ^ -373771253)) - num2 * -393385763) * -305274219 - -1557789071))) - 1835053045) * 1494615721))) % 5;
				int num5 = -1766506387;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 -= -1766506391;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1810850235;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = (num7 - (-1097093912 ^ 0xD1B3638)) * -1467215269;
					num7 = ~num7 - 1458351690;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -568407774;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = -num9 ^ 0xD3CB5DE;
						num9 = (num9 ^ 0xAFEE53F) * -277070047;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -182936476;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = -(num11 ^ 0x67F79AF8);
							num11 = (num11 - ~1017670502) * -439485781;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 109203597;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 *= 993515215;
							}
							if (num3 != (uint)num13)
							{
							}
							return stateMachine._003C_003Et__builder.Task;
						}
						stateMachine._003C_003Et__builder.Start(ref stateMachine);
						int[,] array = new int[4, 4];
						array[0, 0] = 1146375972;
						array[0, 1] = -168209365;
						array[0, 2] = 1828730137;
						array[0, 3] = -1261273199;
						array[1, 0] = -114420970;
						array[1, 1] = -1347742879;
						array[1, 2] = 1151288657;
						array[1, 3] = -1132998475;
						array[2, 0] = -882953757;
						array[2, 1] = 981904739;
						array[2, 2] = 97946281;
						array[2, 3] = 1076147561;
						array[3, 0] = -1129277334;
						array[3, 1] = -948988801;
						array[3, 2] = -573164812;
						array[3, 3] = 1126439178;
						array[1, 3] = array[2, 1] ^ -2062001034;
						array[3, 1] = array[0, 1] ^ -710605639;
						array[0, 1] = array[2, 1] ^ -1427697081;
						array[0, 1] = array[1, 1] ^ -1362775452;
						int num15 = array[0, 1] ^ -823218708;
						num = ((int)num4 * -1566047636) ^ -171676008 ^ num15;
					}
					else
					{
						stateMachine._003C_003E1__state = -1;
						int[,] array2 = new int[3, 4];
						array2[0, 0] = -1304179998;
						array2[0, 1] = -1733343575;
						array2[0, 2] = 31031100;
						array2[0, 3] = 1817804084;
						array2[1, 0] = -1817304333;
						array2[1, 1] = 1132592441;
						array2[1, 2] = -1318420358;
						array2[1, 3] = -777179476;
						array2[2, 0] = -27624895;
						array2[2, 1] = 404055430;
						array2[2, 2] = 152811936;
						array2[2, 3] = -316519611;
						array2[2, 3] = array2[2, 0] ^ 0x4E8994F6;
						array2[1, 1] = array2[0, 3] ^ 0x67C0FE68;
						array2[1, 3] = array2[0, 2] ^ 0x6D63815F;
						int num16 = array2[1, 3] ^ 0x439DA805;
						num = (int)((num4 * 1229681938) ^ 0x4B2D879C) ^ num16;
					}
				}
				else
				{
					stateMachine.uri = EAj_003D;
					int[] array3 = new int[5] { 300401706, 86838168, 1748105596, 23587381, 1792117637 };
					array3[3] ^= -1013523317;
					array3[3] = array3[2] ^ -323320615;
					int[] array4 = new int[5] { 2110633147, 119813670, 613095326, 892147017, 762235570 };
					int[][] array5 = new int[2][] { array3, array4 };
					array4[0] = array5[0][4] ^ -1680612375;
					array4[1] = array4[2] ^ -1858878863;
					array4[3] = array4[2] ^ 0x33EE5731;
					int num17 = array5[1][0] ^ 0x175AFF56;
					num = (int)((num4 * 20091338) ^ 0x4F9A98BC) ^ num17;
				}
			}
		}
	}

	static AsyncTaskMethodBuilder _002A_0024_0021_003D_002B_003D_0024_002A()
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
				int num = -1177924077;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(-(~num2)) ^ 0x7C1C41A5) + (0x3B4B2C45 ^ 0x7F3B89C1))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * -579717507 * -773570515;
						num5 = -num5 * 764186183;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1279541892;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x4C444286;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1486370876;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -1486370877;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = AsyncTaskMethodBuilder.Create();
					int[,] array = new int[4, 4];
					array[0, 0] = 500667957;
					array[0, 1] = 735126228;
					array[0, 2] = 862252541;
					array[0, 3] = -221533712;
					array[1, 0] = 1061059721;
					array[1, 1] = 395356284;
					array[1, 2] = 1200065762;
					array[1, 3] = -1981729835;
					array[2, 0] = -545854;
					array[2, 1] = -1810778661;
					array[2, 2] = 1256251350;
					array[2, 3] = -531234074;
					array[3, 0] = -2106019924;
					array[3, 1] = -1765413972;
					array[3, 2] = -1462919539;
					array[3, 3] = 1662448006;
					array[3, 0] = array[3, 3] ^ 0x1E896212;
					array[1, 3] ^= 1873514213;
					array[2, 2] = array[3, 3] ^ -1977939350;
					int num11 = array[2, 2] ^ 0x6964D78D;
					num = (int)((num4 * 1515355534) ^ 0xE6AD6466u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}
}
