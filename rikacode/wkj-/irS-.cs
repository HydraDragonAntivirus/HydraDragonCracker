using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using RikaNET.Core.Services;
using RikaNET.WinUI.Services;

namespace wkj_003D;

public sealed class irS_003D : IFilePickerService
{
	[AsyncStateMachine(typeof(_003CPickAssemblyAsync_003Ed__0))]
	public Task<string?> PickAssemblyAsync()
	{
		_003CPickAssemblyAsync_003Ed__0 stateMachine = default(_003CPickAssemblyAsync_003Ed__0);
		stateMachine._003C_003Et__builder = AsyncTaskMethodBuilder<string>.Create();
		while (true)
		{
			int num = 1698400217;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(-(~(num2 - ~(0x30036919 ^ ~(2065497895 + -(~(-2010121195 * ~-1605778421)) + ~(-(-1518539683 * (-1142228731 * -335853445)) + 37553281))))) + ~(-(1701997258 * 889067951))) ^ ((--1482920980 - 773925781 * 638479851) ^ 0x24D07B2A ^ 0x41F8BC0D))) % 4;
				int num5 = 2062242594;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~(840664987 * 1065552243 - num5);
					num5 = (num5 ^ 0x61F54E59) * 1262102003;
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
					int num9 = -164409555;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 *= -224339803;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -2031087125;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = -401800222 - (num11 ^ -1738415104);
							num11 = -num11 - 1667998994;
						}
						if (num3 != (uint)num11)
						{
						}
						return stateMachine._003C_003Et__builder.Task;
					}
					stateMachine._003C_003Et__builder.Start(ref stateMachine);
					int[,] array = new int[4, 4];
					array[0, 0] = 440243442;
					array[0, 1] = -12935684;
					array[0, 2] = -1871921461;
					array[0, 3] = -1761978528;
					array[1, 0] = -955665373;
					array[1, 1] = 485986424;
					array[1, 2] = -1311053711;
					array[1, 3] = 266346326;
					array[2, 0] = -2043439234;
					array[2, 1] = 13276942;
					array[2, 2] = 1788356305;
					array[2, 3] = 585298239;
					array[3, 0] = -1048565653;
					array[3, 1] = -1145639677;
					array[3, 2] = 571377065;
					array[3, 3] = 1694342560;
					array[0, 3] = array[3, 3] ^ 0x7B1FE36;
					array[1, 3] = array[0, 0] ^ 0x39D13BC6;
					array[1, 0] = array[1, 2] ^ 0x580A520C;
					array[1, 1] = array[2, 2] ^ 0x4A021B03;
					int num13 = array[1, 1] ^ 0x71AC5BDA;
					num = (int)((num4 * 1552855723) ^ 0x6CB8BC33) ^ num13;
				}
				else
				{
					stateMachine._003C_003E1__state = -1;
					int[] array2 = new int[5];
					array2[0] = -1879338875;
					array2[1] = 1948455083;
					array2[2] = -216338237;
					array2[3] = -1491601666;
					array2[4] = -412881947;
					array2[2] = array2[1] ^ -383063904;
					array2[1] = array2[4] ^ 0x69E47B30;
					int[] array3 = new int[6];
					array3[0] = -665327582;
					array3[1] = -287022073;
					array3[2] = 1949364438;
					array3[3] = -665306783;
					array3[4] = 720164249;
					array3[5] = -392481113;
					array3[0] = array2[3] ^ 0x7D995DA9;
					array3[1] = array3[0] ^ -1104071670;
					array3[3] = array3[0] ^ -1385225459;
					array3[4] ^= -699001599;
					int num14 = array3[0] ^ -1219156139;
					num = (int)((num4 * 1245704085) ^ 0x5688BBAE) ^ num14;
				}
			}
		}
	}
}
