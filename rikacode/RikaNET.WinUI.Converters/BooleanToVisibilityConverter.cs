using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace RikaNET.WinUI.Converters;

public sealed class BooleanToVisibilityConverter : IValueConverter
{
	public object Convert(object value, Type targetType, object parameter, string language)
	{
		if (value is bool)
		{
			goto IL_000e;
		}
		int num = 0;
		goto IL_0406;
		IL_0406:
		bool flag = default(bool);
		int num2;
		if (((uint)num & (flag ? 1u : 0u)) == 0)
		{
			num2 = 338433141;
			goto IL_0013;
		}
		int num3 = 0;
		goto IL_0429;
		IL_000e:
		num2 = 754442235;
		goto IL_0013;
		IL_0013:
		uint num5;
		while (true)
		{
			int num4 = num2;
			uint num6;
			num5 = (num6 = (uint)(((~(-901535763) - -(-num4 * -158031283 * -1107266185)) ^ ~(-632395937)) - -(-(-1791425059 ^ 0x72E2431B)) - (-355124082 - (-1919072763 ^ 0x2C11EC5B)))) % 4;
			int num7 = 1134438240;
			_ = 0;
			for (int num8 = 0; num8 < 2; num8++)
			{
				num7 *= 1512579761;
				num7 = ~num7 ^ 0x252E75D5;
			}
			if (num5 == (uint)num7)
			{
				break;
			}
			int num9 = -3;
			_ = 0;
			for (int num10 = 0; num10 < 1; num10++)
			{
				num9 = -num9;
			}
			if (num5 == (uint)num9)
			{
				flag = (bool)value;
				int[,] array = new int[4, 3];
				array[0, 0] = 1491740725;
				array[0, 1] = 1239526751;
				array[0, 2] = -1777604895;
				array[1, 0] = 61036675;
				array[1, 1] = -1481458225;
				array[1, 2] = 784150939;
				array[2, 0] = -1496026391;
				array[2, 1] = -274901513;
				array[2, 2] = -1187248972;
				array[3, 0] = -1031216467;
				array[3, 1] = -2075448373;
				array[3, 2] = 1442499785;
				array[2, 1] = array[1, 2] ^ -1888650633;
				array[0, 0] = array[0, 1] ^ -1230645069;
				array[2, 2] = array[3, 0] ^ 0x192066D3;
				array[2, 0] = array[0, 2] ^ -1421418068;
				int num11 = array[2, 0] ^ -402169493;
				num2 = (int)((num6 * 580991183) ^ 0x26D723BD) ^ num11;
				continue;
			}
			goto IL_011f;
		}
		goto IL_000e;
		IL_0429:
		return (Visibility)num3;
		IL_011f:
		int num12 = -1542503470;
		_ = 0;
		for (int num13 = 0; num13 < 1; num13++)
		{
			num12 *= 1436239449;
		}
		if (num5 != (uint)num12)
		{
			int num14 = 1194659314;
			_ = 0;
			for (int num15 = 0; num15 < 1; num15++)
			{
				num14 = 1194659315 - num14;
			}
			if (num5 != (uint)num14)
			{
			}
			num3 = 1;
			goto IL_0429;
		}
		num = 1;
		goto IL_0406;
	}

	public object ConvertBack(object value, Type targetType, object parameter, string language)
	{
		int num12;
		if (value is Visibility)
		{
			uint num3;
			Visibility visibility = default(Visibility);
			while (true)
			{
				int num = 1946200079;
				while (true)
				{
					int num2 = num;
					uint num4;
					num3 = (num4 = (uint)((~(~num2) - -1591360223 - 31264474 - ((0x7E6203FC ^ 0x30DCD94D) + (-(1531154897 * 894246954) ^ (0x182E0E57 ^ (-1972100405 + ~1279285625))))) * 142922743)) % 3;
					int num5 = 148716809;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0x8DD3D09;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1991370447;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(num7 * 1848137949);
						num7 = -num7 - 124794628;
					}
					if (num3 != (uint)num7)
					{
						goto end_IL_000e;
					}
					visibility = (Visibility)value;
					int[] array = new int[5];
					array[0] = 376531398;
					array[1] = -1010237718;
					array[2] = 1592112642;
					array[3] = 789497418;
					array[4] = 370878891;
					array[3] = array[0] ^ 0xD4A2695;
					array[3] = array[1] ^ -606801509;
					int[] array2 = new int[6];
					array2[0] = 250621051;
					array2[1] = 1698272127;
					array2[2] = 1393446926;
					array2[3] = -1753196729;
					array2[4] = -1343803966;
					array2[5] = -1873161078;
					array2[3] = array[2] ^ 0x4175D22F;
					array2[0] = array2[4] ^ -1180268136;
					array2[0] = array2[1] ^ -110770780;
					int num9 = array2[3] ^ -1559339455;
					num = (int)((num4 * 640798024) ^ 0x87B9EBE8u) ^ num9;
				}
				continue;
				end_IL_000e:
				break;
			}
			int num10 = 67633152;
			_ = 0;
			for (int num11 = 0; num11 < 2; num11++)
			{
				num10 += ~1189947369;
				num10 = (num10 - ~1563125754) ^ -1646006024;
			}
			if (num3 != (uint)num10)
			{
			}
			num12 = ((visibility == Visibility.Visible) ? 1 : 0);
		}
		else
		{
			num12 = 0;
		}
		return (byte)num12 != 0;
	}
}
