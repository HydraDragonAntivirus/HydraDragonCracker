using System;
using System.CodeDom.Compiler;
using System.Diagnostics;
using Microsoft.UI.Xaml.Markup;

namespace RikaNET.WinUI.RikaNET_WinUI_XamlTypeInfo;

[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
[DebuggerNonUserCode]
internal class XamlMember : IXamlMember
{
	private XamlTypeInfoProvider _provider;

	private string _name;

	private bool _isAttachable;

	private bool _isDependencyProperty;

	private bool _isReadOnly;

	private string _typeName;

	private string _targetTypeName;

	public string Name => _name;

	public IXamlType Type => _provider.GetXamlTypeByName(_typeName);

	public IXamlType TargetType => _provider.GetXamlTypeByName(_targetTypeName);

	public bool IsAttachable => _isAttachable;

	public bool IsDependencyProperty => _isDependencyProperty;

	public bool IsReadOnly => _isReadOnly;

	public Getter Getter { get; set; }

	public Setter Setter { get; set; }

	public XamlMember(XamlTypeInfoProvider provider, string name, string typeName)
	{
		while (true)
		{
			int num = -281805222;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)((~(~num2 ^ (1960299083 * -(((-916456505 * --1875069287) ^ 0xC2BDB73) - ((0x447160DD ^ 0x6ACD9323) * 1191703341 - ~(~1610437248)) * -1967198251) - -796604917 * -1565820775) ^ (-(~(-(1665457313 * --842558606) - ((1195159842 - -779226181 + -1654297151) ^ (-284075415 ^ 0xC334C53)))) + 536685447 * ~((-(1673561258 + 605589710) - ~(-2000787670 ^ 0x30276589)) * 728365539)) ^ -568916615) * -1657713823 - ((-113148265 ^ -2020568659) - (-870170681 ^ -907481726) * 570670283) - ~(-1044462269 * 1082419663) - -172914237) * 995114115)) % 5;
				int num5 = 1989934059;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 -= 1989934059;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 719085860;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -1441959574 - (num7 + 1140527489 * -28439469);
					num7 = ~(num7 + (190407854 - -42865482));
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = -(-num9);
						num9 = -(-num9);
					}
					if (num3 != (uint)num9)
					{
						int num11 = 817364184;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 -= 817364182;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 536191383;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = -(num13 * -14970701);
								num13 -= 1151117360 + 1198689226;
							}
							if (num3 == (uint)num13)
							{
							}
							return;
						}
						_provider = provider;
						int[] array = new int[7];
						array[0] = 1450322994;
						array[1] = 1110281536;
						array[2] = -755984097;
						array[3] = -716689832;
						array[4] = -139750755;
						array[5] = 1807903664;
						array[6] = -2138700809;
						array[4] = array[5] ^ -1406184015;
						array[5] = array[2] ^ 0x2302E1FD;
						array[0] = array[6] ^ -445620246;
						int[] array2 = new int[7];
						array2[0] = -1417035323;
						array2[1] = 216826612;
						array2[2] = -2033739166;
						array2[3] = 1406924020;
						array2[4] = -531498715;
						array2[5] = 111267492;
						array2[6] = -272208488;
						array2[4] = array[2] ^ -832690260;
						array2[1] = array2[2] ^ 0xECFFB77;
						array2[0] = array2[5] ^ -728620446;
						int num15 = array2[4] ^ -1189025051;
						num = (int)((num4 * 284519562) ^ 0x5E998478) ^ num15;
					}
					else
					{
						_typeName = typeName;
						int[] array3 = new int[4];
						array3[0] = -1433625923;
						array3[1] = -1883691289;
						array3[2] = 503817032;
						array3[3] = -139649029;
						array3[3] = array3[2] ^ -481001266;
						array3[3] = array3[2] ^ 0x4DABC6F8;
						array3[3] = array3[2] ^ -526888927;
						int[] array4 = new int[7] { -1035824319, -591618585, 1871000381, 1590747249, -606043705, -1491704047, -1759836249 };
						int[][] array5 = new int[2][] { array3, array4 };
						array4[5] = array5[0][0] ^ 0x3EF01453;
						array4[1] = array4[0] ^ -251408066;
						array4[2] = array4[6] ^ -1482468332;
						int num16 = array5[1][5] ^ -525074700;
						num = ((int)num4 * -751909489) ^ -118471959 ^ num16;
					}
				}
				else
				{
					_name = name;
					int[,] array6 = new int[3, 3];
					array6[0, 0] = 834571591;
					array6[0, 1] = 447753394;
					array6[0, 2] = -439377946;
					array6[1, 0] = 1296516314;
					array6[1, 1] = 1875535496;
					array6[1, 2] = 346470202;
					array6[2, 0] = -1877347483;
					array6[2, 1] = -2044476063;
					array6[2, 2] = 1288432401;
					array6[1, 1] = array6[2, 0] ^ 0x1E3DE9B3;
					array6[0, 1] = array6[2, 0] ^ 0x2D365539;
					array6[0, 2] = array6[2, 1] ^ 0x6924E73C;
					int num17 = array6[0, 2] ^ 0x1AFC48BE;
					num = (int)((num4 * 128249852) ^ 0xB25688D0u) ^ num17;
				}
			}
		}
	}

	public void SetTargetTypeName(string targetTypeName)
	{
		_targetTypeName = targetTypeName;
	}

	public void SetIsAttachable()
	{
		_isAttachable = true;
	}

	public void SetIsDependencyProperty()
	{
		_isDependencyProperty = true;
	}

	public void SetIsReadOnly()
	{
		_isReadOnly = true;
	}

	public object GetValue(object instance)
	{
		if (Getter != null)
		{
			uint num2;
			int num4;
			do
			{
				int num = -1128260775;
				uint num3;
				num2 = (num3 = (uint)(((-((-((~(-1340875176 ^ -2079564011) - (-(1488731060 + 1198929338) - -(~-1710703704))) ^ -1376157571) - -((num * -727560523) ^ (-2077503925 * (46074714 * -1546762109) + (((-(-1837442965) - (-274379301 - -707105463 - -1837101484 * 829001741)) ^ (1377489923 * (-1450990488 ^ 0x58E3EEF5))) * 2145978289 + (-(~481792692 - (-444345503 - 381862723 - --1661278173)) - ((-(-1705810974) ^ -(-304861233)) - (-992610606 ^ -670466054 ^ 0x329C876F)))) * -15581965))) * 442717855) ^ 0x155B6764 ^ -(-849122345)) * -1206332213) ^ -669591649)) % 3;
				num4 = 0;
				_ = 0;
				for (int num5 = 0; num5 < 2; num5++)
				{
					num4 = ~(~num4);
					num4 = -(-num4);
				}
			}
			while (num2 == (uint)num4);
			int num6 = -2;
			_ = 0;
			for (int num7 = 0; num7 < 1; num7++)
			{
				num6 = ~num6;
			}
			if (num2 == (uint)num6)
			{
				return Getter(instance);
			}
			int num8 = -2;
			_ = 0;
			for (int num9 = 0; num9 < 1; num9++)
			{
				num8 = -num8;
			}
			if (num2 == (uint)num8)
			{
			}
		}
		throw new InvalidOperationException(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xFA0 ^ 0xE87]);
	}

	public void SetValue(object instance, object value)
	{
		if (Setter != null)
		{
			uint num3;
			while (true)
			{
				int num = 1900212400;
				while (true)
				{
					int num2 = num;
					uint num4;
					num3 = (num4 = (uint)(~((-(~(num2 * 942372495)) ^ (-1750693311 * ~(-(-(0x517DD8A3 ^ -2091768983)) + -1846376203 * ~(0x7413EA8D ^ -1970767450)))) * -1209925429 * -1969784195 * 1477706205))) % 4;
					int num5 = -190117868;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 ^ 0x4A8D33A2) - 1867207125;
						num5 = num5 * -715287643 * 1943309899;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1431306241;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 - -1255400666;
						num7 = -num7 ^ 0x2A865FFC;
					}
					if (num3 != (uint)num7)
					{
						goto end_IL_000e;
					}
					Setter(instance, value);
					int[,] array = new int[4, 3];
					array[0, 0] = 765165441;
					array[0, 1] = -143018315;
					array[0, 2] = -1585940714;
					array[1, 0] = -1493171444;
					array[1, 1] = 1781104242;
					array[1, 2] = 952717624;
					array[2, 0] = -648022615;
					array[2, 1] = 638748419;
					array[2, 2] = -482923565;
					array[3, 0] = -150916573;
					array[3, 1] = -9274735;
					array[3, 2] = -220285311;
					array[2, 2] = array[3, 2] ^ 0x6B91209E;
					array[1, 0] = array[0, 2] ^ 0x23C0192B;
					array[2, 1] = array[2, 0] ^ -1846275072;
					int num9 = array[2, 1] ^ -968886073;
					num = (int)((num4 * 679625679) ^ 0x49800571) ^ num9;
				}
				continue;
				end_IL_000e:
				break;
			}
			int num10 = 1;
			_ = 0;
			for (int num11 = 0; num11 < 2; num11++)
			{
				num10 = ~num10;
				num10 = num10 + --41534061 - 1041449150;
			}
			if (num3 == (uint)num10)
			{
				return;
			}
			int num12 = -728832194;
			_ = 0;
			for (int num13 = 0; num13 < 1; num13++)
			{
				num12 *= 1422714975;
			}
			if (num3 == (uint)num12)
			{
			}
		}
		throw new InvalidOperationException(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-611 + 314)]);
	}
}
