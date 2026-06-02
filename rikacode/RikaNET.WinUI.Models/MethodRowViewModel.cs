using System;
using CommunityToolkit.Mvvm.ComponentModel;

namespace RikaNET.WinUI.Models;

public sealed class MethodRowViewModel : ObservableObject
{
	private readonly Action<int, bool> _selectionChanged;

	private bool _isSelected;

	public int Token { get; }

	public string Name { get; }

	public string Signature { get; }

	public bool IsPreselected { get; }

	public bool IsSelected
	{
		get
		{
			return _isSelected;
		}
		set
		{
			if (!SetProperty(ref _isSelected, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x445D ^ 0x44C7))]))
			{
				return;
			}
			while (true)
			{
				int num = -1857443832;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-((~num2 ^ ((-693692661 * (-1914385579 + -(-1366511183 * (~(-1655736772) - 351511610)))) ^ (-(0xD12E646 ^ ~(-(-(45142861 - -1238586603)))) + (35464301 - ((-(~(--1743294570)) ^ 0x78EDD446) - (-1331335157 + -1726083164)))))) - -(62396459 - ((0x127834D5 ^ -1291553354) - (0x1B8E93ED ^ -1660193675) - 649476049) + -1930888557 - (-(~(-(--962539838))) + -720770241))) * 1171005607 * -550568841 + -(0x2469994 ^ --1195383891) - -1173298835 * (-1048565036 + 2144397137)) - 470449770)) % 3;
					int num5 = 47750546;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 -= ~-992043479;
						num5 = (num5 ^ 0x63C32D56) * -153234055;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 += 2143811110 - 707386905;
						num7 = -1739965011 - (num7 - (997161098 - 2140926428));
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2018800093;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -2018800093;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					_selectionChanged(Token, value);
					int[,] array = new int[4, 3];
					array[0, 0] = 1895602959;
					array[0, 1] = -1018822904;
					array[0, 2] = -236128935;
					array[1, 0] = 1578324090;
					array[1, 1] = 1078507726;
					array[1, 2] = 1883301874;
					array[2, 0] = -1669520007;
					array[2, 1] = -712915334;
					array[2, 2] = 1109859775;
					array[3, 0] = 1292253212;
					array[3, 1] = 216475759;
					array[3, 2] = -1602083141;
					array[2, 0] = array[1, 2] ^ -1097976109;
					array[1, 0] = array[2, 0] ^ -500501083;
					array[1, 2] = array[0, 2] ^ -1390892800;
					int num11 = array[1, 2] ^ 0x24306C8E;
					num = (int)((num4 * 1180298147) ^ 0x1B0B62C4) ^ num11;
				}
			}
		}
	}

	public MethodRowViewModel(int token, string name, string signature, bool isSelected, bool isPreselected, Action<int, bool> selectionChanged)
	{
		Token = token;
		Name = name;
		Signature = signature;
		_isSelected = isSelected;
		IsPreselected = isPreselected;
		_selectionChanged = selectionChanged;
	}
}
