using System;
using System.CodeDom.Compiler;
using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Markup;
using Pbt_003D;
using RikaNET.WinUI.ViewModels;
using WinRT;

namespace RikaNET.WinUI.Views;

public sealed class MethodsView : UserControl, IComponentConnector
{
	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private UserControl Root;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private bool _contentLoaded;

	public MethodsViewModel ViewModel { get; }

	public MethodsView()
	{
		while (true)
		{
			int num = -911288429;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(~(~(-(~(~num2)) - (-783933646 - 1445054517 - -(~249824977))) - (-(0x69478E5D ^ 0xE9CE0B8) + (-1817890121 + (-13111725 + -1746105254)) * 1801851949)) ^ -1307901321) ^ -1159589920)) % 4;
				int num5 = 1635558416;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = -(~num5);
					num5 = num5 * -598541851 - 2112975810;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -1804640511;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = (num7 - (757004514 + -1758039783)) * 701526269;
					num7 = (num7 ^ 0x68F2ADCE) - 1782602719;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1623555776;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 -= 1623555773;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 0;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 *= 1344942563;
						}
						if (num3 != (uint)num11)
						{
						}
						_002F_005E_0023_0028_0026_0021_0023_0024((FrameworkElement)this, (object)ViewModel);
						return;
					}
					InitializeComponent();
					int[] array = new int[6];
					array[0] = 1496172522;
					array[1] = -1648181198;
					array[2] = -1213301931;
					array[3] = 1580742349;
					array[4] = -604615249;
					array[5] = -1156251721;
					array[4] = array[0] ^ 0x19EE7056;
					array[0] ^= 990072059;
					array[2] = array[5] ^ -1628316489;
					int[] array2 = new int[4];
					array2[0] = 1470792652;
					array2[1] = -1874820158;
					array2[2] = 634159411;
					array2[3] = -1514812507;
					array2[3] = array[3] ^ -1111192670;
					array2[0] = array2[2] ^ -1970611964;
					array2[1] = array2[2] ^ 0x23DBF262;
					array2[2] = array2[3] ^ -90749715;
					int num13 = array2[3] ^ 0x7305450F;
					num = ((int)num4 * -1067760626) ^ -837598630 ^ num13;
				}
				else
				{
					ViewModel = AVZ_003D.TbG_003D.GetRequiredService<MethodsViewModel>();
					int[,] array3 = new int[3, 4];
					array3[0, 0] = -462938084;
					array3[0, 1] = -121059709;
					array3[0, 2] = -1160528575;
					array3[0, 3] = -1325641992;
					array3[1, 0] = -1375582129;
					array3[1, 1] = -1131723807;
					array3[1, 2] = 6211662;
					array3[1, 3] = 1592638783;
					array3[2, 0] = 336442552;
					array3[2, 1] = -2096389971;
					array3[2, 2] = -807877946;
					array3[2, 3] = -820090152;
					array3[2, 3] = array3[0, 1] ^ 0x4ED2B20;
					array3[2, 2] = array3[1, 2] ^ -2121448852;
					array3[0, 2] = array3[1, 2] ^ 0x411C28EB;
					array3[1, 0] = array3[0, 1] ^ 0x49CD6DD0;
					int num14 = array3[1, 0] ^ 0x1CA2FC12;
					num = ((int)num4 * -2004451362) ^ 0x4365C9AE ^ num14;
				}
			}
		}
	}

	private void UserControl_Loaded(object sender, RoutedEventArgs e)
	{
		ViewModel.Refresh();
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public void InitializeComponent()
	{
		if (_contentLoaded)
		{
			goto IL_000e;
		}
		goto IL_0b07;
		IL_000e:
		int num = -580667141;
		goto IL_0013;
		IL_0013:
		Uri uri = default(Uri);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)(-(~(((-(-(-1412494033 * -1852080793) - (-(-1397146454 ^ ~(-(-(-511797841 + ~1383663749)))) + (-(-525973245 - -795606474) + ~(757377243 - -1278524929) + 1068343619 + (-712563171 * (-1143180191 ^ 0x1D060A0A) + ~(~(1047139344 - 545699289))) + 1438632697 - (0x1C416213 ^ -782895961) * -943293491) - ((-1369947927 * -(~(-253109124 - -(~-1218440580 - (-458022526 + 181289492))))) ^ (((-((-1119770186 ^ -1690323292) + -281300187) ^ -(-(-1704132864 + 1928309407)) ^ -1789404662) * 21426313) ^ (-1133005553 * (((593625597 + 305728999 - (-474203532 ^ 0x35A4BD45) - -(--2073894153)) ^ 0xE89FF4C) * -492869079)))) - num2)) - -1886601413) ^ (504749463 * -(-2081558454 ^ (1111979732 - 383414709 + --1758192774))) ^ (~(~(-1698993511)) - (-427053459 ^ -795755144))) - ((-632181569 * -584185651) ^ -1266995509)) * 1187691543))) % 6;
			int num5 = 1962362496;
			_ = 0;
			for (int num6 = 0; num6 < 2; num6++)
			{
				num5 = (num5 - ~2135081812) * 1802719805;
				num5 = ~(-num5);
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = 1;
			_ = 0;
			for (int num8 = 0; num8 < 2; num8++)
			{
				num7 = -num7 - 1625991187;
				num7 = -(~num7);
			}
			if (num3 == (uint)num7)
			{
				return;
			}
			int num9 = -2;
			_ = 0;
			for (int num10 = 0; num10 < 1; num10++)
			{
				num9 = -num9;
			}
			if (num3 != (uint)num9)
			{
				int num11 = 945298571;
				_ = 0;
				for (int num12 = 0; num12 < 2; num12++)
				{
					num11 -= 930871549 * -1459933848;
					num11 = (-1412297193 * 874596491 - num11) ^ 0x3C2FAF45;
				}
				if (num3 != (uint)num11)
				{
					int num13 = 20455429;
					_ = 0;
					for (int num14 = 0; num14 < 2; num14++)
					{
						num13 = num13 + -1447297321 + 1157581978;
						num13 = (num13 ^ -178617730) + 1894950107;
					}
					if (num3 != (uint)num13)
					{
						int num15 = -206652284;
						_ = 0;
						for (int num16 = 0; num16 < 1; num16++)
						{
							num15 *= -870542111;
						}
						if (num3 == (uint)num15)
						{
						}
						return;
					}
					_005E_0025_005E_002B_005E_0024_0023_0040((object)this, uri, ComponentResourceLocation.Application);
					int[,] array = new int[4, 4];
					array[0, 0] = -1237753119;
					array[0, 1] = 840036350;
					array[0, 2] = -16260359;
					array[0, 3] = 869809816;
					array[1, 0] = -651858129;
					array[1, 1] = -2121866374;
					array[1, 2] = 761421041;
					array[1, 3] = 992528998;
					array[2, 0] = 1258545725;
					array[2, 1] = 1908612923;
					array[2, 2] = 169868517;
					array[2, 3] = 1646736656;
					array[3, 0] = 1477886984;
					array[3, 1] = 304474571;
					array[3, 2] = 1759865057;
					array[3, 3] = 472396143;
					array[2, 0] = array[3, 3] ^ -601197930;
					array[2, 1] ^= 1618552768;
					array[2, 0] = array[1, 0] ^ 0x1F333C7C;
					array[2, 2] = array[1, 0] ^ -1002981145;
					int num17 = array[2, 2] ^ 0x82255C2;
					num = (int)((num4 * 197955791) ^ 0xCF22342Du) ^ num17;
				}
				else
				{
					uri = new Uri(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xB483 ^ 0xB5AF]);
					int[,] array2 = new int[4, 4];
					array2[0, 0] = -637721083;
					array2[0, 1] = 1397762969;
					array2[0, 2] = 2028170843;
					array2[0, 3] = -809483424;
					array2[1, 0] = -2066957673;
					array2[1, 1] = 1101330721;
					array2[1, 2] = 828727063;
					array2[1, 3] = 1239685920;
					array2[2, 0] = 165157721;
					array2[2, 1] = 1965238147;
					array2[2, 2] = 2126585711;
					array2[2, 3] = -857634953;
					array2[3, 0] = -1418589722;
					array2[3, 1] = -2135065723;
					array2[3, 2] = 1584794564;
					array2[3, 3] = 725000591;
					array2[2, 1] = array2[2, 3] ^ 0x288C3C11;
					array2[0, 2] = array2[1, 1] ^ -2027569358;
					array2[1, 3] = array2[2, 0] ^ 0x726B6C34;
					int num18 = array2[1, 3] ^ -519714596;
					num = ((int)num4 * -88185043) ^ -768746823 ^ num18;
				}
				continue;
			}
			goto IL_0b07;
		}
		goto IL_000e;
		IL_0b07:
		_contentLoaded = true;
		num = 873089951;
		goto IL_0013;
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public void Connect(int connectionId, object target)
	{
		if (connectionId == 1)
		{
			goto IL_000e;
		}
		goto IL_06ca;
		IL_000e:
		int num = -718399125;
		goto IL_0013;
		IL_0013:
		uint num3;
		while (true)
		{
			int num2 = num;
			uint num4;
			num3 = (num4 = (uint)(-(~(num2 - -(0x23F69D89 ^ (318777887 * (-1502031817 * ~(~(~(-1138847319 - -1213473265 * -1966758123)))))) - ~(1668364133 * (~(1700283017 * (67851143 - 2010547158) - ~(-789573961 * -1870171804) - ~((-1317772575 - -1648659227) * 64333671)) + (-(~(~-447485135 + (381009765 + -1146981622))) - ((0x22C3BEF5 ^ 0x1BC69BF1) + (--544352466 - (0x19E95AF7 ^ 0x1A0494E)) + ~((-1943699469 + -1873213521) * 1566119399))))))))) % 5;
			int num5 = 4;
			_ = 0;
			for (int num6 = 0; num6 < 2; num6++)
			{
				num5 = ~(num5 - -644840405);
				num5 = ~(-num5);
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = -1984062801;
			_ = 0;
			for (int num8 = 0; num8 < 1; num8++)
			{
				num7 ^= -1984062803;
			}
			if (num3 != (uint)num7)
			{
				int num9 = -135393349;
				_ = 0;
				for (int num10 = 0; num10 < 2; num10++)
				{
					num9 *= 256136435;
					num9 = -1068706740 - -1928903311 - num9 - 29385955;
				}
				if (num3 == (uint)num9)
				{
					_0029_002D_003F_003F_0023_0024_0025_003D((FrameworkElement)Root, (RoutedEventHandler)UserControl_Loaded);
					int[] array = new int[4];
					array[0] = 1139624433;
					array[1] = 845783437;
					array[2] = -1972973983;
					array[3] = 1962454298;
					array[3] = array[1] ^ 0x1F09CBF7;
					array[2] = array[1] ^ 0x5D932457;
					array[3] = array[1] ^ 0x4F1FFD6F;
					int[] array2 = new int[5] { 1425831817, 796327247, -839524615, 322347599, -2100532469 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][1] ^ 0x3AD128E8;
					array2[0] = array2[4] ^ -1441881744;
					array2[0] = array2[3] ^ 0x50CB1BA7;
					int num11 = array3[1][4] ^ 0x1B7943B7;
					num = (int)((num4 * 494831236) ^ 0xCEBC6AA4u) ^ num11;
					continue;
				}
				goto IL_024d;
			}
			Root = target.As<UserControl>();
			int[] array4 = new int[5];
			array4[0] = -729532654;
			array4[1] = -952518262;
			array4[2] = 380000691;
			array4[3] = 2046414839;
			array4[4] = -1203605945;
			array4[0] = array4[2] ^ -491568483;
			array4[3] = array4[2] ^ 0x40B9DADA;
			array4[4] = array4[1] ^ 0x4EBADE87;
			int[] array5 = new int[6] { -444243003, -1940240186, -345560213, 1173513070, 1612581900, 1806479561 };
			int[][] array6 = new int[2][] { array4, array5 };
			array5[1] = array6[0][1] ^ -517028175;
			array5[2] ^= 33201996;
			array5[5] = array5[2] ^ 0x1AEB4958;
			array5[3] ^= -839971936;
			int num12 = array6[1][1] ^ -632688920;
			num = (int)((num4 * 920200448) ^ 0xB42F4500u) ^ num12;
		}
		goto IL_000e;
		IL_06ca:
		_contentLoaded = true;
		num = 422204083;
		goto IL_0013;
		IL_024d:
		int num13 = 1472594879;
		_ = 0;
		for (int num14 = 0; num14 < 2; num14++)
		{
			num13 = ~num13 - 1411186208;
			num13 = -num13;
		}
		if (num3 != (uint)num13)
		{
			int num15 = -862249930;
			_ = 0;
			for (int num16 = 0; num16 < 2; num16++)
			{
				num15 = ~(num15 ^ 0x25D5DA5C);
				num15 = (num15 * -790165845) ^ 0x76AE0492;
			}
			if (num3 == (uint)num15)
			{
			}
			return;
		}
		goto IL_06ca;
	}

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	[DebuggerNonUserCode]
	public IComponentConnector GetBindingConnector(int connectionId, object target)
	{
		return null;
	}

	static void _002F_005E_0023_0028_0026_0021_0023_0024(FrameworkElement P_0, object P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1843798700;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(num2 ^ -((~(-284452707 * -(-(~(-749917206 ^ -2031395492)))) - (-648169139 ^ ~(-(-386795438 ^ -1096228790) - -(1277469047 * -1334680215 + (-683473733 ^ -520054550))))) ^ ~(~(578854786 - -1545718081 * -1546213785 * -1018782807 + (-527072156 ^ 0x3A2FC2C0)) + -(~(-(~1662558945)))))) + ((-(-1449908942 ^ (-1291219194 ^ (0x698084E7 ^ -1059032188))) - 1899065291 * ((-556144653 ^ -(-198984934 - 1679020668)) - (0x24BD2BB0 ^ -755323054) * 738738765)) ^ -1251492256)) * 1209873841 * 327214007)) % 3;
					int num5 = 1617107172;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 - (0x757E2924 ^ -702834027) - 1254856884;
						num5 = ~num5 ^ 0x39F9AE72;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1877180156;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 ^ -1721579155) - -1322885645;
						num7 = (num7 - -2065209938) ^ -1421687543;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2048904957;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= 1489289643;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.DataContext = P_1;
					int[] array = new int[5] { 1063007215, 1331451550, -1527649123, 1334254395, 1693925940 };
					array[1] ^= 1374888703;
					array[3] = array[2] ^ -1253182299;
					int[] array2 = new int[4] { -1935668906, 628746971, -356027237, -808735645 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][4] ^ 0x17853DD;
					array2[2] = array2[0] ^ 0x25E15038;
					array2[0] ^= 1108420733;
					array2[0] = array2[1] ^ 0x21D06B75;
					int num11 = array3[1][1] ^ 0x65FD6CE6;
					num = (int)((num4 * 1108242751) ^ 0xFF6C896Au) ^ num11;
				}
			}
		}
	}

	static void _005E_0025_005E_002B_005E_0024_0023_0040(object P_0, Uri P_1, ComponentResourceLocation P_2)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			Application.LoadComponent(P_0, P_1, P_2);
		}
	}

	static void _0029_002D_003F_003F_0023_0024_0025_003D(FrameworkElement P_0, RoutedEventHandler P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1747285740;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~num2 * -645361681 - ~(162269105 * 134131470 + -1737123635)) * -1658481525 - ~(~(-483395784 - -2058282026 - ~1092110206)))) % 3;
					int num5 = 201551424;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 - (640593110 + 353746791));
						num5 *= 279243889;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2133852172;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 ^ --1525153883) - 1367356876;
						num7 = -930567325 - (num7 - --1247400655);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1429149611;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 * 1016706281 * -306267661;
							num9 = -num9 ^ 0x48514FA3;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Loaded += P_1;
					int[] array = new int[5];
					array[0] = 2075981149;
					array[1] = 1944893982;
					array[2] = 1248984669;
					array[3] = -224938895;
					array[4] = -17331724;
					array[1] = array[2] ^ -1138098921;
					array[3] ^= -1977374539;
					array[4] = array[2] ^ 0x975C556;
					int[] array2 = new int[5] { 1268514603, -1350351343, 1461268671, -1306332425, 150293710 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][2] ^ 0x424137CC;
					array2[1] = array2[0] ^ 0x13D540A5;
					array2[1] ^= 447207967;
					array2[0] ^= 486551907;
					int num11 = array3[1][3] ^ 0x7DB1B59E;
					num = (int)((num4 * 1962037708) ^ 0x8EA1D0ACu) ^ num11;
				}
			}
		}
	}
}
