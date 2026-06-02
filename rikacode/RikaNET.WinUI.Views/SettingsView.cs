using System;
using System.CodeDom.Compiler;
using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media.Animation;
using Pbt_003D;
using RikaNET.WinUI.ViewModels;
using WinRT;

namespace RikaNET.WinUI.Views;

public sealed class SettingsView : UserControl, IComponentConnector
{
	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private UserControl Root;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private TextBlock LicenseTextBlockVisible;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private Border LicenseBlurOverlay;

	[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
	private bool _contentLoaded;

	public SettingsViewModel ViewModel { get; }

	public SettingsView()
	{
		while (true)
		{
			int num = -1518322634;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~((((~num2 - (~(~(0x69C81181 ^ 0x37302887) - ((-2014169566 ^ 0x5C59D732) - 1244872131 * -467786135) * -1716478393 - -1482881727 * -(-(772058423 * 896392479))) ^ (-1312950053 * (-1554736387 - ((0x68BB780 ^ -(-278470680)) + ((0x671F0FB2 ^ -1627579203) - ~(~-1051115133))))) ^ -1002239925) - (~(-(-(-(-1919460480 + -2063317358)) - -(-(1189894207 * -640329139)))) - ((((322283271 * (1663339959 * --1046710223)) ^ (-(-1859643312 + -226087678) ^ -1260270762)) - 1456057116) ^ (-1044908662 * 1679906535 - ((-(1421516260 + 404596344) * -280390573) ^ -1857397505))))) ^ -1559692419 ^ ~(-(-(-370990059 ^ 0x2F333E14) ^ -1253608411))) - -(~-190670287)) * 683130205 * 657431207 - -270689587))) % 5;
				int num5 = -4;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 = -num5;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 2073730431;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 = 2073730433 - num7;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -818963753;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 *= 1944975591;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 84836989;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 -= 84836986;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 0;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = -(num13 - (1477835889 + -166154275));
								num13 = 845389830 - -num13;
							}
							if (num3 == (uint)num13)
							{
							}
							return;
						}
						@_003D_0024_002A_0023_0024_003D_003E((FrameworkElement)this, (object)ViewModel);
						int[] array = new int[6];
						array[0] = 700901382;
						array[1] = -488784245;
						array[2] = -1316144592;
						array[3] = -2035878048;
						array[4] = 958691865;
						array[5] = 2062959219;
						array[1] = array[4] ^ -1388045379;
						array[5] ^= -2076935673;
						int[] array2 = new int[5];
						array2[0] = 1461978612;
						array2[1] = 1296304673;
						array2[2] = -1037119179;
						array2[3] = -194649271;
						array2[4] = 1427068081;
						array2[2] = array[4] ^ -1784770843;
						array2[1] = array2[0] ^ -800885435;
						array2[3] = array2[1] ^ 0x500A82C;
						array2[0] = array2[2] ^ -401753420;
						int num15 = array2[2] ^ 0x18AD0558;
						num = ((int)num4 * -1878481094) ^ -1172274234 ^ num15;
					}
					else
					{
						InitializeComponent();
						int[] array3 = new int[4];
						array3[0] = -1292050501;
						array3[1] = -1930394208;
						array3[2] = 1054827326;
						array3[3] = -1917261351;
						array3[3] = array3[1] ^ -1140329487;
						array3[3] = array3[2] ^ 0x7FE6E226;
						int[] array4 = new int[5];
						array4[0] = -1900896746;
						array4[1] = 501626456;
						array4[2] = -1615330226;
						array4[3] = 1777282755;
						array4[4] = 2116936026;
						array4[3] = array3[0] ^ -1803144237;
						array4[4] = array4[3] ^ -918032172;
						array4[4] = array4[2] ^ 0x22A629ED;
						array4[0] = array4[4] ^ 0x5CAE603E;
						int num16 = array4[3] ^ -492677686;
						num = ((int)num4 * -915697117) ^ 0x34D694C0 ^ num16;
					}
				}
				else
				{
					ViewModel = AVZ_003D.TbG_003D.GetRequiredService<SettingsViewModel>();
					int[] array5 = new int[5];
					array5[0] = 1615785229;
					array5[1] = 1296019913;
					array5[2] = 661984806;
					array5[3] = -1172359507;
					array5[4] = 98077959;
					array5[4] = array5[3] ^ -738728801;
					array5[2] = array5[1] ^ 0x724699F3;
					array5[3] = array5[1] ^ 0x280A5152;
					int[] array6 = new int[7] { -1426124004, -1518307698, 1390362798, 87333370, 1528126822, -114477413, 421386940 };
					int[][] array7 = new int[2][] { array5, array6 };
					array6[4] = array7[0][1] ^ -366897802;
					array6[6] ^= -1275753751;
					array6[1] ^= -47179564;
					int num17 = array7[1][4] ^ -99757742;
					num = ((int)num4 * -1387159635) ^ 0x7F7FEB07 ^ num17;
				}
			}
		}
	}

	private void LicenseBorder_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		DoubleAnimation doubleAnimation = new DoubleAnimation();
		_002F_0025_003D_0026_003F_003C_003E_0023(doubleAnimation, (double?)0.0);
		_0025__0024_002A_0024_0025_0024_005E((Timeline)doubleAnimation, _005E_0021_0021_0029_0040_0021_002A_003C(new TimeSpan(0, 0, 0, 0, 300)));
		CubicEase cubicEase = new CubicEase();
		_003D_0029_002A_003D_003F_003E_003F_0023((EasingFunctionBase)cubicEase, EasingMode.EaseOut);
		_002B__003C_0021__003F_005E_003C(doubleAnimation, (EasingFunctionBase)cubicEase);
		DoubleAnimation doubleAnimation2 = doubleAnimation;
		while (true)
		{
			int num = -1085007227;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(((num2 ^ ((-99120501 * (-(-1616066323) * -593704561)) ^ (~(-(-(~(-(~520808926))) ^ ((0x414D3CB0 ^ 0x697E7EC6) + 47777811 * -(-491245165 * 697376845)))) + (1490899729 + -(-((-(-656390873 ^ 0xE5225CB) ^ -1029486896) + (0x6EEA0F06 ^ -2091219929))))))) * -1490241265) ^ (-672982889 * -1482700548 + (-1312809831 ^ (1685084251 * -(1384264888 + ~-896595147)) ^ (--373634349 - (0x4EBD3AB7 ^ 0x582FBAD3)))) ^ (((-665311155 + -448634278 - -2137012143) ^ (-605240030 - 745859212)) + 2030388902 + (1446900580 + -1499293697 - (-1348976879 - (-670923333 + -1166964273)) + (-73204757 ^ -1450591865)) - (-690432632 + (-1736550398 + -1950344839 * (-2000436571 + 569316786)))))) % 3;
				int num5 = -703571646;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = -(-num5);
					num5 = -(num5 * 1185842993);
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 888617049;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = ~(num7 * -1225500481);
					num7 += 798170107 * -2071629521;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -1203863151;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 -= -1203863151;
					}
					if (num3 == (uint)num9)
					{
					}
					return;
				}
				Storyboard storyboard = new Storyboard();
				_003F_003C_002F_0040_005E_003E_002B_0021((Timeline)doubleAnimation2, (DependencyObject)LicenseBlurOverlay);
				_005E_0029_0023_002B_0021_005E_003E_003D((Timeline)doubleAnimation2, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xBC8 ^ 0xAE5]);
				_0024_005E_002F_002B_0026_0026_0025_0028(@_003C_003D_0026_002A_0023_005E_0024(storyboard), (Timeline)doubleAnimation2);
				_005E_0028__005E_0026_0040_0024_002F(storyboard);
				int[,] array = new int[3, 3];
				array[0, 0] = 2077093171;
				array[0, 1] = -2024656874;
				array[0, 2] = -183502829;
				array[1, 0] = 446327956;
				array[1, 1] = 1965466155;
				array[1, 2] = 35553833;
				array[2, 0] = -1346240396;
				array[2, 1] = -1563478124;
				array[2, 2] = -842574809;
				array[1, 2] = array[0, 1] ^ 0x4DC062FC;
				array[1, 1] = array[1, 0] ^ 0xD76E4CF;
				array[2, 2] = array[2, 0] ^ 0x1CEB8C5F;
				array[0, 1] = array[1, 0] ^ 0x1A20B005;
				int num11 = array[0, 1] ^ -75791864;
				num = (int)((num4 * 1308453258) ^ 0x2FA1F496) ^ num11;
			}
		}
	}

	private void LicenseBorder_PointerExited(object sender, PointerRoutedEventArgs e)
	{
		DoubleAnimation doubleAnimation = new DoubleAnimation();
		_002F_0025_003D_0026_003F_003C_003E_0023(doubleAnimation, (double?)1.0);
		_0025__0024_002A_0024_0025_0024_005E((Timeline)doubleAnimation, _005E_0021_0021_0029_0040_0021_002A_003C(new TimeSpan(0, 0, 0, 0, 300)));
		CubicEase cubicEase = new CubicEase();
		_003D_0029_002A_003D_003F_003E_003F_0023((EasingFunctionBase)cubicEase, EasingMode.EaseOut);
		_002B__003C_0021__003F_005E_003C(doubleAnimation, (EasingFunctionBase)cubicEase);
		DoubleAnimation doubleAnimation2 = doubleAnimation;
		while (true)
		{
			int num = -1476019205;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(((~((~(-(-(-1737627764))) ^ -646081278) - -(-(-463225838 ^ -1963231300) + (-(118764877 - 2146751088) - 1481089103 * (1855196628 + 1973593222))) - ((~num2 + -460431549 * (~(-625726617) * -26030849)) ^ (((~(-388141439 * 911976077) - -(1423838463 + 1743871298) - ~(~2283117) * 2051657603 - 1306462869 * -(-962210751 * -759857743)) * 1631422143) ^ (-1407468523 * (1975901279 * -(~(1322473061 + -476897714) + ~-1256692246 * -689398623)))))) - -2058364481 * -1774423813) ^ 0x3756961F) * -1801875353 * -669530137 * 838055549)) % 3;
				int num5 = 2060607894;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = 824196506 - -num5;
					num5 = ~num5 * -1340526965;
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
					int num9 = 753960615;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = -num9 - -1935838026;
						num9 = -1537503188 - num9 - 1198606389;
					}
					if (num3 == (uint)num9)
					{
					}
					return;
				}
				Storyboard storyboard = new Storyboard();
				_003F_003C_002F_0040_005E_003E_002B_0021((Timeline)doubleAnimation2, (DependencyObject)LicenseBlurOverlay);
				_005E_0029_0023_002B_0021_005E_003E_003D((Timeline)doubleAnimation2, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[362 - 10 - 44 - 7]);
				_0024_005E_002F_002B_0026_0026_0025_0028(@_003C_003D_0026_002A_0023_005E_0024(storyboard), (Timeline)doubleAnimation2);
				_005E_0028__005E_0026_0040_0024_002F(storyboard);
				int[] array = new int[4] { -1182649311, -1031161557, -929809419, -1220092873 };
				array[2] ^= 528244376;
				array[0] = array[1] ^ 0xB910E8D;
				array[3] = array[1] ^ -1352014450;
				int[] array2 = new int[6] { -913543648, -1213114343, -1287548120, 1684874488, -326798379, 1925208766 };
				int[][] array3 = new int[2][] { array, array2 };
				array2[5] = array3[0][1] ^ 0x5B2199FD;
				array2[4] = array2[5] ^ -2081444894;
				array2[4] = array2[2] ^ -676165935;
				int num11 = array3[1][5] ^ -711739215;
				num = (int)((num4 * 1686268642) ^ 0xBFE63BC6u) ^ num11;
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
		goto IL_042e;
		IL_000e:
		int num = -1150516507;
		goto IL_0013;
		IL_0013:
		Uri uri = default(Uri);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)(~(-(-(-(~(-num2 * -1453604827)) * 1820029563) - (-(1808745875 - 1921941949) - -1602347924))) * -148697591)) % 6;
			int num5 = -4;
			_ = 0;
			for (int num6 = 0; num6 < 1; num6++)
			{
				num5 = -num5;
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = -6;
			_ = 0;
			for (int num8 = 0; num8 < 1; num8++)
			{
				num7 = ~num7;
			}
			if (num3 == (uint)num7)
			{
				return;
			}
			int num9 = 1;
			_ = 0;
			for (int num10 = 0; num10 < 2; num10++)
			{
				num9 = ~num9 ^ -940636992;
				num9 = ~(-num9);
			}
			if (num3 != (uint)num9)
			{
				int num11 = -1;
				_ = 0;
				for (int num12 = 0; num12 < 1; num12++)
				{
					num11 = ~num11;
				}
				if (num3 != (uint)num11)
				{
					int num13 = -126274857;
					_ = 0;
					for (int num14 = 0; num14 < 1; num14++)
					{
						num13 = -126274854 - num13;
					}
					if (num3 != (uint)num13)
					{
						int num15 = -1656556758;
						_ = 0;
						for (int num16 = 0; num16 < 2; num16++)
						{
							num15 = -(num15 - (-468615787 - -1740472697));
							num15 = (num15 * 1052228747) ^ -938702318;
						}
						if (num3 == (uint)num15)
						{
						}
						return;
					}
					_002F_002A_002A_002A_002D_005E_0040_005E((object)this, uri, ComponentResourceLocation.Application);
					int[] array = new int[5];
					array[0] = 1146228894;
					array[1] = -20210631;
					array[2] = 1418596586;
					array[3] = -532893903;
					array[4] = -1270693633;
					array[2] = array[0] ^ -836986506;
					array[3] = array[0] ^ -1147197279;
					int[] array2 = new int[6] { -1697585322, -412197737, -1108853397, -1020282240, -1692965015, -2021734038 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][1] ^ -1151559881;
					array2[0] = array2[2] ^ -1315466538;
					array2[4] = array2[0] ^ -1296366482;
					int num17 = array3[1][2] ^ -551217506;
					num = (int)((num4 * 2099743920) ^ 0x3A080690) ^ num17;
				}
				else
				{
					uri = new Uri(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x84C ^ 0x962]);
					int[,] array4 = new int[4, 4];
					array4[0, 0] = -1681688581;
					array4[0, 1] = -2006318939;
					array4[0, 2] = 695544083;
					array4[0, 3] = -767825254;
					array4[1, 0] = -1599296035;
					array4[1, 1] = 1321092168;
					array4[1, 2] = -685333646;
					array4[1, 3] = -908785108;
					array4[2, 0] = 1676110744;
					array4[2, 1] = 1723436316;
					array4[2, 2] = 2028269173;
					array4[2, 3] = 1454606312;
					array4[3, 0] = -178867307;
					array4[3, 1] = 1981481043;
					array4[3, 2] = -1014217890;
					array4[3, 3] = 2107588117;
					array4[2, 0] = array4[0, 0] ^ -2111790724;
					array4[2, 0] = array4[2, 1] ^ 0x1EC76FB6;
					array4[1, 1] = array4[2, 1] ^ -1052722126;
					int num18 = array4[1, 1] ^ -27116555;
					num = ((int)num4 * -1135302832) ^ -1172143008 ^ num18;
				}
				continue;
			}
			goto IL_042e;
		}
		goto IL_000e;
		IL_042e:
		_contentLoaded = true;
		num = -231092856;
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
			num = 842080972;
			goto IL_0024;
		case 4:
			LicenseBlurOverlay = target.As<Border>();
			num = 590510183;
			goto IL_0024;
		case 2:
		{
			Border border = target.As<Border>();
			_003E_0040_0024_003E_0023_005E_002A_003C((UIElement)border, (PointerEventHandler)LicenseBorder_PointerEntered);
			_0028_003C_005E_0021_005E_0021_003D_0024((UIElement)border, (PointerEventHandler)LicenseBorder_PointerExited);
			num = 1695270135;
			goto IL_0024;
		}
		case 1:
			Root = target.As<UserControl>();
			num = 1452595852;
			goto IL_0024;
		case 3:
			{
				LicenseTextBlockVisible = target.As<TextBlock>();
				num = 226237820;
				goto IL_0024;
			}
			IL_0024:
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(~(-(~num2))))) % 11;
				int num5 = 842595120;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = -518355294 - (num5 - (62946615 + 267993095));
					num5 = ~num5 - -1538770508;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -680305498;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = (num7 * -1481714829) ^ 0x252B8D2F;
					num7 = ~num7 ^ 0x406C7661;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -337578576;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 += 337578577;
					}
					if (num3 == (uint)num9)
					{
						goto case 1;
					}
					int num11 = -865969669;
					_ = 0;
					for (int num12 = 0; num12 < 2; num12++)
					{
						num11 *= 2065081979;
						num11 = ~(num11 - -1603904179 * 1437796060);
					}
					if (num3 != (uint)num11)
					{
						int num13 = 67008050;
						_ = 0;
						for (int num14 = 0; num14 < 1; num14++)
						{
							num13 ^= 0x3FE763B;
						}
						if (num3 == (uint)num13)
						{
							goto case 2;
						}
						int num15 = 1169607234;
						_ = 0;
						for (int num16 = 0; num16 < 1; num16++)
						{
							num15 *= 1307826789;
						}
						if (num3 != (uint)num15)
						{
							int num17 = -4;
							_ = 0;
							for (int num18 = 0; num18 < 1; num18++)
							{
								num17 = -num17;
							}
							if (num3 != (uint)num17)
							{
								int num19 = -1299907503;
								_ = 0;
								for (int num20 = 0; num20 < 1; num20++)
								{
									num19 *= -1266640681;
								}
								if (num3 != (uint)num19)
								{
									int num21 = -3;
									_ = 0;
									for (int num22 = 0; num22 < 1; num22++)
									{
										num21 = ~num21;
									}
									if (num3 != (uint)num21)
									{
										int num23 = 108607840;
										_ = 0;
										for (int num24 = 0; num24 < 1; num24++)
										{
											num23 ^= 0x6793960;
										}
										if (num3 != (uint)num23)
										{
											int num25 = -1268941679;
											_ = 0;
											for (int num26 = 0; num26 < 2; num26++)
											{
												num25 = (num25 * -1537788231) ^ -2081360073;
												num25 = -num25 + 1860558452;
											}
											if (num3 == (uint)num25)
											{
											}
											return;
										}
										_contentLoaded = true;
										num = 1464683024;
										continue;
									}
									goto case 4;
								}
								int[,] array = new int[4, 4];
								array[0, 0] = -819427688;
								array[0, 1] = 1249515300;
								array[0, 2] = 58826249;
								array[0, 3] = -616610723;
								array[1, 0] = 465515458;
								array[1, 1] = -17399921;
								array[1, 2] = -1698257203;
								array[1, 3] = 1724722376;
								array[2, 0] = 1407402590;
								array[2, 1] = -780870575;
								array[2, 2] = -958896641;
								array[2, 3] = -2058097614;
								array[3, 0] = -2089922609;
								array[3, 1] = -1395351582;
								array[3, 2] = -333252332;
								array[3, 3] = -1796714346;
								array[1, 3] = array[1, 2] ^ 0x4AAFBAFE;
								array[3, 1] = array[2, 1] ^ 0x4B902001;
								array[2, 1] = array[1, 1] ^ -265169648;
								array[2, 2] = array[0, 0] ^ -1013439278;
								int num27 = array[2, 2] ^ 0x2F82DA2D;
								num = ((int)num4 * -1168922326) ^ -2024055934 ^ num27;
								continue;
							}
							goto case 3;
						}
						int[] array2 = new int[4] { 1768443562, -2140053362, -720473854, -234004340 };
						array2[2] ^= -557989847;
						array2[3] = array2[1] ^ 0x7245F9CC;
						array2[3] = array2[2] ^ -1877906527;
						int[] array3 = new int[6] { -657300743, 2096849351, -774904835, 1664156943, -1976065524, -2082988056 };
						int[][] array4 = new int[2][] { array2, array3 };
						array3[5] = array4[0][1] ^ 0x7D4547F7;
						array3[4] = array3[5] ^ -196318232;
						array3[3] = array3[5] ^ -2105461564;
						int num28 = array4[1][5] ^ -570007778;
						num = (int)((num4 * 2054346598) ^ 0xB8CC2D0) ^ num28;
						continue;
					}
					int[] array5 = new int[4];
					array5[0] = 1919577705;
					array5[1] = -469566288;
					array5[2] = -581124425;
					array5[3] = -1356926950;
					array5[3] = array5[2] ^ 0x3AE676A3;
					array5[1] = array5[3] ^ 0x5A69A764;
					int[] array6 = new int[7];
					array6[0] = -165586249;
					array6[1] = 435370485;
					array6[2] = -2028567475;
					array6[3] = 2080144957;
					array6[4] = 1725835757;
					array6[5] = -1249809031;
					array6[6] = -1689715423;
					array6[3] = array5[0] ^ -1533622381;
					array6[2] = array6[4] ^ -335950406;
					array6[2] = array6[6] ^ 0xF5255FC;
					int num29 = array6[3] ^ -170995299;
					num = (int)((num4 * 472593192) ^ 0x507B3D08) ^ num29;
					continue;
				}
				int[] array7 = new int[7];
				array7[0] = -2105023706;
				array7[1] = -994603353;
				array7[2] = -1074726681;
				array7[3] = 1400970054;
				array7[4] = 414426492;
				array7[5] = 2046756661;
				array7[6] = -583078423;
				array7[0] = array7[5] ^ 0x2F91A82E;
				array7[0] ^= 394948475;
				int[] array8 = new int[5];
				array8[0] = 1132113745;
				array8[1] = -764733787;
				array8[2] = 249547881;
				array8[3] = -1803470483;
				array8[4] = 479956538;
				array8[4] = array7[5] ^ -2058403348;
				array8[1] = array8[3] ^ -2112294681;
				array8[0] = array8[1] ^ -1166251241;
				int num30 = array8[4] ^ -545112386;
				num = ((int)num4 * -1655302727) ^ -1220872411 ^ num30;
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

	static void @_003D_0024_002A_0023_0024_003D_003E(FrameworkElement P_0, object P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1526772201;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(2121186059 * ~(1892399270 + -1915534801 - (-786307973 + -483651471))) - ~(-(~(-num2))) + 1555427465) * 1197165899 * -1306453277 * -374975351)) % 3;
					int num5 = 1080624146;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * 594702677 - 1858179589;
						num5 = num5 * 619777241 - -607363190;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1528641425;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7 + 1439637107;
						num7 = -1136675981 - num7 * 591766705;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 443040386;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9;
							num9 = (num9 + (1282572698 + 1886948613)) ^ -1380556468;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.DataContext = P_1;
					int[,] array = new int[4, 3];
					array[0, 0] = -1952330704;
					array[0, 1] = -1000806378;
					array[0, 2] = -49001007;
					array[1, 0] = 1152113875;
					array[1, 1] = 1375668170;
					array[1, 2] = -1930823420;
					array[2, 0] = 109720629;
					array[2, 1] = 653499081;
					array[2, 2] = -657092760;
					array[3, 0] = -1128176214;
					array[3, 1] = 859887684;
					array[3, 2] = 483086921;
					array[2, 1] = array[3, 0] ^ -1612614959;
					array[3, 2] = array[0, 1] ^ -1116057719;
					array[3, 2] = array[1, 0] ^ -513945008;
					int num11 = array[3, 2] ^ -1740409009;
					num = (int)((num4 * 1894263247) ^ 0xDBEDE4F2u) ^ num11;
				}
			}
		}
	}

	static void _002F_0025_003D_0026_003F_003C_003E_0023(DoubleAnimation P_0, double? P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 647315949;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(~(-num2)) ^ 0x62ADA705 ^ -580019174) - ~(-(-1999359707 * ~-1370263583)))) % 3;
					int num5 = 917481704;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -1949450101 - num5 - 1496302515;
						num5 = ~(num5 + ~-1757009820);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -2107564724;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 - ~1594686423) ^ -1793144281;
						num7 = -(num7 * 1486388973);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1862704351;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -701294424 - (num9 - -971102445);
							num9 = (num9 - -1055878323 * 2087632263) * 321435377;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.To = P_1;
					int[] array = new int[5];
					array[0] = 308141431;
					array[1] = 153949713;
					array[2] = 218601468;
					array[3] = -1571243120;
					array[4] = -2132241204;
					array[3] = array[2] ^ 0x2DCB9E73;
					array[2] = array[3] ^ -95925762;
					array[0] = array[1] ^ -300235516;
					int[] array2 = new int[7] { -753701189, -453428826, 1337691023, -1495642318, -624782185, 1623482413, 66267889 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][4] ^ 0x6CF75E16;
					array2[6] = array2[2] ^ 0x1AAB40A8;
					array2[6] = array2[5] ^ 0x5FC1515B;
					int num11 = array3[1][4] ^ -303724298;
					num = (int)((num4 * 1799753254) ^ 0xBD96092Au) ^ num11;
				}
			}
		}
	}

	static Duration _005E_0021_0021_0029_0040_0021_002A_003C(TimeSpan P_0)
	{
		Duration result = default(Duration);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 244859266;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((((~num2 * 1785936129 + -(~(1865998501 * ((-1725598853 ^ -1984197939) - (0x5DE589E ^ -1744882579)) * 1050751327)) + (~(-1932602709 * (2033937981 * -128980131)) + (1034994840 * 1613874445 - ~(0x42B83754 ^ -(-1964269645 ^ -818361685))))) ^ (~(1807913834 - (~-1393996055 + --930414657)) - ~(0x15296FE5 ^ -639406648))) - ((0x226B70EF ^ -1025482711) + (-1783522506 - -(~-1335317439)))) * -2095087011 * 2032992699) * -1097238895)) % 3;
					int num5 = -212776531;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= -212776531;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1721204559;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -1721204561;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1011140701;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= -1011140702;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0;
					int[] array = new int[4] { -631635360, -843534458, -419217647, 65969120 };
					array[2] ^= 111095181;
					array[2] ^= 1368608011;
					array[0] ^= -1065499800;
					int[] array2 = new int[5] { 1615160904, 266331207, -1339298160, -1072965163, -1727432567 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][3] ^ 0x3E6030EA;
					array2[2] = array2[0] ^ 0x314F5B3F;
					array2[2] = array2[1] ^ -669880621;
					array2[0] = array2[4] ^ 0x791D3CF2;
					int num11 = array3[1][3] ^ 0x2B1ECF18;
					num = ((int)num4 * -1487885416) ^ -2071413504 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _0025__0024_002A_0024_0025_0024_005E(Timeline P_0, Duration P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -868892124;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(~(~num2 * 1589606175) ^ -((-1895468564 ^ 0x4851B4E1) - ~((0x343265E2 ^ 0x54EDDA55) * -66168861) - ~(-595504103 * -282765145)) ^ ~((-986049080 ^ -1867999469) - (856671316 - -1812424842 - (0x61F716AD ^ 0x525168A8)) + ((-1500218795 ^ -198575412) - ~-1080111780 * 789850829))) - -436933945 * --2026913596 * -427775129) ^ 0x43259C04)) % 3;
					int num5 = 1499825336;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(~num5);
						num5 = num5 - -27793126 - -1369777854;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 393572800;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(num7 * -355160511);
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1073643385;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ 0x575A870C) - 1109921712;
							num9 = num9 - (-725196053 ^ -1146608692) - 7500904;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Duration = P_1;
					int[] array = new int[6];
					array[0] = 1537182179;
					array[1] = -539000754;
					array[2] = 1978760799;
					array[3] = -668215199;
					array[4] = -2071057063;
					array[5] = 1466733738;
					array[5] = array[4] ^ 0xA06516F;
					array[2] = array[1] ^ 0x5AD3B222;
					int[] array2 = new int[4];
					array2[0] = -632212861;
					array2[1] = -878300400;
					array2[2] = -1519587257;
					array2[3] = 1703676638;
					array2[3] = array[4] ^ 0x26AC1AB7;
					array2[0] = array2[2] ^ 0x784E0257;
					array2[0] = array2[1] ^ -978950239;
					int num11 = array2[3] ^ 0xA96E8A3;
					num = (int)((num4 * 1915797544) ^ 0xEC54F7F8u) ^ num11;
				}
			}
		}
	}

	static void _003D_0029_002A_003D_003F_003E_003F_0023(EasingFunctionBase P_0, EasingMode P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1334836515;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~1338188995 + ~-899468566 - (~(~(-(-(-514436233 * (-(-(1180310196 - 556757594)) - -(-(-803444597 - -1141260499)) - ((0x3A7BC6CF ^ -(1969921623 + 1847169531)) - (-(0x7938BC44 ^ 0x533C2F9C) + (2047196675 - -271716161 - 1293685422 * 1721643909))) + -(-(-(-(-1699335246)))))) - (num2 - ((~(-1469734743 + -316398085 * (-2039267543 - 1810711098 + (-445576742 ^ 0xD2E8EE0)) - (-(-(-1778905482 - 1114196061)) + (--972003446 - -1199116954 * -1321206089) * 762478463)) ^ -340145781 ^ -(-1015222264 + (-300008671 ^ -1810234087) * 65407857)) - ~(~(--1651893188 * 1731766521))))) * 1065986267)) + -385048319 * ~(-1348118203 * -303571285))))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(num5 - ~-1891971982);
						num5 = -(~num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2109104503;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += -2109104502;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -903250274;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 - (1144113456 - -703523773)) ^ 0x4561A766;
							num9 = num9 * -672534689 - -1295277326;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.EasingMode = P_1;
					int[,] array = new int[3, 4]
					{
						{ -804652086, -1705006192, -1187246691, 603719854 },
						{ 110071225, 690045557, 1263148285, -625631557 },
						{ 1644128783, 26041877, 1805503292, -1760328781 }
					};
					array[2, 1] ^= -1632662920;
					array[1, 2] = array[1, 0] ^ -1073235930;
					array[1, 3] = array[2, 2] ^ -2034572687;
					array[0, 2] = array[2, 0] ^ -524340374;
					int num11 = array[0, 2] ^ -1293310860;
					num = ((int)num4 * -928440255) ^ -267270352 ^ num11;
				}
			}
		}
	}

	static void _002B__003C_0021__003F_005E_003C(DoubleAnimation P_0, EasingFunctionBase P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1656529015;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((0x1373AD5F ^ -1105665389) + -738935652 + (1744539875 * 839380025 - 298269766 * 402931961) - ((688350605 - (num2 * 802062523 * -1135360523 + (-1648508522 ^ -1325516504))) * 77173923 - (-(1071194167 * -1784785156 * 2070852675) ^ -(976667849 + 636564263 + ~1488713254))) - (0x77AA1389 ^ -1174701904)) ^ 0x65365B82)) % 3;
					int num5 = 279629988;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 += -279629986;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1586807044;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x5E94C105;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= -464358819;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.EasingFunction = P_1;
					int[,] array = new int[3, 3];
					array[0, 0] = 1808940322;
					array[0, 1] = -1878257453;
					array[0, 2] = -710262580;
					array[1, 0] = 1950300181;
					array[1, 1] = -1347543509;
					array[1, 2] = -2048887667;
					array[2, 0] = 577284902;
					array[2, 1] = -1600020081;
					array[2, 2] = -726940675;
					array[2, 2] = array[1, 2] ^ -1734116902;
					array[0, 0] = array[1, 2] ^ -1830491310;
					array[2, 1] = array[1, 2] ^ -1551052699;
					int num11 = array[2, 1] ^ -23344801;
					num = (int)((num4 * 2111062651) ^ 0x29DE5C7E) ^ num11;
				}
			}
		}
	}

	static void _003F_003C_002F_0040_005E_003E_002B_0021(Timeline P_0, DependencyObject P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1425169892;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(~(-num2) * -526403925) + (-1846948285 + (-(1844605470 - -446417544) + (-1869763531 - (-1585977467 ^ 0x4D74F1E2)) + -609641673))) ^ (-1840210197 ^ (-1408354851 * (-200149908 - -1937305140 - --1907428586))) ^ -266585645)) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(~num5);
						num5 = ~num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1028662911;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= 0x3D50267D;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 764508935;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9 - 1489876698;
							num9 = num9 * -1506013609 - -1355985799;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					Storyboard.SetTarget(P_0, P_1);
					int[,] array = new int[3, 3];
					array[0, 0] = 1892990082;
					array[0, 1] = -325506460;
					array[0, 2] = 1057468350;
					array[1, 0] = -63891371;
					array[1, 1] = -2099589844;
					array[1, 2] = 1399653427;
					array[2, 0] = -1371921007;
					array[2, 1] = -855819281;
					array[2, 2] = 522456226;
					array[0, 1] = array[1, 0] ^ 0x67D090AE;
					array[1, 1] = array[0, 1] ^ -499580876;
					array[1, 0] = array[1, 1] ^ 0x5C03203F;
					array[2, 1] = array[2, 0] ^ -480128182;
					int num11 = array[2, 1] ^ -1258318943;
					num = (int)((num4 * 1276403132) ^ 0x41A82344) ^ num11;
				}
			}
		}
	}

	static void _005E_0029_0023_002B_0021_005E_003E_003D(Timeline P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			Storyboard.SetTargetProperty(P_0, P_1);
		}
	}

	static TimelineCollection @_003C_003D_0026_002A_0023_005E_0024(Storyboard P_0)
	{
		TimelineCollection children = default(TimelineCollection);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -653498974;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(num2 * -1267939729) * 1099977631) ^ (-(682615467 * (-1947853162 - -1928378412) + (437156316 * -1911787583 + 1979038031 * -108096698) + (-2010312049 * 108017025 + (-1900551773 - 2030833341) + ~-1877106077)) + (624301235 + ~(~1591987514) + 169934148)))) % 3;
					int num5 = 1682894200;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 ^ -1731747230) * -1213852719;
						num5 += -1542464442 + -544145458;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -457381542;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = -457381540 - num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1604108799;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ -1101701620) + 415702210;
							num9 = (num9 + --942760565) ^ -1153534873;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					children = P_0.Children;
					int[] array = new int[7] { -1365696204, 296841203, 677011425, -351685643, -55926215, 540421217, -1126231180 };
					array[1] ^= 184861990;
					array[6] ^= 152371321;
					int[] array2 = new int[6];
					array2[0] = 1787898540;
					array2[1] = -2010109718;
					array2[2] = 695490145;
					array2[3] = 80840040;
					array2[4] = 2027312020;
					array2[5] = 236662131;
					array2[0] = array[0] ^ 0x64791F6B;
					array2[3] = array2[2] ^ -763683907;
					array2[4] = array2[3] ^ 0x2F5EDF02;
					int num11 = array2[0] ^ -1777886416;
					num = (int)((num4 * 1805551291) ^ 0xA1E662C9u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return children;
	}

	static void _0024_005E_002F_002B_0026_0026_0025_0028(TimelineCollection P_0, Timeline P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1151510324;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((~(((-(992944085 * -1411939567) + ((-(-2067214889 - 1946948710) ^ 0x481DEFF3) - ~(-1665922202 ^ -148234426) - ((-1178929615 ^ -1766368805 ^ -907987808) - ((-347052940 ^ -1257160644) - (-1778994833 - -212094635) - -844166493 * (1492284496 - 604558090))) + ~(-(-117475904 + (0x736DD7B4 ^ 0x742D6ADA)) * 1025291161)) - (1565412822 - (~((-758153380 ^ -1052955982) - -2084859166) - (~-1658599931 - -78580985 + (--722769851 + (0x7658D1A4 ^ -28617558)) + 1777521145)) + (0x63143DE7 ^ 0x4ED2FB75))) ^ ((-950807162 ^ (--2138140090 + -20021258 * 701675089 * -1196819239)) + (~977815536 - (~-493451925 + (0x101AE5A5 ^ 0x6C81731) + ~(-564189809 * -1559159251))) + ~((0x778F3941 ^ -665901677) - ((-1127648183 ^ 0x13D4801E) + (1851848495 - 1000241182 - (1771651021 + -1244936432)))) - (~(962781210 - -1237218752 + (0xEDD0049 ^ -1999139705) + (-1146430052 + -1331456406) * 1308649057 + ~(0x3AF8268E ^ -1290916241)) - ((~-1916360415 - --662177394) * 975749359 + ((-738553409 ^ -2088190012) + 538775992 + 1358487425 * (1404264377 * 308652143)) - (-(0x2DE65EB2 ^ -1774878688) + -1457843330))) + (~(-1991176631 ^ ((-164272866 ^ -553637333) + -1173825644)) + 1976916503 + ((0x62D72267 ^ -1062518575) * 293559581 * 940884387 * 394085597 - 2145958767 * -2115558911) - 1783980074))) - num2) * -721366711) ^ -(-(0x2AE3A8C3 ^ -1773746466) * 377666213)))) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= -1495698081;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1151026663;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = -1151026662 - num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1072955344;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 ^ 0x7F932C43 ^ -569629076;
							num9 = -num9 - 2120618200;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Add(P_1);
					int[] array = new int[6];
					array[0] = -1812565857;
					array[1] = 2051356270;
					array[2] = -1282687187;
					array[3] = -624722814;
					array[4] = -424012841;
					array[5] = -1101991459;
					array[4] = array[2] ^ 0x1AEF641A;
					array[0] = array[2] ^ 0x2867A6FC;
					array[0] = array[3] ^ 0x74CDD9FC;
					int[] array2 = new int[6];
					array2[0] = 1727371590;
					array2[1] = -134740258;
					array2[2] = 847295415;
					array2[3] = 101180346;
					array2[4] = -1934245426;
					array2[5] = -667915440;
					array2[1] = array[3] ^ 0x62570B54;
					array2[4] = array2[1] ^ -2073820769;
					array2[0] = array2[5] ^ 0x71D85BA0;
					int num11 = array2[1] ^ -1778161444;
					num = (int)((num4 * 1314114304) ^ 0xB09AD500u) ^ num11;
				}
			}
		}
	}

	static void _005E_0028__005E_0026_0040_0024_002F(Storyboard P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -801506352;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(1924996223 * 133617771 - (~(~num2) ^ -(-370843266 * -784263849))) ^ 0x79CD85B2)) % 3;
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
					int num7 = -490257153;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -2019575041;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1198609249;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 1198609247;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Begin();
					int[] array = new int[5];
					array[0] = 96665666;
					array[1] = 2037117276;
					array[2] = -1324063773;
					array[3] = 613400089;
					array[4] = -830923281;
					array[4] = array[2] ^ 0x2B0ACAB7;
					array[4] = array[3] ^ -229415824;
					int[] array2 = new int[4];
					array2[0] = -509079452;
					array2[1] = 249544102;
					array2[2] = -1025431322;
					array2[3] = -776044709;
					array2[2] = array[0] ^ -1607124156;
					array2[3] = array2[2] ^ 0x59734FA5;
					array2[3] = array2[2] ^ -543063283;
					int num11 = array2[2] ^ -1032914902;
					num = (int)((num4 * 868067658) ^ 0x1734A04) ^ num11;
				}
			}
		}
	}

	static void _002F_002A_002A_002A_002D_005E_0040_005E(object P_0, Uri P_1, ComponentResourceLocation P_2)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1389915809;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((num2 ^ ((~-1913137573 - --1553532408 - (-(-(-185751173 ^ 0x1734896B) * 2096456831 - -577690775 * -385625124) - (((0x140D1AC0 ^ -2055158495) - ~(-315749680 ^ -1495392321) + (-810568813 ^ -(-445082513 * ~2065589407))) ^ (--1875987501 ^ 0x71D2199 ^ -1778863983)))) ^ (-(-809731271 * 1442103664) - -(~(-1350166303 ^ ~(-(--1181175794) ^ 0x105C04A6))))) ^ (~(((-(~1790975651) ^ (--1328360956 - 535618113 * -461306529)) - (-1259979494 - (-196355051 ^ -1463623131) + ~(--18163479))) ^ -504803202 ^ -487359744) - -(-(-(--75192475 * 629852765 * 137699253) ^ (2142970253 * --2022065053))))) - (1398270123 - -(~(--2015947906) - (~(-(--244584490)) ^ (-(-29067718 - -781648952) - -(-568151134 - 232706955)))))) ^ 0xA94A53B)) % 3;
					int num5 = 565322964;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 += -1666067608 - -1748348700;
						num5 = (num5 - (2050590404 + 397298205)) * 1866197417;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 370708789;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 - -1727678585;
						num7 = -(num7 ^ -1529733019);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 67583342;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = 1664247874 - ((-1289580716 ^ 0x204A0E65) - num9);
							num9 = ~(686154069 * 1969748651 - num9);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					Application.LoadComponent(P_0, P_1, P_2);
					int[] array = new int[7];
					array[0] = 336358710;
					array[1] = -1294259772;
					array[2] = -1538496336;
					array[3] = -1377207333;
					array[4] = -2088041809;
					array[5] = 1812626216;
					array[6] = -1303289311;
					array[5] = array[1] ^ -217358376;
					array[2] ^= -833685650;
					int[] array2 = new int[5] { -2011075623, -788890660, 1981600468, 441137684, -626166030 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][3] ^ -965308469;
					array2[1] = array2[4] ^ 0x4206ECEB;
					array2[3] = array2[0] ^ 0x54F9AC15;
					int num11 = array3[1][2] ^ 0x19ED40EC;
					num = (int)((num4 * 434103209) ^ 0x94B97FECu) ^ num11;
				}
			}
		}
	}

	static void _003E_0040_0024_003E_0023_005E_002A_003C(UIElement P_0, PointerEventHandler P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1725077869;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(-num2)) * 1509386411 - (-(~((145469404 - 345972491) * 1102937335)) - ~(0x6C81737C ^ -1696240864)))) % 3;
					int num5 = -1561742581;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 += 1561742581;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2043791859;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -264243397;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1000005840;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = 1000005842 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.PointerEntered += P_1;
					int[,] array = new int[3, 3];
					array[0, 0] = 2125182992;
					array[0, 1] = -153632416;
					array[0, 2] = -2023354489;
					array[1, 0] = 1441399805;
					array[1, 1] = 1630510992;
					array[1, 2] = -582990274;
					array[2, 0] = 2035405088;
					array[2, 1] = 463357776;
					array[2, 2] = 1843471069;
					array[1, 0] = array[2, 1] ^ -1482521800;
					array[0, 2] = array[2, 1] ^ 0x448DA266;
					array[2, 1] = array[0, 0] ^ 0x4FE45DD0;
					int num11 = array[2, 1] ^ 0x2D614A59;
					num = ((int)num4 * -142015744) ^ -1005157376 ^ num11;
				}
			}
		}
	}

	static void _0028_003C_005E_0021_005E_0021_003D_0024(UIElement P_0, PointerEventHandler P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 841610310;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(525974349 + -193845211) ^ 0x97F437B) - -(0x47511401 ^ 0x449EE470) - (~(num2 - (~(~(-2079841845 * -100369597 - (~-1235962449 - (-1871539284 ^ 0x190F0674)) + ~2021500861) * -1682726801) - -(-(-118792283 * (0x7E217BB3 ^ -(-1335266629 * (2099693026 + 851888556))))) + (~(-590346363 * -871199227 - 1201266046) - 887165635 * 109383024 * -1105135751 + (~(--199615600 * 779651745 - (-824675669 + ~1559855280) + ((-1923794993 ^ -674576203) - (0x786413F ^ -613855653))) + -(-((-1304348374 ^ -1025703877) - --1727113472 + 1420721507))) + -(532614381 * (-(-1142325635 * 1250416687) + (-985284269 ^ -1796966372) - (0x1AB2ABDE ^ --880706997) * -2116577577) - 230221269)))) - ((-((-1566635995 - ~-499124737 * -1297309011) * 392761023) ^ (-(-(-110897056 - 1920759575 - ~693364316)) + -(~-995905653))) + 718957707) + (-220202935 * -697583365 + -1862296513 + ((-(1344374189 * (963125576 + -909746839)) ^ -(~(-1761820887 * -161364269))) + ~551909994)) + ((~(--1113501742) * 215848677) ^ (54480395 * (~1190498020 - --1142667868))) * -1599229975) - -(~783737160))) % 3;
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
						int num9 = -346489010;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= -733202409;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.PointerExited += P_1;
					int[,] array = new int[3, 3]
					{
						{ -1859809205, 1181471598, 881534942 },
						{ 1457909785, 876287699, -1499729956 },
						{ 924592818, -1182437684, 526961939 }
					};
					array[0, 1] ^= 1830469579;
					array[0, 0] = array[2, 1] ^ -919594260;
					array[2, 2] = array[2, 1] ^ -1930425943;
					int num11 = array[2, 2] ^ -935420629;
					num = ((int)num4 * -910336178) ^ 0x4E40FA3E ^ num11;
				}
			}
		}
	}
}
