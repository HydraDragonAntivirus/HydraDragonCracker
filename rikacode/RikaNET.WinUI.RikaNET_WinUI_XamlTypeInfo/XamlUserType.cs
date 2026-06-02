using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using Microsoft.UI.Xaml.Markup;

namespace RikaNET.WinUI.RikaNET_WinUI_XamlTypeInfo;

[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
[DebuggerNonUserCode]
internal class XamlUserType : XamlSystemBaseType, IXamlType
{
	private XamlTypeInfoProvider _provider;

	private IXamlType _baseType;

	private IXamlType _boxedType;

	private bool _isArray;

	private bool _isMarkupExtension;

	private bool _isBindable;

	private bool _isReturnTypeStub;

	private bool _isLocalType;

	private string _contentPropertyName;

	private string _itemTypeName;

	private string _keyTypeName;

	private Dictionary<string, string> _memberNames;

	private Dictionary<string, object> _enumValues;

	public override IXamlType BaseType => _baseType;

	public override bool IsArray => _isArray;

	public override bool IsCollection => CollectionAdd != null;

	public override bool IsConstructible => Activator != null;

	public override bool IsDictionary => DictionaryAdd != null;

	public override bool IsMarkupExtension => _isMarkupExtension;

	public override bool IsBindable => _isBindable;

	public override bool IsReturnTypeStub => _isReturnTypeStub;

	public override bool IsLocalType => _isLocalType;

	public override IXamlType BoxedType => _boxedType;

	public override IXamlMember ContentProperty => _provider.GetMemberByLongName(_contentPropertyName);

	public override IXamlType ItemType => _provider.GetXamlTypeByName(_itemTypeName);

	public override IXamlType KeyType => _provider.GetXamlTypeByName(_keyTypeName);

	public Activator Activator { get; set; }

	public AddToCollection CollectionAdd { get; set; }

	public AddToDictionary DictionaryAdd { get; set; }

	public CreateFromStringMethod CreateFromStringMethod { get; set; }

	public BoxInstanceMethod BoxInstance { get; set; }

	public XamlUserType(XamlTypeInfoProvider provider, string fullName, Type fullType, IXamlType baseType)
		: base(fullName, fullType)
	{
		while (true)
		{
			int num = 1119833184;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(((0x1DBABB2 ^ (1524046679 * ~(~(-(-(301146114 * -1193667777)))))) - -(-(~((-1626380356 + -1693337092 - -1571839617) * -1580059505))) + -(1187121813 * 1236828840 - ((-(~1904607877) + ~1861551884) ^ -1638343170 ^ -(-303291408 - -1546237534 + (-1440774845 ^ 0x523709FF) - -668764490 * 234827447)) + (0x28EF3243 ^ 0x2230444)) - num2) * -1790369253 - ~(-(-(~(--851629823) ^ 0x36D897AF) ^ (-1930911549 - 282502886 + (0x195FDF8B ^ 0x6D087C32) + -(~1760905541) - (~(~-488068830) + (~1155496732 + (1302430133 - -161910205)))))) - (-(~(-(135928030 - 218485693) ^ 0x420FCA64)) + (0x2D2C4412 ^ (--1628587341 ^ 0x24FF6D07) ^ -(~(-1014270678)) ^ (289432421 * (~926186044 + --1252743581 + (-73693234 ^ -1780450115))))))) % 4;
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
				int num7 = -2;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 = ~num7;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -840083160;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 -= -840083162;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -1541431358;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = (num11 + (-976479115 + 111005957)) * -482708377;
							num11 = ~num11 - 1891777406;
						}
						if (num3 == (uint)num11)
						{
						}
						return;
					}
					_baseType = baseType;
					int[,] array = new int[4, 4];
					array[0, 0] = 220613029;
					array[0, 1] = -937276231;
					array[0, 2] = 1268573693;
					array[0, 3] = -2061906373;
					array[1, 0] = -7238625;
					array[1, 1] = 1051014694;
					array[1, 2] = -1023067775;
					array[1, 3] = 1119945483;
					array[2, 0] = -1489166491;
					array[2, 1] = 1588844196;
					array[2, 2] = -1509213778;
					array[2, 3] = -1460564267;
					array[3, 0] = -1683918984;
					array[3, 1] = -826755630;
					array[3, 2] = -1286742019;
					array[3, 3] = -473613438;
					array[3, 2] = array[0, 3] ^ -1018499746;
					array[0, 1] = array[2, 2] ^ -202176131;
					array[1, 3] = array[3, 0] ^ 0x19204ECD;
					int num13 = array[1, 3] ^ -1480213750;
					num = (int)((num4 * 716047803) ^ 0x27468BD6) ^ num13;
				}
				else
				{
					_provider = provider;
					int[,] array2 = new int[3, 3];
					array2[0, 0] = 2146197675;
					array2[0, 1] = -2058235774;
					array2[0, 2] = -703657506;
					array2[1, 0] = 1924717728;
					array2[1, 1] = 1894083222;
					array2[1, 2] = -1584994232;
					array2[2, 0] = 1802882850;
					array2[2, 1] = -66104349;
					array2[2, 2] = -106160088;
					array2[2, 1] = array2[2, 0] ^ 0x6E199663;
					array2[0, 2] = array2[1, 1] ^ -1616462022;
					array2[0, 1] = array2[0, 0] ^ -1959655125;
					int num14 = array2[0, 1] ^ -538239335;
					num = ((int)num4 * -5049807) ^ 0x2D5C1795 ^ num14;
				}
			}
		}
	}

	public override IXamlMember GetMember(string name)
	{
		if (_memberNames == null)
		{
			goto IL_000e;
		}
		goto IL_0422;
		IL_000e:
		int num = 227012856;
		goto IL_0013;
		IL_0013:
		int num2 = num;
		uint num4;
		uint num3 = (num4 = (uint)((~-1266169693 - (-(--2060339807) - ~(((-2101740777 * -1790857921) ^ -138992090) - -(~(-num2) * 962540977)) * 122542865)) ^ -143378662)) % 5;
		int num5 = 0;
		_ = 0;
		for (int num6 = 0; num6 < 1; num6++)
		{
			num5 = -num5;
		}
		if (num3 == (uint)num5)
		{
			goto IL_000e;
		}
		int num7 = -1168812367;
		_ = 0;
		for (int num8 = 0; num8 < 2; num8++)
		{
			num7 = -num7 ^ -1577223686;
			num7 = num7 * 769859983 * 2117299991;
		}
		string value = default(string);
		if (num3 != (uint)num7)
		{
			int num9 = -2043042984;
			_ = 0;
			for (int num10 = 0; num10 < 1; num10++)
			{
				num9 ^= -2043042982;
			}
			if (num3 != (uint)num9)
			{
				int num11 = -4;
				_ = 0;
				for (int num12 = 0; num12 < 1; num12++)
				{
					num11 = ~num11;
				}
				if (num3 != (uint)num11)
				{
					int num13 = -5;
					_ = 0;
					for (int num14 = 0; num14 < 1; num14++)
					{
						num13 = ~num13;
					}
					if (num3 != (uint)num13)
					{
					}
					return null;
				}
				return _provider.GetMemberByLongName(value);
			}
			goto IL_0422;
		}
		return null;
		IL_0422:
		int num15;
		if (_memberNames.TryGetValue(name, out value))
		{
			num = 2095254208;
			num15 = num;
		}
		else
		{
			num = 790754905;
			num15 = num;
		}
		goto IL_0013;
	}

	public override object ActivateInstance()
	{
		return Activator();
	}

	public override void AddToMap(object instance, object key, object item)
	{
		DictionaryAdd(instance, key, item);
	}

	public override void AddToVector(object instance, object item)
	{
		CollectionAdd(instance, item);
	}

	public override void RunInitializer()
	{
		_0025_002B_003D_0023_0024_003F_003D_0040(_002F_002F_0029_003C_005E_003F_0029_0021(base.UnderlyingType));
	}

	public override object CreateFromString(string input)
	{
		if (BoxedType != null)
		{
			goto IL_000e;
		}
		goto IL_0e73;
		IL_000e:
		int num = 366550349;
		goto IL_0013;
		IL_0013:
		string text = default(string);
		string current = default(string);
		long num90 = default(long);
		int num91 = default(int);
		string[] array17 = default(string[]);
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)((((num2 - -(-(~(-364706979 * (0x6AD17D0A ^ 0x20243DE7))) - (-1835573336 ^ -(~1959030917) ^ -(294791487 * -1449225854 + (~(-1285505600) - (-1775688467 + 1870840215 + -153451825 * 920563611)))) + ((0x62C73F05 ^ -1027006425) + (-1198535770 - (0x3C575058 ^ --154752061 ^ ~(-1048521676 ^ -932933221))) - (~(-(-(1913687327 + -876291258)) * 1641323849) ^ -(~(~(~-22293938) - ~(-169392759))))))) ^ (((-(-600289725 ^ (~1249184423 + --791524439 + -920341365 * ~-1433123713)) - (-(-835447822 - -1708279721 + (-1691233505 ^ -2034308153) - ~(1050529489 + -1930396381)) ^ (1341250267 * -1914363587 - (134922020 - 1497850819) - 1294164959 - -(-1129882451)))) ^ -(-789412643)) * 1617873533)) + -((0x45E8FB2A ^ -(-1418220409 + 1896751181 * 685791786 - ((-710068686 ^ 0x2914608C) - (-1324544733 ^ 0x68812233)))) + 1113280555)) * 716254727)) % 10;
			uint num5 = num3;
			int num6 = -1811777626;
			_ = 0;
			for (int num7 = 0; num7 < 1; num7++)
			{
				num6 += 1811777626;
			}
			if (num5 == (uint)num6)
			{
				break;
			}
			uint num8 = num3;
			int num9 = -1135910700;
			_ = 0;
			for (int num10 = 0; num10 < 2; num10++)
			{
				num9 = ~num9 * 1921818257;
				num9 = -num9;
			}
			if (num8 != (uint)num9)
			{
				uint num11 = num3;
				int num12 = -6;
				_ = 0;
				for (int num13 = 0; num13 < 1; num13++)
				{
					num12 = ~num12;
				}
				if (num11 == (uint)num12)
				{
					goto IL_0e73;
				}
				uint num14 = num3;
				int num15 = 1393124965;
				_ = 0;
				for (int num16 = 0; num16 < 1; num16++)
				{
					num15 *= -1869376953;
				}
				if (num14 != (uint)num15)
				{
					uint num17 = num3;
					int num18 = 1192028894;
					_ = 0;
					for (int num19 = 0; num19 < 1; num19++)
					{
						num18 *= 1874102671;
					}
					if (num17 != (uint)num18)
					{
						uint num20 = num3;
						int num21 = -606601087;
						_ = 0;
						for (int num22 = 0; num22 < 2; num22++)
						{
							num21 = -1148900414 - num21 - 1829682420;
							num21 = (num21 ^ -692730650) - 377454706;
						}
						if (num20 != (uint)num21)
						{
							uint num23 = num3;
							int num24 = -8;
							_ = 0;
							for (int num25 = 0; num25 < 1; num25++)
							{
								num24 = ~num24;
							}
							if (num23 != (uint)num24)
							{
								uint num26 = num3;
								int num27 = 1063426649;
								_ = 0;
								for (int num28 = 0; num28 < 1; num28++)
								{
									num27 ^= 0x3F629A5D;
								}
								if (num26 != (uint)num27)
								{
									uint num29 = num3;
									int num30 = 2030258025;
									_ = 0;
									for (int num31 = 0; num31 < 1; num31++)
									{
										num30 ^= 0x79034760;
									}
									if (num29 == (uint)num30)
									{
										goto IL_0e44;
									}
									uint num32 = num3;
									int num33 = 1475865863;
									_ = 0;
									for (int num34 = 0; num34 < 1; num34++)
									{
										num33 ^= 0x57F7ED0F;
									}
									if (num32 != (uint)num33)
									{
									}
									long num35 = 0L;
									try
									{
										if (_enumValues.TryGetValue(_002A_0026_0021_0025_003D_0023_002A_0021(text), out var value))
										{
											while (true)
											{
												int num36 = -350851868;
												while (true)
												{
													num2 = num36;
													num3 = (num4 = (uint)((((num2 - -(-(~(-364706979 * (0x6AD17D0A ^ 0x20243DE7))) - (-1835573336 ^ -(~1959030917) ^ -(294791487 * -1449225854 + (~(-1285505600) - (-1775688467 + 1870840215 + -153451825 * 920563611)))) + ((0x62C73F05 ^ -1027006425) + (-1198535770 - (0x3C575058 ^ --154752061 ^ ~(-1048521676 ^ -932933221))) - (~(-(-(1913687327 + -876291258)) * 1641323849) ^ -(~(~(~-22293938) - ~(-169392759))))))) ^ (((-(-600289725 ^ (~1249184423 + --791524439 + -920341365 * ~-1433123713)) - (-(-835447822 - -1708279721 + (-1691233505 ^ -2034308153) - ~(1050529489 + -1930396381)) ^ (1341250267 * -1914363587 - (134922020 - 1497850819) - 1294164959 - -(-1129882451)))) ^ -(-789412643)) * 1617873533)) + -((0x45E8FB2A ^ -(-1418220409 + 1896751181 * 685791786 - ((-710068686 ^ 0x2914608C) - (-1324544733 ^ 0x68812233)))) + 1113280555)) * 716254727)) % 4;
													uint num37 = num3;
													int num38 = 0;
													_ = 0;
													for (int num39 = 0; num39 < 1; num39++)
													{
														num38 *= 730129737;
													}
													if (num37 == (uint)num38)
													{
														break;
													}
													uint num40 = num3;
													int num41 = -3;
													_ = 0;
													for (int num42 = 0; num42 < 1; num42++)
													{
														num41 = -num41;
													}
													if (num40 != (uint)num41)
													{
														goto end_IL_0ec2;
													}
													num35 = _002B_0025_003F_0028_0026_002F__005E(value);
													int[,] array = new int[4, 3]
													{
														{ 138035699, 1250978316, 169584287 },
														{ 1714947062, 492915495, -1910684844 },
														{ 1145765854, 2035997344, 1476000195 },
														{ 99131134, -1713731906, 711024694 }
													};
													array[0, 0] ^= -86475300;
													array[2, 1] = array[1, 2] ^ 0x15FD5FAA;
													array[0, 1] = array[1, 0] ^ -1066138352;
													array[2, 2] = array[3, 2] ^ -838667206;
													int num43 = array[2, 2] ^ 0xA173ECF;
													num36 = (int)((num4 * 1826577013) ^ 0xD1E43CDBu) ^ num43;
												}
												continue;
												end_IL_0ec2:
												break;
											}
											uint num44 = num3;
											int num45 = 1367493129;
											_ = 0;
											for (int num46 = 0; num46 < 1; num46++)
											{
												num45 -= 1367493127;
											}
											if (num44 == (uint)num45)
											{
												goto IL_267b;
											}
											uint num47 = num3;
											int num48 = -337651023;
											_ = 0;
											for (int num49 = 0; num49 < 1; num49++)
											{
												num48 *= -354406831;
											}
											if (num47 == (uint)num48)
											{
											}
										}
										try
										{
											num35 = _0026_0023_0024_002A_005E_005E_003F_002A(_002A_0026_0021_0025_003D_0023_002A_0021(text));
										}
										catch (FormatException)
										{
											using Dictionary<string, object>.KeyCollection.Enumerator enumerator = _enumValues.Keys.GetEnumerator();
											uint num84;
											int num85;
											do
											{
												int num50;
												int num51;
												if (!enumerator.MoveNext())
												{
													num50 = 1340162160;
													num51 = num50;
												}
												else
												{
													num50 = 1283729258;
													num51 = num50;
												}
												while (true)
												{
													num2 = num50;
													num3 = (num4 = (uint)((((num2 - -(-(~(-364706979 * (0x6AD17D0A ^ 0x20243DE7))) - (-1835573336 ^ -(~1959030917) ^ -(294791487 * -1449225854 + (~(-1285505600) - (-1775688467 + 1870840215 + -153451825 * 920563611)))) + ((0x62C73F05 ^ -1027006425) + (-1198535770 - (0x3C575058 ^ --154752061 ^ ~(-1048521676 ^ -932933221))) - (~(-(-(1913687327 + -876291258)) * 1641323849) ^ -(~(~(~-22293938) - ~(-169392759))))))) ^ (((-(-600289725 ^ (~1249184423 + --791524439 + -920341365 * ~-1433123713)) - (-(-835447822 - -1708279721 + (-1691233505 ^ -2034308153) - ~(1050529489 + -1930396381)) ^ (1341250267 * -1914363587 - (134922020 - 1497850819) - 1294164959 - -(-1129882451)))) ^ -(-789412643)) * 1617873533)) + -((0x45E8FB2A ^ -(-1418220409 + 1896751181 * 685791786 - ((-710068686 ^ 0x2914608C) - (-1324544733 ^ 0x68812233)))) + 1113280555)) * 716254727)) % 8;
													uint num52 = num3;
													int num53 = -152048951;
													_ = 0;
													for (int num54 = 0; num54 < 2; num54++)
													{
														num53 = -(num53 * -2044101141);
														num53 = -822405240 - ~num53;
													}
													if (num52 == (uint)num53)
													{
														num50 = 1283729258;
														continue;
													}
													uint num55 = num3;
													int num56 = 1204274146;
													_ = 0;
													for (int num57 = 0; num57 < 1; num57++)
													{
														num56 -= 1204274141;
													}
													if (num55 != (uint)num56)
													{
														uint num58 = num3;
														int num59 = -1130905202;
														_ = 0;
														for (int num60 = 0; num60 < 1; num60++)
														{
															num59 *= -250699035;
														}
														if (num58 != (uint)num59)
														{
															uint num61 = num3;
															int num62 = -1706322755;
															_ = 0;
															for (int num63 = 0; num63 < 1; num63++)
															{
																num62 -= -1706322755;
															}
															if (num61 != (uint)num62)
															{
																uint num64 = num3;
																int num65 = -1885504255;
																_ = 0;
																for (int num66 = 0; num66 < 2; num66++)
																{
																	num65 = ~(num65 ^ -619730339);
																	num65 = -(num65 * -1206400117);
																}
																if (num64 != (uint)num65)
																{
																	uint num67 = num3;
																	int num68 = 1887528227;
																	_ = 0;
																	for (int num69 = 0; num69 < 1; num69++)
																	{
																		num68 ^= 0x70816527;
																	}
																	if (num67 != (uint)num68)
																	{
																		break;
																	}
																	int[] array2 = new int[6];
																	array2[0] = -663532741;
																	array2[1] = 746325521;
																	array2[2] = 1504051819;
																	array2[3] = 79327746;
																	array2[4] = 1119363288;
																	array2[5] = -988858016;
																	array2[2] = array2[3] ^ 0x43C16292;
																	array2[5] = array2[0] ^ 0x2E05B9EC;
																	array2[0] = array2[2] ^ 0x7C14FDDE;
																	int[] array3 = new int[5] { -1882517152, -540701493, -1212512328, 1979323594, 1231416368 };
																	int[][] array4 = new int[2][] { array2, array3 };
																	array3[1] = array4[0][3] ^ 0x7F8CC0E8;
																	array3[4] = array3[1] ^ 0x506A2470;
																	array3[2] = array3[1] ^ 0x283C470A;
																	array3[0] = array3[3] ^ -624152472;
																	int num70 = array4[1][1] ^ 0x34D7F29A;
																	num50 = (int)((num4 * 119108470) ^ 0xBDEDF508u) ^ num70;
																}
																else
																{
																	num35 = _002B_0025_003F_0028_0026_002F__005E(value);
																	int[] array5 = new int[7];
																	array5[0] = 1022075308;
																	array5[1] = 216844923;
																	array5[2] = 2046802244;
																	array5[3] = -1217818412;
																	array5[4] = 59744731;
																	array5[5] = -2095910624;
																	array5[6] = -1851270686;
																	array5[0] = array5[6] ^ -177367288;
																	array5[0] = array5[4] ^ 0x62FF2721;
																	array5[1] = array5[3] ^ -1771352129;
																	int[] array6 = new int[4] { -1070383754, 1507906031, 1220687858, 1772363954 };
																	int[][] array7 = new int[2][] { array5, array6 };
																	array6[1] = array7[0][6] ^ 0x42E169A1;
																	array6[0] = array6[2] ^ 0x2EDAB280;
																	array6[3] = array6[2] ^ 0x7AB7B013;
																	int num71 = array7[1][1] ^ 0x5450567A;
																	num50 = (int)((num4 * 395106235) ^ 0x8D4BC5CBu) ^ num71;
																}
															}
															else
															{
																bool num72 = _enumValues.TryGetValue(_002A_0026_0021_0025_003D_0023_002A_0021(current), out value);
																int[] array8 = new int[7] { -1463627286, 1812078611, 996211115, -70369635, -504476827, -780031838, 1363193762 };
																array8[1] ^= -121537460;
																array8[5] = array8[3] ^ 0x8E666D7;
																int[] array9 = new int[5];
																array9[0] = 69758967;
																array9[1] = 1247037013;
																array9[2] = -471427859;
																array9[3] = 1508102456;
																array9[4] = -810226508;
																array9[2] = array8[2] ^ 0x626FB134;
																array9[4] ^= 1820381354;
																array9[0] = array9[3] ^ -2144438546;
																array9[0] = array9[3] ^ 0x13431E5A;
																int num73 = array9[2] ^ -1188847312;
																int[] array10 = new int[5];
																array10[0] = 309574591;
																array10[1] = -281038677;
																array10[2] = 308160809;
																array10[3] = -150466431;
																array10[4] = -1328108103;
																array10[2] = array10[1] ^ 0x2474C097;
																array10[4] = array10[1] ^ -125786695;
																int[] array11 = new int[4];
																array11[0] = 618852951;
																array11[1] = 353389205;
																array11[2] = -834411362;
																array11[3] = 268068604;
																array11[0] = array10[0] ^ -1555855967;
																array11[1] = array11[0] ^ 0x45CF66E6;
																array11[3] ^= -679375829;
																int num74 = array11[0] ^ -878348440;
																int num75 = ((int)num4 * -1465354942) ^ 0x2E894260;
																num73 ^= num75;
																num74 ^= num75;
																int num76;
																int num77;
																if (num72)
																{
																	num76 = num74;
																	num77 = num76;
																}
																else
																{
																	num76 = num73;
																	num77 = num76;
																}
																num50 = num76 ^ num75;
															}
														}
														else
														{
															int num78 = _0029_0040_002F_002B_0025_003C_003F_003D(_002A_0026_0021_0025_003D_0023_002A_0021(text), current, StringComparison.OrdinalIgnoreCase);
															int[] array12 = new int[7];
															array12[0] = -1293438143;
															array12[1] = -2057635840;
															array12[2] = -1917155068;
															array12[3] = -1904160933;
															array12[4] = -5449037;
															array12[5] = -419366170;
															array12[6] = -648001124;
															array12[0] = array12[3] ^ 0x2B9D502B;
															array12[0] = array12[1] ^ 0x5E1D3E8B;
															int[] array13 = new int[6];
															array13[0] = -212506300;
															array13[1] = 135296362;
															array13[2] = 1212543461;
															array13[3] = 1901145871;
															array13[4] = 1872540196;
															array13[5] = 465149451;
															array13[2] = array12[1] ^ -1433662274;
															array13[0] = array13[3] ^ -145069032;
															array13[0] ^= -1161786201;
															array13[3] = array13[5] ^ -1758731747;
															int num79 = array13[2] ^ -805692143;
															int[,] array14 = new int[4, 4];
															array14[0, 0] = -1214720984;
															array14[0, 1] = 1899289238;
															array14[0, 2] = -395171726;
															array14[0, 3] = 983179519;
															array14[1, 0] = 1566365973;
															array14[1, 1] = -257243116;
															array14[1, 2] = 1291978452;
															array14[1, 3] = -284147361;
															array14[2, 0] = -321702359;
															array14[2, 1] = 329543100;
															array14[2, 2] = -321531286;
															array14[2, 3] = -1919537805;
															array14[3, 0] = -360643832;
															array14[3, 1] = 734136813;
															array14[3, 2] = 1705208437;
															array14[3, 3] = -6499635;
															array14[1, 1] = array14[1, 3] ^ -1187082276;
															array14[3, 2] = array14[0, 3] ^ -2079838424;
															array14[0, 1] = array14[2, 2] ^ 0x6CCE88A9;
															int num80 = array14[0, 1] ^ 0x209F1AFE;
															int num81 = (int)(num4 * 69622570) ^ -954423268;
															num79 ^= num81;
															num80 ^= num81;
															int num82;
															int num83;
															if (num78 == 0)
															{
																num82 = num80;
																num83 = num82;
															}
															else
															{
																num82 = num79;
																num83 = num82;
															}
															num50 = num82 ^ num81;
														}
													}
													else
													{
														current = enumerator.Current;
														num50 = 1812923427;
													}
												}
												num84 = num3;
												num85 = 1298962146;
												_ = 0;
												for (int num86 = 0; num86 < 2; num86++)
												{
													num85 = -num85 * -571701321;
													num85 ^= -920994624;
												}
											}
											while (num84 == (uint)num85);
											uint num87 = num3;
											int num88 = 2138852603;
											_ = 0;
											for (int num89 = 0; num89 < 2; num89++)
											{
												num88 = -1078057348 - num88;
												num88 = -num88;
											}
											if (num87 == (uint)num88)
											{
											}
										}
										goto IL_267b;
										IL_267b:
										num90 |= num35;
									}
									catch (FormatException)
									{
										throw new ArgumentException(input, base.FullName);
									}
									num91++;
									goto IL_26af;
								}
								goto IL_2a2e;
							}
							num91 = 0;
							int[] array15 = new int[4];
							array15[0] = 1475394368;
							array15[1] = 959977810;
							array15[2] = -371600776;
							array15[3] = 973262260;
							array15[1] = array15[2] ^ 0x41C9856C;
							array15[2] ^= 2105960414;
							array15[2] ^= 1405562578;
							int[] array16 = new int[5];
							array16[0] = -337856475;
							array16[1] = -1653351485;
							array16[2] = -717715293;
							array16[3] = -1658125889;
							array16[4] = -1716822266;
							array16[1] = array15[0] ^ 0x4A65AA72;
							array16[3] = array16[4] ^ -868828502;
							array16[2] = array16[1] ^ 0x34881EC0;
							int num92 = array16[1] ^ 0x5D5B1DC5;
							num = (int)((num4 * 1168452488) ^ 0xE50BB8F8u) ^ num92;
							continue;
						}
						num90 = 0L;
						array17 = _0023_0026_0024_0024_003F_002B_0021_0029(input, ',', StringSplitOptions.None);
						int[] array18 = new int[6];
						array18[0] = -1043936020;
						array18[1] = -1247991520;
						array18[2] = 42272435;
						array18[3] = -197317589;
						array18[4] = 1196443973;
						array18[5] = 1259142386;
						array18[3] = array18[2] ^ 0x12695BDB;
						array18[1] = array18[0] ^ -699797070;
						int[] array19 = new int[5] { -2136584437, 110717527, -1057825378, -1533859675, -1218476395 };
						int[][] array20 = new int[2][] { array18, array19 };
						array19[2] = array20[0][5] ^ 0x5A7B2572;
						array19[1] = array19[2] ^ 0x16ADA59D;
						array19[4] = array19[2] ^ -1551102638;
						array19[3] = array19[0] ^ -87676333;
						int num93 = array20[1][2] ^ 0x3495BAE4;
						num = (int)((num4 * 1822469808) ^ 0xBCDDC770u) ^ num93;
						continue;
					}
					if (_enumValues != null)
					{
						num = 919431322;
						continue;
					}
					goto IL_2c07;
				}
				return CreateFromStringMethod(input);
			}
			return BoxInstance(_0024_003F_0028_002A_0025_0029__002A(BoxedType, input));
			IL_2c07:
			throw new ArgumentException(input, base.FullName);
			IL_26af:
			int num94 = 534212210;
			goto IL_26b4;
			IL_0e44:
			text = array17[num91];
			num = -2043969837;
			continue;
			IL_2a2e:
			if (num91 < array17.Length)
			{
				goto IL_0e44;
			}
			num94 = 2134237411;
			goto IL_26b4;
			IL_26b4:
			num2 = num94;
			num3 = (num4 = (uint)((((num2 - -(-(~(-364706979 * (0x6AD17D0A ^ 0x20243DE7))) - (-1835573336 ^ -(~1959030917) ^ -(294791487 * -1449225854 + (~(-1285505600) - (-1775688467 + 1870840215 + -153451825 * 920563611)))) + ((0x62C73F05 ^ -1027006425) + (-1198535770 - (0x3C575058 ^ --154752061 ^ ~(-1048521676 ^ -932933221))) - (~(-(-(1913687327 + -876291258)) * 1641323849) ^ -(~(~(~-22293938) - ~(-169392759))))))) ^ (((-(-600289725 ^ (~1249184423 + --791524439 + -920341365 * ~-1433123713)) - (-(-835447822 - -1708279721 + (-1691233505 ^ -2034308153) - ~(1050529489 + -1930396381)) ^ (1341250267 * -1914363587 - (134922020 - 1497850819) - 1294164959 - -(-1129882451)))) ^ -(-789412643)) * 1617873533)) + -((0x45E8FB2A ^ -(-1418220409 + 1896751181 * 685791786 - ((-710068686 ^ 0x2914608C) - (-1324544733 ^ 0x68812233)))) + 1113280555)) * 716254727)) % 4;
			uint num95 = num3;
			int num96 = -490353464;
			_ = 0;
			for (int num97 = 0; num97 < 1; num97++)
			{
				num96 -= -490353467;
			}
			if (num95 == (uint)num96)
			{
				goto IL_26af;
			}
			uint num98 = num3;
			int num99 = 140649349;
			_ = 0;
			for (int num100 = 0; num100 < 2; num100++)
			{
				num99 = ~(-num99);
				num99 = (num99 - 61747093) ^ -879827396;
			}
			if (num98 == (uint)num99)
			{
				goto IL_2a2e;
			}
			uint num101 = num3;
			int num102 = -2;
			_ = 0;
			for (int num103 = 0; num103 < 1; num103++)
			{
				num102 = -num102;
			}
			if (num101 != (uint)num102)
			{
				uint num104 = num3;
				int num105 = 435193538;
				_ = 0;
				for (int num106 = 0; num106 < 2; num106++)
				{
					num105 = 1573332766 - (num105 ^ -1149908242);
					num105 = ~num105 ^ 0x51026466;
				}
				if (num104 == (uint)num105)
				{
				}
				goto IL_2c07;
			}
			return _0029_002A_003E_0024_003D_0040_0021_005E((object)num90, _002B_0025_003E_003F_003E_0029_002A_0021(base.UnderlyingType));
		}
		goto IL_000e;
		IL_0e73:
		int num107;
		if (CreateFromStringMethod != null)
		{
			num = 296327128;
			num107 = num;
		}
		else
		{
			num = 950947299;
			num107 = num;
		}
		goto IL_0013;
	}

	public void SetContentPropertyName(string contentPropertyName)
	{
		_contentPropertyName = contentPropertyName;
	}

	public void SetIsArray()
	{
		_isArray = true;
	}

	public void SetIsMarkupExtension()
	{
		_isMarkupExtension = true;
	}

	public void SetIsBindable()
	{
		_isBindable = true;
	}

	public void SetIsReturnTypeStub()
	{
		_isReturnTypeStub = true;
	}

	public void SetIsLocalType()
	{
		_isLocalType = true;
	}

	public void SetItemTypeName(string itemTypeName)
	{
		_itemTypeName = itemTypeName;
	}

	public void SetKeyTypeName(string keyTypeName)
	{
		_keyTypeName = keyTypeName;
	}

	public void SetBoxedType(IXamlType boxedType)
	{
		_boxedType = boxedType;
	}

	public object BoxType<T>(object instance) where T : struct
	{
		return (T)instance;
	}

	public void AddMemberName(string shortName)
	{
		if (_memberNames == null)
		{
			goto IL_000e;
		}
		goto IL_0544;
		IL_000e:
		int num = 452591122;
		goto IL_0013;
		IL_0013:
		uint num3;
		while (true)
		{
			int num2 = num;
			uint num4;
			num3 = (num4 = (uint)((~(~(num2 - (~(~(-(-(--532310560 + ~1552932414)))) * 310002069 + ~-1809834023 * 222512257 - -(140816358 * 1610972295 * -1127880125) * 2119445539)) - (((-(-1422060971 * 839109685 - (-1958376210 ^ 0xEDAD787)) - (-(~-138447861) - 415660969) + -1271862758 * 670759469) ^ ((~(-2084920059 * ~1229165566) + (~(-309098840 + 2085125861) - (--722674973 + -1137035887 * -133344351))) ^ (-(-303488386 - -150768339) - (-1208351527 - 1261126925) * 999355297 + ~(816246077 * 1932861023) * -996018443))) + (1721234661 * 319600667 - (-((0x1C35D8C4 ^ -1387128158) + -2040386313) + (-1400167056 ^ 0x8B639F4)) + ((-(1835273648 + 1762432775) + (-683700357 * 1046976406 + (0x1E1FCE12 ^ 0x72534354))) * -1859160263 - ~(-77764373 * 1209544015)))) - (((~(-1796480194) + (-361642362 * -2051887025 - 142853762) + (-1567806741 ^ 0x25763185)) * 1023978743) ^ -((-(1371391289 * 1302681734) - -132345807) * -2101694413))) - 21123914) ^ -1675908907)) % 4;
			int num5 = 0;
			_ = 0;
			for (int num6 = 0; num6 < 2; num6++)
			{
				num5 += -1207339880 ^ 0x29D7DF47;
				num5 = ~num5 - -329281364;
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = -1750206621;
			_ = 0;
			for (int num8 = 0; num8 < 2; num8++)
			{
				num7 = ~num7;
				num7 *= -1593266557;
			}
			if (num3 == (uint)num7)
			{
				_memberNames = new Dictionary<string, string>();
				int[] array = new int[6];
				array[0] = 1636094332;
				array[1] = -2050111493;
				array[2] = 872305875;
				array[3] = -445898238;
				array[4] = -866850043;
				array[5] = -1512856125;
				array[5] = array[1] ^ 0x71CB7D5C;
				array[3] = array[4] ^ -980418897;
				int[] array2 = new int[5] { -824914834, 322169246, -625850992, -1957889651, 1407036819 };
				int[][] array3 = new int[2][] { array, array2 };
				array2[0] = array3[0][4] ^ -2128012514;
				array2[3] = array2[1] ^ 0x71EEB542;
				array2[3] = array2[0] ^ -1518791931;
				int num9 = array3[1][0] ^ -1484230569;
				num = (int)((num4 * 1594331101) ^ 0x109740CD) ^ num9;
				continue;
			}
			goto IL_02c8;
		}
		goto IL_000e;
		IL_02c8:
		int num10 = -4;
		_ = 0;
		for (int num11 = 0; num11 < 1; num11++)
		{
			num10 = ~num10;
		}
		if (num3 != (uint)num10)
		{
			int num12 = -2035653056;
			_ = 0;
			for (int num13 = 0; num13 < 2; num13++)
			{
				num12 = 640841275 * 845955949 - num12 - -228297223;
				num12 = ~num12 - 1449648376;
			}
			if (num3 == (uint)num12)
			{
			}
			return;
		}
		goto IL_0544;
		IL_0544:
		_memberNames.Add(shortName, _003F_005E_002F_003C_0028_002D_0025_0023(base.FullName, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[358 - 21 - 24 - 19], shortName));
		num = 683388401;
		goto IL_0013;
	}

	public void AddEnumValue(string name, object value)
	{
		if (_enumValues == null)
		{
			goto IL_000e;
		}
		goto IL_0561;
		IL_000e:
		int num = 275952363;
		goto IL_0013;
		IL_0013:
		uint num3;
		while (true)
		{
			int num2 = num;
			uint num4;
			num3 = (num4 = (uint)(~(-(((~(num2 + (((1868496249 * ~(((-347403435 - ~-1114340876) ^ -530578582 ^ -1782401587) + ((-411417152 * -1273203841 * 1313162001) ^ ((-1131840900 ^ 0x2719F332) - 148030262)))) ^ ((-1588400713 ^ (-19845657 ^ ~(-585833568)) ^ ((--410700887 - (-33174729 + -547780469) - ~-565253379 * -1084616903) ^ -81144770)) + (~824710187 + -(~(-282647353 * -809858887) * -1959482397)) + (--1025139041 - (-(~-1949595765) + (~(-2107924861 * -923834129 * 249518217) - ((--407515659 - 38002653 * -2049941659) ^ -(--1907499424))))))) + ~(-(-910857307 * -(531575879 * (0x715B6647 ^ -913408768))) - (-2042816953 ^ ~(-(935039959 * 1180923873) * 2116443931))))) ^ ((-234681048 ^ (-(1486637607 + -896531970) * -1346402851)) * 659535793)) * -611922949) ^ 0x3F2B0D2) ^ 0xBFA3323) * -277477039)) % 4;
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
			int num7 = 3;
			_ = 0;
			for (int num8 = 0; num8 < 2; num8++)
			{
				num7 = -num7 - -1015468412;
				num7 = ~(-num7);
			}
			if (num3 == (uint)num7)
			{
				_enumValues = new Dictionary<string, object>();
				int[] array = new int[7];
				array[0] = -180933621;
				array[1] = -273101354;
				array[2] = -76874255;
				array[3] = 1496976194;
				array[4] = -1117461778;
				array[5] = -14702224;
				array[6] = -1405085282;
				array[0] = array[2] ^ 0x6131EA0D;
				array[4] = array[3] ^ 0x6AA5B896;
				int[] array2 = new int[6];
				array2[0] = 2067617729;
				array2[1] = -335817093;
				array2[2] = -1236830138;
				array2[3] = -2134536787;
				array2[4] = -319663418;
				array2[5] = -1632549555;
				array2[1] = array[6] ^ 0x49AFCC79;
				array2[4] = array2[1] ^ -1861842063;
				array2[5] ^= -802820443;
				array2[3] = array2[4] ^ 0x56310830;
				int num9 = array2[1] ^ 0x35035E57;
				num = (int)((num4 * 1761912542) ^ 0x5BC15DDA) ^ num9;
				continue;
			}
			goto IL_02e3;
		}
		goto IL_000e;
		IL_02e3:
		int num10 = -1;
		_ = 0;
		for (int num11 = 0; num11 < 1; num11++)
		{
			num10 = ~num10;
		}
		if (num3 != (uint)num10)
		{
			int num12 = 2046809601;
			_ = 0;
			for (int num13 = 0; num13 < 2; num13++)
			{
				num12 = ~(num12 + (2096411794 - -442606846));
				num12 = (num12 ^ 0x454A6F28) - 1321620674;
			}
			if (num3 == (uint)num12)
			{
			}
			return;
		}
		goto IL_0561;
		IL_0561:
		_enumValues.Add(name, value);
		num = 1347720249;
		goto IL_0013;
	}

	static RuntimeTypeHandle _002F_002F_0029_003C_005E_003F_0029_0021(Type P_0)
	{
		RuntimeTypeHandle typeHandle = default(RuntimeTypeHandle);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1139090620;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((~(~((num2 ^ -(-(((-(-(-1844496845 * -1065704110)) - (814763161 * 831235820 * -822890359 - 53001793 * (-1965419746 - -1842943880))) ^ -((--1001296935 ^ 0x53A8D730) - (-103268770 + (964197296 + 321219459)))) - (~(1373909895 - ~(--514626980)) ^ -(--1658772633 - -176037846 * 646166981 - -1969030005 * (-1759244213 * 2006305312)))) + ~(~(1993375009 * -(0x547BDFFC ^ (--2126820631 ^ -1301815288)))))) * 830301677)) - (((-170113401 * -(-2141672102 ^ 0x40C335F)) ^ -1117267504) + ~(~-966508949 * -1212397687 + -851197437 * (-1227581777 + -2133796695)))) ^ ((~(77981167 - -2130060467) + -(~1812929397)) ^ -2064475337)) * 184501645 - -(-1496102072 - -169470178))) % 3;
					int num5 = -1278236970;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= -2117025469;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1694443360;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -1694443361;
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
					typeHandle = P_0.TypeHandle;
					int[] array = new int[7];
					array[0] = -1500819119;
					array[1] = -303743954;
					array[2] = 167339982;
					array[3] = -473890413;
					array[4] = 159157085;
					array[5] = 531601021;
					array[6] = 669140066;
					array[2] = array[5] ^ -1840748331;
					array[4] = array[1] ^ 0x8E6F923;
					int[] array2 = new int[5] { 1251350016, 599721497, -1679807939, -95030807, -2084858591 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][6] ^ 0x1FB539F3;
					array2[0] ^= -1474859187;
					array2[2] ^= -283049438;
					array2[2] ^= 922114838;
					int num11 = array3[1][3] ^ 0x3042C077;
					num = (int)((num4 * 1074345685) ^ 0x25C935A9) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return typeHandle;
	}

	static void _0025_002B_003D_0023_0024_003F_003D_0040(RuntimeTypeHandle P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1045552793;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(1979817698 * -359848345 - (-1266225485 - ~((-(num2 * 1695395423) ^ (-((-(0x18FEB6EC ^ 0x38154039) - -1811648345 * ~(-1949914710 ^ 0x4DC2D5F6)) * -10279609) - -1515612465)) * -579508923 - ~(1487676983 * (1739745241 - -167610133) * 304692853 - 705629023) - ~(-(1041422122 + 266356409)) * -237720013)))) % 3;
					int num5 = -283223229;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -283223227 - num5;
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
						int num9 = -576328844;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = 814162089 - num9 * -660080203;
							num9 = ~(~num9);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					RuntimeHelpers.RunClassConstructor(P_0);
					int[,] array = new int[4, 3]
					{
						{ 724752490, 1409898957, -2110330614 },
						{ -1587605564, -1135615175, 1559080856 },
						{ -1534996896, 695718255, 470517394 },
						{ -1304356059, -1854088890, -1731383794 }
					};
					array[1, 2] ^= -1051279150;
					array[3, 1] = array[2, 0] ^ 0x1863ABF;
					array[3, 0] = array[1, 2] ^ -1589426651;
					array[3, 0] = array[3, 2] ^ -1963978456;
					int num11 = array[3, 0] ^ 0x1033046F;
					num = (int)((num4 * 1691734416) ^ 0xDF0E7240u) ^ num11;
				}
			}
		}
	}

	static object _0024_003F_0028_002A_0025_0029__002A(IXamlType P_0, string P_1)
	{
		object result = default(object);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 2009991888;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(1107162605 - ((~((--115323388 + (0x4DB4EC82 ^ -815605643)) ^ -(1219871056 * -2057092893)) - (~(~(num2 * -1193842033) + (~(~(-1572960072 + -1176477122 - -217248986) - ((-2143862297 ^ 0x238382AA) + ~(-938460158)) + (0x1F3A7EF9 ^ -(1346534356 - -1028564159 - ~-1821179713))) + (1422989693 * ~(1549361505 + 1361599369) + (0x569825CB ^ 0x1813517A) * -482543625 + ((326784601 * -(-1684624352)) ^ (~(-115210461 * 175100553) - (-279550690 - 1481459635 - -412442328))) - (-639439163 * ((0x3098B940 ^ 0x458DF1A) - (18556436 - 757677940) - -(-1706633470 ^ 0x789D4EE0)) + -(--1172024379 + 1009759765) * -297557831)))) ^ 0x969D48F) + -250580699 * 580880925) * 1718289707 - (1644042770 - 571993036)))) % 3;
					int num5 = 77383836;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 77383836;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -459379606;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(num7 - 1865619732);
						num7 = num7 * 1418875593 * -1356730525;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 590454418;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 590454417;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.CreateFromString(P_1);
					int[,] array = new int[3, 4];
					array[0, 0] = -529077826;
					array[0, 1] = 341427339;
					array[0, 2] = -215270253;
					array[0, 3] = 1215999954;
					array[1, 0] = -393426135;
					array[1, 1] = 1574100915;
					array[1, 2] = 228104682;
					array[1, 3] = 631875418;
					array[2, 0] = -2023360769;
					array[2, 1] = 1114108816;
					array[2, 2] = -2134278966;
					array[2, 3] = 16766093;
					array[2, 3] = array[1, 0] ^ -162090063;
					array[2, 2] ^= 765019259;
					array[0, 2] = array[1, 1] ^ 0x5DF0F62A;
					int num11 = array[0, 2] ^ -1253633800;
					num = (int)((num4 * 1090595316) ^ 0xF0F5E808u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string[] _0023_0026_0024_0024_003F_002B_0021_0029(string P_0, char P_1, StringSplitOptions P_2)
	{
		string[] result = default(string[]);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 466163242;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((((~(((((-(~-1798206796) * 567208619 * 766595203 + -1945021335) * -1650972833 - num2) ^ (0x494F7AB6 ^ ((712858123 * -1410275868) ^ (~(~(~-517987841) * 241929155) - (--2087015637 - (-1108925217 - -810032765) + (-345434448 - -1343950051 + (-1823543846 - -330611702)) - (0x220A5EF8 ^ -(0x55ABE923 ^ -85786594))) + (0x450696B ^ -851191348))))) * -914965577 + ~(-(--1201217605 * -559669707) ^ -813310956)) ^ (-(637985603 * (-124091085 - 594048169 * -2052759894)) + ~((0x778D9C77 ^ 0x611DF1D5) + 657039891))) ^ (0x3B4AD95D ^ (--1683376016 - (0x37F34956 ^ 0x3D966661)))) - -(-298229771 ^ 0x2C31831F)) ^ --628010584) * -338421203)) % 3;
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
					int num7 = -705623769;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -(num7 - 2049648131);
						num7 = (num7 - (-248688479 + -957290801)) * 982219775;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1458160830;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ -1232826972) + 814771165;
							num9 = ((0x4F0769F9 ^ -1761916789) - num9) * -472455235;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.Split(P_1, P_2);
					int[,] array = new int[3, 3];
					array[0, 0] = -1088085836;
					array[0, 1] = 2061847619;
					array[0, 2] = -1845043389;
					array[1, 0] = 415046830;
					array[1, 1] = 606117728;
					array[1, 2] = 316101377;
					array[2, 0] = -1493844180;
					array[2, 1] = 1771910033;
					array[2, 2] = -2006249991;
					array[0, 2] = array[2, 1] ^ -2137693162;
					array[1, 0] = array[1, 2] ^ -1715028087;
					array[1, 0] = array[0, 2] ^ -1158554707;
					array[1, 1] = array[2, 2] ^ -2026583176;
					int num11 = array[1, 1] ^ -503498342;
					num = (int)((num4 * 76294188) ^ 0x5AB5ECE0) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string _002A_0026_0021_0025_003D_0023_002A_0021(string P_0)
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
				int num = -1484842605;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((-780589997 ^ -409634436) + (2089323163 - -1439814364 - 779283788) - (-721149295 + (1663275780 + 1869928588) + (--1481315526 + ~475221162) - -1705707155 - ~(-(num2 ^ ((1359492549 * -(~(665756168 - -830244152))) ^ (~((0x5CC8FE84 ^ -111165869) + ((-68597902 ^ -1133466018) - (-426849354 + 705614233) * 1055934237 - (0x39D647F0 ^ 0x234970FE)) + (-1991469811 * -1997273991 + (-1257192550 ^ 0x200A8235) + (329108774 - -2069454733) * -1263702953 - (-1319798419 - (-166959584 - (-616639341 + 142451333))) - (0x4E4D9CB3 ^ (1282434417 * ~(-219806299))))) ^ ((-1455718935 + (-((-871305826 ^ -1812230618) + 1266796645) ^ (183728880 + -1259500328 + --1584609787 - (-1765087882 + -1473260400 + (-1843723089 ^ 0x4F9DC58D))))) * -1635906337 + -424777021 * -1078244311)))) ^ (((-(0x30D2FDFF ^ -937416722) + (~(-422141412 - -554374083) - (-1995270237 ^ -875788656)) - -2128497021 * (-297658531 - -700612840 - --1934497792 - -(~2085132793))) ^ (2145601 * ((0x7C78A81C ^ -668590037) + (-984592904 ^ (-1773519159 * --1813111275))))) + 863198735) ^ ((((666630657 - -1692598443 - -1043003265) * -257087847) ^ ~(-263770123)) - (385949813 - ~(~1260076148) - -((0x6FD34C35 ^ -714213441) - 1882186351)) + ~(-(375422689 - -351475136) - 1080517555) * 1966637925))) - -(--210971645)) + 1856466068)) % 3;
					int num5 = -724086646;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 += 724086648;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1364721905;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = 529315641 - (num7 - (203563826 + -50556659));
						num7 = ~num7 ^ 0x4552FD87;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2050404656;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9 * -1192151997;
							num9 = (num9 + (1416989328 + -2069700437)) * 704365673;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.Trim();
					int[] array = new int[7];
					array[0] = 276798443;
					array[1] = -1117971734;
					array[2] = -1006932521;
					array[3] = 1458309389;
					array[4] = 426098520;
					array[5] = -801643068;
					array[6] = 703373993;
					array[6] = array[2] ^ 0x78318D5A;
					array[5] = array[2] ^ 0x7CBDC83B;
					array[1] = array[6] ^ 0x116C132;
					int[] array2 = new int[7];
					array2[0] = 1914026650;
					array2[1] = 1850722772;
					array2[2] = -664320244;
					array2[3] = 1702935023;
					array2[4] = 1945945573;
					array2[5] = -300750645;
					array2[6] = -925987320;
					array2[3] = array[2] ^ 0x91C1C95;
					array2[1] = array2[2] ^ 0x7675948;
					array2[6] = array2[0] ^ 0x31572A10;
					array2[4] = array2[5] ^ 0x7738FD59;
					int num11 = array2[3] ^ 0x9042384;
					num = ((int)num4 * -1089557366) ^ -1956717336 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static long _002B_0025_003F_0028_0026_002F__005E(object P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return Convert.ToInt64(P_0);
		}
	}

	static long _0026_0023_0024_002A_005E_005E_003F_002A(string P_0)
	{
		long result = default(long);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1112173973;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((((~num2 * 1775326459) ^ ~(-(-55208945 - ~(1533651665 * 1342273979)) * 270880413 + -785968231)) * 1943576465 - (~(~(-(-782657434 - -1720910396))) - (-(-(0x15C03A8F ^ 0x3D09607C)) - (-(-725103941 - 2105878367) - (~-912121025 - --709613813))))) ^ -341859375) * -983284361 + (-1225161339 + ~-1490062951))) % 3;
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
					int num7 = -3;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = ~num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -517996859;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ -1282079306) - 90692004;
							num9 = -(num9 - (232103488 - -1943333554));
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = Convert.ToInt64(P_0);
					int[] array = new int[5] { -1101214995, 1699990715, -1212789666, 202009129, -137897714 };
					array[2] ^= -122488659;
					array[2] ^= -521254684;
					array[4] ^= 391141193;
					int[] array2 = new int[7];
					array2[0] = 1613342214;
					array2[1] = 1699899425;
					array2[2] = 587386001;
					array2[3] = 154219350;
					array2[4] = -633202931;
					array2[5] = 1055121815;
					array2[6] = -718413742;
					array2[1] = array[1] ^ -1257877025;
					array2[3] = array2[4] ^ 0x4FD6FD4D;
					array2[5] = array2[0] ^ 0x50961D1E;
					int num11 = array2[1] ^ 0x658DFC3E;
					num = ((int)num4 * -1807166732) ^ 0x41254EC4 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static int _0029_0040_002F_002B_0025_003C_003F_003D(string P_0, string P_1, StringComparison P_2)
	{
		int result = default(int);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -198738909;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((num2 + ((((0xF13D714 ^ ((-673585368 * -468141029 + ~650720476 - -(-501785794 ^ -1479481502) - 692101559) * 1652548749)) + (-(-(-(-829682195 - 1758988894))) + (((0x268DFD3A ^ 0x4CA9890F) + -(480671984 * -1401411225)) ^ 0x2E3E83D4) - ~(~(1722148901 * -1132474118) - 935325703 * ~721837916 + (-(~1285536962) + 1131093825 * (-739747496 + 273305490))))) ^ (2079119711 * (-331809297 * (((-589616198 ^ 0x724B997) + -1356397701) ^ -2015543348) - (-(-(1240236585 * 1647184480)) + -700352774) - ~(-837258668 + (--1196644571 * -568449345 + (0x7024B74 ^ 0x8C7CDEB)))))) - (-(-(-(-1121936574 + -846683113))) ^ (1045574524 + (~(~938866765 + (-1150846618 + -22766072)) + (-863140719 * (1443407835 * 667239329) + ((0x47AB4D8D ^ -1429943974) - -195806463 * 401376372))) + (673531499 * (-2090458780 - -503981047) - ((0x71FB4ABE ^ 0x2D811081) - -1546614121 * -2035684618) + 1022069014 + ~426973611) + (1570768954 - -1597996135 * (1809934247 + (-642910028 + ~-1525641136)) - (-(1247826251 * 943742946 - (-620128801 ^ 0x5D668D8B)) * -1480322947 + -(1615948373 + -786815331 - ~1356508747 + -(--78231388)))))))) * 333913577 - 657796945 * -(((-1402405450 ^ -555741295) + (619387938 - ((0x7299F524 ^ 0x58E61F4B) - (-1521069262 ^ -2006599819)))) * -1392116453) + (~2139503901 + -(-(~-1065752835)) + (1045172697 * (0x405894B6 ^ 0xD2676F0) * -767983695 - ((-378274903 ^ -950722263) - -798058852)) - -1265065201))) % 3;
					int num5 = 1777672712;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * -2073835857 - 1114029074;
						num5 = (~-560469005 - num5) ^ 0x193C9C42;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1552591454;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 * 1687094623) ^ -643178501;
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 396846968;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= 0x17A76779;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = string.Compare(P_0, P_1, P_2);
					int[] array = new int[7];
					array[0] = 1395373417;
					array[1] = 137776019;
					array[2] = -415011716;
					array[3] = 1643172707;
					array[4] = -814857431;
					array[5] = 1606575100;
					array[6] = -1199624904;
					array[0] = array[4] ^ 0x3410830A;
					array[5] = array[6] ^ -850725292;
					array[6] = array[4] ^ 0x288B98E1;
					int[] array2 = new int[7] { -103887380, 1676918656, 1548518817, 1403646374, 19867120, 1279261078, 1244175683 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][1] ^ -1462157770;
					array2[0] = array2[5] ^ -2099432341;
					array2[1] = array2[3] ^ 0x2A59C11C;
					int num11 = array3[1][3] ^ 0x6F0C5FFA;
					num = ((int)num4 * -1691955473) ^ 0x54388CB6 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static Type _002B_0025_003E_003F_003E_0029_002A_0021(Type P_0)
	{
		Type underlyingType = default(Type);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1015887333;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(-(-(-339915258 + -1465450143 * (-((-765648059 - -1799327255) * -481830023 - 398788439 * (-16512611 ^ -1968956059)) * 52835689) - ~num2 * -1715691085 + (~-488998815 - (1696957948 + ~(--1397049925 - (806523732 + -1589155985))) - (-(-645472388 + -(1871059878 - -218743913)) - --682970332)))))) - ~339895542 - -790757758)) % 3;
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
					int num7 = 66027807;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(num7 * 62123775);
						num7 = ~(num7 ^ -1088455535);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1981761332;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9 * 643493621;
							num9 = (num9 ^ -890777105) - 738229026;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					underlyingType = Enum.GetUnderlyingType(P_0);
					int[] array = new int[4];
					array[0] = 720490586;
					array[1] = -671376444;
					array[2] = -1519270596;
					array[3] = 474993657;
					array[0] = array[3] ^ -1147228442;
					array[3] ^= 1880501798;
					array[1] = array[3] ^ -1794373991;
					int[] array2 = new int[6] { -1292974061, -2042649502, 679223103, -1373376077, -684100338, 1615088340 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][2] ^ 0x7DA0C7E3;
					array2[1] = array2[0] ^ 0x25D09BD;
					array2[1] = array2[0] ^ -1863378157;
					array2[2] = array2[3] ^ -1556135774;
					int num11 = array3[1][3] ^ 0x648AF70C;
					num = (int)((num4 * 32562715) ^ 0x80A725D3u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return underlyingType;
	}

	static object _0029_002A_003E_0024_003D_0040_0021_005E(object P_0, Type P_1)
	{
		object result = default(object);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1938063657;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~((-1307877358 ^ (0x16863289 ^ -1100481706 ^ -(~(0x17377F17 ^ -838037700) * 529838687) ^ 0x1B87CE0A)) - ((num2 ^ -((-1443668053 * (-774170103 * (953592447 * -1774815819 - -(1888079455 + 845121870 - (0x1E492884 ^ -1115703526)) - -(2101446000 + -1993016285 - -1248075399)))) ^ 0x58C97DC1)) - -(((1525465967 + (-(-1328931809 * -388700055) - (-617722079 + -964804140 + 554420262) + (~(-791316545 + -2007686934) + ~(0x1957ABFA ^ 0x5D817395)))) * 26652061) ^ (~(-1708387054) - ~((~67109604 - (-519677060 ^ 0x7430D0AC) - --847760163 * -564116701) ^ 0x5C5C7BC3))))) ^ ~(-(~(-1380024391 + (0x3B45CE63 ^ -542745728))))) * 74470103)) % 3;
					int num5 = -400200421;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= -400200421;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 754612757;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 * 550873093 - 343948514;
						num7 *= 934883237;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1987142572;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 * 1623232865 - -911894755;
							num9 = num9 + -1522944857 + -1911229443;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = Convert.ChangeType(P_0, P_1);
					int[] array = new int[4];
					array[0] = 974274462;
					array[1] = -412958807;
					array[2] = 65935218;
					array[3] = -832584088;
					array[0] = array[3] ^ 0x2F6507B1;
					array[1] = array[2] ^ 0x5DA09F67;
					int[] array2 = new int[5] { 1207402502, 721210143, -252299481, 1115139543, 715891640 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][2] ^ -694198037;
					array2[0] = array2[1] ^ 0x2C18DA08;
					array2[1] ^= 711961636;
					int num11 = array3[1][4] ^ -1471793786;
					num = (int)((num4 * 1468220651) ^ 0xBC37071Cu) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string _003F_005E_002F_003C_0028_002D_0025_0023(string P_0, string P_1, string P_2)
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
				int num = -1494302828;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-num2 * -1563465583 - 1485174803 * 1591040647))) % 3;
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
					int num7 = -335087493;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = 1087875147 - -num7;
						num7 = num7 - 11839704 - 908491696;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -55578870;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 + (-1765512315 + 820738263)) ^ -47778951;
							num9 = 1239176463 - -num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0 + P_1 + P_2;
					int[] array = new int[5];
					array[0] = -567513087;
					array[1] = -1109532399;
					array[2] = 1179169870;
					array[3] = -937177985;
					array[4] = -1287025541;
					array[4] = array[0] ^ 0x2352D498;
					array[4] = array[3] ^ -1410833686;
					array[2] = array[0] ^ 0x28ABF1C;
					int[] array2 = new int[7] { 1752780770, -1223743456, -862428775, 129548562, -511346069, -572132733, -1148077731 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][1] ^ -992756331;
					array2[6] = array2[0] ^ -455158857;
					array2[1] = array2[5] ^ 0xA3B0313;
					array2[4] = array2[0] ^ -1000307707;
					int num11 = array3[1][0] ^ 0x6D4DF146;
					num = (int)((num4 * 35497574) ^ 0x83C1F210u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}
}
