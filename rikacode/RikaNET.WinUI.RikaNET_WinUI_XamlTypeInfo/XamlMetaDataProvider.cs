using System;
using System.CodeDom.Compiler;
using System.Diagnostics;
using Microsoft.UI.Xaml.Markup;
using Windows.Foundation.Metadata;

namespace RikaNET.WinUI.RikaNET_WinUI_XamlTypeInfo;

[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
[DebuggerNonUserCode]
public sealed class XamlMetaDataProvider : IXamlMetadataProvider
{
	private XamlTypeInfoProvider _provider;

	private XamlTypeInfoProvider Provider
	{
		get
		{
			if (_provider == null)
			{
				uint num3;
				while (true)
				{
					int num = 2027880147;
					while (true)
					{
						int num2 = num;
						uint num4;
						num3 = (num4 = (uint)((((-598377806 - 1276538066 * 892903709 + (-1656049997 ^ -528841411) * -1256188049 - ~(~1038736940) * 2031338367 - (-(-1472110598) ^ 0x555B31FA) - -(num2 - ((-55366403 - -(420266604 + -(-944699171 ^ -921387600))) * 964102999 + -(1215334503 + (((-2103971089 ^ -(~564704863)) + -566022456) ^ 0x1AC0275F ^ -(~(~-511162798) - -(-852220937 * ~1321345262))))) - (-(981244638 - 1808222591 - ((--660780011 - 583948723 * 933599112) ^ -736681893) + ~(~(800321642 - -290062251 - (-2125157822 - -1210700893))) + -1625612619 * (1179729087 * (-1018336520 + 2057685263 + -867521669) * -1623557469)) ^ (~(1758692451 * -292990668) - (-(-((-2082130391 ^ -393896912) - ~(-917863064))) + -(1296329644 - -(--1832651800 * 1598661001))))) - (1454467216 + -40111974 - -590573507 * ~((401597157 * --416019030) ^ 0x30A0485C) * -376958339))) ^ -1366328007 ^ 0x40B12C9D) - (0x7F0BB45D ^ -1396006764)) * -1694980057 - 1560945638)) % 3;
						int num5 = -361437626;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = (1060784889 - num5) * -578240651;
							num5 = ~(2064853935 * -87668563 - num5);
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 873332365;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 ^= 0x340DFE8C;
						}
						if (num3 != (uint)num7)
						{
							goto end_IL_000e;
						}
						_provider = new XamlTypeInfoProvider();
						int[] array = new int[5];
						array[0] = -2131217985;
						array[1] = 972057196;
						array[2] = 2010776124;
						array[3] = 286273156;
						array[4] = -2084104653;
						array[4] = array[0] ^ 0x26908CF6;
						array[2] = array[4] ^ 0x1C1BE54D;
						array[1] = array[0] ^ -16128563;
						int[] array2 = new int[7] { -1468065698, 1776753062, 930763303, -1628043286, 1368435413, -1430323280, 1809846277 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[2] = array3[0][3] ^ 0x5D05D436;
						array2[4] = array2[2] ^ -2076667541;
						array2[1] = array2[2] ^ 0x2D16CCE4;
						array2[3] = array2[6] ^ -845137792;
						int num9 = array3[1][2] ^ -1974862959;
						num = ((int)num4 * -187409111) ^ -1743350127 ^ num9;
					}
					continue;
					end_IL_000e:
					break;
				}
				int num10 = 2046197334;
				_ = 0;
				for (int num11 = 0; num11 < 1; num11++)
				{
					num10 -= 2046197334;
				}
				if (num3 == (uint)num10)
				{
				}
			}
			return _provider;
		}
	}

	[DefaultOverload]
	public IXamlType GetXamlType(Type type)
	{
		return Provider.GetXamlTypeByType(type);
	}

	public IXamlType GetXamlType(string fullName)
	{
		return Provider.GetXamlTypeByName(fullName);
	}

	public XmlnsDefinition[] GetXmlnsDefinitions()
	{
		return new XmlnsDefinition[0];
	}
}
