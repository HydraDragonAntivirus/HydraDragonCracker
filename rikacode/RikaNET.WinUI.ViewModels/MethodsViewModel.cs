using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using RikaNET.Core.Models;
using RikaNET.Core.Services;
using RikaNET.WinUI.Models;

namespace RikaNET.WinUI.ViewModels;

public sealed class MethodsViewModel : ObservableObject
{
	[Serializable]
	[CompilerGenerated]
	private sealed class _003C_003Ec
	{
		public static readonly _003C_003Ec _003C_003E9 = new _003C_003Ec();

		public static Func<TypeItem, TypeNodeViewModel> _003C_003E9__40_1;

		public static Func<NamespaceGroupViewModel, IEnumerable<TypeNodeViewModel>> _003C_003E9__40_0;

		public static Func<NamespaceItem, IEnumerable<TypeItem>> _003C_003E9__44_0;

		public static Func<MethodItem, bool> _003C_003E9__44_2;

		internal TypeNodeViewModel _003CRefresh_003Eb__40_1(TypeItem type)
		{
			return new TypeNodeViewModel
			{
				FullName = _0028_0025_003D_0028_0025_0040_003F_0024(type),
				DisplayName = _0021_0021_002D_003E_0021_0024_003F_(type),
				MethodCount = _0023_003C_002F_002F_002B_002B_002A_002F(type),
				IconGlyph = ResolveIcon(type)
			};
		}

		internal IEnumerable<TypeNodeViewModel> _003CRefresh_003Eb__40_0(NamespaceGroupViewModel item)
		{
			return item.Types;
		}

		internal IEnumerable<TypeItem> _003CCountSelectedMethods_003Eb__44_0(NamespaceItem @namespace)
		{
			return _0029_0024_0029__003C_0021_0021_005E(@namespace);
		}

		internal bool _003CCountSelectedMethods_003Eb__44_2(MethodItem method)
		{
			return _0028_0040_002A_002F_0025_0023_002A_005E(method);
		}

		static string _0028_0025_003D_0028_0025_0040_003F_0024(TypeItem P_0)
		{
			string fullName = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 2097597295;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((((((~(num2 + (~(420757372 + 1468563190 - (0x3D473E2F ^ 0x316CEA7A)) - -1553398274 - (-(0x723E4D01 ^ 0x650DA737) - -212650947 * (-2083727097 * -2086329157) + 1194046099 * -(-812468004 - -1668245370)) - -1952099228 + ~333499270 + -((-1993363985 ^ -704227570) + ((0x74ADE387 ^ --2118511915 ^ 0x55F71A1F) - 990735681) + (-(-1800442653 * ~(356817802 - 207048606)) + -1938995220))) * 1872059051) ^ ((-1594653869 * (586714696 + 741636730 + -(~(-1481767325 ^ 0x54535D95)))) ^ (1248716146 - (~(--795146950 + -1007086289) + (-648871300 ^ 0x66E97185) - (--153629947 + 1134387310 + (~-33835919 - ~(626288633 + 128981114))))))) - (-(~(0x4B616580 ^ -1504260464)) + ((-(1280432211 + -1139431691) ^ 0x7C40A425) - 745536488))) * 1098079099 - (-(~(-2134876279 * 1335384015)) - -(0x1E4DE5B6 ^ 0x40843EC1))) ^ (857647445 * -477999383 * -2108518305 - (0x7F5E9F57 ^ --1843860876))) * 195879211 - (0xB9A2F3F ^ 0x7C7FE653)) * 2122514739)) % 3;
						int num5 = 204156812;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -911292714 - (num5 - ~736778961);
							num5 = ~num5 * -577171693;
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
							int num9 = 831124662;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 = 831124664 - num9;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						fullName = P_0.FullName;
						int[] array = new int[5];
						array[0] = 1375824388;
						array[1] = 843478937;
						array[2] = -2058393894;
						array[3] = 652598748;
						array[4] = 1172000332;
						array[4] = array[2] ^ 0x3D764DB0;
						array[3] = array[2] ^ 0x4BFB1594;
						array[0] = array[2] ^ 0x381EA72E;
						int[] array2 = new int[7];
						array2[0] = 1296386340;
						array2[1] = -497689645;
						array2[2] = 1274540992;
						array2[3] = -1601938752;
						array2[4] = -358899421;
						array2[5] = -131458805;
						array2[6] = 631555393;
						array2[3] = array[2] ^ -1436102076;
						array2[4] = array2[1] ^ 0x7AD41B0D;
						array2[5] = array2[1] ^ 0x6AF3DCBB;
						array2[4] = array2[3] ^ 0x1A39A509;
						int num11 = array2[3] ^ 0x4F967473;
						num = (int)((num4 * 190309773) ^ 0xD6A8E832u) ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return fullName;
		}

		static string _0021_0021_002D_003E_0021_0024_003F_(TypeItem P_0)
		{
			string displayName = default(string);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1014295438;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((2019652342 + -1148905877 - -((~(num2 * -1215085793 * -1243769179 - (((789173813 * (-(-991219506 ^ 0x25BD39BB) + ~((-464316202 - -1382532031) * -1169451411))) ^ 0x6BE25D46) + -(-(1641768967 * (-(478621153 * -105610661) * 1603059289))))) ^ 0x34D0BE6F) * -431728909 * -1333837965)) ^ 0x3D767D9E)) % 3;
						int num5 = 2133026394;
						_ = 0;
						for (int num6 = 0; num6 < 1; num6++)
						{
							num5 = 2133026394 - num5;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 105145770;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 *= -1696369027;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 1443259682;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 -= 1443259681;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						displayName = P_0.DisplayName;
						int[] array = new int[7];
						array[0] = 1472270657;
						array[1] = -1903462695;
						array[2] = -1784230919;
						array[3] = -398479483;
						array[4] = -1793767073;
						array[5] = -1022523575;
						array[6] = -626796781;
						array[6] = array[2] ^ 0x1508DE9D;
						array[3] ^= -589767876;
						array[2] = array[0] ^ -1442759208;
						int[] array2 = new int[5] { 520082431, 1583071078, -1744045763, 1140762718, 2003619167 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[2] = array3[0][1] ^ -612910452;
						array2[4] = array2[2] ^ 0x60C16D60;
						array2[4] = array2[0] ^ -1423820649;
						array2[1] = array2[3] ^ -965098723;
						int num11 = array3[1][2] ^ -1722447889;
						num = ((int)num4 * -5141088) ^ 0x706FF660 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return displayName;
		}

		static int _0023_003C_002F_002F_002B_002B_002A_002F(TypeItem P_0)
		{
			int methodCount = default(int);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = 445580422;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(~(-((num2 ^ ((-1519076663 * -2088119531 - ~(~2108487220) - -(-1087497961 + -(-1626692983 ^ -(1408710949 * (1891238415 - 1587580398))))) * 1298964013) ^ (-(1421143067 + -478435243 * (-1913250641 * 1298347611 + (-315696780 - 48817605) - 1175300931 * (-1053914778 ^ 0x35279D84)) - (0x739F7755 ^ (-1447831929 * -792751681) ^ ~(--1426428658))) - ~((--783017122 - ~(~(--223244133) + (-308370785 * -294179022 + 744319639 * 1598106980))) ^ ~((--1380658874 - (1102648468 + -338707536) + -2131916675 * (-879680145 ^ 0x592E18A3)) ^ -1605033682)))) * -2135506657)) - --872871760)) % 3;
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
						int num7 = -1;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 = -num7;
						}
						if (num3 != (uint)num7)
						{
							int num9 = 0;
							_ = 0;
							for (int num10 = 0; num10 < 1; num10++)
							{
								num9 *= -83424947;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						methodCount = P_0.MethodCount;
						int[] array = new int[6];
						array[0] = 1454483840;
						array[1] = 1161462465;
						array[2] = -310596016;
						array[3] = 336495876;
						array[4] = 1013313914;
						array[5] = 507723718;
						array[3] = array[0] ^ 0x47426A3C;
						array[4] ^= -1089963564;
						array[4] = array[1] ^ 0xA084010;
						int[] array2 = new int[7] { -1199194882, -2061153134, 1188923098, -1141127479, -1363303320, -1945345946, 1755566097 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[1] = array3[0][1] ^ -1955242668;
						array2[0] = array2[1] ^ -1059461883;
						array2[2] = array2[3] ^ -1531823718;
						array2[6] = array2[2] ^ 0x4782FF7A;
						int num11 = array3[1][1] ^ 0x70F49690;
						num = ((int)num4 * -1242760187) ^ 0x14F3A2D2 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return methodCount;
		}

		static IReadOnlyList<TypeItem> _0029_0024_0029__003C_0021_0021_005E(NamespaceItem P_0)
		{
			IReadOnlyList<TypeItem> types = default(IReadOnlyList<TypeItem>);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1515987953;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)((~(num2 + -(0x7FB84CD0 ^ (~(-(-471543635 - (-1222364331 - -1364356195) - (1751915562 + 591096879 - (1922995330 - 858929680)))) ^ (-701482103 ^ -(-1734487363 * (--196893273 + (-818671599 - -1779032677)))))) * -1751943525) ^ 0x1DE2CF6) - ~(-(-280088538 ^ 0x8610DBD) + ((-(-510679065 * 1067079038) * -198128297) ^ -1666764853)) - ~(966001427 * (1048685115 - 102426532 - 848277587 * 2046151477 + -1874942433)) - (0x6094C283 ^ -622809939))) % 3;
						int num5 = 6554134;
						_ = 0;
						for (int num6 = 0; num6 < 2; num6++)
						{
							num5 = -num5;
							num5 = (num5 - (154889145 - -144091009)) ^ 0x29B229BB;
						}
						if (num3 == (uint)num5)
						{
							break;
						}
						int num7 = 1384996393;
						_ = 0;
						for (int num8 = 0; num8 < 1; num8++)
						{
							num7 ^= 0x528D5E2B;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1;
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
						types = P_0.Types;
						int[,] array = new int[3, 4];
						array[0, 0] = 1103024080;
						array[0, 1] = -2108816609;
						array[0, 2] = 965807865;
						array[0, 3] = -282094801;
						array[1, 0] = -880548891;
						array[1, 1] = -1938583074;
						array[1, 2] = 29117360;
						array[1, 3] = -1742341904;
						array[2, 0] = -792628212;
						array[2, 1] = 1372137058;
						array[2, 2] = 46203752;
						array[2, 3] = -1894200434;
						array[0, 1] = array[2, 3] ^ -430260779;
						array[2, 3] = array[0, 3] ^ -321892194;
						array[2, 0] = array[2, 1] ^ -155190334;
						array[0, 0] = array[1, 3] ^ 0x708D00B9;
						int num11 = array[0, 0] ^ 0x2B4C6A3F;
						num = ((int)num4 * -674407470) ^ -1783618984 ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return types;
		}

		static bool _0028_0040_002A_002F_0025_0023_002A_005E(MethodItem P_0)
		{
			bool ısSelected = default(bool);
			try
			{
				throw new Exception();
			}
			catch (Exception)
			{
				while (true)
				{
					int num = -1081138831;
					while (true)
					{
						int num2 = num;
						uint num4;
						uint num3 = (num4 = (uint)(-(-(-(-((-(num2 * 1042980263 + ((-1145957831 - -(-(~(-893530019 * -1264842231 * -1943733641)))) ^ ((-300707824 ^ (1410593279 - (-1138526839 * -255784383 - 1963771522) - (-1932106651 + -1755589970) + -(-277588896))) + (~(1776599146 + -(-(~-864338535))) ^ (-803243003 * -1957605851))))) ^ (((-579186344 ^ ((--1362238379 ^ -401434657) - ~1560302529)) + ~(~2136014760)) ^ -322418542)) - -523665247))) * -824560199))) % 3;
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
						int num7 = 1830411787;
						_ = 0;
						for (int num8 = 0; num8 < 2; num8++)
						{
							num7 = ~num7;
							num7 = -num7 * -1323567275;
						}
						if (num3 != (uint)num7)
						{
							int num9 = -1096038942;
							_ = 0;
							for (int num10 = 0; num10 < 2; num10++)
							{
								num9 = ~(num9 ^ -360843017);
								num9 = num9 * 1038833287 * 1391323009;
							}
							if (num3 == (uint)num9)
							{
							}
							goto end_IL_0007;
						}
						ısSelected = P_0.IsSelected;
						int[] array = new int[6];
						array[0] = 1837913377;
						array[1] = -397271670;
						array[2] = 456726813;
						array[3] = 151385141;
						array[4] = 2133025531;
						array[5] = 342489127;
						array[5] = array[1] ^ -909849627;
						array[2] = array[1] ^ -1903791414;
						array[1] = array[3] ^ 0x720B21B9;
						int[] array2 = new int[7];
						array2[0] = -42815793;
						array2[1] = 1463514006;
						array2[2] = 1197186091;
						array2[3] = -508191591;
						array2[4] = -1864314895;
						array2[5] = -2125557753;
						array2[6] = 477048902;
						array2[6] = array[4] ^ 0x6BF93841;
						array2[4] = array2[0] ^ -1616695113;
						array2[2] = array2[0] ^ -398581796;
						array2[0] ^= 1069042639;
						int num11 = array2[6] ^ 0x34A209A3;
						num = ((int)num4 * -511269939) ^ 0x992CF5E ^ num11;
					}
					continue;
					end_IL_0007:
					break;
				}
			}
			return ısSelected;
		}
	}

	private readonly IAssemblyWorkspaceService _assemblyWorkspaceService;

	private List<MethodRowViewModel> _allMethods = new List<MethodRowViewModel>();

	private bool _hasLoadedAssembly;

	private string _searchText = string.Empty;

	private string _selectedTypeName = string.Empty;

	public AppViewModel AppViewModel { get; }

	public RelayCommand ClearSearchCommand { get; }

	public RelayCommand ClearSelectionCommand { get; }

	public bool HasLoadedAssembly
	{
		get
		{
			return _hasLoadedAssembly;
		}
		private set
		{
			if (!SetProperty(ref _hasLoadedAssembly, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xF15 ^ 0xE2B]))
			{
				return;
			}
			while (true)
			{
				int num = 91463564;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(num2 ^ -(1428938321 * (((-(-(27364941 + 54671830)) + ~1681292700 * 7474891 * 201920931 - -2107337132) ^ 0x483C24D1) + -956562937 * (-2086490645 + -1814936067 * (-228318981 * (0x316DB166 ^ -343575903)))))) - ~(~(-(~(-1368094287 + (2002168451 + 544770518)))) * -1175034619) + -(~(-(~-1101166283) - (1625482351 + -547212662 + (0x22B6B1A8 ^ 0x72FA31B5) - (0x791C233B ^ -1387654849)))))) % 3;
					int num5 = 1171618772;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 1171618772;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1990733394;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= 1990733393;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -466387110;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9 * 284713825;
							num9 = 1607907686 - num9 - 792257170;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					@_0040_002B_002F_003C_0028_0023_002A((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[446 - 47 - 4 - 33]);
					int[,] array = new int[3, 4];
					array[0, 0] = -690852547;
					array[0, 1] = 336669410;
					array[0, 2] = -802231887;
					array[0, 3] = -1809745493;
					array[1, 0] = -941512184;
					array[1, 1] = -742682800;
					array[1, 2] = -793331406;
					array[1, 3] = 1554930835;
					array[2, 0] = -635859399;
					array[2, 1] = -1241248015;
					array[2, 2] = 46733659;
					array[2, 3] = -479951581;
					array[0, 1] = array[2, 2] ^ 0x71055A3;
					array[0, 1] = array[0, 2] ^ 0x746E4551;
					array[1, 1] = array[0, 1] ^ -1220502567;
					array[2, 1] = array[0, 0] ^ -813901725;
					int num11 = array[2, 1] ^ -1390905292;
					num = (int)((num4 * 1240141574) ^ 0xE92BB168u) ^ num11;
				}
			}
		}
	}

	public bool HasNoAssembly => !HasLoadedAssembly;

	public bool HasSelectedType => !_0024_0021__005E_0029_0024_003C_002B(SelectedTypeName);

	public ObservableCollection<NamespaceGroupViewModel> NamespaceGroups { get; } = new ObservableCollection<NamespaceGroupViewModel>();

	public string SearchText
	{
		get
		{
			return _searchText;
		}
		set
		{
			if (!SetProperty(ref _searchText, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[2168 - 1852 + 47]))
			{
				return;
			}
			while (true)
			{
				int num = 618224348;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-((~(-(num2 * 1460878015) * -1699365419) + (~(-1838170865 ^ 0x1562B3C5) - ~(1180262389 * -2058669403) + -842025889 + (-31550991 ^ 0x70954CE8)) - (1695190179 * -1437054586 - (1652902595 + -803923615) - ~(1327956387 * 496079363) + ~(-364112058 * -1174228839 - ~2104769730))) * -1520649469) ^ -1180924834) - -1474871005)) % 3;
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
					int num7 = 1956932347;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 *= 91277451;
						num7 = 152341683 - num7 - -2015058026;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 766188850;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9 * 306130679;
							num9 *= -1356719205;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					ApplyFilter();
					int[,] array = new int[4, 4];
					array[0, 0] = 1557892714;
					array[0, 1] = 1018833334;
					array[0, 2] = 13161898;
					array[0, 3] = 1950579548;
					array[1, 0] = 1214898213;
					array[1, 1] = -1571014659;
					array[1, 2] = -1211342880;
					array[1, 3] = 985071463;
					array[2, 0] = 445593110;
					array[2, 1] = -2025803015;
					array[2, 2] = -392268223;
					array[2, 3] = -472866452;
					array[3, 0] = 522718348;
					array[3, 1] = 330038414;
					array[3, 2] = -37788034;
					array[3, 3] = -1870677669;
					array[2, 2] = array[2, 0] ^ -479620465;
					array[0, 2] = array[1, 3] ^ 0x3C26C60F;
					array[0, 3] = array[2, 0] ^ -862624009;
					int num11 = array[0, 3] ^ -507971372;
					num = (int)((num4 * 1350696623) ^ 0xE6E4FCF1u) ^ num11;
				}
			}
		}
	}

	public RelayCommand<TypeNodeViewModel?> SelectTypeCommand { get; }

	public RelayCommand SelectAllCommand { get; }

	public string SelectedTypeName
	{
		get
		{
			return _selectedTypeName;
		}
		private set
		{
			if (!SetProperty(ref _selectedTypeName, value, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[2123 - 1848 + 89]))
			{
				return;
			}
			while (true)
			{
				int num = -751578956;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~((-num2 - ~(-942388055 * (~(0x6B51D907 ^ 0x73DDA02) + -(-1064608351 * (1834823272 - -49546626 - ~301631001 - (-2060596445 ^ -1259589526))))) + ~(-(-(0x2EACB428 ^ 0x169E997F))) * 887041213) * 1844097899)))) % 3;
					int num5 = -318496678;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 + (-1340207803 - -865475180)) * 1366272019;
						num5 = (num5 ^ -2108280497) - 57444783;
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
						int num9 = 1628745114;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(num9 - -2061737679 * 1998713061);
							num9 = ~num9 * 379510739;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					@_0040_002B_002F_003C_0028_0023_002A((ObservableObject)this, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x705 ^ 0x668]);
					int[] array = new int[6] { 1074489332, -971914512, 2132923785, -2097648375, -1130471165, -358491449 };
					array[3] ^= -419559208;
					array[4] = array[3] ^ 0x192CAF6;
					int[] array2 = new int[7] { 157598802, -537863704, -1532499348, -341712768, -297644423, 1774407197, 1770823204 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[5] = array3[0][1] ^ -1095143641;
					array2[6] = array2[5] ^ 0x4F953C72;
					array2[4] = array2[0] ^ 0x4FF215BB;
					array2[4] = array2[3] ^ 0x3093ACB1;
					int num11 = array3[1][5] ^ 0x422486B7;
					num = ((int)num4 * -1793697453) ^ 0x13CA024C ^ num11;
				}
			}
		}
	}

	public ObservableCollection<MethodRowViewModel> VisibleMethods { get; } = new ObservableCollection<MethodRowViewModel>();

	public MethodsViewModel(AppViewModel appViewModel, IAssemblyWorkspaceService assemblyWorkspaceService)
	{
		while (true)
		{
			int num = -1941096363;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)((2091739685 - ~(~(~(-(((num2 ^ (((-(((-344168945 ^ -2086774680) + (~1612453753 - 211139644 + (1234186309 + -834579735 + 2038292726))) * 1780100323) + (~(-1984439025 * -2053495623 * -1087249041) - (1343973001 + -1043598631 - (-1874108008 + 1224483025)) * -902053877 + ~(~(--1572925843))) * -108168815) ^ (-(-(-1658140792 - 808160632) ^ (-(0x143A1DC6 ^ -310057025) * -2017757233 - 1338953537 * (--883331542 + (194431347 + 2018593820)))) ^ (1801937223 * (-1788739102 ^ -905306456) - (-((0x169AC3B7 ^ -458031253) * -2120838765) - (~1063687072 + -311552638 - 135371376)) + 2046943841 * ~(-926663144 ^ (--258560456 + -610520843))))) + -(-(-(-1674878636 ^ (-2119078182 ^ -(1401847297 * 1925099188))) ^ -(-1384877429 ^ -(-2085322087 ^ --31793959)))))) - (-1588682213 ^ 0x1A049049) * -745960321 - (-(171074579 - (--349898569 + (-105863139 + -599752522)) + -1249296274) + -2061667837 * ~(~((0xF066EE6 ^ -1585248006) - -1640476782 * -1647976441)) - (802291899 * ((-537859232 - (-397135769 + (-258607766 - -824881134))) ^ -(-1754699292 ^ -1504476593)) + -(-282568574 + ~1391351056 - -(-757324271) - ~(-1524566681 + 595295334))))) * -59726195))))) * -2106759855)) % 9;
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
				int num7 = -29467312;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = (num7 * 466677381) ^ -1305303753;
					num7 = ~(-num7);
				}
				if (num3 != (uint)num7)
				{
					int num9 = -1;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 = -num9;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -2073877186;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 *= -1981071647;
							num11 = ~num11 * -354885901;
						}
						if (num3 != (uint)num11)
						{
							int num13 = 2064446;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = (num13 ^ -1778690779) + -587933695;
								num13 = -(num13 + (1178728944 + -422275555));
							}
							if (num3 != (uint)num13)
							{
								int num15 = -7;
								_ = 0;
								for (int num16 = 0; num16 < 1; num16++)
								{
									num15 = ~num15;
								}
								if (num3 != (uint)num15)
								{
									int num17 = -1757066979;
									_ = 0;
									for (int num18 = 0; num18 < 2; num18++)
									{
										num17 = ~(num17 + -1802823141);
										num17 = (num17 ^ -1097309845) * -1125444243;
									}
									if (num3 != (uint)num17)
									{
										int num19 = -1192834954;
										_ = 0;
										for (int num20 = 0; num20 < 2; num20++)
										{
											num19 = ~(num19 + ~-564592705);
											num19 = -206818827 - num19 * 642095129;
										}
										if (num3 != (uint)num19)
										{
											int num21 = -1111416951;
											_ = 0;
											for (int num22 = 0; num22 < 1; num22++)
											{
												num21 += 1111416956;
											}
											if (num3 == (uint)num21)
											{
											}
											return;
										}
										_003F_0024_003E_002D_0025_003C_0025_0021((ObservableObject)appViewModel, (PropertyChangedEventHandler)OnAppStateChanged);
										int[,] array = new int[4, 3];
										array[0, 0] = 1403139278;
										array[0, 1] = 1373514361;
										array[0, 2] = 555191100;
										array[1, 0] = 1472662360;
										array[1, 1] = -972402926;
										array[1, 2] = -117486500;
										array[2, 0] = -1854317455;
										array[2, 1] = -437707501;
										array[2, 2] = -901753780;
										array[3, 0] = 1668707073;
										array[3, 1] = 935008815;
										array[3, 2] = -1105179711;
										array[3, 0] = array[3, 2] ^ 0x30A08001;
										array[0, 2] = array[0, 1] ^ 0x46FA5C39;
										array[2, 1] = array[1, 2] ^ -845116443;
										array[1, 1] = array[1, 2] ^ 0x5FC63B40;
										int num23 = array[1, 1] ^ 0x46374288;
										num = (int)((num4 * 217086000) ^ 0x3B64FA90) ^ num23;
									}
									else
									{
										SelectAllCommand = new RelayCommand(SelectAll, CanBulkChangeSelection);
										int[] array2 = new int[7];
										array2[0] = -1134993845;
										array2[1] = 923216110;
										array2[2] = 1065517891;
										array2[3] = -2089510740;
										array2[4] = 2110421294;
										array2[5] = -1898111393;
										array2[6] = 1271716638;
										array2[6] = array2[3] ^ 0x1E5B475A;
										array2[3] = array2[1] ^ 0x59EE6355;
										int[] array3 = new int[6];
										array3[0] = 1566089595;
										array3[1] = 1071571345;
										array3[2] = 2119255635;
										array3[3] = -1294692831;
										array3[4] = -231830335;
										array3[5] = -867457515;
										array3[3] = array2[4] ^ 0x75E8D516;
										array3[0] = array3[1] ^ -2145270335;
										array3[4] ^= -873602783;
										int num24 = array3[3] ^ -558120935;
										num = (int)((num4 * 51545590) ^ 0x36015C36) ^ num24;
									}
								}
								else
								{
									SelectTypeCommand = new RelayCommand<TypeNodeViewModel>(SelectType);
									int[] array4 = new int[6];
									array4[0] = -439967853;
									array4[1] = -627384325;
									array4[2] = 2137125306;
									array4[3] = -1640339388;
									array4[4] = 1779637154;
									array4[5] = 161385302;
									array4[4] = array4[1] ^ -866895429;
									array4[5] = array4[3] ^ 0x25CF2BA;
									int[] array5 = new int[6] { -217328920, -1148608597, -1163506089, 182640478, -1945944849, -1336381432 };
									int[][] array6 = new int[2][] { array4, array5 };
									array5[4] = array6[0][0] ^ -742937531;
									array5[5] ^= 165823044;
									array5[1] = array5[0] ^ -1804051021;
									int num25 = array6[1][4] ^ 0x431D4A61;
									num = ((int)num4 * -1390071463) ^ 0x4AB5B2CE ^ num25;
								}
							}
							else
							{
								ClearSelectionCommand = new RelayCommand(ClearSelection, CanBulkChangeSelection);
								int[] array7 = new int[4];
								array7[0] = -402427440;
								array7[1] = -653563671;
								array7[2] = -1204385567;
								array7[3] = -1305984880;
								array7[0] = array7[2] ^ 0x1C50F431;
								array7[1] = array7[2] ^ 0x61BBBDFD;
								int[] array8 = new int[5] { -61639934, -1095666348, -1870154842, -1040063477, 110631134 };
								int[][] array9 = new int[2][] { array7, array8 };
								array8[4] = array9[0][3] ^ -404413979;
								array8[2] = array8[3] ^ -531538859;
								array8[3] = array8[0] ^ 0x26708F81;
								int num26 = array9[1][4] ^ -156888195;
								num = (int)((num4 * 624013031) ^ 0x3F0F12B0) ^ num26;
							}
						}
						else
						{
							ClearSearchCommand = new RelayCommand(ClearSearch);
							int[] array10 = new int[7];
							array10[0] = -663086889;
							array10[1] = 311855914;
							array10[2] = -1455632216;
							array10[3] = 122629323;
							array10[4] = -1403530631;
							array10[5] = 1797852996;
							array10[6] = -647737520;
							array10[2] = array10[4] ^ 0x545B90A0;
							array10[0] = array10[3] ^ 0x7FFFA229;
							int[] array11 = new int[6];
							array11[0] = -377638952;
							array11[1] = -1177269228;
							array11[2] = 1577592342;
							array11[3] = 312691577;
							array11[4] = -1128178441;
							array11[5] = -1934843778;
							array11[4] = array10[3] ^ -1921011492;
							array11[2] = array11[0] ^ 0x34B2881E;
							array11[3] = array11[4] ^ -1582222364;
							array11[2] = array11[1] ^ 0x3FA8DBD6;
							int num27 = array11[4] ^ 0x4C509C25;
							num = (int)((num4 * 877241323) ^ 0xB2AA660Fu) ^ num27;
						}
					}
					else
					{
						_assemblyWorkspaceService = assemblyWorkspaceService;
						int[] array12 = new int[5];
						array12[0] = 1862997213;
						array12[1] = 264520955;
						array12[2] = -1136403748;
						array12[3] = 1168050692;
						array12[4] = 483552016;
						array12[2] = array12[0] ^ -1607776754;
						array12[1] = array12[4] ^ -1797461245;
						int[] array13 = new int[7] { -1054467897, -1837448497, 962715714, 632053946, 169409921, 567126711, 558995891 };
						int[][] array14 = new int[2][] { array12, array13 };
						array13[6] = array14[0][0] ^ -1242818199;
						array13[5] ^= -206312393;
						array13[5] = array13[0] ^ -1020640005;
						int num28 = array14[1][6] ^ 0x60F14987;
						num = (int)((num4 * 2055657297) ^ 0x16CC025B) ^ num28;
					}
				}
				else
				{
					AppViewModel = appViewModel;
					int[] array15 = new int[6];
					array15[0] = -1139264378;
					array15[1] = 412257167;
					array15[2] = 506695539;
					array15[3] = -1220294833;
					array15[4] = 2039250980;
					array15[5] = 1366211063;
					array15[0] = array15[1] ^ 0x757EF229;
					array15[4] = array15[3] ^ -39120832;
					int[] array16 = new int[7] { -1759348122, 1832992911, -1186906278, 1506522341, 85993963, 1800461997, 1408681055 };
					int[][] array17 = new int[2][] { array15, array16 };
					array16[2] = array17[0][2] ^ 0x4AD9FE92;
					array16[4] = array16[3] ^ 0x1569FFEE;
					array16[5] = array16[6] ^ -1019888083;
					array16[0] = array16[1] ^ -1255812410;
					int num29 = array17[1][2] ^ 0x78F412F8;
					num = (int)((num4 * 393597554) ^ 0x6C33481E) ^ num29;
				}
			}
		}
	}

	public void Refresh()
	{
		NamespaceGroups.Clear();
		AssemblyProfile assemblyProfile = default(AssemblyProfile);
		NamespaceItem current = default(NamespaceItem);
		while (true)
		{
			int num = -807303421;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(~(~(~(~num2 - -(((--655028474 + 619791177 + (540098420 - (-1085205481 ^ 0x34349B98)) + 393594589 * (~-853269159 - --881972334) - (-(-(--1636531291)) ^ -466774297)) ^ ((-(~(-2121760853 + 430177382)) - (1707837761 + (1543453485 * 1969662791 - (-1353744759 - 1444553240)))) ^ -1635492211)) + (~(~(-1598043208 * -1154458159)) - 652637033 * -891692854 + (-384737310 + -157581637 + (0x245A9D99 ^ -1104717879))))) - -(-(2132311107 + ~-511085394) - -(-1175464558 ^ -229212281) - (-2109742204 ^ -1846847259)))) * -2137239315))) % 10;
				uint num5 = num3;
				int num6 = -846409818;
				_ = 0;
				for (int num7 = 0; num7 < 1; num7++)
				{
					num6 ^= -846409823;
				}
				if (num5 == (uint)num6)
				{
					break;
				}
				uint num8 = num3;
				int num9 = -6;
				_ = 0;
				for (int num10 = 0; num10 < 1; num10++)
				{
					num9 = -num9;
				}
				if (num8 != (uint)num9)
				{
					uint num11 = num3;
					int num12 = 4;
					_ = 0;
					for (int num13 = 0; num13 < 2; num13++)
					{
						num12 = -(-num12);
						num12 = ~num12 + 1320472707;
					}
					if (num11 != (uint)num12)
					{
						uint num14 = num3;
						int num15 = 1074032687;
						_ = 0;
						for (int num16 = 0; num16 < 2; num16++)
						{
							num15 = (num15 - 101655907 * 1186125149) ^ -1612190265;
							num15 = -(num15 ^ -1180346596);
						}
						if (num14 != (uint)num15)
						{
							uint num17 = num3;
							int num18 = 154403248;
							_ = 0;
							for (int num19 = 0; num19 < 1; num19++)
							{
								num18 += -154403247;
							}
							if (num17 != (uint)num18)
							{
								uint num20 = num3;
								int num21 = 0;
								_ = 0;
								for (int num22 = 0; num22 < 1; num22++)
								{
									num21 = -num21;
								}
								if (num20 != (uint)num21)
								{
									uint num23 = num3;
									int num24 = 669654310;
									_ = 0;
									for (int num25 = 0; num25 < 1; num25++)
									{
										num24 ^= 0x27EA1D2E;
									}
									if (num23 != (uint)num24)
									{
										uint num26 = num3;
										int num27 = -1533246644;
										_ = 0;
										for (int num28 = 0; num28 < 1; num28++)
										{
											num27 -= -1533246649;
										}
										if (num26 != (uint)num27)
										{
											uint num29 = num3;
											int num30 = -143799083;
											_ = 0;
											for (int num31 = 0; num31 < 2; num31++)
											{
												num30 *= -1319993683;
												num30 -= ~111259609;
											}
											if (num29 == (uint)num30)
											{
												return;
											}
											uint num32 = num3;
											int num33 = -7121382;
											_ = 0;
											for (int num34 = 0; num34 < 2; num34++)
											{
												num33 = 748340573 - ~num33;
												num33 = (num33 * 128935995) ^ -1396323032;
											}
											if (num32 != (uint)num33)
											{
											}
											HasLoadedAssembly = true;
											IEnumerator<NamespaceItem> enumerator = @_003F_003C_0025_0021_0024_002B_003D(assemblyProfile).GetEnumerator();
											try
											{
												uint num46;
												int num47;
												do
												{
													int num35;
													int num36;
													if (!_005E_0025_0026_003E_0023_003E_003E_0025((IEnumerator)enumerator))
													{
														num35 = -962193326;
														num36 = num35;
													}
													else
													{
														num35 = 1148019907;
														num36 = num35;
													}
													while (true)
													{
														num2 = num35;
														num3 = (num4 = (uint)(-(~(~(~(~num2 - -(((--655028474 + 619791177 + (540098420 - (-1085205481 ^ 0x34349B98)) + 393594589 * (~-853269159 - --881972334) - (-(-(--1636531291)) ^ -466774297)) ^ ((-(~(-2121760853 + 430177382)) - (1707837761 + (1543453485 * 1969662791 - (-1353744759 - 1444553240)))) ^ -1635492211)) + (~(~(-1598043208 * -1154458159)) - 652637033 * -891692854 + (-384737310 + -157581637 + (0x245A9D99 ^ -1104717879))))) - -(-(2132311107 + ~-511085394) - -(-1175464558 ^ -229212281) - (-2109742204 ^ -1846847259)))) * -2137239315))) % 5;
														uint num37 = num3;
														int num38 = -3;
														_ = 0;
														for (int num39 = 0; num39 < 1; num39++)
														{
															num38 = -num38;
														}
														if (num37 == (uint)num38)
														{
															num35 = 1148019907;
															continue;
														}
														uint num40 = num3;
														int num41 = 4;
														_ = 0;
														for (int num42 = 0; num42 < 2; num42++)
														{
															num41 = ~(num41 - -232160701);
															num41 = 1381136705 - ~num41;
														}
														if (num40 != (uint)num41)
														{
															uint num43 = num3;
															int num44 = 516842978;
															_ = 0;
															for (int num45 = 0; num45 < 1; num45++)
															{
																num44 -= 516842976;
															}
															if (num43 != (uint)num44)
															{
																break;
															}
															NamespaceGroups.Add(new NamespaceGroupViewModel
															{
																Name = _0021_0023_002F_0024_0024_0040__002B(current),
																Types = (from type in _0029_002B_0024_0024__0026_003C_002F(current)
																	select new TypeNodeViewModel
																	{
																		FullName = _003C_003Ec._0028_0025_003D_0028_0025_0040_003F_0024(type),
																		DisplayName = _003C_003Ec._0021_0021_002D_003E_0021_0024_003F_(type),
																		MethodCount = _003C_003Ec._0023_003C_002F_002F_002B_002B_002A_002F(type),
																		IconGlyph = ResolveIcon(type)
																	}).ToList()
															});
															num35 = 445474660;
														}
														else
														{
															current = enumerator.Current;
															num35 = 529376651;
														}
													}
													num46 = num3;
													num47 = 1480949960;
													_ = 0;
													for (int num48 = 0; num48 < 2; num48++)
													{
														num47 = ~(num47 * -1559151175);
														num47 = ~(~num47);
													}
												}
												while (num46 == (uint)num47);
												uint num49 = num3;
												int num50 = -1;
												_ = 0;
												for (int num51 = 0; num51 < 1; num51++)
												{
													num50 = -num50;
												}
												if (num49 == (uint)num50)
												{
												}
											}
											finally
											{
												if (enumerator != null)
												{
													while (true)
													{
														int num52 = 1002939448;
														while (true)
														{
															num2 = num52;
															num3 = (num4 = (uint)(-(~(~(~(~num2 - -(((--655028474 + 619791177 + (540098420 - (-1085205481 ^ 0x34349B98)) + 393594589 * (~-853269159 - --881972334) - (-(-(--1636531291)) ^ -466774297)) ^ ((-(~(-2121760853 + 430177382)) - (1707837761 + (1543453485 * 1969662791 - (-1353744759 - 1444553240)))) ^ -1635492211)) + (~(~(-1598043208 * -1154458159)) - 652637033 * -891692854 + (-384737310 + -157581637 + (0x245A9D99 ^ -1104717879))))) - -(-(2132311107 + ~-511085394) - -(-1175464558 ^ -229212281) - (-2109742204 ^ -1846847259)))) * -2137239315))) % 3;
															uint num53 = num3;
															int num54 = -1461962106;
															_ = 0;
															for (int num55 = 0; num55 < 2; num55++)
															{
																num54 = -num54 - -1360937426;
																num54 = ~(num54 * 1458600715);
															}
															if (num53 == (uint)num54)
															{
																break;
															}
															uint num56 = num3;
															int num57 = 832432433;
															_ = 0;
															for (int num58 = 0; num58 < 2; num58++)
															{
																num57 = (num57 - (1029109512 + 1735267327)) * 1829880833;
																num57 = -1122623617 - num57 * -2101957099;
															}
															if (num56 != (uint)num57)
															{
																uint num59 = num3;
																int num60 = 1554418816;
																_ = 0;
																for (int num61 = 0; num61 < 1; num61++)
																{
																	num60 = 1554418816 - num60;
																}
																if (num59 == (uint)num60)
																{
																}
																goto end_IL_18e5;
															}
															_002A_005E_003F_005E_003D_002F_0026_003F((IDisposable)enumerator);
															int[] array = new int[6];
															array[0] = 1278284002;
															array[1] = -881412062;
															array[2] = -1127151891;
															array[3] = 832878566;
															array[4] = -525147093;
															array[5] = -966841968;
															array[3] = array[5] ^ -1903914055;
															array[4] = array[3] ^ -686138766;
															int[] array2 = new int[6];
															array2[0] = -2073806142;
															array2[1] = 476244486;
															array2[2] = 1096249559;
															array2[3] = 666464448;
															array2[4] = 313456070;
															array2[5] = -416551168;
															array2[0] = array[2] ^ -2104146343;
															array2[1] = array2[2] ^ 0xD57A052;
															array2[2] = array2[1] ^ 0x73ADBCC4;
															int num62 = array2[0] ^ -1070374782;
															num52 = ((int)num4 * -946494587) ^ -1340969055 ^ num62;
														}
														continue;
														end_IL_18e5:
														break;
													}
												}
											}
											TypeNodeViewModel typeNodeViewModel = NamespaceGroups.SelectMany((NamespaceGroupViewModel item) => item.Types).FirstOrDefault();
											while (true)
											{
												int num63 = -1515617304;
												while (true)
												{
													num2 = num63;
													num3 = (num4 = (uint)(-(~(~(~(~num2 - -(((--655028474 + 619791177 + (540098420 - (-1085205481 ^ 0x34349B98)) + 393594589 * (~-853269159 - --881972334) - (-(-(--1636531291)) ^ -466774297)) ^ ((-(~(-2121760853 + 430177382)) - (1707837761 + (1543453485 * 1969662791 - (-1353744759 - 1444553240)))) ^ -1635492211)) + (~(~(-1598043208 * -1154458159)) - 652637033 * -891692854 + (-384737310 + -157581637 + (0x245A9D99 ^ -1104717879))))) - -(-(2132311107 + ~-511085394) - -(-1175464558 ^ -229212281) - (-2109742204 ^ -1846847259)))) * -2137239315))) % 7;
													uint num64 = num3;
													int num65 = -1861215904;
													_ = 0;
													for (int num66 = 0; num66 < 2; num66++)
													{
														num65 = ~(num65 * 2100833953);
														num65 = -(-num65);
													}
													if (num64 == (uint)num65)
													{
														break;
													}
													uint num67 = num3;
													int num68 = -1421507189;
													_ = 0;
													for (int num69 = 0; num69 < 2; num69++)
													{
														num68 = (num68 - 1466208488 * 487484093) * -1130612969;
														num68 = ~num68 - -1009473373;
													}
													if (num67 != (uint)num68)
													{
														uint num70 = num3;
														int num71 = -101065672;
														_ = 0;
														for (int num72 = 0; num72 < 2; num72++)
														{
															num71 = 558820189 - (num71 - (-1410606283 ^ 0x1B1FD322));
															num71 = (num71 - (-1388830564 - 438301343)) * 757029277;
														}
														if (num70 != (uint)num71)
														{
															uint num73 = num3;
															int num74 = 777648785;
															_ = 0;
															for (int num75 = 0; num75 < 1; num75++)
															{
																num74 ^= 0x2E59FA90;
															}
															if (num73 == (uint)num74)
															{
																return;
															}
															uint num76 = num3;
															int num77 = -264513087;
															_ = 0;
															for (int num78 = 0; num78 < 1; num78++)
															{
																num77 ^= -264513085;
															}
															if (num76 != (uint)num77)
															{
																uint num79 = num3;
																int num80 = -1373117412;
																_ = 0;
																for (int num81 = 0; num81 < 1; num81++)
																{
																	num80 ^= -1373117415;
																}
																if (num79 != (uint)num80)
																{
																	uint num82 = num3;
																	int num83 = -650067823;
																	_ = 0;
																	for (int num84 = 0; num84 < 1; num84++)
																	{
																		num83 += 650067829;
																	}
																	if (num82 == (uint)num83)
																	{
																	}
																	return;
																}
																_0029_003F_005E_002A_0040__002B_0025(SelectAllCommand);
																int[] array3 = new int[7];
																array3[0] = -395634020;
																array3[1] = -1995166974;
																array3[2] = 1125828822;
																array3[3] = -996306693;
																array3[4] = 1234770029;
																array3[5] = 469905553;
																array3[6] = -1576191043;
																array3[4] = array3[0] ^ -1674498358;
																array3[1] = array3[2] ^ 0x58F008B0;
																int[] array4 = new int[6];
																array4[0] = 17698586;
																array4[1] = -2102520785;
																array4[2] = 2082595119;
																array4[3] = -1417065758;
																array4[4] = 1090482695;
																array4[5] = -1628784166;
																array4[3] = array3[0] ^ -723807062;
																array4[4] ^= 715210232;
																array4[4] = array4[0] ^ 0x410CD78C;
																int num85 = array4[3] ^ 0x2B111F59;
																num63 = (int)((num4 * 1019134543) ^ 0x5DDB19D4) ^ num85;
															}
															else
															{
																_0029_003F_005E_002A_0040__002B_0025(ClearSelectionCommand);
																num63 = -1547347043;
															}
														}
														else
														{
															SelectType(typeNodeViewModel);
															int[] array5 = new int[4];
															array5[0] = 1491808911;
															array5[1] = 746191375;
															array5[2] = 641988099;
															array5[3] = -1799140912;
															array5[3] = array5[2] ^ 0x4344B12A;
															array5[1] ^= -655527937;
															int[] array6 = new int[5];
															array6[0] = -91723408;
															array6[1] = 801948622;
															array6[2] = 566515128;
															array6[3] = -749030708;
															array6[4] = -1797486015;
															array6[1] = array5[2] ^ -406102421;
															array6[2] = array6[4] ^ -1915687251;
															array6[4] ^= 831560809;
															array6[4] ^= 405739296;
															int num86 = array6[1] ^ -418296067;
															num63 = ((int)num4 * -1772241394) ^ 0x52215858 ^ num86;
														}
													}
													else
													{
														int[] array7 = new int[7] { -1366374057, 1552090839, 894508488, -146865340, 1478056785, -688212584, -1223028676 };
														array7[4] ^= -1298473710;
														array7[3] = array7[6] ^ 0x31D7BE52;
														array7[6] = array7[0] ^ -526522436;
														int[] array8 = new int[5] { -1546864521, -100241995, 390979830, 226585755, 1409810965 };
														int[][] array9 = new int[2][] { array7, array8 };
														array8[4] = array9[0][0] ^ 0x7709416C;
														array8[0] = array8[1] ^ 0xE9515E3;
														array8[2] ^= 644630836;
														array8[2] = array8[3] ^ -1334651792;
														int num87 = array9[1][4] ^ 0x154822BB;
														int[,] array10 = new int[4, 4];
														array10[0, 0] = 1148006415;
														array10[0, 1] = 956078940;
														array10[0, 2] = 1177534523;
														array10[0, 3] = 642457673;
														array10[1, 0] = 1794887126;
														array10[1, 1] = 1092089638;
														array10[1, 2] = -146190177;
														array10[1, 3] = 1089815921;
														array10[2, 0] = 1110335550;
														array10[2, 1] = 114843251;
														array10[2, 2] = -389379619;
														array10[2, 3] = 1515679162;
														array10[3, 0] = -2106305184;
														array10[3, 1] = 1438988762;
														array10[3, 2] = 116994134;
														array10[3, 3] = 1416672583;
														array10[2, 1] = array10[0, 0] ^ 0x58A427AF;
														array10[2, 0] = array10[1, 0] ^ -1734205929;
														array10[2, 0] = array10[1, 1] ^ 0x2290D395;
														array10[1, 1] = array10[0, 2] ^ 0x204119A0;
														int num88 = array10[1, 1] ^ -1137112210;
														int num89 = ((int)num4 * -713675684) ^ -1410367252;
														num87 ^= num89;
														num88 ^= num89;
														int num90;
														int num91;
														if (typeNodeViewModel != null)
														{
															num90 = num88;
															num91 = num90;
														}
														else
														{
															num90 = num87;
															num91 = num90;
														}
														num63 = num90 ^ num89;
													}
												}
											}
										}
										AppViewModel.UpdateMethodSelectionCount(0);
										int[] array11 = new int[5];
										array11[0] = 809665381;
										array11[1] = 985063726;
										array11[2] = -855554289;
										array11[3] = -190865966;
										array11[4] = -72094125;
										array11[2] = array11[4] ^ -383515350;
										array11[2] = array11[4] ^ -2119746470;
										int[] array12 = new int[7] { 1838929952, -2111260435, 1040029244, -713175657, -1854048617, -98948057, -1649967868 };
										int[][] array13 = new int[2][] { array11, array12 };
										array12[0] = array13[0][1] ^ 0x41E09DE1;
										array12[6] = array12[3] ^ -418344420;
										array12[3] = array12[1] ^ 0x57D87579;
										array12[3] = array12[0] ^ -1986253396;
										int num92 = array13[1][0] ^ 0x844563;
										num = ((int)num4 * -1132449128) ^ 0xB1331C8 ^ num92;
									}
									else
									{
										SelectedTypeName = string.Empty;
										int[,] array14 = new int[3, 4];
										array14[0, 0] = 903741362;
										array14[0, 1] = 1088229512;
										array14[0, 2] = 911348145;
										array14[0, 3] = 207934150;
										array14[1, 0] = 658226394;
										array14[1, 1] = -689032522;
										array14[1, 2] = -1327069909;
										array14[1, 3] = 1260062286;
										array14[2, 0] = 1661781646;
										array14[2, 1] = 1250353645;
										array14[2, 2] = -969018155;
										array14[2, 3] = -1540724879;
										array14[0, 2] = array14[2, 2] ^ 0x27FC62F8;
										array14[1, 3] = array14[1, 2] ^ 0xC7C2673;
										array14[2, 3] = array14[2, 2] ^ -971548721;
										array14[2, 1] = array14[1, 0] ^ -896791513;
										int num93 = array14[2, 1] ^ -1439490889;
										num = ((int)num4 * -580523862) ^ -1205730532 ^ num93;
									}
								}
								else
								{
									HasLoadedAssembly = false;
									int[,] array15 = new int[4, 4];
									array15[0, 0] = 2026306122;
									array15[0, 1] = -213935934;
									array15[0, 2] = -867403010;
									array15[0, 3] = -903475056;
									array15[1, 0] = 437742378;
									array15[1, 1] = 699328654;
									array15[1, 2] = 886957173;
									array15[1, 3] = -202091435;
									array15[2, 0] = 342480527;
									array15[2, 1] = 979082478;
									array15[2, 2] = 1398114480;
									array15[2, 3] = -1013722846;
									array15[3, 0] = 1737218898;
									array15[3, 1] = 1899480162;
									array15[3, 2] = -57270490;
									array15[3, 3] = -726565536;
									array15[1, 2] = array15[2, 3] ^ 0x49FD7DEA;
									array15[3, 3] = array15[3, 1] ^ -69174074;
									array15[3, 2] = array15[3, 3] ^ 0x6EFDF938;
									array15[2, 3] = array15[1, 0] ^ 0x66C9D932;
									int num94 = array15[2, 3] ^ 0x51D7ADD3;
									num = (int)((num4 * 1282971676) ^ 0x4F1DCD50) ^ num94;
								}
							}
							else
							{
								AssemblyProfile assemblyProfile2 = assemblyProfile;
								int[] array16 = new int[5];
								array16[0] = 1985754786;
								array16[1] = -501129865;
								array16[2] = 767653434;
								array16[3] = -669551196;
								array16[4] = 428655690;
								array16[4] = array16[3] ^ 0x40F403B2;
								array16[0] = array16[4] ^ 0x1F22157E;
								int[] array17 = new int[5] { -1133969501, -12271598, 1081423956, 1964344663, -182427310 };
								int[][] array18 = new int[2][] { array16, array17 };
								array17[0] = array18[0][3] ^ 0x1DA7D1ED;
								array17[3] = array17[2] ^ -1221176162;
								array17[4] = array17[0] ^ 0x27102CE;
								int num95 = array18[1][0] ^ 0x1B605D48;
								int[] array19 = new int[4];
								array19[0] = 440591862;
								array19[1] = 1760387115;
								array19[2] = 1237717927;
								array19[3] = 19512457;
								array19[2] = array19[3] ^ -1589167347;
								array19[2] = array19[1] ^ -1892199667;
								array19[0] = array19[3] ^ -674673577;
								int[] array20 = new int[6] { 1538940249, 405369250, 1750734887, -2073070869, 930154719, -466481116 };
								int[][] array21 = new int[2][] { array19, array20 };
								array20[3] = array21[0][1] ^ -2130236207;
								array20[4] = array20[2] ^ 0x3B6B9C6B;
								array20[4] = array20[2] ^ 0x25831929;
								array20[0] = array20[4] ^ -2112920639;
								int num96 = array21[1][3] ^ 0x739E0907;
								int num97 = ((int)num4 * -1456525482) ^ 0x39C13A4A;
								num95 ^= num97;
								num96 ^= num97;
								int num98;
								int num99;
								if (assemblyProfile2 == null)
								{
									num98 = num96;
									num99 = num98;
								}
								else
								{
									num98 = num95;
									num99 = num98;
								}
								num = num98 ^ num97;
							}
						}
						else
						{
							assemblyProfile = _0026_0029_002D_0028_0025_003F_003D_003D(_assemblyWorkspaceService);
							int[] array22 = new int[5] { 1594492384, -839142899, -997308106, -1590602694, -1516384311 };
							array22[2] ^= -1609305618;
							array22[0] ^= 259758443;
							int[] array23 = new int[6];
							array23[0] = -1907145245;
							array23[1] = 1033064873;
							array23[2] = 216785958;
							array23[3] = 1092681578;
							array23[4] = -1972474975;
							array23[5] = -1230598746;
							array23[3] = array22[1] ^ 0xE4DAE8C;
							array23[4] = array23[1] ^ 0x6CFA4FC5;
							array23[2] = array23[0] ^ 0x15701EE4;
							int num100 = array23[3] ^ 0x6FA448EF;
							num = (int)((num4 * 1561069977) ^ 0xFB161D1Bu) ^ num100;
						}
					}
					else
					{
						_allMethods = new List<MethodRowViewModel>();
						int[] array24 = new int[4];
						array24[0] = -203770525;
						array24[1] = -1147224297;
						array24[2] = -1859085157;
						array24[3] = 1116542965;
						array24[0] = array24[1] ^ 0x13F124E8;
						array24[0] = array24[3] ^ 0x6C04F3E9;
						array24[2] = array24[0] ^ 0x542A7C5E;
						int[] array25 = new int[6];
						array25[0] = -1876949781;
						array25[1] = -1248709500;
						array25[2] = -1923260805;
						array25[3] = -218612785;
						array25[4] = 841735638;
						array25[5] = -817640061;
						array25[0] = array24[3] ^ -749875911;
						array25[5] ^= 160175002;
						array25[3] = array25[2] ^ 0x3F4D14D1;
						int num101 = array25[0] ^ 0x4AB6F636;
						num = (int)((num4 * 661296493) ^ 0x12186A5C) ^ num101;
					}
				}
				else
				{
					VisibleMethods.Clear();
					int[,] array26 = new int[3, 3];
					array26[0, 0] = -751528987;
					array26[0, 1] = -2073343684;
					array26[0, 2] = 1768819733;
					array26[1, 0] = -1579141912;
					array26[1, 1] = 310211234;
					array26[1, 2] = 315045741;
					array26[2, 0] = -357092624;
					array26[2, 1] = -2058600350;
					array26[2, 2] = -1614575680;
					array26[0, 1] = array26[1, 0] ^ 0x240F0E1C;
					array26[0, 0] ^= -1962048809;
					array26[0, 1] = array26[2, 2] ^ 0x4E18E01F;
					int num102 = array26[0, 1] ^ 0x7623D862;
					num = (int)((num4 * 187680160) ^ 0x2CCF84C0) ^ num102;
				}
			}
		}
	}

	private void ApplyFilter()
	{
		VisibleMethods.Clear();
		IEnumerable<MethodRowViewModel> enumerable = default(IEnumerable<MethodRowViewModel>);
		MethodRowViewModel current = default(MethodRowViewModel);
		while (true)
		{
			int num = 1640162796;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-((-759598213 ^ 0xF863DAE) - (~(-367416670 - ~((num2 - (--866706282 - (-1048676873 + 323299892) + (~(723688937 * (--256761581 - -(-1988610615 + -1637231665) * -1598450335)) ^ (-426800885 + ((~1829647945 - -1963421319) ^ -588459883) + -(1482130703 * (1712200539 + 1233334324 - -1245078209 * -81419167)) + ~(-430717190 ^ (~585622132 + 900136024 * 1875138781 - -538024375 * 1115924883)) + (0x4B3F8103 ^ -((0x2618F49E ^ 0x3C319D5A) * -877738029)))))) * 398950183 * 1725761639 - (1570289891 * (~((-15603635 ^ -1467405698) + (-2042426390 + -124529122)) - (-1438986283 ^ 0x536B254)) - ~(~(-2045678235 - ((-1296695808 ^ -929878538) + --1819226658)))))) ^ 0x53DF1674)))) % 5;
				uint num5 = num3;
				int num6 = -2128170260;
				_ = 0;
				for (int num7 = 0; num7 < 1; num7++)
				{
					num6 *= 213104755;
				}
				if (num5 == (uint)num6)
				{
					break;
				}
				uint num8 = num3;
				int num9 = 861051297;
				_ = 0;
				for (int num10 = 0; num10 < 2; num10++)
				{
					num9 = (num9 - (1635923222 + -747215610)) * 910513519;
					num9 = (661916977 - 2138073269 - num9) * 931958401;
				}
				if (num8 != (uint)num9)
				{
					uint num11 = num3;
					int num12 = 838104204;
					_ = 0;
					for (int num13 = 0; num13 < 2; num13++)
					{
						num12 = ~num12;
						num12 = -(num12 * 631520685);
					}
					if (num11 != (uint)num12)
					{
						uint num14 = num3;
						int num15 = -2;
						_ = 0;
						for (int num16 = 0; num16 < 2; num16++)
						{
							num15 = ~(num15 ^ -323222328);
							num15 = -(num15 ^ 0x1C5DF158);
						}
						if (num14 != (uint)num15)
						{
							uint num17 = num3;
							int num18 = -912681867;
							_ = 0;
							for (int num19 = 0; num19 < 1; num19++)
							{
								num18 *= 1194972055;
							}
							if (num17 != (uint)num18)
							{
							}
							IEnumerator<MethodRowViewModel> enumerator = enumerable.GetEnumerator();
							try
							{
								uint num32;
								int num33;
								do
								{
									int num20;
									int num21;
									if (!_005E_0025_0026_003E_0023_003E_003E_0025((IEnumerator)enumerator))
									{
										num20 = 674253241;
										num21 = num20;
									}
									else
									{
										num20 = 1655140651;
										num21 = num20;
									}
									while (true)
									{
										num2 = num20;
										num3 = (num4 = (uint)(-((-759598213 ^ 0xF863DAE) - (~(-367416670 - ~((num2 - (--866706282 - (-1048676873 + 323299892) + (~(723688937 * (--256761581 - -(-1988610615 + -1637231665) * -1598450335)) ^ (-426800885 + ((~1829647945 - -1963421319) ^ -588459883) + -(1482130703 * (1712200539 + 1233334324 - -1245078209 * -81419167)) + ~(-430717190 ^ (~585622132 + 900136024 * 1875138781 - -538024375 * 1115924883)) + (0x4B3F8103 ^ -((0x2618F49E ^ 0x3C319D5A) * -877738029)))))) * 398950183 * 1725761639 - (1570289891 * (~((-15603635 ^ -1467405698) + (-2042426390 + -124529122)) - (-1438986283 ^ 0x536B254)) - ~(~(-2045678235 - ((-1296695808 ^ -929878538) + --1819226658)))))) ^ 0x53DF1674)))) % 5;
										uint num22 = num3;
										int num23 = -76224769;
										_ = 0;
										for (int num24 = 0; num24 < 2; num24++)
										{
											num23 = (num23 - (1573701288 - 311327471)) * 1085077999;
											num23 = ~num23 - -1540272716;
										}
										if (num22 == (uint)num23)
										{
											num20 = 1655140651;
											continue;
										}
										uint num25 = num3;
										int num26 = -1447560651;
										_ = 0;
										for (int num27 = 0; num27 < 2; num27++)
										{
											num26 = num26 * 499996205 - -546275305;
											num26 = (num26 ^ --1415456273) - 1619801781;
										}
										if (num25 != (uint)num26)
										{
											uint num28 = num3;
											int num29 = -4;
											_ = 0;
											for (int num30 = 0; num30 < 1; num30++)
											{
												num29 = -num29;
											}
											if (num28 != (uint)num29)
											{
												break;
											}
											VisibleMethods.Add(current);
											int[] array = new int[7];
											array[0] = -364356528;
											array[1] = -2062233754;
											array[2] = 140072824;
											array[3] = -2035502962;
											array[4] = 1287596716;
											array[5] = 1466991708;
											array[6] = -831559763;
											array[5] = array[6] ^ 0x63B93CD3;
											array[1] = array[5] ^ -1835484499;
											array[2] = array[5] ^ -410150744;
											int[] array2 = new int[7];
											array2[0] = -1572062624;
											array2[1] = 425585609;
											array2[2] = 747224811;
											array2[3] = -2073605471;
											array2[4] = 478897368;
											array2[5] = -749337332;
											array2[6] = -210685026;
											array2[3] = array[0] ^ -970386256;
											array2[4] = array2[1] ^ -744292418;
											array2[5] = array2[4] ^ -1530899005;
											int num31 = array2[3] ^ -1379918783;
											num20 = (int)((num4 * 799278145) ^ 0x622C481) ^ num31;
										}
										else
										{
											current = enumerator.Current;
											num20 = -1485346374;
										}
									}
									num32 = num3;
									num33 = 781283304;
									_ = 0;
									for (int num34 = 0; num34 < 2; num34++)
									{
										num33 = (num33 * -1049905161) ^ -1186092232;
										num33 = ~(-1619180158 - num33);
									}
								}
								while (num32 == (uint)num33);
								uint num35 = num3;
								int num36 = 2;
								_ = 0;
								for (int num37 = 0; num37 < 2; num37++)
								{
									num36 = num36 - ~1630177625 - -2144755450;
									num36 = ~num36 + -1993140147;
								}
								if (num35 == (uint)num36)
								{
								}
								return;
							}
							finally
							{
								if (enumerator != null)
								{
									while (true)
									{
										int num38 = -342836060;
										while (true)
										{
											num2 = num38;
											num3 = (num4 = (uint)(-((-759598213 ^ 0xF863DAE) - (~(-367416670 - ~((num2 - (--866706282 - (-1048676873 + 323299892) + (~(723688937 * (--256761581 - -(-1988610615 + -1637231665) * -1598450335)) ^ (-426800885 + ((~1829647945 - -1963421319) ^ -588459883) + -(1482130703 * (1712200539 + 1233334324 - -1245078209 * -81419167)) + ~(-430717190 ^ (~585622132 + 900136024 * 1875138781 - -538024375 * 1115924883)) + (0x4B3F8103 ^ -((0x2618F49E ^ 0x3C319D5A) * -877738029)))))) * 398950183 * 1725761639 - (1570289891 * (~((-15603635 ^ -1467405698) + (-2042426390 + -124529122)) - (-1438986283 ^ 0x536B254)) - ~(~(-2045678235 - ((-1296695808 ^ -929878538) + --1819226658)))))) ^ 0x53DF1674)))) % 3;
											uint num39 = num3;
											int num40 = -3;
											_ = 0;
											for (int num41 = 0; num41 < 1; num41++)
											{
												num40 = ~num40;
											}
											if (num39 == (uint)num40)
											{
												break;
											}
											uint num42 = num3;
											int num43 = -532169247;
											_ = 0;
											for (int num44 = 0; num44 < 2; num44++)
											{
												num43 = ~num43 ^ 0x4F9B8CE5;
												num43 = ~num43 + 1289104784;
											}
											if (num42 != (uint)num43)
											{
												uint num45 = num3;
												int num46 = 0;
												_ = 0;
												for (int num47 = 0; num47 < 1; num47++)
												{
													num46 *= 2073726741;
												}
												if (num45 == (uint)num46)
												{
												}
												goto end_IL_11a5;
											}
											_002A_005E_003F_005E_003D_002F_0026_003F((IDisposable)enumerator);
											int[] array3 = new int[5];
											array3[0] = -595986682;
											array3[1] = 761262437;
											array3[2] = 1883448567;
											array3[3] = 66917488;
											array3[4] = 2046706028;
											array3[1] = array3[3] ^ -575004336;
											array3[2] ^= 222889527;
											array3[3] = array3[2] ^ 0x239045CD;
											int[] array4 = new int[6] { -614195445, 1833652781, 423208884, -1101624603, -833870601, 1837583297 };
											int[][] array5 = new int[2][] { array3, array4 };
											array4[0] = array5[0][4] ^ -948533413;
											array4[5] ^= -866842882;
											array4[1] ^= 1139785359;
											int num48 = array5[1][0] ^ -390352735;
											num38 = (int)((num4 * 223284385) ^ 0x44FAB777) ^ num48;
										}
										continue;
										end_IL_11a5:
										break;
									}
								}
							}
						}
						enumerable = enumerable.Where(delegate(MethodRowViewModel method)
						{
							if (!_0023_002A_0029_0026_0024_0028_0026_003D(method.Name, SearchText, StringComparison.OrdinalIgnoreCase))
							{
								uint num58;
								int num60;
								do
								{
									int num57 = 1918770990;
									uint num59;
									num58 = (num59 = (uint)((0x5B58DC05 ^ -2112388379) - ~(~(~(-942361788)) - (num57 * -41519811 - (-((~(--1453882557) + 2130370254) * 231701347 + -(--943435795 + (1283197573 + -438781261) + -(~1383851637))) - --142569174 + (-(392636347 - (1301453109 * ~(-214579250 ^ -1930140820) + 1599416478)) - 1340309507))) * -159594911 * -926865077))) % 3;
									num60 = 549880844;
									_ = 0;
									for (int num61 = 0; num61 < 1; num61++)
									{
										num60 ^= 0x20C6840C;
									}
								}
								while (num58 == (uint)num60);
								int num62 = 2013454230;
								_ = 0;
								for (int num63 = 0; num63 < 1; num63++)
								{
									num62 *= -1452032541;
								}
								if (num58 == (uint)num62)
								{
									return _0023_002A_0029_0026_0024_0028_0026_003D(method.Signature, SearchText, StringComparison.OrdinalIgnoreCase);
								}
								int num64 = -300389949;
								_ = 0;
								for (int num65 = 0; num65 < 2; num65++)
								{
									num64 = ~(num64 ^ 0x58CE45C8);
									num64 = num64 * -1665002225 * 577183245;
								}
								if (num58 == (uint)num64)
								{
								}
							}
							return true;
						});
						int[] array6 = new int[5];
						array6[0] = 54028501;
						array6[1] = 1712160983;
						array6[2] = 432812976;
						array6[3] = -649334973;
						array6[4] = -299667995;
						array6[4] = array6[2] ^ 0x3508FF76;
						array6[1] = array6[2] ^ 0xBE135D5;
						int[] array7 = new int[6] { -620489113, -361448357, -1534166332, 668145920, 1591056969, 2145387305 };
						int[][] array8 = new int[2][] { array6, array7 };
						array7[0] = array8[0][2] ^ 0xD215A46;
						array7[4] = array7[2] ^ -1532174766;
						array7[4] = array7[2] ^ -55801675;
						int num49 = array8[1][0] ^ 0x532A18E8;
						num = (int)((num4 * 1688150525) ^ 0xB53D0CAEu) ^ num49;
					}
					else
					{
						bool num50 = _0024_0021__005E_0029_0024_003C_002B(SearchText);
						int[,] array9 = new int[3, 3];
						array9[0, 0] = -815138285;
						array9[0, 1] = 1913819905;
						array9[0, 2] = 387774368;
						array9[1, 0] = 1179025922;
						array9[1, 1] = 830915913;
						array9[1, 2] = 400294912;
						array9[2, 0] = 262475798;
						array9[2, 1] = -243363395;
						array9[2, 2] = -75290818;
						array9[1, 1] = array9[2, 1] ^ 0x146CB4FC;
						array9[2, 0] = array9[2, 2] ^ -1111122532;
						array9[2, 2] = array9[0, 1] ^ -1982675423;
						array9[0, 0] = array9[1, 2] ^ 0x33602330;
						int num51 = array9[0, 0] ^ 0x637B562E;
						int[] array10 = new int[7];
						array10[0] = 1694210490;
						array10[1] = -1085551335;
						array10[2] = 1642489645;
						array10[3] = -1516389393;
						array10[4] = -153473948;
						array10[5] = -717761410;
						array10[6] = -1532208325;
						array10[2] = array10[1] ^ -2144224674;
						array10[4] = array10[1] ^ 0x54C767B8;
						array10[6] ^= -2090063638;
						int[] array11 = new int[4] { 1850201319, -1047657659, 27264902, -1536492154 };
						int[][] array12 = new int[2][] { array10, array11 };
						array11[1] = array12[0][1] ^ -1312299807;
						array11[0] = array11[1] ^ -1140602589;
						array11[0] = array11[1] ^ 0x78D44CB6;
						int num52 = array12[1][1] ^ 0xB11BFE5;
						int num53 = (int)(num4 * 969563822) ^ -296262090;
						num51 ^= num53;
						num52 ^= num53;
						int num54;
						int num55;
						if (!num50)
						{
							num54 = num52;
							num55 = num54;
						}
						else
						{
							num54 = num51;
							num55 = num54;
						}
						num = num54 ^ num53;
					}
				}
				else
				{
					enumerable = _allMethods;
					int[,] array13 = new int[4, 4];
					array13[0, 0] = -1343903487;
					array13[0, 1] = 1120458936;
					array13[0, 2] = -1804586946;
					array13[0, 3] = 806669744;
					array13[1, 0] = -1311038537;
					array13[1, 1] = -696100562;
					array13[1, 2] = 1366073288;
					array13[1, 3] = -1253677775;
					array13[2, 0] = -763565223;
					array13[2, 1] = -55147523;
					array13[2, 2] = -1098030937;
					array13[2, 3] = -919169166;
					array13[3, 0] = 581658529;
					array13[3, 1] = -615185931;
					array13[3, 2] = -1480285409;
					array13[3, 3] = 885023141;
					array13[2, 1] = array13[1, 1] ^ -653090565;
					array13[2, 3] = array13[2, 2] ^ 0x21B28350;
					array13[1, 0] = array13[0, 0] ^ -183284126;
					array13[2, 1] = array13[0, 2] ^ -708839823;
					int num56 = array13[2, 1] ^ -1579955879;
					num = ((int)num4 * -60268357) ^ -753158603 ^ num56;
				}
			}
		}
	}

	private void ClearSearch()
	{
		SearchText = string.Empty;
	}

	private void ClearSelection()
	{
		using (List<MethodRowViewModel>.Enumerator enumerator = _allMethods.GetEnumerator())
		{
			uint num4;
			uint num12;
			int num13;
			do
			{
				int num;
				int num2;
				if (!enumerator.MoveNext())
				{
					num = 1964229108;
					num2 = num;
				}
				else
				{
					num = -1217190571;
					num2 = num;
				}
				while (true)
				{
					int num3 = num;
					uint num5;
					num4 = (num5 = (uint)(~(~(-1717060533 + ((-1536463284 ^ 0x7C32E5A1) * -853159755 - (-1233607278 - (-152840854 + -40691792))) - (0x6D4D45D ^ ((-670263893 ^ -1121755912) - (0x5A33FA28 ^ --1798858794)))) - (1681242640 - (1929588726 - -1105554375)) - -(num3 * 1494105905)))) % 4;
					uint num6 = num4;
					int num7 = -456045176;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= -456045176;
					}
					if (num6 == (uint)num7)
					{
						num = -1217190571;
						continue;
					}
					uint num9 = num4;
					int num10 = 2;
					_ = 0;
					for (int num11 = 0; num11 < 2; num11++)
					{
						num10 = -(-num10);
						num10 = ~(num10 ^ -1675971533);
					}
					if (num9 != (uint)num10)
					{
						break;
					}
					enumerator.Current.IsSelected = false;
					num = -790104958;
				}
				num12 = num4;
				num13 = 838553631;
				_ = 0;
				for (int num14 = 0; num14 < 2; num14++)
				{
					num13 = -1059698414 - (num13 + (-1518931267 ^ -1469874142));
					num13 = (num13 + 1565845967 * -284967838) * -208579629;
				}
			}
			while (num12 == (uint)num13);
			uint num15 = num4;
			int num16 = -1262767309;
			_ = 0;
			for (int num17 = 0; num17 < 2; num17++)
			{
				num16 = num16 - --1595047255 + -2068536384;
				num16 = ~(-num16);
			}
			if (num15 == (uint)num16)
			{
			}
		}
		ApplyFilter();
		while (true)
		{
			int num18 = 958823454;
			while (true)
			{
				int num3 = num18;
				uint num5;
				uint num4 = (num5 = (uint)(~(~(-1717060533 + ((-1536463284 ^ 0x7C32E5A1) * -853159755 - (-1233607278 - (-152840854 + -40691792))) - (0x6D4D45D ^ ((-670263893 ^ -1121755912) - (0x5A33FA28 ^ --1798858794)))) - (1681242640 - (1929588726 - -1105554375)) - -(num3 * 1494105905)))) % 3;
				uint num19 = num4;
				int num20 = 85928924;
				_ = 0;
				for (int num21 = 0; num21 < 2; num21++)
				{
					num20 = ~(num20 - (-1695770817 + 1404110978));
					num20 = (num20 * 1318839385) ^ 0x15E232AB;
				}
				if (num19 == (uint)num20)
				{
					break;
				}
				uint num22 = num4;
				int num23 = -705881829;
				_ = 0;
				for (int num24 = 0; num24 < 2; num24++)
				{
					num23 -= ~-61140955;
					num23 = -(471858866 + 1261542913 - num23);
				}
				if (num22 != (uint)num23)
				{
					uint num25 = num4;
					int num26 = -726152;
					_ = 0;
					for (int num27 = 0; num27 < 2; num27++)
					{
						num26 = (num26 - ~-232421846) ^ -1001541930;
						num26 = -(num26 + (-1308605764 + -1614972877));
					}
					if (num25 == (uint)num26)
					{
					}
					return;
				}
				AppViewModel.UpdateMethodSelectionCount(CountSelectedMethods());
				int[] array = new int[7];
				array[0] = 1203814005;
				array[1] = 1141266688;
				array[2] = -412662222;
				array[3] = 821341687;
				array[4] = -1058835276;
				array[5] = 950205075;
				array[6] = -1949205095;
				array[3] = array[6] ^ -931599919;
				array[2] = array[1] ^ 0x4B3282E9;
				int[] array2 = new int[7] { 285868686, -130478868, -431751239, 373156560, -2129414900, -936816598, -927141042 };
				int[][] array3 = new int[2][] { array, array2 };
				array2[6] = array3[0][4] ^ -172041309;
				array2[0] = array2[1] ^ 0x470FA626;
				array2[2] ^= 1254511039;
				array2[2] = array2[3] ^ 0x26127BF3;
				int num28 = array3[1][6] ^ 0x7B272A3B;
				num18 = ((int)num5 * -1692471887) ^ 0x2186D5DD ^ num28;
			}
		}
	}

	private int CountSelectedMethods()
	{
		AssemblyProfile assemblyProfile = _0026_0029_002D_0028_0025_003F_003D_003D(_assemblyWorkspaceService);
		while (true)
		{
			int num = 515718111;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(--1861482426 - (((~(-(num2 - ~(-(-(((--654625393 + (1251087643 - -1776913941 * 472520708) - (-15782667 ^ -1055081907)) ^ (0x851EAD3 ^ -(--1182884379 + 391203163 * 1370914594))) * 1942212279)))) - ~(~(~1080038558)) - ((-225304555 * ~(-54410123 + --292434099 * -591185233)) ^ -(~(-867753111 * ~1347251497) + (883312936 + 2099678053 - 471445557 * -437658407 - (310895759 * 1494215096 + (0x5DD5A2E ^ -1974738853)))))) ^ 0x4F2B0C77) * -764243031) ^ (0x602C2052 ^ -1073886515))))) % 4;
				int num5 = -1648821694;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = (num5 + -678401647) * -1335487519;
					num5 = ~(num5 ^ -215663911);
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 159772327;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -(num7 * -580266805);
					num7 = (num7 ^ --772702667) - 1515189594;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -1655247249;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 -= -1655247251;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 97539145;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = -(num11 * 1939773065);
							num11 = num11 + (74205350 - -1400878805) + 736309272;
						}
						if (num3 != (uint)num11)
						{
						}
						return @_003F_003C_0025_0021_0024_002B_003D(assemblyProfile).SelectMany((NamespaceItem @namespace) => _003C_003Ec._0029_0024_0029__003C_0021_0021_005E(@namespace)).Sum((TypeItem type) => _005E_003D_0021_0028_003C__0024_002A(_assemblyWorkspaceService, @_0025_0024_003F_0024_0029_0029_0025(type)).Count((MethodItem method) => _003C_003Ec._0028_0040_002A_002F_0025_0023_002A_005E(method)));
					}
					return 0;
				}
				int[] array = new int[4];
				array[0] = -1719982759;
				array[1] = 1732669540;
				array[2] = -1099156189;
				array[3] = 821145175;
				array[1] = array[3] ^ -1319225657;
				array[3] = array[2] ^ -180116822;
				int[] array2 = new int[4];
				array2[0] = -1409719581;
				array2[1] = -1192826882;
				array2[2] = 1192393208;
				array2[3] = -1493243685;
				array2[3] = array[2] ^ 0x71B7E52D;
				array2[0] = array2[3] ^ -21352040;
				array2[1] ^= -1702132132;
				array2[1] = array2[2] ^ -906785307;
				int num13 = array2[3] ^ -187911333;
				int[,] array3 = new int[3, 3];
				array3[0, 0] = 1326314475;
				array3[0, 1] = 46323935;
				array3[0, 2] = 1449006076;
				array3[1, 0] = 1806714607;
				array3[1, 1] = 526404157;
				array3[1, 2] = -1899188317;
				array3[2, 0] = 364155693;
				array3[2, 1] = -61618293;
				array3[2, 2] = -863611938;
				array3[0, 2] = array3[0, 1] ^ -2039118681;
				array3[1, 2] = array3[0, 2] ^ -1015200008;
				array3[1, 0] = array3[1, 1] ^ -1767032487;
				array3[1, 2] = array3[2, 1] ^ -1660542469;
				int num14 = array3[1, 2] ^ -993388854;
				int num15 = ((int)num4 * -1516516645) ^ 0x7B3529A5;
				num13 ^= num15;
				num14 ^= num15;
				int num16;
				int num17;
				if (assemblyProfile == null)
				{
					num16 = num14;
					num17 = num16;
				}
				else
				{
					num16 = num13;
					num17 = num16;
				}
				num = num16 ^ num15;
			}
		}
	}

	private void OnAppStateChanged(object? sender, PropertyChangedEventArgs e)
	{
		if (!@_002F_0024_003F_002F_003F_002B_0025(_0024_0021_0024_003D_003D_003C_0023_003C(e), _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[~(-750 + 431)]))
		{
			return;
		}
		while (true)
		{
			int num = -807560562;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(-(((-((-num2 + (--696213705 - (~621170191 + (~(-857406833) - ~(~693274777) - ~(--341709635)) - ((873269011 + -1026462235 - (171480110 + -309812591) - -223735061 * (-1707398761 ^ 0x716F7915)) * 1732387151 - (-602630699 + 974336059 + -313415928 - (-141188029 ^ 0x2281AC5D) + -1574084167)) - (~(~(-(-1959539465 - 1642092602))) - (-2113032348 - -1038451128) + --145692498))) - -(~(-91090505 * (-178087779 ^ (-1503690569 - (607463576 + -843715498))) - -(-(0x558E70C4 ^ 0x2C6D3791))))) ^ -((~(-(--593349912)) - -516321581) * -71502051)) - ((0x62C9EB9B ^ --1393481286) + -(1084555648 + -1252419158) - 449824308) - (-147082994 ^ -(-1250710586 + 1783237683))) ^ -1127154109) - --890783679))) % 3;
				int num5 = -343814240;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~num5 - 1858289805;
					num5 = num5 * 1178808469 + 1229375022;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -1006178452;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 *= 1366164125;
					num7 = (num7 ^ -1918272831) * 535230263;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -1848122924;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 ^= -1848122923;
					}
					if (num3 == (uint)num9)
					{
					}
					return;
				}
				Refresh();
				int[,] array = new int[3, 3];
				array[0, 0] = 1302957486;
				array[0, 1] = -2091638492;
				array[0, 2] = -125414372;
				array[1, 0] = 61087821;
				array[1, 1] = -689591636;
				array[1, 2] = -1422684646;
				array[2, 0] = -951276804;
				array[2, 1] = -437618069;
				array[2, 2] = -2112087125;
				array[0, 1] = array[1, 0] ^ 0xEAF23A1;
				array[1, 2] = array[0, 2] ^ 0x12CDE1A;
				array[0, 1] ^= -1995590455;
				array[1, 0] = array[0, 2] ^ 0x5246521C;
				int num11 = array[1, 0] ^ 0xCA73B1;
				num = ((int)num4 * -1794422766) ^ 0x367D1BEA ^ num11;
			}
		}
	}

	private void OnSelectionChanged(int token, bool isSelected)
	{
		_0026_003D_003E_0040_005E_002B_002F_002B(_assemblyWorkspaceService, token, isSelected);
		while (true)
		{
			int num = -1498966319;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(1852360247 - (-(-(~(((~(--1930742859) - ~(~-2082589376)) ^ -1202783415) * -1464780041 - (~num2 - -(-(-1873900950 ^ ((-((0x6E70DC67 ^ -39683206) * -790730373) + (-1786959920 - -1970368905 * (-1592954559 * 1395895376))) ^ ~(0x28B30093 ^ -1150169501 ^ -1413578232)))))) - (1126613537 * -(~-2096814729) - ~(537102518 + 1949586360 + 1966030368) - (0x59F6571D ^ -847565401))) * -1166016425) ^ 0x161576D8))) % 5;
				int num5 = -200023554;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~(num5 ^ 0xE9B159D);
					num5 = num5 + 1962556035 * 850353595 - 702836624;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -1018606885;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 -= -1018606889;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -1960437747;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = -(num9 + 1098808929 * 2055866113);
						num9 = -(num9 + --1456484710);
					}
					if (num3 != (uint)num9)
					{
						int num11 = -335229579;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = num11 * -1375583335 + 785284280;
							num11 = ~(num11 * 325096285);
						}
						if (num3 != (uint)num11)
						{
							int num13 = -134223926;
							_ = 0;
							for (int num14 = 0; num14 < 2; num14++)
							{
								num13 = num13 - (-1836744236 + -508999832) - 142970737;
								num13 = (num13 ^ 0x3B2F49CB) - -160787538;
							}
							if (num3 == (uint)num13)
							{
							}
							return;
						}
						_0029_003F_005E_002A_0040__002B_0025(SelectAllCommand);
						int[] array = new int[7];
						array[0] = 306058663;
						array[1] = -2056707;
						array[2] = -1651953867;
						array[3] = -2097571129;
						array[4] = 5516868;
						array[5] = -2000409485;
						array[6] = 204832351;
						array[0] = array[6] ^ -1100678433;
						array[0] ^= 239844475;
						array[4] = array[5] ^ -915647907;
						int[] array2 = new int[7];
						array2[0] = -1628405174;
						array2[1] = -1090995787;
						array2[2] = 1859341736;
						array2[3] = 1905223347;
						array2[4] = -1577531931;
						array2[5] = 1010224678;
						array2[6] = 1138196447;
						array2[5] = array[5] ^ 0x364CC0B5;
						array2[2] = array2[5] ^ 0x52CB4694;
						array2[6] = array2[1] ^ -330299285;
						array2[3] = array2[2] ^ 0x6623C676;
						int num15 = array2[5] ^ 0x7223CBCA;
						num = ((int)num4 * -962145642) ^ -1113466722 ^ num15;
					}
					else
					{
						_0029_003F_005E_002A_0040__002B_0025(ClearSelectionCommand);
						int[,] array3 = new int[3, 4];
						array3[0, 0] = -1416250963;
						array3[0, 1] = -1551031932;
						array3[0, 2] = 908996023;
						array3[0, 3] = 1050765163;
						array3[1, 0] = 695532663;
						array3[1, 1] = -196282399;
						array3[1, 2] = -315172857;
						array3[1, 3] = 2098693290;
						array3[2, 0] = 1155612234;
						array3[2, 1] = -707229641;
						array3[2, 2] = -1097663198;
						array3[2, 3] = -1270526393;
						array3[0, 0] = array3[0, 3] ^ 0x23418550;
						array3[2, 3] = array3[0, 0] ^ -1963222458;
						array3[2, 3] = array3[2, 0] ^ 0x77559C43;
						array3[0, 2] = array3[1, 2] ^ -1509394392;
						int num16 = array3[0, 2] ^ -875261645;
						num = (int)((num4 * 985258637) ^ 0xEAA986CEu) ^ num16;
					}
				}
				else
				{
					AppViewModel.UpdateMethodSelectionCount(CountSelectedMethods());
					int[] array4 = new int[4];
					array4[0] = 997830684;
					array4[1] = 1373066575;
					array4[2] = -55928298;
					array4[3] = -365031704;
					array4[3] = array4[0] ^ -557418787;
					array4[1] = array4[0] ^ -1182364204;
					int[] array5 = new int[4];
					array5[0] = -1387152623;
					array5[1] = 931986346;
					array5[2] = 497503090;
					array5[3] = -616084146;
					array5[3] = array4[0] ^ 0x1EBBD414;
					array5[0] = array5[3] ^ 0x5D2DB63A;
					array5[0] ^= 945760793;
					array5[0] = array5[1] ^ -251689066;
					int num17 = array5[3] ^ -29819725;
					num = (int)((num4 * 1170565234) ^ 0xFA373800u) ^ num17;
				}
			}
		}
	}

	private unsafe static string ResolveIcon(TypeItem type)
	{
		if (_0025_0026__003C_0028_002A_003E_003C(type))
		{
			goto IL_000e;
		}
		goto IL_075e;
		IL_000e:
		int num = -846207841;
		goto IL_0013;
		IL_0013:
		uint num3;
		while (true)
		{
			int num2 = num;
			uint num4;
			num3 = (num4 = (uint)(~((~(-num2 - -(((-1119423375 * (-(~-108280555) ^ -281497596) - -530042375 * -(-(~2110378232))) ^ 0x1774138) + -(~(((-2137985178 ^ -815373072) - (-553649937 + -396384901 - --1295202845)) * -624531571)))) + (~(-1551425622 ^ -1331306180) + -1020690855 * -(699691794 * -1583599785 + --1109751631) + (1732891784 - -(-240859643)))) * -1544511335) * -1163387195)) % 7;
			int num5 = -1766020990;
			_ = 0;
			for (int num6 = 0; num6 < 1; num6++)
			{
				num5 *= -1111018685;
			}
			if (num3 == (uint)num5)
			{
				break;
			}
			int num7 = 477062973;
			_ = 0;
			for (int num8 = 0; num8 < 2; num8++)
			{
				num7 = -num7;
				num7 = (num7 + 743935119 * -59473862) * 1298843787;
			}
			if (num3 != (uint)num7)
			{
				int num9 = -506566041;
				_ = 0;
				for (int num10 = 0; num10 < 1; num10++)
				{
					num9 ^= -506566046;
				}
				if (num3 != (uint)num9)
				{
					int num11 = 1816661199;
					_ = 0;
					for (int num12 = 0; num12 < 2; num12++)
					{
						num11 = num11 ^ -495682945 ^ 0x3C1834C1;
						num11 = -(num11 + -30155494 * -2047153505);
					}
					if (num3 != (uint)num11)
					{
						int num13 = -1480943838;
						_ = 0;
						for (int num14 = 0; num14 < 2; num14++)
						{
							num13 = 1344098713 - (num13 ^ 0x47D4A238);
							num13 = (num13 * 652182565) ^ -1581739610;
						}
						if (num3 == (uint)num13)
						{
							int num15;
							if (!_003F_0040_002F_003F_005E__005E_002D(type))
							{
								num = -2037723965;
								num15 = num;
							}
							else
							{
								num = -1481912125;
								num15 = num;
							}
							continue;
						}
						goto IL_0312;
					}
					return _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[427 - 16 - 22 - 22];
				}
				goto IL_075e;
			}
			return _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[(378 + sizeof(int)) ^ sizeof(Guid)];
		}
		goto IL_000e;
		IL_0312:
		int num16 = 0;
		_ = 0;
		for (int num17 = 0; num17 < 2; num17++)
		{
			num16 = ~num16 ^ -1864031935;
			num16 = ~(num16 ^ 0x5B6126F6);
		}
		if (num3 != (uint)num16)
		{
			int num18 = 4;
			_ = 0;
			for (int num19 = 0; num19 < 2; num19++)
			{
				num18 = -num18;
				num18 = ~(-num18);
			}
			if (num3 != (uint)num18)
			{
			}
			return _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0xAC49 ^ 0xAD38))];
		}
		return _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x21CC ^ 0x20BC];
		IL_075e:
		int num20;
		if (_002D_0040_003F_0040_003E_0023_002B_003D(type))
		{
			num = -740247556;
			num20 = num;
		}
		else
		{
			num = -1455863058;
			num20 = num;
		}
		goto IL_0013;
	}

	private void SelectType(TypeNodeViewModel? typeNode)
	{
		if (typeNode == null)
		{
			goto IL_0009;
		}
		goto IL_0e4a;
		IL_0009:
		int num = 605521289;
		goto IL_000e;
		IL_000e:
		while (true)
		{
			int num2 = num;
			uint num4;
			uint num3 = (num4 = (uint)((-(-((-(~(((-1610209921 * -(1370024054 + ((-409638323 - 257235539) * 908598219 - (~432045404 + 1754881317 * 1775931741)) - ~(-1978550177)) + ((((0x18C7A60B ^ (0x7CBAD02A ^ -1030314703)) - ((-232355965 ^ 0x1062DFE) + (~1237801673 - (866622945 - 1839525769)))) ^ (--912082669 - ((-1442199760 - -2133338657) * -702255831 + 1825680553 * (-325315836 - 471075498)))) + ~(~-407277505 + (-(--213857530) ^ -65271559)) + (-1058654106 + (~-1813863982 - -1177977229)))) ^ -((-(-((--1939100060 * 996198539) ^ -(~719814051))) ^ (-(~(~(631712071 * -1194955740))) + ~(0x79222C18 ^ -991746934))) * -450255193)) - num2) * 68537563) ^ -(-(-(-1355919287)) - -394541723)) - (~(0x5D036C4 ^ -26785876) - (0x7FDF41F8 ^ -1876697550)))) ^ 0x7ED59C02) - -1980682938)) % 8;
			int num5 = 2099745695;
			_ = 0;
			for (int num6 = 0; num6 < 2; num6++)
			{
				num5 = --1370649697 - num5 - 712682829;
				num5 = (num5 + (-1086194067 ^ 0xBEB225D)) * 1693531341;
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
			int num9 = -124356395;
			_ = 0;
			for (int num10 = 0; num10 < 1; num10++)
			{
				num9 ^= -124356397;
			}
			if (num3 != (uint)num9)
			{
				int num11 = -300597381;
				_ = 0;
				for (int num12 = 0; num12 < 2; num12++)
				{
					num11 = num11 * 188296391 * -1037280149;
					num11 = 146597840 - num11 * 247065495;
				}
				if (num3 != (uint)num11)
				{
					int num13 = -1697944660;
					_ = 0;
					for (int num14 = 0; num14 < 1; num14++)
					{
						num13 -= -1697944660;
					}
					if (num3 != (uint)num13)
					{
						int num15 = -2095476303;
						_ = 0;
						for (int num16 = 0; num16 < 2; num16++)
						{
							num15 = (num15 - (-1939710818 ^ -1354452029)) * 78354855;
							num15 = -(num15 * -211321465);
						}
						if (num3 != (uint)num15)
						{
							int num17 = 1115791994;
							_ = 0;
							for (int num18 = 0; num18 < 2; num18++)
							{
								num17 = ~(num17 - ~-242494289);
								num17 = ~(num17 * -462144043);
							}
							if (num3 != (uint)num17)
							{
								int num19 = 4;
								_ = 0;
								for (int num20 = 0; num20 < 2; num20++)
								{
									num19 = -(num19 - (-894793963 - -1866183870));
									num19 = num19 - (-625662594 ^ -1268038913) + 896535989;
								}
								if (num3 == (uint)num19)
								{
								}
								return;
							}
							_0029_003F_005E_002A_0040__002B_0025(SelectAllCommand);
							int[,] array = new int[4, 3];
							array[0, 0] = -2123377018;
							array[0, 1] = -2104006263;
							array[0, 2] = 1165934216;
							array[1, 0] = -1808433992;
							array[1, 1] = 1790513384;
							array[1, 2] = -1165410514;
							array[2, 0] = -549580701;
							array[2, 1] = -1922856188;
							array[2, 2] = 1875511952;
							array[3, 0] = -727299507;
							array[3, 1] = 1919433330;
							array[3, 2] = -567498164;
							array[1, 2] = array[3, 1] ^ 0x4F79743D;
							array[2, 2] = array[1, 0] ^ 0x168CB5C7;
							array[2, 1] = array[3, 2] ^ -399624470;
							int num21 = array[2, 1] ^ 0x3816E98A;
							num = ((int)num4 * -1244443643) ^ 0x70076D9A ^ num21;
						}
						else
						{
							_0029_003F_005E_002A_0040__002B_0025(ClearSelectionCommand);
							int[] array2 = new int[6];
							array2[0] = 1399780102;
							array2[1] = -1195545507;
							array2[2] = 155688158;
							array2[3] = 751922260;
							array2[4] = -816660721;
							array2[5] = -336023765;
							array2[1] = array2[4] ^ 0x3742F85E;
							array2[1] = array2[4] ^ 0x44A833EB;
							int[] array3 = new int[4] { -673758539, 426106923, 754435500, -1650364484 };
							int[][] array4 = new int[2][] { array2, array3 };
							array3[3] = array4[0][0] ^ 0x5B488D1B;
							array3[0] = array3[2] ^ -318375083;
							array3[2] = array3[1] ^ -1617395404;
							array3[2] = array3[0] ^ -819579358;
							int num22 = array4[1][3] ^ -934488485;
							num = ((int)num4 * -1401322014) ^ 0x6984EE12 ^ num22;
						}
					}
					else
					{
						ApplyFilter();
						int[] array5 = new int[7];
						array5[0] = 1370993447;
						array5[1] = -86608284;
						array5[2] = 795539909;
						array5[3] = -692177461;
						array5[4] = -660430627;
						array5[5] = 1182778628;
						array5[6] = 1835705797;
						array5[0] = array5[1] ^ 0x2C1D2031;
						array5[5] = array5[6] ^ 0x26D7FDB9;
						int[] array6 = new int[5];
						array6[0] = -366376811;
						array6[1] = 763031484;
						array6[2] = 1920121635;
						array6[3] = -1511993572;
						array6[4] = -1961028172;
						array6[1] = array5[1] ^ -1955737139;
						array6[2] = array6[4] ^ 0x488918D8;
						array6[2] = array6[3] ^ -1476605649;
						int num23 = array6[1] ^ -2076912500;
						num = ((int)num4 * -2074174835) ^ -104490208 ^ num23;
					}
				}
				else
				{
					_allMethods = (from method in _005E_003D_0021_0028_003C__0024_002A(_assemblyWorkspaceService, typeNode.FullName)
						select new MethodRowViewModel(@_0023_0025_0025_003C_0040_003D_003D(method), _0028_002F_0028_003C_002A_002A_0024_0023(method), _0028_003D_002A_003E_0023_002F_002B_002D(method), _0024_0025_0025_002B__002B_0025_003E(method), _0024__0021_0024_005E_0024_0025_005E(method), OnSelectionChanged)).ToList();
					int[,] array7 = new int[3, 3];
					array7[0, 0] = 1139341955;
					array7[0, 1] = 676543688;
					array7[0, 2] = -472019480;
					array7[1, 0] = 386838813;
					array7[1, 1] = 1552387824;
					array7[1, 2] = 994468157;
					array7[2, 0] = -1551878525;
					array7[2, 1] = 773188071;
					array7[2, 2] = -1017214789;
					array7[0, 2] = array7[2, 0] ^ 0x43201ABE;
					array7[2, 2] = array7[2, 1] ^ 0x53E5DB78;
					array7[2, 0] = array7[2, 1] ^ -1877897684;
					array7[0, 2] = array7[2, 1] ^ 0xB4E411C;
					int num24 = array7[0, 2] ^ 0x538D4FEB;
					num = (int)((num4 * 1759360520) ^ 0x9BAD3ED8u) ^ num24;
				}
				continue;
			}
			goto IL_0e4a;
		}
		goto IL_0009;
		IL_0e4a:
		SelectedTypeName = typeNode.DisplayName;
		num = 728172643;
		goto IL_000e;
	}

	private void SelectAll()
	{
		using (List<MethodRowViewModel>.Enumerator enumerator = _allMethods.GetEnumerator())
		{
			uint num4;
			uint num12;
			int num13;
			do
			{
				int num;
				int num2;
				if (!enumerator.MoveNext())
				{
					num = 72664227;
					num2 = num;
				}
				else
				{
					num = -1532758790;
					num2 = num;
				}
				while (true)
				{
					int num3 = num;
					uint num5;
					num4 = (num5 = (uint)(-(~(~(-(-num3 + ((-1300128079 * (1411544398 - --1493457498 * 1288654679) + -1372860733 * 572820296 - 694992337 * ~(~(-140663475 * (-481780026 ^ 0x2653D63D))) + 1052528416) ^ 0xEB2AFBC))))) * -1380779759)) % 4;
					uint num6 = num4;
					int num7 = 427754373;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = 427754373 - num7;
					}
					if (num6 == (uint)num7)
					{
						num = -1532758790;
						continue;
					}
					uint num9 = num4;
					int num10 = -910555803;
					_ = 0;
					for (int num11 = 0; num11 < 1; num11++)
					{
						num10 += 910555806;
					}
					if (num9 != (uint)num10)
					{
						break;
					}
					enumerator.Current.IsSelected = true;
					num = 44356304;
				}
				num12 = num4;
				num13 = -1;
				_ = 0;
				for (int num14 = 0; num14 < 2; num14++)
				{
					num13 = -(~num13);
					num13 = -(-num13);
				}
			}
			while (num12 == (uint)num13);
			uint num15 = num4;
			int num16 = -2;
			_ = 0;
			for (int num17 = 0; num17 < 1; num17++)
			{
				num16 = -num16;
			}
			if (num15 == (uint)num16)
			{
			}
		}
		ApplyFilter();
		while (true)
		{
			int num18 = -1344418241;
			while (true)
			{
				int num3 = num18;
				uint num5;
				uint num4 = (num5 = (uint)(-(~(~(-(-num3 + ((-1300128079 * (1411544398 - --1493457498 * 1288654679) + -1372860733 * 572820296 - 694992337 * ~(~(-140663475 * (-481780026 ^ 0x2653D63D))) + 1052528416) ^ 0xEB2AFBC))))) * -1380779759)) % 3;
				uint num19 = num4;
				int num20 = 1169131480;
				_ = 0;
				for (int num21 = 0; num21 < 2; num21++)
				{
					num20 = -(~num20);
					num20 = (num20 * 1247013213) ^ -802542545;
				}
				if (num19 == (uint)num20)
				{
					break;
				}
				uint num22 = num4;
				int num23 = -1070319518;
				_ = 0;
				for (int num24 = 0; num24 < 2; num24++)
				{
					num23 ^= 0x57909B2E;
					num23 -= 378303859 + -1920069187;
				}
				if (num22 != (uint)num23)
				{
					uint num25 = num4;
					int num26 = -2;
					_ = 0;
					for (int num27 = 0; num27 < 1; num27++)
					{
						num26 = ~num26;
					}
					if (num25 == (uint)num26)
					{
					}
					return;
				}
				AppViewModel.UpdateMethodSelectionCount(CountSelectedMethods());
				int[,] array = new int[3, 4];
				array[0, 0] = -1546759746;
				array[0, 1] = -1406327974;
				array[0, 2] = 863822322;
				array[0, 3] = 1706287300;
				array[1, 0] = 319424137;
				array[1, 1] = -1913155591;
				array[1, 2] = -1504670102;
				array[1, 3] = -1250394145;
				array[2, 0] = 2094083284;
				array[2, 1] = -482691166;
				array[2, 2] = 1277197471;
				array[2, 3] = -1530717494;
				array[1, 1] = array[2, 2] ^ -1675064289;
				array[1, 3] = array[1, 2] ^ 0x60AD0434;
				array[0, 1] = array[0, 2] ^ -246981463;
				int num28 = array[0, 1] ^ 0x2C1B1660;
				num18 = ((int)num5 * -1164364104) ^ -165405808 ^ num28;
			}
		}
	}

	private bool CanBulkChangeSelection()
	{
		return _allMethods.Count > 0;
	}

	static void _003F_0024_003E_002D_0025_003C_0025_0021(ObservableObject P_0, PropertyChangedEventHandler P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 21361991;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((~(~(-(0x559509FF ^ -1610526898) - ~-168193845 * 42402413) - ~2039189060) + 1884020410 - -(-num2)) * -523944143))) % 3;
					int num5 = -304056144;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * -1735363191 - 165744092;
						num5 = num5 ^ -890067704 ^ 0xA33790E;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 2;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(~num7);
						num7 = -num7 - 603896206;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 149709082;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = 149709083 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.PropertyChanged += P_1;
					int[] array = new int[7];
					array[0] = 1519706650;
					array[1] = -371386400;
					array[2] = -759764761;
					array[3] = -719769432;
					array[4] = -460554399;
					array[5] = -1696314333;
					array[6] = -1722091656;
					array[3] = array[2] ^ 0x36A75EC7;
					array[6] = array[0] ^ 0x6F7735F0;
					int[] array2 = new int[7] { -1775836680, -532843008, 1251917091, -1681410053, -528062330, 117712417, -733116144 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][0] ^ -1778002895;
					array2[0] = array2[5] ^ -432222237;
					array2[1] = array2[6] ^ -979967286;
					array2[0] = array2[2] ^ -2090791482;
					int num11 = array3[1][3] ^ 0x6BDF0EBE;
					num = ((int)num4 * -1424902539) ^ -221788050 ^ num11;
				}
			}
		}
	}

	static void @_0040_002B_002F_003C_0028_0023_002A(ObservableObject P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1012602958;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~((-(((-(~(~((0x67AE0E1C ^ 0x2D9BCDE6) * 2130998727 - (~(~-1651266611) - -(-971134428 - -1560770633))))) + (1579864618 - (~(-(~-847535267 - -1654161780) * 277935795) - (-1031375119 + ~(-1876603183 * (1296438882 + (0x36A2DB7E ^ 0x68338AE4))))))) ^ (~(-(~(-(-300365185 * ~-323197223)))) + (((0x1B6EE746 ^ 0x3EC4F56F) - ((~(--1519946494) ^ -417875260) + 1699055157) + ((-811024694 ^ -1295136502) + (-(-1667757574 - -613286812) - (-954986729 + 1496596972 - (-1352760759 ^ -1539804112)) - (0x1229BFFB ^ (-1857387478 ^ -1971568828))))) ^ 0x42E20D58))) - num2) ^ -(-(~(0x1670DDF5 ^ 0x6EAB832E) - ((-422272880 ^ 0x472EE12A) * 899990321 - (~552581277 + --1400475476))) + ~(~(414915851 * 1152832389 - (-2100714318 ^ 0x776B1424)) + -(~1371813675 - 1354532583)))) + (1845563357 * (--1010523546 + 37866394) - -1951031359)))) % 3;
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
					int num7 = -8175777;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (-347295321 * 277577187 - num7) ^ 0x4D2A4D7;
						num7 += ~1633537464;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 0;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (0xF8251DF ^ 0xC5FEB6D) - num9 + -2048181963;
							num9 = 1877241483 - ~num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.OnPropertyChanged(P_1);
					int[] array = new int[4];
					array[0] = 1761096042;
					array[1] = 1077691983;
					array[2] = 1722358880;
					array[3] = -401558994;
					array[0] = array[3] ^ -1677484467;
					array[2] ^= 1856828034;
					int[] array2 = new int[7];
					array2[0] = -1604866989;
					array2[1] = -1755215781;
					array2[2] = 1968884018;
					array2[3] = -1406864736;
					array2[4] = -1133616473;
					array2[5] = 537077093;
					array2[6] = -2020094009;
					array2[6] = array[1] ^ 0x7B056480;
					array2[1] = array2[4] ^ 0x1A6E8BC5;
					array2[3] = array2[5] ^ 0x52B9B827;
					array2[2] = array2[3] ^ -107871814;
					int num11 = array2[6] ^ 0x715DE166;
					num = (int)((num4 * 2137638854) ^ 0xF7418AE2u) ^ num11;
				}
			}
		}
	}

	static bool _0024_0021__005E_0029_0024_003C_002B(string P_0)
	{
		bool result = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1315284043;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(((~(1444350368 - (-(num2 * -371943993) ^ -(~(-((0x161778B ^ -1935705279) - 1438153936)))) * 253635411) ^ (1065578941 * (--1399049863 - ~-1610790795))) - -(-1978068010 - -1270213861)) * 850866851 - -837934282)) % 3;
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
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1059269842;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 ^= -1059269841;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = string.IsNullOrWhiteSpace(P_0);
					int[] array = new int[4];
					array[0] = 132854782;
					array[1] = -1523917764;
					array[2] = -1512154602;
					array[3] = -842144446;
					array[3] = array[0] ^ 0x5792B993;
					array[1] = array[2] ^ -924785482;
					array[1] = array[3] ^ 0xE86043D;
					int[] array2 = new int[4] { -309755014, 2062161224, -187920476, -2109146156 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][2] ^ 0x21E3B3E2;
					array2[0] = array2[2] ^ 0x30D520E3;
					array2[1] = array2[3] ^ 0x7186DA83;
					int num11 = array3[1][2] ^ -39325662;
					num = (int)((num4 * 820206164) ^ 0xBD5C3B14u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static AssemblyProfile _0026_0029_002D_0028_0025_003F_003D_003D(IAssemblyWorkspaceService P_0)
	{
		AssemblyProfile currentProfile = default(AssemblyProfile);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 133586138;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-((-(((num2 * -1205383281) ^ ~(-553692111 * ((-796569373 ^ ((-915677325 - (-384739721 - 2024355065)) * -1797270399)) * 1032082753) - (-1153931514 - -(~(~-232706669)) * -1310684517) * 1568427299)) - -(-(-1612599941 * (1970629132 + (-(0x7DC7F97D ^ 0x4997C8C3) - (--211773838 + 1575101060 * 202368521)))))) - (-1993601721 - (1801703670 * 1297258461 * -557051745 + ~313070691 * -769350547) - ~(-370330039 ^ -1569357108))) ^ (-547797202 ^ -362673163) ^ -(-(~414063320)))) ^ -38042841)) % 3;
					int num5 = -90397153;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -90397153 - num5;
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
					currentProfile = P_0.CurrentProfile;
					int[] array = new int[5];
					array[0] = -836842252;
					array[1] = 957586001;
					array[2] = 1331103744;
					array[3] = 656178118;
					array[4] = 735339076;
					array[0] = array[4] ^ 0x3F3E06A9;
					array[0] = array[3] ^ 0x3AEE26B;
					int[] array2 = new int[5];
					array2[0] = 383906410;
					array2[1] = -1101480084;
					array2[2] = -384012683;
					array2[3] = 274248964;
					array2[4] = 1200380470;
					array2[0] = array[4] ^ -1663144950;
					array2[4] = array2[0] ^ 0x4375CC12;
					array2[3] = array2[4] ^ 0x2F5133A7;
					int num11 = array2[0] ^ -1426172881;
					num = ((int)num4 * -563396977) ^ -1259879366 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return currentProfile;
	}

	static IReadOnlyList<NamespaceItem> @_003F_003C_0025_0021_0024_002B_003D(AssemblyProfile P_0)
	{
		IReadOnlyList<NamespaceItem> namespaces = default(IReadOnlyList<NamespaceItem>);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 709844648;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(((-(num2 - 674418415 * ~(-(-(~(2040349478 - 1627109167)) + (-1286510446 - 403007163) - (-(-(-1127763044 + 1220536210)) - -55526351)) - -(0x6A0BD14 ^ -2137665763)) + ~(1832138831 * ~(~(0x55BDA2D8 ^ -78852696)) * 935559675 - ~(--85481273))) ^ ((-418512958 - -1557282550 * 275989417 + -(1344278502 * 2136151355) + (0x551DEFD0 ^ 0x4B5D8DD) - ((-581640433 ^ -1492916570) - (1813953808 - -2097363157))) * -2034094419)) - ~(-1939718243 * (1396225969 * -1159052122 - (535465760 - 477352630))) * 681643485) * 1920767599))) % 3;
					int num5 = -904117594;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= -904117594;
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
					namespaces = P_0.Namespaces;
					int[] array = new int[6];
					array[0] = -819308778;
					array[1] = 996931071;
					array[2] = 1550918477;
					array[3] = -1547328791;
					array[4] = -166896505;
					array[5] = 158313364;
					array[0] = array[5] ^ 0x4884B780;
					array[2] = array[1] ^ -913946745;
					array[1] = array[3] ^ 0x12B87FCD;
					int[] array2 = new int[5] { -1409143842, -71572325, -917770185, 924537932, 1939444450 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[3] = array3[0][4] ^ -774183386;
					array2[2] = array2[1] ^ 0x7BC00DD0;
					array2[0] = array2[2] ^ 0x154D67A7;
					array2[1] = array2[0] ^ 0x6C6E525D;
					int num11 = array3[1][3] ^ -13766768;
					num = ((int)num4 * -304543614) ^ 0x78B4A2C2 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return namespaces;
	}

	static string _0021_0023_002F_0024_0024_0040__002B(NamespaceItem P_0)
	{
		string name = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1846560409;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(num2 * -1643914159 + (((-1521070104 ^ -(~(0x1CE88FA6 ^ -1272029619 ^ -(0xF3842E5 ^ -375097787)))) - (~((0x210F9B33 ^ 0x607A53DA) - -(-(-777812019 ^ -1442256000))) + (-90438604 ^ (~925466529 + ~(--1114366340 + 1094771573))))) ^ ~(~(-511515396 * 1406828653) - -500067719 + -132090043 * (1421713737 * (-(0x1D7E36DA ^ 0x224D3CA2) + 1147564239))))) ^ 0x66A96CD6))) % 3;
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
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 ^ 0x46E25BCC;
						num7 = -(-num7);
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1516539526;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ --1954914256) * -676142027;
							num9 -= -632949059 * -953521258;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					name = P_0.Name;
					int[] array = new int[7];
					array[0] = 57223720;
					array[1] = 626720103;
					array[2] = -133916247;
					array[3] = -1943555733;
					array[4] = -1142685505;
					array[5] = 841733880;
					array[6] = -524438621;
					array[1] = array[5] ^ -1643709172;
					array[1] = array[3] ^ 0x45D14BD4;
					array[4] = array[6] ^ -2093169602;
					int[] array2 = new int[6] { -1131565771, 954498364, -1268692751, -1331072490, -2052802325, -776320867 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][0] ^ -334269443;
					array2[4] = array2[0] ^ 0xF4E093C;
					array2[1] ^= -1396138318;
					int num11 = array3[1][2] ^ 0x1A779494;
					num = ((int)num4 * -355538320) ^ -32282496 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return name;
	}

	static IReadOnlyList<TypeItem> _0029_002B_0024_0024__0026_003C_002F(NamespaceItem P_0)
	{
		IReadOnlyList<TypeItem> types = default(IReadOnlyList<TypeItem>);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1601641582;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-1736204867 * ~-95263999 - ~(~(~(~(~num2 ^ ((~(1770314877 + -2080868709) ^ (0x7683D00C ^ (~((-297730126 ^ -560811221) + --724286499) ^ 0x1E29E067) ^ (~((-1319409413 ^ -167479420) - -596833603 * -206358830) + 1537333603))) - -(~(-1661206369 * (1336732060 - 468555799 + (0x23F3C07C ^ -1202979184)) - -(0x347C73E4 ^ -1667599579) * -1436963781) + ((693357159 * (--1300137151 - -2064931621) + ((-1859349260 ^ -1067147595) - (-1880412406 - 449407329 + (0x274CFC04 ^ -1951909705)))) ^ (~(-2056545134 ^ --1933969930) ^ 0x6EC43104))))))) * -2002742887))) % 3;
					int num5 = -1294536840;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -1294536838 - num5;
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
						int num9 = -1997903240;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 * 380698967 * -1832392901;
							num9 = ~num9 ^ 0x3B30BDE5;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					types = P_0.Types;
					int[] array = new int[5];
					array[0] = -182910093;
					array[1] = -844404216;
					array[2] = 1841797626;
					array[3] = 2116897499;
					array[4] = 878701106;
					array[2] = array[0] ^ 0x6892DAD2;
					array[4] = array[1] ^ 0x73EB2BE7;
					int[] array2 = new int[4];
					array2[0] = -1826698114;
					array2[1] = 505108304;
					array2[2] = -1842518325;
					array2[3] = 854290474;
					array2[0] = array[1] ^ 0x70124AF9;
					array2[2] = array2[1] ^ 0x5594FC77;
					array2[2] = array2[0] ^ -1687618802;
					int num11 = array2[0] ^ 0x18703D1;
					num = (int)((num4 * 1230687462) ^ 0x2D3E3A64) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return types;
	}

	static bool _005E_0025_0026_003E_0023_003E_003E_0025(IEnumerator P_0)
	{
		bool result = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1240492748;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((-((~num2 + (-((406204859 * (-(--764867432) - ~(~-1152835754)) * -1624540313) ^ (-740343397 ^ (-(-(1252722854 + 2003663142)) * 54757881))) - ~(~(-((~1379565343 + ~1159519949) * 203239357 + -736623910))))) * 441090111) - 1061510130 - (0x6FF6F416 ^ -1674571601) - -((-252097062 ^ 0x470EDA) - --1431672429) - (-308601751 - -390792762 - (751095730 + -1789362747))) ^ -583264668))) % 3;
					int num5 = 2059502978;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 *= 1056623937;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -2049191205;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = 1681705328 - num7 * 1149001845;
						num7 = num7 ^ 0x5910CECC ^ -1922006591;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -500705308;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ -1174250157) * 1116727361;
							num9 = -(num9 * -1999572229);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.MoveNext();
					int[] array = new int[5] { 1533006551, 1320283351, 581377586, 1298213183, 882492828 };
					array[1] ^= 986033518;
					array[2] = array[1] ^ -1982769022;
					int[] array2 = new int[5];
					array2[0] = 198252937;
					array2[1] = 13906502;
					array2[2] = 875424308;
					array2[3] = -824808439;
					array2[4] = -539232937;
					array2[1] = array[3] ^ 0x67D7E2A4;
					array2[0] = array2[3] ^ 0x6631B56A;
					array2[0] = array2[3] ^ -1226683289;
					array2[2] ^= 278235494;
					int num11 = array2[1] ^ 0x2DDEC930;
					num = (int)((num4 * 1195102011) ^ 0xBA2F0122u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _002A_005E_003F_005E_003D_002F_0026_003F(IDisposable P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1935982209;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(-(~(2027345530 * -927171915)) - ~(-(~num2)))))) % 3;
					int num5 = -1716646842;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 ^ -796544310) * -1254458883;
						num5 = -num5 * 977060725;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1072132317;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 ^ -540925108;
						num7 = ~num7 - 1678534292;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -58726642;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 ^ 0x6DB5E362) - -112639509;
							num9 = 564047876 - -num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Dispose();
					int[] array = new int[5];
					array[0] = -167625569;
					array[1] = -765643566;
					array[2] = -593550864;
					array[3] = 1367512080;
					array[4] = 2122262362;
					array[2] = array[1] ^ -1760366642;
					array[3] = array[1] ^ -1855491992;
					array[2] = array[0] ^ -1265196067;
					int[] array2 = new int[5];
					array2[0] = 1385326551;
					array2[1] = 697038260;
					array2[2] = -593436154;
					array2[3] = -1697546489;
					array2[4] = 262284810;
					array2[2] = array[1] ^ -1920329293;
					array2[4] ^= 1439394877;
					array2[3] ^= -1273977402;
					int num11 = array2[2] ^ -554129331;
					num = ((int)num4 * -308943315) ^ -677145394 ^ num11;
				}
			}
		}
	}

	static void _0029_003F_005E_002A_0040__002B_0025(RelayCommand P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			P_0.NotifyCanExecuteChanged();
		}
	}

	static string _0024_0021_0024_003D_003D_003C_0023_003C(PropertyChangedEventArgs P_0)
	{
		string propertyName = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -1402997659;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~((-((num2 + ~(0x3626318B ^ -((-(-132537180) * -1006563551 + ((0x3EA7594F ^ -1096832847) - ((0x1B5667E9 ^ 0x772D9B45) - -570866495 * -1857069261) - (-304051492 ^ -644918588))) * 1739266263))) * 249110773) ^ ~(-(-1373681888 ^ 0x2060147F)) ^ (~(~(-1262682776 - ~243901193)) - ~((382628236 - 1276584899 + --2140625351) ^ -1667975608))) + --263263591) - (--436847881 - (-266163847 ^ -614543000))))) % 3;
					int num5 = 957141112;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 957141112;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -20956158;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 + --1210150358) ^ -628155255;
						num7 = num7 - (-790915603 ^ -412955199) - 534001443;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 546276591;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 546276590;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					propertyName = P_0.PropertyName;
					int[] array = new int[7];
					array[0] = -1989359412;
					array[1] = -909270474;
					array[2] = 2127285113;
					array[3] = -1719432196;
					array[4] = -956207660;
					array[5] = 1409836188;
					array[6] = -115807699;
					array[5] = array[4] ^ 0xFAA701F;
					array[5] = array[4] ^ 0x35A72DBA;
					int[] array2 = new int[6];
					array2[0] = -1966010761;
					array2[1] = -1864249059;
					array2[2] = 1042125868;
					array2[3] = 933175266;
					array2[4] = 2099491819;
					array2[5] = 594371428;
					array2[3] = array[2] ^ 0x3F5A1DF4;
					array2[1] = array2[3] ^ -1691308264;
					array2[2] = array2[4] ^ -1804312222;
					array2[4] = array2[2] ^ 0x6CAEDF5C;
					int num11 = array2[3] ^ 0x671DAA6F;
					num = (int)((num4 * 516228776) ^ 0x650A1C10) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return propertyName;
	}

	static bool @_002F_0024_003F_002F_003F_002B_0025(string P_0, string P_1)
	{
		bool result = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1114245603;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(((num2 ^ (~1002213894 - (310490941 * 483915449 - ((-(-1257366214 * -421809553) ^ 0x1D99D423) - -405807282)) - (--2110488841 - (-(-1471069579 * 79497306 - -761863191) ^ (548155588 + -(~477119901)))))) - (~(~(-(-1233127865 * (-795287420 ^ --1996807025))) + 1378782009) - (--1342695464 ^ -1294675986 ^ ((-1582677961 + ((0x41B7AC0C ^ -705632996) * -577420817 + -1690471832) + -(-1437736285 + (-1867459825 - -147512449) - -183805955)) ^ (~(-(0x6923705F ^ 0x1AF8F6A1) + 1815647771 * (-1609189400 - -1317696616)) ^ 0x3C6C799C))))) ^ (103533249 * ~((--1200182938 + (-(-403654588 + 1493606664) ^ -(-1073221760))) ^ ((-1454376204 - -(852412532 - -474161348)) ^ -(-(747647209 - 490029393)))))) * 397122457)) % 3;
					int num5 = -1819597888;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (num5 + 910848034) ^ -1867760426;
						num5 = -(num5 ^ -649493209);
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
						int num9 = -1792815150;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(num9 - -109173829);
							num9 = (num9 - -539838186) * -643036761;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0 == P_1;
					int[] array = new int[6] { -1096888981, -1613438102, -240862034, 1323185590, 357333986, 1168329348 };
					array[4] ^= -67999531;
					array[4] = array[2] ^ 0x67B1E124;
					int[] array2 = new int[4];
					array2[0] = 1788408456;
					array2[1] = -1865403103;
					array2[2] = 1397425889;
					array2[3] = 1520248538;
					array2[3] = array[1] ^ -628733991;
					array2[2] = array2[1] ^ 0x1005E0C8;
					array2[0] = array2[1] ^ -1139282536;
					int num11 = array2[3] ^ -1614452320;
					num = ((int)num4 * -270579394) ^ 0x41FE5B10 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _0026_003D_003E_0040_005E_002B_002F_002B(IAssemblyWorkspaceService P_0, int P_1, bool P_2)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -108634225;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-((-669407279 + (0x545171C8 ^ -2026848478)) * -456605815 - 436970679 * (~(-704545132 ^ 0x40A983FF) - ~(-1137181313 - 194720979)) + (~(-(-420145658 * -986623853)) - (0x5A2C7FDC ^ -452947732)) - -(-(-1983824307 * -959053859) - ~num2)) - -1399350281 * ~(-503443127 ^ -106129891)))) % 3;
					int num5 = 1914921116;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -num5 * -194926419;
						num5 = (num5 * -112253313) ^ 0x399FA873;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 32469961;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -1939401095;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 + 1234898087 * 1832622719);
							num9 = ~(-num9);
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.SetMethodSelection(P_1, P_2);
					int[,] array = new int[4, 3];
					array[0, 0] = 441561241;
					array[0, 1] = -768437380;
					array[0, 2] = -2097281939;
					array[1, 0] = 572754306;
					array[1, 1] = -38921880;
					array[1, 2] = 1267705747;
					array[2, 0] = -478413484;
					array[2, 1] = 619510033;
					array[2, 2] = 77861925;
					array[3, 0] = -461574505;
					array[3, 1] = 1277216923;
					array[3, 2] = -1264876516;
					array[1, 1] = array[0, 1] ^ -1602549884;
					array[3, 2] = array[2, 0] ^ 0x3BA7C664;
					array[1, 2] = array[0, 0] ^ 0x28E9B10F;
					int num11 = array[1, 2] ^ 0x2139384B;
					num = ((int)num4 * -1557821882) ^ 0x37AE81E6 ^ num11;
				}
			}
		}
	}

	static bool _0025_0026__003C_0028_002A_003E_003C(TypeItem P_0)
	{
		bool ısInterface = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 468331234;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-1956212069 * -65791671 * 1850132199 - ~((num2 ^ (-(~(-1498036594 ^ -1758497976)) + -1167853723 * (40569731 - (-(1987442614 - ~(-1855191423) + (-730295421 + ~-2055024905) * -2016085703) - -((0xCEA99BA ^ 0x75842166) + ~(-(-971537501 ^ -388620230))))))) + -(88236625 * -1651009273 + ((1662177157 * ((0x8F2ADD3 ^ --648682846) + -(-1520937489 * 1668018231) - 432872685 * -331013477)) ^ -870330277))) * -1774078953 + ~(~(1500169587 - -1906423157 * -1278214682))) ^ ((-225126666 ^ -34978142) * 1969773923))) % 3;
					int num5 = 1758279480;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * 628027953 - 1312148092;
						num5 = -(-num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1390175995;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~num7;
						num7 = (num7 * -441739613) ^ -145849270;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -307636494;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 - (-2134498329 - 1482468471)) * -1863533471;
							num9 = 1579834929 - (1800510173 - -1401684380 - num9);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ısInterface = P_0.IsInterface;
					int[] array = new int[4] { 352845654, -54238625, 1365529175, -462143425 };
					array[0] ^= 1770915315;
					array[1] ^= 1249541098;
					array[2] = array[0] ^ -1761706020;
					int[] array2 = new int[7] { 1570208258, 107182280, -2071223704, -2017565119, 683381595, -856630659, 1379143413 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][3] ^ 0x2819C61E;
					array2[3] = array2[4] ^ 0x1B1EB0A1;
					array2[3] = array2[6] ^ -116025673;
					int num11 = array3[1][0] ^ -175856361;
					num = (int)((num4 * 1906749241) ^ 0x898111EFu) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ısInterface;
	}

	static bool _002D_0040_003F_0040_003E_0023_002B_003D(TypeItem P_0)
	{
		bool ısValueType = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -340816422;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~((~(num2 * 1133587221) - (-(~(~(~(718404109 - 370882526)))) + -(~(~697556269)) - ((0x1DE9E0D8 ^ (-(-1424746440 + -133080112) + (-362355210 - 1352580064 + (-1212525414 + -1078199840)))) - -1565976352 + -(~(1182684963 * ~(336016540 - 1036661503)))))) * 1326872507) * 1824578995 - 239866659 * -(--2087448251)) * -815327911 - (0x2D8338ED ^ 0x7FB5DAA2))) % 3;
					int num5 = 873843250;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 * 917741775);
						num5 = num5 ^ -1743202561 ^ -1580910067;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -694504960;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 * 1761416457;
						num7 = (num7 * -1713003507) ^ -1049680013;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -93179519;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(~num9);
							num9 = ~num9 * -673369951;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ısValueType = P_0.IsValueType;
					int[,] array = new int[4, 4];
					array[0, 0] = -1960216156;
					array[0, 1] = 1841871983;
					array[0, 2] = 601473529;
					array[0, 3] = 1825960733;
					array[1, 0] = 1301958303;
					array[1, 1] = 1507899949;
					array[1, 2] = 2094984597;
					array[1, 3] = -1977949527;
					array[2, 0] = 160437657;
					array[2, 1] = -841158267;
					array[2, 2] = -1721513134;
					array[2, 3] = -129938491;
					array[3, 0] = 1583612935;
					array[3, 1] = -374762922;
					array[3, 2] = -103818336;
					array[3, 3] = -73046474;
					array[3, 2] = array[1, 0] ^ 0x1A72D387;
					array[3, 1] = array[0, 2] ^ 0x48187E0E;
					array[2, 0] = array[1, 3] ^ -592325861;
					int num11 = array[2, 0] ^ 0x584951C8;
					num = ((int)num4 * -1916992514) ^ 0x1EC00954 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ısValueType;
	}

	static bool _003F_0040_002F_003F_005E__005E_002D(TypeItem P_0)
	{
		bool ısAbstract = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -721897722;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~((-(num2 * -1979990407) + -(1625602625 * (18765595 + -(-(462991066 - 13557578)) - -1163939168))) ^ (((-(-935636461 ^ -534375860) ^ (-(-1051810759 - 390655928) - -(0x733F3EC9 ^ 0x641E3FF3))) + 590526536) * -1566545391))))) % 3;
					int num5 = -211376902;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(num5 * -222934159);
						num5 = (num5 - (-168437707 - 2065165545)) ^ -129878211;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1877848899;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 ^ -692004464) - 859829885;
						num7 = num7 * 379172153 + 1202292168;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -542542262;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= 903145645;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ısAbstract = P_0.IsAbstract;
					int[] array = new int[7];
					array[0] = -1203343184;
					array[1] = -1884205727;
					array[2] = 718809041;
					array[3] = -1756580815;
					array[4] = 722105864;
					array[5] = -80984385;
					array[6] = -1587594739;
					array[6] = array[0] ^ 0x738CC040;
					array[5] = array[1] ^ 0x486EE890;
					array[0] = array[2] ^ -944848677;
					int[] array2 = new int[7];
					array2[0] = -1954451713;
					array2[1] = 1176366858;
					array2[2] = 1000651923;
					array2[3] = 498480050;
					array2[4] = 1616303733;
					array2[5] = 1896943023;
					array2[6] = 1632145536;
					array2[2] = array[4] ^ -1574123001;
					array2[6] = array2[4] ^ 0xE406798;
					array2[1] = array2[0] ^ 0x3D7C3353;
					int num11 = array2[2] ^ 0x37319D55;
					num = (int)((num4 * 487028086) ^ 0x33E8E00A) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ısAbstract;
	}

	static IReadOnlyList<MethodItem> _005E_003D_0021_0028_003C__0024_002A(IAssemblyWorkspaceService P_0, string P_1)
	{
		IReadOnlyList<MethodItem> methodsForType = default(IReadOnlyList<MethodItem>);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1244436646;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(~(1204232503 - -(-(~(num2 * 1689443527 - ~(--415911220))) - (-2017095283 - -187930193 * -(1059901549 * -1096675923))))))) % 3;
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
					int num7 = -70257663;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -70257665;
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
					methodsForType = P_0.GetMethodsForType(P_1);
					int[] array = new int[6];
					array[0] = 684567875;
					array[1] = 472874847;
					array[2] = 414620170;
					array[3] = -194575624;
					array[4] = 1055362045;
					array[5] = -517572259;
					array[2] = array[0] ^ -1564705587;
					array[1] ^= 2063697292;
					array[4] = array[5] ^ -678592504;
					int[] array2 = new int[5] { -140379369, 1119818911, -1763189524, 1366329251, -1910842143 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][3] ^ 0x26DBD369;
					array2[2] = array2[4] ^ -1999817046;
					array2[4] = array2[0] ^ 0x75CCCAF9;
					array2[3] = array2[0] ^ -1503190866;
					int num11 = array3[1][1] ^ -1948758962;
					num = (int)((num4 * 1757792489) ^ 0xE448151Bu) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return methodsForType;
	}

	static bool _0023_002A_0029_0026_0024_0028_0026_003D(string P_0, string P_1, StringComparison P_2)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return P_0.Contains(P_1, P_2);
		}
	}

	static string @_0025_0024_003F_0024_0029_0029_0025(TypeItem P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return P_0.FullName;
		}
	}

	static int @_0023_0025_0025_003C_0040_003D_003D(MethodItem P_0)
	{
		int token = default(int);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -894716241;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(~(-(~(~(-(-num2)) * -78325385)))) ^ 0x41090A7A) * -1852111755)) % 3;
					int num5 = -552231228;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 += 0x49B715DD ^ -1443383149;
						num5 = num5 * -270220379 + -5460652;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 6334553;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = num7 - -1565587409 - -593954858;
						num7 -= 358479607 + -343253712;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2655280;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(~num9);
							num9 = -1327639 - -num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					token = P_0.Token;
					int[] array = new int[5];
					array[0] = -605327457;
					array[1] = -124346739;
					array[2] = 1553940244;
					array[3] = 1852148341;
					array[4] = 414336341;
					array[1] = array[2] ^ 0x398A813C;
					array[4] = array[3] ^ 0x2C2F452B;
					int[] array2 = new int[7] { 736685051, -1010238234, 544840528, -1302202731, 419232499, -1856179970, -775720503 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][3] ^ -2038646829;
					array2[6] = array2[1] ^ 0x71012073;
					array2[4] = array2[0] ^ 0x20FF719A;
					int num11 = array3[1][0] ^ 0x4977B9BE;
					num = (int)((num4 * 2069552362) ^ 0x34B18CE6) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return token;
	}

	static string _0028_002F_0028_003C_002A_002A_0024_0023(MethodItem P_0)
	{
		string name = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1087826470;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(((((-(~(132312895 * -1919308667 + -1471905753 * 2021497699 + ~(-1156039591 ^ 0x1724C551)) + 1939926499 * (360894032 - -173635949 + (563977649 - 1394649142) + -(--1584175779)) - -(-26586725 - (-693834742 - (1482650422 - 302330362) - -1272553501 * ~-1473371903))) - ~num2 * 1077518711) ^ 0x74085C10) * 894155623) ^ 0x2AA3D270) * -1998969873))) % 3;
					int num5 = 1155006446;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * -439087397 - -275581824;
						num5 = num5 ^ 0x1A002139 ^ -689289924;
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
					name = P_0.Name;
					int[,] array = new int[3, 4];
					array[0, 0] = 186509143;
					array[0, 1] = 1547599754;
					array[0, 2] = -1376719639;
					array[0, 3] = 1229809985;
					array[1, 0] = -347438796;
					array[1, 1] = -1843343923;
					array[1, 2] = -2070501896;
					array[1, 3] = -1602012634;
					array[2, 0] = 661157177;
					array[2, 1] = 55100673;
					array[2, 2] = 1181892797;
					array[2, 3] = 173401228;
					array[0, 2] = array[1, 2] ^ 0x5A3F7921;
					array[1, 1] = array[1, 0] ^ 0x1655BE2F;
					array[2, 0] = array[2, 1] ^ -83020199;
					int num11 = array[2, 0] ^ -497715087;
					num = ((int)num4 * -455086261) ^ -1925809129 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return name;
	}

	static string _0028_003D_002A_003E_0023_002F_002B_002D(MethodItem P_0)
	{
		string signature = default(string);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 631851938;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(~(~(~(-(~num2 - (-(-1547464713 * -703807683) - (-477662280 - ~818711971) - ((~1883904744 - --941203064 - ~(~-316763098) - 915786971 * (830660373 - -400305802 + -1460558733 * 1410493321) + ((-1534669569 + -466691474 + -(-1773969426 ^ 0x27E59F8C)) ^ (-(-235364193 - -1862388152) + (1916108442 * 739031413 - (1869791012 + -2039601836))))) ^ -1495406362) - (~1508056788 - 736315679 * (--177437510 - ~(-1156888092 ^ 0xCB20B26) - ((--780006588 + 399567552 * 1144433161) ^ 0x6094A5B1 ^ 0x2B7D3C53)))))))) - (-847445567 - -299327345)) * 2147384459) ^ -1433586699)) % 3;
					int num5 = 2067878750;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 * 84381261 - -1386752164;
						num5 = ~num5 ^ 0x5C4E88BA;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1581428319;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (-602538699 * -776956031 - num7) * 1610856815;
						num7 = (num7 ^ 0x76DA7A97) - 1099932392;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1618968664;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(-1983866157 - num9);
							num9 = num9 * -537769229 * 621050043;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					signature = P_0.Signature;
					int[] array = new int[6] { -1152409976, -793007483, 1965903796, 1966723126, 26043959, -1370633992 };
					array[2] ^= 1218133650;
					array[2] ^= -1566926726;
					array[1] = array[5] ^ 0x272E8F60;
					int[] array2 = new int[4];
					array2[0] = 819624727;
					array2[1] = 23244252;
					array2[2] = 1212086823;
					array2[3] = -151411236;
					array2[0] = array[3] ^ 0x27A3B456;
					array2[2] = array2[3] ^ 0x53FF4117;
					array2[1] ^= -1106610856;
					int num11 = array2[0] ^ -580770914;
					num = (int)((num4 * 999816103) ^ 0x7710F96F) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return signature;
	}

	static bool _0024_0025_0025_002B__002B_0025_003E(MethodItem P_0)
	{
		bool ısSelected = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1837778660;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(~((((((-(~(0x2DD8F1CB ^ -(1414839339 + -1654002348)) + (1814363147 * ~836372474 - -198242939 - 2063802296) + ~-603842500 + -(((165516550 + -218999345 - -1810840517) ^ ~(-737707177)) + ((--1276593344 - -872003763 * -234059263 - ~(-919010880)) ^ ~(-(~1006468548))))) ^ ((-2062434566 + -(651257863 + 1586257497 * (-1194318183 + -1805789258) + (--347832110 ^ 0x472A9405) + --670251925)) ^ 0x2118BF4A)) - num2) * -1568059431) ^ (-1137192954 ^ (((-(-1406825656 ^ 0x4B82C723) + (-(~-860284324) ^ -(2068722227 * -1163316862))) ^ (-1855382211 * ((-1905772118 ^ -540605216) - (-2116671434 ^ -1397603925) + -(1227883569 - 1954652017)))) - (-(1182022252 * 961921789) ^ 0x4F06F79E)))) + (-897714792 ^ --598640278) - -(1488878621 * (-917924828 ^ 0x78D024E0) - (-1547569181 - -2127021053))) ^ 0x1075344A ^ 0x6BF4A231))))) % 3;
					int num5 = 2;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(num5 - (0x5A5C05A3 ^ 0x4B190CB5));
						num5 = num5 - (-511435479 + -1686832574) + -166914038;
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
						int num9 = 927824210;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 + (-1970462985 ^ -1133570326) + 762788666;
							num9 = -(-num9);
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ısSelected = P_0.IsSelected;
					int[,] array = new int[4, 3];
					array[0, 0] = 1024023987;
					array[0, 1] = 1367083120;
					array[0, 2] = -267382841;
					array[1, 0] = -1496612222;
					array[1, 1] = -1922919246;
					array[1, 2] = -1852862270;
					array[2, 0] = 979348033;
					array[2, 1] = 1413030624;
					array[2, 2] = 1586579008;
					array[3, 0] = -1872725275;
					array[3, 1] = 512787273;
					array[3, 2] = 62480103;
					array[1, 2] = array[1, 0] ^ -1331556153;
					array[3, 1] = array[0, 2] ^ -661734686;
					array[3, 2] = array[0, 2] ^ 0x25FA541F;
					int num11 = array[3, 2] ^ -457878118;
					num = (int)((num4 * 1385718954) ^ 0x917FC2C0u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ısSelected;
	}

	static bool _0024__0021_0024_005E_0024_0025_005E(MethodItem P_0)
	{
		bool ısPreselected = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1457238515;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(-(782910011 * -1286484935 - (-855108629 + 2035058902))) - -(num2 * 508118483 * -477965995 * -445396239 * 1082178739)) ^ -1028677413)) % 3;
					int num5 = -884162342;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 * -590234309);
						num5 = -(num5 + (0x42D6E662 ^ 0x27E3742D));
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1173325367;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 - 1592910796) * -587785905;
						num7 = -num7 ^ -877172141;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 16;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9 ^ -310426431;
							num9 = ~num9 ^ -487482266;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					ısPreselected = P_0.IsPreselected;
					int[] array = new int[7];
					array[0] = 1850556939;
					array[1] = -1526313483;
					array[2] = 273177139;
					array[3] = 2032991189;
					array[4] = 733135315;
					array[5] = 769695438;
					array[6] = 113416020;
					array[4] = array[6] ^ 0x758FB741;
					array[0] = array[4] ^ -1641093727;
					int[] array2 = new int[5];
					array2[0] = 777293362;
					array2[1] = -840021514;
					array2[2] = 1918852111;
					array2[3] = -164281740;
					array2[4] = -96182441;
					array2[1] = array[6] ^ 0x147AFF55;
					array2[4] = array2[1] ^ -88675294;
					array2[2] = array2[1] ^ -501940247;
					array2[2] = array2[0] ^ 0x1B41CCE5;
					int num11 = array2[1] ^ 0x5B28E45A;
					num = (int)((num4 * 1763448511) ^ 0x39AACBFD) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return ısPreselected;
	}
}
