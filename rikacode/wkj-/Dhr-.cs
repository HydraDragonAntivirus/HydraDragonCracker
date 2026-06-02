using System;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using RikaNET.Core.Models;
using RikaNET.Core.Services;
using RikaNET.WinUI.Services;

namespace wkj_003D;

public sealed class Dhr_003D : IAuthenticationService
{
	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CCheckLicenseAsync_003Ed__27 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder<string> _003C_003Et__builder;

		public Dhr_003D _003C_003E4__this;

		public string license;

		public string hardwareId;

		public CancellationToken cancellationToken;

		private HttpClient _003Cclient_003E5__2;

		private ConfiguredTaskAwaitable<string>.ConfiguredTaskAwaiter _003C_003Eu__1;

		[MethodImpl(MethodImplOptions.NoInlining)]
		private void MoveNext()
		{
			object[] array = default(object[]);
			try
			{
				array = new object[1] { this };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OD1qb2dnOGZeXwJZWF5bcF4=", array);
			}
			finally
			{
				this = (_003CCheckLicenseAsync_003Ed__27)array[0];
			}
		}

		void IAsyncStateMachine.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			this.MoveNext();
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		[DebuggerHidden]
		private void SetStateMachine(IAsyncStateMachine stateMachine)
		{
			object[] array = default(object[]);
			try
			{
				array = new object[2] { this, stateMachine };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZjEwOzZgMWQCA3JTBAIHLQI=", array);
			}
			finally
			{
				this = (_003CCheckLicenseAsync_003Ed__27)array[0];
			}
		}

		void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
			this.SetStateMachine(stateMachine);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static HttpRequestHeaders __005E_003E_003D_0040_0024_0028_003F(HttpClient P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (HttpRequestHeaders)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NmJgZmE3MGVTUj/IVVNWY1M=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static HttpHeaderValueCollection<ProductInfoHeaderValue> _002F_002B_002F_002A_002B_003E__003F(HttpRequestHeaders P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (HttpHeaderValueCollection<ProductInfoHeaderValue>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Mj0/bz1vOzkLCmZoDQsOOgs=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static Task<string> _002F_0023_002A_0024_0025__0029_0023(HttpClient P_0, string P_1, CancellationToken P_2)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { P_0, P_1, P_2 };
			return (Task<string>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YTRhZzZkNjZXVjkiUVdSZVc=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static void @_0024_002B_0025__002F_005E_003C(IDisposable P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MmJmYTU1NTYEBWulAgQBNwQ=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}
	}

	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CResetHardwareIdAsync_003Ed__28 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder<string> _003C_003Et__builder;

		public string license;

		public Dhr_003D _003C_003E4__this;

		public CancellationToken cancellationToken;

		private HttpClient _003Cclient_003E5__2;

		private ConfiguredTaskAwaitable<HttpResponseMessage>.ConfiguredTaskAwaiter _003C_003Eu__1;

		private ConfiguredTaskAwaitable<string>.ConfiguredTaskAwaiter _003C_003Eu__2;

		[MethodImpl(MethodImplOptions.NoInlining)]
		private void MoveNext()
		{
			object[] array = default(object[]);
			try
			{
				array = new object[1] { this };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YmAzZWBtMTdVVCZWU1VQFVU=", array);
			}
			finally
			{
				this = (_003CResetHardwareIdAsync_003Ed__28)array[0];
			}
		}

		void IAsyncStateMachine.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			this.MoveNext();
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		[DebuggerHidden]
		private void SetStateMachine(IAsyncStateMachine stateMachine)
		{
			object[] array = default(object[]);
			try
			{
				array = new object[2] { this, stateMachine };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZDJjaGVlNTVRUMMrV1FUEFE=", array);
			}
			finally
			{
				this = (_003CResetHardwareIdAsync_003Ed__28)array[0];
			}
		}

		void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
			this.SetStateMachine(stateMachine);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static HttpRequestHeaders _003F_002F_003D_0024_0023_0040_0026_003C(HttpClient P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (HttpRequestHeaders)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OThsNjg4bDYPDoRqCQ8KTQ8=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static HttpHeaderValueCollection<ProductInfoHeaderValue> _003D_0023_005E_0024_0023_003F_002D_0029(HttpRequestHeaders P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (HttpHeaderValueCollection<ProductInfoHeaderValue>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("M2ExZGRiY2ZVVNl4U1VQFlU=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static string _0025_0024_003D_0025_0024_002A_003C_0024(string P_0, string P_1)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
			return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MTdkMTVmNDQFBIn8AwUAQQU=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static Task<HttpResponseMessage> _0029_0023_0024_003F_002A_0021_003D_(HttpClient P_0, string P_1, HttpContent P_2, CancellationToken P_3)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[4] { P_0, P_1, P_2, P_3 };
			return (Task<HttpResponseMessage>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Mzk+PG9qbjgLCoUiDQsOTgs=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static HttpContent _0024_002B_005E_0028_002A_005E_0028_003C(HttpResponseMessage P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (HttpContent)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MmFjZjk4ZDIAAY/JBgAFRgA=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static Task<string> _003C_005E_002A_005E_005E_0024_0028_003F(HttpContent P_0, CancellationToken P_1)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
			return (Task<string>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OWNkZjAzMjkAAZCRBgAFRwA=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static void _002B_0026_003D_0029_003F_003D_0029_0028(IDisposable P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OTpra2g7aDMKC5vADAoPQgo=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}
	}

	[StructLayout(LayoutKind.Auto)]
	[CompilerGenerated]
	private struct _003CResolveEndpointAsync_003Ed__31 : IAsyncStateMachine
	{
		public int _003C_003E1__state;

		public AsyncTaskMethodBuilder<string> _003C_003Et__builder;

		public CancellationToken cancellationToken;

		private ConfiguredTaskAwaitable<HttpResponseMessage>.ConfiguredTaskAwaiter _003C_003Eu__1;

		[MethodImpl(MethodImplOptions.NoInlining)]
		private void MoveNext()
		{
			object[] array = default(object[]);
			try
			{
				array = new object[1] { this };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ODQzOWcxMjkBAJYjBwEESAE=", array);
			}
			finally
			{
				this = (_003CResolveEndpointAsync_003Ed__31)array[0];
			}
		}

		void IAsyncStateMachine.MoveNext()
		{
			//ILSpy generated this explicit interface implementation from .override directive in MoveNext
			this.MoveNext();
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		[DebuggerHidden]
		private void SetStateMachine(IAsyncStateMachine stateMachine)
		{
			object[] array = default(object[]);
			try
			{
				array = new object[2] { this, stateMachine };
				_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("Y2BiNjAxYjBTUvU3VVNWGVM=", array);
			}
			finally
			{
				this = (_003CResolveEndpointAsync_003Ed__31)array[0];
			}
		}

		void IAsyncStateMachine.SetStateMachine(IAsyncStateMachine stateMachine)
		{
			//ILSpy generated this explicit interface implementation from .override directive in SetStateMachine
			this.SetStateMachine(stateMachine);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static string _0023_003C__0021_0040__002A_003D(string P_0, string P_1)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { P_0, P_1 };
			return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ZDI1OWNgMWUBAKMlBwEESgE=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static Task<HttpResponseMessage> _0028_0028_0024_002B_002B_0024_0040_0024(HttpClient P_0, string P_1, CancellationToken P_2)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { P_0, P_1, P_2 };
			return (Task<HttpResponseMessage>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MWIyNjY4MDEAAaOHBgAFTAA=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static bool __0024_0029_0025_0021_003F_003D_0026(HttpResponseMessage P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			return (bool)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YjJgMmYwZTZUVfD7UlRRGVQ=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}

		[MethodImpl(MethodImplOptions.NoInlining)]
		static void _003D_0024_005E_0021_0026_0025_003C_0026(IDisposable P_0)
		{
			object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
			_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YzUzYz4zMWUGB6OyAAYDSAY=", _0024_0029_0024_002A_0021_002F_0021_005E);
		}
	}

	private static readonly HttpClient yTK_003D = lwR_003D();

	private static readonly HttpClient Fwv_003D = DAg_003D();

	private readonly wgc_003D yGp_003D;

	private readonly ISettingsStore Kjr_003D;

	private bool HYP_003D;

	[CompilerGenerated]
	private string? jud_003D;

	public string? FJp_003D
	{
		[CompilerGenerated]
		get
		{
			return jud_003D;
		}
		[CompilerGenerated]
		private set
		{
			jud_003D = value;
		}
	}

	internal string ILZ_003D => yGp_003D.ILZ_003D;

	internal string[] yVP_003D => yGp_003D.yVP_003D;

	public Dhr_003D(wgc_003D iso_003D, ISettingsStore BJM_003D)
	{
		while (true)
		{
			int num = -1628618471;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~((~(num2 ^ -((-2052790041 + -(~(~(-327838964 ^ -1160720018)) - (-1128667868 - (--711655247 - (-1608325789 + -1986354251))))) ^ (902077845 * (-(~(1257166045 - -1846987378 - ~2055216760)) - ~(~(-1904424940 ^ -1495704765) + (857929273 - 1799667352) * 1002256761))) ^ ((-703296586 * -642678557) ^ ((-((-576465484 ^ 0x1115CB89) - (1644477386 + 1047104918) + (0x7A7BD6E4 ^ 0x7924D41D)) + 1439948785) ^ -((-946885093 ^ 0x71D9B59) - -73158820))))) ^ (582427540 - ((-524249387 * -(~1580541755 - (748159268 + -2115033591)) + (~(1330531929 - -1432957008 - -1035766690) + ~-855069214)) ^ -315374926))) * 851433313 * -1567224505))) % 4;
				int num5 = 0;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~(num5 ^ 0x7B9F9CF1);
					num5 = num5 ^ 0x696FD721 ^ 0x7A03EC3F;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1482758075;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 = -num7 * 1814254293;
					num7 = num7 * 1903592519 * 611442841;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -2095387522;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 *= -1154516545;
					}
					if (num3 != (uint)num9)
					{
						int num11 = 246678060;
						_ = 0;
						for (int num12 = 0; num12 < 1; num12++)
						{
							num11 = 246678061 - num11;
						}
						if (num3 == (uint)num11)
						{
						}
						return;
					}
					Kjr_003D = BJM_003D;
					int[] array = new int[5] { -1398911923, -1987439754, 1981066890, -744080523, 285304634 };
					array[1] ^= -295906762;
					array[1] ^= -2049913889;
					array[2] = array[1] ^ 0x47B64C8C;
					int[] array2 = new int[4];
					array2[0] = -1031548986;
					array2[1] = 1689724499;
					array2[2] = -1485743911;
					array2[3] = -135759800;
					array2[3] = array[0] ^ 0x5A46B66D;
					array2[0] = array2[3] ^ 0x48CEBFD0;
					array2[1] = array2[3] ^ 0x4EA85546;
					array2[0] = array2[2] ^ -1417605959;
					int num13 = array2[3] ^ -273915489;
					num = ((int)num4 * -1075407488) ^ -1699324160 ^ num13;
				}
				else
				{
					yGp_003D = iso_003D;
					int[] array3 = new int[5];
					array3[0] = 1056096809;
					array3[1] = -1961633825;
					array3[2] = -1843314871;
					array3[3] = 1312681169;
					array3[4] = -641235534;
					array3[4] = array3[0] ^ 0x73E02C5C;
					array3[4] = array3[0] ^ -1675535454;
					int[] array4 = new int[5];
					array4[0] = -1397366220;
					array4[1] = -1693294159;
					array4[2] = 815017781;
					array4[3] = 1295154476;
					array4[4] = -845892793;
					array4[0] = array3[1] ^ -515999855;
					array4[3] = array4[2] ^ -1652490954;
					array4[2] = array4[4] ^ -760002550;
					int num14 = array4[0] ^ 0x629A230;
					num = (int)((num4 * 603279876) ^ 0x567AADCC) ^ num14;
				}
			}
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[AsyncStateMachine(typeof(_003CInitializeAsync_003Ed__13))]
	public Task<AuthBootstrapState> InitializeAsync(CancellationToken yDB_003D)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { this, yDB_003D };
		return (Task<AuthBootstrapState>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NGYxOzo6ZTcDAlJgBQMGCwM=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[AsyncStateMachine(typeof(_003CSignInAsync_003Ed__14))]
	public Task<AuthResult> SignInAsync(string eNJ_003D, bool JCJ_003D, CancellationToken RBU_003D)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[4] { this, eNJ_003D, JCJ_003D, RBU_003D };
		return (Task<AuthResult>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YjIzO2dhMGEDAlAbBQMGCgM=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	public void SignOut()
	{
		FJp_003D = null;
	}

	private static HttpClient lwR_003D()
	{
		HttpClient httpClient = new HttpClient();
		_0024_003C_003E_002A_002D_0023_002F_0021(httpClient, _0025_0021_005E_003F_0028_0021_002A_005E(10.0));
		_003E_0040_002D_0021_0024_005E_0028_0028(_003D_0024_002F_0025_003E_003D_002D_003F(httpClient)).ParseAdd(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xC083 ^ 0xC150]);
		return httpClient;
	}

	private static HttpClient DAg_003D()
	{
		HttpClient httpClient = new HttpClient();
		_0024_003C_003E_002A_002D_0023_002F_0021(httpClient, _0025_0021_005E_003F_0028_0021_002A_005E(2.0));
		_003E_0040_002D_0021_0024_005E_0028_0028(_003D_0024_002F_0025_003E_003D_002D_003F(httpClient)).ParseAdd(_002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[597 - 36 - 45 - 49]);
		return httpClient;
	}

	private static string pRZ_003D(string LPl_003D)
	{
		string text = KIV_003D(_0021_003E_0028_003D_003F_002A_0021_(_002A_0025_0026__0025_005E_0029_003D(_002F_003D_003D_005E_0029_003F_005E_003C(), LPl_003D)));
		return _0028_0040_0040_0026_0028_0026_0023_002F(_0021_003E_0028_003D_003F_002A_0021_(_002A_0025_0026__0025_005E_0029_003D(_002F_003D_003D_005E_0029_003F_005E_003C(), text)));
	}

	private static string? GxV_003D(string iCK_003D)
	{
		string result = default(string);
		try
		{
			string text = KIV_003D(_0021_0024_002F__002A_0023_002B_003F(_002F_003D_003D_005E_0029_003F_005E_003C(), _0026_0026_0029_0024_0029_005E__003F(iCK_003D)));
			while (true)
			{
				int num = -782997038;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(-(num2 ^ (~(~(~(~(-816982899) ^ -991215762))) - ~(-(~(-2092027477 * -1691478133) + (1471355740 + -1022752106 + (238702803 - -1369781822)) - ~-1185132246 + ~365276300)) + ~(~(~(~(~103034216)) - 557699707 + ~(-1745313061) + ((2019021423 + -(-2144770266 - 1532658439)) ^ -1912460948))))) - (~(~((0x3F91A086 ^ 0x2D7158C6) * -1718355667) + (-(~(-70462169 * 2081798145)) ^ -40829603)) + (-198392203 * (-(607293405 * (-1014731463 * 953032084)) + (-45502358 - (-769866962 - -1528497375) - -1980316756)) - -41143959))) - -827036608 + (-((-2044968965 ^ 0x4173D49C) - (-1949442361 - 489851167)) ^ ((-1400018090 * -2138588307) ^ -2046874297)) - -(-1920618965 * -613605963)))) % 3;
					int num5 = 1382113870;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~num5 * 824121131;
						num5 = (num5 * -530233871) ^ 0x71A1AC36;
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
						int num9 = 37367410;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -num9 ^ -76731676;
							num9 = ~num9 * 954705295;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_001c;
					}
					result = _0021_0024_002F__002A_0023_002B_003F(_002F_003D_003D_005E_0029_003F_005E_003C(), _0026_0026_0029_0024_0029_005E__003F(text));
					int[] array = new int[6];
					array[0] = 877421374;
					array[1] = 540947516;
					array[2] = 1054193985;
					array[3] = -706558556;
					array[4] = -1977043204;
					array[5] = -1661896643;
					array[2] = array[4] ^ 0x2077DFF4;
					array[3] = array[2] ^ -1807939925;
					int[] array2 = new int[5] { -101002103, -1176913217, -950845074, 1988046033, -1828712358 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][4] ^ -782765138;
					array2[2] = array2[1] ^ 0xC80CD21;
					array2[3] = array2[1] ^ 0x230DD4D7;
					int num11 = array3[1][0] ^ -1379502575;
					num = (int)((num4 * 1693247487) ^ 0x7B9D6E5E) ^ num11;
				}
				continue;
				end_IL_001c:
				break;
			}
		}
		catch
		{
			result = null;
		}
		return result;
	}

	private static string KIV_003D(string cqv_003D)
	{
		char[] array = _002D_005E_0021_0028_003F_003C_002B_(cqv_003D);
		int num33 = default(int);
		char c = default(char);
		while (true)
		{
			int num = -1481677138;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(~(~num2 - -(((-(-1581400682 - 1089884111) - 965012797) ^ (0x2660B36D ^ -(-731527318 ^ --574219258))) + -(361918991 * ~(--108741869 ^ -2079794303)) - (~(0x139D992E ^ -556663472) + -1766896422 - -(((-815662848 ^ -103429400) + (37015396 - 385382474)) * 1445281921) + ((-(~(-111915138)) - -(~(-1497316566 + -2140672098))) ^ -432967910)))) - (455727586 + -1463522419 * (-396873541 * (1867889665 * -(0x2023DDA ^ 0x2EEE2AC8))))))) % 14;
				int num5 = 2118370947;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 += -2118370945;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 519486549;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 ^= 0x1EF6BC59;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 1145702484;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = num9 * -638690521 + -1731620624;
						num9 = num9 - (1717319248 - 1070458258) - 1493128684;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -203422770;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = ~num11 ^ 0x71CDFD9D;
							num11 = -num11 + 659018645;
						}
						if (num3 != (uint)num11)
						{
							int num13 = -12;
							_ = 0;
							for (int num14 = 0; num14 < 1; num14++)
							{
								num13 = ~num13;
							}
							if (num3 != (uint)num13)
							{
								int num15 = -7;
								_ = 0;
								for (int num16 = 0; num16 < 1; num16++)
								{
									num15 = -num15;
								}
								if (num3 != (uint)num15)
								{
									int num17 = -1919881941;
									_ = 0;
									for (int num18 = 0; num18 < 2; num18++)
									{
										num17 = num17 * 1814600543 * 985714263;
										num17 = ~(num17 + (177173834 + -2028291862));
									}
									if (num3 != (uint)num17)
									{
										int num19 = -394377014;
										_ = 0;
										for (int num20 = 0; num20 < 2; num20++)
										{
											num19 = ~(num19 - (87061829 + 848802892));
											num19 = 475001467 - num19 - 1489431885;
										}
										if (num3 != (uint)num19)
										{
											int num21 = 549721963;
											_ = 0;
											for (int num22 = 0; num22 < 1; num22++)
											{
												num21 *= -1752933053;
											}
											int num41;
											if (num3 != (uint)num21)
											{
												int num23 = -878246127;
												_ = 0;
												for (int num24 = 0; num24 < 2; num24++)
												{
													num23 = (num23 - ~-246471207) * -1930303289;
													num23 = -num23;
												}
												if (num3 != (uint)num23)
												{
													int num25 = 776065368;
													_ = 0;
													for (int num26 = 0; num26 < 2; num26++)
													{
														num25 = num25 + --1252021570 + -1089867445;
														num25 = (num25 * 1314078153) ^ 0x2FB614DF;
													}
													if (num3 != (uint)num25)
													{
														int num27 = -1526584647;
														_ = 0;
														for (int num28 = 0; num28 < 2; num28++)
														{
															num27 = ~num27 ^ 0x7A93DD80;
															num27 = num27 * -1775742827 - -2067629706;
														}
														if (num3 != (uint)num27)
														{
															int num29 = 274737920;
															_ = 0;
															for (int num30 = 0; num30 < 1; num30++)
															{
																num29 -= 274737911;
															}
															if (num3 != (uint)num29)
															{
																int num31 = -636601096;
																_ = 0;
																for (int num32 = 0; num32 < 2; num32++)
																{
																	num31 = (num31 ^ 0x4543E0D8) + -743122177;
																	num31 *= 1915075591;
																}
																if (num3 != (uint)num31)
																{
																}
																return new string(array);
															}
															int num34;
															if (num33 >= array.Length)
															{
																num = -955360006;
																num34 = num;
															}
															else
															{
																num = -837053660;
																num34 = num;
															}
														}
														else
														{
															num33++;
															num = -696856707;
														}
													}
													else
													{
														array[num33] = (char)((c > 'M') ? (c - 13) : (c + 13));
														num = -1496471639;
													}
													continue;
												}
												char num35 = c;
												int[] array2 = new int[4] { 511778687, 1320919750, 698922920, -374060369 };
												array2[0] ^= 272591450;
												array2[2] ^= -1411132033;
												int[] array3 = new int[4] { 913503927, -327999934, -2074451478, -1709652274 };
												int[][] array4 = new int[2][] { array2, array3 };
												array3[0] = array4[0][1] ^ -1325596125;
												array3[2] = array3[3] ^ -1343480340;
												array3[1] = array3[2] ^ -862096982;
												int num36 = array4[1][0] ^ 0x588B074C;
												int[,] array5 = new int[4, 3];
												array5[0, 0] = -1297585540;
												array5[0, 1] = -448726443;
												array5[0, 2] = -1234875973;
												array5[1, 0] = 4320169;
												array5[1, 1] = -1062434553;
												array5[1, 2] = 1409907986;
												array5[2, 0] = 919538310;
												array5[2, 1] = -1157074157;
												array5[2, 2] = 312850709;
												array5[3, 0] = 59124397;
												array5[3, 1] = -1090887141;
												array5[3, 2] = -1996413657;
												array5[3, 0] = array5[3, 2] ^ 0x53139924;
												array5[0, 2] = array5[3, 0] ^ 0x3365C921;
												array5[1, 1] = array5[3, 2] ^ 0x77DFA3CF;
												array5[1, 2] = array5[3, 1] ^ -675984084;
												int num37 = array5[1, 2] ^ -1229379687;
												int num38 = ((int)num4 * -368607682) ^ 0x6AD4E2CE;
												num36 ^= num38;
												num37 ^= num38;
												int num39;
												int num40;
												if (num35 <= 'Z')
												{
													num39 = num37;
													num40 = num39;
												}
												else
												{
													num39 = num36;
													num40 = num39;
												}
												num = num39 ^ num38;
											}
											else if (c >= 'A')
											{
												num = -1359723915;
												num41 = num;
											}
											else
											{
												num = -1496471639;
												num41 = num;
											}
										}
										else
										{
											int[] array6 = new int[5];
											array6[0] = 2142671651;
											array6[1] = -1520612717;
											array6[2] = 702794540;
											array6[3] = 2055278761;
											array6[4] = 731646112;
											array6[4] = array6[2] ^ 0x7A50FC33;
											array6[4] = array6[1] ^ 0x3AA7DEBF;
											int[] array7 = new int[5];
											array7[0] = 1251539997;
											array7[1] = 1658264288;
											array7[2] = -789832095;
											array7[3] = 1813322546;
											array7[4] = 137988827;
											array7[1] = array6[3] ^ -1460979157;
											array7[0] = array7[1] ^ 0x519516C8;
											array7[2] = array7[4] ^ -1714360742;
											array7[0] = array7[4] ^ 0x25DB0D86;
											int num42 = array7[1] ^ 0x74A78D2B;
											num = (int)((num4 * 369040361) ^ 0x448AA3FE) ^ num42;
										}
									}
									else
									{
										array[num33] = (char)((c > 'm') ? (c - 13) : (c + 13));
										num = -730315808;
									}
								}
								else
								{
									char num43 = c;
									int[,] array8 = new int[3, 4];
									array8[0, 0] = -1626987011;
									array8[0, 1] = -1297303527;
									array8[0, 2] = -498413515;
									array8[0, 3] = -609310704;
									array8[1, 0] = -2054908200;
									array8[1, 1] = -1658476005;
									array8[1, 2] = 353225570;
									array8[1, 3] = -1417560069;
									array8[2, 0] = -1598770286;
									array8[2, 1] = -1618885331;
									array8[2, 2] = 1483280570;
									array8[2, 3] = 1395394612;
									array8[2, 0] = array8[2, 1] ^ -1070611807;
									array8[1, 1] = array8[0, 0] ^ -1126810295;
									array8[1, 3] = array8[1, 2] ^ -1550962956;
									int num44 = array8[1, 3] ^ 0x1757E84B;
									int[] array9 = new int[4] { 164625982, 1515639238, 859054433, -920918757 };
									array9[0] ^= -1656424852;
									array9[3] = array9[1] ^ 0x380AE39;
									int[] array10 = new int[5];
									array10[0] = 1911942014;
									array10[1] = -196480712;
									array10[2] = -1573399485;
									array10[3] = -1291610980;
									array10[4] = -1127837295;
									array10[3] = array9[2] ^ -1143497350;
									array10[4] = array10[0] ^ -2018717127;
									array10[0] = array10[1] ^ 0x5EE19736;
									array10[1] = array10[0] ^ 0x54A56910;
									int num45 = array10[3] ^ 0x46BBC886;
									int num46 = (int)((num4 * 735477726) ^ 0x54C1A54A);
									num44 ^= num46;
									num45 ^= num46;
									int num47;
									int num48;
									if (num43 <= 'z')
									{
										num47 = num45;
										num48 = num47;
									}
									else
									{
										num47 = num44;
										num48 = num47;
									}
									num = num47 ^ num46;
								}
							}
							else
							{
								char num49 = c;
								int[] array11 = new int[7];
								array11[0] = 731617995;
								array11[1] = -1490288808;
								array11[2] = -1117972276;
								array11[3] = -652191037;
								array11[4] = -2062388719;
								array11[5] = 195011841;
								array11[6] = 1173763456;
								array11[1] = array11[5] ^ -1712082808;
								array11[2] = array11[1] ^ 0x4DB60E5F;
								int[] array12 = new int[6];
								array12[0] = 1774103392;
								array12[1] = -203545833;
								array12[2] = -422082762;
								array12[3] = -1775984598;
								array12[4] = 1582730014;
								array12[5] = 511746454;
								array12[1] = array11[4] ^ 0x45B3AE59;
								array12[0] = array12[2] ^ 0x57257D28;
								array12[0] = array12[5] ^ 0x23D50070;
								array12[3] = array12[1] ^ -198428321;
								int num50 = array12[1] ^ 0x6175D195;
								int[,] array13 = new int[4, 3];
								array13[0, 0] = 1778278779;
								array13[0, 1] = -1837589606;
								array13[0, 2] = 1893891313;
								array13[1, 0] = -356037472;
								array13[1, 1] = -108076819;
								array13[1, 2] = 486684342;
								array13[2, 0] = 251848439;
								array13[2, 1] = -306960806;
								array13[2, 2] = 648974455;
								array13[3, 0] = 93747637;
								array13[3, 1] = 1956067611;
								array13[3, 2] = 2071059167;
								array13[1, 0] = array13[3, 1] ^ -799236382;
								array13[3, 1] = array13[0, 0] ^ 0x7911DD43;
								array13[0, 2] = array13[2, 0] ^ 0x1985A516;
								int num51 = array13[0, 2] ^ -45682846;
								int num52 = (int)((num4 * 277017372) ^ 0x294A736C);
								num50 ^= num52;
								num51 ^= num52;
								int num53;
								int num54;
								if (num49 >= 'a')
								{
									num53 = num51;
									num54 = num53;
								}
								else
								{
									num53 = num50;
									num54 = num53;
								}
								num = num53 ^ num52;
							}
						}
						else
						{
							c = array[num33];
							num = -914887711;
						}
					}
					else
					{
						int[] array14 = new int[7];
						array14[0] = -308000288;
						array14[1] = 158081311;
						array14[2] = 1459947980;
						array14[3] = -1360745489;
						array14[4] = -850784239;
						array14[5] = -1879161095;
						array14[6] = -2068652166;
						array14[0] = array14[2] ^ -1371519225;
						array14[3] = array14[5] ^ 0x779B713;
						int[] array15 = new int[7];
						array15[0] = 1775420226;
						array15[1] = -128415676;
						array15[2] = -584121044;
						array15[3] = 4381581;
						array15[4] = 531034375;
						array15[5] = -1420501562;
						array15[6] = -431897114;
						array15[2] = array14[1] ^ 0xB2DF26D;
						array15[6] = array15[3] ^ -573772793;
						array15[6] = array15[2] ^ -580957776;
						int num55 = array15[2] ^ -734585841;
						num = (int)((num4 * 1640558708) ^ 0xC3E9ED60u) ^ num55;
					}
				}
				else
				{
					num33 = 0;
					int[] array16 = new int[6];
					array16[0] = 1719930868;
					array16[1] = -1923562061;
					array16[2] = -1988630151;
					array16[3] = 1226765221;
					array16[4] = -586679503;
					array16[5] = -1095474518;
					array16[1] = array16[0] ^ 0x3725EBC5;
					array16[2] = array16[3] ^ -2101728096;
					array16[1] = array16[5] ^ 0x2BE2BF74;
					int[] array17 = new int[4];
					array17[0] = 1257990510;
					array17[1] = -2144565217;
					array17[2] = 1193886970;
					array17[3] = -1209644753;
					array17[0] = array16[5] ^ -149184724;
					array17[2] = array17[3] ^ 0x5304152D;
					array17[1] ^= 1684444440;
					array17[3] = array17[0] ^ -504540430;
					int num56 = array17[0] ^ -387438480;
					num = (int)((num4 * 483724201) ^ 0x75B41C80) ^ num56;
				}
			}
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static string MUb_003D()
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[0];
		return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YWExNGVgMWUEBVEWAgQBFgQ=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	private string? cRo_003D()
	{
		if (!_003C_0024_0026_0026_0028_0023_0040_0028(Kjr_003D, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[-(-(0x1285E ^ 0x1292D))], false))
		{
			uint num2;
			int num4;
			do
			{
				int num = 1937986951;
				uint num3;
				num2 = (num3 = (uint)(~(-(((((num - -((174888659 * -1933060347) ^ -723063870)) ^ 0x4C4EAA6F) - ~(~(30554767 * -(~(~(1477682891 - 1820585441)))))) ^ 0x1EE6FF2C) * 1746168853 - -(-588600329 + (-631184135 + -374302991) + -1106435597) - -1331147779 * ((-1894063205 - 2117202348) * 1909018037))))) % 3;
				num4 = -3;
				_ = 0;
				for (int num5 = 0; num5 < 1; num5++)
				{
					num4 = ~num4;
				}
			}
			while (num2 == (uint)num4);
			int num6 = 966247553;
			_ = 0;
			for (int num7 = 0; num7 < 1; num7++)
			{
				num6 *= 287079297;
			}
			if (num2 == (uint)num6)
			{
				return null;
			}
			int num8 = -1764705896;
			_ = 0;
			for (int num9 = 0; num9 < 2; num9++)
			{
				num8 = -num8;
				num8 = (num8 ^ -625724004) * -1778209587;
			}
			if (num2 == (uint)num8)
			{
			}
		}
		return _002F_003F_0028_0024_002F_003D_002A_0023(Kjr_003D, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0x2DE1 ^ 0x2C93]);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[AsyncStateMachine(typeof(_003CCheckLicenseAsync_003Ed__27))]
	private Task<string> UMQ_003D(string QBm_003D, string CXM_003D, CancellationToken xCJ_003D)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[4] { this, QBm_003D, CXM_003D, xCJ_003D };
		return (Task<string>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YWJiZWdjYTJTUgkWVVNWR1M=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[AsyncStateMachine(typeof(_003CResetHardwareIdAsync_003Ed__28))]
	private Task<string> WRG_003D(string eDY_003D, CancellationToken sBN_003D)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { this, eDY_003D, sBN_003D };
		return (Task<string>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("ND89ND41aTgMDX07CgwJGQw=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[AsyncStateMachine(typeof(_003CRikaNET_002DCore_002DServices_002DIAuthenticationService_002DResetHardwareIdAsync_003Ed__29))]
	Task<AuthResult> IAuthenticationService.ResetHardwareIdAsync(string RnZ_003D, CancellationToken Lvi_003D)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[3] { this, RnZ_003D, Lvi_003D };
		return (Task<AuthResult>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MzNiM29gbmVWV8X9UFZTQFY=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	private void lRh_003D(string JAt_003D, bool Imf_003D)
	{
		_003D_005E_0023_0025_0040_005E_0040_0024(Kjr_003D, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[0xA730 ^ 0xA643], Imf_003D);
		while (true)
		{
			int num = -1835710235;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)(~(~(~((-(~num2 + ~(0x48DC80E5 ^ ((-778160445 ^ -1393107163) + (~1112118541 * -1221438443 - -(--933370851) + -(-786531491 * (-1914269409 ^ 0x775B0A20))) + ~((0x1B62853 ^ 0x376B34B1) + (-1846476197 * -104367641 - 1532478344) + -(~-358271236 + (-1586420262 - -625648603)))))) - ~(-684786747)) ^ (-1246585488 + -1214254051 - ~(537522960 * -1789565929) + 1616727321 * (-173481518 + 2028659574 + 67072185) - -1815836223 * -(792180601 * (1253976290 + 1669352671))))) - (~-1383454313 + -1070361478)))) % 6;
				int num5 = 2139395480;
				_ = 0;
				for (int num6 = 0; num6 < 1; num6++)
				{
					num5 -= 2139395476;
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = -1063427549;
				_ = 0;
				for (int num8 = 0; num8 < 2; num8++)
				{
					num7 *= -940655649;
					num7 = num7 ^ 0x37D2FBA6 ^ 0x5703D137;
				}
				if (num3 != (uint)num7)
				{
					int num9 = 103037150;
					_ = 0;
					for (int num10 = 0; num10 < 2; num10++)
					{
						num9 = ~num9 - -735014452;
						num9 = num9 * 352339093 - -448398224;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -132250523;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = (num11 ^ -1421064180) - 1947140661;
							num11 = ~(~num11);
						}
						if (num3 == (uint)num11)
						{
							return;
						}
						int num13 = -1820773152;
						_ = 0;
						for (int num14 = 0; num14 < 2; num14++)
						{
							num13 = (0x4D07F469 ^ 0x3B1D2B21) - num13;
							num13 = -num13 * 739261683;
						}
						if (num3 != (uint)num13)
						{
							int num15 = 1;
							_ = 0;
							for (int num16 = 0; num16 < 2; num16++)
							{
								num15 = -(num15 - -1788122696);
								num15 = -(-num15);
							}
							if (num3 == (uint)num15)
							{
							}
							return;
						}
						_002A_002D_0024_0029_0025_005E_003D_0024(Kjr_003D, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[498 - 45 - 47 - 36]);
						num = 1110800865;
					}
					else
					{
						_0024_0025_002F__005E_003E_003C_0028(Kjr_003D, _002B_0023_005E_0023_003C_0024_0024_0028._002B_002A_0024_002F_003F_0028_0021_003E[5324 - 5011 + 57], JAt_003D);
						int[] array = new int[6] { -985459327, 1267414368, -31579340, -773885490, -447381986, 615471093 };
						array[0] ^= -252493502;
						array[3] = array[5] ^ -590783328;
						int[] array2 = new int[6] { 184793074, 238908620, 2073304211, -207501410, 45481253, -1551589129 };
						int[][] array3 = new int[2][] { array, array2 };
						array2[0] = array3[0][1] ^ 0x449B00D9;
						array2[4] ^= -1305240844;
						array2[5] = array2[4] ^ -1645989348;
						array2[5] = array2[0] ^ -1944761035;
						int num17 = array3[1][0] ^ -458923826;
						num = (int)((num4 * 270641095) ^ 0x535F3AE6) ^ num17;
					}
				}
				else
				{
					int[,] array4 = new int[3, 3];
					array4[0, 0] = 1434257364;
					array4[0, 1] = -1524738973;
					array4[0, 2] = 1881438424;
					array4[1, 0] = -873247813;
					array4[1, 1] = 771924507;
					array4[1, 2] = -817098736;
					array4[2, 0] = -1135341546;
					array4[2, 1] = -553399454;
					array4[2, 2] = -1820500104;
					array4[2, 2] = array4[0, 2] ^ 0x41DDF1C7;
					array4[1, 0] ^= 516012329;
					array4[1, 1] = array4[0, 2] ^ -1931315221;
					array4[2, 2] = array4[1, 2] ^ -1191582319;
					int num18 = array4[2, 2] ^ -304945411;
					int[] array5 = new int[7];
					array5[0] = 895290662;
					array5[1] = -1955732901;
					array5[2] = 665434478;
					array5[3] = -2064336996;
					array5[4] = -707882010;
					array5[5] = -824895279;
					array5[6] = -774269089;
					array5[5] = array5[2] ^ 0x778633AA;
					array5[0] = array5[3] ^ 0x35A88728;
					int[] array6 = new int[6];
					array6[0] = -1840442933;
					array6[1] = 605798241;
					array6[2] = 1473946101;
					array6[3] = 1960030799;
					array6[4] = 1480351034;
					array6[5] = -254266613;
					array6[5] = array5[3] ^ 0x551BD167;
					array6[4] = array6[5] ^ 0x3DA678E9;
					array6[3] = array6[5] ^ -1203053492;
					int num19 = array6[5] ^ 0x3B790DC1;
					int num20 = ((int)num4 * -1665633598) ^ -1383324162;
					num18 ^= num20;
					num19 ^= num20;
					int num21;
					int num22;
					if (Imf_003D)
					{
						num21 = num19;
						num22 = num21;
					}
					else
					{
						num21 = num18;
						num22 = num21;
					}
					num = num21 ^ num20;
				}
			}
		}
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	[AsyncStateMachine(typeof(_003CResolveEndpointAsync_003Ed__31))]
	private Task<string> puS_003D(CancellationToken nXn_003D)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[2] { this, nXn_003D };
		return (Task<string>)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("NzMxYGc0Z2JVVMAzU1VQTVU=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	static TimeSpan _0025_0021_005E_003F_0028_0021_002A_005E(double P_0)
	{
		TimeSpan result = default(TimeSpan);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 2024960003;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(-(~(~(-num2)) ^ (((-(1543986969 * (0x5813D370 ^ -1477661717)) ^ ((544216347 + -37642545) ^ -(~-915575542))) - -999984077 * (705720603 * ~(0x6E0A241C ^ 0x6062FD47))) * -1707680881))) ^ 0x41C93056 ^ 0x2EA21FE1) * -1399601651)) % 3;
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
					int num7 = 1874505614;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = -num7 * 17550979;
						num7 = ~(num7 ^ 0x703B54C4);
					}
					if (num3 != (uint)num7)
					{
						int num9 = -2095424358;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 = -2095424357 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = TimeSpan.FromSeconds(P_0);
					int[] array = new int[7];
					array[0] = -38523770;
					array[1] = -1932680932;
					array[2] = 441845812;
					array[3] = -1786104053;
					array[4] = 723188537;
					array[5] = 773913758;
					array[6] = 722507679;
					array[6] = array[1] ^ 0x1108AE37;
					array[4] = array[0] ^ 0x6C379530;
					int[] array2 = new int[6] { 1588734387, 611704540, -1758074532, 1934614526, -467454176, -2018119182 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[0] = array3[0][5] ^ -1082177229;
					array2[3] = array2[0] ^ 0x1D5AD3A4;
					array2[2] = array2[5] ^ 0x67E18E69;
					int num11 = array3[1][0] ^ 0x122E6C8F;
					num = ((int)num4 * -1934231380) ^ 0x6106E1B4 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _0024_003C_003E_002A_002D_0023_002F_0021(HttpClient P_0, TimeSpan P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1548181770;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(1077828217 * (-9761935 - 622269441 - (-600836500 - 1912837810) + (0x1A23E84C ^ 0x5152694C) * 1293884209)) - (-(num2 ^ -(~((--695207975 ^ -707220438 ^ 0x5CFA47B4) * 1360146697 - ~((-995698260 - (836813412 + 783167458)) ^ -1621191553)) - 1880695521 - ((0x6795BA70 ^ (-226314523 ^ -(-1162068925 ^ -1442959673)) ^ 0x23CA063D) - (~(-(~(-2061343218) ^ 0x563EEB82)) + -(~-1325026912))))) * -2042314949 - -1768592104))) % 3;
					int num5 = -2;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1753017474;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 ^= -1753017473;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -512887156;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9 * -1786509277;
							num9 = (num9 - (1058944259 - 1064515700)) ^ -1746727061;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Timeout = P_1;
					int[] array = new int[5];
					array[0] = -307872185;
					array[1] = 403517434;
					array[2] = -476856637;
					array[3] = -1518572707;
					array[4] = -858833246;
					array[2] = array[4] ^ 0xDB15DEE;
					array[2] = array[3] ^ -175389244;
					int[] array2 = new int[5];
					array2[0] = 1805876604;
					array2[1] = -100061173;
					array2[2] = -833082913;
					array2[3] = -873278012;
					array2[4] = -398576446;
					array2[3] = array[4] ^ -502529500;
					array2[4] = array2[2] ^ -1672677760;
					array2[4] = array2[1] ^ 0x39CA9F94;
					array2[1] = array2[4] ^ 0x7F6A69AE;
					int num11 = array2[3] ^ -1454566686;
					num = ((int)num4 * -702471886) ^ -1880755318 ^ num11;
				}
			}
		}
	}

	static HttpRequestHeaders _003D_0024_002F_0025_003E_003D_002D_003F(HttpClient P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return P_0.DefaultRequestHeaders;
		}
	}

	static HttpHeaderValueCollection<ProductInfoHeaderValue> _003E_0040_002D_0021_0024_005E_0028_0028(HttpRequestHeaders P_0)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			return P_0.UserAgent;
		}
	}

	static Encoding _002F_003D_003D_005E_0029_003F_005E_003C()
	{
		Encoding uTF = default(Encoding);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -96783082;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((((--949727623 + ((0x79FCDDD0 ^ -938451712) - (550486824 + -854120508))) * -461336227 + -(1156594511 - -1271154299) - -(925925721 * (459765360 - -1368432555 * -1586904991) + -1029849597 * ~(862555623 * 1066776772))) * -1178410065 + (1143220683 * (626765577 * -(0x3ACBB652 ^ 0x380176F9) - 1413548619) - ~(0x7C0D29E2 ^ (--997170886 + ~(~-1055634638))) + (-(~-1649779785) ^ (-(~-1314973561 * 1351239921 - ((0x5961F2B5 ^ -493685138) - ~1338040181)) ^ -958668267))) - ~num2 + ((858302307 + (-1666141858 + -(-(1772258518 - -104426301))) + -2142016335 * ((0x7648D806 ^ -1269338156) * -1456316749)) ^ ((-1164264447 ^ -(~(865269152 - 1603734083))) * -1666309777 + (~(286649063 * 1387385827 + ~(2098062409 * -950449300)) + 471296993 * (1285004611 * ((307813592 + -1679725224) * 259894853))))) - ~(~533666432 + ~(--1989173402))) * -950216395)) % 3;
					int num5 = 2;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(~num5);
						num5 = ~(-num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -917705769;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += 917705771;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 2019526531;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = (num9 - -1614556611) * 1068162829;
							num9 = num9 * -763913271 * -1784320507;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					uTF = Encoding.UTF8;
					int[] array = new int[5];
					array[0] = 1205348353;
					array[1] = -2023092820;
					array[2] = -2079052568;
					array[3] = -646570573;
					array[4] = -801380131;
					array[1] = array[2] ^ 0x435B0AD1;
					array[4] = array[1] ^ -292403537;
					int[] array2 = new int[5] { 1487903261, -586433073, 1400111246, 227648801, 1730244522 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][3] ^ -483960168;
					array2[4] = array2[3] ^ -329106953;
					array2[0] = array2[4] ^ 0xEA315A0;
					int num11 = array3[1][1] ^ -156385583;
					num = (int)((num4 * 817864878) ^ 0xBB6A166Cu) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return uTF;
	}

	static byte[] _002A_0025_0026__0025_005E_0029_003D(Encoding P_0, string P_1)
	{
		byte[] bytes = default(byte[]);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 2012586977;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(((~((--2061630106 ^ 0x694E6EE2) + ~(247120206 + 1290073306)) * 1347044375 - (-((num2 * 437807489) ^ (~-2005148072 - -1713837349 * (-(~1789683927 - (-416459325 - 1886280973) - ~(1678316747 * -885449525)) + --773188641) + (-118427812 - --1997729067))) - ~((-1212136837 ^ 0x4AE42CB) - ~(407988289 * 302057071 * -1018676493) * 242634645))) ^ (-1869160951 * -(0x1C079D60 ^ -1844519301))) - (-1715055642 + -702800034 - (-1857163370 - 1068735256) + -(1288087577 * -598931828))))) % 3;
					int num5 = 1220004714;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 1220004714;
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
						int num9 = 2;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = 1646494435 - -num9;
							num9 = -num9 + -565648505;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					bytes = P_0.GetBytes(P_1);
					int[] array = new int[6];
					array[0] = -1926045382;
					array[1] = -1000774344;
					array[2] = 1346768288;
					array[3] = -1632882587;
					array[4] = 729836096;
					array[5] = -58591573;
					array[3] = array[2] ^ 0x25F64609;
					array[0] = array[5] ^ 0x4357DD90;
					int[] array2 = new int[7];
					array2[0] = 669929409;
					array2[1] = -1597383517;
					array2[2] = -361368555;
					array2[3] = -1245330973;
					array2[4] = 953113031;
					array2[5] = -202223793;
					array2[6] = -2002041658;
					array2[0] = array[1] ^ -1120687319;
					array2[4] = array2[2] ^ -1680762505;
					array2[5] = array2[0] ^ 0x7851DEA5;
					int num11 = array2[0] ^ -1224681282;
					num = ((int)num4 * -1484260156) ^ -1034873324 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return bytes;
	}

	static string _0021_003E_0028_003D_003F_002A_0021_(byte[] P_0)
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
				int num = 1477948832;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(~(~(~((-(~(num2 - (~(1481813705 * (484658421 * (~(-(~1473150460 + (-307500852 + 1267112025))) - (~-682842068 - (~(2100500928 + 2120333384) + 475877059 * -1160191212 * 1010620143))))) - (--1309277189 ^ (1275123353 * (-(~((0x4F398599 ^ -1263240796) - (0x190B4760 ^ -258956685)) - ~(-(~-2067026136))) ^ (-999844961 * -982866041 - (-182174427 - ~(-1950118187 ^ -1869483343)) + -(85013506 + (-722102365 + 2059659145) - ((-1136595044 ^ -894747267) + 152820151))))))))) - (1403229411 * -(259584051 * -1241515165 - -1910567163) * 1177036371 - (-((-1797149239 ^ 0x26B0BB44) + (--229918788 - (-1383294799 ^ 0x1C1F1C4F))) ^ ~(-(~-1706209139))))) ^ -181909471)))))) % 3;
					int num5 = -953007718;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -num5 * -759838841;
						num5 = ~(-num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1022749555;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 1166291387;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1539787094;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 * 964069609 - -52319408;
							num9 = ~(num9 - (-441998915 + -2043780751));
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = Convert.ToBase64String(P_0);
					int[] array = new int[6];
					array[0] = 573975852;
					array[1] = -1684723547;
					array[2] = 124221907;
					array[3] = -321331780;
					array[4] = -71509528;
					array[5] = -2004142157;
					array[1] = array[4] ^ -42017836;
					array[5] = array[0] ^ 0x74A5B01F;
					array[1] ^= -75131701;
					int[] array2 = new int[4] { 300080637, 836949665, -183661452, 1462334679 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][0] ^ -1463502682;
					array2[3] ^= 822559970;
					array2[2] = array2[0] ^ 0x3F6FCD75;
					int num11 = array3[1][1] ^ -503258299;
					num = (int)((num4 * 2066095992) ^ 0xB8FEDAE0u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string _0028_0040_0040_0026_0028_0026_0023_002F(string P_0)
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
				int num = 1709605494;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-(-(~(130183370 + (-862179918 - (~(1024473815 + -767834109 + (-14034481 + -496666585) + -(0x3EE8EFFF ^ 0x7528CAA3)) + -(-145082978 ^ -(-1215123428 + 1538688133)))) - (num2 - (((-2002438149 * (2112553486 - -287958695 + -1277998283 * -840156733) - (-212096794 - (-476555741 - (1337046351 + 1272465445))) + (971277738 - -133857249 - (-959547461 ^ 0x62BD2151) - 1768064511 + -629665454)) ^ (-742924646 - -(-(1129741791 * (-1306707871 ^ -1045462199))))) + ((-(1136514462 - -1233779964 + (-1175836656 - 631798587)) - ((-753782936 ^ 0x48F8D5D9) - (-1291997344 ^ 0x1F49FBF7) * -126961739)) ^ 0x403AA8C1) * 1405446111 - ~(-(-((818710525 - 1394765198) * 979883027) * 2069825765) * 1721163309) + -(~(~1409707005 - ((0x207971F5 ^ -2033577112) - -1531712317 * (-1928632155 ^ -853244372))) + -1283430393 * (-(246219627 * -526602639) - 1838462701 + -(~2018332488 - (-34329441 - 1533305121))) + ((-((-1283207045 ^ 0x7326405F) - ~-317266487) + 1558220099 * (-1453870704 - -668312523 - -514601796 * 1916956043)) ^ 0x5F319FFE ^ ((0x6AE06C07 ^ -519113512) + (-1025182146 - -(-1898826953 + -566210265 * 326046773)))))) - (-(-589484844 ^ ((-1515882529 ^ -1425410480 ^ (-1013913209 - ~856735902)) - (0x7E7299FE ^ -(-1622238370 ^ 0x7F311AD8)) + (-(-(-929732312 ^ 0x695ED9F2)) ^ ((--1040121844 - (-1515050866 + 2060715325)) * 200704227)))) - (1802752653 * 137849597 - ((-(-(1436586641 - 23191509 - 528762759)) - ~(343876681 + (--656733489 - ~-1049226500))) ^ 0x5A97DC7C))))) * 1550340917 - ~-1751364374) - -(-238689873 * 1641951109)) ^ -58701929)) % 3;
					int num5 = 1970565276;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 -= 1970565276;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 491763120;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = (num7 * -917037335) ^ 0xA8EA5D3;
						num7 *= 1655950983;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 1542683168;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 1542683167;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = Uri.EscapeDataString(P_0);
					int[,] array = new int[4, 3];
					array[0, 0] = 990265715;
					array[0, 1] = -900426972;
					array[0, 2] = 106515814;
					array[1, 0] = 397204028;
					array[1, 1] = -841738941;
					array[1, 2] = 381779868;
					array[2, 0] = -1209874393;
					array[2, 1] = 1019913183;
					array[2, 2] = 1875873736;
					array[3, 0] = 2031683489;
					array[3, 1] = 1443031485;
					array[3, 2] = 1152130999;
					array[1, 2] = array[0, 2] ^ 0x6BE23B8F;
					array[0, 0] = array[1, 2] ^ -1627246627;
					array[2, 2] ^= -1002212802;
					array[0, 1] = array[3, 0] ^ -1544427915;
					int num11 = array[0, 1] ^ 0x1F58AAD9;
					num = ((int)num4 * -1017494926) ^ -810490746 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static byte[] _0026_0026_0029_0024_0029_005E__003F(string P_0)
	{
		byte[] result = default(byte[]);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 1505131724;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((-(((((num2 ^ ((0x7AFEEBC8 ^ -(1011145297 * (-(-864921286 - (-700678680 ^ -2061339275) - (1673244526 + -1131216203) * 1900195173) - ((-1264415871 ^ 0xF229939) + 1363186835)))) * 1194513833)) * -279023359 - (~(-(~(--961730164)) - ((0x54DC6004 ^ -1555247503) + -(-536145312 + -1355750038))) + ((-(~(1811509368 * 262066851)) * -309375967) ^ 0x3EE4EBD3) + (((-1422986471 * (~(-806428296 - -432385237) + -(448301081 - -1517480504))) ^ -440452265) - -1820164291 * ((344073924 - -1186935264 + (-698718341 + -428709169) - -(-2031157707)) ^ (--1266763607 + (1198718444 + 198504289 - 698530899)))))) * 1272774305 * 360889345) ^ ~(-(1126443266 - (2043873977 - -852600503)))) - -1492290755 * (-917157093 ^ 0x3893A9FF)) + -823984302) * 528421583)) % 3;
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
					int num7 = -1;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1070725124;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = num9 ^ -599231373 ^ -1568272642;
							num9 = (num9 ^ -1522007215) - 1913732065;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = Convert.FromBase64String(P_0);
					int[] array = new int[6];
					array[0] = 1570703130;
					array[1] = -1164378213;
					array[2] = 1750346758;
					array[3] = 1545166958;
					array[4] = 1782297971;
					array[5] = 868365048;
					array[3] = array[0] ^ -1728915395;
					array[2] ^= -1278625269;
					int[] array2 = new int[5];
					array2[0] = -892767088;
					array2[1] = 1687876308;
					array2[2] = -1796236490;
					array2[3] = 549116701;
					array2[4] = 1548394760;
					array2[1] = array[1] ^ 0x790834A6;
					array2[3] ^= 2059703519;
					array2[0] = array2[4] ^ 0x4C0DD515;
					array2[0] = array2[1] ^ 0x46AC8A66;
					int num11 = array2[1] ^ 0x3AB3419;
					num = (int)((num4 * 2008515235) ^ 0xFFEAA7E7u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static string _0021_0024_002F__002A_0023_002B_003F(Encoding P_0, byte[] P_1)
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
				int num = -819701746;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(666269148 - ((((~(-(num2 ^ ~(-(((0x45A11B7A ^ (~(-1897513879 + -1981029480 + --2094709255) - 1911959781 * -(-1570647109 * 597965250))) - ~(-109828568 ^ -248974467)) ^ ((~(0x4E9B8064 ^ 0x2E65AF2E) + -(-1341374749 * (1083145201 + 1646311795) * -558663993)) ^ ((-1354604287 ^ -(~1346963297)) - (-(-768465141) - -869860126) + -377242868)))))) ^ (~(-317946288 * 189102947 + -1663216461) - (2096797289 * 1383558797 + ~-1720947378 * -296385731) + (((-804642894 - 1273129936 * 1650626797) ^ -1713950991) + ~(~1029795874)) + -874171199)) * -2126403477 + (-(~(-1063845872 ^ -716930054)) - ~(~-991290053))) ^ (-(-1577342495) - (-1564854145 + 1874296430 - 7987085 * 1912230572))) + -(-1327134645)) * -680922871)) % 3;
					int num5 = -802666889;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 = -802666889 - num5;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -2024641931;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 -= -2024641932;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -357740524;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(num9 * -1717831469);
							num9 = num9 + (0x2800C6E0 ^ -2100709773) - -1296734878;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.GetString(P_1);
					int[] array = new int[7];
					array[0] = -1582641071;
					array[1] = -1131991405;
					array[2] = -2137590188;
					array[3] = -421849120;
					array[4] = -1757423893;
					array[5] = 2054126951;
					array[6] = 327694189;
					array[2] = array[1] ^ -1297820648;
					array[5] = array[3] ^ -420212443;
					array[6] = array[5] ^ 0x153F69AE;
					int[] array2 = new int[5] { -703374612, 93001721, 1563986675, -1821193619, -959219462 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[2] = array3[0][1] ^ -406081521;
					array2[1] = array2[2] ^ 0x39ECE64D;
					array2[4] = array2[2] ^ -852138760;
					int num11 = array3[1][2] ^ -1802465618;
					num = (int)((num4 * 267867621) ^ 0xF3FD2AFDu) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static char[] _002D_005E_0021_0028_003F_003C_002B_(string P_0)
	{
		char[] result = default(char[]);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -2099866014;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-20889392 + (-1740158107 + -(-(--545304312) - 153216727)) - ((~num2 - (~1068026753 - (283991855 * ~(-(-514702193 ^ 0x45FF53F9)) - -2130158965 * -442056730 - ~(-(467182883 * ~1853255 + -309986187 + 1089586155 * -2120485973))))) ^ ~(144124677 * (-(-1277073405 + -1639940447 + (1719194681 - -700666997) - -(~1025252715)) ^ ~(-(-(818959291 - 1826732926)))))))) % 3;
					int num5 = 1966993388;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = num5 - --1808325896 - 157686687;
						num5 = -(num5 ^ 0x456F890B);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = 1;
					_ = 0;
					for (int num8 = 0; num8 < 2; num8++)
					{
						num7 = ~(num7 ^ 0x6A5F71EB);
						num7 = num7 ^ -741846064 ^ -1276270896;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -496037438;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = -(~num9);
							num9 = -1390551453 - num9 * -406122719;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.ToCharArray();
					int[] array = new int[7] { -233075784, -255921403, 167063996, 940573381, -989001999, -952315933, 1379308563 };
					array[6] ^= -1173804337;
					array[1] = array[5] ^ -899912831;
					int[] array2 = new int[6];
					array2[0] = 1956719675;
					array2[1] = -1273564094;
					array2[2] = 1334523632;
					array2[3] = -1236887926;
					array2[4] = -228988003;
					array2[5] = 1588849964;
					array2[5] = array[5] ^ -1654601294;
					array2[0] ^= -1877771242;
					array2[2] = array2[4] ^ -479203388;
					int num11 = array2[5] ^ -424587009;
					num = (int)((num4 * 341651564) ^ 0x85758180u) ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static WindowsIdentity _003D_0023__0028_003E_002D_005E_0021()
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[0];
		return (WindowsIdentity)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("OWo5PTpsPjEICV5nDggNLQg=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static SecurityIdentifier _0023_0028_0025_005E_0028__0025_0040(WindowsIdentity P_0)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
		return (SecurityIdentifier)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("N2UyMGRnYjYBAFYsBwEEJwE=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static string _005E_002B_003D_003D_0029_0029_0024_0026(IdentityReference P_0)
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[1] { P_0 };
		return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("MGYzN2c2NmJSUwWnVFJXdVI=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	static string __0025_003D__0026_003D_0021_002B()
	{
		object[] _0024_0029_0024_002A_0021_002F_0021_005E = new object[0];
		return (string)_003C_0028_002B_0025_0028_0028_0024_0023._002A_002B_002D_003D_0025_002B_005E_0024("YzVmZm9lZzRXVg7QUVdSf1c=", _0024_0029_0024_002A_0021_002F_0021_005E);
	}

	static bool _003C_0024_0026_0026_0028_0023_0040_0028(ISettingsStore P_0, string P_1, bool P_2)
	{
		bool boolean = default(bool);
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 912424557;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(270484100 + ((-1827680621 ^ -1901846857) - (-1490821457 + 819436545 - -220623873)) + 1227645895 + -1039462507 - (num2 - (~(-817365336 + (~(-(--520433679)) + ((0x5A27F14E ^ -933617664) * 2059183437 + ~(964977342 - 293801034))) + (-(1007977075 + 2058703746 - -327930515) - (0x25EFB747 ^ 0x3983B406) + ~(-(-(-1156510174 + 652902886))))) - ~(-2058248325 + (~-1416923467 - -(1518786758 - (-477028493 + 2015302287) - -2117219919))) + (-2076967585 * (-799936899 * (2143424528 + -1205126987 + -1336453122 * 157420899 + --1995363860 * -545399365 + -1728264031 * -(-1821403111 + -773618263))) * 1043760743 - (((-1833437511 ^ 0x4ACA68CD) - ((((-876346323 - -108529505) ^ 0x11FB38E9) + ~1842822867) ^ 0x57493ACC)) ^ -28792873))) + 208131047 * ~(~(~(-1131041854) - ((-1791747826 ^ -974325011) + -1120755037))) * 820017083) * 1064416339)) % 3;
					int num5 = 1869919864;
					_ = 0;
					for (int num6 = 0; num6 < 1; num6++)
					{
						num5 ^= 0x6F74B678;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -477208041;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = -477208040 - num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 783830680;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 += -783830678;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					boolean = P_0.GetBoolean(P_1, P_2);
					int[] array = new int[7];
					array[0] = 1144489412;
					array[1] = -1161653546;
					array[2] = 1409015223;
					array[3] = -353830514;
					array[4] = 316193215;
					array[5] = -63575347;
					array[6] = 1149664917;
					array[3] = array[4] ^ -424717381;
					array[3] = array[4] ^ 0x9D7EE61;
					int[] array2 = new int[5] { -905883755, 533752383, -1754514895, -1435110349, 885239126 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][6] ^ -58258927;
					array2[0] ^= 1520963595;
					array2[2] = array2[1] ^ 0x5915A086;
					int num11 = array3[1][1] ^ -583839668;
					num = ((int)num4 * -1392370006) ^ -257840654 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return boolean;
	}

	static string _002F_003F_0028_0024_002F_003D_002A_0023(ISettingsStore P_0, string P_1)
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
				int num = -2018537993;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(~(-(~(num2 - (-(1635177881 * 1585894707 - (283867340 - ((0x295E8881 ^ 0x21DE3752) + (0x58F9BF62 ^ 0x3485E82B) + (0x39A78284 ^ -2006048909)))) + -139000784 + -(-((-861010488 ^ -44038478) * -1083472179 + -1939741783 * ~(~1668272024 + (0x4F3F126D ^ 0x340771B4)))) - ~(-710132771 - ((((--1378753215 - 993433768 * -203046545 - ~(351663592 - -2078375749)) ^ (-(-1014565937) ^ -367094025)) + (-(-(1164601104 + 1615094848)) + (-527257624 ^ -1184678075) * 700827839)) ^ 0x1128BD32))) - (~((-55688556 ^ 0x4A018BF0) * -897623791) - ~-842459531)) * -1873337323)))) % 3;
					int num5 = -833842796;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = (-1303886568 - -286115796 - num5) * -2088391059;
						num5 = ~num5 * 1304721013;
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1773931837;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= 155110891;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -1756660814;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~num9 + 140189177;
							num9 = ~-1018519584 - num9;
						}
						if (num3 == (uint)num9)
						{
						}
						goto end_IL_0007;
					}
					result = P_0.GetString(P_1);
					int[] array = new int[4] { 996146059, -224650496, 1350575178, 2019066980 };
					array[3] ^= 1223066625;
					array[1] = array[3] ^ 0xB48422D;
					int[] array2 = new int[7] { 2115214671, 611525803, 833533558, 1864665635, -1513179562, 557655813, -1810974139 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[4] = array3[0][0] ^ -2111303712;
					array2[2] = array2[5] ^ -221483260;
					array2[6] = array2[5] ^ -53886973;
					int num11 = array3[1][4] ^ 0x1F3F0FA5;
					num = ((int)num4 * -1584948240) ^ -460072720 ^ num11;
				}
				continue;
				end_IL_0007:
				break;
			}
		}
		return result;
	}

	static void _003D_005E_0023_0025_0040_005E_0040_0024(ISettingsStore P_0, string P_1, bool P_2)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -871000273;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)(-((((~(-(-num2)) * -1999034971 * 787320231) ^ (-1962648901 * (-478099439 + (--991729465 - ~-2053878349)))) * -2061074141 - -846480363) ^ 0x63A79FFA))) % 3;
					int num5 = 2;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = -(-num5);
						num5 = ~(-num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -1412435202;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 += 1412435204;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -146568529;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 *= -1126691761;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.SetBoolean(P_1, P_2);
					int[] array = new int[4];
					array[0] = 456469702;
					array[1] = 768150216;
					array[2] = -1898073154;
					array[3] = -1691012975;
					array[2] = array[1] ^ 0x19820AA9;
					array[1] ^= 1794144806;
					array[2] = array[0] ^ -1580249347;
					int[] array2 = new int[6];
					array2[0] = 2113273816;
					array2[1] = -1607583830;
					array2[2] = -256701757;
					array2[3] = -1740268390;
					array2[4] = 1516538680;
					array2[5] = 331665546;
					array2[4] = array[0] ^ -935586988;
					array2[0] = array2[4] ^ -1269697777;
					array2[2] = array2[5] ^ -1095801851;
					array2[1] = array2[0] ^ 0x4843BCCB;
					int num11 = array2[4] ^ -1240106419;
					num = (int)((num4 * 705103182) ^ 0x8263EBD6u) ^ num11;
				}
			}
		}
	}

	static void _0024_0025_002F__005E_003E_003C_0028(ISettingsStore P_0, string P_1, string P_2)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = -546442223;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~(~(-2053649886) - -(-1581153869 ^ 0x12BE7F4A)) - ((-991758105 ^ -(--2133144628) ^ -487593559) - ~(1373248436 + -1882103049 + ~-1894602072 - (-362160453 + 462097319 - ~2063244496))) - -(num2 + -(-1796666359 * (0x7E8ADF2A ^ -282567804) + ~(0x735F1E5 ^ (1266083684 + (-(-922285702 - -368199492) ^ -(-1563360610 + 1922641698)))) - (-(~(-(-1818335118 - 129136311))) - ~(-1727166288) + ((0x2ADCC342 ^ -1870888999) - -1332966247 * (1915795327 + 895845566) * 792511413 + ~507742293)) * -1175615015)) * -1319596353 - 991763713) * 968307127)) % 3;
					int num5 = 0;
					_ = 0;
					for (int num6 = 0; num6 < 2; num6++)
					{
						num5 = ~(num5 ^ 0x78375E56);
						num5 = -(-num5);
					}
					if (num3 == (uint)num5)
					{
						break;
					}
					int num7 = -2079240146;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 *= -1993928793;
					}
					if (num3 != (uint)num7)
					{
						int num9 = -866995985;
						_ = 0;
						for (int num10 = 0; num10 < 2; num10++)
						{
							num9 = ~(num9 * 921797105);
							num9 = -num9;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.SetString(P_1, P_2);
					int[] array = new int[7];
					array[0] = -138845913;
					array[1] = -1060383422;
					array[2] = 925198905;
					array[3] = 2137755943;
					array[4] = 1138168462;
					array[5] = -656034098;
					array[6] = 2128677305;
					array[4] = array[3] ^ -225402090;
					array[0] = array[6] ^ -1416102115;
					array[6] ^= -827055398;
					int[] array2 = new int[4] { 50942542, -425748594, 2001784030, -1954365921 };
					int[][] array3 = new int[2][] { array, array2 };
					array2[1] = array3[0][5] ^ 0x65D72508;
					array2[3] = array2[0] ^ -1681473054;
					array2[2] = array2[1] ^ -1428972722;
					array2[3] = array2[2] ^ -2105697829;
					int num11 = array3[1][1] ^ 0x6A1F95E8;
					num = ((int)num4 * -1130519648) ^ 0xEC1BB80 ^ num11;
				}
			}
		}
	}

	static void _002A_002D_0024_0029_0025_005E_003D_0024(ISettingsStore P_0, string P_1)
	{
		try
		{
			throw new Exception();
		}
		catch (Exception)
		{
			while (true)
			{
				int num = 2072768011;
				while (true)
				{
					int num2 = num;
					uint num4;
					uint num3 = (num4 = (uint)((~num2 + (-208399029 * ((0x779F9705 ^ -1697297717) * 569160299) - (-(~(0x4CB2A6FC ^ 0x52875CDD) + (0x6FF46606 ^ 0x180887B6)) - ~(-(~(-1175795679 + 1318733429)) * -2115928295)) - -167276253 * ((1733848591 - -(~(-493600166 + -91620513) + (-1955657894 + 186156667 + ~-1667855607))) ^ -2031846218)) - ((--2028983500 + 1532803033) ^ 0x7A5C995E)) * -1605948321)) % 3;
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
					int num7 = -2;
					_ = 0;
					for (int num8 = 0; num8 < 1; num8++)
					{
						num7 = -num7;
					}
					if (num3 != (uint)num7)
					{
						int num9 = 506582207;
						_ = 0;
						for (int num10 = 0; num10 < 1; num10++)
						{
							num9 -= 506582206;
						}
						if (num3 == (uint)num9)
						{
						}
						return;
					}
					P_0.Remove(P_1);
					int[,] array = new int[3, 4];
					array[0, 0] = -1382567262;
					array[0, 1] = -464316089;
					array[0, 2] = 931728145;
					array[0, 3] = -264041127;
					array[1, 0] = -1916035744;
					array[1, 1] = -898148495;
					array[1, 2] = -1308854348;
					array[1, 3] = -451238334;
					array[2, 0] = 1919234310;
					array[2, 1] = -785887117;
					array[2, 2] = 607148937;
					array[2, 3] = -424916245;
					array[1, 3] = array[2, 1] ^ -1436573887;
					array[1, 2] = array[2, 1] ^ -405105878;
					array[0, 3] = array[0, 1] ^ -637251522;
					int num11 = array[0, 3] ^ 0x356A79E5;
					num = (int)((num4 * 684833803) ^ 0x5A88989F) ^ num11;
				}
			}
		}
	}
}
