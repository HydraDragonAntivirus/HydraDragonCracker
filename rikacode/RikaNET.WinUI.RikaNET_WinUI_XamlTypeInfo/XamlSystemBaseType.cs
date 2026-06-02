using System;
using System.CodeDom.Compiler;
using System.Diagnostics;
using Microsoft.UI.Xaml.Markup;

namespace RikaNET.WinUI.RikaNET_WinUI_XamlTypeInfo;

[GeneratedCode("Microsoft.UI.Xaml.Markup.Compiler", " 3.0.0.2403")]
[DebuggerNonUserCode]
internal class XamlSystemBaseType : IXamlType
{
	private string _fullName;

	private Type _underlyingType;

	public string FullName => _fullName;

	public Type UnderlyingType => _underlyingType;

	public virtual IXamlType BaseType
	{
		get
		{
			throw new NotImplementedException();
		}
	}

	public virtual IXamlMember ContentProperty
	{
		get
		{
			throw new NotImplementedException();
		}
	}

	public virtual bool IsArray
	{
		get
		{
			throw new NotImplementedException();
		}
	}

	public virtual bool IsCollection
	{
		get
		{
			throw new NotImplementedException();
		}
	}

	public virtual bool IsConstructible
	{
		get
		{
			throw new NotImplementedException();
		}
	}

	public virtual bool IsDictionary
	{
		get
		{
			throw new NotImplementedException();
		}
	}

	public virtual bool IsMarkupExtension
	{
		get
		{
			throw new NotImplementedException();
		}
	}

	public virtual bool IsBindable
	{
		get
		{
			throw new NotImplementedException();
		}
	}

	public virtual bool IsReturnTypeStub
	{
		get
		{
			throw new NotImplementedException();
		}
	}

	public virtual bool IsLocalType
	{
		get
		{
			throw new NotImplementedException();
		}
	}

	public virtual IXamlType ItemType
	{
		get
		{
			throw new NotImplementedException();
		}
	}

	public virtual IXamlType KeyType
	{
		get
		{
			throw new NotImplementedException();
		}
	}

	public virtual IXamlType BoxedType
	{
		get
		{
			throw new NotImplementedException();
		}
	}

	public XamlSystemBaseType(string fullName, Type underlyingType)
	{
		while (true)
		{
			int num = -1400678754;
			while (true)
			{
				int num2 = num;
				uint num4;
				uint num3 = (num4 = (uint)((~(~(num2 * -912636101 - (-507513278 - ~(447417537 * ~(0x12E060D8 ^ ~(-1503644663 ^ -1058476465)))))) * 429183243 * -447752733 + (720699674 - (600701036 + -1276939016 + ~-972784957)) - 878573448 - 1707082338 * -1659280211) ^ -187778816)) % 4;
				int num5 = 0;
				_ = 0;
				for (int num6 = 0; num6 < 2; num6++)
				{
					num5 = ~(-num5);
					num5 = ~(num5 + -929787429);
				}
				if (num3 == (uint)num5)
				{
					break;
				}
				int num7 = 1717750223;
				_ = 0;
				for (int num8 = 0; num8 < 1; num8++)
				{
					num7 *= 1536662831;
				}
				if (num3 != (uint)num7)
				{
					int num9 = -3;
					_ = 0;
					for (int num10 = 0; num10 < 1; num10++)
					{
						num9 = ~num9;
					}
					if (num3 != (uint)num9)
					{
						int num11 = -925258979;
						_ = 0;
						for (int num12 = 0; num12 < 2; num12++)
						{
							num11 = ~-1268485358 - num11 + 365746761;
							num11 = 1935100623 * -907503097 - num11;
						}
						if (num3 == (uint)num11)
						{
						}
						return;
					}
					_underlyingType = underlyingType;
					int[] array = new int[4];
					array[0] = 1840602963;
					array[1] = -360210514;
					array[2] = -1738248913;
					array[3] = 1836400484;
					array[2] = array[1] ^ 0x48100E76;
					array[1] ^= -1451771741;
					int[] array2 = new int[7];
					array2[0] = 851510171;
					array2[1] = -1223743870;
					array2[2] = 1360298747;
					array2[3] = -1578051816;
					array2[4] = 1832195579;
					array2[5] = 1314532347;
					array2[6] = 1579659136;
					array2[0] = array[3] ^ -1903758946;
					array2[1] = array2[3] ^ -2065501623;
					array2[2] = array2[5] ^ 0x7AF1E481;
					array2[5] = array2[3] ^ -742125073;
					int num13 = array2[0] ^ -1183181754;
					num = ((int)num4 * -1622816503) ^ -169587742 ^ num13;
				}
				else
				{
					_fullName = fullName;
					int[] array3 = new int[4] { 1423255871, -1968855122, -1788307118, -1982362509 };
					array3[1] ^= 1974735894;
					array3[1] = array3[3] ^ 0x73E6C541;
					array3[1] = array3[0] ^ -1907748970;
					int[] array4 = new int[7];
					array4[0] = 1173431183;
					array4[1] = -948316983;
					array4[2] = 43529649;
					array4[3] = -1596646927;
					array4[4] = -1768734709;
					array4[5] = -54376773;
					array4[6] = -1028339451;
					array4[4] = array3[0] ^ -313600580;
					array4[0] = array4[1] ^ 0x305B4EB4;
					array4[2] = array4[1] ^ 0x3C02621F;
					int num14 = array4[4] ^ 0x33508642;
					num = ((int)num4 * -513738221) ^ 0x4F2F1F93 ^ num14;
				}
			}
		}
	}

	public virtual IXamlMember GetMember(string name)
	{
		throw new NotImplementedException();
	}

	public virtual object ActivateInstance()
	{
		throw new NotImplementedException();
	}

	public virtual void AddToMap(object instance, object key, object item)
	{
		throw new NotImplementedException();
	}

	public virtual void AddToVector(object instance, object item)
	{
		throw new NotImplementedException();
	}

	public virtual void RunInitializer()
	{
		throw new NotImplementedException();
	}

	public virtual object CreateFromString(string input)
	{
		throw new NotImplementedException();
	}
}
