using System.Collections.Generic;

namespace RikaNET.WinUI.Models;

public sealed class NamespaceGroupViewModel
{
	public required string Name { get; init; }

	public required IReadOnlyList<TypeNodeViewModel> Types { get; init; }
}
