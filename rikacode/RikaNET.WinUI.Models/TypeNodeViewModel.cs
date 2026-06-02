namespace RikaNET.WinUI.Models;

public sealed class TypeNodeViewModel
{
	public required string FullName { get; init; }

	public required string DisplayName { get; init; }

	public required int MethodCount { get; init; }

	public required string IconGlyph { get; init; }
}
