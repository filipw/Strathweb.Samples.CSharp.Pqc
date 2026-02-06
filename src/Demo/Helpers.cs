using Spectre.Console;

public static class Helpers
{
    public static string PrettyPrint(this byte[] bytes)
    {
        var base64 = Convert.ToBase64String(bytes);
        return base64.Length > 50 ? $"{base64[..25]}...{base64[^25..]}" : base64;
    }

    public static void PrintPanel(string header, string[] data)
    {
        var content = string.Join(Environment.NewLine, data);
        var panel = new Panel(content)
        {
            Header = new PanelHeader(header)
        };
        AnsiConsole.Write(panel);
    }
}