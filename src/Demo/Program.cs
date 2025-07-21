using Spectre.Console;

var demo = AnsiConsole.Prompt(
    new SelectionPrompt<string>()
        .Title("Choose the [green]demo[/] to run?")
        .AddChoices(
        [
            "ML-KEM (BouncyCastle)", "ML-DSA (BouncyCastle)", "ML-KEM (Windows API)", "ML-DSA (Windows API)"
        ]));

switch (demo)
{
    case "ML-KEM (BouncyCastle)":
        BouncyCastleDemo.RunMlKem();
        break;
    case "ML-DSA (BouncyCastle)":
        BouncyCastleDemo.RunMldsa();
        break;
    case "ML-DSA (Windows API)":
        WindowsDemo.RunMlDsa();
        break;
    case "ML-KEM (Windows API)":
        WindowsDemo.RunMlKem();
        break;
    default:
        Console.WriteLine("Nothing selected!");
        break;
}

public static class FormatExtensions
{
    public static string PrettyPrint(this byte[] bytes)
    {
        var base64 = Convert.ToBase64String(bytes);
        return base64.Length > 50 ? $"{base64[..25]}...{base64[^25..]}" : base64;
    }
}