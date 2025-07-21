using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Spectre.Console;

var demo = AnsiConsole.Prompt(
    new SelectionPrompt<string>()
        .Title("Choose the [green]demo[/] to run?")
        .AddChoices(new[]
        {
            "ML-KEM (BouncyCastle)", "ML-DSA (BouncyCastle)", "ML-KEM (Windows API)", "ML-DSA (Windows API)"
        }));

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