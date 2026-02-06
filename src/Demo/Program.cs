using Spectre.Console;
using LibOQS.NET;

var demo = AnsiConsole.Prompt(
    new SelectionPrompt<string>()
        .Title("Choose the [green]demo[/] to run?")
        .AddChoices(
        [
            "ML-KEM (BouncyCastle)",
                "ML-DSA (BouncyCastle)",
                "ML-KEM (System.Security.Cryptography API)",
                "ML-DSA (System.Security.Cryptography API)",
                "ML-KEM (LibOQS.NET)",
                "ML-DSA (LibOQS.NET)"
        ]));

switch (demo)
{
    case "ML-KEM (BouncyCastle)":
        BouncyCastleDemo.RunMlKem();
        break;
    case "ML-DSA (BouncyCastle)":
        BouncyCastleDemo.RunMldsa();
        break;
    case "ML-DSA (System.Security.Cryptography API)":
        SystemSecurityCryptographyDemo.RunMlDsa();
        break;
    case "ML-KEM (System.Security.Cryptography API)":
        SystemSecurityCryptographyDemo.RunMlKem();
        break;
    case "ML-KEM (LibOQS.NET)":
        LibOqsDemo.RunMlKem();
        break;
    case "ML-DSA (LibOQS.NET)":
        LibOqsDemo.RunMldsa();
        break;
    default:
        Console.WriteLine("Nothing selected!");
        break;
}

LibOqs.Cleanup();