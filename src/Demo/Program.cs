using LibOQS.NET;
using Spectre.Console;

try
{
    // Initialize LibOQS for the LibOQS.NET demos
    LibOqs.Initialize();

    var demo = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
            .Title("Choose the [green]demo[/] to run?")
            .AddChoices(
            [
                "ML-KEM (BouncyCastle)", 
                "ML-DSA (BouncyCastle)", 
                "ML-KEM (Windows API)", 
                "ML-DSA (Windows API)",
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
        case "ML-DSA (Windows API)":
            WindowsDemo.RunMlDsa();
            break;
        case "ML-KEM (Windows API)":
            WindowsDemo.RunMlKem();
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
}
catch (OqsException ex)
{
    AnsiConsole.Write(
        new Panel($"[red]Error:[/] {ex.Message}")
            .BorderColor(Color.Red)
            .Header("[red]LibOQS Error[/]"));
    
    AnsiConsole.WriteLine();
    AnsiConsole.Write(
        new Panel("Please ensure the liboqs shared library is installed and accessible.\nSee BUILD.md for installation instructions.")
            .BorderColor(Color.Yellow)
            .Header("[yellow]Solution[/]"));
}
catch (Exception ex)
{
    AnsiConsole.WriteException(ex);
}
finally
{
    LibOqs.Cleanup();
}

public static class FormatExtensions
{
    public static string PrettyPrint(this byte[] bytes)
    {
        var base64 = Convert.ToBase64String(bytes);
        return base64.Length > 50 ? $"{base64[..25]}...{base64[^25..]}" : base64;
    }
}