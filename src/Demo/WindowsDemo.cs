#pragma warning disable SYSLIB5006 // ML-DSA is experimental
using System.Text;
using System.Security.Cryptography;
using Spectre.Console;

public static class WindowsDemo
{
    public static void RunMlKem()
    {
        if (!MLDsa.IsSupported)
        {
            PrintPanel("Error", new[] { $":broken_heart: ML-DSA is not supported on your Windows. PQC capabilities are available for Windows Insiders, Canary Channel Build 27852 and higher only." });
            return;
        }

        Console.WriteLine("***************** ML-DSA *******************");

        var raw = "Hello, ML-DSA!";
        Console.WriteLine($"Raw Message: {raw}");

        var data = Encoding.ASCII.GetBytes(raw);
        PrintPanel("Message", new[] { $"Raw: {raw}", $"Encoded: {data.PrettyPrint()}" });

        // Generate key pair using ML-DSA 65 (equivalent to Dilithium3)
        using var mldsaKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);

        // Export keys for demonstration
        var publicKeyBytes = mldsaKey.ExportSubjectPublicKeyInfo();
        var privateKeyBytes = mldsaKey.ExportPkcs8PrivateKey();
        PrintPanel("Keys", new[] { $":unlocked: Public: {publicKeyBytes.PrettyPrint()}", $":locked: Private: {privateKeyBytes.PrettyPrint()}" });

        // Sign the data
        var signatureBuffer = new byte[mldsaKey.Algorithm.SignatureSizeInBytes];
        int signatureLength = mldsaKey.SignData(data, signatureBuffer);
        var signature = signatureBuffer[..signatureLength];
        PrintPanel("Signature", new[] { $":pen: {signature.PrettyPrint()}" });

        // Verify signature with the same key
        bool verified = mldsaKey.VerifyData(data, signature);
        PrintPanel("Verification", new[] { $"{(verified ? ":check_mark_button:" : ":cross_mark:")} Verified!" });

        // Demonstrate key import/export - recreate key from exported private key
        using var recoveredKey = MLDsa.ImportPkcs8PrivateKey(privateKeyBytes);
        var signature2Buffer = new byte[recoveredKey.Algorithm.SignatureSizeInBytes];
        int signature2Length = recoveredKey.SignData(data, signature2Buffer);
        var signature2 = signature2Buffer[..signature2Length];
        PrintPanel("Signature (from recovered key)", new[] { $":pen: {signature2.PrettyPrint()}" });

        // Verify second signature with a public-key-only instance
        using var publicOnlyKey = MLDsa.ImportSubjectPublicKeyInfo(publicKeyBytes);
        bool verifiedWithPublicKey = publicOnlyKey.VerifyData(data, signature2);
        PrintPanel("Reverification", new[] { $"{(verifiedWithPublicKey ? ":check_mark_button:" : ":cross_mark:")} Verified!" });
    }

    static void PrintPanel(string header, string[] data)
    {
        var content = string.Join(Environment.NewLine, data);
        var panel = new Panel(content)
        {
            Header = new PanelHeader(header)
        };
        AnsiConsole.Write(panel);
    }
}

