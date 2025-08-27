#pragma warning disable SYSLIB5006 // ML-DSA is experimental
using System.Text;
using System.Security.Cryptography;
using System.Linq;
using Spectre.Console;

public static class WindowsDemo
{
    public static void RunMlKem()
    {
        if (!MLKem.IsSupported)
        {
            PrintPanel("Error", [$":broken_heart: ML-KEM is not supported on your Windows. PQC capabilities are available for Windows Insiders, Canary Channel Build 27852 and higher only."]);
            return;
        }

        Console.WriteLine("***************** ML-KEM *******************");

        // Generate key pair for Alice using ML-KEM 768
        using var aliceKeyPair = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);

        // Get and view the keys
        var pubEncoded = aliceKeyPair.ExportEncapsulationKey();
        var privateEncoded = aliceKeyPair.ExportDecapsulationKey();
        PrintPanel("Alice's keys", [$":unlocked: Public: {pubEncoded.PrettyPrint()}", $":locked: Private: {privateEncoded.PrettyPrint()}"]);

        // Bob encapsulates a new shared secret using Alice's public key
        using var bobKey = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, pubEncoded);
        bobKey.Encapsulate(out byte[] cipherText, out byte[] bobSecret);

        // Alice decapsulates a new shared secret using Alice's private key
        byte[] aliceSecret = aliceKeyPair.Decapsulate(cipherText);
        PrintPanel("Key encapsulation", [$":man: Bob's secret: {bobSecret.PrettyPrint()}", $":locked_with_key: Cipher text (Bob -> Alice): {cipherText.PrettyPrint()}", $":woman: Alice's secret: {aliceSecret.PrettyPrint()}"]);

        // Compare secrets
        var equal = bobSecret.SequenceEqual(aliceSecret);
        PrintPanel("Verification", [$"{(equal ? ":check_mark_button:" : ":cross_mark:")} Secrets equal!"]);
    }

    public static void RunMlDsa()
    {
        if (!MLDsa.IsSupported)
        {
            PrintPanel("Error", [$":broken_heart: ML-DSA is not supported on your Windows. PQC capabilities are available for Windows Insiders, Canary Channel Build 27852 and higher only."]);
            return;
        }

        Console.WriteLine("***************** ML-DSA *******************");

        var raw = "Hello, ML-DSA!";
        Console.WriteLine($"Raw Message: {raw}");

        var data = Encoding.ASCII.GetBytes(raw);
        PrintPanel("Message", [$"Raw: {raw}", $"Encoded: {data.PrettyPrint()}"]);

        // Generate key pair using ML-DSA 65 (equivalent to Dilithium3)
        using var mldsaKey = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);

        // Export keys for demonstration
        var publicKeyBytes = mldsaKey.ExportSubjectPublicKeyInfo();
        var privateKeyBytes = mldsaKey.ExportPkcs8PrivateKey();
        PrintPanel("Keys", [$":unlocked: Public: {publicKeyBytes.PrettyPrint()}", $":locked: Private: {privateKeyBytes.PrettyPrint()}"]);

        // Sign the data
        var signature = mldsaKey.SignData(data);
        PrintPanel("Signature", [$":pen: {signature.PrettyPrint()}"]);

        // Verify signature with the same key
        bool verified = mldsaKey.VerifyData(data, signature);
        PrintPanel("Verification", [$"{(verified ? ":check_mark_button:" : ":cross_mark:")} Verified!"]);

        // Demonstrate key import/export - recreate key from exported private key
        using var recoveredKey = MLDsa.ImportPkcs8PrivateKey(privateKeyBytes);
        var signature2 = recoveredKey.SignData(data);
        PrintPanel("Signature (from recovered key)", [$":pen: {signature2.PrettyPrint()}"]);

        // Verify second signature with a public-key-only instance
        using var publicOnlyKey = MLDsa.ImportSubjectPublicKeyInfo(publicKeyBytes);
        bool verifiedWithPublicKey = publicOnlyKey.VerifyData(data, signature2);
        PrintPanel("Reverification", [$"{(verifiedWithPublicKey ? ":check_mark_button:" : ":cross_mark:")} Verified!"]);
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

