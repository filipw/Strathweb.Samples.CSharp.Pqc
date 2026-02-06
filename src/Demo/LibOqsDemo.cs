using LibOQS.NET;
using Spectre.Console;
using System.Text;

public static class LibOqsDemo
{
    public static void RunMldsa()
    {
        if (!SigAlgorithm.MlDsa65.IsEnabled())
        {
            Helpers.PrintPanel("Error", [$":broken_heart: ML-DSA-65 is not enabled in this LibOQS build."]);
            return;
        }

        Console.WriteLine("***************** ML-DSA *******************");

        var raw = "Hello, ML-DSA!";
        Console.WriteLine($"Raw Message: {raw}");

        var data = Encoding.ASCII.GetBytes(raw);
        Helpers.PrintPanel("Message", [$"Raw: {raw}", $"Encoded: {data.PrettyPrint()}"]);

        using var sig = new SigInstance(SigAlgorithm.MlDsa65);

        // Generate key pair
        var (publicKey, secretKey) = sig.GenerateKeypair();
        Helpers.PrintPanel("Keys", [$":unlocked: Public: {publicKey.PrettyPrint()}", $":locked: Private: {secretKey.PrettyPrint()}"]);

        // Sign
        var signature = sig.Sign(data, secretKey);
        Helpers.PrintPanel("Signature", [$":pen: {signature.PrettyPrint()}"]);

        // Verify signature
        var verified = sig.Verify(data, signature, publicKey);
        Helpers.PrintPanel("Verification", [$"{(verified ? ":check_mark_button:" : ":cross_mark:")} Verified!"]);

        // Demonstrate key re-use - sign again with same key
        var signature2 = sig.Sign(data, secretKey);
        Helpers.PrintPanel("Signature (from recovered key)", [$":pen: {signature2.PrettyPrint()}"]);

        // Demonstrate verification with public-key-only scenario
        // In real world, verifier would only have the public key, not the full key pair
        using var verifierSig = new SigInstance(SigAlgorithm.MlDsa65);
        var verifiedWithPublicKeyOnly = verifierSig.Verify(data, signature2, publicKey);
        Helpers.PrintPanel("Reverification", [$"{(verifiedWithPublicKeyOnly ? ":check_mark_button:" : ":cross_mark:")} Verified!"]);
    }

    public static void RunMlKem()
    {
        if (!KemAlgorithm.MlKem768.IsEnabled())
        {
            Helpers.PrintPanel("Error", [$":broken_heart: ML-KEM-768 is not enabled in this LibOQS build."]);
            return;
        }

        Console.WriteLine("***************** ML-KEM *******************");

        using var kem = new KemInstance(KemAlgorithm.MlKem768);

        // generate key pair for Alice
        var (alicePublic, alicePrivate) = kem.GenerateKeypair();
        Helpers.PrintPanel("Alice's keys", [$":unlocked: Public: {alicePublic.PrettyPrint()}", $":locked: Private: {alicePrivate.PrettyPrint()}"]);

        // Bob encapsulates a new shared secret using Alice's public key
        var (cipherText, bobSecret) = kem.Encapsulate(alicePublic);

        // Alice decapsulates a new shared secret using Alice's private key
        byte[] aliceSecret = kem.Decapsulate(alicePrivate, cipherText);
        Helpers.PrintPanel("Key encapsulation", [$":man: Bob's secret: {bobSecret.PrettyPrint()}", $":locked_with_key: Cipher text (Bob -> Alice): {cipherText.PrettyPrint()}", $":woman: Alice's secret: {aliceSecret.PrettyPrint()}"]);

        // Compare secrets
        var equal = bobSecret.SequenceEqual(aliceSecret);
        Helpers.PrintPanel("Verification", [$"{(equal ? ":check_mark_button:" : ":cross_mark:")} Secrets equal!"]);
    }
}
