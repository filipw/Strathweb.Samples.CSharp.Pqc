using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Spectre.Console;

public static class BouncyCastleDemo
{
    public static void RunMldsa()
    {
        Console.WriteLine("***************** ML-DSA *******************");

        var raw = "Hello, ML-DSA!";
        Console.WriteLine($"Raw Message: {raw}");

        var data = Hex.Encode(Encoding.ASCII.GetBytes(raw));
        Helpers.PrintPanel("Message", [$"Raw: {raw}", $"Encoded: {data.PrettyPrint()}"]);

        // Initialize key generation
        var random = new SecureRandom();
        var keyGenParameters = new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_65); // Equivalent to Dilithium3
        var mldsaKeyPairGenerator = new MLDsaKeyPairGenerator();
        mldsaKeyPairGenerator.Init(keyGenParameters);

        // Generate key pair
        var keyPair = mldsaKeyPairGenerator.GenerateKeyPair();

        // Get and view the keys
        var publicKey = (MLDsaPublicKeyParameters)keyPair.Public;
        var privateKey = (MLDsaPrivateKeyParameters)keyPair.Private;
        var pubEncoded = publicKey.GetEncoded();
        var privateEncoded = privateKey.GetEncoded();
        Helpers.PrintPanel("Keys", [$":unlocked: Public: {pubEncoded.PrettyPrint()}", $":locked: Private: {privateEncoded.PrettyPrint()}"]);

        // Sign
        var alice = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
        alice.Init(true, privateKey);
        alice.BlockUpdate(data, 0, data.Length);
        var signature = alice.GenerateSignature();
        Helpers.PrintPanel("Signature", [$":pen: {signature.PrettyPrint()}"]);

        // Verify signature
        var bob = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
        bob.Init(false, publicKey);
        bob.BlockUpdate(data, 0, data.Length);
        var verified = bob.VerifySignature(signature);
        Helpers.PrintPanel("Verification", [$"{(verified ? ":check_mark_button:" : ":cross_mark:")} Verified!"]);

        // Recreate signer from exported private key
        var recoveredKey = MLDsaPrivateKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, privateKey.GetEncoded());
        var aliceRecovered = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
        aliceRecovered.Init(true, recoveredKey);
        aliceRecovered.BlockUpdate(data, 0, data.Length);
        var signature2 = aliceRecovered.GenerateSignature();
        Helpers.PrintPanel("Signature (from recovered key)", [$":pen: {signature2.PrettyPrint()}"]);

        // Verify second signature
        bob.Init(false, publicKey);
        bob.BlockUpdate(data, 0, data.Length);
        var bobReVerified = bob.VerifySignature(signature2);
        Helpers.PrintPanel("Reverification", [$"{(bobReVerified ? ":check_mark_button:" : ":cross_mark:")} Verified!"]);
    }

    public static void RunMlKem()
    {
        Console.WriteLine("***************** ML-KEM *******************");

        var random = new SecureRandom();
        var keyGenParameters = new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768);

        var kyberKeyPairGenerator = new MLKemKeyPairGenerator();
        kyberKeyPairGenerator.Init(keyGenParameters);

        // generate key pair for Alice
        var aliceKeyPair = kyberKeyPairGenerator.GenerateKeyPair();

        // get and view the keys
        var alicePublic = (MLKemPublicKeyParameters)aliceKeyPair.Public;
        var alicePrivate = (MLKemPrivateKeyParameters)aliceKeyPair.Private;
        var pubEncoded = alicePublic.GetEncoded();
        var privateEncoded = alicePrivate.GetEncoded();
        Helpers.PrintPanel("Alice's keys", [$":unlocked: Public: {pubEncoded.PrettyPrint()}", $":locked: Private: {privateEncoded.PrettyPrint()}"]);

        // Bob encapsulates a new shared secret using Alice's public key
        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(new ParametersWithRandom(alicePublic, random));

        var cipherText = new byte[encapsulator.EncapsulationLength];
        var bobSecret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(cipherText, 0, cipherText.Length, bobSecret, 0, bobSecret.Length);

        // Alice decapsulates a new shared secret using Alice's private key
        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        decapsulator.Init(alicePrivate);

        byte[] aliceSecret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(cipherText, 0, cipherText.Length, aliceSecret, 0, aliceSecret.Length);
        Helpers.PrintPanel("Key encapsulation", [$":man: Bob's secret: {bobSecret.PrettyPrint()}", $":locked_with_key: Cipher text (Bob -> Alice): {cipherText.PrettyPrint()}", $":woman: Alice's secret: {aliceSecret.PrettyPrint()}"]);

        // Compare secrets
        var equal = bobSecret.SequenceEqual(aliceSecret);
        Helpers.PrintPanel("Verification", [$"{(equal ? ":check_mark_button:" : ":cross_mark:")} Secrets equal!"]);
    }
}