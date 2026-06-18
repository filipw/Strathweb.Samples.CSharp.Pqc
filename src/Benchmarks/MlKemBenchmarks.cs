using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using LibOQS.NET;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

namespace Benchmarks;

/// <summary>
/// Benchmarks for ML-KEM-768 (key encapsulation mechanism) across three libraries.
/// 
/// Operations measured in isolation:
///   - KeyGen       : generate a fresh key pair
///   - Encapsulate  : produce ciphertext + shared secret from a public key
///   - Decapsulate  : recover shared secret from a private key + ciphertext
///
/// NOTE: [MemoryDiagnoser] tracks managed heap allocations only.
/// LibOQS.NET wraps a native C library; its native heap allocations are
/// not visible to the .NET GC and will not appear in the Allocated column.
///
/// System.Security.Cryptography benchmarks require Windows 26100.7171+
/// or Linux with OpenSSL 3.5+. On unsupported platforms they throw
/// NotSupportedException, which BenchmarkDotNet surfaces as a failed run.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
public class MlKemBenchmarks
{
    // ── BouncyCastle pre-generated state ──────────────────────────────────
    private MLKemPublicKeyParameters _bcPublicKey = null!;
    private MLKemPrivateKeyParameters _bcPrivateKey = null!;
    private byte[] _bcCipherText = null!;
    private readonly SecureRandom _bcRandom = new SecureRandom();

    // ── System.Security.Cryptography pre-generated state ─────────────────
    private MLKem? _scKeyPair;
    private byte[] _scPublicKeyBytes = null!;
    private byte[] _scCipherText = null!;
    private byte[] _scPrivateKeyBytes = null!;

    // ── LibOQS.NET pre-generated state ────────────────────────────────────
    private KemInstance _libOqsKem = null!;
    private byte[] _libOqsPublicKey = null!;
    private byte[] _libOqsPrivateKey = null!;
    private byte[] _libOqsCipherText = null!;

    [GlobalSetup]
    public void Setup()
    {
        // BouncyCastle
        var bcKeyGenParams = new MLKemKeyGenerationParameters(_bcRandom, MLKemParameters.ml_kem_768);
        var bcKeyGen = new MLKemKeyPairGenerator();
        bcKeyGen.Init(bcKeyGenParams);
        var bcKeyPair = bcKeyGen.GenerateKeyPair();
        _bcPublicKey = (MLKemPublicKeyParameters)bcKeyPair.Public;
        _bcPrivateKey = (MLKemPrivateKeyParameters)bcKeyPair.Private;

        var bcEncapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        bcEncapsulator.Init(new ParametersWithRandom(_bcPublicKey, _bcRandom));
        _bcCipherText = new byte[bcEncapsulator.EncapsulationLength];
        var bcSecret = new byte[bcEncapsulator.SecretLength];
        bcEncapsulator.Encapsulate(_bcCipherText, 0, _bcCipherText.Length, bcSecret, 0, bcSecret.Length);

        // System.Security.Cryptography
        if (MLKem.IsSupported)
        {
            _scKeyPair = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
            _scPublicKeyBytes = _scKeyPair.ExportEncapsulationKey();
            _scPrivateKeyBytes = _scKeyPair.ExportDecapsulationKey();

            using var bobKem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, _scPublicKeyBytes);
            bobKem.Encapsulate(out _scCipherText, out _);
        }

        // LibOQS.NET
        _libOqsKem = new KemInstance(KemAlgorithm.MlKem768);
        (_libOqsPublicKey, _libOqsPrivateKey) = _libOqsKem.GenerateKeypair();
        (_libOqsCipherText, _) = _libOqsKem.Encapsulate(_libOqsPublicKey);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _scKeyPair?.Dispose();
        _libOqsKem?.Dispose();
    }

    // ── BouncyCastle ──────────────────────────────────────────────────────

    [Benchmark(Description = "BC KeyGen")]
    public void BC_KeyGen()
    {
        var keyGenParams = new MLKemKeyGenerationParameters(_bcRandom, MLKemParameters.ml_kem_768);
        var keyGen = new MLKemKeyPairGenerator();
        keyGen.Init(keyGenParams);
        keyGen.GenerateKeyPair();
    }

    [Benchmark(Description = "BC Encapsulate")]
    public void BC_Encapsulate()
    {
        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(new ParametersWithRandom(_bcPublicKey, _bcRandom));
        var cipherText = new byte[encapsulator.EncapsulationLength];
        var secret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(cipherText, 0, cipherText.Length, secret, 0, secret.Length);
    }

    [Benchmark(Description = "BC Decapsulate")]
    public void BC_Decapsulate()
    {
        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        decapsulator.Init(_bcPrivateKey);
        var secret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(_bcCipherText, 0, _bcCipherText.Length, secret, 0, secret.Length);
    }

    // ── System.Security.Cryptography ─────────────────────────────────────

    [Benchmark(Description = "SC KeyGen")]
    public void SC_KeyGen()
    {
        if (!MLKem.IsSupported)
            throw new NotSupportedException("MLKem is not supported on this platform.");

        using var key = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
    }

    [Benchmark(Description = "SC Encapsulate")]
    public void SC_Encapsulate()
    {
        if (!MLKem.IsSupported)
            throw new NotSupportedException("MLKem is not supported on this platform.");

        using var bobKem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, _scPublicKeyBytes);
        bobKem.Encapsulate(out _, out _);
    }

    [Benchmark(Description = "SC Decapsulate")]
    public void SC_Decapsulate()
    {
        if (!MLKem.IsSupported)
            throw new NotSupportedException("MLKem is not supported on this platform.");

        _scKeyPair!.Decapsulate(_scCipherText);
    }

    // ── LibOQS.NET ────────────────────────────────────────────────────────

    [Benchmark(Description = "LibOQS KeyGen")]
    public void LibOqs_KeyGen()
    {
        using var kem = new KemInstance(KemAlgorithm.MlKem768);
        kem.GenerateKeypair();
    }

    [Benchmark(Description = "LibOQS Encapsulate")]
    public void LibOqs_Encapsulate()
    {
        _libOqsKem.Encapsulate(_libOqsPublicKey);
    }

    [Benchmark(Description = "LibOQS Decapsulate")]
    public void LibOqs_Decapsulate()
    {
        _libOqsKem.Decapsulate(_libOqsPrivateKey, _libOqsCipherText);
    }
}
