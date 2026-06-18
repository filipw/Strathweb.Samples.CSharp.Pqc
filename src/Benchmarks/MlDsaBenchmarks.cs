using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using LibOQS.NET;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;

namespace Benchmarks;

/// <summary>
/// Benchmarks for ML-DSA-65 (digital signature algorithm) across three libraries.
///
/// Operations measured in isolation:
///   - KeyGen : generate a fresh key pair
///   - Sign   : produce a signature over a fixed 1 KB message
///   - Verify : verify a pre-computed signature against the message
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
public class MlDsaBenchmarks
{
    // Fixed 1 KB message used for all Sign/Verify benchmarks
    private static readonly byte[] Message = new byte[1024];

    // ── BouncyCastle pre-generated state ──────────────────────────────────
    private MLDsaPublicKeyParameters _bcPublicKey = null!;
    private MLDsaPrivateKeyParameters _bcPrivateKey = null!;
    private byte[] _bcSignature = null!;
    private readonly SecureRandom _bcRandom = new SecureRandom();

    // ── System.Security.Cryptography pre-generated state ─────────────────
    private MLDsa? _scKeyPair;
    private byte[] _scPublicKeyBytes = null!;
    private byte[] _scSignature = null!;

    // ── LibOQS.NET pre-generated state ────────────────────────────────────
    private SigInstance _libOqsSig = null!;
    private byte[] _libOqsPublicKey = null!;
    private byte[] _libOqsPrivateKey = null!;
    private byte[] _libOqsSignature = null!;

    [GlobalSetup]
    public void Setup()
    {
        // Fill message with deterministic data so results are consistent
        for (int i = 0; i < Message.Length; i++)
            Message[i] = (byte)(i & 0xFF);

        // BouncyCastle
        var bcKeyGenParams = new MLDsaKeyGenerationParameters(_bcRandom, MLDsaParameters.ml_dsa_65);
        var bcKeyGen = new MLDsaKeyPairGenerator();
        bcKeyGen.Init(bcKeyGenParams);
        var bcKeyPair = bcKeyGen.GenerateKeyPair();
        _bcPublicKey = (MLDsaPublicKeyParameters)bcKeyPair.Public;
        _bcPrivateKey = (MLDsaPrivateKeyParameters)bcKeyPair.Private;

        var bcSigner = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
        bcSigner.Init(true, _bcPrivateKey);
        bcSigner.BlockUpdate(Message, 0, Message.Length);
        _bcSignature = bcSigner.GenerateSignature();

        // System.Security.Cryptography
        if (MLDsa.IsSupported)
        {
            _scKeyPair = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
            _scPublicKeyBytes = _scKeyPair.ExportSubjectPublicKeyInfo();
            _scSignature = _scKeyPair.SignData(Message);
        }

        // LibOQS.NET
        _libOqsSig = new SigInstance(SigAlgorithm.MlDsa65);
        (_libOqsPublicKey, _libOqsPrivateKey) = _libOqsSig.GenerateKeypair();
        _libOqsSignature = _libOqsSig.Sign(Message, _libOqsPrivateKey);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _scKeyPair?.Dispose();
        _libOqsSig?.Dispose();
    }

    // ── BouncyCastle ──────────────────────────────────────────────────────

    [Benchmark(Description = "BC KeyGen")]
    public void BC_KeyGen()
    {
        var keyGenParams = new MLDsaKeyGenerationParameters(_bcRandom, MLDsaParameters.ml_dsa_65);
        var keyGen = new MLDsaKeyPairGenerator();
        keyGen.Init(keyGenParams);
        keyGen.GenerateKeyPair();
    }

    [Benchmark(Description = "BC Sign")]
    public void BC_Sign()
    {
        var signer = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
        signer.Init(true, _bcPrivateKey);
        signer.BlockUpdate(Message, 0, Message.Length);
        signer.GenerateSignature();
    }

    [Benchmark(Description = "BC Verify")]
    public void BC_Verify()
    {
        var verifier = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: true);
        verifier.Init(false, _bcPublicKey);
        verifier.BlockUpdate(Message, 0, Message.Length);
        verifier.VerifySignature(_bcSignature);
    }

    // ── System.Security.Cryptography ─────────────────────────────────────

    [Benchmark(Description = "SC KeyGen")]
    public void SC_KeyGen()
    {
        if (!MLDsa.IsSupported)
            throw new NotSupportedException("MLDsa is not supported on this platform.");

        using var key = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);
    }

    [Benchmark(Description = "SC Sign")]
    public void SC_Sign()
    {
        if (!MLDsa.IsSupported)
            throw new NotSupportedException("MLDsa is not supported on this platform.");

        _scKeyPair!.SignData(Message);
    }

    [Benchmark(Description = "SC Verify")]
    public void SC_Verify()
    {
        if (!MLDsa.IsSupported)
            throw new NotSupportedException("MLDsa is not supported on this platform.");

        using var pubKey = MLDsa.ImportSubjectPublicKeyInfo(_scPublicKeyBytes);
        pubKey.VerifyData(Message, _scSignature);
    }

    // ── LibOQS.NET ────────────────────────────────────────────────────────

    [Benchmark(Description = "LibOQS KeyGen")]
    public void LibOqs_KeyGen()
    {
        using var sig = new SigInstance(SigAlgorithm.MlDsa65);
        sig.GenerateKeypair();
    }

    [Benchmark(Description = "LibOQS Sign")]
    public void LibOqs_Sign()
    {
        _libOqsSig.Sign(Message, _libOqsPrivateKey);
    }

    [Benchmark(Description = "LibOQS Verify")]
    public void LibOqs_Verify()
    {
        _libOqsSig.Verify(Message, _libOqsSignature, _libOqsPublicKey);
    }
}
