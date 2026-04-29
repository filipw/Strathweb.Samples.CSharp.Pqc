# Strathweb.Samples.CSharp.Crystals

Demo code showcasing Post-Quantum Cryptography (PQC) in .NET using three different approaches.

## Approaches

The demo covers three ways to use PQC algorithms in .NET:

| | System.Security.Cryptography | BouncyCastle | Maybe LibOQS.NET |
|---|---|---|---|
| **Type** | .NET System API | Fully Managed | Native Wrapper |
| **Windows** | 26100.7171+ | ✅ | ✅ |
| **Linux** | OpenSSL 3.5+ | ✅ | ✅ |
| **Mac** | ❌ | ✅ | ✅ |
| **WASM & others** | ❌ | ✅ | ❌ |
| **Platform** | .NET 10+ (partly experimental) | .NET Standard 2.0 | .NET Standard 2.0 |
| **Algorithms** | 2/3 | 11 | 16 |
| **Key Advantage** | Official | Maximum Portability | Uses liboqs |

### System.Security.Cryptography

The built-in .NET API (`System.Security.Cryptography`) gained PQC support in .NET 10. It is the official approach but has platform limitations — it requires Windows 26100.7171+ or Linux with OpenSSL 3.5+, and is not supported on macOS or WASM. Some APIs are still experimental.

### BouncyCastle

[BouncyCastle](https://www.bouncycastle.org/) is a fully managed cryptography library targeting .NET Standard 2.0. It supports 11 PQC algorithms and runs on all platforms including macOS and WASM, making it the most portable option.

### Maybe LibOQS.NET

[Maybe LibOQS.NET](https://github.com/filipw/maybe-liboqs-dotnet) is a .NET wrapper around [liboqs](https://github.com/open-quantum-safe/liboqs), the Open Quantum Safe C library. It targets .NET Standard 2.0 and supports 16 PQC algorithms. Because it wraps a native library, it does not support WASM or other non-native targets.

## Further Reading

- Blog post: [Post quantum cryptography in .NET](https://www.strathweb.com/2023/02/post-quantum-cryptography-in-net/)
- See [Strathweb.Dilithium](https://github.com/filipw/Strathweb.Dilithium) for a reusable Dilithium library that's easy to integrate into various .NET features.
