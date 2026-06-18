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

## Benchmarks

The `src/Benchmarks` project uses [BenchmarkDotNet](https://benchmarkdotnet.org/) to measure CPU time and managed memory allocations for each library × operation combination.  
Run with:

```
dotnet run -c Release --project src/Benchmarks
# filter to a single algorithm
dotnet run -c Release --project src/Benchmarks -- --filter *MlKem*
dotnet run -c Release --project src/Benchmarks -- --filter *MlDsa*
```

> **Note:** `[MemoryDiagnoser]` tracks managed heap allocations only. LibOQS.NET wraps a native C library — its native heap allocations are not reflected in the `Allocated` column.

### ML-KEM-768 — results

Benchmarked on .NET SDK 10.0.100, Windows 11 26H1 (OS build 28020.1546), Snapdragon X 12-core X1E80100 @ 3.40 GHz, ARM64, 32 GB RAM.

| Method | Mean | Error | StdDev | Median | Gen0 | Gen1 | Allocated |
|---|---:|---:|---:|---:|---:|---:|---:|
| SC Decapsulate | 17.15 µs | 0.019 µs | 0.015 µs | 17.15 µs | - | - | 56 B |
| SC Encapsulate | 25.83 µs | 0.285 µs | 0.253 µs | 25.77 µs | 0.2747 | 0.0305 | 1,240 B |
| LibOQS KeyGen | 33.19 µs | 0.994 µs | 2.930 µs | 33.80 µs | 0.9155 | - | 3,904 B |
| BC Encapsulate | 37.09 µs | 0.717 µs | 0.636 µs | 37.15 µs | 6.7139 | - | 28,312 B |
| LibOQS Encapsulate | 39.46 µs | 0.424 µs | 0.376 µs | 39.45 µs | 0.2441 | - | 1,168 B |
| LibOQS Decapsulate | 44.74 µs | 1.310 µs | 3.863 µs | 47.05 µs | - | - | 56 B |
| BC KeyGen | 44.82 µs | 0.885 µs | 0.785 µs | 44.76 µs | 5.4321 | - | 22,946 B |
| BC Decapsulate | 50.63 µs | 0.797 µs | 1.241 µs | 50.46 µs | 7.3853 | - | 30,888 B |
| SC KeyGen | 51.30 µs | 0.359 µs | 0.300 µs | 51.27 µs | - | - | 72 B |

### ML-DSA-65 — results

Benchmarked on .NET SDK 10.0.100, Windows 11 26H1 (OS build 28020.1546), Snapdragon X 12-core X1E80100 @ 3.40 GHz, ARM64, 32 GB RAM. Message size: 1 KB.

| Method | Mean | Error | StdDev | Median | Gen0 | Gen1 | Allocated |
|---|---:|---:|---:|---:|---:|---:|---:|
| LibOQS KeyGen | 104.7 µs | 1.29 µs | 1.21 µs | 104.6 µs | 1.4648 | - | 6,256 B |
| LibOQS Verify | 107.0 µs | 1.22 µs | 1.02 µs | 107.0 µs | - | - | - |
| BC Verify | 108.9 µs | 1.56 µs | 1.46 µs | 108.8 µs | 42.6025 | 0.1221 | 178,216 B |
| BC KeyGen | 118.0 µs | 1.90 µs | 3.70 µs | 116.5 µs | 45.7764 | 0.3662 | 191,480 B |
| SC Verify | 202.0 µs | 3.94 µs | 4.83 µs | 200.9 µs | - | - | 320 B |
| BC Sign | 251.5 µs | 4.97 µs | 10.26 µs | 255.3 µs | 65.1855 | 0.4883 | 273,592 B |
| LibOQS Sign | 409.4 µs | 6.70 µs | 6.27 µs | 410.3 µs | 1.4648 | - | 6,672 B |
| SC Sign | 546.5 µs | 10.83 µs | 24.90 µs | 542.6 µs | - | - | 3,337 B |
| SC KeyGen | 863.8 µs | 17.26 µs | 48.96 µs | 876.3 µs | - | - | 73 B |

## Further Reading

- Blog post: [Post quantum cryptography in .NET](https://www.strathweb.com/2023/02/post-quantum-cryptography-in-net/)
- See [Strathweb.Dilithium](https://github.com/filipw/Strathweb.Dilithium) for a reusable Dilithium library that's easy to integrate into various .NET features.
