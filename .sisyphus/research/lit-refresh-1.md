# Literature Refresh #1 (2024-2026)

This document summarizes new papers relevant to publicly verifiable threshold FHE, lattice folding, and recursive SNARKs discovered during the 2026 literature refresh.

## New Papers

### Threshold Fully Homomorphic Encryption with Synchronized Decryptors
- **ePrint ID**: 2026/031
- **Authors**: François Colin de Verdière, Alain Passelègue, Damien Stehlé
- **Year**: 2026
- **Summary**: This paper studies ThFHE in the synchronous setting and identifies security vulnerabilities in existing schemes (e.g., key-recovery attacks). It proposes a simple and efficient construction achieving strong security by masking partial decryption shares with pseudorandom functions (PRFs).
- **Relevance Tag**: arch-A, general

### Threshold FHE with Efficient Asynchronous Decryption
- **ePrint ID**: 2025/712
- **Authors**: Zvika Brakerski, Offir Friedman, Avichai Marmor, Dolev Mutzari, Yuval Spiizer, Ni Trieu
- **Year**: 2025
- **Summary**: This work addresses scaling challenges in ThFHE by operating in the asynchronous communication model and reducing the overhead on public parameters. It introduces a preprocessing technique to batch and perform zero-knowledge proofs (ZKPs) in an offline phase, mitigating the computational cost of malicious security during the online decryption phase.
- **Relevance Tag**: arch-A, arch-B, general

### Cyclo: Lightweight Lattice-based Folding via Partial Range Checks
- **ePrint ID**: 2026/359
- **Authors**: Albert Garreta, Helger Lipmaa, Urmas Luhaäär, Michał Osadnik
- **Year**: 2026
- **Summary**: Cyclo improves upon LatticeFold+ by eliminating the need for norm checks on the accumulator through an amortized norm-refreshing design. It only performs range checks on the input witness, reducing prover overhead and achieving proof sizes significantly smaller (order of 30 KB) than previous lattice-based folding schemes.
- **Relevance Tag**: arch-B, arch-C

### Practical Post-Quantum Secure Publicly Verifiable Secret Sharing and Applications
- **ePrint ID**: 2026/813
- **Authors**: Aniket Kate, Pratyay Mukherjee, Hamza Saleem, Pratik Sarkar, Rohit Sinha
- **Year**: 2026
- **Summary**: This paper presents a PVSS framework with non-interactive dealers using lattice-based identity-based encryption (IBE) and commitments. It avoids expensive zero-knowledge proofs for verification and demonstrates a significant performance improvement over state-of-the-art lattice-based PVSS, specifically targeting blockchain-compatible applications like secure voting.
- **Relevance Tag**: arch-B, general

### Verifiable Computation for Approximate Homomorphic Encryption Schemes
- **ePrint ID**: 2025/286
- **Authors**: Ignacio Cascudo, Anamaria Costache, Daniele Cozzo, Dario Fiore, Antonio Guimarães, Eduardo Soria-Vazquez
- **Year**: 2025
- **Summary**: This work focuses on proving the validity of homomorphic computations specifically for the CKKS scheme. It introduces a succinct argument system that handles polynomial ring arithmetic and maintenance operations (modulus switching, rescaling) natively without emulation overhead, scaling efficiently to large circuits.
- **Relevance Tag**: arch-C, general

### High-Throughput Universally Composable Threshold FHE Decryption
- **ePrint ID**: 2025/1781
- **Authors**: Guy Zyskind, Doron Zarchy, Max Leibovich, Chris Peikert
- **Year**: 2025
- **Summary**: Proposes a novel threshold FHE decryption protocol that avoids noise flooding and provides simulation-based security in the Universal Composability (UC) framework. It securely removes ciphertext noise via an efficient MPC rounding procedure, significantly improving throughput and latency compared to noise flooding approaches.
- **Relevance Tag**: arch-A, general

### Hermine: An Efficient Lattice-based FROST-like Threshold Signature
- **ePrint ID**: 2026/419
- **Authors**: Giacomo Borin, Sofía Celi, Rafael del Pino, Thomas Espitau, Shuichi Katsumata, Guilhem Niot, Thomas Prest, Kaoru Takemure
- **Year**: 2026
- **Summary**: While focused on signatures, Hermine introduces "everywhere-short secret sharing," which splits a short secret vector into short shares and admits a short linear reconstruction. This technique is highly relevant to lattice-based PVSS and threshold FHE key management where short secrets must be distributed and reconstructed.
- **Relevance Tag**: arch-B, general
