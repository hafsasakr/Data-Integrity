# Data Integrity Verification System Using SHA-256

**Course:** ECE4113 – Secure Software Development
**Team members:** [Hafsa – 241004443], [Mai – 231004675]

## Abstract

This project implements a small C++ console program that demonstrates the security service of **data integrity**. It uses the SHA-256 hash function from the OpenSSL library to compute a digest of a message, stores a trusted reference digest in memory, and later recomputes the digest to check whether the message has been modified. The project shows that even a small change in the input normally produces a very different digest, and it discusses why a plain hash cannot authenticate a sender or protect against an attacker who can replace both the data and the reference hash. It is an educational demonstration and not a production security system.

## 1. Introduction and Problem Statement

Data stored or sent over a network can be changed accidentally (transmission errors) or deliberately (an attacker). A receiver needs a way to **detect** such changes. The problem addressed here is: *given an original message and a trusted reference value, how can a program check whether a later copy of the message is unchanged?*

## 2. Objectives

- Explain data integrity and cryptographic hash functions.
- Use a real SHA-256 implementation (OpenSSL), not a homemade one.
- Build a simple, modular, beginner-readable C++ program with input validation and error handling.
- Demonstrate successful and failed integrity verification.
- Identify the limitations of the design honestly.

## 3. Security Concept: Data Integrity

**Data integrity** means that data has not been altered in an unauthorized way. Hashing does not *prevent* modification; it helps **detect** it, provided the value being compared against (the reference hash) is itself trustworthy.

Key points:
- **Hash vs encryption:** a hash function is one-way and keyless; it produces a fixed-size fingerprint and the original data cannot be recovered from it. Encryption is reversible with a key and is aimed at confidentiality.
- **Why a trusted reference is needed:** a new hash is only meaningful when compared with a known-good one. Computing a hash alone proves nothing about the data.
- **No sender authentication:** anyone can compute SHA-256 of any message, so a matching hash does not show *who* produced the message.
- **Attacker replaces both:** if an attacker can change the message *and* the stored reference hash, the check still passes. The reference must be protected (e.g. stored or transmitted over a separate trusted channel).
- **Future improvement:** a keyed construction such as HMAC (FIPS 198-1) or a digital signature addresses authenticity. It is not implemented here.

## 4. SHA-256 Mechanism (high level)

SHA-256 is defined in NIST FIPS 180-4. It takes input of any practical length and outputs a 256-bit (32-byte) digest, shown as 64 hexadecimal characters. At a high level:

1. The message is **padded** so its length is a multiple of 512 bits, with the original length appended.
2. The padded message is split into 512-bit **blocks**.
3. A 256-bit internal state (eight 32-bit words) starts from fixed initial values.
4. For each block, a **compression function** runs 64 rounds of bitwise operations, rotations, additions and fixed constants, mixing the block into the state.
5. The final state is the digest.

Because every input bit influences many rounds, changing even one input character normally changes about half the output bits (the *avalanche effect*). Finding two different inputs with the same digest is considered computationally infeasible with current knowledge.

## 5. System Design and Workflow

Three source files:

| File | Role |
|---|---|
| `src/main.cpp` | Menu, user input, validation, output |
| `src/integrity.h` | Declarations of the hashing and comparison functions |
| `src/integrity.cpp` | OpenSSL SHA-256 calculation, hex conversion, comparison |

Workflow: the user chooses a menu option → `main.cpp` reads and validates input → calls `integrity::computeSha256Hex` → compares with `integrity::hashesMatch` where needed → prints the result. The reference (original message + hash) is held in a struct in memory for the session; verification never modifies it.

Menu: (1) calculate hash, (2) set reference, (3) verify, (4) demonstrate modification, (5) exit.

## 6. Implementation Details

- **OpenSSL EVP API:** `EVP_MD_CTX_new`, `EVP_DigestInit_ex(..., EVP_sha256(), ...)`, `EVP_DigestUpdate`, `EVP_DigestFinal_ex`, `EVP_MD_CTX_free`. Every call's return value is checked (1 = success) and the context is always freed. The low-level `SHA256_*` functions are deprecated in OpenSSL 3.0, so EVP is used.
- **Hex conversion:** each of the 32 bytes is printed as two lowercase hex digits using `std::hex`, `std::setw(2)` and `std::setfill('0')`.
- **Comparison:** `hashesMatch` compares the two hex strings for exact equality.
- **Input handling:** `std::getline` reads whole lines (spaces allowed); empty input, invalid menu choices and closed input streams are handled with messages. Messages are not trimmed because spaces change the hash.
- **Error handling:** a hashing failure produces an error message and leaves the existing reference unchanged. A compile-time flag `INTEGRITY_SIMULATE_FAILURE` exists only to test this path.
- **Build:** MSYS2 UCRT64 with `g++`, linking `-lcrypto` (see README).

## 7. Test Plan and Results

The full plan is in `tests/test_plan.md` (15 cases: normal hash, repeated hash, one-character change, different message, unchanged message, verification before reference, empty input, invalid menu choice, simulated hashing failure, and others).

| Test group | Status |
|---|---|
| Hashing (T1, T2, T12) | **[RESULT PLACEHOLDER – run on team machine and record]** |
| Verification / modification (T3–T6, T13) | **[RESULT PLACEHOLDER]** |
| Input handling (T7–T11, T15) | **[RESULT PLACEHOLDER]** |
| Simulated hashing failure (T14) | **[RESULT PLACEHOLDER]** |

*Do not replace these placeholders until the tests have actually been run. Optionally add a screenshot of a run and of the Windows build.*

## 8. Limitations and Possible Improvements

**Limitations**
- A plain hash gives no sender authentication.
- If an attacker replaces both the message and the reference hash, the change goes undetected.
- The reference exists only in memory; it is lost on exit and not tamper-protected.
- Only single-line typed text is supported; files are not hashed.
- Not a production-grade security system.

**Possible improvements**
- Use HMAC-SHA-256 with a secret key, or digital signatures, for authenticity.
- Hash files in chunks.
- Store the reference hash in a separate, protected location.
- Automated unit tests.

## 9. Conclusion

The project demonstrates, with a real SHA-256 implementation from OpenSSL, how comparing a recomputed hash with a trusted reference can detect modification of data. It also shows, honestly, where this simple approach stops being sufficient and which mechanisms (HMAC, signatures, protected storage) address those gaps.

## 10. References

1. NIST, *FIPS 180-4: Secure Hash Standard (SHS)*. https://csrc.nist.gov/pubs/fips/180-4/upd1/final
2. NIST, *Cryptographic Standards and Guidelines – Example Values*. https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
3. OpenSSL, *EVP_DigestInit documentation (3.0)*. https://docs.openssl.org/3.0/man3/EVP_DigestInit/
4. OpenSSL Project. https://www.openssl.org/
5. MSYS2. https://www.msys2.org/ and https://packages.msys2.org/
6. Visual Studio Code, *Using GCC with MinGW*. https://code.visualstudio.com/docs/cpp/config-mingw
7. NIST, *FIPS 198-1: The Keyed-Hash Message Authentication Code (HMAC)*. https://csrc.nist.gov/pubs/fips/198-1/final


