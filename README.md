# Data Integrity Verification System Using SHA-256

A small C++ console program for the course **ECE4113 – Secure Software Development**. It demonstrates the security service **data integrity**: detecting whether a message has been modified by comparing its newly calculated SHA-256 hash with a trusted reference hash.

> **Honest status note.** The code was compiled with `g++` and run with scripted inputs against OpenSSL 3.0.13 on **Linux** in the environment where it was generated. It has **not** been compiled or tested on Windows/MSYS2. Run the checklist in `tests/test_plan.md` on your own machine and record your own results.

> **Not production-grade.** This is an educational demonstration. See [Limitations](#limitations).

## Features

| Menu option | What it does |
|---|---|
| 1. Calculate a message hash | Hashes a typed message with OpenSSL SHA-256 and prints 64 hex characters (256 bits). |
| 2. Set the original reference message | Stores the message and its hash **in memory only** as the trusted reference. |
| 3. Verify a message | Hashes a message and compares it with the reference. Never replaces the reference. |
| 4. Demonstrate a message modification | Compares a modified message with the original and shows how many hex characters changed. |
| 5. Exit | Quits. |

Invalid menu choices, empty input and closed input (Ctrl+Z then Enter on Windows) are handled with clear messages and do not crash the program.

## Repository layout

```
data-integrity-verification/
├── README.md
├── .gitignore
├── src/
│   ├── main.cpp        menu, input, program flow
│   ├── integrity.h     declarations
│   └── integrity.cpp   OpenSSL SHA-256 + comparison
├── tests/
│   └── test_plan.md
└── docs/
    ├── report.md
    └── viva_guide.md   (extra: study guide for the oral exam)
```

**Our own code:** everything in `src/`. **External:** the OpenSSL library (SHA-256 implementation), the compiler, and the standards/documents listed in [References](#references). No hash algorithm is implemented by us.

## 1. VS Code vs compiler vs OpenSSL

These are three different things, and you need all three:

- **VS Code** is only a text editor. It does not compile anything by itself.
- **A C++ compiler** (here: `g++` from MinGW-w64) turns `.cpp` files into an `.exe`.
- **OpenSSL** is a library of cryptographic code. To use it from C++ you need its **development files**: header files (e.g. `openssl/evp.h`) and library files (e.g. `libcrypto`). The `openssl.exe` command-line tool alone does **not** guarantee these are present.

## 2. Recommended Windows setup (one consistent path): MSYS2 UCRT64

There are two common toolchains on Windows: **MinGW-w64 (via MSYS2)** and **MSVC (Visual Studio)**. Their commands and library files are not interchangeable. This README uses **only MSYS2 UCRT64 with `g++`**, because MSYS2 supplies the compiler *and* the OpenSSL headers/libraries through one package manager, and the VS Code documentation describes the same compiler setup.

### 2.1 Install MSYS2 and the tools

1. Install MSYS2 from the official site: <https://www.msys2.org/> (follow its installer instructions; the default folder is `C:\msys64`).
2. Open the **MSYS2 UCRT64** shell from the Start menu (not the plain "MSYS2 MSYS" one).
3. Update, then install the compiler and OpenSSL development files:

```bash
pacman -Syu
# the shell may ask you to close it; reopen "MSYS2 UCRT64" and continue
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-openssl
```

(Package names come from the MSYS2 package repository: <https://packages.msys2.org/>. If `pacman` reports a package not found, search that site for the current name.)

4. Add the UCRT64 `bin` folder to your Windows PATH so VS Code's terminal can find `g++`. With the default install this folder is `C:\msys64\ucrt64\bin` (see the VS Code guide in References). Then close and reopen VS Code.

### 2.2 Check what you have

In the VS Code terminal (PowerShell) or the UCRT64 shell:

```
g++ --version          # compiler present?
openssl version        # command-line tool present? (does NOT prove headers exist)
```

Check the **development files** (the important part):

```powershell
# PowerShell, default MSYS2 location:
Test-Path C:\msys64\ucrt64\include\openssl\evp.h     # should print True
Test-Path C:\msys64\ucrt64\lib\libcrypto.dll.a       # should print True
```

If either prints `False`, repeat the `pacman -S` step for OpenSSL.

## 3. Get the project

```
git clone <your-repository-url>
cd data-integrity-verification
```

or simply download the folder and open it in VS Code with **File → Open Folder**.

## 4. Compile

Run from the repository root (the folder containing `src`), in the VS Code terminal or the UCRT64 shell:

```
g++ -std=c++17 -Wall -Wextra -o integrity.exe src/main.cpp src/integrity.cpp -lcrypto
```

- `-std=c++17` uses the C++17 language standard.
- `-Wall -Wextra` turn on helpful warnings.
- `-o integrity.exe` names the output program.
- `-lcrypto` links OpenSSL's crypto library (this is where SHA-256 lives).

(The `.exe` is a build artifact and is ignored by `.gitignore`; do not commit it.)

## 5. Run

```
.\integrity.exe        # PowerShell
./integrity.exe        # UCRT64 shell
```

If Windows says a `.dll` is missing, run it from a terminal whose PATH includes `C:\msys64\ucrt64\bin` (see troubleshooting).

### Example session

```
Enter your choice (1-5): 2
Enter the ORIGINAL message to use as the trusted reference: Hello World
...
Enter your choice (1-5): 3
Enter the message to verify: Hello World!
RESULT: hashes DIFFER. The message has changed or does not match the reference.
```

## 6. Test

Follow `tests/test_plan.md`. It lists inputs and expected results; fill in the "Actual result" column yourself. One test uses a special build flag to simulate a hashing failure:

```
g++ -std=c++17 -DINTEGRITY_SIMULATE_FAILURE -o integrity_fail.exe src/main.cpp src/integrity.cpp -lcrypto
```

You can cross-check hashes with Windows PowerShell:

```powershell
"abc" | Out-File -NoNewline -Encoding ascii t.txt; Get-FileHash t.txt -Algorithm SHA256
```

The SHA-256 of `abc` should be `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` (this is a published NIST example value).

## 7. Common errors

| Symptom | Likely cause | Fix |
|---|---|---|
| `'g++' is not recognized...` | Compiler not installed or not on PATH | Install via MSYS2 (section 2.1), add `C:\msys64\ucrt64\bin` to PATH, restart VS Code. |
| `fatal error: openssl/evp.h: No such file or directory` | OpenSSL development files missing | Run the `pacman -S ... openssl` command; re-check with `Test-Path`. |
| `undefined reference to 'EVP_...'` | Missing `-lcrypto`, or flag placed before the source files | Use the exact command in section 4 (libraries go **after** the `.cpp` files). |
| `cannot find -lcrypto` | Wrong MSYS2 environment/compiler mix | Use the UCRT64 shell and the `ucrt64` packages consistently. |
| Program opens then complains about a missing `.dll` | Runtime DLLs not on PATH | Run from a terminal with `C:\msys64\ucrt64\bin` on PATH. |
| `openssl` works but compilation fails | CLI tool installed without headers/libs | Install the dev package (section 2.1). |
| Mixing MSVC (`cl`) commands with `g++` commands | Incompatible toolchains | Stay with the MSYS2 UCRT64 path in this README. |

## Limitations

- A plain SHA-256 hash **does not authenticate the sender** and does not prevent changes; it only helps **detect** changes when compared to a *trustworthy* reference.
- An attacker who can replace **both** the message and the reference hash defeats this demonstration.
- The reference is stored **only in memory**: lost when the program exits and not protected from tampering.
- Only typed single-line text is hashed (no files).
- Future improvement: use a keyed MAC such as HMAC, or digital signatures, when authenticity matters.

## References

External sources (we did not write these):

1. NIST, **FIPS 180-4, Secure Hash Standard (SHS)** – defines SHA-256. <https://csrc.nist.gov/pubs/fips/180-4/upd1/final>
2. NIST, **Cryptographic Standards and Guidelines – Example Values** (published SHA-256 test vectors, e.g. for "abc"). <https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values>
3. OpenSSL documentation, **EVP_DigestInit / EVP_DigestUpdate / EVP_DigestFinal_ex**. <https://docs.openssl.org/3.0/man3/EVP_DigestInit/>
4. OpenSSL Project home and documentation. <https://www.openssl.org/>
5. MSYS2 project (installer and `pacman` usage). <https://www.msys2.org/>
6. MSYS2 package search. <https://packages.msys2.org/>
7. Visual Studio Code documentation, **Using GCC with MinGW** (compiler setup on Windows). <https://code.visualstudio.com/docs/cpp/config-mingw>
8. NIST, **FIPS 198-1, The Keyed-Hash Message Authentication Code (HMAC)** – mentioned only as a possible future improvement. <https://csrc.nist.gov/pubs/fips/198-1/final>

