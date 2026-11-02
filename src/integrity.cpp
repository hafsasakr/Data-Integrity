// integrity.cpp
// Implementation of SHA-256 hashing (written by hand, no libraries) and
// hash comparison.
//
// OVERVIEW OF HOW SHA-256 WORKS:
//   1. Pad the message so its length is a multiple of 64 bytes.
//   2. Start with 8 fixed 32-bit numbers (the "state").
//   3. For every 64-byte block, scramble the state with 64 rounds of
//      bit rotations, XORs and additions.
//   4. The final state, written out as 32 bytes, is the hash.

#include "integrity.h"

#include <array>      // std::array: fixed-size arrays
#include <cstdint>    // std::uint8_t, std::uint32_t, std::uint64_t: exact-size integers
#include <exception>  // std::exception: used to catch unexpected failures
#include <iomanip>    // std::setw, std::setfill: formatting the hex output
#include <sstream>    // std::ostringstream: building the hex string
#include <vector>     // std::vector: resizable array for the padded message

namespace {  // Anonymous namespace: these helpers are private to this file.

// ===========================================================================
// SHA-256 CONSTANTS
// ===========================================================================

// Round constants (one per round, 64 rounds).
// Each is the first 32 bits of the fractional part of the cube root of one
// of the first 64 prime numbers. Using a different constant in every round
// stops the rounds from being identical to each other.
constexpr std::array<std::uint32_t, 64> K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// ===========================================================================
// SHA-256 HELPER FUNCTIONS (the small bit-mixing tools)
// ===========================================================================

// Rotate right: shift x right by n bits, and bits that fall off the right
// end re-enter on the left. Unlike a plain shift, no information is lost.
inline std::uint32_t rotr(std::uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

// "Choose": for each of the 32 bit positions, if the bit in e is 1 the result
// takes f's bit, otherwise it takes g's bit. Acts like a bit-wise if/else.
inline std::uint32_t choose(std::uint32_t e, std::uint32_t f, std::uint32_t g) {
    return (e & f) ^ (~e & g);
}

// "Majority": for each bit position, the result is whichever value (0 or 1)
// appears in at least two of the three inputs. Like a bit-wise vote.
inline std::uint32_t majority(std::uint32_t a, std::uint32_t b, std::uint32_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

// Bit scramblers. Each combines rotations (and for the small ones, a plain
// shift) with XOR so that every output bit depends on several input bits.
// The "big" sigmas are used inside the 64 rounds; the "small" sigmas are
// used when expanding the message schedule.
inline std::uint32_t bigSigma0(std::uint32_t x)   { return rotr(x, 2)  ^ rotr(x, 13) ^ rotr(x, 22); }
inline std::uint32_t bigSigma1(std::uint32_t x)   { return rotr(x, 6)  ^ rotr(x, 11) ^ rotr(x, 25); }
inline std::uint32_t smallSigma0(std::uint32_t x) { return rotr(x, 7)  ^ rotr(x, 18) ^ (x >> 3); }
inline std::uint32_t smallSigma1(std::uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

// ===========================================================================
// processBlock: THE ENGINE
// Scrambles ONE 64-byte block into the running hash state.
// ===========================================================================
void processBlock(const std::uint8_t* block, std::array<std::uint32_t, 8>& state) {

    // STEP 1: Message schedule.
    // Build 64 words (w[0..63]) from the 64 bytes of the block.
    std::array<std::uint32_t, 64> w{};

    // First 16 words: read 4 bytes at a time, big-endian
    // (the first byte becomes the highest 8 bits of the word).
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
               (static_cast<std::uint32_t>(block[i * 4 + 3]));
    }

    // Remaining 48 words: each is computed from earlier words using rotations
    // and shifts. This spreads every input bit across many later rounds.
    for (std::size_t i = 16; i < 64; ++i) {
        w[i] = smallSigma1(w[i - 2]) + w[i - 7] + smallSigma0(w[i - 15]) + w[i - 16];
    }

    // STEP 2: Working variables.
    // Copy the current state into a..h so we can scramble them without losing
    // the original state (we need it again in step 4).
    std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    std::uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    // STEP 3: 64 rounds of mixing.
    // All additions wrap around at 2^32, which uint32_t does automatically.
    for (std::size_t i = 0; i < 64; ++i) {
        // t1 mixes in: the variable h, a bit-scramble of e, a bit-by-bit
        // "if e then f else g", this round's constant K[i], and this round's
        // message word w[i] (this is where your data actually enters).
        const std::uint32_t t1 = h + bigSigma1(e) + choose(e, f, g) + K[i] + w[i];

        // t2 mixes in: a bit-scramble of a, and the majority vote of a, b, c.
        const std::uint32_t t2 = bigSigma0(a) + majority(a, b, c);

        // Shift every variable down one slot (like a conveyor belt)...
        h = g;
        g = f;
        f = e;
        e = d + t1;  // ...but e and a receive the freshly mixed values.
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // STEP 4: Feed-forward.
    // Add the scrambled variables back into the original state. This addition
    // is what makes the function one-way: without it, the rounds above could
    // be run backwards.
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// ===========================================================================
// sha256Manual: THE DRIVER
// Computes the raw 32-byte SHA-256 digest of the message.
// ===========================================================================
std::array<std::uint8_t, 32> sha256Manual(const std::string& message) {

    // STEP 1: Initial state.
    // Eight 32-bit numbers that together form the running 256-bit hash.
    // They are fixed by the standard (fractional parts of the square roots of
    // the first 8 primes), so everyone starts from the same place.
    std::array<std::uint32_t, 8> state = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    // STEP 2: Padding.
    // SHA-256 only works on 64-byte blocks, so we stretch the message:
    //   [ message ][ 0x80 ][ zeros ... ][ original length in bits (8 bytes) ]
    std::vector<std::uint8_t> data(message.begin(), message.end());

    // Length in BITS (bytes * 8), saved before we modify the data.
    const std::uint64_t bitLength = static_cast<std::uint64_t>(message.size()) * 8;

    // 0x80 = binary 10000000: a single "1" bit marking the end of the message.
    data.push_back(0x80);

    // Add zero bytes until the size is 56 mod 64, leaving exactly 8 bytes of
    // room at the end of the last block for the length.
    while (data.size() % 64 != 56) {
        data.push_back(0x00);
    }

    // Append the bit length as 8 bytes, most significant byte first (big-endian).
    // shift goes 56, 48, 40, ... 0, picking out one byte at a time.
    for (int shift = 56; shift >= 0; shift -= 8) {
        data.push_back(static_cast<std::uint8_t>((bitLength >> shift) & 0xff));
    }

    // STEP 3: Process each 64-byte block.
    // The output state of one block is the input state of the next, so the
    // final hash depends on the whole message, in order.
    for (std::size_t offset = 0; offset < data.size(); offset += 64) {
        processBlock(data.data() + offset, state);
    }

    // STEP 4: Produce the digest.
    // Turn the eight 32-bit words into 32 bytes, big-endian
    // (most significant byte of each word first).
    std::array<std::uint8_t, 32> digest{};
    for (std::size_t i = 0; i < 8; ++i) {
        digest[i * 4]     = static_cast<std::uint8_t>((state[i] >> 24) & 0xff);  // top byte
        digest[i * 4 + 1] = static_cast<std::uint8_t>((state[i] >> 16) & 0xff);
        digest[i * 4 + 2] = static_cast<std::uint8_t>((state[i] >> 8) & 0xff);
        digest[i * 4 + 3] = static_cast<std::uint8_t>(state[i] & 0xff);          // bottom byte
    }
    return digest;
}

// ===========================================================================
// bytesToHex
// Converts raw bytes into lowercase hexadecimal text.
// Example: the single byte 0x0A becomes "0a" (two characters, never just "a").
// ===========================================================================
std::string bytesToHex(const std::uint8_t* bytes, std::size_t length) {
    std::ostringstream stream;
    // std::hex prints numbers in base 16. setfill('0') pads with zeros.
    // setfill stays active; setw(2) must be repeated for every byte.
    stream << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < length; ++i) {
        // Cast to int, otherwise the stream would print the byte as a character.
        stream << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return stream.str();
}

}  // namespace

// ===========================================================================
// PUBLIC FUNCTIONS (declared in integrity.h)
// ===========================================================================
namespace integrity {

// Computes the SHA-256 hash of `message` and returns it as 64 hex characters.
// Returns true on success. On failure returns false and fills errorMessage.
bool computeSha256Hex(const std::string& message,
                      std::string& hexDigest,
                      std::string& errorMessage) {
    hexDigest.clear();      // Never leave an old value behind
    errorMessage.clear();

#ifdef INTEGRITY_SIMULATE_FAILURE
    // Test hook: compile with -DINTEGRITY_SIMULATE_FAILURE to prove that the
    // program handles a hashing failure without crashing (see tests/test_plan.md).
    errorMessage = "Simulated hashing failure (test build only).";
    return false;
#endif

    try {
        // Run the manual SHA-256 algorithm.
        const std::array<std::uint8_t, 32> digest = sha256Manual(message);

        // Sanity check: SHA-256 must always produce exactly 32 bytes.
        if (digest.size() != SHA256_HEX_LENGTH / 2) {
            errorMessage = "Unexpected digest length from manual SHA-256.";
            return false;
        }

        // Convert the 32 raw bytes into a 64-character hex string.
        hexDigest = bytesToHex(digest.data(), digest.size());
        return true;
    } catch (const std::exception& ex) {
        // The only realistic failure is running out of memory for the padded copy.
        errorMessage = std::string("Manual SHA-256 failed: ") + ex.what();
        hexDigest.clear();
        return false;
    }
}

// Returns true only if both hashes are identical.
bool hashesMatch(const std::string& computedHash,
                 const std::string& referenceHash) {
    // std::string's == compares length and every character.
    // (Both hashes are public values here, so a timing-safe comparison is not
    // needed for this demonstration.)
    return computedHash == referenceHash;
}

// Counts how many hex characters differ between two hashes.
// Useful for showing the avalanche effect: a tiny input change flips most of them.
std::size_t countDifferentHexChars(const std::string& hashA,
                                   const std::string& hashB) {
    const std::size_t shorter = hashA.size() < hashB.size() ? hashA.size() : hashB.size();
    const std::size_t longer = hashA.size() < hashB.size() ? hashB.size() : hashA.size();

    std::size_t differences = longer - shorter;  // Unmatched extra characters
    for (std::size_t i = 0; i < shorter; ++i) {
        if (hashA[i] != hashB[i]) {
            ++differences;
        }
    }
    return differences;
}

}  // namespace integrity