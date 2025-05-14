/* Copyright (c) 2024 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "reference.h"

#define HTOBE32(x) (((x) >> 24) | (((x) >> 8) & 0xFF00) | \
    (((x) << 8) & 0xFF0000) | (((x) & 0xFF) << 24))
#define HTOBE64(x) (((x) >> 56) | (((x) >> 40) & 0xFF00) | \
    (((x) >> 24) & 0xFF0000) | (((x) >> 8) & 0xFF000000) | \
    (((x) & 0xFF000000) << 8) | (((x) & 0xFF0000) << 24) | \
    (((x) & 0xFF00) << 40) | ((x) << 56))

#define ROR64(x, n) ((x) >> (n) | ((x) << (64 - (n))))

#define SHA512_INIT_F1(i) \
    (ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7))
#define SHA512_INIT_F2(i) \
    (ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6))
#define SHA512_INIT_EXP(i) \
    w[i] = w[i - 16] + SHA512_INIT_F1(i) + w[i - 7] + SHA512_INIT_F2(i)

#define SHA512_STEP(a, b, c, d, e, f, g, h, n) \
    tmp1 = h + (ROR64(e, 14) ^ ROR64(e, 18) ^ ROR64(e, 41)) + \
      ((e & f) ^ ((~e) & g)) + sha512_init_round_vector[n] + w[n]; \
    tmp2 = (ROR64(a, 28) ^ ROR64(a, 34) ^ ROR64(a, 39)) + \
      ((a & b) ^ (a & c) ^ (b & c)); \
    d += tmp1; \
    h = tmp1 + tmp2

const uint64_t sha512_init_vector[8] = {
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
  0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

const uint64_t sha512_init_round_vector[80] = {
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
  0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
  0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
  0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
  0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
  0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
  0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
  0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
  0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
  0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
  0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
  0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
  0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
  0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
  0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
  0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
  0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
  0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
  0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
  0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
  0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

void kit_sha512_iterate_c(uint64_t * ctx, const uint64_t * data)
{
  uint64_t w[80];

  w[0] = HTOBE64(data[0]);
  w[1] = HTOBE64(data[1]);
  w[2] = HTOBE64(data[2]);
  w[3] = HTOBE64(data[3]);
  w[4] = HTOBE64(data[4]);
  w[5] = HTOBE64(data[5]);
  w[6] = HTOBE64(data[6]);
  w[7] = HTOBE64(data[7]);
  w[8] = HTOBE64(data[8]);
  w[9] = HTOBE64(data[9]);
  w[10] = HTOBE64(data[10]);
  w[11] = HTOBE64(data[11]);
  w[12] = HTOBE64(data[12]);
  w[13] = HTOBE64(data[13]);
  w[14] = HTOBE64(data[14]);
  w[15] = HTOBE64(data[15]);

  uint64_t a = ctx[0], b = ctx[1], c = ctx[2], d = ctx[3];
  uint64_t e = ctx[4], f = ctx[5], g = ctx[6], h = ctx[7];
  uint64_t tmp1, tmp2;

  SHA512_STEP(a, b, c, d, e, f, g, h, 0);
  SHA512_STEP(h, a, b, c, d, e, f, g, 1);
  SHA512_STEP(g, h, a, b, c, d, e, f, 2);
  SHA512_STEP(f, g, h, a, b, c, d, e, 3);
  SHA512_STEP(e, f, g, h, a, b, c, d, 4);
  SHA512_STEP(d, e, f, g, h, a, b, c, 5);
  SHA512_STEP(c, d, e, f, g, h, a, b, 6);
  SHA512_STEP(b, c, d, e, f, g, h, a, 7);
  SHA512_STEP(a, b, c, d, e, f, g, h, 8);
  SHA512_STEP(h, a, b, c, d, e, f, g, 9);
  SHA512_STEP(g, h, a, b, c, d, e, f, 10);
  SHA512_STEP(f, g, h, a, b, c, d, e, 11);
  SHA512_STEP(e, f, g, h, a, b, c, d, 12);
  SHA512_STEP(d, e, f, g, h, a, b, c, 13);
  SHA512_STEP(c, d, e, f, g, h, a, b, 14);
  SHA512_STEP(b, c, d, e, f, g, h, a, 15);

  SHA512_INIT_EXP(16);
  SHA512_STEP(a, b, c, d, e, f, g, h, 16);

  SHA512_INIT_EXP(17);
  SHA512_STEP(h, a, b, c, d, e, f, g, 17);

  SHA512_INIT_EXP(18);
  SHA512_STEP(g, h, a, b, c, d, e, f, 18);

  SHA512_INIT_EXP(19);
  SHA512_STEP(f, g, h, a, b, c, d, e, 19);

  SHA512_INIT_EXP(20);
  SHA512_STEP(e, f, g, h, a, b, c, d, 20);

  SHA512_INIT_EXP(21);
  SHA512_STEP(d, e, f, g, h, a, b, c, 21);

  SHA512_INIT_EXP(22);
  SHA512_STEP(c, d, e, f, g, h, a, b, 22);

  SHA512_INIT_EXP(23);
  SHA512_STEP(b, c, d, e, f, g, h, a, 23);

  SHA512_INIT_EXP(24);
  SHA512_STEP(a, b, c, d, e, f, g, h, 24);

  SHA512_INIT_EXP(25);
  SHA512_STEP(h, a, b, c, d, e, f, g, 25);

  SHA512_INIT_EXP(26);
  SHA512_STEP(g, h, a, b, c, d, e, f, 26);

  SHA512_INIT_EXP(27);
  SHA512_STEP(f, g, h, a, b, c, d, e, 27);

  SHA512_INIT_EXP(28);
  SHA512_STEP(e, f, g, h, a, b, c, d, 28);

  SHA512_INIT_EXP(29);
  SHA512_STEP(d, e, f, g, h, a, b, c, 29);

  SHA512_INIT_EXP(30);
  SHA512_STEP(c, d, e, f, g, h, a, b, 30);

  SHA512_INIT_EXP(31);
  SHA512_STEP(b, c, d, e, f, g, h, a, 31);

  SHA512_INIT_EXP(32);
  SHA512_STEP(a, b, c, d, e, f, g, h, 32);

  SHA512_INIT_EXP(33);
  SHA512_STEP(h, a, b, c, d, e, f, g, 33);

  SHA512_INIT_EXP(34);
  SHA512_STEP(g, h, a, b, c, d, e, f, 34);

  SHA512_INIT_EXP(35);
  SHA512_STEP(f, g, h, a, b, c, d, e, 35);

  SHA512_INIT_EXP(36);
  SHA512_STEP(e, f, g, h, a, b, c, d, 36);

  SHA512_INIT_EXP(37);
  SHA512_STEP(d, e, f, g, h, a, b, c, 37);

  SHA512_INIT_EXP(38);
  SHA512_STEP(c, d, e, f, g, h, a, b, 38);

  SHA512_INIT_EXP(39);
  SHA512_STEP(b, c, d, e, f, g, h, a, 39);

  SHA512_INIT_EXP(40);
  SHA512_STEP(a, b, c, d, e, f, g, h, 40);

  SHA512_INIT_EXP(41);
  SHA512_STEP(h, a, b, c, d, e, f, g, 41);

  SHA512_INIT_EXP(42);
  SHA512_STEP(g, h, a, b, c, d, e, f, 42);

  SHA512_INIT_EXP(43);
  SHA512_STEP(f, g, h, a, b, c, d, e, 43);

  SHA512_INIT_EXP(44);
  SHA512_STEP(e, f, g, h, a, b, c, d, 44);

  SHA512_INIT_EXP(45);
  SHA512_STEP(d, e, f, g, h, a, b, c, 45);

  SHA512_INIT_EXP(46);
  SHA512_STEP(c, d, e, f, g, h, a, b, 46);

  SHA512_INIT_EXP(47);
  SHA512_STEP(b, c, d, e, f, g, h, a, 47);

  SHA512_INIT_EXP(48);
  SHA512_STEP(a, b, c, d, e, f, g, h, 48);

  SHA512_INIT_EXP(49);
  SHA512_STEP(h, a, b, c, d, e, f, g, 49);

  SHA512_INIT_EXP(50);
  SHA512_STEP(g, h, a, b, c, d, e, f, 50);

  SHA512_INIT_EXP(51);
  SHA512_STEP(f, g, h, a, b, c, d, e, 51);

  SHA512_INIT_EXP(52);
  SHA512_STEP(e, f, g, h, a, b, c, d, 52);

  SHA512_INIT_EXP(53);
  SHA512_STEP(d, e, f, g, h, a, b, c, 53);

  SHA512_INIT_EXP(54);
  SHA512_STEP(c, d, e, f, g, h, a, b, 54);

  SHA512_INIT_EXP(55);
  SHA512_STEP(b, c, d, e, f, g, h, a, 55);

  SHA512_INIT_EXP(56);
  SHA512_STEP(a, b, c, d, e, f, g, h, 56);

  SHA512_INIT_EXP(57);
  SHA512_STEP(h, a, b, c, d, e, f, g, 57);

  SHA512_INIT_EXP(58);
  SHA512_STEP(g, h, a, b, c, d, e, f, 58);

  SHA512_INIT_EXP(59);
  SHA512_STEP(f, g, h, a, b, c, d, e, 59);

  SHA512_INIT_EXP(60);
  SHA512_STEP(e, f, g, h, a, b, c, d, 60);

  SHA512_INIT_EXP(61);
  SHA512_STEP(d, e, f, g, h, a, b, c, 61);

  SHA512_INIT_EXP(62);
  SHA512_STEP(c, d, e, f, g, h, a, b, 62);

  SHA512_INIT_EXP(63);
  SHA512_STEP(b, c, d, e, f, g, h, a, 63);

  SHA512_INIT_EXP(64);
  SHA512_STEP(a, b, c, d, e, f, g, h, 64);

  SHA512_INIT_EXP(65);
  SHA512_STEP(h, a, b, c, d, e, f, g, 65);

  SHA512_INIT_EXP(66);
  SHA512_STEP(g, h, a, b, c, d, e, f, 66);

  SHA512_INIT_EXP(67);
  SHA512_STEP(f, g, h, a, b, c, d, e, 67);

  SHA512_INIT_EXP(68);
  SHA512_STEP(e, f, g, h, a, b, c, d, 68);

  SHA512_INIT_EXP(69);
  SHA512_STEP(d, e, f, g, h, a, b, c, 69);

  SHA512_INIT_EXP(70);
  SHA512_STEP(c, d, e, f, g, h, a, b, 70);

  SHA512_INIT_EXP(71);
  SHA512_STEP(b, c, d, e, f, g, h, a, 71);

  SHA512_INIT_EXP(72);
  SHA512_STEP(a, b, c, d, e, f, g, h, 72);

  SHA512_INIT_EXP(73);
  SHA512_STEP(h, a, b, c, d, e, f, g, 73);

  SHA512_INIT_EXP(74);
  SHA512_STEP(g, h, a, b, c, d, e, f, 74);

  SHA512_INIT_EXP(75);
  SHA512_STEP(f, g, h, a, b, c, d, e, 75);

  SHA512_INIT_EXP(76);
  SHA512_STEP(e, f, g, h, a, b, c, d, 76);

  SHA512_INIT_EXP(77);
  SHA512_STEP(d, e, f, g, h, a, b, c, 77);

  SHA512_INIT_EXP(78);
  SHA512_STEP(c, d, e, f, g, h, a, b, 78);

  SHA512_INIT_EXP(79);
  SHA512_STEP(b, c, d, e, f, g, h, a, 79);

  ctx[0] += a;
  ctx[1] += b;
  ctx[2] += c;
  ctx[3] += d;
  ctx[4] += e;
  ctx[5] += f;
  ctx[6] += g;
  ctx[7] += h;
}
