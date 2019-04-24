#!/usr/bin/python3

from operator import itemgetter

# ------------------------------- Begin of the phe Library ------------------------------- #

import fractions
import math
import sys


import os
import random
from base64 import urlsafe_b64encode, urlsafe_b64decode
from binascii import hexlify, unhexlify

try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False

try:
    from Crypto.Util import number
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

# GMP's powmod has greater overhead than Python's pow, but is faster.
# From a quick experiment on our machine, this seems to be the break even:
_USE_MOD_FROM_GMP_SIZE = (1 << (8*2))


def powmod(a, b, c):
    if a == 1:
        return 1
    if not HAVE_GMP or max(a, b, c) < _USE_MOD_FROM_GMP_SIZE:
        return pow(a, b, c)
    else:
        return int(gmpy2.powmod(a, b, c))


def extended_euclidean_algorithm(a, b):
    r0, r1 = a, b
    s0, s1 = 1, 0
    t0, t1 = 0, 1
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q*r1
        s0, s1 = s1, s0 - q*s1
        t0, t1 = t1, t0 - q*t1
    return r0, s0, t0


def invert(a, b):
    if HAVE_GMP:
        s = int(gmpy2.invert(a, b))
        # according to documentation, gmpy2.invert might return 0 on
        # non-invertible element, although it seems to actually raise an
        # exception; for consistency, we always raise the exception
        if s == 0:
            raise ZeroDivisionError('invert() no inverse exists')
        return s
    else:
        r, s, _ = extended_euclidean_algorithm(a, b)
        if r != 1:
            raise ZeroDivisionError('invert() no inverse exists')
        return s % b


def getprimeover(N):
    if HAVE_GMP:
        randfunc = random.SystemRandom()
        r = gmpy2.mpz(randfunc.getrandbits(N))
        r = gmpy2.bit_set(r, N - 1)
        return int(gmpy2.next_prime(r))
    elif HAVE_CRYPTO:
        return number.getPrime(N, os.urandom)
    else:
        randfunc = random.SystemRandom()
        n = randfunc.randrange(2**(N-1), 2**N) | 1
        while not is_prime(n):
            n += 2
        return n


def isqrt(N):
    if HAVE_GMP:
        return int(gmpy2.isqrt(N))
    else:
        return improved_i_sqrt(N)


def improved_i_sqrt(n):
    assert n >= 0
    if n == 0:
        return 0
    i = n.bit_length() >> 1    # i = floor( (1 + floor(log_2(n))) / 2 )
    m = 1 << i    # m = 2^i
    #
    # Fact: (2^(i + 1))^2 > n, so m has at least as many bits
    # as the floor of the square root of n.
    #
    # Proof: (2^(i+1))^2 = 2^(2i + 2) >= 2^(floor(log_2(n)) + 2)
    # >= 2^(ceil(log_2(n) + 1) >= 2^(log_2(n) + 1) > 2^(log_2(n)) = n. QED.
    #
    while (m << i) > n: # (m<<i) = m*(2^i) = m*m
        m >>= 1
        i -= 1
    d = n - (m << i) # d = n-m^2
    for k in range(i-1, -1, -1):
        j = 1 << k
        new_diff = d - (((m<<1) | j) << k) # n-(m+2^k)^2 = n-m^2-2*m*2^k-2^(2k)
        if new_diff >= 0:
            d = new_diff
            m |= j
    return m

# base64 utils from jwcrypto

def base64url_encode(payload):
    if not isinstance(payload, bytes):
        payload = payload.encode('utf-8')
    encode = urlsafe_b64encode(payload)
    return encode.decode('utf-8').rstrip('=')


def base64url_decode(payload):
    l = len(payload) % 4
    if l == 2:
        payload += '=='
    elif l == 3:
        payload += '='
    elif l != 0:
        raise ValueError('Invalid base64 string')
    return urlsafe_b64decode(payload.encode('utf-8'))


def base64_to_int(source):
    return int(hexlify(base64url_decode(source)), 16)


def int_to_base64(source):
    assert source != 0
    I = hex(source).rstrip("L").lstrip("0x")
    return base64url_encode(unhexlify((len(I) % 2) * '0' + I))


# prime testing

first_primes = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
    157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
    239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
    331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
    509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
    613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
    709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
    821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
    919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013,
    1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091,
    1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181,
    1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277,
    1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361,
    1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451,
    1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531,
    1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609,
    1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699,
    1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789,
    1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889,
    1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997,
    1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083,
    2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161,
    2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273,
    2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357,
    2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441,
    2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551,
    2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663,
    2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729,
    2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819,
    2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917,
    2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011, 3019, 3023,
    3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137,
    3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251,
    3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
    3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449,
    3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533,
    3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617,
    3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697, 3701, 3709,
    3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797, 3803, 3821,
    3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917,
    3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013,
    4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093, 4099, 4111,
    4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201, 4211, 4217, 4219,
    4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297,
    4327, 4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423,
    4441, 4447, 4451, 4457, 4463, 4481, 4483, 4493, 4507, 4513, 4517, 4519,
    4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603, 4621, 4637, 4639,
    4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729,
    4733, 4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831,
    4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937, 4943, 4951,
    4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011, 5021, 5023,
    5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147,
    5153, 5167, 5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261,
    5273, 5279, 5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387,
    5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443, 5449, 5471,
    5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563,
    5569, 5573, 5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659,
    5669, 5683, 5689, 5693, 5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779,
    5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857,
    5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981,
    5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089,
    6091, 6101, 6113, 6121, 6131, 6133, 6143, 6151, 6163, 6173, 6197, 6199,
    6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287,
    6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367,
    6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491,
    6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571, 6577, 6581, 6599, 6607,
    6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701, 6703, 6709,
    6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827,
    6829, 6833, 6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917,
    6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997, 7001, 7013,
    7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121, 7127, 7129,
    7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243,
    7247, 7253, 7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369,
    7393, 7411, 7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499,
    7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561, 7573, 7577,
    7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681,
    7687, 7691, 7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789,
    7793, 7817, 7823, 7829, 7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901,
    7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017,
    8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123,
    8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219, 8221, 8231, 8233, 8237,
    8243, 8263, 8269, 8273, 8287, 8291, 8293, 8297, 8311, 8317, 8329, 8353,
    8363, 8369, 8377, 8387, 8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461,
    8467, 8501, 8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597,
    8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677, 8681, 8689,
    8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741, 8747, 8753, 8761, 8779,
    8783, 8803, 8807, 8819, 8821, 8831, 8837, 8839, 8849, 8861, 8863, 8867,
    8887, 8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001,
    9007, 9011, 9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109,
    9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199, 9203, 9209,
    9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283, 9293, 9311, 9319, 9323,
    9337, 9341, 9343, 9349, 9371, 9377, 9391, 9397, 9403, 9413, 9419, 9421,
    9431, 9433, 9437, 9439, 9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511,
    9521, 9533, 9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631,
    9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733, 9739, 9743,
    9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811, 9817, 9829, 9833, 9839,
    9851, 9857, 9859, 9871, 9883, 9887, 9901, 9907, 9923, 9929, 9931, 9941,
    9949, 9967, 9973, 10007, 10009, 10037, 10039, 10061, 10067, 10069, 10079,
    10091, 10093, 10099, 10103, 10111, 10133, 10139, 10141, 10151, 10159,
    10163, 10169, 10177, 10181, 10193, 10211, 10223, 10243, 10247, 10253,
    10259, 10267, 10271, 10273, 10289, 10301, 10303, 10313, 10321, 10331,
    10333, 10337, 10343, 10357, 10369, 10391, 10399, 10427, 10429, 10433,
    10453, 10457, 10459, 10463, 10477, 10487, 10499, 10501, 10513, 10529,
    10531, 10559, 10567, 10589, 10597, 10601, 10607, 10613, 10627, 10631,
    10639, 10651, 10657, 10663, 10667, 10687, 10691, 10709, 10711, 10723,
    10729, 10733, 10739, 10753, 10771, 10781, 10789, 10799, 10831, 10837,
    10847, 10853, 10859, 10861, 10867, 10883, 10889, 10891, 10903, 10909,
    10937, 10939, 10949, 10957, 10973, 10979, 10987, 10993, 11003, 11027,
    11047, 11057, 11059, 11069, 11071, 11083, 11087, 11093, 11113, 11117,
    11119, 11131, 11149, 11159, 11161, 11171, 11173, 11177, 11197, 11213,
    11239, 11243, 11251, 11257, 11261, 11273, 11279, 11287, 11299, 11311,
    11317, 11321, 11329, 11351, 11353, 11369, 11383, 11393, 11399, 11411,
    11423, 11437, 11443, 11447, 11467, 11471, 11483, 11489, 11491, 11497,
    11503, 11519, 11527, 11549, 11551, 11579, 11587, 11593, 11597, 11617,
    11621, 11633, 11657, 11677, 11681, 11689, 11699, 11701, 11717, 11719,
    11731, 11743, 11777, 11779, 11783, 11789, 11801, 11807, 11813, 11821,
    11827, 11831, 11833, 11839, 11863, 11867, 11887, 11897, 11903, 11909,
    11923, 11927, 11933, 11939, 11941, 11953, 11959, 11969, 11971, 11981,
    11987, 12007, 12011, 12037, 12041, 12043, 12049, 12071, 12073, 12097,
    12101, 12107, 12109, 12113, 12119, 12143, 12149, 12157, 12161, 12163,
    12197, 12203, 12211, 12227, 12239, 12241, 12251, 12253, 12263, 12269,
    12277, 12281, 12289, 12301, 12323, 12329, 12343, 12347, 12373, 12377,
    12379, 12391, 12401, 12409, 12413, 12421, 12433, 12437, 12451, 12457,
    12473, 12479, 12487, 12491, 12497, 12503, 12511, 12517, 12527, 12539,
    12541, 12547, 12553, 12569, 12577, 12583, 12589, 12601, 12611, 12613,
    12619, 12637, 12641, 12647, 12653, 12659, 12671, 12689, 12697, 12703,
    12713, 12721, 12739, 12743, 12757, 12763, 12781, 12791, 12799, 12809,
    12821, 12823, 12829, 12841, 12853, 12889, 12893, 12899, 12907, 12911,
    12917, 12919, 12923, 12941, 12953, 12959, 12967, 12973, 12979, 12983,
    13001, 13003, 13007, 13009, 13033, 13037, 13043, 13049, 13063, 13093,
    13099, 13103, 13109, 13121, 13127, 13147, 13151, 13159, 13163, 13171,
    13177, 13183, 13187, 13217, 13219, 13229, 13241, 13249, 13259, 13267,
    13291, 13297, 13309, 13313, 13327, 13331, 13337, 13339, 13367, 13381,
    13397, 13399, 13411, 13417, 13421, 13441, 13451, 13457, 13463, 13469,
    13477, 13487, 13499, 13513, 13523, 13537, 13553, 13567, 13577, 13591,
    13597, 13613, 13619, 13627, 13633, 13649, 13669, 13679, 13681, 13687,
    13691, 13693, 13697, 13709, 13711, 13721, 13723, 13729, 13751, 13757,
    13759, 13763, 13781, 13789, 13799, 13807, 13829, 13831, 13841, 13859,
    13873, 13877, 13879, 13883, 13901, 13903, 13907, 13913, 13921, 13931,
    13933, 13963, 13967, 13997, 13999, 14009, 14011, 14029, 14033, 14051,
    14057, 14071, 14081, 14083, 14087, 14107, 14143, 14149, 14153, 14159,
    14173, 14177, 14197, 14207, 14221, 14243, 14249, 14251, 14281, 14293,
    14303, 14321, 14323, 14327, 14341, 14347, 14369, 14387, 14389, 14401,
    14407, 14411, 14419, 14423, 14431, 14437, 14447, 14449, 14461, 14479,
    14489, 14503, 14519, 14533, 14537, 14543, 14549, 14551, 14557, 14561,
    14563, 14591, 14593, 14621, 14627, 14629, 14633, 14639, 14653, 14657,
    14669, 14683, 14699, 14713, 14717, 14723, 14731, 14737, 14741, 14747,
    14753, 14759, 14767, 14771, 14779, 14783, 14797, 14813, 14821, 14827,
    14831, 14843, 14851, 14867, 14869, 14879, 14887, 14891, 14897, 14923,
    14929, 14939, 14947, 14951, 14957, 14969, 14983, 15013, 15017, 15031,
    15053, 15061, 15073, 15077, 15083, 15091, 15101, 15107, 15121, 15131,
    15137, 15139, 15149, 15161, 15173, 15187, 15193, 15199, 15217, 15227,
    15233, 15241, 15259, 15263, 15269, 15271, 15277, 15287, 15289, 15299,
    15307, 15313, 15319, 15329, 15331, 15349, 15359, 15361, 15373, 15377,
    15383, 15391, 15401, 15413, 15427, 15439, 15443, 15451, 15461, 15467,
    15473, 15493, 15497, 15511, 15527, 15541, 15551, 15559, 15569, 15581,
    15583, 15601, 15607, 15619, 15629, 15641, 15643, 15647, 15649, 15661,
    15667, 15671, 15679, 15683, 15727, 15731, 15733, 15737, 15739, 15749,
    15761, 15767, 15773, 15787, 15791, 15797, 15803, 15809, 15817, 15823,
    15859, 15877, 15881, 15887, 15889, 15901, 15907, 15913, 15919, 15923,
    15937, 15959, 15971, 15973, 15991, 16001, 16007, 16033, 16057, 16061,
    16063, 16067, 16069, 16073, 16087, 16091, 16097, 16103, 16111, 16127,
    16139, 16141, 16183, 16187, 16189, 16193, 16217, 16223, 16229, 16231,
    16249, 16253, 16267, 16273, 16301, 16319, 16333, 16339, 16349, 16361,
    16363, 16369, 16381, 16411, 16417, 16421, 16427, 16433, 16447, 16451,
    16453, 16477, 16481, 16487, 16493, 16519, 16529, 16547, 16553, 16561,
    16567, 16573, 16603, 16607, 16619, 16631, 16633, 16649, 16651, 16657,
    16661, 16673, 16691, 16693, 16699, 16703, 16729, 16741, 16747, 16759,
    16763, 16787, 16811, 16823, 16829, 16831, 16843, 16871, 16879, 16883,
    16889, 16901, 16903, 16921, 16927, 16931, 16937, 16943, 16963, 16979,
    16981, 16987, 16993, 17011, 17021, 17027, 17029, 17033, 17041, 17047,
    17053, 17077, 17093, 17099, 17107, 17117, 17123, 17137, 17159, 17167,
    17183, 17189, 17191, 17203, 17207, 17209, 17231, 17239, 17257, 17291,
    17293, 17299, 17317, 17321, 17327, 17333, 17341, 17351, 17359, 17377,
    17383, 17387, 17389, 17393, 17401, 17417, 17419, 17431, 17443, 17449,
    17467, 17471, 17477, 17483, 17489, 17491, 17497, 17509, 17519, 17539,
    17551, 17569, 17573, 17579, 17581, 17597, 17599, 17609, 17623, 17627,
    17657, 17659, 17669, 17681, 17683, 17707, 17713, 17729, 17737, 17747,
    17749, 17761, 17783, 17789, 17791, 17807, 17827, 17837, 17839, 17851,
    17863,
]


def miller_rabin(n, k):
    assert n > 3
    d = n-1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    assert n-1 == d * 2**r
    assert d % 2 == 1
    for _ in range(k):  # each iteration divides risk of false prime by 4
        a = random.randint(2, n-2)  # choose a random witness
        x = pow(a, d, n)
        if x == 1 or x == n-1:
            continue  # go to next witness

        for _ in range(1, r):
            x = x*x % n
            if x == n-1:
                break   # go to next witness
        else:
            return False
    return True


def is_prime(n, mr_rounds=25):
    if n <= first_primes[-1]:
        return n in first_primes
    # for small dividors (relatively frequent), euclidean division is best
    for p in first_primes:
        if n % p == 0:
            return False
    return miller_rabin(n, mr_rounds)


try:
    from collections.abc import Mapping
except ImportError:
    Mapping = dict

DEFAULT_KEYSIZE = 3072

def generate_paillier_keypair(private_keyring=None, n_length=DEFAULT_KEYSIZE):

    p = q = n = None
    n_len = 0
    while n_len != n_length:
        p = getprimeover(n_length // 2)
        q = p
        while q == p:
            q = getprimeover(n_length // 2)
        n = p * q
        n_len = n.bit_length()

    public_key = PaillierPublicKey(n)
    private_key = PaillierPrivateKey(public_key, p, q)

    if private_keyring is not None:
        private_keyring.add(private_key)

    return public_key, private_key



class PaillierPrivateKeyring(Mapping):
    def __init__(self, private_keys=None):
        if private_keys is None:
            private_keys = []
        public_keys = [k.public_key for k in private_keys]
        self.__keyring = dict(zip(public_keys, private_keys))
    def __getitem__(self, key):
        return self.__keyring[key]

    def __len__(self):
        return len(self.__keyring)

    def __iter__(self):
        return iter(self.__keyring)

    def __delitem__(self, public_key):
        del self.__keyring[public_key]

    def add(self, private_key):

        if not isinstance(private_key, PaillierPrivateKey):
            raise TypeError("private_key should be of type PaillierPrivateKey, "
                            "not %s" % type(private_key))
        self.__keyring[private_key.public_key] = private_key

    def decrypt(self, encrypted_number):

        relevant_private_key = self.__keyring[encrypted_number.public_key]
        return relevant_private_key.decrypt(encrypted_number)


class EncodedNumber(object):

    BASE = 16

    LOG2_BASE = math.log(BASE, 2)
    FLOAT_MANTISSA_BITS = sys.float_info.mant_dig

    def __init__(self, public_key, encoding, exponent):
        self.public_key = public_key
        self.encoding = encoding
        self.exponent = exponent

    @classmethod
    def encode(cls, public_key, scalar, precision=None, max_exponent=None):

        # Calculate the maximum exponent for desired precision
        if precision is None:
            if isinstance(scalar, int):
                prec_exponent = 0
            elif isinstance(scalar, float):
                # Encode with *at least* as much precision as the python float
                # What's the base-2 exponent on the float?
                bin_flt_exponent = math.frexp(scalar)[1]

                # What's the base-2 exponent of the least significant bit?
                # The least significant bit has value 2 ** bin_lsb_exponent
                bin_lsb_exponent = bin_flt_exponent - cls.FLOAT_MANTISSA_BITS

                # What's the corresponding base BASE exponent? Round that down.
                prec_exponent = math.floor(bin_lsb_exponent / cls.LOG2_BASE)
            else:
                raise TypeError("Don't know the precision of type %s."
                                % type(scalar))
        else:
            prec_exponent = math.floor(math.log(precision, cls.BASE))

        # Remember exponents are negative for numbers < 1.
        # If we're going to store numbers with a more negative
        # exponent than demanded by the precision, then we may
        # as well bump up the actual precision.
        if max_exponent is None:
            exponent = prec_exponent
        else:
            exponent = min(max_exponent, prec_exponent)

        # Use rationals instead of floats to avoid overflow.
        int_rep = round(fractions.Fraction(scalar)
                        * fractions.Fraction(cls.BASE) ** -exponent)

        if abs(int_rep) > public_key.max_int:
            raise ValueError('Integer needs to be within +/- %d but got %d'
                             % (public_key.max_int, int_rep))

        # Wrap negative numbers by adding n
        return cls(public_key, int_rep % public_key.n, exponent)
    #
    def decode(self):

        if self.encoding >= self.public_key.n:
            # Should be mod n
            raise ValueError('Attempted to decode corrupted number')
        elif self.encoding <= self.public_key.max_int:
            # Positive
            mantissa = self.encoding
        elif self.encoding >= self.public_key.n - self.public_key.max_int:
            # Negative
            mantissa = self.encoding - self.public_key.n
        else:
            raise OverflowError('Overflow detected in decrypted number')

        if self.exponent >= 0:
            # Integer multiplication. This is exact.
            return mantissa * self.BASE ** self.exponent
        else:
            # BASE ** -e is an integer, so below is a division of ints.
            # Not coercing mantissa to float prevents some overflows.
            try:
                return mantissa / self.BASE ** -self.exponent
            except OverflowError as e:
                raise OverflowError('decoded result too large for a float') from e
                # return 0

    def decrease_exponent_to(self, new_exp):

        if new_exp > self.exponent:
            raise ValueError('New exponent %i should be more negative than'
                             'old exponent %i' % (new_exp, self.exponent))
        factor = pow(self.BASE, self.exponent - new_exp)
        new_enc = self.encoding * factor % self.public_key.n
        return self.__class__(self.public_key, new_enc, new_exp)


class PaillierPublicKey(object):

    def __init__(self, n):
        self.g = n + 1
        self.n = n
        self.nsquare = n * n
        self.max_int = n // 3 - 1

    def __repr__(self):
        publicKeyHash = hex(hash(self))[2:]
        return "<PaillierPublicKey {}>".format(publicKeyHash[:10])

    def __eq__(self, other):
        return self.n == other.n

    def __hash__(self):
        return hash(self.n)

    def raw_encrypt(self, plaintext, r_value=None):

        if not isinstance(plaintext, int):
            raise TypeError('Expected int type plaintext but got: %s' %
                            type(plaintext))

        if self.n - self.max_int <= plaintext < self.n:
            # Very large plaintext, take a sneaky shortcut using inverses
            neg_plaintext = self.n - plaintext  # = abs(plaintext - nsquare)
            neg_ciphertext = (self.n * neg_plaintext + 1) % self.nsquare
            nude_ciphertext = invert(neg_ciphertext, self.nsquare)
        else:
            # we chose g = n + 1, so that we can exploit the fact that
            # (n+1)^plaintext = n*plaintext + 1 mod n^2
            nude_ciphertext = (self.n * plaintext + 1) % self.nsquare

        r = r_value or self.get_random_lt_n()
        obfuscator = powmod(r, self.n, self.nsquare)

        return (nude_ciphertext * obfuscator) % self.nsquare

    def get_random_lt_n(self):

        return random.SystemRandom().randrange(1, self.n)

    def encrypt(self, value, precision=None, r_value=None):


        if isinstance(value, EncodedNumber):
            encoding = value
        else:
            encoding = EncodedNumber.encode(self, value, precision)

        return self.encrypt_encoded(encoding, r_value)

    def encrypt_encoded(self, encoding, r_value):

        # If r_value is None, obfuscate in a call to .obfuscate() (below)
        obfuscator = r_value or 1
        ciphertext = self.raw_encrypt(encoding.encoding, r_value=obfuscator)
        # print("ciphertext: ")
        # print(ciphertext)
        # print("encoding.exponent:")
        # print(encoding.exponent)
        encrypted_number = EncryptedNumber(self, ciphertext, encoding.exponent)
        # print(ciphertext)
        if r_value is None:
            encrypted_number.obfuscate()
        return encrypted_number


class EncryptedNumber(object):

    def __init__(self, public_key, ciphertext, exponent=0):
        self.public_key = public_key
        self.__ciphertext = ciphertext
        self.exponent = exponent
        self.__is_obfuscated = False
        if isinstance(self.ciphertext, EncryptedNumber):
            raise TypeError('ciphertext should be an integer')
        if not isinstance(self.public_key, PaillierPublicKey):
            raise TypeError('public_key should be a PaillierPublicKey')

    def get_ciphertext(self):
        return self.__ciphertext

    def __add__(self, other):

        if isinstance(other, EncryptedNumber):
            return self._add_encrypted(other)
        elif isinstance(other, EncodedNumber):
            return self._add_encoded(other)
        else:
            return self._add_scalar(other)

    def __radd__(self, other):

        return self.__add__(other)

    def __mul__(self, other):

        if isinstance(other, EncryptedNumber):
            raise NotImplementedError('Good luck with that...')

        if isinstance(other, EncodedNumber):
            encoding = other
        else:
            encoding = EncodedNumber.encode(self.public_key, other)
        product = self._raw_mul(encoding.encoding)
        exponent = self.exponent + encoding.exponent

        return EncryptedNumber(self.public_key, product, exponent)

    def __rmul__(self, other):
        return self.__mul__(other)

    def __sub__(self, other):
        return self + (other * -1)

    def __rsub__(self, other):
        return other + (self * -1)

    def __truediv__(self, scalar):
        return self.__mul__(1 / scalar)

    def ciphertext(self, be_secure=True):

        if be_secure and not self.__is_obfuscated:
            self.obfuscate()

        return self.__ciphertext

    def decrease_exponent_to(self, new_exp):

        if new_exp > self.exponent:
            raise ValueError('New exponent %i should be more negative than '
                             'old exponent %i' % (new_exp, self.exponent))
        multiplied = self * pow(EncodedNumber.BASE, self.exponent - new_exp)
        multiplied.exponent = new_exp
        return multiplied

    def obfuscate(self):

        r = self.public_key.get_random_lt_n()
        r_pow_n = powmod(r, self.public_key.n, self.public_key.nsquare)
        self.__ciphertext = self.__ciphertext * r_pow_n % self.public_key.nsquare
        self.__is_obfuscated = True

    def _add_scalar(self, scalar):

        encoded = EncodedNumber.encode(self.public_key, scalar,
                                       max_exponent=self.exponent)

        return self._add_encoded(encoded)

    def _add_encoded(self, encoded):

        if self.public_key != encoded.public_key:
            raise ValueError("Attempted to add numbers encoded against "
                             "different public keys!")

        # In order to add two numbers, their exponents must match.
        a, b = self, encoded
        if a.exponent > b.exponent:
            a = self.decrease_exponent_to(b.exponent)
        elif a.exponent < b.exponent:
            b = b.decrease_exponent_to(a.exponent)

        # Don't bother to salt/obfuscate in a basic operation, do it
        # just before leaving the computer.
        encrypted_scalar = a.public_key.raw_encrypt(b.encoding, 1)

        sum_ciphertext = a._raw_add(a.ciphertext(False), encrypted_scalar)
        return EncryptedNumber(a.public_key, sum_ciphertext, a.exponent)

    def _add_encrypted(self, other):

        if self.public_key != other.public_key:
            raise ValueError("Attempted to add numbers encrypted against "
                             "different public keys!")

        # In order to add two numbers, their exponents must match.
        a, b = self, other
        if a.exponent > b.exponent:
            a = self.decrease_exponent_to(b.exponent)
        elif a.exponent < b.exponent:
            b = b.decrease_exponent_to(a.exponent)

        sum_ciphertext = a._raw_add(a.ciphertext(False), b.ciphertext(False))
        return EncryptedNumber(a.public_key, sum_ciphertext, a.exponent)

    def _raw_add(self, e_a, e_b):

        return e_a * e_b % self.public_key.nsquare

    def _raw_mul(self, plaintext):

        if not isinstance(plaintext, int):
            raise TypeError('Expected ciphertext to be int, not %s' %
                type(plaintext))

        if plaintext < 0 or plaintext >= self.public_key.n:
            raise ValueError('Scalar out of bounds: %i' % plaintext)

        if self.public_key.n - self.public_key.max_int <= plaintext:
            # Very large plaintext, play a sneaky trick using inverses
            neg_c = invert(self.ciphertext(False), self.public_key.nsquare)
            neg_scalar = self.public_key.n - plaintext
            return powmod(neg_c, neg_scalar, self.public_key.nsquare)
        else:
            return powmod(self.ciphertext(False), plaintext, self.public_key.nsquare)


class PaillierPrivateKey(object):

    def __init__(self, public_key, p, q):
        if not p*q == public_key.n:
            raise ValueError('given public key does not match the given p and q.')
        if p == q:
            # check that p and q are different, otherwise we can't compute p^-1 mod q
            raise ValueError('p and q have to be different')
        self.public_key = public_key
        if q < p: #ensure that p < q.
            self.p = q
            self.q = p
        else:
            self.p = p
            self.q = q
        self.psquare = self.p * self.p

        self.qsquare = self.q * self.q
        self.p_inverse = invert(self.p, self.q)
        self.hp = self.h_function(self.p, self.psquare)
        self.hq = self.h_function(self.q, self.qsquare)

    @staticmethod
    def from_totient(public_key, totient):

        p_plus_q = public_key.n - totient + 1
        p_minus_q = isqrt(p_plus_q * p_plus_q - public_key.n * 4)
        q = (p_plus_q - p_minus_q) // 2
        p = p_plus_q - q
        if not p*q == public_key.n:
            raise ValueError('given public key and totient do not match.')
        return PaillierPrivateKey(public_key, p, q)

    def __repr__(self):
        pub_repr = repr(self.public_key)
        return "<PaillierPrivateKey for {}>".format(pub_repr)

    def decrypt(self, encrypted_number):

        encoded = self.decrypt_encoded(encrypted_number)
        return encoded.decode()

    def decrypt_encoded(self, encrypted_number, Encoding=None):

        if not isinstance(encrypted_number, EncryptedNumber):
            raise TypeError('Expected encrypted_number to be an EncryptedNumber'
                            ' not: %s' % type(encrypted_number))

        if self.public_key != encrypted_number.public_key:
            raise ValueError('encrypted_number was encrypted against a '
                             'different key!')

        if Encoding is None:
            Encoding = EncodedNumber

        encoded = self.raw_decrypt(encrypted_number.ciphertext(be_secure=False))
        return Encoding(self.public_key, encoded,
                             encrypted_number.exponent)

    def raw_decrypt(self, ciphertext):

        if not isinstance(ciphertext, int):
            raise TypeError('Expected ciphertext to be an int, not: %s' %
                type(ciphertext))

        decrypt_to_p = self.l_function(powmod(ciphertext, self.p-1, self.psquare), self.p) * self.hp % self.p
        decrypt_to_q = self.l_function(powmod(ciphertext, self.q-1, self.qsquare), self.q) * self.hq % self.q
        return self.crt(decrypt_to_p, decrypt_to_q)

    def h_function(self, x, xsquare):

        return invert(self.l_function(powmod(self.public_key.g, x - 1, xsquare),x), x)

    def l_function(self, x, p):

        return (x - 1) // p

    def crt(self, mp, mq):

        u = (mq - mp) * self.p_inverse % self.q
        return mp + (u * self.p)

    def __eq__(self, other):
        return self.p == other.p and self.q == other.q

    def __hash__(self):
        return hash((self.p, self.q))


# ------------------------------- End of the phe Library ------------------------------- #
    
n = 4459262300547858904658930414020825434987219645034206439443309803892354203401695292452650710089733576285085079516053137623734239796365092847130309448167252790605675345863865748471810427958631308784281532621422186125191933571399598154685591274370659718970896072116865398065589138659731186658973843782196515455322379921320592828587864328464547386279346810498157626667827913205594046034383834939455698273513557709386123596698993743863842679298718644481233825575395163958007706588797559411305883553975318221459211423461420529152990913433112849572384386804123734761363552718959437055418832197055385414943422505484239999089162219562068522109177849100249708358542458923150856429379796299256974841048572160226373252945955131632712424627098378112174714867575395358724941466765870764414110422553375792454964713950936872164015189333071767245946141940687491603580695369476126822861715535480066593358047938092090755328499707527005214935663

public_key = PaillierPublicKey(n)
aggregation = 0

for line in sys.stdin:
    lineNumber = int(line.strip())
    lineClass = EncryptedNumber(public_key, lineNumber)
    aggregation += lineClass


#----------------data receiver----------------#
p = 2035371799199481933591012944125913537544717038199894135285584303032087934092423767158010434690226923924714014047467862645305314468873957260749852237221792179720372232027896648442209422120679409207055326926507314755403716103439909241935841525642892718085985786636970867011378396675800591346793298313965152930077200879449416449263530512493234654100208923733575494460700571944886333118624114776207617005278495000571104744401657977430632580459621725493810701384810641

q = 2190883406315102062831877231503263335219456522549015395315378295711972865475612430029022054841572044292181228008248544271364933039519449383891542675962892047611242265275523884201084878531939977346718100224688427714408095322674707450064503237102721124786192712922509622950729774079863672943482539138549656900909786154475902425538624479516579105128818794805293381337328637435196360605425396227593162234764283964869760442808843709989186358431493687328263216916454143

private_key = PaillierPrivateKey(public_key, p, q)
print('%s' % str(private_key.decrypt(aggregation)))

