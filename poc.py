#!/usr/bin/env python3
"""PoC: recover Polar-KEM shared secrets from the public key and ciphertext alone.

Runs all 30 records from the official KAT files copied unmodified next to this
script (KAT_KEM_PolarKEM-{128,256,512}.txt, 10 records each). Only the PK and
CT fields feed the recovery routine; the Seed and SK fields present in the same
files are never used, and the expected SS is used solely by the final
comparator. No submitted C code is executed.

Algorithm constants below are transcribed from the official submission package
(Polar-KEM.zip, SHA-256
3ae9d4f1a717fb473e76447014d585cd5d14fe38728f02b1a044cc6a2d03e16d):
polarkem_params.h values and the polarkem_info_positions tables.

Requires Python with SM3 in hashlib (3.11+ on OpenSSL 3.x).
Usage: python3 poc.py && echo OK
"""

import hashlib
import re
import sys
from pathlib import Path

PERM_DOMAIN = b"PolarKEM-PERM-v1"
SIGN_DOMAIN = b"PolarKEM-SIGN-v1"
SS_DOMAIN = b"PolarKEM-SS-v1"

PARAMS = {
    128: dict(
        N=512,
        Q=12289,
        MESSAGE_BYTES=16,
        QUANT_BITS=11,
        SS_BYTES=16,
        positions=[
        191, 223, 237, 238, 239, 243, 245, 246, 247, 249, 250, 251, 252, 253, 254, 255,
        317, 318, 319, 343, 347, 349, 350, 351, 359, 363, 365, 366, 367, 371, 373, 374,
        375, 376, 377, 378, 379, 380, 381, 382, 383, 399, 407, 411, 413, 414, 415, 422,
        423, 425, 426, 427, 428, 429, 430, 431, 433, 434, 435, 436, 437, 438, 439, 440,
        441, 442, 443, 444, 445, 446, 447, 451, 453, 454, 455, 457, 458, 459, 460, 461,
        462, 463, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478,
        479, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495,
        496, 497, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 511,
        ],
    ),
    256: dict(
        N=1024,
        Q=12289,
        MESSAGE_BYTES=32,
        QUANT_BITS=9,
        SS_BYTES=32,
        positions=[
        255, 383, 439, 443, 445, 446, 447, 463, 471, 475, 477, 478, 479, 487, 491, 492,
        493, 494, 495, 498, 499, 500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510,
        511, 623, 631, 635, 637, 638, 639, 671, 687, 695, 698, 699, 700, 701, 702, 703,
        717, 718, 719, 723, 725, 726, 727, 729, 730, 731, 732, 733, 734, 735, 739, 741,
        742, 743, 745, 746, 747, 748, 749, 750, 751, 753, 754, 755, 756, 757, 758, 759,
        760, 761, 762, 763, 764, 765, 766, 767, 799, 811, 813, 814, 815, 819, 821, 822,
        823, 825, 826, 827, 828, 829, 830, 831, 839, 843, 845, 846, 847, 851, 853, 854,
        855, 857, 858, 859, 860, 861, 862, 863, 867, 869, 870, 871, 873, 874, 875, 876,
        877, 878, 879, 881, 882, 883, 884, 885, 886, 887, 888, 889, 890, 891, 892, 893,
        894, 895, 903, 907, 909, 910, 911, 915, 917, 918, 919, 920, 921, 922, 923, 924,
        925, 926, 927, 930, 931, 932, 933, 934, 935, 936, 937, 938, 939, 940, 941, 942,
        943, 944, 945, 946, 947, 948, 949, 950, 951, 952, 953, 954, 955, 956, 957, 958,
        959, 961, 962, 963, 964, 965, 966, 967, 968, 969, 970, 971, 972, 973, 974, 975,
        976, 977, 978, 979, 980, 981, 982, 983, 984, 985, 986, 987, 988, 989, 990, 991,
        992, 993, 994, 995, 996, 997, 998, 999, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007,
        1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020, 1021, 1022, 1023,
        ],
    ),
    512: dict(
        N=2048,
        Q=18433,
        MESSAGE_BYTES=64,
        QUANT_BITS=8,
        SS_BYTES=64,
        positions=[
        511, 759, 763, 765, 766, 767, 863, 879, 887, 891, 893, 894, 895, 927, 942, 943,
        947, 949, 950, 951, 953, 954, 955, 956, 957, 958, 959, 967, 971, 973, 974, 975,
        979, 981, 982, 983, 985, 986, 987, 988, 989, 990, 991, 995, 997, 998, 999, 1001,
        1002, 1003, 1004, 1005, 1006, 1007, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018,
        1019, 1020, 1021, 1022, 1023, 1215, 1247, 1263, 1269, 1270, 1271, 1273, 1274, 1275, 1276, 1277,
        1278, 1279, 1343, 1371, 1373, 1374, 1375, 1383, 1387, 1389, 1390, 1391, 1395, 1397, 1398, 1399,
        1401, 1402, 1403, 1404, 1405, 1406, 1407, 1423, 1431, 1435, 1437, 1438, 1439, 1447, 1451, 1453,
        1454, 1455, 1459, 1461, 1462, 1463, 1465, 1466, 1467, 1468, 1469, 1470, 1471, 1479, 1483, 1485,
        1486, 1487, 1490, 1491, 1492, 1493, 1494, 1495, 1496, 1497, 1498, 1499, 1500, 1501, 1502, 1503,
        1505, 1506, 1507, 1508, 1509, 1510, 1511, 1512, 1513, 1514, 1515, 1516, 1517, 1518, 1519, 1520,
        1521, 1522, 1523, 1524, 1525, 1526, 1527, 1528, 1529, 1530, 1531, 1532, 1533, 1534, 1535, 1591,
        1595, 1597, 1598, 1599, 1615, 1623, 1627, 1629, 1630, 1631, 1639, 1643, 1645, 1646, 1647, 1650,
        1651, 1652, 1653, 1654, 1655, 1656, 1657, 1658, 1659, 1660, 1661, 1662, 1663, 1679, 1687, 1690,
        1691, 1692, 1693, 1694, 1695, 1701, 1702, 1703, 1705, 1706, 1707, 1708, 1709, 1710, 1711, 1713,
        1714, 1715, 1716, 1717, 1718, 1719, 1720, 1721, 1722, 1723, 1724, 1725, 1726, 1727, 1731, 1733,
        1734, 1735, 1737, 1738, 1739, 1740, 1741, 1742, 1743, 1745, 1746, 1747, 1748, 1749, 1750, 1751,
        1752, 1753, 1754, 1755, 1756, 1757, 1758, 1759, 1761, 1762, 1763, 1764, 1765, 1766, 1767, 1768,
        1769, 1770, 1771, 1772, 1773, 1774, 1775, 1776, 1777, 1778, 1779, 1780, 1781, 1782, 1783, 1784,
        1785, 1786, 1787, 1788, 1789, 1790, 1791, 1805, 1806, 1807, 1811, 1813, 1814, 1815, 1817, 1818,
        1819, 1820, 1821, 1822, 1823, 1827, 1829, 1830, 1831, 1833, 1834, 1835, 1836, 1837, 1838, 1839,
        1841, 1842, 1843, 1844, 1845, 1846, 1847, 1848, 1849, 1850, 1851, 1852, 1853, 1854, 1855, 1859,
        1861, 1862, 1863, 1865, 1866, 1867, 1868, 1869, 1870, 1871, 1873, 1874, 1875, 1876, 1877, 1878,
        1879, 1880, 1881, 1882, 1883, 1884, 1885, 1886, 1887, 1889, 1890, 1891, 1892, 1893, 1894, 1895,
        1896, 1897, 1898, 1899, 1900, 1901, 1902, 1903, 1904, 1905, 1906, 1907, 1908, 1909, 1910, 1911,
        1912, 1913, 1914, 1915, 1916, 1917, 1918, 1919, 1923, 1925, 1926, 1927, 1929, 1930, 1931, 1932,
        1933, 1934, 1935, 1937, 1938, 1939, 1940, 1941, 1942, 1943, 1944, 1945, 1946, 1947, 1948, 1949,
        1950, 1951, 1953, 1954, 1955, 1956, 1957, 1958, 1959, 1960, 1961, 1962, 1963, 1964, 1965, 1966,
        1967, 1968, 1969, 1970, 1971, 1972, 1973, 1974, 1975, 1976, 1977, 1978, 1979, 1980, 1981, 1982,
        1983, 1985, 1986, 1987, 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999,
        2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015,
        2016, 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026, 2027, 2028, 2029, 2030, 2031,
        2032, 2033, 2034, 2035, 2036, 2037, 2038, 2039, 2040, 2041, 2042, 2043, 2044, 2045, 2046, 2047,
        ],
    ),
}


def sm3(data):
    return hashlib.new("sm3", data).digest()


def xof(data, length):
    # Official auxiliary pseudoXOF for byte-aligned inputs: SM3 in counter mode.
    return b"".join(sm3(data + i.to_bytes(4, "big"))
                    for i in range(1, (length + 31) // 32 + 1))[:length]


def public_signed_permutation(seed, n):
    """Permutation and signs as derived by the scheme from the PUBLIC pk seed."""
    def words():
        block = 0
        while True:
            data = xof(PERM_DOMAIN + seed + block.to_bytes(4, "little"), 4096)
            for offset in range(0, 4096, 4):
                yield int.from_bytes(data[offset:offset + 4], "little")
            block += 1

    stream = words()
    permutation = list(range(n))
    for i in range(n - 1, 0, -1):  # Fisher-Yates with rejection sampling
        bound = i + 1
        limit = (2**32 // bound) * bound
        sample = next(stream)
        while sample >= limit:
            sample = next(stream)
        j = sample % bound
        permutation[i], permutation[j] = permutation[j], permutation[i]
    sign_bytes = xof(SIGN_DOMAIN + seed, (n + 7) // 8)
    signs = [-1 if (sign_bytes[i >> 3] >> (i & 7)) & 1 else 1 for i in range(n)]
    return permutation, signs


def recover_shared_secret(pk, ct, params):
    """Attack interface: public key, ciphertext, public parameters — nothing else."""
    n, q, width = params["N"], params["Q"], params["QUANT_BITS"]
    permutation, signs = public_signed_permutation(pk[16:48], n)  # seed is public in pk
    payload = int.from_bytes(ct[16:16 + n * width // 8], "little")
    codeword = [0] * n
    for i in range(n):
        packed = (payload >> (i * width)) & ((1 << width) - 1)   # de-quantize
        coefficient = (packed * q + (1 << width) // 2) >> width
        centered = coefficient - q if coefficient > q // 2 else coefficient
        codeword[permutation[i]] = int(signs[i] * centered < 0)  # exact hard decision
    half = 1
    while half < n:  # inverse polar transform: same self-inverse XOR butterfly
        for block in range(0, n, 2 * half):
            for j in range(half):
                codeword[block + j] ^= codeword[block + half + j]
        half *= 2
    message = bytearray(params["MESSAGE_BYTES"])
    for j, position in enumerate(params["positions"]):
        message[j >> 3] |= codeword[position] << (j & 7)
    return xof(SS_DOMAIN + message + sm3(ct), params["SS_BYTES"])


def load_kats(path):
    """Parse one official KAT_KEM_PolarKEM-*.txt file.

    Only the PK, CT, and SS fields are ever read; the Seed and SK fields that
    the official files also contain are parsed past and never used.
    """
    records, current = [], {}
    for line in path.read_text().splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key, value = key.strip(), value.strip()
        if key == "Count":
            current = {"count": int(value)}
        elif key in ("PK", "CT", "SS"):
            current[key] = bytes.fromhex(value)
            if key == "SS":
                records.append(current)
    return records


def main():
    folder = Path(__file__).resolve().parent
    files = sorted(folder.glob("KAT_KEM_PolarKEM-*.txt"))
    if not files:
        sys.exit("no KAT_KEM_PolarKEM-*.txt files found next to poc.py")
    recovered = total = 0
    for path in files:
        level = int(re.search(r"PolarKEM-(\d+)", path.name)[1])
        cases = load_kats(path)
        matches = sum(
            recover_shared_secret(case["PK"], case["CT"], PARAMS[level]) == case["SS"]
            for case in cases)  # expected SS used by this comparator only
        recovered += matches
        total += len(cases)
        print(f"PolarKEM-{level:<3} {matches}/{len(cases)} shared secrets "
              f"recovered from public data alone ({path.name})")
    print(f"{recovered}/{total} vectors recovered")
    return 0 if recovered == total else 1


if __name__ == "__main__":
    sys.exit(main())
