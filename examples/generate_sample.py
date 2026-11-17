#!/usr/bin/env python3
"""Generates synthetic sample data so graphcat can be tried without real data.

Produces:
  sample.ntds  -> secretsdump-style dump (-format 3)
  sample.pot   -> hashcat-style potfile

Every password here is invented. None of it comes from a client engagement.
"""

import struct
import sys
from pathlib import Path

# --- Pure-Python MD4 --------------------------------------------------------
# OpenSSL 3 dropped MD4 from hashlib, and the NT hash needs it. This is only
# used to fabricate the sample hashes; graphcat itself never computes hashes.

def _lrot(x, n):
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def md4(data: bytes) -> str:
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    msg = bytearray(data)
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', bit_len)

    for off in range(0, len(msg), 64):
        X = list(struct.unpack('<16I', msg[off:off + 64]))
        a, b, c, d = h

        for i in (0, 4, 8, 12):
            a = _lrot(a + ((b & c) | (~b & d)) + X[i], 3)
            d = _lrot(d + ((a & b) | (~a & c)) + X[i + 1], 7)
            c = _lrot(c + ((d & a) | (~d & b)) + X[i + 2], 11)
            b = _lrot(b + ((c & d) | (~c & a)) + X[i + 3], 19)

        for i in (0, 1, 2, 3):
            a = _lrot(a + ((b & c) | (b & d) | (c & d)) + X[i] + 0x5A827999, 3)
            d = _lrot(d + ((a & b) | (a & c) | (b & c)) + X[i + 4] + 0x5A827999, 5)
            c = _lrot(c + ((d & a) | (d & b) | (a & b)) + X[i + 8] + 0x5A827999, 9)
            b = _lrot(b + ((c & d) | (c & a) | (d & a)) + X[i + 12] + 0x5A827999, 13)

        for i in (0, 2, 1, 3):
            a = _lrot(a + (b ^ c ^ d) + X[i] + 0x6ED9EBA1, 3)
            d = _lrot(d + (a ^ b ^ c) + X[i + 8] + 0x6ED9EBA1, 9)
            c = _lrot(c + (d ^ a ^ b) + X[i + 4] + 0x6ED9EBA1, 11)
            b = _lrot(b + (c ^ d ^ a) + X[i + 12] + 0x6ED9EBA1, 15)

        h = [(v + n) & 0xFFFFFFFF for v, n in zip(h, (a, b, c, d))]

    return struct.pack('<4I', *h).hex()


def nthash(password: str) -> str:
    return md4(password.encode('utf-16le'))


# --- Synthetic population ---------------------------------------------------
# (username, password or None if uncracked, [password history])
# Deliberately shaped to exercise every section of the report: reuse, username
# in password, embedded years, keyboard walks, and minimal-change rotation.
POPULATION = [
    ('a.silva',    'Verano2024!',   ['Verano2023!', 'Invierno2023']),
    ('b.rojas',    'qwerty123',     []),
    ('c.mendez',   'C.Mendez2024',  ['C.Mendez2023']),
    ('d.paredes',  'Password1',     []),
    ('e.quiroga',  'Empresa2025#',  ['Empresa2024#']),
    ('f.navarro',  'qwerty123',     []),
    ('g.ibarra',   None,            []),
    ('h.lopez',    'asdfgh',        []),
    ('i.duran',    'Bienvenido01',  []),
    ('j.castro',   'Password1',     []),
    ('k.aguirre',  None,            []),
    ('l.fuentes',  '1qaz2wsx',      []),
    ('m.salinas',  'Marzo2019$',    []),
    ('n.vergara',  'n.vergara123',  []),
    ('o.pizarro',  'Tr0ub4dor&3',   []),
    ('p.riquelme', None,            []),
    ('q.bustos',   'Verano2024!',   []),
    ('r.donoso',   '12345678',      []),
    ('s.leiva',    'Correcto.Caballo.Bateria.Grapa', []),
    ('t.olivares', 'Password1',     []),
    # A baseword family: four distinct strings, one idea. Counting distinct
    # strings calls these four unique; the report calls them variations.
    ('u.arriaga',  'Nacional12',    []),
    ('v.tapia',    'nacional13',    []),
    ('w.moreno',   'Nacional2024',  []),
    ('x.bravo',    'nacional.14!',  []),
    # Passwords hashcat can only write as $HEX[...]: the first holds a colon,
    # which would break the potfile format, the second a cp1252 'n' with tilde
    # that is not valid UTF-8.
    ('y.zamora',   'admin:2024',    []),
    ('z.pena',     'Contrase\u00f1a10',  []),
]


def _potfile_value(password: str) -> str:
    """Encodes a password the way hashcat writes it into a potfile.

    hashcat falls back to $HEX[...] when the cleartext contains a colon or is
    not valid UTF-8, so the sample data exercises that path too.
    """
    if ':' in password:                       # would split the hash:password line
        return f"$HEX[{password.encode('utf-8').hex()}]"
    if not password.isascii():                # came from a cp1252 wordlist
        return f"$HEX[{password.encode('cp1252', 'replace').hex()}]"
    return password


def main():
    out = Path(__file__).resolve().parent
    ntds, pot = [], {}

    for rid, (user, pwd, history) in enumerate(POPULATION, start=1100):
        secrets = [(user, pwd)]
        secrets += [(f'{user}_history{i}', h) for i, h in enumerate(history)]
        for name, secret in secrets:
            h = nthash(secret) if secret is not None else 'x' * 32
            ntds.append(f'DOMINIO\\{name}:{rid}:aad3b435b51404eeaad3b435b51404ee:{h}:::')
            if secret is not None:
                pot[h] = _potfile_value(secret)

    (out / 'sample.ntds').write_text('\n'.join(ntds) + '\n', encoding='utf-8')
    (out / 'sample.pot').write_text(
        '\n'.join(f'{h}:{p}' for h, p in pot.items()) + '\n', encoding='utf-8')

    print(f'[-] {out / "sample.ntds"}: {len(ntds)} lines')
    print(f'[-] {out / "sample.pot"}: {len(pot)} entries')
    return 0


if __name__ == '__main__':
    sys.exit(main())
