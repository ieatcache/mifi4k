#!/usr/bin/env python3
"""
mifare.py — read and decode MIFARE Classic 1K cards you own.

Decoding is pure Python stdlib and reads Flipper Zero .nfc files, raw .mfd/.bin
dumps, Proxmark .eml, pm3/Flipper JSON, or pasted hex.

Flipper Zero workflow (no libnfc needed):
  1. NFC app -> Read, hold the card to the Flipper's back, Save.
  2. Copy the .nfc off the Flipper (qFlipper file manager, lab.flipper.net, or
     the microSD at /ext/nfc/<name>.nfc).
  3. python3 mifare.py decode mycard.nfc

The `read` command below is only for a computer-attached libnfc reader (ACR122U,
PN532, etc.) and is not needed with a Flipper.

Usage:
  python3 mifare.py decode mycard.nfc    # decode a Flipper .nfc (or .mfd/.bin/.eml/hex)
  python3 mifare.py decode --no-color mycard.nfc
  python3 mifare.py read                 # libnfc reader only: read card -> dump.mfd
  python3 mifare.py read --mfoc          # libnfc reader only: recover custom keys first

For cards you own. MIFARE Classic's Crypto1 cipher is broken by design, so
these cards are readable — treat them as convenient, not secure.
"""
import sys, os, argparse, subprocess, shutil, json, re

# ---------- access-condition lookup tables (code = C1 C2 C3) ----------
DATA_AC = {  # [read, write, increment, dec/transfer/restore]
    '000': ['A|B', 'A|B', 'A|B', 'A|B'], '010': ['A|B', '--', '--', '--'],
    '100': ['A|B', 'B',   '--',  '--'],  '110': ['A|B', 'B',  'B',  'A|B'],
    '001': ['A|B', '--',  '--',  'A|B'], '011': ['B',   'B',  '--', '--'],
    '101': ['B',   '--',  '--',  '--'],  '111': ['--',  '--', '--', '--'],
}
DATA_NOTE = {'001': 'value-block config', '000': 'transport/default'}
TRAIL_AC = {  # [readKeyA, writeKeyA, readAccess, writeAccess, readKeyB, writeKeyB]
    '000': ['--', 'A',  'A',   '--', 'A',  'A'],  '010': ['--', '--', 'A',   '--', 'A',  '--'],
    '100': ['--', 'B',  'A|B', '--', '--', 'B'],  '110': ['--', '--', 'A|B', '--', '--', '--'],
    '001': ['--', 'A',  'A',   'A',  'A',  'A'],  '011': ['--', 'B',  'A|B', 'B',  '--', 'B'],
    '101': ['--', '--', 'A|B', 'B',  '--', '--'], '111': ['--', '--', 'A|B', '--', '--', '--'],
}
TRAIL_NOTE = {'001': 'transport/default', '000': 'Key B readable (usable as data)'}

# ---------- color ----------
class C:
    enabled = True
    def __getattr__(self, name):
        codes = dict(dim='2', red='31', green='32', yellow='33', blue='34',
                     mag='35', cyan='36', bold='1', reset='0')
        return (f'\033[{codes.get(name,"0")}m') if C.enabled else ''
c = C()

def paint(s, col):
    return f'{col}{s}{c.reset}' if C.enabled else s

# ---------- decoding ----------
def decode_access(t):
    b6, b7, b8 = t[6], t[7], t[8]
    bit = lambda byte, p: (byte >> p) & 1
    c1 = [bit(b7, 4), bit(b7, 5), bit(b7, 6), bit(b7, 7)]
    c2 = [bit(b8, 0), bit(b8, 1), bit(b8, 2), bit(b8, 3)]
    c3 = [bit(b8, 4), bit(b8, 5), bit(b8, 6), bit(b8, 7)]
    c1i = [bit(b6, 0), bit(b6, 1), bit(b6, 2), bit(b6, 3)]
    c2i = [bit(b6, 4), bit(b6, 5), bit(b6, 6), bit(b6, 7)]
    c3i = [bit(b7, 0), bit(b7, 1), bit(b7, 2), bit(b7, 3)]
    valid = all(c1[i] != c1i[i] and c2[i] != c2i[i] and c3[i] != c3i[i] for i in range(4))
    codes = [f'{c1[i]}{c2[i]}{c3[i]}' for i in range(4)]
    return valid, codes

def value_block(b):
    u32 = lambda o: int.from_bytes(b[o:o+4], 'little')
    v0, v1, v2 = u32(0), u32(4), u32(8)
    if v0 != v2 or v0 != ((~v1) & 0xFFFFFFFF):
        return None
    a, ia, aa, ib = b[12], b[13], b[14], b[15]
    if a != aa or a != (ia ^ 0xFF) or a != (ib ^ 0xFF):
        return None
    signed = v0 - 0x100000000 if v0 > 0x7FFFFFFF else v0
    return signed, v0, a

def ascii_str(bs):
    return ''.join(chr(x) if 32 <= x <= 126 else '.' for x in bs)

def hexbytes(bs, sep=' '):
    return sep.join(f'{x:02X}' for x in bs)

def parse_flipper(text):
    """Parse a Flipper Zero .nfc file (Block N: hh hh ... lines; '??' = unread)."""
    blocks, unknown = {}, []
    for line in text.splitlines():
        m = re.match(r'^\s*Block\s+(\d+):\s*(.+?)\s*$', line)
        if not m:
            continue
        n = int(m.group(1))
        toks = m.group(2).split()[:16]
        if '??' in toks:
            unknown.append(n)
        blocks[n] = bytes(0 if tk == '??' else int(tk, 16) for tk in toks)
    if not blocks:
        return None, []
    total = max(blocks) + 1
    data = bytearray(total * 16)
    for n, bs in blocks.items():
        data[n*16:n*16+len(bs)] = bs
    return bytes(data), unknown

def load_bytes(path):
    with open(path, 'rb') as f:
        raw = f.read()
    if len(raw) in (320, 1024, 4096):
        return raw
    # not a raw binary of a known size — try text (Flipper .nfc, hex, Proxmark .eml, pm3 JSON)
    text = raw.decode('utf-8', 'replace')
    if 'Filetype: Flipper NFC' in text or re.search(r'(?m)^\s*Block\s+\d+:', text):
        data, unknown = parse_flipper(text)
        if data is None:
            raise ValueError('Looks like a Flipper file but no Block lines were found.')
        if unknown:
            print(paint(f'note: {len(unknown)} block(s) had unread bytes (shown as 00): '
                        + ', '.join(map(str, unknown)), c.yellow))
        return data
    t = text.strip()
    if t.startswith('{'):
        j = json.loads(t)
        blk = j.get('blocks') or j.get('Blocks')
        if blk:
            allhex = ''.join(blk[k] for k in sorted(blk, key=lambda x: int(x)))
            return bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', allhex))
    h = re.sub(r'0x', '', text, flags=re.I)
    h = re.sub(r'[^0-9a-fA-F]', '', h)
    return bytes.fromhex(h)

def decode(data):
    n = len(data)
    if n != 1024:
        hint = ''
        if n == 4096: hint = '  (this is a 4K dump — only the first 1K is decoded here)'
        elif n == 320: hint = '  (this is a MIFARE Mini — only sectors present are decoded)'
        print(paint(f'warning: expected 1024 bytes, got {n}.{hint}', c.yellow))
        if n < 64:
            print(paint('too small to decode.', c.red)); return
    sectors = min(16, n // 64)

    b0 = data[0:16]
    uid = hexbytes(b0[0:4], '')
    bcc = b0[4]; bcc_calc = b0[0] ^ b0[1] ^ b0[2] ^ b0[3]
    bcc_ok = bcc == bcc_calc
    sak = b0[5]; atqa = hexbytes(b0[6:8], '')

    print()
    print(paint('MIFARE Classic 1K', c.bold))
    bcc_tag = paint('valid', c.green) if bcc_ok else paint(f'BAD (calc {bcc_calc:02X})', c.red)
    print(f'  UID {paint(uid, c.cyan)}   BCC {bcc:02X} [{bcc_tag}]   '
          f'SAK {paint(f"{sak:02X}", c.mag)}   ATQA {paint(atqa, c.blue)}')
    print()

    for s in range(sectors):
        base = s * 4
        blocks = [data[(base+bi)*16:(base+bi)*16+16] for bi in range(4)]
        trailer = blocks[3]
        valid, codes = decode_access(trailer)
        keyA = hexbytes(trailer[0:6], ''); keyB = hexbytes(trailer[10:16], '')
        gpb = trailer[9]
        bits_tag = paint('bits OK', c.green) if valid else paint('bits INCONSISTENT', c.red)
        print(paint(f'Sector {s:>2}', c.bold) + f'  blocks {base}-{base+3}   [{bits_tag}]')

        for bi, blk in enumerate(blocks):
            absn = base + bi
            is_trailer = bi == 3
            is_manuf = s == 0 and bi == 0
            vb = value_block(blk) if (not is_trailer and not is_manuf) else None
            line = f'    {absn:>3} | {hexbytes(blk)} | {ascii_str(blk)}'
            if is_manuf:   line += paint('   <- manufacturer', c.dim)
            elif is_trailer: line += paint('   <- trailer', c.yellow)
            elif vb:       line += paint(f'   <- value {vb[0]} (0x{vb[1]:08X}) addr 0x{vb[2]:02X}', c.mag)
            print(line)

        # access-condition detail
        note = TRAIL_NOTE.get(codes[3])
        print(paint(f'      access:', c.dim) + f' GPB 0x{gpb:02X}' +
              (paint(f'  ({note})', c.dim) if note else ''))
        for i in range(3):
            d = DATA_AC[codes[i]]; dn = DATA_NOTE.get(codes[i], '')
            dn = paint(f'  [{dn}]', c.dim) if dn else ''
            print(f'        blk {base+i}  bits {codes[i]}  '
                  f'read={d[0]:<3} write={d[1]:<3} inc={d[2]:<3} dec={d[3]:<3}{dn}')
        t = TRAIL_AC[codes[3]]
        print(f'        blk {base+3}  bits {codes[3]}  '
              f'KeyA: write={t[1]}  Access: read={t[2]} write={t[3]}  '
              f'KeyB: read={t[4]} write={t[5]}  (Key A never readable)')
        print()

# ---------- reading via libnfc ----------
def read_card(outfile, use_mfoc):
    if not shutil.which('nfc-mfclassic'):
        print(paint('nfc-mfclassic not found. Install libnfc first:', c.red))
        print('  macOS:          brew install libnfc')
        print('  Debian/Ubuntu:  sudo apt install libnfc-bin libnfc-examples mfoc')
        print('  then plug in your reader and run:  nfc-list')
        sys.exit(1)

    if use_mfoc:
        if not shutil.which('mfoc'):
            print(paint('mfoc not found — skipping key recovery. (brew/apt install mfoc)', c.yellow))
        else:
            print(paint(f'Recovering keys with mfoc -> {outfile} ...', c.bold))
            r = subprocess.run(['mfoc', '-O', outfile])
            if r.returncode == 0 and os.path.exists(outfile):
                print(paint('mfoc dump complete.', c.green))
                decode(load_bytes(outfile)); return
            print(paint('mfoc did not complete; falling back to default-key read.', c.yellow))

    print(paint(f'Reading card with default keys -> {outfile} ...', c.bold))
    # r=read  a=use key A  u=tolerate failed sectors (dump what we can)
    r = subprocess.run(['nfc-mfclassic', 'r', 'a', 'u', outfile])
    if not os.path.exists(outfile):
        print(paint('No dump produced. Is the card on the reader? Try `nfc-list` to confirm '
                    'the reader sees it. If sectors use non-default keys, rerun with --mfoc.', c.red))
        sys.exit(1)
    if r.returncode != 0:
        print(paint('Some sectors could not be read with default keys (locked with custom keys). '
                    'Decoding what was recovered; rerun with --mfoc to crack the rest.', c.yellow))
    decode(load_bytes(outfile))

# ---------- cli ----------
def main():
    ap = argparse.ArgumentParser(description='Read and decode MIFARE Classic 1K cards you own.')
    sub = ap.add_subparsers(dest='cmd', required=True)
    pr = sub.add_parser('read', help='read a card via libnfc, then decode')
    pr.add_argument('-o', '--out', default='dump.mfd', help='output dump file (default dump.mfd)')
    pr.add_argument('--mfoc', action='store_true', help='recover non-default keys with mfoc first')
    pd = sub.add_parser('decode', help='decode an existing dump (.mfd/.bin/.eml/.json/hex)')
    pd.add_argument('file', help='path to the dump')
    for p in (pr, pd):
        p.add_argument('--no-color', action='store_true', help='disable ANSI colors')
    a = ap.parse_args()

    C.enabled = (not getattr(a, 'no_color', False)) and sys.stdout.isatty()
    if a.cmd == 'read':
        read_card(a.out, a.mfoc)
    else:
        try:
            decode(load_bytes(a.file))
        except FileNotFoundError:
            print(paint(f'file not found: {a.file}', c.red)); sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        os._exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
