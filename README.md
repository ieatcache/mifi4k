# mifi4k — MIFARE Classic 1K Decoder

A browser-based decoder for MIFARE Classic 1K card dumps. Everything runs
locally in your browser — nothing is uploaded.

**Live site:** https://ieatcache.github.io/mifi4k/

## What it does

Drop in a card dump and it decodes:

- **Manufacturer block** — UID, BCC (with validity check), SAK, ATQA
- **Every sector trailer** — Key A, access-condition bits (with integrity
  check), Key B, and the GPB byte
- **Access conditions** — per-block read / write / increment / decrement
  permissions, expanded from the C1/C2/C3 bits
- **Value blocks** — detected and decoded (value + address)
- **Security assessment** — grades how exposed the card is: flags publicly-known
  keys, factory-default access, readable Key B, value blocks, a mismatched BCC
  (magic-card tell), and clonability
- **Known-key labeling** — matches each sector's Key A/B against a dictionary of
  published keys (default, MAD, NDEF, common/transit) with an all-keys table
- **Search + copy** — find any hex or ASCII string across the dump and jump to it;
  one-click copy for the UID, any key, or any block
- Hex + ASCII view of all 16 sectors, with a text / JSON export

## Supported input formats

- **Flipper Zero `.nfc`** files (including `??` unread bytes)
- Raw binary dumps (`.mfd`, `.bin`, `.dmp`) — 1024 bytes
- Proxmark3 `.eml`
- Flipper / pm3 JSON
- Pasted hex

## How to get a dump

**Flipper Zero:** NFC → Read, hold the card to the back, Save. Copy the
`.nfc` off the device (qFlipper, lab.flipper.net, or the microSD at
`/ext/nfc/`), then drop it onto the site.

**Computer + libnfc reader (ACR122U, PN532):**
```bash
nfc-mfclassic r a u dump.mfd
```

## Companion CLI

`mifare.py` (Python 3, stdlib only) decodes the same formats in a terminal:

```bash
python3 mifare.py decode mycard.nfc
```

## Note

For decoding cards you own. MIFARE Classic's Crypto1 cipher is broken by
design, so treat these cards as readable, not secure.
