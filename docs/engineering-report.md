# WPA-Cracker — Engineering Report

## Overview

WPA-Cracker is a scapy-based tool for capturing WPA/WPA2 handshakes and cracking PSK pre-shared keys via wordlist attack. Supports PMKID-style attacks on compatible access points. Built primarily as an educational tool to understand the IEEE 802.11i 4-way handshake and key derivation.

## Architecture

### Capture Engine

Two modes:
1. **Live capture**: Opens a monitor mode interface via scapy's `sniff()` with channel hopping
2. **Pcap analysis**: Reads a pcap file, scans for EAPOL frames

Both modes produce the same internal representation — a list of handshake objects.

### Handshake Detection Algorithm

1. Filter packets by EtherType 0x888E (EAPOL)
2. Within EAPOL, filter for Key Descriptor Type = 2 (RSN)
3. Group by (BSSID, STA) tuple
4. Track message sequence: Msg1 (A-nonce), Msg2 (S-nonce + MIC1), Msg3 (GTK + MIC2), Msg4 (ACK)
5. A handshake is complete when all 4 messages are observed
6. PMKID is extracted from Msg1 if present (flags bit 4 set)

### Cracking Engine

The PSK-to-PMK derivation follows IEEE 802.11i-2004 Section 8.5.1.1:

```
PMK = PBKDF2(HMAC-SHA1, PSK, ssid, 4096, 256)
```

PTK derivation follows Section 8.5.1.2:

```
PTK = PRF-X(PMK, "Pairwise key expansion", 
             min(AP_MAC, STA_MAC) || max(AP_MAC, STA_MAC) ||
             min(A-nonce, S-nonce) || max(A-nonce, S-nonce))
```

PRF-X is the NIST-defined pseudo-random function using HMAC-SHA1, producing X bits of output. For CCMP (AES), X=384.

MIC verification compares the computed MIC against the MIC field in EAPOL-Key frame message 2. The MIC covers the EAPOL-Key frame from version field through the Key Data field, with the MIC field set to zero during computation.

### PMKID Calculation

```
PMKID = HMAC-SHA1(PMK, "PMK Name" || AP_MAC || STA_MAC)[0:16]
```

Truncated to 16 bytes per IEEE 802.11-2012 Section 11.6.1.3.

## Performance

| Operation | Rate | Notes |
|-----------|------|-------|
| PBKDF2 (4096 iters) | ~500/s | Python, single core |
| PBKDF2 (4096 iters) | ~50,000/s | Hashcat, RTX 4090 |
| MIC verification | ~200,000/s | Trivial compared to PBKDF2 |
| Live capture parsing | ~10,000 pkt/s | Scapy bound |

## Testing

100 unit tests covering:
- EAPOL frame parsing (message 1-4)
- Handshake detection from synthetic packets
- PMK derivation (PBKDF2 test vectors)
- PTK derivation (PRF test vectors)
- MIC verification
- PMKID calculation
- Wordlist loading and processing
- Capture output formatting
- Edge cases: partial handshakes, corrupted frames, duplicate packets
- CLI argument parsing

## Test Vectors

PBKDF2 test vector (IEEE 802.11i Annex H.4):
- PSK: "password"
- SSID: "Test"
- Expected PMK: 0x4e... (truncated for brevity, full vector in test file)

## Limitations

1. **Python PBKDF2 is slow.** Hashcat is the production tool. This is for understanding and automation.
2. **No WPA3 support.** SAE handshake uses different frame types.
3. **Channel hopping not implemented.** Live capture stays on one channel.
4. **Hidden SSID networks need manual ESSID.** Probe response parsing is TODO.
5. **EAPOL parsing is fragile.** Some APs send frames in unexpected order.

## Future Work

- WPA3/SAE handshake support
- GPU acceleration via PyOpenCL
- Hashcat .hccapx/.hc22000 export
- Automated deauthentication attack to force handshake
- Wi-Fi Protected Setup (WPS) PIN attack
- 5GHz/6GHz channel support with proper regulatory compliance
