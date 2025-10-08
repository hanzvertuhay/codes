from hashlib import sha256
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import SEED_SEARCHER_FINAL_electrum_v3 as mod  # noqa: E402
from bip39_data import WORDLIST  # noqa: E402


def entropy_to_mnemonic(ent_hex: str) -> str:
    data = bytes.fromhex(ent_hex)
    ent_bits = len(data) * 8
    cs_bits = ent_bits // 32
    digest_bits = ''.join(f"{b:08b}" for b in sha256(data).digest())
    bitstr = ''.join(f"{b:08b}" for b in data) + digest_bits[:cs_bits]
    words = [WORDLIST[int(bitstr[i:i + 11], 2)] for i in range(0, len(bitstr), 11)]
    return ' '.join(words)


def test_find_phrases_detects_various_lengths():
    provided = "ticket luggage flavor grain hover soap truly again oak someone biology correct"
    mnemonics = {
        12: provided,
        15: entropy_to_mnemonic('0' * 40),
        18: entropy_to_mnemonic('0' * 48),
        21: entropy_to_mnemonic('0' * 56),
        24: entropy_to_mnemonic('0' * 64),
    }

    text = '\n'.join(mnemonics.values())
    valid, near, electrum = mod.find_phrases_robust(text)

    assert not near
    assert not electrum
    found = {len(v.split()): v for v in valid}
    assert set(found) == set(mnemonics)
    for length, phrase in mnemonics.items():
        assert found[length] == phrase


def test_electrum_detection_and_suspicious_filter():
    electrum_phrase = "churn donor mandate video climb pool easy planet renew enter inner record"
    text = f"Some intro text\n{electrum_phrase}\nTrailing"  # ensure parsing handles noise
    valid, near, electrum = mod.find_phrases_robust(text)

    assert electrum == [electrum_phrase]
    assert not mod.bip39_check(electrum_phrase)
    assert not near

    noisy = "little boy twenty hello there little girl tiger there little girl tiger hello there little boy mind there"
    assert mod.is_suspicious(noisy)
