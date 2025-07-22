import hashlib
import hmac
import binascii
import os
import time
import requests
from requests.exceptions import RequestException, Timeout, HTTPError
import json
import struct
import unicodedata
import random
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from queue import Queue
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import base58
import ecdsa
from ecdsa.curves import SECP256k1
from ecdsa.keys import SigningKey
from ecdsa.util import number_to_string
import sys

# Logging to file
logging.basicConfig(filename='balance_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# Load BIP-39 wordlist from GitHub
def load_bip39_wordlist():
    url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.text.splitlines()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load BIP-39 wordlist: {e}")
        sys.exit(1)

BIP39_WORDLIST = load_bip39_wordlist()

# Pure Base58 implementation
def base58_encode(data):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big')
    encoded = ''
    while num:
        num, rem = divmod(num, 58)
        encoded = alphabet[rem] + encoded
    leading_zeros = len(data) - len(data.lstrip(b'\x00'))
    return '1' * leading_zeros + encoded

def base58_encode_check(data):
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    return base58_encode(data + checksum)

# Pure Ed25519 implementation (minimal for public key generation)
# Based on public domain pure Python Ed25519 from https://github.com/warner/python-ed25519 (simplified)
ed25519_q = 2**255 - 19
ed25519_l = 2**252 + 27742317777372353535851937790883648493
ed25519_d = -451324261841723566111282542702799631633 / 11426906937444062381257060823651921513897804145751392891080894113392941543293534467345313235330611650435 % ed25519_q

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

def ed25519_base_point():
    return Point(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)

def ed25519_scalar_mult(scalar, point):
    if scalar == 0:
        return Point(0, 1)
    q = ed25519_scalar_mult(scalar // 2, point)
    q = ed25519_point_double(q)
    if scalar % 2:
        q = ed25519_point_add(q, point)
    return q

def ed25519_point_double(p):
    x, y = p.x, p.y
    t = (x + y) % ed25519_q
    xx = (x * x) % ed25519_q
    yy = (y * y) % ed25519_q
    xy2 = (xx + yy) % ed25519_q
    x3 = (t * t - xy2) % ed25519_q
    y3 = (yy - xx) * (1 + ed25519_d * xy2 * xy2) % ed25519_q
    return Point(x3, y3)

def ed25519_point_add(p1, p2):
    if p1.x == p2.x and p1.y == -p2.y % ed25519_q:
        return Point(0, 1)
    dx = (p1.x - p2.x) % ed25519_q
    dy = (p1.y - p2.y) % ed25519_q
    tt = (dx * dy) % ed25519_q
    t = pow(dx * dy, ed25519_q - 2, ed25519_q)
    x3 = (tt * (p1.x + p2.x) - dy * dy) * t % ed25519_q
    y3 = (tt * (p1.y + p2.y) - dx * dx * (1 + ed25519_d * tt * tt)) * t % ed25519_q
    return Point(x3, y3)

def ed25519_encode_point(p):
    x = p.x % 2
    y = p.y
    if x:
        y |= (1 << 255)
    return y.to_bytes(32, 'little')

def ed25519_public_key(priv):
    h = hashlib.sha512(priv).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (2**255 - 8)
    a |= (1 << 254)
    A = ed25519_scalar_mult(a, ed25519_base_point())
    return ed25519_encode_point(A)

# BIP32Ed25519 class (kept as is, but use ed25519_public_key for pub)
class BIP32Ed25519:
    def root_key_slip10(self, master_secret):
        s = _Fk(b"ed25519 seed", master_secret)
        i_l = s[0:32]
        i_r = s[32:64]
        k_l = i_l
        while (int.from_bytes(k_l, 'little') & 0x20) != 0:
            s = _Fk(s, master_secret)
            i_l = s[0:32]
            k_l = i_l
        c = _h512(b"ed25519 seed" + master_secret)[32:]
        return k_l + i_r, c

    def derive_private_child_key(self, parent_key, parent_chain_code, index):
        if index < 0x80000000:
            raise ValueError("Soft derivation not supported for Ed25519")
        i = _Fk(struct.pack(">L", index), b'\x00' + parent_key[0:32] + parent_chain_code)
        i_l = i[0:32]
        i_r = i[32:64]
        a_i = (int.from_bytes(i_l, 'little') * 8) % ed25519_l
        k_l = (a_i + int.from_bytes(parent_key[0:32], 'little')) % ed25519_l
        k_l_bytes = k_l.to_bytes(32, 'little')
        k_r = (int.from_bytes(parent_key[32:64], 'little') + int.from_bytes(i_r, 'little')) % (2**256)
        k_r_bytes = k_r.to_bytes(32, 'little')
        c_i = _h512(i)[32:]
        return k_l_bytes + k_r_bytes, c_i

# Helper functions
def _NFKDbytes(str):
    return unicodedata.normalize('NFKD', str).encode()

def _h512(m):
    return hashlib.sha512(m).digest()

def _Fk(message, secret):
    return hmac.new(secret, message, hashlib.sha512).digest()

# mnemonic_to_seed
def mnemonic_to_seed(mnemonic, passphrase=""):
    mnemonic = _NFKDbytes(mnemonic)
    salt = _NFKDbytes("mnemonic" + passphrase)
    return hashlib.pbkdf2_hmac('sha512', mnemonic, salt, 2048)

# bip32_derive_master_key
def bip32_derive_master_key(seed):
    return hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()

# bip32_derive_child_key
def bip32_derive_child_key(parent_priv, parent_chain, index):
    if index >= 0x80000000:
        data = b'\x00' + parent_priv + struct.pack('>I', index)
    else:
        pub = get_secp256k1_public_key(parent_priv)
        data = pub + struct.pack('>I', index)
    i = hmac.new(parent_chain, data, hashlib.sha512).digest()
    i_l = i[:32]
    child_priv = (int.from_bytes(i_l, 'big') + int.from_bytes(parent_priv, 'big')) % SECP256k1.order
    child_chain = i[32:]
    return child_priv.to_bytes(32, 'big'), child_chain

# parse_derivation_path
def parse_derivation_path(path):
    parts = path.strip('m/').split('/')
    indices = []
    for p in parts:
        if p.endswith("'"):
            indices.append(int(p[:-1]) + 0x80000000)
        else:
            indices.append(int(p))
    return indices

# derive_priv_key
def derive_priv_key(seed, path):
    master_key = bip32_derive_master_key(seed)
    priv = master_key[:32]
    chain = master_key[32:]
    for index in parse_derivation_path(path):
        priv, chain = bip32_derive_child_key(priv, chain, index)
    return priv

# derive_ed25519
def derive_ed25519(seed, path):
    hd = BIP32Ed25519()
    master_key, master_chain = hd.root_key_slip10(seed)
    priv, chain = master_key, master_chain
    for index in parse_derivation_path(path)[1:]:
        priv, chain = hd.derive_private_child_key(priv, chain, index)
    return priv[:32]

# get_secp256k1_public_key
def get_secp256k1_public_key(priv_key):
    sk = SigningKey.from_string(priv_key, curve=SECP256k1)
    vk = sk.get_verifying_key()
    return b'\x04' + vk.to_string()

# get_public_key
def get_public_key(priv, ed25519=False):
    if ed25519:
        return ed25519_public_key(priv)
    else:
        return get_secp256k1_public_key(priv)

# eth_address
def eth_address(pub_key):
    keccak = hashlib.new('sha3_256', pub_key[1:]).digest()
    return '0x' + keccak[-20:].hex()

# btc_address
def btc_address(pub_key, addr_type='legacy'):
    sha = hashlib.sha256(pub_key).digest()
    ripemd = hashlib.new('ripemd160', sha).digest()
    extended = b'\x00' + ripemd
    return base58_encode_check(extended)

# sol_address
def sol_address(pub_key):
    return base58_encode(pub_key)

# algo_address fixed
def algo_address(pub_key):
    h = _h512(pub_key)[:32]  # SHA512/256
    checksum = h[-4:]
    return base58_encode(pub_key + checksum)

# xrp_address fixed
def xrp_address(pub_key):
    ripemd = hashlib.new('ripemd160', hashlib.sha256(pub_key).digest()).digest()
    extended = b'\x00' + ripemd
    return base58_encode_check(extended)

# ada_address (simplified, note: real Cardano addresses may require stake key)
def ada_address(pub_key):
    blake = hashlib.blake2b(pub_key, digest_size=20).digest()
    bits = convertbits(blake, 8, 5)
    return bech32_encode('addr', bits)

# dot_address fixed to SS58
def dot_address(pub_key):
    prefix = 0
    pre = prefix.to_bytes(1, 'little')  # for prefix 0-63, 1 byte
    input_data = b'SS58PRE' + pre + pub_key
    checksum = hashlib.blake2b(input_data).digest()[:2]
    return base58_encode(pre + pub_key + checksum)

# ton_address (simplified)
def ton_address(pub_key):
    hash_pub = hashlib.sha256(pub_key).digest()
    return 'EQ' + base58_encode(hash_pub)

# convertbits, bech32_polymod, bech32_hrp_expand, bech32_create_checksum, bech32_encode (kept as is)
def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 0x1f for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

# check_balance_rpc (adjusted for REST vs JSON-RPC)
def check_balance_rpc(url_list, method, params, proxy=None, timeout=5, session=None):
    if not session:
        session = requests.Session()
    for url in url_list:
        try:
            if proxy:
                session.proxies = {'http': proxy, 'https': proxy}
            if "http" in method:  # For REST endpoints like Cosmos
                full_url = url + "/" + method
                response = session.get(full_url, timeout=timeout)
            else:
                response = session.post(url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=timeout)
            response.raise_for_status()
            if response.status_code == 429:
                continue
            return response.json()
        except (Timeout, HTTPError, RequestException):
            continue
    return None

# find_fastest_rpc
def find_fastest_rpc(rpc_list, check_method="eth_chainId", params=[]):
    fastest = None
    min_time = float('inf')
    session = requests.Session()
    for rpc in rpc_list:
        start = time.time()
        result = check_balance_rpc([rpc], check_method, params, session=session)
        elapsed = time.time() - start
        if result is not None and elapsed < min_time:
            min_time = elapsed
            fastest = rpc
    return fastest or rpc_list[0]

# get_evm_token_balance
def get_evm_token_balance(addr, contract, rpc_list, proxy=None, timeout=5):
    data = '0x70a08231' + '000000000000000000000000' + addr[2:].zfill(64)
    payload = {"to": contract, "data": data}
    result = check_balance_rpc(rpc_list, "eth_call", [payload, "latest"], proxy, timeout)
    return int(result or '0x0', 16) / 10**6

# NETWORKS (removed cardano and litecoin due to API key requirements; add if you have keys)
NETWORKS = {
    "algorand": {
        "coin_type": 283,
        "paths": ["m/44'/283'/0'/0'/0'", "m/44'/283'/{i}'/0/0"],
        "ed25519": True,
        "address_func": algo_address,
        "rpc": ["https://mainnet-api.algonode.cloud"],
        "balance_func": lambda addr, rpc, proxy, timeout, session: check_balance_rpc(rpc, "v2/accounts/" + addr, [], proxy, timeout, session).get('amount') / 1e6 if check_balance_rpc(rpc, "v2/accounts/" + addr, [], proxy, timeout, session) else 0
    },
    "bitcoin": {
        "coin_type": 0,
        "paths": ["m/44'/0'/0'/0/0", "m/49'/0'/0'/0/0", "m/84'/0'/0'/0/0", "m/86'/0'/0'/0/0"],
        "address_func": btc_address,
        "rpc": ["https://blockchain.info/rawaddr/{}"],
        "balance_func": lambda addr, rpc, proxy, timeout, session: check_btc_balance(addr, proxy, timeout)
    },
    "bitcoin_cash": {
        "coin_type": 145,
        "paths": ["m/44'/145'/0'/0/0", "m/44'/145'/{i}'/0/0"],
        "address_func": lambda pub: 'bitcoincash:' + base58_encode_check(b'\x00' + hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()),
        "rpc": ["https://rest1.biggestfan.net/ext/getbalance/{}"],
        "balance_func": lambda addr, rpc, proxy, timeout, session: float(requests.get(rpc[0].format(addr.replace('bitcoincash:', '')), proxies={'http': proxy, 'https': proxy} if proxy else None, timeout=timeout).json().get('balance', 0)) / 1e8 if requests.get(rpc[0].format(addr.replace('bitcoincash:', '')), proxies={'http': proxy, 'https': proxy} if proxy else None, timeout=timeout).status_code == 200 else 0
    },
    "dogecoin": {
        "coin_type": 3,
        "paths": ["m/44'/3'/0'/0/0", "m/44'/3'/{i}'/0/0"],
        "address_func": lambda pub: base58_encode_check(b'\x1e' + hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()),
        "rpc": ["https://dogechain.info/api/v1/address/balance/{}"],
        "balance_func": lambda addr, rpc, proxy, timeout, session: float(requests.get(rpc[0].format(addr), proxies={'http': proxy, 'https': proxy} if proxy else None, timeout=timeout).json().get('balance', 0)) if requests.get(rpc[0].format(addr), proxies={'http': proxy, 'https': proxy} if proxy else None, timeout=timeout).status_code == 200 else 0
    },
    "polkadot": {
        "coin_type": 354,
        "paths": ["m/44'/354'/0'/0'/0"],
        "ed25519": True,
        "address_func": dot_address,
        "rpc": ["https://rpc.polkadot.io"],
        "balance_func": lambda addr, rpc, proxy, timeout, session: int(check_balance_rpc(rpc, "system_account", [addr], proxy, timeout, session).get('data', {}).get('free', 0)) / 1e10 if check_balance_rpc(rpc, "system_account", [addr], proxy, timeout, session) else 0
    },
    "solana": {
        "coin_type": 501,
        "paths": ["m/44'/501'/0'/0'", "m/44'/501'/0'", "m/44'/501'/{i}'/0'"],
        "ed25519": True,
        "address_func": sol_address,
        "rpc": ["https://api.mainnet-beta.solana.com"],
        "balance_func": lambda addr, rpc, proxy, timeout, session: check_sol_balance(addr, rpc, proxy, timeout, session),
        "staking_func": lambda addr, rpc, proxy, timeout, session: sum([int(stake['lamports']) for stake in check_balance_rpc(rpc, "getStakeAccounts", [addr], proxy, timeout, session).get('value', [])]) / 1e9 if check_balance_rpc(rpc, "getStakeAccounts", [addr], proxy, timeout, session) else 0
    },
    "ton": {
        "coin_type": 607,
        "paths": ["m/44'/607'/0'/0", "m/44'/607'/{i}'/0"],
        "ed25519": True,
        "address_func": ton_address,
        "rpc": ["https://toncenter.com/api/v2/getAddressBalance?address={}"],
        "balance_func": lambda addr, rpc, proxy, timeout, session: int(requests.get(rpc[0].format(addr), proxies={'http': proxy, 'https': proxy} if proxy else None, timeout=timeout).json().get('result', 0)) / 1e9 if requests.get(rpc[0].format(addr), proxies={'http': proxy, 'https': proxy} if proxy else None, timeout=timeout).status_code == 200 else 0
    },
    "cosmos": {
        "coin_type": 118,
        "paths": ["m/44'/118'/0'/0/0", "m/44'/118'/{i}'/0/0"],
        "address_func": lambda pub: bech32_encode("cosmos", convertbits(hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest(), 8, 5)),
        "rpc": ["https://rpc.cosmos.network"],
        "balance_func": lambda addr, rpc, proxy, timeout, session: int(check_balance_rpc(rpc, f"cosmos/bank/v1beta1/balances/{addr}", [], proxy, timeout, session).get('balances', [{}])[0].get('amount', 0)) / 1e6 if check_balance_rpc(rpc, f"cosmos/bank/v1beta1/balances/{addr}", [], proxy, timeout, session) else 0,
        "staking_func": lambda addr, rpc, proxy, timeout, session: sum(int(d.get('balance', {}).get('amount', 0)) for d in check_balance_rpc(rpc, f"cosmos/staking/v1beta1/delegations/{addr}", [], proxy, timeout, session).get('delegation_responses', [])) / 1e6 if check_balance_rpc(rpc, f"cosmos/staking/v1beta1/delegations/{addr}", [], proxy, timeout, session) else 0
    },
}

# EVM_CHAINS (example ones; add more as needed with public RPCs without keys)
EVM_CHAINS = {
    "karura_network": {"chain_id": 686, "rpc": ["https://eth-rpc-karura.aca-api.network"], "paths": ["m/44'/60'/0'/0/0"], "address_func": eth_address, "balance_func": lambda addr, rpc, proxy, timeout, session: int(check_balance_rpc(rpc, "eth_getBalance", [addr, "latest"], proxy, timeout, session) or 0, 16) / 1e18, "token_func": lambda addr, rpc, proxy, timeout, session: get_evm_token_balance(addr, "0xdAC17F958D2ee523a2206206994597C13D831ec7", rpc, proxy, timeout)},
    "ethereum_classic": {"chain_id": 61, "rpc": ["https://www.ethercluster.com/etc"], "paths": ["m/44'/60'/0'/0/0"], "address_func": eth_address, "balance_func": lambda addr, rpc, proxy, timeout, session: int(check_balance_rpc(rpc, "eth_getBalance", [addr, "latest"], proxy, timeout, session) or 0, 16) / 1e18, "token_func": lambda addr, rpc, proxy, timeout, session: get_evm_token_balance(addr, "0xdAC17F958D2ee523a2206206994597C13D831ec7", rpc, proxy, timeout)},
    "boba_network": {"chain_id": 288, "rpc": ["https://mainnet.boba.network"], "paths": ["m/44'/60'/0'/0/0"], "address_func": eth_address, "balance_func": lambda addr, rpc, proxy, timeout, session: int(check_balance_rpc(rpc, "eth_getBalance", [addr, "latest"], proxy, timeout, session) or 0, 16) / 1e18, "token_func": lambda addr, rpc, proxy, timeout, session: get_evm_token_balance(addr, "0xdAC17F958D2ee523a2206206994597C13D831ec7", rpc, proxy, timeout)},
    "bnb_smart_chain_mainnet": {"chain_id": 56, "rpc": ["https://bsc-dataseed.binance.org/"], "paths": ["m/44'/60'/0'/0/0"], "address_func": eth_address, "balance_func": lambda addr, rpc, proxy, timeout, session: int(check_balance_rpc(rpc, "eth_getBalance", [addr, "latest"], proxy, timeout, session) or 0, 16) / 1e18, "token_func": lambda addr, rpc, proxy, timeout, session: get_evm_token_balance(addr, "0x55d398326f99059fF775485246999027B3197955", rpc, proxy, timeout)},
    # Add more EVM chains here as needed (up to 336 if you have the list and public RPCs)
    "geso_verse": {"chain_id": 42888, "rpc": ["https://rpc.gesotensei.0xshaggy.com"], "paths": ["m/44'/60'/0'/0/0"], "address_func": eth_address, "balance_func": lambda addr, rpc, proxy, timeout, session: int(check_balance_rpc(rpc, "eth_getBalance", [addr, "latest"], proxy, timeout, session) or 0, 16) / 1e18, "token_func": lambda addr, rpc, proxy, timeout, session: get_evm_token_balance(addr, "0xdAC17F958D2ee523a2206206994597C13D831ec7", rpc, proxy, timeout)},
}

# check_btc_balance
def check_btc_balance(addr, proxy=None, timeout=5):
    url = f"https://blockchain.info/rawaddr/{addr}"
    try:
        response = requests.get(url, proxies={'http': proxy, 'https': proxy} if proxy else None, timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            return data['final_balance'] / 10**8
        return 0
    except Exception:
        return 0

# check_sol_balance
def check_sol_balance(addr, rpc, proxy, timeout, session):
    result = check_balance_rpc(rpc, "getBalance", [addr], proxy, timeout, session)
    return result.get('result', {}).get('value', 0) / 10**9 if result else 0

# GUI with visual log
class SeedCheckerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Seed Phrase Checker")
        self.root.geometry("800x600")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Checker tab
        self.check_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.check_tab, text="Checker")

        tk.Label(self.check_tab, text="Seeds File/URL:").grid(row=0, column=0, padx=5, pady=5)
        self.seeds_entry = tk.Entry(self.check_tab, width=50)
        self.seeds_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(self.check_tab, text="Browse", command=self.load_seeds_file).grid(row=0, column=2, padx=5, pady=5)

        tk.Label(self.check_tab, text="Proxies File/URL:").grid(row=1, column=0, padx=5, pady=5)
        self.proxies_entry = tk.Entry(self.check_tab, width=50)
        self.proxies_entry.grid(row=1, column=1, padx=5, pady=5)
        tk.Button(self.check_tab, text="Browse", command=self.load_proxies_file).grid(row=1, column=2, padx=5, pady=5)
        self.proxies_count_label = tk.Label(self.check_tab, text="Proxies loaded: 0")
        self.proxies_count_label.grid(row=1, column=3, padx=5, pady=5)
        self.proxies_entry.bind("<FocusOut>", self.load_proxies_on_focus_out)

        tk.Label(self.check_tab, text="Threads:").grid(row=2, column=0, padx=5, pady=5)
        self.threads_entry = tk.Entry(self.check_tab, width=10)
        self.threads_entry.insert(0, "10")
        self.threads_entry.grid(row=2, column=1, padx=5, pady=5)

        tk.Label(self.check_tab, text="Timeout (s):").grid(row=3, column=0, padx=5, pady=5)
        self.timeout_entry = tk.Entry(self.check_tab, width=10)
        self.timeout_entry.insert(0, "5")
        self.timeout_entry.grid(row=3, column=1, padx=5, pady=5)

        tk.Label(self.check_tab, text="Depth:").grid(row=4, column=0, padx=5, pady=5)
        self.depth_entry = tk.Entry(self.check_tab, width=10)
        self.depth_entry.insert(0, "1")
        self.depth_entry.grid(row=4, column=1, padx=5, pady=5)

        tk.Label(self.check_tab, text="Network batch fraction:").grid(row=5, column=0, padx=5, pady=5)
        self.batch_entry = tk.Entry(self.check_tab, width=10)
        self.batch_entry.insert(0, "1.0")
        self.batch_entry.grid(row=5, column=1, padx=5, pady=5)

        self.start_check_btn = tk.Button(self.check_tab, text="Start Check", command=self.start_check)
        self.start_check_btn.grid(row=6, column=1, pady=10)

        self.progress = ttk.Progressbar(self.check_tab, length=400, mode='determinate')
        self.progress.grid(row=7, column=0, columnspan=3, padx=5, pady=5)

        self.stats_label = tk.Label(self.check_tab, text="Processed: 0/0 | Speed: 0/s | Errors: 0 conn, 0 proj, 0 timeout")
        self.stats_label.grid(row=8, column=0, columnspan=3, padx=5, pady=5)

        # Visual log
        self.log_text = tk.Text(self.check_tab, height=10, state='disabled')
        self.log_text.grid(row=9, column=0, columnspan=4, padx=5, pady=5, sticky="nsew")

        # Address Generator tab
        self.gen_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.gen_tab, text="Address Generator")

        tk.Label(self.gen_tab, text="Seeds File/URL for Addresses:").grid(row=0, column=0, padx=5, pady=5)
        self.gen_seeds_entry = tk.Entry(self.gen_tab, width=50)
        self.gen_seeds_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(self.gen_tab, text="Browse", command=self.load_gen_seeds_file).grid(row=0, column=2, padx=5, pady=5)

        tk.Label(self.gen_tab, text="Depth:").grid(row=1, column=0, padx=5, pady=5)
        self.gen_depth_entry = tk.Entry(self.gen_tab, width=10)
        self.gen_depth_entry.insert(0, "1")
        self.gen_depth_entry.grid(row=1, column=1, padx=5, pady=5)

        self.start_gen_btn = tk.Button(self.gen_tab, text="Generate Addresses", command=self.start_generate)
        self.start_gen_btn.grid(row=2, column=1, pady=10)

        # Stats
        self.processed = 0
        self.total_seeds = 0
        self.start_time = 0
        self.conn_errors = 0
        self.proj_errors = 0
        self.timeout_errors = 0
        self.queue = Queue()
        self.root.after(100, self.process_queue)

        self.proxies = []

    def log_message(self, message):
        self.queue.put(("log", message))

    def load_seeds_file(self):
        file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file:
            self.seeds_entry.delete(0, tk.END)
            self.seeds_entry.insert(0, file)

    def load_proxies_file(self):
        file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file:
            self.proxies_entry.delete(0, tk.END)
            self.proxies_entry.insert(0, file)

    def load_gen_seeds_file(self):
        file = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file:
            self.gen_seeds_entry.delete(0, tk.END)
            self.gen_seeds_entry.insert(0, file)

    def load_list(self, path_or_url):
        if path_or_url.startswith(("http://", "https://")):
            try:
                response = requests.get(path_or_url, timeout=5)
                response.raise_for_status()
                return response.text.splitlines()
            except Exception as e:
                self.log_message(f"Failed to load from URL: {e}")
                return []
        else:
            try:
                with open(path_or_url, 'r') as f:
                    return f.read().splitlines()
            except Exception as e:
                self.log_message(f"Failed to load file: {e}")
                return []

    def load_proxies_on_focus_out(self, event):
        proxies_path = self.proxies_entry.get()
        self.proxies = self.load_list(proxies_path)
        self.proxies_count_label.config(text=f"Proxies loaded: {len(self.proxies)}")

    def start_check(self):
        seeds_path = self.seeds_entry.get()
        proxies_path = self.proxies_entry.get()
        try:
            threads = int(self.threads_entry.get())
            timeout = int(self.timeout_entry.get())
            depth = int(self.depth_entry.get())
            batch_fraction = float(self.batch_entry.get())
            if not (0 < batch_fraction <= 1):
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Invalid input for threads, timeout, depth, or batch fraction")
            return

        seeds = self.load_list(seeds_path)
        self.proxies = self.load_list(proxies_path)

        if not seeds:
            messagebox.showerror("Error", "No seeds loaded")
            return

        self.total_seeds = len(seeds)
        self.processed = 0
        self.start_time = time.time()
        self.conn_errors = 0
        self.proj_errors = 0
        self.timeout_errors = 0
        self.start_check_btn.config(state='disabled')
        self.log_message("Starting check...")

        threading.Thread(target=self.run_check, args=(seeds, self.proxies, threads, timeout, depth, batch_fraction)).start()

    def run_check(self, seeds, proxies, threads, timeout, depth, batch_fraction):
        proxy_idx = [0]

        def check_seed(seed_str):
            nonlocal proxy_idx
            try:
                self.log_message(f"Checking seed: {seed_str}")
                words = seed_str.split()
                if len(words) not in [12, 15, 24]:
                    self.proj_errors += 1
                    self.log_message(f"Invalid seed length for {seed_str}")
                    return
                seed = mnemonic_to_seed(seed_str)
                networks = list({**NETWORKS, **EVM_CHAINS}.items())
                batch_size = max(1, int(len(networks) * batch_fraction))

                def process_network(item):
                    net_name, net = item
                    self.log_message(f"  Network: {net_name}")
                    try:
                        for path_template in net.get("paths", []):
                            for acc in range(depth):
                                for chg in [0, 1]:
                                    for idx in range(depth):
                                        path = path_template.format(i=acc, a=acc, c=chg, idx=idx)
                                        priv = derive_ed25519(seed, path) if net.get("ed25519") else derive_priv_key(seed, path)
                                        priv_hex = binascii.hexlify(priv).decode()
                                        pub = get_public_key(priv, net.get("ed25519"))
                                        addr = net["address_func"](pub)
                                        self.log_message(f"    Address: {addr} (path: {path})")
                                        session = requests.Session()
                                        for _ in range(len(proxies) + 1 if proxies else 1):
                                            proxy = proxies[proxy_idx[0] % len(proxies)] if proxies else None
                                            proxy_idx[0] += 1
                                            try:
                                                balance = net["balance_func"](addr, net["rpc"], proxy, timeout, session)
                                                if balance is not None:
                                                    if balance > 0:
                                                        logging.info(f"Seed: {seed_str} | Network: {net_name} | Address: {addr} | PrivateKey: {priv_hex} | Balance: {balance}")
                                                        self.log_message(f"      Positive balance: {balance}")
                                                    if "token_func" in net:
                                                        token_balance = net["token_func"](addr, net["rpc"], proxy, timeout, session)
                                                        if token_balance > 0:
                                                            logging.info(f"Seed: {seed_str} | Network: {net_name} | Address: {addr} | PrivateKey: {priv_hex} | Token Balance: {token_balance}")
                                                            self.log_message(f"      Positive token balance: {token_balance}")
                                                    if "staking_func" in net:
                                                        staking_balance = net["staking_func"](addr, net["rpc"], proxy, timeout, session)
                                                        if staking_balance > 0:
                                                            logging.info(f"Seed: {seed_str} | Network: {net_name} | Address: {addr} | PrivateKey: {priv_hex} | Staking Balance: {staking_balance}")
                                                            self.log_message(f"      Positive staking balance: {staking_balance}")
                                                    break
                                            except Timeout:
                                                self.timeout_errors += 1
                                                self.log_message("      Timeout error")
                                            except (HTTPError, RequestException) as e:
                                                if isinstance(e, HTTPError) and e.response.status_code == 429:
                                                    self.log_message("      Rate limit, retrying")
                                                    continue
                                                self.conn_errors += 1
                                                self.log_message(f"      Connection error: {e}")
                                            except Exception as e:
                                                self.proj_errors += 1
                                                self.log_message(f"      Project error: {e}")
                    except Exception as e:
                        self.proj_errors += 1
                        self.log_message(f"Error in network {net_name}: {e}")

                for i in range(0, len(networks), batch_size):
                    batch = networks[i:i + batch_size]
                    with ThreadPoolExecutor(max_workers=len(batch)) as net_executor:
                        futures = [net_executor.submit(process_network, item) for item in batch]
                        for _ in as_completed(futures):
                            pass

                self.processed += 1
                self.queue.put("update")
            except Exception as e:
                self.proj_errors += 1
                self.log_message(f"Error checking seed {seed_str}: {e}")
                self.queue.put("update")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(check_seed, seed) for seed in seeds]
            for _ in as_completed(futures):
                pass
        self.queue.put("done")

    def start_generate(self):
        seeds_path = self.gen_seeds_entry.get()
        try:
            depth = int(self.gen_depth_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid input for depth")
            return

        seeds = self.load_list(seeds_path)

        if not seeds:
            messagebox.showerror("Error", "No seeds loaded")
            return

        self.start_gen_btn.config(state='disabled')
        threading.Thread(target=self.run_generate, args=(seeds, depth)).start()

    def run_generate(self, seeds, depth):
        for seed_str in seeds:
            try:
                seed = mnemonic_to_seed(seed_str)
                for net_name, net in {**NETWORKS, **EVM_CHAINS}.items():
                    for path_template in net.get("paths", []):
                        for acc in range(depth):
                            path = path_template.format(i=acc, a=acc, c=0, idx=0)
                            priv = derive_ed25519(seed, path) if net.get("ed25519") else derive_priv_key(seed, path)
                            priv_hex = binascii.hexlify(priv).decode()
                            pub = get_public_key(priv, net.get("ed25519"))
                            addr = net["address_func"](pub)
                            self.log_message(f"{net_name} - Address: {addr} : Mnemonic: {seed_str} : PrivateKey: {priv_hex}")
            except Exception as e:
                self.log_message(f"Error generating for seed {seed_str}: {e}")
        self.queue.put("done")

    def process_queue(self):
        try:
            while not self.queue.empty():
                msg = self.queue.get_nowait()
                if msg == "update":
                    elapsed = time.time() - self.start_time if self.start_time > 0 else 1
                    speed = self.processed / elapsed if elapsed > 0 else 0
                    self.stats_label.config(text=f"Processed: {self.processed}/{self.total_seeds} | Speed: {speed:.2f}/s | Errors: {self.conn_errors} conn, {self.proj_errors} proj, {self.timeout_errors} timeout")
                    self.progress['value'] = (self.processed / self.total_seeds) * 100 if self.total_seeds > 0 else 0
                elif msg == "done":
                    self.start_check_btn.config(state='normal')
                    self.start_gen_btn.config(state='normal')
                    messagebox.showinfo("Done", "Operation completed")
                elif isinstance(msg, tuple) and msg[0] == "log":
                    self.log_text.config(state='normal')
                    self.log_text.insert(tk.END, msg[1] + "\n")
                    self.log_text.see(tk.END)
                    self.log_text.config(state='disabled')
        except:
            pass
        self.root.after(100, self.process_queue)

if __name__ == "__main__":
    app = SeedCheckerGUI()
    app.root.mainloop()