from flask import Flask, render_template, request
from pycoin.symbols.btc import network
import random
import os
import hashlib
import base58
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

MAX_EXPONENT = 115792089237316195423570985008687907852837564279074904382605163141518161494336
KEYS_PER_PAGE = 127

# Search config — tuned for Render free tier (512MB RAM, shared CPU)
SEARCH_LIMIT = 500_000       # keys scanned per search request
MAX_WORKERS  = 8             # parallel threads (keep low to avoid OOM)
CHUNK_SIZE   = 500           # keys per thread chunk

# ---------------------------------------------------------------------------
# Fast address derivation using raw secp256k1 via coincurve (no pycoin overhead)
# Falls back to pycoin if coincurve is unavailable.
# ---------------------------------------------------------------------------
try:
    import coincurve
    import hashlib

    _G = coincurve.PublicKey.from_secret(b'\x00' * 31 + b'\x01')  # warm up

    def _pubkey_bytes(secret_exponent, compressed):
        sec_bytes = secret_exponent.to_bytes(32, 'big')
        pub = coincurve.PublicKey.from_secret(sec_bytes)
        return pub.format(compressed=compressed)

    def _pub_to_address(pub_bytes):
        sha256 = hashlib.sha256(pub_bytes).digest()
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        payload = b'\x00' + ripemd160
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return base58.b58encode(payload + checksum).decode()

    def secret_to_address(secret_exponent):
        if not isinstance(secret_exponent, int) or secret_exponent <= 0 or secret_exponent >= MAX_EXPONENT:
            return None
        try:
            sec_bytes = secret_exponent.to_bytes(32, 'big')
            pub_u = coincurve.PublicKey.from_secret(sec_bytes).format(compressed=False)
            pub_c = coincurve.PublicKey.from_secret(sec_bytes).format(compressed=True)
            addr   = _pub_to_address(pub_u)
            caddr  = _pub_to_address(pub_c)
            # WIF (uncompressed)
            wif_payload = b'\x80' + sec_bytes
            wif_check   = hashlib.sha256(hashlib.sha256(wif_payload).digest()).digest()[:4]
            wif = base58.b58encode(wif_payload + wif_check).decode()
            return secret_exponent, wif, addr, caddr
        except Exception as e:
            print(f"[coincurve] Error at {secret_exponent}: {e}")
            return None

    USING_COINCURVE = True

except ImportError:
    # Fallback: pycoin (slower but always available)
    USING_COINCURVE = False

    def secret_to_address(secret_exponent):
        if not isinstance(secret_exponent, int) or secret_exponent <= 0 or secret_exponent >= MAX_EXPONENT:
            return None
        try:
            key_u = network.keys.private(secret_exponent)
            key_u._is_compressed = False
            addr = key_u.address()
            wif  = key_u.wif()
            key_c = network.keys.private(secret_exponent)
            key_c._is_compressed = True
            caddr = key_c.address()
            return secret_exponent, wif, addr, caddr
        except Exception as e:
            print(f"[pycoin] Error at {secret_exponent}: {e}")
            return None


# ---------------------------------------------------------------------------
# Page helpers (unchanged from original)
# ---------------------------------------------------------------------------
def max_pages():
    m = MAX_EXPONENT // (KEYS_PER_PAGE + 1)
    return m if MAX_EXPONENT % (KEYS_PER_PAGE + 1) == 0 else m + 1

def page_range(page_num):
    from_sec = (page_num - 1) * (KEYS_PER_PAGE + 1)
    to_sec   = from_sec + KEYS_PER_PAGE
    if to_sec > MAX_EXPONENT:
        to_sec = MAX_EXPONENT
    return range(from_sec + 1, to_sec + 1)


# ---------------------------------------------------------------------------
# Parallel search helper
# ---------------------------------------------------------------------------
def _search_chunk(start, end, target_address):
    """Search keys [start, end) and return matching result or None."""
    for i in range(start, end):
        result = secret_to_address(i)
        if result:
            sec, wif, addr, caddr = result
            if target_address in (addr, caddr):
                return result
    return None


def parallel_search(address, search_limit=SEARCH_LIMIT, max_workers=MAX_WORKERS, chunk_size=CHUNK_SIZE):
    """
    Search keys 1..search_limit in parallel chunks.
    Returns (result, keys_checked) where result is None if not found.
    """
    chunks = [
        (start, min(start + chunk_size, search_limit + 1))
        for start in range(1, search_limit + 1, chunk_size)
    ]

    found = None
    keys_checked = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_search_chunk, s, e, address): (s, e) for s, e in chunks}
        for future in as_completed(futures):
            s, e = futures[future]
            keys_checked += (e - s)
            try:
                result = future.result()
                if result and found is None:
                    found = result
                    # Cancel remaining futures (best-effort)
                    for f in futures:
                        f.cancel()
            except Exception as ex:
                print(f"Chunk {s}-{e} error: {ex}")

    return found, keys_checked


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route('/')
def hello_world():
    return render_template('home.html')


@app.route('/key/<int:secret_exponent>')
def show_address(secret_exponent):
    if secret_exponent < 1 or secret_exponent > MAX_EXPONENT:
        return render_template('error.html', error=f'Invalid Key, not in range 1–{MAX_EXPONENT}')
    result = secret_to_address(secret_exponent)
    if not result:
        return render_template('error.html', error='Key generation failed')
    sec, wif, addr, caddr = result
    return render_template('key.html', sec=sec, compressed_addr=caddr, addr=addr, private_key=wif)


@app.route('/key/')
@app.route('/key/<string:foo>')
def default_key(foo=1):
    return render_template('error.html', error='Invalid Key')


@app.route('/page/<int:page_num>')
def show_page(page_num):
    max_p = max_pages()
    if page_num < 1:
        page_num = 1
    if page_num > max_p:
        page_num = max_p
    p = [secret_to_address(i) for i in page_range(page_num)]
    p = [entry for entry in p if entry]
    return render_template('page.html', page=page_num, page_elements=p, max_pages=max_p)


@app.route('/page/')
@app.route('/page/<string:foo>')
def default_page(foo=1):
    return show_page(1)


@app.route('/lottery')
def lottery():
    return render_template('lottery.html')


@app.route('/gen_pair')
def gen_pair():
    sec_exp = random.randint(1, MAX_EXPONENT)
    result  = secret_to_address(sec_exp)
    if result:
        _, priv, addr, _ = result
        return f'{priv} {addr}'
    return 'Key generation failed'


@app.route('/search')
def search():
    address = request.args.get('address', '').strip()
    if not address:
        return render_template('error.html', error='Please provide an address to search')

    result, keys_checked = parallel_search(address)

    search_results = [result] if result else []
    return render_template(
        'search_results.html',
        address=address,
        results=search_results,
        searched_range=keys_checked,
    )


@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', code=404, error='File not found'), 404


# --------------------------
# ENTRY POINT FOR RENDER.COM
# --------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
