from flask import Flask, render_template
from pycoin.symbols.btc import network
import math
import random

app = Flask(__name__)

MAX_EXPONENT = 115792089237316195423570985008687907852837564279074904382605163141518161494336
KEYS_PER_PAGE = 127

def max_pages():
    m = MAX_EXPONENT // (KEYS_PER_PAGE + 1)
    return m if MAX_EXPONENT % (KEYS_PER_PAGE + 1) == 0 else m + 1

def page_range(page_num):
    from_sec = (page_num - 1) * (KEYS_PER_PAGE + 1)
    to_sec = from_sec + KEYS_PER_PAGE
    if to_sec > MAX_EXPONENT:
        to_sec = MAX_EXPONENT
    return range(from_sec + 1, to_sec + 1)

def secret_to_address(secret_exponent):
    if not isinstance(secret_exponent, int) or secret_exponent <= 0 or secret_exponent >= MAX_EXPONENT:
        return None

    try:
        # Uncompressed key
        key_uncompressed = network.keys.private(secret_exponent)
        key_uncompressed._is_compressed = False
        addr = key_uncompressed.address()
        wif = key_uncompressed.wif()

        # Compressed key
        key_compressed = network.keys.private(secret_exponent)
        key_compressed._is_compressed = True
        caddr = key_compressed.address()

        return secret_exponent, wif, addr, caddr
    except Exception as e:
        print(f"Error processing secret_exponent {secret_exponent}: {e}")
        return None

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
    result = secret_to_address(sec_exp)
    if result:
        _, priv, addr, _ = result
        return f'{priv} {addr}'
    return 'Key generation failed'

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', code=404, error='File not found'), 404
