"""

server.py
=========
An HTTP server that exposes an "encrypt" endpoint. This endpoint uses
buggy encryption scheme based on RC4 that is vulnerable to key
recovery attacks. See "About:" for more details, and solve.py for the
attack code.

Usage:
  server.py [--hostname=<url>] [--port=<int>] [--key_size=<int>] [--counter_size=<int>] [--nonce_size=<int>] [--block_size=<int>] [--debug]
  server.py (-h | --help)

Options:
  -h --help             Show this screen.
  --hostname=<str>      URL of server to attack [default: localhost].
  --port=<int>          URL of server to attack [default: 5000].
  --key_size=<int>      Size of key in bytes [default: 13].
  --counter_size=<int>  Size of block counter in bytes [default: 3].
  --nonce_size=<int>    Size of per-session nonce in bytes [default: 16].
  --block_size=<int>    Size of each block in bytes [default: 48].
  --debug               Sets the server to run in debug mode [default: false].

Environment Variables:
  RC4_KEY              This should contain a <key_size> length string
                       that acts as the long term key for this server
                       [required].

Example:
  server.py --port=8888 --debug
  server.py --block_size=16
  RC4_KEY=TOPSECRETINFO server.py --block_size=16

About:
  This is an HTTP server implementing an encryption oracle on the
  /rc4-ctr/encrypt endpoint. It uses a made-up scheme I've called
  RC4-CTR, that poorly borrows ideas from AESs counter mode to
  implement a block cipher from the RC4 key stream. The scheme works
  as follows:
    - There is a long-term key of 13 bytes, named `key`.
    - Communications are split into sessions which use a public nonce
      of 16 random bytes (referred to as `nonce`).
    - Each session is split into many blocks, identified by an
       unsigned, little endian, 3 byte integer (referred to as
       `counter`).
    - A per-block key is derived via `nonce || counter || key`.
    - This per-block key is fed into RC4 to generate a block sized
      keystream; ready to XORed against the plaintext.

  Python pseudo-code to summarise (see the encrypt() fn)

    def encrypt_block(nonce, counter, key, plaintext):
      block_key = nonce || counter || key
      keystream = RC4(key, length=len(plaintext))
      ciphertext = keystream ⊕ plaintext
      return ciphertext

  This server exposes to an HTTP API that works as an encryption
  oracle. You can give it the parameters of the above function via a
  GET call to:

    /rc4-ctr/encrypt/<nonce>/<counter>/<plaintext>

  where <nonce> and <plaintext> are hex strings, while counter is a
  non-negative integer. An example call might be:

    GET /rc4-ctr/encrypt/710790b2e53bbe3f4da853d64fb513b9/0/3c05a07f9a332132b3...6e0aa1

  The body of the response will be the encrypted block.

  This endpoint acts as an oracle for a chosen-plaintext attack, which
  solve.py uses to recover the private key.

"""
import logging
import docopt
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from flask import Flask


RC4_KEY = os.getenv("RC4_KEY")
if isinstance(RC4_KEY, str):
    RC4_KEY = bytes(RC4_KEY, "utf-8")

KEYSIZE = 13
COUNTERSIZE = 3
NONCESIZE = 16
BLOCKSIZE = 48


URL_PREFIX = "/rc4-ctr"


# HTTP Server ---------------------------------------------------------------- #
app = Flask(__name__)


@app.route(URL_PREFIX + "/encrypt/<nonce>/<counter>/<data>")
def encrypt(nonce, counter, data):
    try:
        nonce = bytes.fromhex(nonce)
        assert len(nonce) == NONCESIZE

        counter = int(counter)
        assert counter >= 0

        counter = counter.to_bytes(length=COUNTERSIZE, byteorder="little", signed=False)

        data = bytes.fromhex(data)
        assert len(data) == BLOCKSIZE

    except Exception as e:
        logging.error("Failed to validate inputs", exc_info=e)
        return "Failed to validate inputs."

    block_key = nonce + counter + RC4_KEY

    cipher = Cipher(
        algorithm=algorithms.ARC4(block_key), mode=None, backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext_bytes = encryptor.update(data)

    return ciphertext_bytes.hex()



if __name__ == "__main__":
    args = docopt.docopt(__doc__)

    KEYSIZE = int(args["--key_size"])
    COUNTERSIZE = int(args["--counter_size"])
    NONCESIZE = int(args["--nonce_size"])
    BLOCKSIZE = int(args["--block_size"])

    if not isinstance(RC4_KEY, bytes):
        logging.error("The RC4_KEY environment variable must be set.")
        quit()

    app.run(debug=args["--debug"], host=args["--hostname"], port=args["--port"])
