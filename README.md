# Key Recovery Attacks on RC4
This repo includes a key recovery attack against a mock encryption scheme I've called RC4-CTR. This scheme builds a block cipher using poorly borrowed ideas from AES's counter mode, and in doing so, introduces a key recovery attack. The attack is similar to the WEP attack used by tools such as aircrack-ng but the initialisation vector is placed before the long term key.

This is a chosen-plaintext attack that recovers the private key in around 100,000 blocks. It works when ephemeral keys are generated by concatenating a public nonce before the long-term key (ala Section 4.3 in ["Attacks on the RC4 stream cipher"](https://engineering.purdue.edu/ece404/Resources/AndreasKlein.pdf) by Andreas Klein). And should be generalisable to similar constructions. 

 - [`server.py`](./server.py) implements the encryption scheme, exposed via an API endpoint. Check the docstring and source code for a description of the scheme. 
 - [`solve.py`](./solve.py) implements the attack. Check the docstring and source code for details on how the attack works.
 
This was written as a learning exercise, and I've tried to document how and why it works (up to the limit of inline code comments). Hopefully the attack code is a useful accompaniment to the [original paper](https://engineering.purdue.edu/ece404/Resources/AndreasKlein.pdf).

There is a live version of the server on my website. You can extract it's key by running:
```
$ python3 solve.py --cache=samples-djwj.csv --server=https://danielwilshirejones.com
```
