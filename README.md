# RC4 Key Recovery Attacks
This repo includes a key recovery attack against a mock encryption scheme I've called RC4-CTR. This scheme builds a block cipher using poorly borrowed ideas from AES's counter mode, and in doing so, introduces a key recovery attack. The attack is similar to the WEP attack used by tools such as aircrack-ng but the initialisation vector is placed before the long term key.

This is a chosen-plaintext attack that recovers the private key in around 100,000 blocks. It works when ephemeral keys are generated by concatenating a public nonce before the long-term key (ala Section 4.3 in ["Attacks on the RC4 stream cipher"](https://engineering.purdue.edu/ece404/Resources/AndreasKlein.pdf) by Andreas Klein). And should be generalisable to similar constructions. 

See [`solve.py`](./solve.py) for more information on how it works. This was written as a learning exercise, and I've tried to document how and why it works (up to the limit of inline code comments).

This repo currently only contains the attack implementation. I'm planning on creating an oracle server to let people mount this attack against something real. In the meantime, the `test_key` function could be used to build an oracle. I'll add a link when the server is up, and add it'ssource to this repo.
