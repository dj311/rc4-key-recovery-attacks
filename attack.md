# Klein's RC4 Key Recovery Attack

*Be warned,* this document is a work-in-progressa and probably contains
a bunch of incorrect information.

How does this attack work? The RC4 algorithm is relatively simple
and easy to follow. If you reduce the size of the initial state from
256 to say 16 bytes, it can be stepped through with a pen and
paper. This is definitely worth doing if you want to get a good
intuitive understanding of how the internal state develops as a
function of its inputs.

Boneh and Shoup's "A Graduate Course in Cryptography" provides a
great explanation. Skip to [page 90](https://toc.cryptobook.us/book.pdf#page=90).

This simplicity makes it practical for us to inspect and model the
algorithms behavior in hypothetical situations. We can say things
like:

  - If the key is one single repeated unknown value, what will the
    internal state look like at the end of the key scheduling stage?
    Can we write this state as a function of that unkown value?
  - If we know the final `x` bytes of the key, can we learn anything
    about the internal state at the end of the key scheduling stage?
    This is what Klein's attack on WEP starts with.
  - If we know the first `x` bytes of the key, can we learn anything
    about the internal state at the end of the key scheduling stage?
    This is what our attack starts with.

As part of this analysis you could model direct relationships: what can we
know for certain? However, the purpose of RC4 (and other stream
ciphers), is to take in ordered inputs and scramble them to create
randomness. So this approach is pretty hard, by design.

An alternative approach is to look at this from a probability
standpoint. For example, given the keys first byte is 123, what is
the likelihood the first output byte of the cipher is 123? An ideal
cipher would have a uniform distribution for all output bytes. Can
we do better using our understanding of the algorithm? It turns out
in the example I just gave, you totally 100% can! This is a slight
aside to the attack we are looking at today, but it was shown TODO.

This attack starts with the following assumptions:

  - Each encryption operation uses a fresh key, in the form:
      `session_nonce || counter || long_term_key`
    where `session_nonce` is a public, random set of bytes,
      `counter` is a public counter, incremented after each encryption,
      and `long_term_key` is the private key we want to find out.
    Essentially, `fresh_key` = `bytes_we_know || bytes_we_want_to_know`
  - Cont.

We know the first `num_known_bytes` of the key, so we can
step through the first `num_known_bytes` iteratons of RC4s
key scheduling algorithm (KSA):

Consider the next iteration of the KSA in Python pseudo-code:

```
  i'= i + 1
  j' = (j + S[i'] + unknown_key_byte) % 256
  S'[i], S'[j] = S[j'], S[i']
```

Considering modifications `S'[i]` only, we can summarise the above
code as:
```
  S'[i] = S[j + S[i'] + unknown_key_byte % 256]
```

where `i  = num_known_bytes - 1`
  and `i' = num_known_bytes`.

And we also have concrete values for `S` and `j`. The only
unknowns are `S'[i]` and `unknown_key_byte` (I refer to
`S'[i]` as `next_S_i` in the code from now on).

The paper shows that the probability `next_S_i` doesn't
change during the rest of the KSA is
`((n-1)/n)^(n-num_known_bytes)`. Further, the
probability that `next_S_i` isn't modified in the first
`num_known_bytes` iterations of the keystream generation,
similarly, `((n-1)/n)^num_known_bytes`. Combining these
two tells us that `next_S_i` should still be unchanged at
`num_known_bytes`th iteration of the PRNG with prob
`((n-1)/n)^n ~= 1/e ~= 0.367)`.

So, we have a relation between `S'[i]` and
`unknown_key_byte` for which they are the only unknowns.
And we know that around a third of the time, `S[i]` still
equals `S'[i]` (`next_S_i`) at the `num_known_bytes`th
iteration of the PRNG.

Next, theorem 1 in the paper gives us a probabilistic
relation between the `num_known_bytes`th output of the
PRNG and the value of `S[i]` during that iteration.

(Note that this `S[i]` is equal to `S'[i]` (`next_S_i`) about
a third of the time, and that the `i` we are talking about
is `num_known_bytes`. I.e. these are
`num_known_bytes+1`th value inside `S` at the time).

The paper combines these two relations to show that

```
Prob(next_S_i == num_known_bytes - num_known_bytes-th output_byte)
    ~= 1.36/n
```

This means ... that the `output_byte` that shows up
1.36/256 of the time is the one in the case where `S[i]`
is unchanged from `next_S_i`. And so we can find that
`output_byte`, calculate `next_S_i`, then reverse the
relation from earlier to find an implied value for
`unknown_key_byte`! Cool stuff.

For now we collect candidate `key_bytes`, using candidate
`next_S_i`s derived from candidate `output_bytes`. When
we've taken a bunch of samples, we'll figure out which
one shows up 1.36/n of the time.

Now we've got a bunch of candidate values for our unknown
key byte. Which one occurs `1.36/n = 1.36/256` of the time?
Well, there are `n-1 = 255` other potential values, and we can
assume the rest are all uniformly distributed.  Then all the
other possible values will occur less than `1.36/n` of the
time.
