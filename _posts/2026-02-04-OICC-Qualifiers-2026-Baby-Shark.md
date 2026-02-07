---
layout: post
title: "2026 OICC Qualifiers - Baby Shark"
tags: writeups, oicc, crypto
---

<script src="https://cdn.mathjax.org/mathjax/latest/MathJax.js?config=TeX-AMS-MML_HTMLorMML" type="text/javascript"></script>

It's been a while since I've written on this blog! Since I last posted, I've gotten better at crypto challenges, and was able to solve one for the [Team Oceania](https://oceaniacc.com/) Qualifiers this year.

<br>

## The Challenge
```python
from fastecdsa import curve, ecdsa, keys
import ast, os

FLAG = os.getenv('FLAG', 'oiccflag{?????????????????????????????????????}')

p = (3<<256) - (3<<128) + 1
EC = curve.Curve("BabyShark258", p, 0, 22, p, 3, 7)
priv, pub = keys.gen_keypair(EC)

msgs = ['Baby shark', 'Doo doo doo doo doo doo']
for msg in msgs:
    print(f'{msg}: {ecdsa.sign(msg, priv, EC)}')
sig = ast.literal_eval(input('Combined signature: '))
print(all(ecdsa.verify(sig, msg, pub, EC) for msg in msgs) and FLAG)
```

<br>

First thing I notice - we aren't given the public key, but with either one of the signatures, it's possible to recover. I used some of the code from the `recover_public_keys` function in the [python ecdsa library](https://github.com/tlsfuzzer/python-ecdsa/blob/master/src/ecdsa/ecdsa.py), modified to work with the custom curve.

```python
from ecdsa import numbertheory
from hashlib import sha256

def msg_bytes(msg) -> bytes:
    if isinstance(msg, bytes):
        return msg
    elif isinstance(msg, str):
        return msg.encode()
    elif isinstance(msg, bytearray):
        return bytes(msg)

def recover_pubkey(r, s, msg):
    x = r
    e = int(sha256(msg_bytes(msg)).hexdigest(), 16)

    alpha = (pow(x, 3, p) + (a * x) + b) % p
    beta = numbertheory.square_root_mod_prime(alpha, p)
    y = beta if beta % 2 == 0 else p - beta

    # Compute the public key
    R1 = E(x, y)
    Q1 = pow(r, -1, n) * (s * R1 + (-e % n) * G)
    Pk1 = Q1

    # And the second solution
    R2 = E(x, -y)
    Q2 = pow(r, -1, n) * (s * R2 + (-e % n) * G)
    Pk2 = Q2

    return [Pk1, Pk2]
```

For both signatures, one of the valid public keys was shared, and that is the public key we need.

<br>

Second thing to notice - **this curve is anomolous!** This means that the order of the generator point is the same as the curve order, and it is possible to use Smart's Attack. This means that the points on the elliptic curve can be "lifted" to a curve defined over p-adic numbers, and you can then recover the private key. [This github page](https://github.com/elikaski/ECC_Attacks?tab=readme-ov-file#The-curve-is-anomalous) has a good example of the attack, which I used.

```python
def lift(P, E, p):
    # lift point P from old curve to a new curve
    Px, Py = map(ZZ, P.xy())
    for point in E.lift_x(Px, all=True):
         # take the matching one of the 2 points corresponding to this x on the p-adic curve
        _, y = map(ZZ, point.xy())
        if y % p == Py:
            return point

P = pubkey
E_adic = EllipticCurve(Qp(p), [a+p*13, b+p*37])
newG = p * lift(G, E_adic, p)
P = p * lift(P, E_adic, p)

# Calculate discrete log
Gx, Gy = newG.xy()
Px, Py = P.xy()
d = int(GF(p)((Px / Py) / (Gx / Gy)))
assert pubkey == d * G
```

<br>

After getting the private key, the last challenge is making a signature using a chosen value $$k$$ - instead of a random one - where $$(r, s)$$ is the same for the hashes of both messages, denoted $$z_1$$ and $$z_2$$.

<br>

As $$k=z+r\cdot d$$, when using $$k_2=k_1^{-1}$$, it is possible to force the same value of $r$ by solving for $$r$$ when $$\frac{k_1}{k_2} = \frac{z_1 + r\cdot d}{z_2 + r\cdot d}$$. After re-arranging, you find $$k_1$$ (and $$k_2$$, as it is the inverse of $$k_1$$) by lifting $$r$$ to the p-adic curve - finding $$k_1$$ the same way as the private key. With this crafted value of $$k$$, you can calculate $$s$$ as normal, and it will a valid signature for both $$z_1$$ and $$z_2$$.

<br>

```python
msgs = ["Baby shark", "Doo doo doo doo doo doo"]

z1 = int(sha256(msg_bytes(msgs[0])).hexdigest(), 16)
z2 = int(sha256(msg_bytes(msgs[1])).hexdigest(), 16)

r = -(z1 + z2) * pow(2 * d, -1, p) % p
R = E.lift_x(r)
Rx, Ry = (p * lift(R, E_adic, p)).xy()
k1 = ZZ(-(Rx / Ry) / -(Gx / Gy)) % p

r1 = (k1 * G).xy()[0] % p
s = pow(k1, -1, p) * (z1 + r1 * d) % p

print("(" + str(r1) + ", " + str(s) + ")")
```

As the signature is valid for both messages, submitting the signature to the server will result in a flag :) 

<br>
    
The full code can be found [on this gist](https://gist.github.com/numberri/23a50c2ac525a0aec24bb75c7d522f44).
