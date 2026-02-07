---
layout: post
title: "CrikeyCon 2025 - I CHOOSE YOU"
tags: writeups, crikeycon, crypto
---

```
Category: Crypto
Points: 100
Solves: 3
```
<br>

***Prove you are timk:***

<br>

*I've chosen a Pokemon and encrypted it using timk's public key.*

*To prove you are timk, use your private key to decrypt the ciphertext which will tell you the Pokemon to select.*

*I know timk has lots of keypairs so I've supplied the public key for him to know which private key to use.*

<br>

*To ensure things stay safe, I'll rotate the Pokemon and key every 5 minutes.*

*Don't bother trying to guess as I will block you for 30 seconds on an incorrect attempt!*

<br>

# The go plan - and where I mess things up

Upon inspecting the website, this comment is also revealed:

```html
<!-- TODO: Look into newer padding schemes. For now I have just padded PT to the key size using leading null bytes, but it should be pretty solid. -->
 ```

<br>

Pretty solid... of an attack strategy :)

<br>

The TL;DR of what needs to be done is:
- Take the public key provided and the list of all 808 Pokemon.
- Pad the Pokemon with leading null bytes, and then encrypt that string with the public key provided.
- Compare this ciphertext with the encrypted Pokemon provided. If you find a match, then you have the Pokemon!

<br>

Pretty easy! First problem I run into... parsing the .pem key to an RSA public key. I opt to pass this to openssl:

```python
def pad_with_null_bytes(pokemon):
    max_data_size = 244 # This was first done by trial and error...
    # I found out there was a reason why this was 244 and not 256 later, which was why my code was failing. :P
    padding_length = max_data_size - len(pokemon)
    padded = b"\x00" * padding_length + pokemon
    return padded

with open('character.enc', 'rb') as file:
    encrypted_solution = file.read().strip()

pokemon = open("pokemon_list.txt", "r")

for p in pokemon:
    p = pad_with_null_bytes(p.strip())
    with open('current.txt', 'w') as current:
        current.write(p)
    
    os.system('cat current.txt | openssl pkeyutl -encrypt -pubin -inkey public.pem > text.enc')
    # This was a lot messier and had full paths, but I'm shortening it for privacy and to make it easier to read

    with open('text.enc', 'rb') as c:
        pokemon_encrypted = c.read()

    if pokemon_encrypted == encrypted_solution:
        print(p)

```

<br>

Great! Code to encrypt Pokemon done! And yet... I wasn't getting any matches.

<br>

# A bit of hindsight, and more mistakes
I think that a common theme of write-ups on this blog so far has been "I spend too long barking up the wrong tree, and I should have figured out what was going on earlier". 

<br>

What was actually happening was I was double-padding the text! Most libraries that encrypt things using RSA public keys hope that you use sane and secure padding, which is fantastic for IRL implementations, however for this CTF challenge it wasn't what I wanted.

<br>

This is also why I couldn't encrypt things when the plaintext was longer than 244 bytes, instead of the 256 byte key length I expected - it's because of PKCS#1 v1.5 padding overhead.

<br>

I unfortunately didn't realize this, and spent more time writing incorrect code, and a LOT of time debugging it.

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def load_public_key(pem_path):
    with open(pem_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())
    # It was good to find a library that let me load a public key in Python, but for future reference I should understand it more before using it. :)

def pad_with_null_bytes(pokemon):
    max_data_size = 244
    padding_length = max_data_size - len(pokemon)
    padded = b"\x00" * padding_length + pokemon
    return padded

def encrypt_pokemon(public_key, pokemon):
    key_size = public_key.key_size // 8  
    # Converting the RSA key size from bits to bytes.
    padded = pad_with_null_bytes(pokemon)

    encrypted = public_key.encrypt(
        padded,
        padding.PKCS1v15()
        # I definitely knew that it was double padding at this point, but I didn't know how the library worked so trying to not pad this threw errors.
        # At some point, I even had the comment of "how do I get rid of this shit"...
    )
    return encrypted

pubkey = load_public_key("public.pem")

with open('character.enc', 'rb') as file:
    encrypted_solution = file.read().strip()
pokemon = open("pokemon_list.txt", "r")

for p in pokemon:
    p = pad_with_null_bytes(p.strip())
    pokemon_encrypted = encrypt_pokemon(pubkey, p.encode())
    if pokemon_encrypted == encrypted_solution:
        print(p)
```

<br>

# The solution, finally
Partially because I was running around the con and talking to people as well as doing the CTF, I only got the solution 10 minutes before the CTF ended.

```python
from cryptography.hazmat.primitives import serialization

def load_public_key(pem_path):
    with open(pem_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def encrypt_pokemon(public_key, pokemon):
    key_size = public_key.key_size // 8
    # Converting the RSA key size from bits to bytes.
    encrypted = public_key.public_numbers().n.to_bytes(key_size, 'big')
    encrypted = pow(int.from_bytes(pokemon, 'big'), public_key.public_numbers().e, public_key.public_numbers().n)
    return encrypted.to_bytes(key_size, 'big')

pubkey = load_public_key("i_choose_you/public.pem")

with open('i_choose_you/character.enc', 'rb') as file:
    encrypted_solution = file.read().strip()
pokemon = open("i_choose_you/pokemon_list.txt", "r")

for p in pokemon:
    p = p.strip()
    tst = encrypt_pokemon(pubkey, p.encode())
    if tst == encrypted_solution:
        print(p)
```

<br>

And then...

<br>

```
# python3 ./final.py
Chimecho
```

<br>

Finally! I'm able to submit the Pokemon with 10 minutes left in the CTF.

<br>

```
Well done! flag{                  }
```

<br>

# Finishing notes and self reflection
I actually wasn't planning on taking part in this CTF, however I got a text from one of the members from my uni society asking me to join the team as they need someone who understands crypto. I know I've always said that crypto doesn't like me, but it turns out that kind of half understanding crypto is a pretty high bar. We ended up coming third in the CTF as well, which is incredible!

<br>

On the flip side, I ended up meeting the crypto player of the winning team, as well. He ended up getting over half the points for his team, and he was pretty incredible.... I may have gotten a bit of a case of impostor syndrome after the CTF. I think that this is definitely going to encourage me to work harder on training for CTFs in the future, although this motivation may be killed by university work in the near future.

(also, you should check this guy out. [he's pretty cool](https://jsur.in/).)
 
<br>

Overall, I think that what I need to get better at is being able to script well, and knowing the libraries and ins and outs of the tools I use for CTFs. Unfortunately this is something where the solution is "just play more", but I think that's life.
