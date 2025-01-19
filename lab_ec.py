#####################################################
# COMP0061 -- Privacy Enhancing Technologies -- Lab on encryption, elliptic curves, and signatures
#
# Basics of Pycryptodome, encryption, signatures and an end-to-end encryption system.
#
# Run the tests through:
# $ pytest -v
from typing import NamedTuple, Optional


#####################################################
# TASK 1 -- Ensure libraries are installed on the system.
#           Ensure the lab code can be imported.

import Cryptodome

#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM
#           (Galois Counter Mode)
#
# Implement encryption and decryption functions
# that simply performs AES_GCM symmetric encryption
# and decryption using the functions in `Cryptodome.Cipher`.

from os import urandom

from Cryptodome.Cipher import AES

SymKey = bytes
Message = bytes
Nonce = bytes
CipherText = bytes
Tag = bytes
AuthEncryption = tuple[Nonce, CipherText, Tag]


def encrypt_message(key: SymKey, message: Message) -> AuthEncryption:
    """Encrypt a message under a key given as input"""

    nonce = urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    return nonce, ciphertext, tag


def decrypt_message(key: SymKey, auth_ciphertext: AuthEncryption) -> Message:
    """Decrypt a cipher text under a key given as input

    In case the decryption fails, throw an exception.
    """
    try:
        nonce, ciphertext, tag = auth_ciphertext
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except Exception as e:
        print("Decryption failed:", e)
        raise
    


#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic
#           - Test if a point is on a curve.
#           - Implement Point addition.
#           - Implement Point doubling.
#           - Implement Scalar multiplication (double & add).
#           - Implement Scalar multiplication (Montgomery ladder).
#

from Cryptodome.Math.Numbers import Integer

Point = NamedTuple("Point", [("x", Optional[Integer]), ("y", Optional[Integer])])


def is_point_on_curve(a: Integer, b: Integer, p: Integer, point: Point) -> bool:
    """
    Check that a point (x, y) is on the curve defined by a,b and prime p.
    Reminder: an Elliptic Curve on a prime field p is defined as:

              y^2 = x^3 + ax + b (mod p)
                  (Weierstrass form)

    Return True if point (x,y) is on curve, otherwise False.
    By convention a (None, None) point represents "infinity".
    """
    x, y = point

    if x is None and y is None:
        return True

    lhs = (y * y) % p
    rhs = (x * x * x + a * x + b) % p
    on_curve = lhs == rhs

    return on_curve


def point_add(a: Integer, b: Integer, p: Integer, point0: Point, point1: Point) -> Point:
    """Define the "addition" operation for 2 EC Points.

    Reminder: (xr, yr) = (xq, yq) + (xp, yp)
    is defined as:
        lam = (yq - yp) * (xq - xp)^-1 (mod p)
        xr  = lam^2 - xp - xq (mod p)
        yr  = lam * (xp - xr) - yp (mod p)

    Return the point resulting from the addition by
    implementing the above pseudocode.
    Raises an Exception if the points are equal.
    Make sure you can handle the case where one point is the negation
    of the other: (xq, yq) == -(xp, yp) == (xp, -yp).
    """

    xr, yr = None, None
    xp, yp = point0
    xq, yq = point1

    
    # special cases: 

    # one point being inf:
    if xp is None and yp is None:
        return point1    
    if xq is None and yq is None:
        return point0

    # raise exception for (xp, yq) == (xq, yq):
    if point0 == point1:
        raise Exception("EC Points must not be equal")
    
    # one point being the other's negation:
    if (xp == xq) and (yp == (p - yq)):
        return Point(None, None)
    

    xminus = (p + xq - xp) % p # xminus = (xq - xp) mod p
    xinv = Integer(xminus).inverse(p)
    lam = ((yq - yp) * xinv) % p
    xr  = (lam**2 - xp - xq) % p
    yr  = (lam * (xp - xr) - yp) % p

    return Point(xr, yr)


def point_double(a: Integer, b: Integer, p: Integer, point: Point) -> Point:
    """Define "doubling" an EC point.
     A special case, when a point needs to be added to itself.

     Reminder:
        lam = (3 * xp ^ 2 + a) * (2 * yp) ^ -1 (mod p)
        xr  = lam ^ 2 - 2 * xp
        yr  = lam * (xp - xr) - yp (mod p)

    Returns the point representing the double of the input (x, y).
    """

    xr, yr = None, None
    xp, yp = point

    # special case: when point is None
    if xp is None and yp is None:
        return point

    y2 = (Integer(2)*yp) % p
    yinv = y2.inverse(p)
    lam = ((Integer(3) * xp**2 + a) * yinv) % p
    xr  = (lam**2 - Integer(2) * xp) % p
    yr  = (lam * (xp - xr) - yp) % p

    return Point(xr, yr)


def point_scalar_multiplication_double_and_add(a: Integer, b: Integer, p: Integer, point: Point, scalar: Integer) -> Point:
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        Q = infinity
        for i = 0 to num_bits(r)-1
            if bit i of r == 1 then
                Q = Q + P
            P = 2 * P
        return Q

    """

    result = Point(None, None)

    for i in range(scalar.size_in_bits()):
        if (scalar >> i) & Integer(1) == Integer(1): 
            result = point_add(a=a, b=b, p=p, point0=result, point1=point)
        point = point_double(a=a, b=b, p=p, point=point)

    return result


def point_scalar_multiplication_montgomerry_ladder(a: Integer, b: Integer, p: Integer, point: Point, scalar: Integer) -> Point:
    """
    Implement Point multiplication with a scalar:
        r * (x, y) = (x, y) + ... + (x, y)    (r times)

    Reminder of Double and Multiply algorithm: r * P
        R0 = infinity
        R1 = P
        for i in num_bits(P)-1 to zero:
            if di = 0:
                R1 = R0 + R1
                R0 = 2R0
            else
                R0 = R0 + R1
                R1 = 2 R1
        return R0

    """
    res0 = Point(None, None)
    res1 = point

    for i in reversed(range(0, scalar.size_in_bits())):
        if (scalar >> i) & Integer(1) == Integer(0):
            res0_new = point_double(a=a, b=b, p=p, point=res0)
            res1_new = point_add(a=a, b=b, p=p, point0=res0, point1=res1)
            res0 = res0_new
            res1 = res1_new
        else:
            res0_new = point_add(a=a, b=b, p=p, point0=res0, point1=res1)
            res1_new = point_double(a=a, b=b, p=p, point=res1)
            res0 = res0_new
            res1 = res1_new

    return res0


#####################################################
# TASK 4 -- Standard ECDSA signatures
#
#          - Implement a key / param generation
#          - Implement ECDSA signature using `Cryptodome.Signature.DSS`
#          - Implement ECDSA signature verification using `Cryptodome.Signature.DSS`

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC, _point, _curve
from Cryptodome.Signature import DSS

curves = _point._curves
Curve = _curve._Curve

PrivSignKey = ECC.EccKey
PubVerifyKey = ECC.EccKey
Signature = bytes


def ecdsa_key_gen() -> tuple[PrivSignKey, PubVerifyKey]:
    """Returns an EC group, a random private key for signing
    and the corresponding public key for verification"""
    key_sign = ECC.generate(curve="secp224r1")
    return key_sign, key_sign.public_key()


def ecdsa_sign(priv_sign: PrivSignKey, message: Message) -> Signature:
    """Sign the SHA256 digest of the message using ECDSA and return a signature"""
    h = SHA256.new(message)
    signer = DSS.new(priv_sign, mode='fips-186-3')
    signature = signer.sign(h)

    return signature


def ecdsa_verify(pub_verify: PubVerifyKey, message: Message, sig: Signature) -> bool:
    """Verify the ECDSA signature on the message"""
    h = SHA256.new(message)
    verifier = DSS.new(pub_verify, mode='fips-186-3')
    try:
        verifier.verify(h, sig)
        print("The message is authentic.")
    except ValueError:
        print("The message is not authentic.")
        raise


#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation
#           - use Bob's public key to derive a shared key.
#           - Use Bob's public key to encrypt a message.
#           - Use Bob's private key to decrypt the message.

PrivDHKey = Integer
PubDHKey = ECC.EccPoint


def _point_to_bytes(p: ECC.EccPoint) -> bytes:
    x, y = p.xy
    return x.to_bytes() + y.to_bytes()


def dh_get_key() -> tuple[Curve, PrivDHKey, PubDHKey]:
    """Generate a DH key pair"""
    group = curves["secp224r1"]
    priv_dec = Integer.random_range(min_inclusive=1, max_exclusive=group.order)
    pub_enc = priv_dec * group.G
    return group, priv_dec, pub_enc


def dh_encrypt(pub: PubDHKey, message: Message, alice_sig: PrivSignKey) -> tuple[PubDHKey, AuthEncryption, Signature]:
    """Assume you know the public key of someone else (Bob),
    and wish to Encrypt a message for them.
        - Generate a fresh DH key for this message.
        - Derive a fresh shared key.
        - Use the shared key to generate a symmetric key
        - Use the symmetric key to AES_GCM encrypt the message.
        - Sign the message with Alice's signing key.
    """

    # generate priv using _point_to_bytes() and random generator
    # group, priv_dec, pub_enc = dh_get_key(priv)
    pass


def dh_decrypt(priv: PrivDHKey, fresh_pub: PubDHKey, auth_ciphertext: AuthEncryption, sig: Signature, alice_ver: PubVerifyKey) -> Message:
    """Decrypt a received message encrypted using your public key,
    of which the private key is provided.
    Verify the message came from Alice using her verification
    key."""

    # TODO: ADD YOUR CODE HERE
    ...
    pass


# TODO: POPULATE THESE (OR MORE) TESTS
# Pytest assumes any function that starts with `test_` is a test.
# To create additional tests, add more functions below the given stubs
# and mark them as being part of task5.
# Ensure they run using the "pytest lab_ec.py" command.


import pytest
from pytest import raises


@pytest.mark.task5
def test_encrypt():
    _, _, bob_pub_enc = dh_get_key()
    alice_sign, _ = ecdsa_key_gen()
    ...
    assert False


@pytest.mark.task5
def test_decrypt():
    _, bob_priv_enc, bob_pub_enc = dh_get_key()
    alice_sign, alice_ver = ecdsa_key_gen()
    ...
    assert False


@pytest.mark.task5
def test_fails_decryption_wrong_ciphertext_nonce():
    ...
    with raises(Exception) as excinfo:
        dh_decrypt(...)
    assert "MAC check failed" in str(excinfo.value)


@pytest.mark.task5
def test_fails_decryption_wrong_ciphertext_tag():
    ...
    with raises(Exception) as excinfo:
        dh_decrypt(...)
    assert "MAC check failed" in str(excinfo.value)


@pytest.mark.task5
def test_fails_signature_verification():
    ...
    with raises(Exception) as excinfo:
        dh_decrypt(...)
    assert "The signature is not authentic" in str(excinfo.value)


"""
Run the tests with test coverage:
$ pytest --cov-report html --cov lab_ec

If you implemented task 5, your coverage should be 100%. If it's not, where is it missing cases?

Why is coverage important for tests, especially with cryptography?
Is high coverage enough to ensure high quality cryptographic software?

TODO: ADD YOUR ANSWER HERE
"""


#####################################################
# TASK 6 -- Time EC scalar multiplication
#             Open Task.
#
#           - Time your implementations of scalar multiplication
#             (use time.perf_counter_ns() for measurements) for
#             different scalar sizes
#           - Print reports on timing dependencies on secrets.
#           - Fix one implementation to not leak information.


def time_scalar_mul():  # pragma: no cover
    # TODO: ADD YOUR CODE HERE
    pass
