#####################################################
# COMP0061 -- Privacy Enhancing Technologies -- Lab on encryption, elliptic curves, and signatures
#
# Basics of Pycryptodome, encryption, signatures and an end-to-end encryption system.
#
# Run the tests through:
# $ pytest -v

import sys
from lab_ec import *

#####################################################
# TASK 1 -- Ensure libraries are installed on the system.
#           Ensure the lab code can be imported.

@pytest.mark.task1
def test_libs_present():
    """
    Check Cryptodome and pytest are imported
    """
    assert "Cryptodome" in sys.modules
    assert "pytest" in sys.modules


@pytest.mark.task1
def test_code_present():
    """
    Check lab_ec is imported
    """
    assert "lab_ec" in sys.modules


#####################################################
# TASK 2 -- Symmetric encryption using AES-GCM (Galois Counter Mode)

@pytest.mark.task2
def test_gcm_encrypt():
    key = urandom(16)
    message = b"Hello World!"
    nonce, ciphertext, tag = encrypt_message(key, message)

    assert len(nonce) == 12
    assert len(ciphertext) == len(message)
    assert len(tag) == 16


@pytest.mark.task2
def test_gcm_decrypt():
    key = urandom(16)
    message = b"Hello World!"
    nonce, ciphertext, tag = encrypt_message(key, message)

    assert len(nonce) == 12
    assert len(ciphertext) == len(message)
    assert len(tag) == 16

    m = decrypt_message(key, (nonce, ciphertext, tag))
    assert m == message


@pytest.mark.task2
def test_gcm_fails():
    key = urandom(16)
    message = b"Hello World!"
    nonce, ciphertext, tag = encrypt_message(key, message)

    with raises(ValueError) as excinfo:
        decrypt_message(key, (nonce, urandom(len(ciphertext)), tag))
    assert "MAC check failed" in str(excinfo.value)

    with raises(ValueError) as excinfo:
        decrypt_message(key, (nonce, ciphertext, urandom(len(tag))))
    assert "MAC check failed" in str(excinfo.value)

    with raises(ValueError) as excinfo:
        decrypt_message(key, (urandom(len(nonce)), ciphertext, tag))
    assert "MAC check failed" in str(excinfo.value)

    with raises(ValueError) as excinfo:
        decrypt_message(urandom(len(key)), (nonce, ciphertext, tag))
    assert "MAC check failed" in str(excinfo.value)


#####################################################
# TASK 3 -- Understand Elliptic Curve Arithmetic

@pytest.mark.task3
def test_on_curve():
    """
    Test the procedures that tests whether a point is on a curve.

    """
    group = curves["secp224r1"]  # NIST curve
    b, p = group.b, group.p
    a = p - 3
    gx, gy = group.Gx, group.Gy

    assert is_point_on_curve(a, b, p, Point(gx, gy))

    assert is_point_on_curve(a, b, p, Point(None, None))


@pytest.mark.task3
def test_point_addition():
    group = curves["secp224r1"]  # NIST curve
    b, p = group.b, group.p
    a = p - 3
    g = group.G
    gx0, gy0 = group.Gx, group.Gy
    point0 = Point(gx0, gy0)

    r = Integer.random_range(min_inclusive=1, max_exclusive=group.order)
    gx1, gy1 = (r * g).xy
    point1 = Point(gx1, gy1)

    assert is_point_on_curve(a, b, p, point0)
    assert is_point_on_curve(a, b, p, point1)

    # Test a simple addition
    h = (r + 1) * g
    hx1, hy1 = h.xy
    expected = Point(hx1, hy1)

    result = point_add(a, b, p, point0, point1)
    assert is_point_on_curve(a, b, p, result)
    assert result == expected

    # Ensure commutativity
    result_com = point_add(a, b, p, point1, point0)
    assert is_point_on_curve(a, b, p, result_com)
    assert result_com == expected

    # Ensure addition with neutral returns the element
    result_n0 = point_add(a, b, p, Point(None, None), point0)
    assert is_point_on_curve(a, b, p, result_n0)
    assert result_n0 == point0

    result_n1 = point_add(a, b, p, point1, Point(None, None))
    assert is_point_on_curve(a, b, p, result_n1)
    assert result_n1 == point1

    result_n2 = point_add(a, b, p, Point(None, None), Point(None, None))
    assert is_point_on_curve(a, b, p, result_n2)
    assert result_n2 == Point(None, None)

    # An error is raised in case the points are equal
    with raises(Exception) as excinfo:
        point_add(a, b, p, point0, point0)
    assert "EC Points must not be equal" in str(excinfo.value)


@pytest.mark.task3
def test_point_addition_check_inf_result():
    group = curves["secp224r1"]  # NIST curve
    b, p = group.b, group.p
    a = p - 3
    gx0, gy0 = group.Gx, group.Gy
    point0 = Point(gx0, gy0)
    gx1, gy1 = gx0, p - gy0
    point1 = Point(gx1, gy1)

    assert is_point_on_curve(a, b, p, point0)
    assert is_point_on_curve(a, b, p, point1)

    result = point_add(a, b, p, point0, point1)
    assert is_point_on_curve(a, b, p, result)
    assert result.x is None
    assert result.y is None


@pytest.mark.task3
def test_point_doubling():
    group = curves["secp224r1"]  # NIST curve
    b, p = group.b, group.p
    a = p - 3
    g = group.G
    gx0, gy0 = group.Gx, group.Gy
    point0 = Point(gx0, gy0)

    gx2, gy2 = (2 * g).xy
    expected = Point(gx2, gy2)

    result = point_double(a, b, p, point0)
    assert is_point_on_curve(a, b, p, result)
    assert result == expected

    result_inf = point_double(a, b, p, Point(None, None))
    assert is_point_on_curve(a, b, p, result_inf)
    assert result_inf.x is None and result_inf.y is None


@pytest.mark.task3
def test_point_scalar_mult_double_and_add():
    group = curves["secp224r1"]  # NIST curve
    b, p = group.b, group.p
    a = p - 3
    g = group.G
    gx0, gy0 = group.Gx, group.Gy
    point0 = Point(gx0, gy0)
    r = Integer.random_range(min_inclusive=1, max_exclusive=group.order)

    gx2, gy2 = (r * g).xy
    expected = Point(gx2, gy2)

    result = point_scalar_multiplication_double_and_add(a, b, p, point0, r)
    assert is_point_on_curve(a, b, p, result)
    assert result == expected


@pytest.mark.task3
def test_point_scalar_mult_montgomerry_ladder():
    group = curves["secp224r1"]  # NIST curve
    b, p = group.b, group.p
    a = p - 3
    g = group.G
    gx0, gy0 = group.Gx, group.Gy
    point0 = Point(gx0, gy0)

    r = Integer.random_range(min_inclusive=1, max_exclusive=group.order)

    gx2, gy2 = (r * g).xy
    expected = Point(gx2, gy2)

    result = point_scalar_multiplication_montgomerry_ladder(a, b, p, point0, r)
    assert is_point_on_curve(a, b, p, result)
    assert result == expected


#####################################################
# TASK 4 -- Standard ECDSA signatures

@pytest.mark.task4
def test_ecdsa_key_gen():
    """Tests the key generation of ECDSA"""
    ecdsa_key_gen()
    assert True


@pytest.mark.task4
def test_produce_signature():
    msg = b"Test" * 1000

    priv, pub = ecdsa_key_gen()
    ecdsa_sign(priv, msg)


@pytest.mark.task4
def test_check_signature():
    msg = b"Test" * 1000

    priv, pub = ecdsa_key_gen()

    sig = ecdsa_sign(priv, msg)
    ecdsa_verify(pub, msg, sig)


@pytest.mark.task4
def test_check_fail():
    """Ensures verification fails when it should"""
    msg = b"Test" * 1000
    msg2 = b"Text" * 1000

    priv, pub = ecdsa_key_gen()

    sig = ecdsa_sign(priv, msg)
    with raises(Exception) as excinfo:
        ecdsa_verify(pub, msg2, sig)
    assert "The signature is not authentic" in str(excinfo.value)


#####################################################
# TASK 5 -- Diffie-Hellman Key Exchange and Derivation

@pytest.mark.task5
def test_dh_key_gen():
    group, priv, pub = dh_get_key()
    assert pub == priv * group.G
