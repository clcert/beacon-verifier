import io
import random
import hashlib
import time


# Miller-Rabin primality test
def is_probable_prime(n, k = 25):

    assert n >= 2, "Error in is_probable_prime: input (%d) is < 2" % n

    # First check if n is divisible by any of the prime numbers < 1000
    low_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
                  59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
                  127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
                  191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
                  257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
                  331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
                  401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
                  467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
                  563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
                  631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
                  709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
                  797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
                  877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
                  967, 971, 977, 983, 991, 997]

    for prime in low_primes:
        if n % prime == 0:
            return False

    # Perform the real Miller-Rabin test
    s = 0
    d = n - 1
    while True:
        quotient, remainder = divmod(d, 2)
        if remainder == 1:
            break
        s += 1
        d = quotient

    # test the base a to see if it is a witness for the compositeness of n
    def try_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, n) == n-1:
                return False
        return True # n is definitely composite

    for i in range(k):
        a = random.randrange(2, n)
        if try_composite(a):
            return False

    return True # no base tested showed n as composite


def next_prime_3_mod_4(start):
    p = start + 1
    while (p % 4) != 3:
        p = p + 1

    while True:
        # if is_pseudoprime(p):
        if is_probable_prime(p):
            return p
        else:
            p += 4


# Checks if given number x is a quadratic residue modulo p
def is_quadratic_residue(x, modulus):
    # exp = (modulus - 1) / 2
    exp = (modulus - 1) // 2
    res = pow(x, int(exp), modulus)
    return res == 1


# Wrappers for sha hashing functions so that it is easy to change
# the implementation used (current is sha from python's hashlib).
def hash_sha3_512(input):
    if isinstance(input, str):
        input_enc = input.encode('ascii')
    else:
        input_enc = input

    return hashlib.sha3_512(input_enc).hexdigest()


def read_binary_file(file_path):
    data = []

    with io.open(file_path, mode="rb") as f:
        byte = f.read(1)
        while byte:
            data.append(byte)
            byte = f.read(1)

    return data


def read_text_file(file_path):
    data = []

    with io.open(file_path, "r", encoding='ascii') as f:
        byte = f.read(1)
        while byte != "":
            data.append(byte)
            byte = f.read(1)

    return data


# Creates hex value of given integer x,
# but strips prefix '0x' and suffix 'L' which is added sometimes by python
def hex_strip(x):
    res = hex(x)[2:]
    if res[-1] == 'L':
        res = res[:-1]

    return res


class SlothUnicornGenerator:
    sloth_hash = None
    commitment = None
    witness = None
    witness_hash = None

    verification = None
    COMMIT_FAIL = -3
    WITNESS_FAIL = -2
    HASH_FAIL = -1
    ALL_PASSED = 1

    sloth_prime_len = 2048

    def __init__(self, message, iter):
        self.message = message
        self.sloth_num_iter = iter

    def get_sloth_hash(self):
        return self.sloth_hash

    def get_sloth_commitment(self):
        return self.commitment

    def get_sloth_witness(self):
        return self.witness

    # Generates sloth hash from input data
    def generate(self, prime_p=0):

        sloth_input = self.generate_sloth_input()

        self.commitment = hash_sha3_512(sloth_input)

        if prime_p == 0:
            prime_p = self.generate_prime_p(sloth_input)

        s_int = self.generate_s_int(sloth_input, prime_p)

        flip_mask = pow(2, int(self.sloth_prime_len / 2)) - 1
        # flip_mask = pow(2, 1024) - 1
        ro_func_exp = (prime_p + 1) // 4

        for i in range(self.sloth_num_iter):
            # s_int = (s_int ^ flip_mask) % prime_p
            s_int = pow(s_int, int(flip_mask), prime_p)
            s_int = self.ro_function(s_int, ro_func_exp, prime_p)

        self.witness = hex_strip(s_int)
        self.sloth_hash = hash_sha3_512(self.witness)

    # Verifies if given values are correctly generated
    def verify(self, expected_comm, expected_hash, expected_wit, prime_p=0):

        sloth_input = self.generate_sloth_input()

        self.commitment = hash_sha3_512(sloth_input)

        if self.commitment != expected_comm:
            self.verification = self.COMMIT_FAIL
            return False

        wit_hash = hash_sha3_512(expected_wit)
        if wit_hash != expected_hash:
            self.verification = self.WITNESS_FAIL
            self.witness_hash = wit_hash
            return False

        if prime_p == 0:
            prime_p = self.generate_prime_p(sloth_input)

        s_int = self.generate_s_int(sloth_input, prime_p)

        flip_mask = pow(2, self.sloth_prime_len / 2) - 1

        inv_val = int(expected_wit, 16)
        for i in range(self.sloth_num_iter):
            if inv_val % 2 == 0:
                inv_val = pow(inv_val, 2, prime_p)
            else:
                inv_val = prime_p - pow(inv_val, 2, prime_p)
            # inv_val = (inv_val ^ flip_mask) % prime_p
            inv_val = pow(inv_val, flip_mask, prime_p)

        if inv_val != s_int:
            self.verification = self.HASH_FAIL
            return False

        self.verification = self.ALL_PASSED
        return True

    def generate_prime_p(self, sloth_input):

        # We divide with 512 because we are using sha512 hash function
        num_hashes = int(self.sloth_prime_len / 512)

        p0_hex = ""
        for i in range(num_hashes):
            p0_hex += hash_sha3_512(sloth_input + "prime" + str(i))

        p0_int = int(p0_hex, 16)
        p1_int = p0_int | pow(2, self.sloth_prime_len - 1)

        prime_p = next_prime_3_mod_4(p1_int)

        return prime_p

    def generate_s_int(self, sloth_input, prime_p):

        num_hashes = int(self.sloth_prime_len / 512)

        s_hex = ""
        for i in range(num_hashes):
            s_hex += hash_sha3_512(sloth_input + "seed" + str(i))

        s_int = int(s_hex, 16)
        s_int = s_int % prime_p

        return s_int

    def ro_function(self, x, exp, p):

        is_qr = is_quadratic_residue(x, p)

        if is_qr:
            sq_root = pow(x, exp, p)
            if sq_root % 2 == 0:
                return sq_root
            else:
                return p - sq_root
        else:
            sq_root = pow(p - x, int(exp), p)
            if sq_root % 2 == 0:
                return p - sq_root
            else:
                return sq_root

    # Check only if given commitment matches the calculated commitment
    def check_commitment(self, expected_comm):

        sloth_input = self.generate_sloth_input()

        comm = hash_sha3_512(sloth_input)

        if comm == expected_comm:
            return True
        else:
            return False

    # Read image and tweets files as binary files, concatenate data,
    # hash it with sha512 and return hash digest as a result
    def generate_sloth_input(self):

        ret_val = hash_sha3_512(self.message.encode())

        return ret_val
