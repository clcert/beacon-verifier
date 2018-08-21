# Python script that verifies the correctness of all the pulses generated
# by both NIST (2.0) and CLCERT (2.0) Randomness Beacons.
# In particular, this script verifies the correctness of the following properties on each pulse:
# - PreCommitment on local random value
# - Valid pulse's Signature
# - Using of previous values
# - Hash function on signature to produce final output
# The pulses to analyze are the ones generated in the last active chain.

import argparse
import random
from tqdm import tqdm
import requests
import json
import hashlib
import datetime
from dateutil import relativedelta
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def get_pulse(url):
    req = requests.get(url)
    return json.loads(req.content)["pulse"]


def hashed_value(value, cipher_suite):
    assert cipher_suite == 0 or cipher_suite == 1
    hash_function = None
    if cipher_suite == 0:
        hash_function = hashlib.sha512
    elif cipher_suite == 1:
        hash_function = hashlib.sha3_512
    return hash_function(bytes.fromhex(value)).digest().hex()


def get_certificate(certificate_id):
    req = requests.get(BASE_URL + API_VERSION + "certificate/" + certificate_id)
    cert_raw = req.content.replace(b'-M', b'-\r\nM')  # temporary fix for NIST certificate
    return load_pem_x509_certificate(cert_raw, default_backend())


def hash_fn(cipher_suite):
    assert cipher_suite == 0 or cipher_suite == 1
    if cipher_suite == 0:
        return hashlib.sha512
    elif cipher_suite == 1:
        return hashlib.sha3_512


def get_message_signed(pulse_object):
    out = b''

    raw_uri = pulse_object["uri"]
    raw_version = pulse_object["version"]
    raw_cipher_suite = pulse_object["cipherSuite"]
    raw_period = pulse_object["period"]
    raw_certificate_id = pulse_object["certificateId"]
    raw_chain_index = pulse_object["chainIndex"]
    raw_pulse_index = pulse_object["pulseIndex"]
    raw_timestamp = pulse_object["timeStamp"]
    raw_local_random_value = pulse_object["localRandomValue"]
    raw_previous = find_prev_by_type(pulse_object["listValues"], "previous")
    raw_previous_hour = find_prev_by_type(pulse_object["listValues"], "hour")
    raw_previous_day = find_prev_by_type(pulse_object["listValues"], "day")
    raw_previous_month = find_prev_by_type(pulse_object["listValues"], "month")
    raw_previous_year = find_prev_by_type(pulse_object["listValues"], "year")
    raw_pre_commitment = pulse_object["precommitmentValue"]
    raw_status_code = pulse_object["statusCode"]

    len_uri = len(raw_uri)
    len_version = len(raw_version)
    cipherSuite = raw_cipher_suite.to_bytes(4, byteorder='big')  # 4-byte big-endian
    period = raw_period.to_bytes(4, byteorder='big')  # 4-byte big-endian
    len_cert = len(bytes.fromhex(raw_certificate_id))
    chainIndex = raw_chain_index.to_bytes(8, byteorder='big')  # 8-byte big-endian
    pulseIndex = raw_pulse_index.to_bytes(8, byteorder='big')  # 8-byte big-endian
    len_ts = len(raw_timestamp)
    len_lrv = len(bytes.fromhex(raw_local_random_value))
    ext_values = get_ext_values_for_signature(pulse_object["external"])
    len_prev = len(bytes.fromhex(raw_previous))
    len_prev_hour = len(bytes.fromhex(raw_previous_hour))
    len_prev_day = len(bytes.fromhex(raw_previous_day))
    len_prev_month = len(bytes.fromhex(raw_previous_month))
    len_prev_year = len(bytes.fromhex(raw_previous_year))
    len_pre_comm = len(bytes.fromhex(raw_pre_commitment))
    statusCode = raw_status_code.to_bytes(4, byteorder='big')  # 4-byte big-endian

    out += len_uri.to_bytes(4, byteorder='big')
    out += raw_uri.encode('utf-8')
    out += len_version.to_bytes(4, byteorder='big')
    out += raw_version.encode('utf8')
    out += cipherSuite
    out += period
    out += len_cert.to_bytes(4, byteorder='big')
    out += bytes.fromhex(raw_certificate_id)
    out += chainIndex
    out += pulseIndex
    out += len_ts.to_bytes(4, byteorder='big')
    out += raw_timestamp.encode('utf-8')
    out += len_lrv.to_bytes(4, byteorder='big')
    out += bytes.fromhex(raw_local_random_value)
    out += ext_values  # external value
    out += len_prev.to_bytes(4, byteorder='big')
    out += bytes.fromhex(raw_previous)
    out += len_prev_hour.to_bytes(4, byteorder='big')
    out += bytes.fromhex(raw_previous_hour)
    out += len_prev_day.to_bytes(4, byteorder='big')
    out += bytes.fromhex(raw_previous_day)
    out += len_prev_month.to_bytes(4, byteorder='big')
    out += bytes.fromhex(raw_previous_month)
    out += len_prev_year.to_bytes(4, byteorder='big')
    out += bytes.fromhex(raw_previous_year)
    out += len_pre_comm.to_bytes(4, byteorder='big')
    out += bytes.fromhex(raw_pre_commitment)
    out += statusCode

    return out


def find_prev_by_type(list_values, type):
    for value in list_values:
        if value["type"] == type:
            return value["value"]


def get_ext_values_for_signature(external_values):
    output = b''
    if type(external_values) is list:  # CLCERT external values is a list of objects
        for external in external_values:
            output += len(bytes.fromhex(external["sourceId"])).to_bytes(4, byteorder='big')
            output += bytes.fromhex(external["sourceId"])
            output += (external["statusCode"]).to_bytes(4, byteorder='big')  # 4-byte big-endian
            output += len(bytes.fromhex(external["value"])).to_bytes(4, byteorder='big')
            output += bytes.fromhex(external["value"])
    else:  # NIST external values is just one object
        output += len(bytes.fromhex(external_values["sourceId"])).to_bytes(4, byteorder='big')
        output += bytes.fromhex(external_values["sourceId"])
        output += (external_values["statusCode"]).to_bytes(4, byteorder='big')  # 4-byte big-endian
        output += len(bytes.fromhex(external_values["value"])).to_bytes(4, byteorder='big')
        output += bytes.fromhex(external_values["value"])
    return output


def verify_signature(public_key, signature, message, cipher_suite):
    assert cipher_suite == 0 or cipher_suite == 1
    if cipher_suite == 0:
        public_key.verify(signature,
                          message,
                          padding=padding.PKCS1v15(),
                          algorithm=hashes.SHA512())
    elif cipher_suite == 1:
        public_key.verify(signature,
                          message,
                          padding=padding.PSS(
                              mgf=padding.MGF1(hashes.SHA512()),
                              salt_length=20),
                          algorithm=hashes.SHA512())


def verify_output_value(pulse_object, prime=None):
    cipher_suite = pulse_object["cipherSuite"]
    assert cipher_suite == 0 or cipher_suite == 1

    signature_input = get_message_signed(pulse_object)
    signature = bytes.fromhex(pulse_object["signatureValue"])
    message_for_output = signature_input + signature
    output = pulse_object["outputValue"]

    if cipher_suite == 0:
        h = hash_fn(cipher_suite)()
        h.update(message_for_output)
        return h.hexdigest().lower() == output.lower()
    elif cipher_suite == 1:
        from sloth import SlothUnicornGenerator

        iterations = pulse_object["iterations"]
        witness = pulse_object["witness"]

        sloth_obj = SlothUnicornGenerator(message_for_output, iterations)
        comm = calculate_commitment_for_sloth(message_for_output)
        return sloth_obj.verify(comm,
                                output,
                                witness,
                                prime_p=prime)


def calculate_commitment_for_sloth(input):
    return hashlib.sha3_512(hashlib.sha3_512(input).hexdigest().encode('ascii')).hexdigest()


def first_of(pulse_object, period, chain_index):
    ts = datetime.datetime.strptime(pulse_object["timeStamp"], '%Y-%m-%dT%H:%M:%S.%fZ')
    first_of_chain = get_pulse(BASE_URL + API_VERSION + "chain/" + chain_index + "/pulse/1")
    first_of_period = datetime.datetime.utcnow()

    if period == 'hour':
        first_of_period = ts.replace(minute=0, second=0, microsecond=0, tzinfo=datetime.timezone.utc)
    elif period == 'day':
        first_of_period = ts.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=datetime.timezone.utc)
    elif period == 'month':
        first_of_period = ts.replace(day=1, hour=0, minute=0, second=0, microsecond=0, tzinfo=datetime.timezone.utc)
    elif period == 'year':
        first_of_period = ts.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0,
                                     tzinfo=datetime.timezone.utc)

    first_pulse_of_period = get_pulse(
        BASE_URL + API_VERSION + "pulse/time/" + str(int(first_of_period.timestamp() * 1000)))

    if first_of_chain["chainIndex"] > first_pulse_of_period["chainIndex"] or first_of_chain["pulseIndex"] >= \
            first_pulse_of_period["pulseIndex"]:
        return first_of_chain["outputValue"]

    if first_pulse_of_period["pulseIndex"] == pulse_object["pulseIndex"]:
        if period == "hour":
            first_of_period = first_of_period - datetime.timedelta(hours=1)
        elif period == "day":
            first_of_period = first_of_period - datetime.timedelta(days=1)
        elif period == "month":
            first_of_period = first_of_period - relativedelta.relativedelta(months=1)
        elif period == "year":
            first_of_period = first_of_period - relativedelta.relativedelta(years=1)

    first_pulse_of_period = get_pulse(
        BASE_URL + API_VERSION + "pulse/time/" + str(int(first_of_period.timestamp() * 1000)))

    if first_of_chain["chainIndex"] > first_pulse_of_period["chainIndex"] or first_of_chain["pulseIndex"] >= \
            first_pulse_of_period["pulseIndex"]:
        return first_of_chain["outputValue"]

    return first_pulse_of_period["outputValue"]


def select_random_pulses(seed, total, select):
    random.seed(seed)
    return random.sample(range(0, total + 1), select)


def valid_pulse(pulse_obj):
    if pulse_obj is not None:
        return pulse_obj["statusCode"] != 102 and pulse_obj["statusCode"] != 103
    return True


def get_closest_previous_pulse_valid(index):
    for i in reversed(range(index)):
        prev_pulse = get_pulse(BASE_URL + API_VERSION + "chain/" + CHAIN_INDEX + "/pulse/" + str(i))
        if valid_pulse(prev_pulse):
            return prev_pulse
    return None


# PARSE OPTIONS
parser = argparse.ArgumentParser(description="(NIST/CLCERT) Randomness Beacon Pulses Verifier Script")
parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", default=False)

# Organization to verify
org_group = parser.add_argument_group('Organization')
org_group.add_argument("--organization", choices=['NIST', 'CLCERT', 'testing'], dest="org", type=str,
                       help="Select which randomness beacon service to analyze.")

# Tests to execute
tests_group = parser.add_argument_group('Properties to analyze')
tests_group.add_argument("-a", "--all", action="store_true", dest="all", default=False,
                         help="Run all tests (check all properties).")
tests_group.add_argument("-c", "--preCommitment", action="store_true", dest="comm", default=False,
                         help="Checks only local random value pre-committed.")
tests_group.add_argument("-s", "--signature", action="store_true", dest="sign", default=False,
                         help="Checks only valid signature.")
tests_group.add_argument("-o", "--outputValue", action="store_true", dest="outp", default=False,
                         help="Checks only correct generation of output value using hash function.")
tests_group.add_argument("-p", "--previousValues", action="store_true", dest="prev", default=False,
                         help="Checks only reference of previous pulses already created in the chain.")

# Delimiters on which pulses to verify
pulses_group = parser.add_argument_group('Pulses to verify')
pulses_group.add_argument("--init", action="store", dest="init_id", type=int, default=1,
                          help="Set initial pulse as the one with id INIT_ID to analyze.")
pulses_group.add_argument("--final", action="store", dest="final_id", type=int, default=0,
                          help="Set final pulse as the one with id FINAL_ID to analyze.")
pulses_group.add_argument("--random", action="store", dest="random_pulses", type=int, default=0,
                          help="Checks only RANDOM_PULSES pulses selected at random.")
pulses_group.add_argument("--only", action="store", dest="only_id", type=int, default=0,
                          help="Checks only the pulse with id ONLY_ID.")

options = parser.parse_args()

vprint = print if options.verbose else lambda *a, **k: None

vprint("NIST/CLCERT Randomness Beacon - Pulses Verifier")

BASE_URL = ''
API_VERSION = ''
if options.org == 'NIST':
    BASE_URL = 'https://beacon.nist.gov/beacon/'
    API_VERSION = '2.0/'
elif options.org == 'CLCERT':
    BASE_URL = 'https://beacon.clcert.cl/beacon/'
    API_VERSION = '2.0/'
elif options.org == 'testing':
    BASE_URL = 'http://0.0.0.0/beacon/'
    API_VERSION = '2.0/'

vprint("HOST URL: " + BASE_URL + API_VERSION)

if options.all:
    options.comm = options.sign = options.outp = options.prev = True

vprint("TESTS TO BE EXECUTED:")
if options.comm:
    vprint("- Precommitment Values")
if options.sign:
    vprint("- Signatures")
if options.outp:
    vprint("- Output Values")
if options.prev:
    vprint("- Previous Values")

lp = get_pulse(BASE_URL + API_VERSION + "chain/last/pulse/last")
li = lp["pulseIndex"]
CHAIN_INDEX = str(lp["chainIndex"])
certs = {lp["certificateId"]: get_certificate(lp["certificateId"])}

pulses_to_verify = []
if options.random_pulses != 0:
    pulses_to_verify = select_random_pulses(lp["outputValue"], li, options.random_pulses)
elif options.only_id != 0:
    pulses_to_verify = [options.only_id]
else:
    if options.final_id == 0:
        options.final_id = li
    pulses_to_verify = range(options.init_id, options.final_id + 1)

if options.random_pulses:
    vprint("Pulses: " + str(pulses_to_verify))
elif options.only_id:
    vprint("Pulse #" + str(options.only_id))
else:
    vprint("Pulses from #" + str(options.init_id) + " to #" + str(options.final_id))

prime_p = None
prev_comm = prev_value = None
for i in tqdm(pulses_to_verify, unit='pulses'):
    pulse = get_pulse(BASE_URL + API_VERSION + "chain/" + CHAIN_INDEX + "/pulse/" + str(i))

    if i != 1:
        prev_pulse_valid = get_closest_previous_pulse_valid(pulse["pulseIndex"])
        prev_comm = prev_pulse_valid["precommitmentValue"]
        prev_value = prev_pulse_valid["outputValue"]

    # CHECK PRE-COMMITMENT VALUE
    if options.comm and valid_pulse(pulse):
        if i != 1:
            commitment = hashed_value(pulse["localRandomValue"], pulse["cipherSuite"])
            if commitment.lower() != prev_comm.lower():
                print('Invalid RandomValue/Commitment for Pulse #' + str(i))

    # CHECK SIGNATURE
    if options.sign and valid_pulse(pulse):
        message_signed = get_message_signed(pulse)
        try:
            hashed_message = pulse["hashedMessage"]
            if hashed_value(message_signed.hex(), pulse["cipherSuite"]) != hashed_message:
                print('Invalid Message for Signature in Pulse #' + str(i))
            else:
                raise KeyError
        except KeyError:
            try:
                verify_signature(certs[pulse["certificateId"]].public_key(),
                                 bytes.fromhex(pulse["signatureValue"]),
                                 message_signed,
                                 pulse["cipherSuite"])
            except InvalidSignature:
                print('Invalid Signature for Pulse #' + str(i))

    # CHECK OUTPUT VALUE
    if options.outp and valid_pulse(pulse):
        if prime_p is None and pulse["cipherSuite"] == 1:
            from sloth import SlothUnicornGenerator

            max_message = '0' * 2195
            sloth1 = SlothUnicornGenerator(max_message, 1)
            prime_p = sloth1.generate_prime_p(sloth1.generate_sloth_input())
        if not verify_output_value(pulse, prime_p):
            print('Invalid Output Value for Pulse #' + str(i))

    # CHECK PREVIOUS VALUES
    if options.prev and valid_pulse(pulse):
        if i != 1:
            if prev_value.lower() != find_prev_by_type(pulse["listValues"], "previous").lower():
                print('Invalid Previous Value for Pulse #' + str(i))

            prev_hour = first_of(pulse, "hour", CHAIN_INDEX)
            prev_day = first_of(pulse, "day", CHAIN_INDEX)
            prev_month = first_of(pulse, "month", CHAIN_INDEX)
            prev_year = first_of(pulse, "year", CHAIN_INDEX)

            if prev_hour.lower() != find_prev_by_type(pulse["listValues"], "hour").lower():
                print('Invalid First of Hour for Pulse #' + str(i))
            if prev_day.lower() != find_prev_by_type(pulse["listValues"], "day").lower():
                print('Invalid First of Day for Pulse #' + str(i))
            if prev_month.lower() != find_prev_by_type(pulse["listValues"], "month").lower():
                print('Invalid First of Month for Pulse #' + str(i))
            if prev_year.lower() != find_prev_by_type(pulse["listValues"], "year").lower():
                print('Invalid First of Year for Pulse #' + str(i))
