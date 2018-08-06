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
from cryptography.hazmat.primitives.asymmetric import padding, utils
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
    # cert_raw = req.content
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
    if type(external_values) is list:
        for external in external_values:
            output += len(bytes.fromhex(external["sourceId"])).to_bytes(4, byteorder='big')
            output += bytes.fromhex(external_values["sourceId"])
            output += (external["statusCode"]).to_bytes(4, byteorder='big')  # 4-byte big-endian
            output += len(bytes.fromhex(external["value"])).to_bytes(4, byteorder='big')
            output += bytes.fromhex(external_values["value"])
    else:
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


def calculate_output_value(pulse_object):
    cipher_suite = pulse_object["cipherSuite"]
    assert cipher_suite == 0 or cipher_suite == 1
    if cipher_suite == 0:
        h = hash_fn(cipher_suite)()

        signature_input = get_message_signed(pulse_object)
        signature = bytes.fromhex(pulse_object["signatureValue"])

        h.update(signature_input)
        h.update(signature)

        return h.digest().hex()
    elif cipher_suite == 1:
        pass


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
        first_of_period = ts.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0, tzinfo=datetime.timezone.utc)

    first_pulse_of_period = get_pulse(BASE_URL + API_VERSION + "pulse/time/" + str(int(first_of_period.timestamp()*1000)))

    if first_of_chain["pulseIndex"] >= first_pulse_of_period["pulseIndex"]:
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

    first_pulse_of_period = get_pulse(BASE_URL + API_VERSION + "pulse/time/" + str(int(first_of_period.timestamp()*1000)))

    if first_of_chain["pulseIndex"] >= first_pulse_of_period["pulseIndex"]:
        return first_of_chain["outputValue"]

    return first_pulse_of_period["outputValue"]


def select_random_pulses(seed, total, select):
    random.seed(seed)
    return random.sample(range(0, total + 1), select)


# PARSE OPTIONS
parser = argparse.ArgumentParser(description="(NIST/CLCERT) Beacon Pulses Verifier Script")
parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", default=False)

parser.add_argument("-a", "--all", action="store_true", dest="all", default=False)
parser.add_argument("-c", "--precommitment", action="store_true", dest="comm", default=False)
parser.add_argument("-s", "--signature", action="store_true", dest="sign", default=False)
parser.add_argument("-o", "--outputValue", action="store_true", dest="outp", default=False)
parser.add_argument("-p", "--previousValues", action="store_true", dest="prev", default=False)

parser.add_argument("-e", "--entity", choices=['nist', 'clcert', 'test'], dest="ent", type=str)

parser.add_argument("-i", "--initial", action="store", dest="ini", type=int, default=1)
parser.add_argument("-f", "--final", action="store", dest="fin", type=int, default=0)
parser.add_argument("--random", action="store", dest="random_pulses", type=int, default=0)

options = parser.parse_args()

vprint = print if options.verbose else lambda *a, **k: None

vprint("NIST/CLCERT Randomness Beacon - Pulses Verifier")

BASE_URL = ''
API_VERSION = ''
if options.ent == 'nist':
    BASE_URL = 'https://beacon.nist.gov/beacon/'
    API_VERSION = '2.0/'
elif options.ent == 'clcert':
    BASE_URL = 'https://beacon.clcert.cl/beacon/'
    API_VERSION = '1.1/'
elif options.ent == 'test':
    BASE_URL = 'http://localhost:5000/beacon/'
    API_VERSION = '1.1/'
CHAIN_INDEX = "1"

vprint("HOST URL: " + BASE_URL + API_VERSION)

if options.all:
    options.comm = options.sign = options.outp = options.prev = True

vprint("TESTS TO BE EXECUTED:")
if options.comm:
    vprint("- PreCommitments")
if options.sign:
    vprint("- Signatures")
if options.outp:
    vprint("- Output Values")
if options.prev:
    vprint("- Previous Values")

lp = get_pulse(BASE_URL + API_VERSION + "chain/" + CHAIN_INDEX + "/pulse/last")
li = lp["pulseIndex"]
certs = {lp["certificateId"]: get_certificate(lp["certificateId"])}

if options.ini != 1:
    prev_pulse = get_pulse(BASE_URL + API_VERSION + "chain/" + CHAIN_INDEX + "/pulse/" + str(options.ini - 1))
    prev = prev_pulse["outputValue"]
    pre_comm = prev_pulse["precommitmentValue"]

if options.fin == 0:
    options.fin = li

pulses_to_verify = range(options.ini, options.fin + 1)

vprint("Pulses from #" + str(options.ini) + " to #" + str(options.fin))
for i in tqdm(pulses_to_verify, unit='pulses'):
    pulse = get_pulse(BASE_URL + API_VERSION + "chain/" + CHAIN_INDEX + "/pulse/" + str(i))

    # CHECK PRE-COMMITMENT VALUE
    if options.comm:
        if i is 1:
            pre_comm = pulse["precommitmentValue"]
        else:
            commitment = hashed_value(pulse["localRandomValue"], pulse["cipherSuite"])
            if commitment.lower() != pre_comm.lower():
                print('Invalid RandomValue/Commitment for Pulse #' + str(i))
            pre_comm = pulse["precommitmentValue"]

    # CHECK SIGNATURE
    if options.sign:
        message_signed = get_message_signed(pulse)
        try:
            verify_signature(certs[pulse["certificateId"]].public_key(),
                             bytes.fromhex(pulse["signatureValue"]),
                             message_signed,
                             pulse["cipherSuite"])
        except InvalidSignature:
            print('Invalid Signature for Pulse #' + str(i))

    # CHECK OUTPUT VALUE
    if options.outp:
        expected_output_value = calculate_output_value(pulse)
        if expected_output_value.lower() != pulse["outputValue"].lower():
            print('Invalid Output Value for Pulse #' + str(i))

    # CHECK PREVIOUS VALUES
    if options.prev:
        if i is 1:
            prev = prev_hour = prev_day = prev_month = prev_year = pulse["outputValue"]
        else:
            if prev.lower() != find_prev_by_type(pulse["listValues"], "previous").lower():
                print('Invalid Previous Value for Pulse #' + str(i))
            prev = pulse["outputValue"]

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
