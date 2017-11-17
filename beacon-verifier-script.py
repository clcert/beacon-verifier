# Script that verifies the correctness of all the pulses generated
# by the CLCERT Random Beacon.
# In particular, this script verifies the correctness of the following properties on each pulse:
# - Hash of external events
# - Slow Hash function
# - Pre-commitment on local random value
# - Valid Signature
# - Using of previous values (chaining)
# - Hash of signature to produce final output

import urllib.request, json, hashlib
from optparse import OptionParser
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# CLCERT_BEACON_URL = "http://beacon.clcert.cl/"
CLCERT_BEACON_URL = "http://0.0.0.0:5000/"
API_PREFIX = "beacon/1.0/pulse/"


def get_pulse(url):
    return json.loads(urllib.request.urlopen(url).read().decode())


def hash_value(value):
    return hashlib.sha3_512(value.encode('utf-8')).digest().hex()


def get_msg_to_sign(curr_pulse):
    return curr_pulse["version"] + str(curr_pulse["frequency"]) + curr_pulse["certificateId"] + str(
        curr_pulse["time"]) + curr_pulse[
               "localRandomValue"] + get_external_events_str(curr_pulse["external"]) \
           + curr_pulse["listValue"]["previous"] + curr_pulse["listValue"]["hour"] + curr_pulse["listValue"]["day"] \
           + curr_pulse["listValue"]["month"] + curr_pulse["listValue"]["year"] \
           + curr_pulse["preCommitmentValue"] + str(curr_pulse["status"])


def get_external_events_str(external_list):
    final_str = ''
    for event in external_list:
        final_str += event["sourceId"]
        final_str += event["externalValue"]
        final_str += str(event["statusCode"])
    return final_str


parser = OptionParser()
parser.add_option("-a", "--all",
                  action="store_true", dest="all", default=True,
                  help="perform all correctness tests")
(options, args) = parser.parse_args()

print("Welcome to the CLCERT Random Beacon - Verification Software")

# Obtain all the pulses from 1 to last
last_index = get_pulse(CLCERT_BEACON_URL + API_PREFIX + "last")["id"]

# Get public certificate (for now)
public_certificate = urllib.request.urlopen(CLCERT_BEACON_URL + "beacon/1.0/certificate/1").read()
cert = x509.load_pem_x509_certificate(public_certificate, default_backend())
public_key = cert.public_key()

previous_value = "None"
pre_commitment = "None"
if options.all:
    for i in range(1, last_index + 1):
        pulse = get_pulse(CLCERT_BEACON_URL + API_PREFIX + "id/" + str(i))

        # CHECK IMMEDIATELY PREVIOUS VALUES
        if i is 1:
            previous_value = pulse["outputValue"]
        else:
            if previous_value != pulse["listValue"]["previous"]:
                print("NOT THE SAME VALUE!")
                print("Previous value in pulse #" + str(i) + " not the same as output value in pulse #" + str(i - 1))
                break
            previous_value = pulse["outputValue"]

        # CHECK PRE-COMMITMENTS
        if i is 1:
            pre_commitment = pulse["preCommitmentValue"]
        else:
            commitment = hash_value(pulse["localRandomValue"])
            if commitment != pre_commitment:
                print("NOT THE SAME COMMITMENT!")
                print(
                    "Value committed in pulse #" + str(i - 1) + " not the same as local value used in pulse #" + str(i))
                break
            pre_commitment = pulse["preCommitmentValue"]

        # CHECK SIGNATURE
        message_to_sign = get_msg_to_sign(pulse)
        try:
            public_key.verify(bytes.fromhex(pulse["signatureValue"]),
                              message_to_sign.encode(),
                              padding.PSS(
                                  mgf=padding.MGF1(hashes.SHA256()),
                                  salt_length=padding.PSS.MAX_LENGTH
                              ),
                              hashes.SHA256())
        except InvalidSignature:
            print("Invalid Signature in pulse #" + str(i))
