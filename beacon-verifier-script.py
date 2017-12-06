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
import argparse

import sys

import time
import datetime
from dateutil import relativedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# CLCERT_BEACON_URL = "http://beacon.clcert.cl/"
CLCERT_BEACON_URL = "http://0.0.0.0:5000/"
PULSE_PREFIX = "beacon/1.0/pulse/"
RAW_PREFIX = "beacon/1.0/raw/"


def get_json(url):
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


def generate_output_value(curr_pulse):
    data = get_msg_to_sign(curr_pulse)
    # TODO: This should be an slow hash function
    return hash_value(curr_pulse["signatureValue"] + data)


def first_of_period(curr_pulse, period):
    if curr_pulse["id"] == 1:
        return "0" * 128
    else:
        curr_pulse_date = datetime.datetime.strptime(curr_pulse["timestamp"], "%a, %d %b %Y %H:%M:%S %Z").replace(
                                                     tzinfo=datetime.timezone.utc)

        if period == "hour":
            start_of_current_period = curr_pulse_date.replace(minute=0, second=0, microsecond=0,
                                                              tzinfo=datetime.timezone.utc)
        elif period == "day":
            start_of_current_period = curr_pulse_date.replace(hour= 0, minute=0, second=0, microsecond=0,
                                                              tzinfo=datetime.timezone.utc)
        elif period == "month":
            start_of_current_period = curr_pulse_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0,
                                                              tzinfo=datetime.timezone.utc)
        elif period == "year":
            start_of_current_period = curr_pulse_date.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0,
                                                              tzinfo=datetime.timezone.utc)

        # check that the date is after the first pulse generated (only if there are less than 60 pulses generated)
        if curr_pulse["id"] <= 60:
            first_pulse = get_json(CLCERT_BEACON_URL + PULSE_PREFIX + "id/1")
            first_pulse_date = datetime.datetime.strptime(first_pulse["timestamp"],
                                                          "%a, %d %b %Y %H:%M:%S %Z").replace(
                                                          tzinfo=datetime.timezone.utc)
            if start_of_current_period < first_pulse_date:
                return first_pulse["outputValue"]

        first_of_current_period = get_json(CLCERT_BEACON_URL + PULSE_PREFIX +
                                           str(int(start_of_current_period.timestamp())))

        if start_of_current_period == curr_pulse_date:
            if period == "hour":
                start_of_current_period = start_of_current_period - datetime.timedelta(hours=1)
            elif period == "day":
                start_of_current_period = start_of_current_period - datetime.timedelta(days=1)
            elif period == "month":
                start_of_current_period = start_of_current_period - relativedelta.relativedelta(month=1)
            elif period == "year":
                start_of_current_period = start_of_current_period - relativedelta.relativedelta(years=1)
            first_of_current_period = get_json(CLCERT_BEACON_URL + PULSE_PREFIX +
                                               str(int(start_of_current_period.timestamp())))

        return first_of_current_period["outputValue"]


# PARSE OPTIONS
parser = argparse.ArgumentParser(description="Verifier Script for Pulses generated by CLCERT Random Beacon")
parser.add_argument("-a", "--all",
                    action="store_true", dest="all", default=False,
                    help="perform all correctness tests")
parser.add_argument("-c", "--chained",
                    action="store_true", dest="chain", default=False,
                    help="check chaining of previous values")
parser.add_argument("-p", "--pre-commitment",
                    action="store_true", dest="pre_commitment", default=False,
                    help="check pre-commitments")
parser.add_argument("-s", "--signature",
                    action="store_true", dest="signature", default=False,
                    help="check signature of all pulses")
parser.add_argument("-o", "--output-value",
                    action="store_true", dest="output_value", default=False,
                    help="check correct generation of output value")
parser.add_argument("-e", "--external-values-hash",
                    action="store_true", dest="ext_values_hash", default=False,
                    help="check correct hashing of external events (last hour)")
parser.add_argument("-i", "--initial-pulse",
                    action="store", dest="first_index", default=1, type=int,
                    help="first pulse to check the chain")
parser.add_argument("-f", "--final-pulse",
                    action="store", dest="last_index", default=0, type=int,
                    help="last pulse to check the chain")
options = parser.parse_args()

# CHECK FOR NO OPTIONS
if not sum(vars(options).values()) > 1:
    parser.print_help()
    sys.exit()

print("Welcome to the CLCERT Random Beacon - Verification Software")

# SET LIMITS FOR CHAIN TO CHECK
first_index = int(options.first_index)

last_pulse = get_json(CLCERT_BEACON_URL + PULSE_PREFIX + "last")["id"]

if options.last_index == 0:
    last_index = last_pulse
else:
    last_index = int(options.last_index)

# CHECK THAT LAST INDEX IS BEFORE THE LAST PULSE GENERATED
if last_index > last_pulse:
    print("ERROR: LAST INDEX BIGGER THAN LAST PULSE GENERATED!")
    sys.exit()

# CHECK THAT INITIAL IS LOWER THAN LAST PULSE SOLICITED
if last_index < first_index:
    print("ERROR: INITIAL PULSE MUST BE LOWER THAN FINAL PULSE!")
    sys.exit()

# SET WHICH TESTS ARE GOING TO BE RUN
if options.all:
    # TODO: Automatically set all options to True
    options.chain = True
    options.pre_commitment = True
    options.signature = True
    options.output_value = True
    options.ext_values_hash = True

if options.chain:
    print("TESTING CHAINING OF OUTPUT VALUES")

if options.pre_commitment:
    print("TESTING PRE-COMMITMENTS VALUES")

if options.signature:
    print("TESTING SIGNATURE VALUES")

if options.output_value:
    print("TESTING CORRECTNESS OF OUTPUT VALUES")

if options.ext_values_hash:
    print("TESTING CORRECT HASHING OF EXTERNAL VALUES (LAST HOUR)")

print("TESTING PULSES FROM #" + str(first_index) + " TO #" + str(last_index))

# Get public certificate (for now)
public_certificate = urllib.request.urlopen(CLCERT_BEACON_URL + "beacon/1.0/certificate/1").read()
cert = x509.load_pem_x509_certificate(public_certificate, default_backend())
public_key = cert.public_key()

if first_index != 1:
    previous_pulse = get_json(CLCERT_BEACON_URL + PULSE_PREFIX + "id/" + str(first_index - 1))
    previous_value = previous_pulse["outputValue"]
    pre_commitment = previous_pulse["preCommitmentValue"]

for i in range(first_index, last_index + 1):
    pulse = get_json(CLCERT_BEACON_URL + PULSE_PREFIX + "id/" + str(i))

    if options.chain:
        # CHECK IMMEDIATELY PREVIOUS VALUES
        if i is 1:
            previous_value = first_of_hour_value = first_of_day_value = first_of_month_value = first_of_year_value = \
                pulse["outputValue"]
        else:
            if previous_value != pulse["listValue"]["previous"]:
                print("Previous value in pulse #" + str(i) + " not the same as output value in pulse #" + str(i - 1))
            previous_value = pulse["outputValue"]

            first_of_hour_value = first_of_period(pulse, "hour")
            first_of_day_value = first_of_period(pulse, "day")
            first_of_month_value = first_of_period(pulse, "month")
            first_of_year_value = first_of_period(pulse, "year")

            if first_of_hour_value != pulse["listValue"]["hour"]:
                print("Previous hour value in pulse #" + str(i) + " not correct")
                print(first_of_hour_value)
                print(pulse["listValue"]["hour"])
                break
            if first_of_day_value != pulse["listValue"]["day"]:
                print("Previous day value in pulse #" + str(i) + " not correct")
            if first_of_month_value != pulse["listValue"]["month"]:
                print("Previous month value in pulse #" + str(i) + " not correct")
            if first_of_year_value != pulse["listValue"]["year"]:
                print("Previous year value in pulse #" + str(i) + " not correct")

    if options.pre_commitment:
        # CHECK PRE-COMMITMENTS
        if i is 1:
            pre_commitment = pulse["preCommitmentValue"]
        else:
            commitment = hash_value(pulse["localRandomValue"])
            if commitment != pre_commitment:
                print(
                    "Value committed in pulse #" + str(i - 1) + " not the same as local value used in pulse #" + str(i))
            pre_commitment = pulse["preCommitmentValue"]

    if options.signature:
        # CHECK SIGNATURE
        message_to_sign = get_msg_to_sign(pulse)
        if message_to_sign != pulse["message"]:
            print("Message signed in pulse #" + str(i) + " changed!")
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

    if options.output_value:
        # CHECK CORRECT GENERATION OF OUTPUT VALUE
        correct_output_value = generate_output_value(pulse)
        if correct_output_value != pulse["outputValue"]:
            print("Output value in pulse #" + str(i) + " should be " + correct_output_value)

    if options.ext_values_hash:
        # CHECK HASH OF EXTERNAL EVENTS PRODUCED IN THE LAST HOUR
        if i > (last_pulse - 60) + 1:
            raw_events = get_json(CLCERT_BEACON_URL + RAW_PREFIX + "id/" + str(i))
            for event in raw_events:
                source_id = event["source_id"]
                for hashed_event in pulse["external"]:
                    if hash_value(str(source_id)) == hashed_event["sourceId"] and hash_value(event["raw_value"]) != \
                            hashed_event["externalValue"] and not event["raw_value"] == "DELETED":
                        print("Hash of source #" + str(source_id) +
                              " not the same as value showed in pulse #" + str(i))

    # Prevent 'Too Many Requests' response from server
    time.sleep(0.05)