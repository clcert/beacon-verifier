# Script that verifies the correctness of all the pulses generated
# by the CLCERT Random Beacon.
# In particular, this script verifies the correctness of the following properties on each pulse:
# - Hash of external events (-e)
# - Slow Hash function on signature to produce final output (-o)
# - Pre-commitment on local random value (-p)
# - Valid Signature (-s)
# - Using of previous values a.k.a. chaining (-c)
# - Limit which pulses are going to be verified (-i <initial> -f <final>)
# - Set the address of the beacon web server (-w <beacon-web-address>)

import json
import hashlib
import argparse
import sys
import datetime
import requests
from dateutil import relativedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from tqdm import tqdm
import time
from requests.exceptions import ConnectionError
from json.decoder import JSONDecodeError

from sloth import SlothUnicornGenerator

CLCERT_BEACON_URL = "http://beacon.clcert.cl/"
PULSE_PREFIX = "beacon/1.0/pulse/"
RAW_PREFIX = "beacon/1.0/raw/"
requests.packages.urllib3.disable_warnings()  # Disable warning for self signed certificate


class BeaconServerError(Exception):
    def __init__(self):
        pass


class BeaconPulseError(Exception):
    def __init__(self):
        pass


def get_json(url, retry=0):
    # time.sleep(0.05)  # Prevent 'Too Many Requests' response from server

    if retry == 5:
        raise BeaconServerError

    try:
        req = requests.get(url, verify=False)  # TODO: change for not self signed certificate
    except ConnectionError:
        raise BeaconServerError

    req_code = req.status_code

    if req_code == 200:  # success
        return json.loads(req.content)

    if req_code == 500 and retry < 5:  # retry if a 500 response is returned (up to 5 times)
        return get_json(url, retry=retry + 1)

    if req_code == 502:  # upstream server is down
        raise BeaconServerError

    if req_code == 404:  # record not found
        raise BeaconPulseError


def hash_value(value):
    return hashlib.sha3_512(value.encode('utf-8')).digest().hex()


def get_msg_to_sign(curr_pulse):
    message = curr_pulse["version"] + str(curr_pulse["frequency"]) + curr_pulse["certificateId"] + str(
        curr_pulse["time"]) + curr_pulse[
               "localRandomValue"] + get_external_events_str(curr_pulse["external"]) \
           + curr_pulse["listValue"]["previous"] + curr_pulse["listValue"]["hour"] + curr_pulse["listValue"]["day"] \
           + curr_pulse["listValue"]["month"] + curr_pulse["listValue"]["year"] \
           + curr_pulse["preCommitmentValue"] + str(curr_pulse["status"])
    return message


def get_external_events_str(external_list):
    final_str = ''
    for event in external_list:
        final_str += event["sourceId"]
        final_str += event["externalValue"]
        final_str += str(event["statusCode"])
    return final_str


def verify_output_value(curr_pulse):
    data = get_msg_to_sign(curr_pulse)

    sloth_obj = SlothUnicornGenerator(curr_pulse["signatureValue"] + data, 180)
    return sloth_obj.verify(hash_value(curr_pulse["signatureValue"] + data), curr_pulse["outputValue"], curr_pulse["witness"], prime_p=prime_p)


def first_of_period(curr_pulse, start_of_chain, period):
    if curr_pulse["id"] == 1 or curr_pulse["status"] == 1:
        return "0" * 128
    else:
        curr_pulse_date = datetime.datetime.strptime(curr_pulse["timestamp"], "%a, %d %b %Y %H:%M:%S %Z").replace(
            tzinfo=datetime.timezone.utc)

        start_of_current_period = datetime.datetime.utcnow()

        if period == "hour":
            start_of_current_period = curr_pulse_date.replace(minute=0, second=0, microsecond=0,
                                                              tzinfo=datetime.timezone.utc)
        elif period == "day":
            start_of_current_period = curr_pulse_date.replace(hour=0, minute=0, second=0, microsecond=0,
                                                              tzinfo=datetime.timezone.utc)
        elif period == "month":
            start_of_current_period = curr_pulse_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0,
                                                              tzinfo=datetime.timezone.utc)
        elif period == "year":
            start_of_current_period = curr_pulse_date.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0,
                                                              tzinfo=datetime.timezone.utc)

        try:
            first_of_current_period = get_json(CLCERT_BEACON_URL + PULSE_PREFIX +
                                               str(int(start_of_current_period.timestamp())))
            # start_of_chain = get_json(CLCERT_BEACON_URL + PULSE_PREFIX +
            #                           'start-chain/' + str(int(curr_pulse["time"])))
        except (BeaconServerError, BeaconPulseError) as e:
            raise e

        if start_of_chain["timestamp"] >= first_of_current_period["timestamp"]:
            return start_of_chain["outputValue"]

        if start_of_current_period == curr_pulse_date:
            if period == "hour":
                start_of_current_period = start_of_current_period - datetime.timedelta(hours=1)
            elif period == "day":
                start_of_current_period = start_of_current_period - datetime.timedelta(days=1)
            elif period == "month":
                start_of_current_period = start_of_current_period - relativedelta.relativedelta(months=1)
            elif period == "year":
                start_of_current_period = start_of_current_period - relativedelta.relativedelta(years=1)

            try:
                first_of_current_period = get_json(CLCERT_BEACON_URL + PULSE_PREFIX +
                                                   str(int(start_of_current_period.timestamp())))
            except (BeaconServerError, BeaconPulseError) as e:
                raise e

        if start_of_chain["timestamp"] >= first_of_current_period["timestamp"]:
            return start_of_chain["outputValue"]

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
parser.add_argument("-t", "--tail",
                    action="store", dest="tail", default=0, type=int,
                    help="number of last pulses to check")
parser.add_argument("-w", "--beacon-web",
                    action="store", dest="beacon_web", default="", type=str,
                    help="beacon server web host")
parser.add_argument("-x", "--active-chain",
                    action="store_true", dest="active_chain", default=False,
                    help="check only current active chain")
parser.add_argument("-v", "--verbose",
                    action="store_true", dest="verbose", default=False,
                    help="verbose mode")
options = parser.parse_args()

# CHECK FOR NO OPTIONS
# if not sum(vars(options).values()) > 1:
#     parser.print_help()
#     sys.exit()

vprint = print if options.verbose else lambda *a, **k: None

vprint("CLCERT Random Beacon - Chain Verifier")

# CHECK FOR INCOMPATIBILITIES IN OPTIONS
if options.tail != 0 and (options.first_index != 1 or options.last_index != 0):
    vprint('ERROR: CAN\'T USE -t AND -i OR -f OPTIONS')
    sys.exit()

# SET FIRST INDEX IF TAIL OPTION IS NOT GIVEN
if options.tail == 0:
    first_index = int(options.first_index)

# CHECK BEACON HOST OPTION
if options.beacon_web != "":
    CLCERT_BEACON_URL = options.beacon_web

# GET ID OF LAST PULSE
try:
    lp = get_json(CLCERT_BEACON_URL + PULSE_PREFIX + "last")
except (BeaconServerError, BeaconPulseError):
    vprint("BEACON SERVER IS DOWN")
    sys.exit()
last_pulse_id = lp["id"]

# SET LAST INDEX
if options.last_index == 0:
    last_index = last_pulse_id
else:
    last_index = int(options.last_index)

# SET FIRST INDEX IF TAIL OPTION IS GIVEN
if options.tail != 0:
    first_index = last_index - options.tail + 1
    if first_index < 1:
        first_index = 1

# SET INITIAL INDEX IF ONLY ACTIVE CHAIN WILL BE CHECKED
if options.active_chain:
    start_of_chain = get_json(CLCERT_BEACON_URL + PULSE_PREFIX + 'start-chain/' + str(lp["time"]))
    first_index = start_of_chain["id"]

# CHECK THAT LAST INDEX IS BEFORE THE LAST PULSE GENERATED
if last_index > last_pulse_id:
    vprint("ERROR: LAST INDEX BIGGER THAN LAST PULSE GENERATED!")
    sys.exit()

# CHECK THAT INITIAL IS LOWER THAN LAST PULSE SOLICITED
if last_index < first_index:
    vprint("ERROR: INITIAL PULSE MUST BE LOWER THAN FINAL PULSE!")
    sys.exit()

# SET WHICH TESTS ARE GOING TO BE RUN
if options.all:
    options.chain = True
    options.pre_commitment = True
    options.signature = True
    options.output_value = True
    options.ext_values_hash = True

# Generate prime only if output value needs to be tested
if options.output_value:
    max_message = '0' * 2195
    sloth = SlothUnicornGenerator(max_message, 1)
    vprint("Generating prime for Sloth verification...")
    prime_p = sloth.generate_prime_p(sloth.generate_sloth_input())
    vprint("Prime Generated!")

vprint("\nTESTS TO BE EXECUTED:")

if options.chain:
    vprint("- Chaining of Output Values")

if options.pre_commitment:
    vprint("- Pre-Commitments Values")

if options.signature:
    vprint("- Signature Values")

if options.output_value:
    vprint("- Correctness of Output Values")

if options.ext_values_hash:
    vprint("- Correct Hashing of External Events (Last Hour)")

vprint("\nTESTING PULSES FROM #" + str(first_index) + " TO #" + str(last_index))

# Get public certificate (for now)
try:
    public_certificate = requests.get(CLCERT_BEACON_URL + "beacon/1.0/certificate/1", verify=False).content  # TODO: change for not self signed certificate
except ConnectionError:
    vprint("BEACON SERVER IS DOWN")
    sys.exit()

cert = x509.load_pem_x509_certificate(public_certificate, default_backend())
public_key = cert.public_key()

if first_index != 1:
    try:
        previous_pulse = get_json(CLCERT_BEACON_URL + PULSE_PREFIX + "id/" + str(first_index - 1))
    except (BeaconServerError, BeaconPulseError):
        vprint("BEACON SERVER IS DOWN")
        sys.exit()
    previous_value = previous_pulse["outputValue"]
    pre_commitment = previous_pulse["preCommitmentValue"]

chain_errors = {"previous": [], "hour": [], "day": [], "month": [], "year": []}
pre_commitment_errors = []
signature_errors = {"message": [], "signature": []}
output_errors = []
hash_errors = []

for i in tqdm(range(first_index, last_index + 1), unit='pulses', disable=not options.verbose):
    try:
        pulse = get_json(CLCERT_BEACON_URL + PULSE_PREFIX + "id/" + str(i))
    except (BeaconServerError, BeaconPulseError):
        vprint("\nBEACON SERVER IS DOWN")
        vprint("LAST RECORD ANALYZED #" + str(i-1))
        break

    # CHECK PREVIOUS VALUES (CONSISTENCY OF THE CHAIN)
    if options.chain:

        start_of_chain = get_json(CLCERT_BEACON_URL + PULSE_PREFIX + 'start-chain/' + str(int(pulse["time"])))

        # The first record doesn't need to check previous values
        if i is 1:
            previous_value = first_of_hour_value = first_of_day_value = first_of_month_value = first_of_year_value = \
                pulse["outputValue"]
        else:
            if previous_value != pulse["listValue"]["previous"]:
                chain_errors["previous"].append(i)
            previous_value = pulse["outputValue"]

            try:
                first_of_hour_value = first_of_period(pulse, start_of_chain, "hour")
                first_of_day_value = first_of_period(pulse, start_of_chain, "day")
                first_of_month_value = first_of_period(pulse, start_of_chain, "month")
                first_of_year_value = first_of_period(pulse, start_of_chain, "year")
            except (BeaconServerError, BeaconPulseError):
                vprint("\nBEACON SERVER IS DOWN")
                vprint("LAST RECORD ANALYZED #" + str(i - 1))
                break

            if first_of_hour_value != pulse["listValue"]["hour"]:
                chain_errors["hour"].append(i)
            if first_of_day_value != pulse["listValue"]["day"]:
                chain_errors["day"].append(i)
            if first_of_month_value != pulse["listValue"]["month"]:
                chain_errors["month"].append(i)
            if first_of_year_value != pulse["listValue"]["year"]:
                chain_errors["year"].append(i)

    # CHECK PRE-COMMITMENTS
    if options.pre_commitment:

        # The first record doesn't use a local random value
        if i is 1:
            pre_commitment = pulse["preCommitmentValue"]
        else:
            if pulse["status"] == 102 or pulse["status"] == 103:
                pre_commitment = pulse["preCommitmentValue"]
            else:
                commitment = hash_value(pulse["localRandomValue"])
                if pulse["localRandomValue"] != ('0' * 128) and commitment != pre_commitment:
                    pre_commitment_errors.append(i)
                pre_commitment = pulse["preCommitmentValue"]

    # CHECK SIGNATURE
    if options.signature:

        # Only check signatures of normal records (status != 102 or 103)
        if pulse["status"] != 102 and pulse["status"] != 103:
            message_to_sign = get_msg_to_sign(pulse)
            if hash_value(message_to_sign) != pulse["hashedMessage"]:
                signature_errors["message"].append(i)
            else:
                try:
                    public_key.verify(bytes.fromhex(pulse["signatureValue"]),
                                      message_to_sign.encode(),
                                      padding.PSS(
                                          mgf=padding.MGF1(hashes.SHA256()),
                                          salt_length=padding.PSS.MAX_LENGTH
                                      ),
                                      hashes.SHA256())
                except InvalidSignature:
                    signature_errors["signature"].append(i)

    # CHECK CORRECT GENERATION OF OUTPUT VALUE
    if options.output_value:

        # Only check output value of normal records (status != 102 or 103)
        if pulse["status"] != 102 and pulse["status"] != 103:
            if verify_output_value(pulse):
                output_errors.append(i)

    # CHECK HASH OF EXTERNAL EVENTS PRODUCED IN THE LAST HOUR
    if options.ext_values_hash:

        # Only check last 60 records
        if i > (last_pulse_id - 60) + 1:
            # Only check records not missing
            if pulse["status"] != 103:
                try:
                    raw_events = get_json(CLCERT_BEACON_URL + RAW_PREFIX + "id/" + str(i))
                except (BeaconServerError, BeaconPulseError):
                    vprint("\nBEACON SERVER IS DOWN")
                    vprint("LAST RECORD ANALYZED #" + str(i - 1))
                    break
                for event in raw_events:
                    source_id = event["source_id"]
                    for hashed_event in pulse["external"]:
                        if hash_value(str(source_id)) == hashed_event["sourceId"] and hash_value(event["raw_value"]) != \
                                hashed_event["externalValue"] and not event["raw_value"] == "DELETED":
                            hash_errors.append(i)

# PRINT FINAL REPORT
vprint("\nFINAL REPORT:")
if not any(chain_errors.values()) and not pre_commitment_errors and not any(signature_errors.values()) and \
        not output_errors and not hash_errors:
    vprint("All pulses analyzed were correct!")
else:
    print('ERRORS (' + str(datetime.datetime.now().replace(microsecond=0)) + ')')
    if any(chain_errors.values()):
        vprint("CHAIN ERRORS")
        vprint(str(chain_errors) + '\n')
    if pre_commitment_errors:
        vprint("PRE-COMMITMENT ERRORS")
        vprint(str(pre_commitment_errors) + '\n')
    if any(signature_errors.values()):
        vprint("SIGNATURE ERRORS")
        vprint(str(signature_errors) + '\n')
    if output_errors:
        vprint("OUTPUT VALUES ERRORS")
        vprint(str(output_errors) + '\n')
    if hash_errors:
        vprint("HASH OF EXTERNAL EVENTS ERRORS")
        vprint(str(hash_errors))
vprint("")
