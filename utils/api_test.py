# Test all the routes (endpoints) available in the CLCERT Randomness Beacon project
import requests
import json
# import random
import secrets
import datetime

HOST = 'https://random.uchile.cl/'
API_PREFIX = 'beacon/2.0/'
LAST_PULSE_1 = 'pulse/last'
LAST_PULSE_2 = 'chain/last/pulse/last'

# get last pulse
req_lp_1 = requests.get(HOST + API_PREFIX + LAST_PULSE_1)
req_lp_2 = requests.get(HOST + API_PREFIX + LAST_PULSE_2)

# check status code
if req_lp_1.status_code != req_lp_2.status_code != 200:
    raise Exception('No 200 Response Code: Last Pulse!')

# get last chain and last pulse indexes
lp_idx = json.loads(req_lp_1.content)["pulse"]["pulseIndex"]
lc_idx = json.loads(req_lp_1.content)["pulse"]["chainIndex"]

# select random pulse
# random_pulse = random.randint(1, lp_idx)
random_pulse = secrets.randbelow(lp_idx - 1) + 1

# generate routes for pulses by id
LAST_PULSE_BY_ID = 'chain/' + str(lc_idx) + '/pulse/' + str(lp_idx)
FIRST_PULSE_BY_ID = 'chain/' + str(lc_idx) + '/pulse/1'
RANDOM_PULSE_BY_ID = 'chain/' + str(lc_idx) + '/pulse/' + str(random_pulse)

# get pulses by id
req_by_id_1 = requests.get(HOST + API_PREFIX + LAST_PULSE_BY_ID)
req_by_id_2 = requests.get(HOST + API_PREFIX + FIRST_PULSE_BY_ID)
req_by_id_3 = requests.get(HOST + API_PREFIX + RANDOM_PULSE_BY_ID)

# check status code
if req_by_id_1.status_code != 200 and req_by_id_2.status_code != 200 and req_by_id_3.status_code != 200:
    raise Exception('No 200 Response Code: Pulses by Id')

# get last pulse timestamp
lp_ts = int(datetime.datetime.strptime(json.loads(req_by_id_1.content)["pulse"]["timeStamp"], '%Y-%m-%dT%H:%M:%S.000Z')
            .replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)

# select random timestamp
# random_ts = random.randint(lp_ts - (lp_idx * 1000), lp_ts)
random_ts = secrets.randbelow(lp_idx * 1000) + lp_ts - (lp_idx * 1000)

# generate routes for pulses by timestamp
LAST_PULSE_BY_TS = 'pulse/time/' + str(lp_ts)
RANDOM_PULSE_BY_TS = 'pulse/time/' + str(random_ts)
PREV_PULSE_BY_TS = 'pulse/time/previous/' + str(random_ts)
NEXT_PULSE_BY_TS = 'pulse/time/next/' + str(random_ts)

# get pulses by timestamp
req_by_ts_1 = requests.get(HOST + API_PREFIX + LAST_PULSE_BY_TS)
req_by_ts_2 = requests.get(HOST + API_PREFIX + RANDOM_PULSE_BY_TS)
req_by_ts_3 = requests.get(HOST + API_PREFIX + PREV_PULSE_BY_TS)
req_by_ts_4 = requests.get(HOST + API_PREFIX + NEXT_PULSE_BY_TS)

# check status code
if req_by_ts_1.status_code != 200 and req_by_ts_2.status_code != 200 and req_by_ts_3.status_code != 200 and \
        req_by_ts_4.status_code != 200:
    raise Exception('No 200 Response Code: Pulses by Timestamp')

# generate route for raw external events
RAW_EVENTS_BY_ID = 'raw/chain/' + str(lc_idx) + '/pulse/' + str(lp_idx)

# get raw events by id
req_raw_by_id = requests.get(HOST + API_PREFIX + RAW_EVENTS_BY_ID)

# check status code
if req_raw_by_id.status_code != 200:
    raise Exception('No 200 Response Code: Last Pulse\'s Raw External Events')

# generate route for system's public key certificate
SYSTEM_PUB_CERTIFICATE = 'certificate/' + json.loads(req_lp_1.content)["pulse"]["certificateId"]

# get system public certificate
req_pub_cert = requests.get(HOST + API_PREFIX + SYSTEM_PUB_CERTIFICATE)

# check status code
if req_pub_cert.status_code != 200:
    raise Exception('No 200 Response Code: Public Key Certificate')

# generate route for pulse PDF certificate
PULSE_PDF_CERTIFICATE = 'beacon/2.0/pulse_certificate/chain/' + str(lc_idx) + '/pulse/' + str(random_pulse)

# get pulse PDF certificate
req_pdf_cert = requests.get(HOST + PULSE_PDF_CERTIFICATE)

# check status code
if req_pdf_cert.status_code != 200:
    raise Exception('No 200 Response Code: Pulse PDF Certificate')
