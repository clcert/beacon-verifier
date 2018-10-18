# Real time script that verifies that the data extracted by the
# beacon collector is the same public data that this host can observe, or
# has a tolerable delay.

import datetime
import queue
import time
import requests
import binascii
import json
import argparse
from requests.exceptions import ConnectionError
from json.decoder import JSONDecodeError
from bs4 import BeautifulSoup
import threading


CLCERT_BEACON_URL = "https://beacon.clcert.cl/"
PULSE_PREFIX = "beacon/1.0/pulse/"
RAW_PREFIX = "beacon/1.0/raw/"


class BeaconServerError(Exception):
    def __init__(self):
        pass


class BeaconPulseError(Exception):
    def __init__(self):
        pass


class SourceCollector:

    def __init__(self, que, s):
        self.que = que
        self.source = s

    def process(self):
        try:
            self.collect_event()
        except Exception:
            if self.source == 'r':
                self.que.put(('radio', 'timeout error'))
            elif self.source == 'e':
                self.que.put(('earthquake', 'timeout error'))
            elif self.source == 't':
                self.que.put(('twitter', 'timeout error'))
            return

    def collect_event(self):
        pass


class RadioStream(SourceCollector):

    def __init__(self, que, s):
        super().__init__(que, s)

    def collect_event(self):
        now_utc = datetime.datetime.utcnow()

        stream_url = "http://stream3.rbm.cl:8010/playerweb.aac"

        raw_result = ''
        raw_block = b''

        time.sleep(5 - now_utc.second)

        r = requests.get(stream_url, stream=True, timeout=1)

        # Get 25 blocks of 1024 bytes each (25 kB, approx. 3 seconds of audio)
        i = c = 0
        delimiter = '00' * 45  # 45 bytes of 0s
        for block in r.iter_content(1024):
            if i < 260 and c < 25:
                i += 1
                result = binascii.b2a_hex(block).decode()
                if delimiter in result or (0 < c < 25):
                    raw_block += block
                    raw_result += result
                    c += 1
                    i -= 1

            else:
                self.que.put(('radio', raw_result))
                return

        self.que.put(('radio', raw_result))
        return


def truncate_data(data):
    if len(data) > 80:
        return data[:79] + '\n'
    else:
        return data + ('#' * (79 - len(data))) + '\n'


class EarthquakeWeb(SourceCollector):

    def __init__(self, que, s):
        super().__init__(que, s)

    def collect_event(self):
        now_cl = datetime.datetime.now(tz=datetime.timezone(-datetime.timedelta(hours=3)))
        current_year = str(now_cl.year)
        current_month = str(now_cl.month) if len(str(now_cl.month)) == 2 else '0' + str(now_cl.month)
        current_day = str(now_cl.day) if len(str(now_cl.day)) == 2 else '0' + str(now_cl.day)
        url = 'http://sismologia.cl/events/listados/' + current_year + '/' + current_month + \
              '/' + current_year + current_month + current_day + '.html'

        # Wait until reach half a minute
        time.sleep(30 - datetime.datetime.utcnow().second)

        # Gets the last earthquake produced over degree 2.5 informed by sismologia.cl
        web = requests.get(url, timeout=5).content

        soup = BeautifulSoup(web, "html.parser")
        earthquakes_text = soup.findAll("tr", {'class': ['impar', 'par']})[1:]

        earthquakes = []
        for earthquake_text in earthquakes_text:
            params = []
            for parameter in earthquake_text.contents:
                params.append(parameter.text)
            date = params[0]
            latitude = params[2]
            longitude = params[3]
            depth = params[4]
            magnitude = params[5]
            reference = params[6]
            single_earthquake = "%s %s %s %s %s" % (adjust(date, 'date'), adjust(latitude, 'coord'),
                                                    adjust(longitude, 'coord'), adjust(depth, 'magnitude'),
                                                    adjust(magnitude, 'depth'))
            earthquakes.append(single_earthquake)

        raw_result = ''
        for earthquake in earthquakes:
            raw_result = earthquake
            if float(raw_result.split(' ')[-1]) >= 3:
                break

        self.que.put(('earthquake', raw_result))


def adjust(data, option):
    if option == 'coord':
        return str(float('%.1f' % (float(data))))
    if option == 'magnitude' or option == 'depth':
        return data.split(' ')[0]
    return data


def get_json(url):
    time.sleep(0.05)  # Prevent 'Too Many Requests' response from server
    try:
        return json.loads(requests.get(url).content)  # TODO: change for not self signed certificate
    except ConnectionError:
        raise BeaconServerError
    except JSONDecodeError:
        raise BeaconPulseError


class EthereumBlockchain(SourceCollector):

    def __init__(self, que, s):
        super().__init__(que, s)

    def collect_event(self):
        time.sleep(25 - datetime.datetime.utcnow().second)
        eth_api = 'https://api.blockcypher.com/v1/eth/main'

        request = requests.get(eth_api, timeout=5)

        content = json.loads(request.content)
        last_block_hash = content["hash"]
        last_block_prev_hash = content["previous_hash"]
        last_block_height = content["height"]
        self.que.put(('ethereum', last_block_hash, last_block_prev_hash, last_block_height))


class TrendingTwitter(SourceCollector):

    def __init__(self, que, s):
        super().__init__(que, s)


def check_eq_event(collected, reported, event_status, current_time):
    if event_status == 0:
        if collected == reported:
            pass
        else:
            print('EARTHQUAKE ERROR!\t' + current_time)
            print('col: ' + collected)
            print('rep: ' + reported)
    else:
        print('BEACON EVENT ERROR!\t' + current_time)


# Validates if the ethereum event received by the verifier is the "same" as the one reported by the Beacon.
# The are three conditions under the check will be valid:
# 1. The hash of the blocks are the same.
# 2. The hash of the previous block collected is the same as the one reported.
# 3. There are, at most, 2 blocks of difference between the collected and the reported one.
# In any other case, the validation will not be valid.
def check_eth_event(collected, reported, event_status, curr_time):
    if event_status != 0:
        print('BEACON EVENT ERROR!\t' + curr_time)
        return 3  # beacon service error

    if collected == '':
        print('ETHEREUM COLLECTED EVENT ERROR!\t' + curr_time)
        return 2  # verifier error

    col_eth_hash = collected[0]
    col_eth_phash = collected[1]
    col_eth_height = collected[2]

    rep_values = reported.split()
    rep_eth_hash = rep_values[0]
    rep_eth_height = int(rep_values[1])

    if col_eth_hash == rep_eth_hash or col_eth_phash == rep_eth_hash or abs(col_eth_height - rep_eth_height) <= 2:
        return 0  # valid verification
    else:
        print('ETHEREUM ERROR!\t' + curr_time)
        print('col height: ' + str(col_eth_height))
        print('rep height: ' + str(rep_eth_height))
        print('col hash: ' + col_eth_hash)
        print('rep hash: ' + rep_eth_hash)
        return 1  # invalid verification


# PARSE OPTIONS
parser = argparse.ArgumentParser(description="Real-Time Script for External Events collected by CLCERT Random Beacon")
parser.add_argument("-w", "--beacon-web",
                    action="store", dest="beacon_web", default="", type=str,
                    help="beacon server web host")
parser.add_argument("-a", "--all-sources",
                    action="store_true", dest="all_sources", default=False,
                    help="check all sources")
parser.add_argument("-e", "--earthquake",
                    action="store_true", dest="eq_check", default=False,
                    help="check earthquake collector")
parser.add_argument("-r", "--radio",
                    action="store_true", dest="radio_check", default=False,
                    help="check radio collector")
parser.add_argument("-t", "--twitter",
                    action="store_true", dest="tw_check", default=False,
                    help="check twitter collector")
parser.add_argument("-b", "--blockchain",
                    action="store_true", dest="block_check", default=False,
                    help="check blockchain (ethereum) collector")
options = parser.parse_args()

print("CLCERT Random Beacon - Real-Time Verifier")

# CHECK BEACON HOST OPTION
if options.beacon_web != "":
    CLCERT_BEACON_URL = options.beacon_web

# CHECK WHICH SOURCES TO VERIFY
if options.all_sources:
    options.eq_check = True
    options.radio_check = True
    options.tw_check = True
    options.block_check = True

# Wait for the current minute to end
second_mark_init = 0
while 1:
    if datetime.datetime.now().second == second_mark_init:
        break
    else:
        now_utc = datetime.datetime.now()
        time_to_wait = (60 - now_utc.second - 1) + second_mark_init + ((1000000 - now_utc.microsecond) / 1000000)
        time.sleep(time_to_wait)

# Execute the main function at the beginning of each minute
while 1:

    # Queue return value to a Queue object
    q = queue.Queue()

    # Process each collector as a separate thread
    threads = []

    if options.eq_check:
        t0 = threading.Thread(target=EarthquakeWeb(q, 'e').process)
        threads.append(t0)
        earthquake_event = ''
    if options.tw_check:
        t1 = threading.Thread(target=TrendingTwitter(q, 't').process)
        threads.append(t1)
        twitter_event = ''
    if options.radio_check:
        t2 = threading.Thread(target=RadioStream(q, 'r').process)
        threads.append(t2)
        radio_event = ''
    if options.block_check:
        t3 = threading.Thread(target=EthereumBlockchain(q, 'b').process)
        threads.append(t3)
        ethereum_event = ''

    # Start all threads
    for t in threads:
        t.start()

    # Wait all threads to finish
    for t in threads:
        t.join()

    while not q.empty():
        element = q.get()
        if element[0] == 'radio':
            radio_event = element[1]
        elif element[0] == 'earthquake':
            earthquake_event = element[1]
        elif element[0] == 'twitter':
            twitter_event = element[1]
        elif element[0] == 'ethereum':
            ethereum_event = element[1:]

    # Wait until 35 second mark to retrieve external events values
    now_utc = datetime.datetime.utcnow()
    wait_time = 35 - now_utc.second
    if wait_time < 0:
        print(str(now_utc.minute) + ':' + str(now_utc.second))
        print('Error in waiting time')
        time.sleep(wait_time + 35)
    else:
        time.sleep(wait_time)

    try:
        last_pulse = get_json(CLCERT_BEACON_URL + PULSE_PREFIX + "last")
    except (BeaconServerError, BeaconPulseError):
        print('ERROR IN SERVER\t\t ' + str(now_utc.replace(second=0, microsecond=0)))
        now_utc = datetime.datetime.now()
        time_to_wait = (60 - now_utc.second - 1) + second_mark_init + ((1000000 - now_utc.microsecond) / 1000000)
        time.sleep(time_to_wait)
        continue

    last_pulse_id = int(last_pulse["id"])

    try:
        last_pulse_raw_events = get_json(CLCERT_BEACON_URL + RAW_PREFIX + "id/" + str(last_pulse_id + 1))
    except (BeaconServerError, BeaconPulseError):
        print('ERROR IN SERVER\t\t ' + str(now_utc.replace(second=0, microsecond=0)))
        now_utc = datetime.datetime.now()
        time_to_wait = (60 - now_utc.second - 1) + second_mark_init + ((1000000 - now_utc.microsecond) / 1000000)
        time.sleep(time_to_wait)
        continue

    last_pulse_earthquake_raw_value = ''
    last_pulse_earthquake_status = 0
    last_pulse_radio_raw_value = ''
    last_pulse_radio_status = 0
    last_pulse_twitter_raw_value = ''
    last_pulse_twitter_status = 0
    last_pulse_ethereum_raw_value = ''
    last_pulse_ethereum_status = 0
    for event in last_pulse_raw_events:
        if event["source_id"] == 1:
            last_pulse_earthquake_raw_value = event["raw_value"]
            last_pulse_earthquake_status = event["status_code"]
        elif event["source_id"] == 2:
            last_pulse_twitter_raw_value = event["raw_value"]
            last_pulse_twitter_status = event["status_code"]
        elif event["source_id"] == 3:
            last_pulse_radio_raw_value = event["raw_value"]
            last_pulse_radio_status = event["status_code"]
        elif event["source_id"] == 4:
            last_pulse_ethereum_raw_value = event["raw_value"]
            last_pulse_ethereum_status = event["status_code"]

    # Check differences between what verifier collected and what the beacon reported
    current_time = str(now_utc.replace(second=0, microsecond=0))
    if options.eq_check:
        check_eq_event(earthquake_event, last_pulse_earthquake_raw_value, last_pulse_earthquake_status, current_time)

    if options.radio_check:
        if radio_event != last_pulse_radio_raw_value:
            if radio_event != 'timeout error':
                if last_pulse_radio_status == 0:
                    print('ERROR RADIO\t\t\t ' + current_time)
                else:
                    print('EVENT ERROR RADIO ' + current_time)
            else:
                print('TIMEOUT RADIO\t\t ' + current_time)

    if options.tw_check:
        if twitter_event != last_pulse_twitter_raw_value:
            if twitter_event != 'timeout error':
                if last_pulse_twitter_status == 0:
                    print('ERROR TWITTER\t\t\t ' + current_time)
                else:
                    print('EVENT ERROR TWITTER ' + current_time)
            else:
                print('TIMEOUT TWITTER\t\t ' + current_time)

    if options.block_check:
        if check_eth_event(ethereum_event, last_pulse_ethereum_raw_value, last_pulse_ethereum_status, current_time) == 0:
            print("success!\t" + current_time)

    # Wait until the next minute
    now_utc = datetime.datetime.utcnow()
    time_to_wait = (60 - now_utc.second - 1) + second_mark_init + ((1000000 - now_utc.microsecond) / 1000000)
    time.sleep(time_to_wait)
