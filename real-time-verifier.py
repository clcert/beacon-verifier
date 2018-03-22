# Real time script that verifies that the data extracted by the
# collectors is the same public data that this host can observe.

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


CLCERT_BEACON_URL = "http://www/"
PULSE_PREFIX = "beacon/1.0/pulse/"
RAW_PREFIX = "beacon/1.0/raw/"
requests.packages.urllib3.disable_warnings()  # Disable warning for self signed certificate


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
            single_earthquake = "%s %s %s %s %s %s" % (params[0], params[2], params[3], params[4], params[5], params[6])
            earthquakes.append(single_earthquake)

        raw_result = truncate_data(earthquakes[0])

        self.que.put(('earthquake', raw_result))


def get_json(url):
    time.sleep(0.05)  # Prevent 'Too Many Requests' response from server
    try:
        return json.loads(requests.get(url, verify=False).content)  # TODO: change for not self signed certificate
    except ConnectionError:
        raise BeaconServerError
    except JSONDecodeError:
        raise BeaconPulseError


# PARSE OPTIONS
parser = argparse.ArgumentParser(description="Real-Time Script for External Events collected by CLCERT Random Beacon")
parser.add_argument("-w", "--beacon-web",
                    action="store", dest="beacon_web", default="", type=str,
                    help="beacon server web host")
options = parser.parse_args()

print("CLCERT Random Beacon - Real-Time Verifier")

# CHECK BEACON HOST OPTION
if options.beacon_web != "":
    CLCERT_BEACON_URL = options.beacon_web

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

    t0 = threading.Thread(target=EarthquakeWeb(q, 'e').process)
    # t1 = threading.Thread(target=TrendingTwitter(q, 't').process)
    t2 = threading.Thread(target=RadioStream(q, 'r').process)

    threads.append(t0)
    # threads.append(t1)
    threads.append(t2)

    # Start all threads
    for t in threads:
        t.start()

    # Wait all threads to finish
    for t in threads:
        t.join()

    radio_event = ''
    earthquake_event = ''
    # twitter_event = ''

    while not q.empty():
        element = q.get()
        if element[0] == 'radio':
            radio_event = element[1]
        elif element[0] == 'earthquake':
            earthquake_event = element[1]
        # elif element[0] == 'twitter':
            # twitter_event = element[1]

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
    # last_pulse_twitter_raw_value = ''
    # last_pulse_twitter_status = 0
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

    # Check differences between what verifier collected and what the beacon reported
    current_time = str(now_utc.replace(second=0, microsecond=0))
    if earthquake_event != last_pulse_earthquake_raw_value:
        if earthquake_event != 'timeout error':
            if last_pulse_earthquake_status == 0:
                print('ERROR EARTHQUAKE\t ' + current_time)
            else:
                print('EVENT ERROR EARTHQUAKE ' + current_time)
        else:
            print('TIMEOUT EARTHQUAKE\t ' + current_time)

    if radio_event != last_pulse_radio_raw_value:
        if radio_event != 'timeout error':
            if last_pulse_radio_status == 0:
                print('ERROR RADIO\t\t\t ' + current_time)
            else:
                print('EVENT ERROR RADIO ' + current_time)
        else:
            print('TIMEOUT RADIO\t\t ' + current_time)

    # if twitter_event != last_pulse_twitter_raw_value:
        # print('ERROR TWITTER ' + str(now.replace(second=0, microsecond=0)))

    # Wait until the next minute
    now_utc = datetime.datetime.utcnow()
    time_to_wait = (60 - now_utc.second - 1) + second_mark_init + ((1000000 - now_utc.microsecond) / 1000000)
    time.sleep(time_to_wait)
