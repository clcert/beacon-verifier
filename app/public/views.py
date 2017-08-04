from app import application
import urllib
import json
import binascii


@application.route('/beacon/1.0/check_radio/id/<record_id>')
def check_radio(record_id):
    base_url = "http://0.0.0.0:5000"
    raw_data_from_record = urllib.request.urlopen(base_url + "/beacon/1.0/raw/id/" + record_id)
    raw_data_json = json.loads(raw_data_from_record.read())

    raw_audio = b''

    for raw_events in raw_data_json:
        if raw_events["source_id"] is 4:
            raw_audio = binascii.a2b_hex(raw_events["raw_value"].encode())

    return raw_audio, {'Content-Type': 'audio/aacp'}


@application.route('/')
def index():
    return 'Under construction...'
