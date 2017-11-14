from app import application
import urllib
import json
import binascii
from flask import jsonify, url_for
from flask import render_template


base_url = json.load(application.open_resource('config.json'))['beacon-server-url']


@application.route('/verifier/1.0/check_earthquake_web/id/<record_id>')
def check_earthquake_web(record_id):
    raw_data_from_record = urllib.request.urlopen(base_url + "/beacon/1.0/raw/id/" + record_id)
    raw_data_json = json.loads(raw_data_from_record.read())

    eq_web_source_id = 1
    eq_web_object = {'earthquakes': []}

    for raw_events in raw_data_json:
        if raw_events['source_id'] is eq_web_source_id:
            raw_eq_web = raw_events["raw_value"]
            earthquakes = raw_eq_web.split('\n')
            for eq in earthquakes[:-1]:
                eq_web_object['earthquakes'].append(eq)

    return jsonify(eq_web_object)


@application.route('/verifier/1.0/check_earthquake_twitter/id/<record_id>')
def check_earthquake_twitter(record_id):
    raw_data_from_record = urllib.request.urlopen(base_url + "/beacon/1.0/raw/id/" + record_id)
    raw_data_json = json.loads(raw_data_from_record.read())

    eq_tw_source_id = 2
    eq_tw_object = {'earthquakes': []}

    for raw_events in raw_data_json:
        if raw_events['source_id'] is eq_tw_source_id:
            raw_eq_tw = raw_events['raw_value']
            earthquakes = raw_eq_tw.split('\n')
            for eq in earthquakes[:-1]:
                eq_tw_object['earthquakes'].append(eq)

    return jsonify(eq_tw_object)


@application.route('/verifier/1.0/check_trending/id/<record_id>')
def check_trending(record_id):
    url = base_url + "/beacon/1.0/raw/id/" + record_id

    raw_data_from_record = urllib.request.urlopen(url)
    raw_data_json = json.loads(raw_data_from_record.read())

    trending_source_id = 3
    trending_object = {}

    for raw_events in raw_data_json:
        if raw_events["source_id"] is trending_source_id:
            raw_trending = raw_events["raw_value"]
            trending_segments = raw_trending.split('\n')
            trending_object["topics"] = trending_segments[0]
            trending_object["tweets"] = []
            for tweet in trending_segments[1:-1]:
                trending_object['tweets'].append(tweet)

    return jsonify(trending_object)


@application.route('/verifier/1.0/check_radio/id/<record_id>')
def check_radio(record_id):
    raw_data_from_record = urllib.request.urlopen(base_url + "/beacon/1.0/raw/id/" + record_id)
    raw_data_json = json.loads(raw_data_from_record.read())

    audio_source_id = 4
    raw_audio = b''

    for raw_events in raw_data_json:
        if raw_events["source_id"] is audio_source_id:
            raw_audio = binascii.a2b_hex(raw_events["raw_value"].encode())

    return raw_audio, {'Content-Type': 'audio/aacp'}


@application.route('/')
def index():
    print("The URL for this page is {}".format(url_for("index")))
    return render_template('verifier.html')
