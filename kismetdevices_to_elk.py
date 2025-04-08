import re
import glob
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
import json
import argparse
import subprocess
import csv
import datetime

version = "1.1"
print(
    """
 __    __   ____  __    __  __  _    ___  _      __  _ 
|  |__|  | /    ||  |__|  ||  |/ ]  /  _]| |    |  |/ ]
|  |  |  ||  o  ||  |  |  ||  ' /  /  [_ | |    |  ' / 
|  |  |  ||     ||  |  |  ||    \ |    _]| |___ |    \ 
|  `  '  ||  _  ||  `  '  ||     ||   [_ |     ||     |
 \      / |  |  | \      / |  .  ||     ||     ||  .  |
  \_/\_/  |__|__|  \_/\_/  |__|\_||_____||_____||__|\_|
                                                       
"""
)
print("Version " + str(version))

device_arr = {}

# given file input from command line
parser = argparse.ArgumentParser(description="Parse kismetdb files to ELK")
parser.add_argument(
    "-i",
    dest="input",
    action="store",
    help="Path to the directory containing *.kismet files\n",
    required=True,
)
parser.add_argument(
    "-e",
    dest="es",
    action="store",
    help="Elasticsearch IP address; default is localhost\n",
    required=False,
    default="localhost",
)
parser.add_argument(
    "-u",
    dest="username",
    action="store",
    help="Elasticsearch username; default is user\n",
    required=False,
    default="user",
)
parser.add_argument(
    "-p",
    dest="password",
    action="store",
    help="Elasticsearch password\n",
    required=True,
)
args = parser.parse_args()


def es_connect():
    host = str(args.es)
    port = 9200
    es_username = str(args.username)
    es_password = str(args.password)
    es = Elasticsearch([host], basic_auth=(es_username, es_password))
    # print(es.info())
    if es.ping():
        print("[+] Connection established to Elasticsearch")
    else:
        print("[!] Connect to Elasticsearch failed")
        print(
            "Host: "
            + str(host)
            + ", Username: "
            + es_username
            + ", Password: "
            + es_password
        )
        exit(0)
    return es


def es_create_index(es, es_index_name="test_index"):
    created = False
    # index settings
    settings = {
        "settings": {"index.mapping.depth.limit": 20},
        "mappings": {
            "dynamic": "true",
            "numeric_detection": False,
            "properties": {
                "@timestamp": {
                    "type": "date",
                    "format": "yyyy-MM-dd HH:mm:ss||yyyy-MM-dd||epoch_millis",
                },
                "kismet_device_base_location_avg_geopoint": {"type": "geo_point"},
                "kismet_device_base_location": {
                    "type": "nested",
                    "dynamic": "false",
                    "properties": {
                        "kismet_common_location_avg_loc": {
                            "type": "nested",
                            "dynamic": "false",
                            "properties": {
                                "kismet_common_location_geopoint": {"type": "geo_point"}
                            },
                        },
                        "kismet_common_location_last": {
                            "type": "nested",
                            "dynamic": "false",
                            "properties": {
                                "kismet_common_location_geopoint": {"type": "geo_point"}
                            },
                        },
                        "kismet_common_location_max_loc": {
                            "type": "nested",
                            "dynamic": "false",
                            "properties": {
                                "kismet_common_location_geopoint": {"type": "geo_point"}
                            },
                        },
                        "kismet_common_location_min_loc": {
                            "type": "nested",
                            "dynamic": "false",
                            "properties": {
                                "kismet_common_location_geopoint": {"type": "geo_point"}
                            },
                        },
                    },
                },
                "kismet_device_base_signal": {
                    "type": "nested",
                    "dynamic": "false",
                    "properties": {
                        "kismet_common_signal_peak_loc": {
                            "type": "nested",
                            "properties": {
                                "kismet_common_location_geopoint": {"type": "geo_point"}
                            },
                        }
                    },
                },
                # "kismet_device_base_tx_packets_rrd": {
                #    "type": "nested",
                #    "properties": {
                #        "kismet_common_rrd_day_vec": {"type": "float"},
                #        "kismet_common_rrd_hour_vec": {"type": "float"},
                #    },
                # },
                # "kismet_device_base_rx_packets_rrd": {
                #    "type": "nested",
                #    "properties": {
                #        "kismet_common_rrd_hour_vec": {"type": "float"},
                #        "kismet_common_rrd_day_vec": {"type": "float"},
                #    },
                # },
                # "kismet_device_base_seenby": {
                #    "type": "nested",
                #    "properties": {
                #        "kismet_common_seenby_source": {
                #            "type": "nested",
                #            "properties": {
                #                "kismet_datasource_packets_datasize_rrd": {
                #                    "type": "object",
                #                    "properties": {
                #                        "kismet_common_rrd_hour_vec": {"type": "float"},
                #                        "kismet_common_rrd_day_vec": {"type": "float"},
                #                    },
                #                },
                #                "kismet_datasource_packets_rrd": {
                #                    "type": "object",
                #                    "properties": {
                #                        "kismet_common_rrd_day_vec": {"type": "float"},
                #                        "kismet_common_rrd_hour_vec": {"type": "float"},
                #                    },
                #                },
                #            },
                #        }
                #    },
                # },
                # "kismet_device_base_packets_rrd": {
                #    "type": "object",
                #    "properties": {
                #        "kismet_common_rrd_hour_vec": {"type": "float"},
                #        "kismet_common_rrd_day_vec": {"type": "float"},
                #    },
                # },
                "dot11_device": {
                    "type": "nested",
                    "dynamic": "false",
                    "properties": {
                        "dot11_device_advertised_ssid_map": {
                            "type": "nested",
                            "properties": {
                                "advertisedssid": {
                                    "type": "nested",
                                    "properties": {
                                        "wps_model_number": {"type": "text"}
                                    },
                                }
                            },
                        }
                    },
                },
            },
        },
    }

    try:
        if not es.indices.exists(index=es_index_name):
            es.indices.create(index=es_index_name, body=settings)
            print("[+] Created ES index named " + str(es_index_name))
        created = True
    except Exception as ex:
        print(str(ex))
    finally:
        return created


def convert_kismetdbtojson(dbfile):
    try:
        process = subprocess.Popen(
            ["kismetdb_dump_devices", "--in", dbfile, "--out", "-", "-s", "-j"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except:
        print(
            "Problem with running kismetdb_dump_devices - do you have this installed?"
        )
        exit(0)

    stdout, stderr = process.communicate()
    # print(stdout)
    if stderr:
        print("[!] Error with parsing " + str(dbfile) + " -- " + str(stderr))
        return False
    else:
        jsonoutput = json.loads(stdout)
        # for x in jsontest:
        #    print(x['kismet_device_base_type'])
        return jsonoutput


def process_json(records, filename):
    blacklist_patterns = [
        "kismet_device_base_freq_khz_map",
        "kismet_device_base_location_cloud",
        "kismet_device_base_packet_bin_250",
        "kismet_device_base_seenby",
        "kismet_device_base_signal",
        r"dot11_device.dot11_device_associated_client_map.*",
        r"kismet_device_base_.*_rrd",
        "dot11_device_associated_client_map",
        r"kismet_device_base_key.keyword.*",
    ]

    # Function to check if any of the blacklist patterns match
    def should_exclude(field_name):
        for pattern in blacklist_patterns:
            if re.match(pattern, field_name):
                return True
        return False

    new_devices = []
    for x in records:
        new_row = x.copy()  # Copy the record to avoid mutating the original data
        for y in list(x.keys()):
            # If field matches a blacklist pattern, delete it
            if should_exclude(y):
                del new_row[y]

        # Special handling for the location field
        if "kismet_device_base_location" in list(x.keys()):
            if "kismet_common_location_avg_loc" in list(
                x["kismet_device_base_location"].keys()
            ):
                new_row["kismet_device_base_location_avg_geopoint"] = x[
                    "kismet_device_base_location"
                ]["kismet_common_location_avg_loc"]["kismet_common_location_geopoint"]

        new_devices.append(new_row)

    return new_devices


records_count = 0


def es_set_data(records, es_index_name):
    global records_count
    for record in records:
        # get timestamp value
        timestamp = datetime.datetime.fromtimestamp(
            record["kismet_device_base_last_time"]
        ).strftime("%Y-%m-%d %H:%M:%S")

        doc_id = record["kismet_device_base_key"]
        record["@timestamp"] = timestamp
        yield {"_index": es_index_name, "_id": doc_id, "_source": record}
        records_count += 1


def es_load(es, records, es_index_name, **kwargs):
    actions = list(es_set_data(records, es_index_name, **kwargs))
    success, failed = bulk(es, actions, stats_only=False, raise_on_error=False)

    # Check individual item responses
    for i, response in enumerate(failed):
        if "index" in response and response["index"].get("error"):
            error = response["index"]["error"]
            print(f"[!] Document {i} failed: {error}")
            # You can also log the document that caused the failure:
            # print(json.dumps(actions[i]["_source"], indent=2))

    return success


if __name__ == ("__main__"):
    print("[+] Attempting to load the provided files from folder " + str(args.input))

    # Get all *.kismet files from the provided folder
    kismet_files = glob.glob(f"{args.input}/*.kismet")

    if not kismet_files:
        print("[!] No .kismet files found in the folder")
        exit(0)

    for kismet_file in kismet_files:
        print(f"[+] Processing file: {kismet_file}")
        records = convert_kismetdbtojson(kismet_file)

        if records == False:
            print(f"[!] Skipping {kismet_file}")
        else:
            print(f"[+] Parsing {kismet_file}.")
            new_records = process_json(records, kismet_file)

            if len(new_records) > 0:
                es = es_connect()
                if es_create_index(es, "kismet_devices"):
                    print(f"[+] Let's put some data in our index for {kismet_file}...")
                    try:
                        es_load_results = es_load(es, new_records, "kismet_devices")
                    except Exception as ex:
                        print(ex)
                    # TODO Determine better method for validating documents loaded and presenting any errors
                    print(
                        f"[+] Allegedly loaded {records_count} entries from {kismet_file}."
                    )
