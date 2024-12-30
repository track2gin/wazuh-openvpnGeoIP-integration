#!/var/ossec/framework/python/bin/python3

import json
import sys
import time
import os
import requests
from socket import socket, AF_UNIX, SOCK_DGRAM


alert = {}
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = "{0}/queue/sockets/queue".format(pwd)


def send_event(msg, agent=None):
    if not agent or agent["id"] == "000":
        string = "1:geoip:{0}".format(json.dumps(msg))
    else:
        string = "1:[{0}] ({1}) {2}->geoip:{3}".format(
            agent["id"],
            agent["name"],
            agent["ip"] if "ip" in agent else "any",
            json.dumps(msg),
        )
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()


def query_api(srcip):
  headers = {
    'Accept': 'application/json',
  }

  response = requests.get(f'https://api.sypexgeo.net/json/{srcip}', headers=headers)
  if response.status_code == 200:
      json_response = response.json()
      region = json_response["region"]["name_en"] + " (" + json_response["country"]["name_en"] + ")"
      if region.startswith('Tver'):
         return 0
      else:
         return region
  else:
      alert_output = {}
      alert_output["geoip"] = {}
      alert_output["integration"] = "custom-geoip"
      json_response = response.json()
      alert_output["geoip"]["error"] = response.status_code
      alert_output["geoip"]["description"] = json_response["errors"][0]["detail"]
      send_event(alert_output)
      exit(0)


def request_geoip_info(alert):
    alert_output = {}

    if not "srcip" in alert["data"]:
       return(0)

    data = query_api(alert["data"]["srcip"])

    if data:
       alert_output["geoip"] = {}
       alert_output["integration"] = "custom-geoip"
       alert_output["geoip"]["source"] = {}
       alert_output["geoip"]["source"]["alert_id"] = alert["id"]
       alert_output["geoip"]["source"]["rule"] = alert["rule"]["id"]
       alert_output["geoip"]["source"]["description"] = alert["rule"]["description"]
       alert_output["geoip"]["source"]["full_log"] = alert["full_log"]
       alert_output["geoip"]["source"]["srcip"] = alert["data"]["srcip"]
       alert_output["geoip"]["source"]["srcuser"] = alert["data"]["srcuser"]
       alert_output["geoip"]["region"] = data
       return alert_output
    else:
       return 0



if __name__ == "__main__":
    alert_file_location = sys.argv[1]

    with open(alert_file_location) as alert_file:
      alert = json.load(alert_file)

    msg = request_geoip_info(alert)
    if msg:
       send_event(msg, alert["agent"])
