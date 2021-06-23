#!/usr/bin/env python3
#pylint: disable=line-too-long,invalid-name,missing-function-docstring,too-many-statements,pointless-string-statement,too-many-locals

"""
$ openssl s_client -connect mqtt.miraie.in:8883
CONNECTED(00000003)
...
"""

import ssl
import sys
import json
import time

import paho.mqtt.client as mqtt


# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("[v] Connected with result code "+str(rc))
    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    # client.subscribe("$SYS/#")
    topic = "%s/%s/#" % (userId, homeId)
    topic_control_publish = "%s/%s/%s/control" % (userId, homeId, deviceId)
    print("[+] Subscribing to topic '%s'" % topic)
    client.subscribe(topic)

    # off -> b'{"ps":"off","ki":0,"cnt":"an","sid":"0"}
    # on -> b'{"ps":"on","ki":0,"cnt":"an","sid":"0"}

    msg_0 = {"ps":"on","ki":0,"cnt":"an","sid":"0"}
    client.publish(topic_control_publish, json.dumps(msg_0))

    msg_1 = {"acmd":"auto","ki":0,"cnt":"an","sid":"0"}
    if len(sys.argv) > 1:
        temperature = int(sys.argv[1])
    else:
        temperature = 30
    msg_2 = {"actmp":"%s.0" % temperature,"ki":0,"cnt":"an","sid":"0"}
    client.publish(topic_control_publish, json.dumps(msg_1))
    client.publish(topic_control_publish, json.dumps(msg_2))

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    print(msg.topic+" "+str(msg.payload))

# grab "auth" data
with open("login_data.txt") as f:
    login_data = json.loads(f.read())
    userId = login_data["userId"]
    accessToken = login_data["accessToken"]
with open("home_plus_user_details.txt") as f:
    home_plus_user_details = json.loads(f.read())[0]
    homeId = home_plus_user_details["homeId"]
with open("ac_details.txt") as f:
    ac_details = json.loads(f.read())[0]
    deviceId = ac_details["deviceId"]

print(homeId, accessToken, userId)

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message
client.tls_set("/etc/ssl/certs/ca-certificates.crt", tls_version=ssl.PROTOCOL_TLSv1_2)
client.tls_insecure_set(True)
client.username_pw_set(username=homeId, password=accessToken)
client.connect("mqtt.miraie.in", 8883, 60)

# Blocking call that processes network traffic, dispatches callbacks and
# handles reconnecting.
# Other loop*() functions are available that give a threaded interface and a
# manual interface.
client.loop_forever()


if __name__ == "__main__":
    main()
