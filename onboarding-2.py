#!/usr/bin/env python3

"""
Onboarding crypto code.
"""

import sys
import json
import socket
import binascii

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# grab "auth" data
with open("login_data.txt") as f:
    login_data = json.loads(f.read())
    userId = login_data["userId"]
    accessToken = login_data["accessToken"]
with open("home_plus_user_details.txt") as f:
    home_plus_user_details = json.loads(f.read())[0]
    homeId = home_plus_user_details["homeId"]
    spaceId = home_plus_user_details["spaces"][0]["spaceId"]
with open("ac_details.txt") as f:
    ac_details = json.loads(f.read())[0]
    deviceId = ac_details["deviceId"]
    deviceRegistrationTokenEncrypted = ac_details["deviceRegistrationTokenEncrypted"]

# print(homeId, spaceId, accessToken, userId)

"""
After fixing the AONB ("Already Onboarded") problem, we are now running into
the 116 error code which is perfectly reasonable ;)

D2M_MSG_ALL_OK = 201
D2M_MSG_ALL_SUCCESS = 200
D2M_MSG_REGISTRATION_DEVICE_ALREADY_ADDED = 0x74  // 116 <-- We are running into this!
"""

def main():
    onboardingPayload = {
            "BSSID": "90:???",
            "deviceName": "???",
            "homeId": homeId,
            "useProd": "1",
            "spaceId": spaceId,
            "userId": userId,
            "wifipassword": "???",
            "wifissid": "???" }

    key = b'\x00' * 32  # for AES-256
    iv = b'\x00' * 16

    # encrypt payload
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    from cryptography.hazmat.primitives import padding
    padder = padding.PKCS7(128).padder()
    # data = b'12345678'
    data = json.dumps(onboardingPayload).encode("utf-8")
    padded_data = padder.update(data) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    payload = binascii.hexlify(ct).decode("ascii")

    # encrypt key + iv with public key
    with open("device_public_key.txt", "rb") as f:
        devicePublicKey = serialization.load_pem_public_key(f.read())
    ckey = devicePublicKey.encrypt(key, apadding.PKCS1v15())
    ckey = binascii.hexlify(ckey).decode("ascii")
    civ = devicePublicKey.encrypt(iv, apadding.PKCS1v15())
    civ = binascii.hexlify(civ).decode("ascii")

    encryptedPayload = {
            "deviceRegistrationToken": deviceRegistrationTokenEncrypted,
            "iv": civ,
            "key": ckey,
            "payload": payload,
            "version": "1.0"
    }
    print(encryptedPayload)
    final_payload = json.dumps(encryptedPayload).encode("utf-8")

    HOST = '192.168.4.1'  # The server's hostname or IP address
    PORT = 443            # The port used by the server

    initial_payload = b"""{"type": "ob", "size": %d}""" % len(final_payload)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(initial_payload)
        data = s.recv(10240)
        print('Received', repr(data))
        s.sendall(final_payload)
        data = s.recv(10240)
        print('Received', repr(data))

if __name__ == "__main__":
    main()
