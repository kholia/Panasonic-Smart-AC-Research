#!/usr/bin/env python3
#pylint: disable=line-too-long,invalid-name,missing-function-docstring,too-many-statements,pointless-string-statement,too-many-locals

"""
AC onboarding stuff.
"""

import requests


def pretty_print_POST(req):
    """
    At this point it is completely built and ready
    to be fired; it is "prepared".

    However pay attention at the formatting used in
    this function because it is programmed to be pretty
    printed and may differ from the actual request.
    """
    print('{}\n{}\r\n{}\r\n\r\n{}'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body,
    ))


def main():
    user_agent = "okhttp/3.13.1"
    headers = {
            'User-Agent': user_agent,
            'Accept-Encoding': "gzip",
    }

    # login
    client_id = "PBcMcfG19njNCL8AOgvRzIC8AjQa"
    mobile_number, password, ac_mac = open("credentials.txt").read().rstrip().split()  # provide your own values here
    data = {"clientId": client_id, "mobile": "+91%s" % mobile_number, "password": password, "scope": ""}
    url = "https://auth.miraie.in/simplifi/v1/userManagement/login"
    req = requests.Request('POST', url, headers=headers, json=data)
    prepared = req.prepare()
    pretty_print_POST(prepared)
    s = requests.Session()
    r = s.send(prepared)
    assert r.status_code == 200
    data = r.json()
    with open("login_data.txt", "w") as f:
        f.write(r.text)

    # extract auth data
    userId = data["userId"]
    accessToken = data["accessToken"]
    print(userId, accessToken)
    headers = {
            'User-Agent': user_agent,
            'Accept-Encoding': "gzip",
            "Authorization": "Bearer %s" % accessToken,
    }

    # grab user details
    url = "https://auth.miraie.in/simplifi/v1/userManagement/users"
    req = requests.Request('GET', url, headers=headers)
    prepared = req.prepare()
    pretty_print_POST(prepared)
    r = s.send(prepared)
    print(r.text)

    # get "home" details
    url = "https://app.miraie.in/simplifi/v1/homeManagement/homes"
    req = requests.Request('GET', url, headers=headers)
    prepared = req.prepare()
    pretty_print_POST(prepared)
    r = s.send(prepared)
    print(r.json())
    data = r.json()[0]
    spaceId = data["spaces"][0]["spaceId"]
    homeId = data["homeId"]
    print(spaceId, homeId, userId)
    with open("home_plus_user_details.txt", "w") as f:
        f.write(r.text)

    # called during onboarding, important, buggy (allows snooping on other devices by changing the mac address)
    url = "https://app.miraie.in/simplifi/v1/deviceManagement/devices/macAddress/%s" % ac_mac
    req = requests.Request('GET', url, headers=headers)
    prepared = req.prepare()
    pretty_print_POST(prepared)
    r = s.send(prepared)
    data = r.json()[0]
    # deviceId = data["deviceId"]
    # firmwareVersion = data["firmwareVersion"]
    deviceRegistrationTokenEncrypted = data["deviceRegistrationTokenEncrypted"]
    devicePublicKey = data["devicePublicKey"]
    with open("device_public_key.txt", "w") as f:
        f.write(devicePublicKey)
    with open("ac_details.txt", "w") as f:
        f.write(r.text)

    print(homeId, spaceId, userId, deviceRegistrationTokenEncrypted)


if __name__ == "__main__":
    main()
