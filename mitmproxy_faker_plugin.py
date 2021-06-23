"""
This example shows how to send a reply from the proxy immediately
without sending any data to the remote server.
"""

from mitmproxy import http

import sys
import json


def request(flow: http.HTTPFlow) -> None:
    if "deviceManagement/devices/macAddress" in flow.request.pretty_url:
        """
        Fake the 'userId' value for testing the onboarding process.

        The fake 'userId' value comes from 'ac_details.txt' file.
        """

        content = open("ac_details.txt", "rb").read()
        print("/DML handled locally!")
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            content,  # (optional) content
            # (optional) headers
            {"Content-Type": "application/json;charset=utf-8"}
        )
