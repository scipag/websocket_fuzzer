#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Provides a simple WebSocket fuzzer. Analysis of the results must still happen manually after running this script.
"""

import websocket
import ssl
import argparse
import sys
import datetime

__version__ = "2.0.0"
__author__ = "Andrea Hauser - scip AG"

class colors:
    RED = '\033[31m'
    ENDC = '\033[m'

# Payload parsing is optimized for JSON, if other message types are used, change parsing here
def payload_parsing(payload):
    payload = payload.replace('"', '\\"')
    return payload


def fuzzer(auth_header, cookie, target, url, fuzz_values_file, websocket_messages_file, proxy_host, proxy_port, timeout, verbose, error_messages):
    websocket.enableTrace(verbose)

    if target.startswith("https://"):
        wss_target = "wss://" + target.split("https://")[1]
    else:
        wss_target = "ws://" + target.split("http://")[1]

    # Read fuzzing payloads from text file
    with open(fuzz_values_file, "r") as f:
        fuzz_values = [payload_parsing(line.rstrip('\n')) for line in f.readlines()]
        fuzz_total = len(fuzz_values)

    # Read WebSocket message from text file
    with open(websocket_messages_file, "r") as messages_file:
        premessage_count = 0
        message_count = 0
        premessages = []

        for websocket_message in messages_file:
            websocket_message = websocket_message.strip()
            message_count += 1

            if websocket_message.startswith("PRE_MESSAGE"):
                premessage_count += 1
                premessages.append(websocket_message.replace("PRE_MESSAGE", "").strip())
            else:
                fuzz_count = 0
                for fuzz_value in fuzz_values:
                    fuzz_count += 1
                    # Create the WebSocket
                    if proxy_host is None:
                        ws = websocket.WebSocket()
                        ws.connect(wss_target+url, cookie=cookie, header=auth_header, origin=target)
                    else:
                        ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
                        ws.connect(wss_target+url, cookie=cookie, header=auth_header, origin=target, 
                                   http_proxy_host=proxy_host, http_proxy_port=proxy_port, proxy_type="http")

                    # Send pre messages if there are any
                    if premessage_count > 0:
                        for premessage in premessages:
                            ws.send(premessage)
                            print("\n<----> Pre message that was sent: " + premessage)

                    # Replace FUZZ_VALUE with attack payload from the file
                    message = websocket_message.replace("FUZZ_VALUE", fuzz_value)

                    # Send the fuzzed message over the WebSocket connection
                    ws.send(message)
                    print("\n<----> WebSocket message that was sent/fuzzed: " + message)
                    print("<----> Fuzzing message " + str(fuzz_count) + " of " + str(fuzz_total) + " sent for WebSocket message on line " + str(message_count))

                    # Receive answers for specified amount of seconds and process them
                    while True:
                        try:
                            ws.settimeout(timeout)
                            result = ws.recv()
                            print("Received response with length: " + str(len(result)) + " on time: "
                                   + datetime.datetime.now().strftime('%H:%M:%S %d.%m.%Y'))

                            for error_message in error_messages:
                                if error_message in result.lower():
                                    print(colors.RED + "The sent fuzz value " + message + " should be checked further, response contains " + error_message + colors.ENDC)
                        except websocket._exceptions.WebSocketException:
                            break
                    ws.close()

                premessages = []
                premessage_count = 0


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Simple WebSocket fuzzer: Manuall analysis of results needed! Author: ' + __author__)
    parser.add_argument('-a', '--auth_header', action='append', help='Sets user defined header(s), for applications which are not using cookies. '
                        + 'For multiple headers use option more than once', default=[])
    parser.add_argument('-c', '--cookie', type=str, help='Specifies a cookie for setting up WebSocket')
    parser.add_argument('-e', '--error_messages', help='Specifies what error messages a potential response should be analyzed for. '
                        + 'Expected format is a comma separated string like value1,value2. The default strings that will be looked '
                        + 'for are error, stacktrace and trace', default='error,stacktrace,trace')
    parser.add_argument('-f', '--fuzz_file', type=str, 
                        help='File which contains the fuzzing attack payloads, one payload per line', required=True)
    parser.add_argument('-m', '--message_file', type=str, 
                        help='File which contains the WebSocket messages prepared to be fuzzed. Assumes one message per line. The string FUZZ_VALUE '
                        + 'will be replaced with the content of the fuzzing payloads file. If non fuzzed pre messages are required before successfully '
                        + 'fuzzing a message, list those pre messages line by line before the actual message and start them with PRE_MESSAGE', required=True)
    parser.add_argument('-p', '--proxy', type=str, help='Specifies proxy in format proxy:port')
    parser.add_argument('-t', '--timeout', type=int, help='Specifies how many seconds a WebSocket connection is kept open to receive responses', default=3)
    parser.add_argument('-u', '--url_path', type=str, help='URL path where protocol switching happens', default="/")
    parser.add_argument('-v', '--verbose', action='store_true', help='Increases program output in the console', default=False)
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('target', type=str, help='Defines target to fuzz in format protocol://hostname:port where protocol is either http/https and :port is optional')
    args = parser.parse_args()

    proxy = args.proxy
    if proxy is not None:
        if ":" in proxy:
            proxy_host = proxy.split(":")[0]
            proxy_port = proxy.split(":")[1]
        else:
            print("The proxy needs to be defined in the format hostname:port or ip:port!")
            sys.exit(1)
    else:
        proxy_host = None
        proxy_port = None

    if not args.target.startswith("http://") is not args.target.startswith("https://"):
        print("The target needs to be defined in the format protocol://hostname:port where protocol is either http or https!")
        sys.exit(1)

    error_messages = args.error_messages.split(',')

    fuzzer(args.auth_header, args.cookie, args.target, args.url_path, args.fuzz_file, args.message_file, proxy_host, proxy_port, args.timeout, args.verbose, error_messages)


if __name__ == "__main__":
    main()
