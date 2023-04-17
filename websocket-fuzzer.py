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


# Payload parsing is optimized for JSON, if other message types are used, change parsing here
def payload_parsing(payload):
    payload = payload.replace('"', '\\"')
    return payload


def fuzzer(cookie, hostname, url, fuzz_values_file, websocket_messages_file, proxy_host, proxy_port, timeout, verbose):
    websocket.enableTrace(verbose)

    # Read fuzzing payloads from text file
    with open(fuzz_values_file, "r") as f:
        fuzz_values = [payload_parsing(line.rstrip('\n')) for line in f.readlines()]

    # Read WebSocket message from text file
    with open(websocket_messages_file, "r") as messages_file:
        premessage_count = 0
        premessages = []

        for websocket_message in messages_file:
            websocket_message = websocket_message.strip()

            if websocket_message.startswith("PRE_MESSAGE"):
                premessage_count += 1
                premessages.append(websocket_message.replace("PRE_MESSAGE", "").strip())
            else:
                for fuzz_value in fuzz_values:
                    # Create the WebSocket
                    if proxy_host is None:
                        ws = websocket.WebSocket()
                        ws.connect("wss://"+hostname+url, cookie=cookie, origin="https://"+hostname)
                    else:
                        ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
                        ws.connect("wss://"+hostname+url, cookie=cookie, origin="https://"+hostname,
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
                    
                    # Receive answers for 3 seconds and process them
                    while True:
                        try:
                            ws.settimeout(timeout)
                            result = ws.recv()
                            print("Received response with length: " + str(len(result)) + " on time: "
                                   + datetime.datetime.now().strftime('%H:%M:%S %d.%m.%Y'))
                        except websocket._exceptions.WebSocketException:
                            break
                    ws.close()

                premessages = []
                premessage_count = 0


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Simple WebSocket fuzzer: Manuall analysis of results needed!')
    parser.add_argument('-c', '--cookie', type=str, help='Specifies a cookie for setting up WebSocket')
    parser.add_argument('-f', '--fuzz_file', type=str, 
                        help='File which contains the fuzzing attack payloads, one payload per line', required=True)
    parser.add_argument('-m', '--message_file', type=str, 
                        help='File which contains the WebSocket messages prepared to be fuzzed. The string FUZZ_VALUE will be ' 
                        + 'replaced with the content of the fuzzing payloads file. If non fuzzed pre messages are required before successfully '
                        + 'fuzzing a message, list those pre messages line by line before the actual message and start them with PRE_MESSAGE', required=True)
    parser.add_argument('-p', '--proxy', type=str, help='Specifies proxy in format proxy:port')
    parser.add_argument('-t', '--timeout', type=int, help='Specifies how long a WebSocket connection is kept open to receive responses', default=3)
    parser.add_argument('-u', '--url_path', type=str, help='URL path where protocol switching happens', default="/")
    parser.add_argument('-v', '--verbose', action='store_true', help='Increases program output in the console', default=False)
    parser.add_argument('hostname', type=str, help='Hostname of the system to fuzz')
    args = parser.parse_args()

    proxy = args.proxy
    if proxy is not None:
        if ":" in proxy:
            proxy_host = proxy.split(":")[0]
            proxy_port = proxy.split(":")[1]
        else:
            print("The proxy needs to be defined in the format hostname:port or ip:port!")
            sys.exit(1)

    fuzzer(args.cookie, args.hostname, args.url_path, args.fuzz_file, args.message_file, proxy_host, proxy_port, args.timeout, args.verbose)


if __name__ == "__main__":
    main()