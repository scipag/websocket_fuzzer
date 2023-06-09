# WebSocket Fuzzer

_WebSocket Fuzzer_ is a simple WebSocket fuzzing script. Part of its creation process is described in the article [WebSocket Fuzzing - Development of a custom fuzzer](https://www.scip.ch/en/?labs.20230420).

## Installation and usage

The script only runs with Python 3. To install the necessary modules use `pip3 install -r requirements.txt`.

It is generally recommended to use a proxy like Burp Suite or OWASP ZAP to record the WebSocket traffic which is created by this script since this script does not generate a log file of all the messages that have been sent. Furthermore, the analysis of all the generated server responses has to happen manually by the tester. The script creates a new WebSocket for every fuzzed message and closes it again after processing the response. This was done since it could not be guaranteed that a WebSocket was still valid after a previous fuzzing round.

Common execution examples for the WebSocket Fuzzer would be:

```bash
# fuzz http://example.com with specified session cookie and proxy
python3 websocket-fuzzer.py -c "session=example_value" -f fuzzing_payloads.txt -m websocket_messages.txt -p "127.0.0.1:8080" http://example.com

# fuzz https://example.com with specified Authorization header and proxy, includes a timout of 5 seconds to wait for responses and runs in verbose mode
python3 websocket-fuzzer.py -a "Authorization: Bearer <token>" -f fuzzing_payloads.txt -m websocket_messages.txt -p "127.0.0.1:8080" -t 5 -v https://example.com
```

The script was developed for fuzzing websocket applications which send their messages with JSON. If this is not the case for you, please customize the following function: `payload_parsing`.

## Usage options

```
usage: websocket-fuzzer.py [-h] [-a AUTH_HEADER] [-c COOKIE] [-e ERROR_MESSAGES] -f FUZZ_FILE -m MESSAGE_FILE [-p PROXY] [-t TIMEOUT] [-u URL_PATH] [-v] [--version] target

Simple WebSocket fuzzer: Manuall analysis of results needed! Author: Andrea Hauser - scip AG

positional arguments:
  target                Defines target to fuzz in format protocol://hostname:port where protocol is either http/https and :port is optional

options:
  -h, --help            show this help message and exit
  -a AUTH_HEADER, --auth_header AUTH_HEADER
                        Sets user defined header(s), for applications which are not using cookies.
                        For multiple headers use option more than once
  -c COOKIE, --cookie COOKIE
                        Specifies a cookie for setting up WebSocket
  -e ERROR_MESSAGES, --error_messages ERROR_MESSAGES
                        Specifies what error messages a potential response should be analyzed for. Expected format
                        is a comma separated string like value1,value2. The default strings that will be looked for
                        are error, stacktrace and trace
  -f FUZZ_FILE, --fuzz_file FUZZ_FILE
                        File which contains the fuzzing attack payloads, one payload per line
  -m MESSAGE_FILE, --message_file MESSAGE_FILE
                        File which contains the WebSocket messages prepared to be fuzzed. Assumes one message per line.
                        The string FUZZ_VALUE will be replaced with the content of the fuzzing payloads file.
                        If non fuzzed pre messages are required before successfully fuzzing a message, list those
                        pre messages line by line before the actual message and start them with PRE_MESSAGE
  -p PROXY, --proxy PROXY
                        Specifies proxy in format proxy:port
  -t TIMEOUT, --timeout TIMEOUT
                        Specifies how long a WebSocket connection is kept open to receive responses
  -u URL_PATH, --url_path URL_PATH
                        URL path where protocol switching happens
  -v, --verbose         Increases program output in the console
  --version             show program's version number and exit
```

## Examples

The _examples_ directory contains example files which show what potential _fuzzing\_payloads_ and _websocket\_messages_ files need to look like.

If _websocket\_messages.txt_ contains the following values:
```
PRE_MESSAGE READY
{"message":"FUZZ_VALUE"}
{"other":"FUZZ_VALUE"}
```

and the _fuzzing\_payloads.txt_ file contains the following values:
```
<img src=1 onerror='alert(1)'>
sql test with space '-- 
```

the script will send `READY` as a pre message for the message where it was specified befor sending a fuzzed message.

Therefore the script will send the following WebSocket messages with the provided example files:

```
READY
{"message":"<img src=1 onerror='alert(1)'>"}
READY
{"message":"sql test with space '-- "}
{"other":"<img src=1 onerror='alert(1)'>"}
{"other":"sql test with space '-- "}
```

## Ideas for future enhancements

- [x] The established WebSocket connection is closed again relatively quickly after sending the fuzzed messages. The aim is to build in a timeout so that the response time of the server can also be somewhat longer and still be captured. A good balance must be found between extending the time to fuzz and the time to wait for delayed responses.
- [x] Currently the script can only be used with cookies. This should be generalised so that other authentication methods such as Authentication: Bearer can also be used.
- [x] Despite the initially contrary decision, it could still be helpful to include a primitive detection option for successful attacks in the script, for example matching on error or stack trace or similar, so that the tester already has some good ideas for further manual investigations.
- [x] Including a progress indicator could be helpful for the tester, as it is currently difficult to see how many payloads the script has already processed if there are many payloads in the fuzzing file.
