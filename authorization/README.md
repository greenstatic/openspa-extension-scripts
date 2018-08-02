# Authorization Extension Script
The `authorization.py` script is meant to be a jump-off point to allow custom
authorization. The script as is will allow any verified client device
access to the requested server ip for a duration of 3 minutes.

The authorization script needs to always complete successfully (exit status 0)
and write to stdout a number with a new line (eg. 300\n). This number if greater
than zero is treated as the authorization duration for the request. Otherwise if
it zero or less it will signify that the client is not authorized thus their
request will go ignored.

## Requirements:
* Python3