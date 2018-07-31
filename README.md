# Introduction
TODO

# Installation

Make sure you have [Python 2](https://www.python.org/downloads/) installed.

Install the dependencies:
```bash
pip install -r requirements.txt
```

# Running the script
This script checks whether the security headers for a given website (URI) are secure. This script implements the checks of 
- http://securityheaders.io/
- https://csp.withgoogle.com
- as well as custom checks.

Start the script as follows.
``` bash
python securityheaders.py URI
```

Use the -h flag for all options.
``` bash
python securityheaders.py -h
```

## Using Docker

For easy portablity, we've added support for Docker for the cli tool.

Building the container:
```bash
docker build -t securityheaders:latest .
```

Run the container:
```bash
docker run -it --rm securityheaders:latest {URI} [options]
```

*Note:* if you wish to add your own bypass files, use Docker `volumes`:
```bash
docker run -it --rm -v ~/whitelists:/securityheaders/conf securityheaders:latest {URI} [options]
```

# Security Headers
TODO explain the headers themselves plus the insecure configurations that are being checked
