# Introduction
Applications can set secure HTTP response headers as an additional layer of defense that prevents browsers from running into easy preventable vulnerabilities.
The script in this repository validates whether the headers pertaining to security are present and if present, whether they have been configured securely.
In summary, the script implements the checks identified by 
- http://securityheaders.io/
- https://csp.withgoogle.com
- my original research

Start the script as follows.
``` bash
python securityheaders.py URI
```

Use the -h flag for all options.
``` bash
python securityheaders.py -h
```


# Security Headers
Security headers are HTTP headers. [HTTP header](https://www.w3.org/Protocols/rfc2616/rfc2616-sec6.html#sec6.2) fields are part of HTTP message that consists of requests from client to server and responses from server to client that define parameters for the communication process including: language, compression support, security and a lot of resources.


## Content Security Policy
A Content Security Policy (CSP) consists of a set of directives that restrict how a webpage loads resources, such as scripts and media files. The CSP protects a web page from various attacks, such as cross-site scripting (XSS) and clickjacking. A CSP supports many directives that limit how the resources are loaded.

The tool validates the following best practices:
- **Configure a CSP**: not configuring a Content Security Policy may not be beneficial for some websites. 
- **Avoid using an empty CSP**: Using the Content Security Policy header with an empty value is equivalent to know content security policy.
- **Specify default-src**: default-src should be set as a fall-back for when other directives are not specified. 
- **Specify object-src, script-src, and base-uri**: explicitly specify these directives, as without a restrictive default-src directive, execution of JavaScript is still possible.
- **Avoid using unsafe-inline**: this value allows execution of third-party JavaScript inline.
- **Avoid using unsafe-eval**: this value allows execution of untrusted JavaScript at runtime with eval.
- **Avoid using the wild-card**: 'object-src' should not be set to *, as it allows loading of arbitrary plugins that can execute JavaScript (e.g. Flash).
- **Avoid specifying an IP source**: validates whether localhost (127.0.0.1) was specified. This source is ignored by the browser.
- **Avoid using deprecated directives**: validates whether the policy uses a directive that is deprecated for that policy version. For instance, report-uri is deprecated in CSP3.
- **Avoid using sources that start with http:**: validates whether the policy allows loading of resources over HTTP.
- **Avoid using sources that are untrusted**: validates whether the policy allows loading of resources from known untrusted hosts.


The tool also identifies the following syntax errors:
- **Unknown directives**: unknown directives (e.g. due to typos) are ignored by the browser.
- **Missing Semicolumn**: directives are seperated with a semi-column. If a directive keyword is part of another, one can assume that the seperator character is missing.
- **Specify a valid nonce**: validates whether the specified nonce is is syntactically valid (correct length, etc.).

## Strict Transport Security
The HTTP Strict Transport Security (HSTS) header ensures that all communication (to a website) is being protected via SSL/TLS. If the browser encounters this header, it will use HTTPS for all subsequent communications with that server.

The tool validates whether the HSTS header has been specified.

## XFrameOptions
The X-Frame-Options HTTP header mitigates clickjacking attacks by limiting what can be rendered in a frame. The header can specify one of the following options:
- "DENY": do not render the page if it is in an iframe. 
- "SAMEORIGIN": do not render the page if it is in an iframe on any page hosted outside the framed page's domain. 
- "ALLOW-FROM": only allow a specific origin in which this page be framed.

The tool validates the following:
- **Configure a X-Frame-Options header**: has the header been used.
- **Avoid using allow-from** as it allows rendering from other domains. Note that this might be ok and thus need to be manually verified.

## XContentTypeOptions
The X-Content-Type-Options header stops a browser from trying to MIME-sniff the content type and forces it to stick with the declared content-type. 

The tool validates the following:
- **Configure a X-Content-Type-Options header**: has the header been used.
- **Avoid setting the header to anything other than nosniff**: prevents sniffing of the header.

## XSSSProtection
The X-XSS-Protection header sets the configuration for the cross-site scripting filter built into most browsers. 

The tool validates the following:
- **If the header has been used, does it enable the filter**: the recommended value is "X-XSS-Protection: 1; mode=block

## CORS
A Cross-Origin Resource Sharing (CORS) policy controls whether and how content running on other origins can interact with the origin that publishes the policy.

The tool validates the following:
- **Avoid allowing access from all origins**: this is insecure as it is the equivalent of not specifying a policy.
- **Avoid setting the preflight time for longer than 30 minutes**: the Access-Control-Max-Age header instructs the browser to cache responses to preflight requests. The time is how long the browser can cache the request. If this is too long, a browser may use outdated information.
- **Avoid using the null header**: TODO
- **Only allow HTTPS origins for requests with credentials**: TODO


## ReferrerPolicy
The Referer HTTP header is set by browsers to tell the server the page that brought it there. The Referer-Policy header specifies whether the browser is allowed to send the Referer header. 

The tool validates the following:
- **Configure a Referrer-Policy header**: has the header been used.
- **Avoid using unsafe-url and origin-when-cross-origin** as they allow transfer of sensitive information (via the Referer header) from HTTPS environments to HTTP environments.

## FeaturePolicy
The Feature-Policy header allows a site to control which features and APIs can be used in the browser (location services, etc.). 

The tool validates whether this header has been used.

