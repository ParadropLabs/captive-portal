Captive Portal Chute
====================

This is a chute (an app for the Paradrop platform) designed to launch a virtual
WiFi access point on a Paradrop router.  The WiFi network is open by default
and redirects users to a configurable login page.

Learn more about Paradrop or launch this chute on your Paradrop router at
paradrop.org!

Environment Variables
---------------------

* CP\_AUTH\_URL: URL to check in a MAC address is authenticated.
* CP\_LOGIN\_URL: URL to redirect users to login.
* CP\_LANDING\_URL: URL to redirect users after they are logged in.
* CP\_LOCATION: Location associated with the chute instance.
* CP\_EXPIRATION: Expiration time (seconds) for client sessions.
* CP\_ALLOW\_DOMAIN: Special destination domain(s) to allow unrestricted.  This should be a space separated list of domains, e.g. "example.com example.org".

Login Flow
----------

1. Client device connects to the WiFi network.
2. Most devices test connectivity by issuing an HTTP GET request, e.g. to
   captive.apple.com or connectivitycheck.gstatic.com/generate\_204.
3. The captive portal (CP) chute catches this HTTP request and responds with a
   302 Found that redirects the user to the CP, e.g. http://192.168.128.2.
4. The client issues a GET request to the CP.
5. The CP issues a POST to the configured CP\_LOGIN\_URL with the client's
   MAC address and CP\_LOCATION.  The result is a login page with embedded
   client information.
6. The CP returns this login page to the client in response to its GET request.
7. The client displays the login page with additional assets (images, JS, CSS).
   These are passed through unmodified by the CP based on the Referer header.
8. The user enters the requested information and clicks Submit, which issues
   a POST to the CP.
9. The CP forwards the POST to CP\_LOGIN\_URL and returns the response to
   the client.
