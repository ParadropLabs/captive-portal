<?php

/*
 * Constants from the start script.
 *
 * It uses sed commands to override these from chute environment variables.
 */
$auth_url = "https://cp-api.5nines.com/v1.12";
$login_url = "https://majestic.5nines.com/cp-login-1";
$landing_url = "https://majestic.5nines.com";
$location = 0;
$expiration = 3600;

// This shorter expiration time is used to temporarily authorize a device while
// their login is being processed.
$temp_expiration = 60;

// This is our own IP address.  We redirect clients to connect here and relay
// information to and from the login_url.
$login_host = $_SERVER['SERVER_ADDR'];
$allowed_referer = "http://$login_host/";

// Path to the arp command on the local server
$arp = "/usr/sbin/arp";

// Reconstruct the original URL requested for logging and in case we need to
// forward the request.
$original_url = (isset($_SERVER['HTTPS']) ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

// Client's MAC address.
$mac = find_mac();

// Whether we should redirect to $login_url or to the local server.
$redirect_local = FALSE;

/*
 * Find the client's MAC address.
 */
function find_mac() {
    global $arp;

    // Attempt to get the client's mac address
    $found_mac = false;
    $source = @fopen("/paradrop/dnsmasq-wifi.leases", "r");
    if ($source) {
        while ($device = fscanf($source, "%s %s %s %s %s\n",
                                $expiration, $mac, $ip, $name, $devid)) {
            if ($ip == $_SERVER['REMOTE_ADDR']) {
                $found_mac = true;
                break;
            }
        }
        fclose($source);
    }

    // Try with arp command in case the dnsmasq file is not available.
    if (!$found_mac) {
        $mac = shell_exec("$arp -a " . $_SERVER['REMOTE_ADDR']);
        preg_match('/..:..:..:..:..:../', $mac, $matches);
        @$mac = $matches[0];
        if (!isset($mac)) {
            return "00:00:00:00:00:00";
        }
    }

    return $mac;
}

/*
 * Send a redirect (302) response.
 */
function send_redirect($url) {
    header("Location: $url");
}

/*
 * Query the auth function to check if a device should be allowed.
 */
function is_authenticated() {
    global $auth_url;
    global $location;
    global $mac;

    $curl = curl_init();

    $url = "$auth_url/$mac/$location";

    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_POST, 0);

    $result = curl_exec($curl);
    $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);

    curl_close($curl);

    error_log("auth: $url $code $result");

    // Version 1.12 returns simple strings '1' or '0'.
    if ($result === '1') {
        return TRUE;
    } elseif ($result === '0') {
        return FALSE;
    } elseif ($result === '') {
        return FALSE;
    }

    // Version 1.2 returns JSON with integer auth values.
    // Example: '[{"auth":1,"email":""}]'
    $data = @json_decode($result);
    if (is_array($data) && !empty($data)) {
        if ($data[0]->auth === 1) {
            return TRUE;
        } elseif($data[0]->auth === 0) {
            return FALSE;
        }
    }

    // Default: be kind to users?
    return TRUE;
}

/*
 * Grant wide area access to a MAC address by calling iptables.
 */
function enable_address($mac, $expiration) {
    $expires = time() + $expiration;

    // The comment specifies when the rule expires so it can be removed.
    $comment = "-m comment --comment 'expires $expires'";

    // Add PC to the firewall
    exec("sudo iptables -I clients 1 -t mangle -m mac --mac-source $mac $comment -j RETURN");

    // The following line removes connection tracking for the PC
    // This clears any previous (incorrect) route info for the redirection
    //
    // This may be causing trouble with the response to the current request.
    // exec("sudo rmtrack ".$_SERVER['REMOTE_ADDR']);
}

/*
 * Forward a GET request to the intended recipient and return the result to the
 * client.
 */
function forward_request() {
    global $original_url;

    $curl = curl_init();

    curl_setopt($curl, CURLOPT_URL, $original_url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_POST, 0);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, 1);

    $result = curl_exec($curl);
    $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);

    curl_close($curl);

    http_response_code($code);
    echo $result;
}

/*
 * Forward a login POST to the login_url and return the result to the client.
 */
function forward_login() {
    global $login_url;
    global $location;
    global $mac;

    $curl = curl_init();

    curl_setopt($curl, CURLOPT_URL, $login_url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_POST, 1);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $_POST);

    $result = curl_exec($curl);
    $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);

    curl_close($curl);

    http_response_code($code);
    echo $result;
}

/*
 * POST to the login_url and return the response to the user.
 */
function post_initial_login() {
    global $login_url;
    global $location;
    global $mac;

    $curl = curl_init();

    $data = array(
        'mac' => $mac,
        'location' => $location
    );

    curl_setopt($curl, CURLOPT_URL, $login_url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_POST, 1);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $data);

    $result = curl_exec($curl);
    $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);

    curl_close($curl);

    http_response_code($code);
    echo $result;
}

/*
 * Send a dummy page that automatically does a POST to the login URL.
 */
function send_login_page() {
    global $mac;
    global $login_url;
    global $location;

    echo '<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
  </head>
  <body>
    <form id="redirect" action="' . $login_url . '" method="post">
      <input type="hidden" name="mac" value="' . $mac . '">';

    if ($location) {
        echo '      <input type="hidden" name="location" value="' . $location . '">';
    }

    echo '      <input type="submit" value="Continue">
    </form>
    <p>If the page does not load automatically, please click the button to continue.</p>
    <script>
      document.getElementById("redirect").submit();
    </script>
  </body>
</html>';
}

/*
 * Send a dummy page that redirects to the landing page.
 */
function send_landing_page() {
    global $landing_url;

    http_response_code(203);

    echo '<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="1;url=' . $landing_url . '">
    <script type="text/javascript">
      window.location.href = "'. $landing_url . '"
    </script>
  </head>
  <body>
    <p>You are now connected to the network.  Feel free to <a href="' . $landing_url . '">visit our landing page</a> for special offers.</p>
  </body>
</html>';
}

/*
 * Main logic to handle requests.
 */
$action = "unknown";
if ($_SERVER['HTTP_HOST'] == $login_host) {
    // Request is directed at this server, so it is either a request to load
    // the login page (GET) or submit the login page (POST).
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        // Temporarily authorize the device.  This may help with the race
        // condition in which devices test connectivity immediately after
        // posting their login.
        enable_address($mac, $temp_expiration);

        // Forward the information to login_url.
        forward_login();

        // Check if the device is now allowed, and give it longer access.
        if (is_authenticated()) {
            enable_address($mac, $expiration);
        }
        $action = "post_login";
    } else {
        // POST to the login_url to get the login page and return it to the
        // client.
        post_initial_login();
        $action = "show_login";
    }
} elseif (isset($_SERVER['HTTP_REFERER']) && $_SERVER['HTTP_REFERER'] == $allowed_referer) {
    // The request appears to be related to loading the login page because the
    // Referer header is set to our server.  This could be other assets for
    // rendering the login page (images, JS, CSS), so forward the request.
    //
    // This code probably doesn't do anything when $redirect_local is FALSE,
    // because the client should be making HTTPS connections to outside.  It
    // might work when $redirect_local is TRUE.
    forward_request();
    $action = "pass_related";
} elseif (is_authenticated()) {
    // For any other request (e.g. captive.apple.com), if the auth_url returned
    // true, then we allow the device, forward the request, and return its
    // result to the client.
    enable_address($mac, $expiration);
    forward_request();
    $action = "pass_allowed";
} else {
    // For any other request, if the device should not be allowed, then return
    // a redirect (302 Found) to our server and have the client load the login
    // page.
    if ($redirect_local) {
        send_redirect("http://$login_host");
        $action = "redirect_local";
    } else {
        $url = "$login_url/?mac=$mac";
        send_redirect($url);
        $action = "redirect_remote";
    }
}

/*
 * Log the result.
 */
$method = $_SERVER['REQUEST_METHOD'];
$code = http_response_code();
error_log("$action: $mac $method $original_url $code");

?>
