<?php

$server_name = "cp";
$domain_name = "paradrop.lan";
$site_name = "5nines.com 4g Wireless Network in conjunction with paradrop.io!";

$auth_url = "https://5nines.com/wp-content/themes/DiviExtended/cp-mac-auth.php";
$login_url = "https://opus.5nines.com/cp-login-1";
$landing_url = "https://opus.5nines.com";
$location = null;

// Path to the arp command on the local server
$arp = "/usr/sbin/arp";

// Attempt to get the client's mac address
$found_mac = false;
$source = @fopen("/paradrop/dnsmasq-wifi.leases", "r");
if ($source) {
    while ($device = fscanf($source, "%s %s %s %s %s\n", $expiration, $mac, $ip, $name, $devid)) {
        if ($ip == $_SERVER['REMOTE_ADDR']) {
            $found_mac = true;
            break;
        }
    }
    fclose($source);
}

// Try with arp command in case the dnsmasq file is not available.
if (!$found_mac) {
    $mac = shell_exec("$arp -a ".$_SERVER['REMOTE_ADDR']);
    preg_match('/..:..:..:..:..:../',$mac , $matches);
    @$mac = $matches[0];
    if (!isset($mac)) {
        exit;
    }
}

if (is_authenticated()) {
    enable_address();
    send_landing_page();
} else {
    send_login_page();
}

function is_authenticated() {
    global $auth_url;
    global $location;
    global $mac;

    $curl = curl_init();

    $url = $auth_url . '?mac=' . urlencode($mac);
    if ($location) {
        $url = $url . '&location=' . urlencode($location);
    }

    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($curl, CURLOPT_POST, 0);

    $result = curl_exec($curl);
    $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);

    curl_close($curl);

    return ($result === '1');
}

// This function enables the PC on the system by calling iptables, and also saving the
// details in the users file for next time the firewall is reset
function enable_address() {
    global $email;
    global $mac;

    // The comment contains the timestamp when the rule was added, so that a
    // script can remove it after expiration.
    $comment = "-m comment --comment 'added " . time() . "'";

    // Add PC to the firewall
    exec("sudo iptables -I internet 1 -t mangle -m mac --mac-source $mac $comment -j RETURN");

    // The following line removes connection tracking for the PC
    // This clears any previous (incorrect) route info for the redirection
    //
    // This may be causing trouble with the response to the current request.
    // exec("sudo rmtrack ".$_SERVER['REMOTE_ADDR']);
}

// Send a dummy page that automatically does a POST to the actual login page.
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

// Send a dummy page that redirects to the landing page.
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

?>
