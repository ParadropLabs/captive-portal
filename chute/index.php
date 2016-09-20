<?php

$server_name = "cp";
$domain_name = "paradrop.lan";
$site_name = "5nines.com 4g Wireless Network in conjunction with paradrop.io!";

$auth_url = "https://5nines.com/wp-content/themes/DiviExtended/cp-mac-auth.php";
$login_url = "https://opus.5nines.com/cp-login-1";
$landing_url = "https://opus.5nines.com";

// Path to the arp command on the local server
$arp = "/usr/sbin/arp";

// The following file is used to keep track of users
$users = "/var/www/users";

// Check if we've been redirected by firewall to here.
// If so redirect to registration address
//if ($_SERVER['SERVER_NAME']!="$server_name.$domain_name") {
//  header("location:http://$server_name.$domain_name/index.php?add="
//    .urlencode($_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI']));
//  exit;
//}

// Attempt to get the client's mac address
$mac = shell_exec("$arp -a ".$_SERVER['REMOTE_ADDR']);
preg_match('/..:..:..:..:..:../',$mac , $matches);
@$mac = $matches[0];
if (!isset($mac)) { exit; }

if (is_authenticated()) {
    enable_address();
    send_landing_page();

    // Redirect to landing page.
    // header('Location: ' . $landing_url);

    // Redirect to whatever the user requested originally.
//    header("location:http://".$_GET['add']);
} else {
    // Redirect to the 5nines login page with the MAC address as a parameter.
//    $url = $login_url . '?mac=' . urlencode($mac);
//    header('Location: ' . $url);

    send_login_page();
}

function is_authenticated() {
    global $auth_url;
    global $mac;

    $curl = curl_init();

    $url = $auth_url . '?mac=' . urlencode($mac);
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
    global $users;

//    file_put_contents($users,$_POST['email']."\t"
//        .$_SERVER['REMOTE_ADDR']."\t$mac\t".date("d.m.Y")."\n",FILE_APPEND + LOCK_EX);

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

    echo '<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
  </head>
  <body>
    <form id="redirect" action="' . $login_url . '" method="post">
      <input type="hidden" name="mac" value="' . $mac . '">
      <input type="submit" value="Continue">
    </form>
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

// Function to print page header
function print_header() {

  ?>
  <html>
  <head><title>Welcome to <?php echo $site_name;?></title>
  <META HTTP-EQUIV="CACHE-CONTROL" CONTENT="NO-CACHE">
  <LINK rel="stylesheet" type="text/css" href="./style.css">
  </head>

  <body bgcolor=#FFFFFF text=000000>
  <?php
}

// Function to print page footer
function print_footer() {
  echo "</body>";
  echo "</html>";

}

?>
