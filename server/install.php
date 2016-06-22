<?php
	// Web Knocker Firewall Service server installer.
	// (C) 2016 CubicleSoft.  All Rights Reserved.

	if (!isset($_SERVER["argc"]) || !$_SERVER["argc"])
	{
		echo "This file is intended to be run from the command-line.";

		exit();
	}

	// Temporary root.
	$rootpath = str_replace("\\", "/", dirname(__FILE__));

	require_once $rootpath . "/support/wkfs_functions.php";

	if (!function_exists("posix_getpwuid") || !function_exists("posix_geteuid"))  WKFS_DisplayError("Required PHP POSIX function(s) are missing.  The Web Knocker Firewall Service requires Linux and the PHP POSIX extension to run the setup program.");

	$uid = posix_geteuid();
	if ($uid !== 0)  WKFS_DisplayError("The Web Knocker Firewall Service installation program must be run as the 'root' user (UID = 0).");

	echo "Welcome to the Web Knocker Firewall Service server installer!\n\n";
	echo "During the installation process, you will be shown information about your system and asked a series of questions about how you want the Web Knocker portion of your firewall rules to be set up.\n\n";
	echo "WARNING:  Changing firewall settings is a dangerous operation that could result in loss of access.  Be absolutely certain that you have the ability to restore access via a console, virtual console, or other means in the event that this installer does the wrong thing.\n\n";

	echo "Press 'enter' or 'return' to continue or Ctrl-C to quit now.";
	fgets(STDIN);
	echo "\n\n\n";

	$config = array();
	$config["path"] = getenv("PATH");

	echo "----------\n\n";
	echo "Here are the ports that are currently open on your system (Local Address column):\n\n";
	system("netstat -plnt | grep -v 127.0.0.1: | grep -v ::1:");
	echo "\n\n";
	echo "Select which ports to protect, one per line (leave empty to move on).  TCP first, then UDP.  Be sure to NOT include your web server port(s) (e.g. 80 and 443) or you'll lock yourself out!\n";
	$config["tcpprotected"] = array();
	do
	{
		echo "TCP port to protect:  ";
		$cmd = trim(fgets(STDIN));
		if ($cmd !== "")
		{
			$port = (int)$cmd;
			if ($port > 0 && $port < 65536)  $config["tcpprotected"][$port] = true;
		}
	} while ($cmd !== "");
	$config["udpprotected"] = array();
	do
	{
		echo "UDP port to protect:  ";
		$cmd = trim(fgets(STDIN));
		if ($cmd !== "")
		{
			$port = (int)$cmd;
			if ($port > 0 && $port < 65536)  $config["udpprotected"][$port] = true;
		}
	} while ($cmd !== "");

	echo "Maximum length of time to open the specified ports (in seconds):  ";
	$config["maxtime"] = (int)trim(fgets(STDIN));
	echo "\n\n";

	echo "----------\n\n";
	echo "The web server 'index.php' file sends allowed IP addresses to 'server.php' over localhost TCP/IP.  The following questions configure the server portion so that it functions properly.\n\n";
	echo "IPv6 (Y/N):  ";
	$ipv6 = (substr(strtoupper(trim(fgets(STDIN))), 0, 1) == "Y");
	$config["host"] = ($ipv6 ? "[::1]" : "127.0.0.1");

	echo "Port (leave blank for the default - 33491):  ";
	$port = trim(fgets(STDIN));
	if ($port === "")  $port = 33491;
	$port = (int)$port;
	if ($port < 0 || $port > 65535)  $port = 33491;
	$config["port"] = $port;
	echo "\n\n";

	echo "----------\n\n";
	echo "This section is optional but highly recommended.  When an IP address + port is unlocked, notification e-mails can be sent.  Requires PHP mail() to be configured correctly.  When done adding recipients, leave blank to move on.\n\n";
	$config["recipients"] = array();
	do
	{
		echo "Add notification recipient:  ";
		$cmd = trim(fgets(STDIN));
		if ($cmd !== "")  $config["recipients"][] = $cmd;
	} while ($cmd !== "");
	echo "\n\n";

	echo "----------\n\n";
	echo "The next few questions look at the current firewall setup to figure out where to place the rules for Web Knocker Firewall Service.\n\n";
	echo "Below is the current list of chains in iptables (IPv4):\n\n";
	system("iptables -L -n -v | grep Chain | awk '{ print \$2 }'");
	echo "\n\n";
	echo "Parent chain (default is INPUT):  ";
	$chain = trim(fgets(STDIN));
	if ($chain === "")  $chain = "INPUT";
	$config["iptparentchain"] = $chain;
	echo "Name for new iptables chain (default is web-knocker-firewall-service):  ";
	$chain = trim(fgets(STDIN));
	if ($chain === "")  $chain = "web-knocker-firewall-service";
	$config["iptchain"] = $chain;
	echo "\n\n";

	echo "Below is the current list of chains in ip6tables (IPv6):\n\n";
	system("ip6tables -L -n -v | grep Chain | awk '{ print \$2 }'");
	echo "\n\n";
	echo "Parent chain (default is INPUT):  ";
	$chain = trim(fgets(STDIN));
	if ($chain === "")  $chain = "INPUT";
	$config["ip6tparentchain"] = $chain;
	echo "Name for new ip6tables chain (default is web-knocker-firewall-service):  ";
	$chain = trim(fgets(STDIN));
	if ($chain === "")  $chain = "web-knocker-firewall-service";
	$config["ip6tchain"] = $chain;
	echo "\n\n";

	echo "----------\n\n";
	echo "The next few questions look at the current firewall setup to figure out what rules to remove.  If you already use a strong firewall setup (e.g. INPUT DROP), you most likely already have rules in place to allow access to the ports you actually want to protect.  Those rules need to be removed to allow Web Knocker Firewall Service to function as expected.  The rules will be saved in case you later decide to uninstall Web Knocker Firewall Service.\n\n";
	echo "Current IPv4 firewall rules:\n\n";
	ob_start();
	system("iptables-save | grep -- '-A '");
	$currrules = explode("\n", trim(ob_get_contents()));
	ob_end_clean();
	foreach ($currrules as $num => $rule)
	{
		if (substr($rule, 0, 3) !== "-A ")  unset($currrules[$num]);
	}
	$currrules = array_values($currrules);
	foreach ($currrules as $num => $rule)
	{
		echo $num . ":  " . $rule . "\n";
	}
	echo "\n\n";
	echo "Use the numbers above to select rules to remove.  If you are removing SSH (port 22), save it for last to minimize issues.\n";
	$config["removediptrules"] = array();
	do
	{
		echo "Remove rule:  ";
		$cmd = trim(fgets(STDIN));
		if ($cmd !== "")
		{
			$num = (int)$cmd;
			if (isset($currrules[$num]))  $config["removediptrules"][] = $currrules[$num];
		}
	} while ($cmd !== "");
	echo "\n\n";

	echo "Current IPv6 firewall rules:\n\n";
	ob_start();
	system("ip6tables-save | grep -- '-A '");
	$currrules = explode("\n", trim(ob_get_contents()));
	ob_end_clean();
	foreach ($currrules as $num => $rule)
	{
		if (substr($rule, 0, 3) !== "-A ")  unset($currrules[$num]);
	}
	$currrules = array_values($currrules);
	foreach ($currrules as $num => $rule)
	{
		echo $num . ":  " . $rule . "\n";
	}
	echo "\n\n";
	echo "Use the numbers above to select rules to remove.  If you are removing SSH (port 22), save it for last to minimize issues.\n";
	$config["removedip6trules"] = array();
	do
	{
		echo "Remove rule:  ";
		$cmd = trim(fgets(STDIN));
		if ($cmd !== "")
		{
			$num = (int)$cmd;
			if (isset($currrules[$num]))  $config["removedip6trules"][] = $currrules[$num];
		}
	} while ($cmd !== "");
	echo "\n\n";

	require_once "support/random.php";

	$rng = new CSPRNG(true);
	$data = array(
		"key1" => bin2hex($rng->GetBytes(32)),
		"iv1" => bin2hex($rng->GetBytes(16)),
		"key2" => bin2hex($rng->GetBytes(32)),
		"iv2" => bin2hex($rng->GetBytes(16)),
		"sign" => bin2hex($rng->GetBytes(20))
	);

	$config["encryption_key"] = $data;

	$config["secret"] = bin2hex($rng->GetBytes(40));

	$data = "<" . "?php\n";
	$data .= "\t\$config = " . var_export($config, true) . ";\n";
	$data .= "?" . ">";
	file_put_contents($rootpath . "/config.php", $data);
	chmod($rootpath . "/config.php", 0444);

	echo "\n";
	echo "**********\n";
	echo "Configuration file is located at '" . $rootpath . "/config.php'.\n\n";

	echo "Here is information you will need to configure the Web Knocker Firewall Service client:\n\n";
	echo "  key1 = " . $config["encryption_key"]["key1"] . "\n";
	echo "  iv1  = " . $config["encryption_key"]["iv1"] . "\n";
	echo "  key2 = " . $config["encryption_key"]["key2"] . "\n";
	echo "  iv2  = " . $config["encryption_key"]["iv2"] . "\n";
	echo "  sign = " . $config["encryption_key"]["sign"] . "\n";
	echo "**********\n\n";
	echo "\n\n";

	echo "----------\n\n";
	echo "Past this point be dragons!  The server will be installed and started, which will modify the firewall.  Depending on what ports are being protected, your connection to this system may drop.\n\n";
	echo "Proceed (Y/N):  ";
	$proceed = (substr(strtoupper(trim(fgets(STDIN))), 0, 1) == "Y");

	if (!$proceed)  WKFS_DisplayError("Operation cancelled.  Installation terminated.  Server was not installed nor started and no firewall changes were made.");

	// Install and start 'server.php' as a system service.
	echo "Installing system service...\n";
	system("php " . escapeshellarg($rootpath . "/server.php") . " install");
	system("php " . escapeshellarg($rootpath . "/server.php") . " start");
	echo "\n\n";

	echo "Done.\n";
?>