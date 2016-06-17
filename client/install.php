<?php
	// Web Knocker Firewall Service client installer.
	// (C) 2016 CubicleSoft.  All Rights Reserved.

	if (!isset($_SERVER["argc"]) || !$_SERVER["argc"])
	{
		echo "This file is intended to be run from the command-line.";

		exit();
	}

	// Temporary root.
	$rootpath = str_replace("\\", "/", dirname(__FILE__));

	require_once $rootpath . "/support/wkfs_functions.php";

	echo "Welcome to the Web Knocker Firewall Service client installer!\n\n";

	echo "If you want to install the client so that it runs when the OS boots, you should run this installer as Administrator, root, or an equivalent account.\n\n";

	echo "Press 'enter' or 'return' to continue or Ctrl-C to quit now.";
	fgets(STDIN);
	echo "\n\n\n";

	$config = array();

	echo "----------\n\n";
	echo "From the server installation screen or the server 'config.php' file, copy and paste the following information:\n\n";

	$config["encryption_key"] = array();

	echo "key1:  ";
	$config["encryption_key"]["key1"] = trim(fgets(STDIN));
	echo "iv1:  ";
	$config["encryption_key"]["iv1"] = trim(fgets(STDIN));
	echo "key2:  ";
	$config["encryption_key"]["key2"] = trim(fgets(STDIN));
	echo "iv2:  ";
	$config["encryption_key"]["iv2"] = trim(fgets(STDIN));
	echo "sign:  ";
	$config["encryption_key"]["sign"] = trim(fgets(STDIN));
	echo "\n\n";

	echo "----------\n";
	do
	{
		echo "\n";
		echo "Remote service URL:  ";
		$config["url"] = trim(fgets(STDIN));
		echo "\n";

		echo "Checking URL and gathering information...\n";

		$wkfshelper = new WKFS_Helper();
		$wkfshelper->Init($config);

		$result = $wkfshelper->GetServerInfo();
		if (!$result["success"])  WKFS_DisplayError("An error occurred while retrieving information from the remote server.  Try again.", $result, false);
	} while (!$result["success"]);

	echo "----------\n\n";
	echo "This section is optional.  As a system service, the web knocker will regularly attempt to keep all protected ports open for the maximum amount of time.  This can be useful if you are protecting an e-mail, database, or other server(s) where TCP/IP connections are created and destroyed on a regular basis behind the scenes.\n\n";
	echo "System service name (leave blank to not install):  ";
	$config["servicename"] = trim(fgets(STDIN));

	file_put_contents($rootpath . "/config.dat", json_encode($config, JSON_PRETTY_PRINT));

	echo "\n";
	echo "**********\n";
	echo "Configuration file is located at '" . $rootpath . "/config.dat'.\n\n";
	echo "Server information:\n\n";
	var_dump($result);
	echo "**********\n";
	echo "\n";

	if ($config["servicename"] !== "")
	{
		system(escapeshellarg(PHP_BINARY) . " " . escapeshellarg($rootpath . "/run.php") . " install");
		system(escapeshellarg(PHP_BINARY) . " " . escapeshellarg($rootpath . "/run.php") . " start");
		echo "\n";
	}

	echo "Done.\n";
?>