<?php
	// Web Knocker Firewall Service client.
	// (C) 2016 CubicleSoft.  All Rights Reserved.

	if (!isset($_SERVER["argc"]) || !$_SERVER["argc"])
	{
		echo "This file is intended to be run from the command-line.";

		exit();
	}

	// Temporary root.
	$rootpath = str_replace("\\", "/", dirname(__FILE__));

	require_once $rootpath . "/support/wkfs_functions.php";

	$filename = $rootpath . "/config.dat";
	if (!file_exists($filename))  WKFS_DisplayError("Configuration file '" . $filename . "' is missing.  Run the installer to create the necessary configuration file.");

	$config = json_decode(file_get_contents($filename), true);
	if (!isset($config["encryption_key"]["sign"]))  WKFS_DisplayError("Configuration file '" . $filename . "' is invalid.  Run the installer to create the necessary configuration file.");

	require_once $rootpath . "/support/cli.php";

	// Process the command-line options.
	$options = array(
		"shortmap" => array(
			"f" => "frequency",
			"m" => "maxtime",
			"t" => "tcp",
			"u" => "udp",
			"?" => "help"
		),
		"rules" => array(
			"frequency" => array("arg" => true),
			"maxtime" => array("arg" => true),
			"tcp" => array("arg" => true, "multiple" => true),
			"udp" => array("arg" => true, "multiple" => true),
			"help" => array("arg" => false)
		)
	);
	$args = ParseCommandLine($options);

	if (isset($args["opts"]["help"]))
	{
		echo "Web Knocker Firewall Service client\n";
		echo "Purpose:  Open preconfigured remote host firewall ports.\n";
		echo "\n";
		echo "Syntax:  " . $args["file"] . " [options] [servicecommand]\n";
		echo "Options:\n";
		echo "\t-f   The amount of time to wait before sending another port request.\n";
		echo "\t-m   The maximum amount of time to open the ports for.  Server capped.\n";
		echo "\t-t   The TCP port to open.  Defaults to all possible options.\n";
		echo "\t-u   The UDP port to open.  Defaults to all possible options.\n";
		echo "\n";
		echo "Example:\n";
		echo "\tphp " . $args["file"] . " -t=22\n";

		exit();
	}

	if (count($args["params"]))
	{
		// Service Manager PHP SDK.
		require_once $rootpath . "/servicemanager/sdks/servicemanager.php";

		$sm = new ServiceManager($rootpath . "/servicemanager");

		echo "Service manager:  " . $sm->GetServiceManagerRealpath() . "\n\n";

		$servicename = preg_replace('/[^a-z0-9]/', "-", $config["servicename"]);
		if ($servicename === "")  WKFS_DisplayError("The configuration file 'servicename' field is empty.  Update the configuration file and then re-run the command.");

		$argv[1] = $args["params"][0];

		if ($argv[1] == "install")
		{
			// Install the service.
			$args = array();
			$options = array();

			$result = $sm->Install($servicename, __FILE__, $args, $options, true);
			if (!$result["success"])  WKFS_DisplayError("Unable to install the '" . $servicename . "' service.", $result);
		}
		else if ($argv[1] == "start")
		{
			// Start the service.
			$result = $sm->Start($servicename, true);
			if (!$result["success"])  WKFS_DisplayError("Unable to start the '" . $servicename . "' service.", $result);
		}
		else if ($argv[1] == "stop")
		{
			// Stop the service.
			$result = $sm->Stop($servicename, true);
			if (!$result["success"])  WKFS_DisplayError("Unable to stop the '" . $servicename . "' service.", $result);
		}
		else if ($argv[1] == "uninstall")
		{
			// Uninstall the service.
			$result = $sm->Uninstall($servicename, true);
			if (!$result["success"])  WKFS_DisplayError("Unable to uninstall the '" . $servicename . "' service.", $result);
		}
		else if ($argv[1] == "dumpconfig")
		{
			$result = $sm->GetConfig($servicename);
			if (!$result["success"])  WKFS_DisplayError("Unable to retrieve the configuration for the '" . $servicename . "' service.", $result);

			echo "Service configuration:  " . $result["filename"] . "\n\n";

			echo "Current service configuration:\n\n";
			foreach ($result["options"] as $key => $val)  echo "  " . $key . " = " . $val . "\n";
		}
		else
		{
			echo "Command not recognized.  Run the service manager directly for anything other than 'install', 'start', 'stop', 'uninstall', and 'dumpconfig'.\n";
		}
	}
	else
	{
		// Make sure PHP doesn't introduce weird limitations.
		ini_set("memory_limit", "-1");
		set_time_limit(0);

		$wkfshelper = new WKFS_Helper();
		$wkfshelper->Init($config);

		$nextquery = 0;
		$serverinfo = false;

		// Main service code.
		$stopfilename = __FILE__ . ".notify.stop";
		$reloadfilename = __FILE__ . ".notify.reload";
		$lastservicecheck = time();
		$running = true;

		do
		{
			if ($nextquery > 0)  sleep(1);

			if ($nextquery <= time())
			{
				// Get server information.
				if ($serverinfo === false)
				{
					$result = $wkfshelper->GetServerInfo();
					if (!$result["success"])
					{
						WKFS_DisplayError("An error occurred while retrieving information from the remote server.  Try again.", $result, false);

						$nextquery = time() + 15;
					}
					else
					{
						echo "Retrieved server information.\n";

						if (isset($args["opts"]["tcp"]))
						{
							$ports = array();
							foreach ($result["tcp"] as $num)
							{
								if (in_array($num, $args["opts"]["tcp"]))  $ports[] = $num;
							}
							$result["tcp"] = $ports;
						}

						if (isset($args["opts"]["udp"]))
						{
							$ports = array();
							foreach ($result["udp"] as $num)
							{
								if (in_array($num, $args["opts"]["udp"]))  $ports[] = $num;
							}
							$result["udp"] = $ports;
						}

						$serverinfo = $result;
					}
				}

				if ($serverinfo !== false)
				{
					$maxtime = (isset($args["opts"]["maxtime"]) ? min((int)$args["opts"]["maxtime"], (int)$serverinfo["maxtime"]) : $serverinfo["maxtime"]);
					if ($maxtime <= 0)  $maxtime = 10;
					$frequency = (int)(isset($args["opts"]["frequency"]) ? min((int)$args["opts"]["frequency"], $maxtime / 3) : $maxtime / 3);
					if ($frequency <= 0)  $frequency = 1;

					$result = $wkfshelper->OpenServerPorts($serverinfo["tcp"], $serverinfo["udp"], $maxtime);
					if (!$result["success"])
					{
						WKFS_DisplayError("An error occurred while attempting to open the requested server ports.", $result, false);

						$serverinfo = false;
						$nextquery = 0;
					}
					else
					{
						echo "Renewed until:  " . date("Y-m-d H:i:s", $result["expires"]) . "\n";
						$nextquery = time() + $frequency;
					}
				}
			}

			// Check the status of the two service file options.
			if ($lastservicecheck <= time() - 3)
			{
				if (file_exists($stopfilename) || file_exists($reloadfilename))  $running = false;

				$lastservicecheck = time();
			}
		} while ($running);
	}
?>