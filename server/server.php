<?php
	// Web Knocker Firewall Service main service.
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

	// Load configuration.
	require_once $rootpath . "/config.php";

	if ($argc > 1)
	{
		// Service Manager PHP SDK.
		require_once $rootpath . "/servicemanager/sdks/servicemanager.php";

		$sm = new ServiceManager($rootpath . "/servicemanager");

		echo "Service manager:  " . $sm->GetServiceManagerRealpath() . "\n\n";

		$servicename = preg_replace('/[^a-z0-9]/', "-", $config["iptchain"]);

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

			// Since external executables are running here, restoring the path is important.
			putenv("PATH=" . $config["path"]);

			// Remove and add iptables rules.
			foreach ($config["removediptrules"] as $rule)
			{
				@system("iptables -D " . substr($rule, 3));
				@system("iptables " . $rule);
			}

			foreach ($config["removedip6trules"] as $rule)
			{
				@system("ip6tables -D " . substr($rule, 3));
				@system("ip6tables " . $rule);
			}

			// Remove existing chains.
			@system("iptables -D " . escapeshellarg($config["iptparentchain"]) . " -j " . escapeshellarg($config["iptchain"]));
			@system("ip6tables -D " . escapeshellarg($config["ip6tparentchain"]) . " -j " . escapeshellarg($config["ip6tchain"]));
			@system("iptables -F " . escapeshellarg($config["iptchain"]));
			@system("ip6tables -F " . escapeshellarg($config["ip6tchain"]));
			@system("iptables -X " . escapeshellarg($config["iptchain"]));
			@system("ip6tables -X " . escapeshellarg($config["ip6tchain"]));
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

		// Since external executables are running here, restoring the path is important.
		putenv("PATH=" . $config["path"]);

		// Remove existing chains.
		@system("iptables -D " . escapeshellarg($config["iptparentchain"]) . " -j " . escapeshellarg($config["iptchain"]));
		@system("ip6tables -D " . escapeshellarg($config["ip6tparentchain"]) . " -j " . escapeshellarg($config["ip6tchain"]));
		@system("iptables -F " . escapeshellarg($config["iptchain"]));
		@system("ip6tables -F " . escapeshellarg($config["ip6tchain"]));
		@system("iptables -X " . escapeshellarg($config["iptchain"]));
		@system("ip6tables -X " . escapeshellarg($config["ip6tchain"]));

		// Create the iptables chains.
		system("iptables -N " . escapeshellarg($config["iptchain"]));
		system("iptables -A " . escapeshellarg($config["iptchain"]) . " -j RETURN");
		system("ip6tables -N " . escapeshellarg($config["ip6tchain"]));
		system("ip6tables -A " . escapeshellarg($config["ip6tchain"]) . " -j RETURN");

		// Add the new chain to the target chain at the user-specified location.
		system("iptables -A " . escapeshellarg($config["iptparentchain"]) . " -j " . escapeshellarg($config["iptchain"]));
		system("ip6tables -A " . escapeshellarg($config["ip6tparentchain"]) . " -j " . escapeshellarg($config["ip6tchain"]));

		// Remove iptables rules.
		foreach ($config["removediptrules"] as $rule)
		{
			@system("iptables -D " . substr($rule, 3));
		}

		foreach ($config["removedip6trules"] as $rule)
		{
			@system("ip6tables -D " . substr($rule, 3));
		}

		require_once $rootpath . "/support/ipaddr.php";

		// Start the TCP/IP server.
		$context = stream_context_create();
		$serverfp = stream_socket_server("tcp://" . $config["host"] . ":" . $config["port"], $errornum, $errorstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
		if ($serverfp === false)  return array("success" => false, "error" => HTTP::HTTPTranslate("Bind() failed.  Reason:  %s (%d)", $errorstr, $errornum), "errorcode" => "bind_failed");

		// Enable non-blocking mode.
		stream_set_blocking($serverfp, 0);

		$nextclientid = 1;
		$clients = array();

		$tracker = array();

		function UpdateStreams(&$readfps, &$writefps)
		{
			global $serverfp, $clients;

			if ($serverfp !== false)  $readfps["wksf_s"] = $serverfp;

			foreach ($clients as $id => $client)
			{
				if ($client->mode === "request")  $readfps["wksf_c_" . $id] = $client->fp;
				else if ($client->data !== "")  $writefps["wksf_c_" . $id] = $client->fp;
			}
		}

		// Sometimes keyed arrays don't work properly.
		function FixedStreamSelect(&$readfps, &$writefps, &$exceptfps, $timeout)
		{
			// In order to correctly detect bad outputs, no '0' integer key is allowed.
			if (isset($readfps[0]) || isset($writefps[0]) || ($exceptfps !== NULL && isset($exceptfps[0])))  return false;

			$origreadfps = $readfps;
			$origwritefps = $writefps;
			$origexceptfps = $exceptfps;

			$result2 = @stream_select($readfps, $writefps, $exceptfps, $timeout);
			if ($result2 === false)  return false;

			if (isset($readfps[0]))
			{
				$fps = array();
				foreach ($origreadfps as $key => $fp)  $fps[(int)$fp] = $key;

				foreach ($readfps as $num => $fp)
				{
					$readfps[$fps[(int)$fp]] = $fp;

					unset($readfps[$num]);
				}
			}

			if (isset($writefps[0]))
			{
				$fps = array();
				foreach ($origwritefps as $key => $fp)  $fps[(int)$fp] = $key;

				foreach ($writefps as $num => $fp)
				{
					$writefps[$fps[(int)$fp]] = $fp;

					unset($writefps[$num]);
				}
			}

			if ($exceptfps !== NULL && isset($exceptfps[0]))
			{
				$fps = array();
				foreach ($origexceptfps as $key => $fp)  $fps[(int)$fp] = $key;

				foreach ($exceptfps as $num => $fp)
				{
					$exceptfps[$fps[(int)$fp]] = $fp;

					unset($exceptfps[$num]);
				}
			}

			return true;
		}

		function RemoveClient($id)
		{
			global $clients;

			if (isset($clients[$id]))
			{
				@fclose($clients[$id]->fp);

				unset($clients[$id]);
			}
		}

		// Main service code.
		$stopfilename = __FILE__ . ".notify.stop";
		$reloadfilename = __FILE__ . ".notify.reload";
		$lastservicecheck = time();
		$running = true;

		do
		{
			// Wait for a connection or timeout.
			$readfps = array();
			$writefps = array();
			$exceptfps = NULL;
			UpdateStreams($readfps, $writefps);
			$result = FixedStreamSelect($readfps, $writefps, $exceptfps, 1);
			if ($result === false)  break;

			// Handle new connections.
			if (isset($readfps["wksf_s"]))
			{
				while (($fp2 = @stream_socket_accept($serverfp, 0)) !== false)
				{
					// Enable non-blocking mode.
					stream_set_blocking($fp2, 0);

					$client = new stdClass();
					$client->id = $nextclientid;
					$client->mode = "request";
					$client->data = "";
					$client->fp = $fp2;
					$client->lastts = microtime(true);

					$clients[$nextclientid] = $client;

					$nextclientid++;
				}

				unset($readfps["wksf_s"]);
			}

			// Handle clients in the read queue.
			foreach ($readfps as $cid => $fp)
			{
				if (!is_string($cid) || strlen($cid) < 6 || substr($cid, 0, 7) !== "wksf_c_")  continue;

				$id = (int)substr($cid, 7);

				if (!isset($clients[$id]))  continue;

				$client = $clients[$id];

				$client->lastts = microtime(true);

				$data = @fread($client->fp, 4096);
				if ($data === false || feof($client->fp))  RemoveClient($id);
				else
				{
					$client->data .= $data;

					$info = @json_decode($client->data, true);
					if (is_array($info))
					{
						$client->mode = "response";

						if (!isset($info["secret"]) || !is_string($info["secret"]) || $info["secret"] !== $config["secret"])  $client->data = json_encode(array("success" => false, "error" => "Missing 'secret'.", "missing_secret"));
						else if (!isset($info["ip"]) || !is_string($info["ip"]))  $client->data = json_encode(array("success" => false, "error" => "Missing 'ip'.", "missing_ip"));
						else if (!isset($info["ports"]) || !is_array($info["ports"]))  $client->data = json_encode(array("success" => false, "error" => "Missing 'ports'.", "missing_ports"));
						else if (!isset($info["time"]) || (int)$info["time"] < 1)  $client->data = json_encode(array("success" => false, "error" => "Missing or invalid 'time'.", "missing_time"));
						else
						{
							$ipaddr = IPAddr::NormalizeIP($info["ip"]);
							$ipv6 = ($ipaddr["ipv4"] === "");
							$ipaddr = ($ipv6 ? $ipaddr["shortipv6"] : $ipaddr["ipv4"]);

							$time = min((int)$info["time"], $config["maxtime"]);
							$ts = time() + $time;

							$added = array();
							foreach ($info["ports"] as $portinfo)
							{
								if (!isset($portinfo["proto"]) || !isset($portinfo["num"]))  continue;

								$proto = strtoupper($portinfo["proto"]);
								$num = (int)$portinfo["num"];
								if ($num < 1 || $num > 65535)  continue;
								$valid = (($proto === "TCP" && isset($config["tcpprotected"][$num])) || ($proto === "UDP" && isset($config["udpprotected"][$num])));
								if (!$valid)  continue;

								// Calculate iptables add/remove calls.
								$basecmd = " -p " . $proto . " -s " . escapeshellarg($ipaddr) . " --destination-port " . $num . " -j ACCEPT";
								$addcmd = ($ipv6 ? "ip6tables" : "iptables") . " -I " . escapeshellarg($ipv6 ? $config["ip6tchain"] : $config["iptchain"]) . " 1" . $basecmd;
								$removecmd = ($ipv6 ? "ip6tables" : "iptables") . " -D " . escapeshellarg($ipv6 ? $config["ip6tchain"] : $config["iptchain"]) . $basecmd;

								// Add the iptables rule (allow access).
								if (!isset($tracker[$removecmd]))
								{
									system($addcmd);
									$added[] = $ipaddr . " : " . $num . " (" . $proto . ")";
								}

								// Register the timeout.
								if (!isset($tracker[$removecmd]) || $tracker[$removecmd] < $ts)  $tracker[$removecmd] = $ts;
							}

							if (count($added))
							{
								foreach ($config["recipients"] as $recipient)
								{
									mail($recipient, "[" . gethostname() . "] " . (count($added) == 1 ? "Port" : "Ports") . " opened for " . $ipaddr, implode("\r\n", $added) . "\r\n\r\n" . date("l, F j, Y @ g:i a"), "From: " . $recipient);
								}
							}

							$client->data = json_encode(array("success" => true, "expires" => $ts));
						}
					}
				}
			}

			// Handle clients in the write queue.
			foreach ($writefps as $cid => $fp)
			{
				if (!is_string($cid) || strlen($cid) < 6 || substr($cid, 0, 7) !== "wksf_c_")  continue;

				$id = (int)substr($cid, 7);

				if (!isset($clients[$id]))  continue;

				$client = $clients[$id];

				$client->lastts = microtime(true);

				$result = @fwrite($client->fp, $client->data);
				if ($data === false || feof($client->fp))  RemoveClient($id);
				else
				{
					$client->data = (string)substr($client->data, $result);
					if ($client->data === "")  RemoveClient($id);
				}
			}

			// Handle client timeouts.
			$ts = microtime(true);
			foreach ($clients as $id => $client)
			{
				if ($client->lastts + 30 < $ts)  RemoveClient($id);
			}

			// Handle firewall timeouts.
			$ts = time();
			foreach ($tracker as $removecmd => $ts2)
			{
				if ($ts2 <= $ts)
				{
					// Remove the iptables rule (deny access).
					system($removecmd);

					unset($tracker[$removecmd]);
				}
			}

			// Check the status of the two service file options.
			if ($lastservicecheck <= time() - 3)
			{
				if (file_exists($stopfilename) || file_exists($reloadfilename))  $running = false;

				$lastservicecheck = time();
			}
		} while ($running);

		// Add removed iptables rules.
		foreach ($config["removediptrules"] as $rule)
		{
			@system("iptables " . $rule);
		}

		foreach ($config["removedip6trules"] as $rule)
		{
			@system("ip6tables " . $rule);
		}

		// Remove existing chains.
		@system("iptables -D " . escapeshellarg($config["iptparentchain"]) . " -j " . escapeshellarg($config["iptchain"]));
		@system("ip6tables -D " . escapeshellarg($config["ip6tparentchain"]) . " -j " . escapeshellarg($config["ip6tchain"]));
		@system("iptables -F " . escapeshellarg($config["iptchain"]));
		@system("ip6tables -F " . escapeshellarg($config["ip6tchain"]));
		@system("iptables -X " . escapeshellarg($config["iptchain"]));
		@system("ip6tables -X " . escapeshellarg($config["ip6tchain"]));
	}
?>