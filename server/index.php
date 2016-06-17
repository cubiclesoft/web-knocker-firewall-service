<?php
	// Web Knocker Firewall Service web frontend.
	// (C) 2016 CubicleSoft.  All Rights Reserved.

	if ($_SERVER["REQUEST_METHOD"] !== "POST" || !isset($_POST["data"]))
	{
		http_response_code(400);

		exit();
	}

	// Temporary root.
	$rootpath = str_replace("\\", "/", dirname(__FILE__));

	require_once $rootpath . "/support/wkfs_functions.php";

	require_once $rootpath . "/config.php";

	$wkfshelper = new WKFS_Helper();
	$wkfshelper->Init($config);

	// Packet decryption failure response.
	$data = @base64_decode(str_replace(array("-", "_"), array("+", "/"), $_POST["data"]));
	if ($data === false)
	{
		http_response_code(403);

		exit();
	}

	$data = $wkfshelper->ExtractPacket($data);
	if ($data === false)
	{
		http_response_code(403);

		exit();
	}

	// This packet should not receive a unique response yet.
	$data = @json_decode($data, true);
	if (!is_array($data) || !isset($data["ver"]) || !isset($data["ts"]) || (int)$data["ts"] > time() + 15 || (int)$data["ts"] < time() - 15 || !isset($data["api"]))
	{
		http_response_code(403);

		exit();
	}

	// If there is a client/server mismatch, then respond accordingly.
	if ((int)$data["ver"] != 1)
	{
		http_response_code(405);

		echo "The version of your client does not match the version of the server.";

		exit();
	}

	// The client is probably valid past this point.
	if ($data["api"] === "getinfo")
	{
		$result = array(
			"success" => true,
			"tcp" => array_keys($config["tcpprotected"]),
			"udp" => array_keys($config["udpprotected"]),
			"maxtime" => $config["maxtime"],
			"ip" => $_SERVER["REMOTE_ADDR"]
		);

		header("Content-Type: application/octet-stream");

		echo $wkfshelper->CreatePacket(json_encode($result));
	}
	else if ($data["api"] === "openports")
	{
		if (!isset($data["ip"]) || $data["ip"] !== $_SERVER["REMOTE_ADDR"] || !isset($data["ports"]) || !isset($data["time"]))
		{
			http_response_code(403);

			exit();
		}

		$context = @stream_context_create();
		$fp = @stream_socket_client("tcp://" . $config["host"] . ":" . $config["port"], $errornum, $errorstr, 3, STREAM_CLIENT_CONNECT, $context);
		if ($fp === false)
		{
			http_response_code(504);

			exit();
		}

		// Send the request.
		$data2 = array(
			"secret" => $config["secret"],
			"ip" => $data["ip"],
			"ports" => $data["ports"],
			"time" => $data["time"]
		);

		@fwrite($fp, json_encode($data2));

		// Get the response.
		$result = "";
		do
		{
			$data2 = @fread($fp, 4096);
			if ($data2 === false)  $data2 = "";
			$result .= $data2;

		} while ($data2 !== "");

		@fclose($fp);

		header("Content-Type: application/octet-stream");

		echo $wkfshelper->CreatePacket($result);
	}
	else
	{
		http_response_code(405);

		echo "Unknown 'api' option.";
	}
?>