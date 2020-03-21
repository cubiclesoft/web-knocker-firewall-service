<?php
	// Web Knocker Firewall Service core functions
	// (C) 2016 CubicleSoft.  All Rights Reserved.

	function WKFS_DisplayError($msg, $result = false, $exit = true)
	{
		echo "\n" . $msg . "\n";

		if ($result !== false)
		{
			echo $result["error"] . " (" . $result["errorcode"] . ")\n";
			if (isset($result["info"]))  var_dump($result["info"]);
		}

		if ($exit)  exit();
	}

	function WKFS_UnpackInt($data)
	{
		if ($data === false)  return false;

		if (strlen($data) == 2)  $result = unpack("n", $data);
		else if (strlen($data) == 4)  $result = unpack("N", $data);
		else if (strlen($data) == 8)
		{
			$result = 0;
			for ($x = 0; $x < 8; $x++)
			{
				$result = ($result * 256) + ord($data[$x]);
			}

			return $result;
		}
		else  return false;

		return $result[1];
	}

	// Drop-in replacement for hash_hmac() on hosts where Hash is not available.
	// Only supports HMAC-MD5 and HMAC-SHA1.
	if (!function_exists("hash_hmac"))
	{
		function hash_hmac($algo, $data, $key, $raw_output = false)
		{
			$algo = strtolower($algo);
			$size = 64;
			$opad = str_repeat("\x5C", $size);
			$ipad = str_repeat("\x36", $size);

			if (strlen($key) > $size)  $key = $algo($key, true);
			$key = str_pad($key, $size, "\x00");

			$y = strlen($key) - 1;
			for ($x = 0; $x < $y; $x++)
			{
				$opad[$x] = $opad[$x] ^ $key[$x];
				$ipad[$x] = $ipad[$x] ^ $key[$x];
			}

			$result = $algo($opad . $algo($ipad . $data, true), $raw_output);

			return $result;
		}
	}

	class WKFS_Helper
	{
		private $config, $rng, $cipher1, $cipher2, $sign, $ipaddr;

		public function Init($config)
		{
			global $rootpath;

			$this->config = $config;

			// Set up encryption.
			require_once $rootpath . "/support/random.php";
			require_once $rootpath . "/support/phpseclib/Crypt/AES.php";

			$encryptkey = array();
			foreach ($this->config["encryption_key"] as $key => $val)  $encryptkey[$key] = hex2bin($val);

			$this->rng = new CSPRNG();
			$this->cipher1 = new Crypt_AES();
			$this->cipher1->setKey($encryptkey["key1"]);
			$this->cipher1->setIV($encryptkey["iv1"]);
			$this->cipher1->disablePadding();
			$this->cipher2 = new Crypt_AES();
			$this->cipher2->setKey($encryptkey["key2"]);
			$this->cipher2->setIV($encryptkey["iv2"]);
			$this->cipher2->disablePadding();
			$this->sign = $encryptkey["sign"];

			$this->ipaddr = false;
		}

		public function CreatePacket($data)
		{
			// Generate block.
			$block = $this->rng->GetBytes(4);

			$block .= pack("N", strlen($data));
			$block .= $data;

			$block .= hash_hmac("sha1", $data, $this->sign, true);
			$block .= $this->rng->GetBytes(4);
			if (strlen($block) % 512 != 0)  $block .= $this->rng->GetBytes(512 - (strlen($block) % 512));

			// Encrypt the block.
			$block = $this->cipher1->encrypt($block);

			// Alter block.  (See:  http://cubicspot.blogspot.com/2013/02/extending-block-size-of-any-symmetric.html)
			$block = substr($block, -1) . substr($block, 0, -1);

			// Encrypt the block again.
			$block = $this->cipher2->encrypt($block);

			return $block;
		}

		public function ExtractPacket($block)
		{
			if ($block === "" || strlen($block) % 512 != 0)  return false;

			// Decrypt the block.
			$block = $this->cipher2->decrypt($block);

			// Alter block.  (See:  http://cubicspot.blogspot.com/2013/02/extending-block-size-of-any-symmetric.html)
			$block = substr($block, 1) . substr($block, 0, 1);

			// Decrypt the block again.
			$block = $this->cipher1->decrypt($block);

			// 32 bytes of overhead (4 byte prefix random, 4 byte data size, 20 byte hash, 4 byte suffix random).
			$size = WKFS_UnpackInt(substr($block, 4, 4));
			if ($size > strlen($block) - 32)  return false;

			$data = substr($block, 8, $size);
			$hash = substr($block, 8 + $size, 20);
			$hash2 = hash_hmac("sha1", $data, $this->sign, true);
			if ($hash !== $hash2)  return false;

			return $data;
		}

		// Client API.
		public function GetServerInfo()
		{
			$options = array(
				"api" => "getinfo"
			);

			$result = $this->RunAPI($options);
			if ($result["success"] && isset($result["ip"]))  $this->ipaddr = $result["ip"];

			return $result;
		}

		public function OpenServerPorts($tcp, $udp, $time)
		{
			$options = array(
				"api" => "openports",
				"ip" => $this->ipaddr,
				"ports" => array(),
				"time" => (int)$time
			);

			foreach ($tcp as $num)  $options["ports"][] = array("proto" => "TCP", "num" => (int)$num);
			foreach ($udp as $num)  $options["ports"][] = array("proto" => "UDP", "num" => (int)$num);

			return $this->RunAPI($options);
		}

		private static function WKFS_Translate()
		{
			$args = func_get_args();
			if (!count($args))  return "";

			return call_user_func_array((defined("CS_TRANSLATE_FUNC") && function_exists(CS_TRANSLATE_FUNC) ? CS_TRANSLATE_FUNC : "sprintf"), $args);
		}

		private function RunAPI($data)
		{
			global $rootpath;

			require_once $rootpath . "/support/web_browser.php";

			$web = new WebBrowser();

			$data["ver"] = 1;
			$data["ts"] = time();
			if ($this->ipaddr !== false)  $data["ip"] = $this->ipaddr;
			$data = $this->CreatePacket(json_encode($data));

			$options = array(
				"postvars" => array(
					"data" => str_replace(array("+", "/", "="), array("-", "_", ""), base64_encode($data))
				)
			);

			$result = $web->Process($this->config["url"], $options);

			if (!$result["success"])  return $result;

			if ($result["response"]["code"] != 200)  return array("success" => false, "error" => self::WKFS_Translate("Expected a 200 response from the web server.  Received '%s'.", $result["response"]["line"]), "errorcode" => "unexpected_server_response", "info" => $result);

			// Attempt to decrypt the packet.
			$data = $this->ExtractPacket($result["body"]);
			if ($data === false)  return array("success" => false, "error" => self::WKFS_Translate("Unable to decrypt response data."), "errorcode" => "bad_decrypt");

			$data = @json_decode($data, true);
			if ($data === NULL || $data === false)  return array("success" => false, "error" => self::WKFS_Translate("Unable to decode JSON response."), "errorcode" => "bad_json_decode");

			return $data;
		}
	}
?>