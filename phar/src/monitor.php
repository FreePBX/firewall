<?php

include_once 'asmanager.php';

if (!isset($thissvc)) {
	// We're running from the command line
	start_monitor(false);
}

function start_monitor($fork = true) {
	// We want to fork, and become our own person.
	if (!$fork) {
		run_monitoring(posix_getppid());
	}

	$monitorpid = pcntl_fork();
	if ($monitorpid !== 0) {
		// We are the parent. Continue on, as there's
		// nothing here for you now.
		return $monitorpid;
	}

	$ppid = posix_getppid();

	// Yes. It's not a thread. I know. We can't rely on the thread
	// module being installed, and it doesn't matter anyway.
	$newtitle = "voipfirewalld (Monitor thread)";

	// PHP 5.3 doesn't have this.
	$titlechanged = false;
	if (function_exists('cli_set_process_title')) {
		if (cli_set_process_title($newtitle)) {
			$titlechanged = true;
		}
	}

	if (!$titlechanged) {
		if (function_exists('setproctitle')) {
			setproctitle($newtitle);
		}
	}

	run_monitoring($ppid);
}

function run_monitoring($ppid) {
	// Loop forever
	while (1) {
		$creds = getAMICreds();
		// If we don't have any, sleep for 60 seconds and start again.
		if (!$creds) {
			sleep(60);
			continue;
		}

		// Recreate and reconnect to astman each 24 hours
		$restartafter = time() + 86400;

		$ami = new AGI_AsteriskManager(null, array("log_level" => 0));
		$ami->connect("127.0.0.1", "firewall", $creds['secret']);
		$allow_timeout = true;
		$return_on_event = true;
		$ami->add_event_handler("successfulauth", "successfulauth_handler");
		$ami->add_event_handler("failedauth", "failed_handler");
		$ami->add_event_handler("failedacl", "failed_handler");

		while (1) {
			// This will wait for a max of 30 seconds (when allow_timeout = true)
			$result = $ami->wait_response($allow_timeout, $return_on_event);
			if (file_exists("/tmp/firewall.debug")) {
				print time().": Event debugging - ".json_encode($result)."\n";
			}

			// Is our parent still alive?
			$cppid = posix_getppid();
			if ($ppid !== $cppid) {
				print time().": Monitoring parent (voipfirewalld) died. Shutting down!\n";
				exit;
			}

			// If result of wait_response is bool false, something went wrong.
			// Sleep 30 seconds and restart.
			if ($result === false) {
				print time().": wait_response returned false. Restarting monitoring thread.\n";
				sleep(30);
				break;
			}

			// If we've been running too long, reconnect to Astman
			if (time() > $restartafter) {
				break;
			}
		}
		// The monitoring daemon has been running for 24 hours, or Asterisk
		// has closed the connection for some reason. Reconnect!
	}
}


function getAMICreds() {
	$amifile = "/etc/asterisk/manager_additional.conf";
	if (!file_exists($amifile)) {
		wall("Can't read/find $amifile. Firewall monitoring broken! (Did you forget to click 'Reload'?)");
		return array();
	}
	$creds = @parse_ini_file($amifile, true, INI_SCANNER_RAW);
	if (!isset($creds['firewall'])) {
		wall("Can't find 'firewall' user in $amifile. Firewall monitoring broken! (Did you forget to click 'Reload'?)");
		return array();
	}
	return $creds['firewall'];
}


function successfulauth_handler($e, $params, $server, $port) {
	// If this auth is using a password, it's a valid client.
	// Whitelist it for 90 seconds.
	if (isset($params['UsingPassword']) && $params['UsingPassword'] === "1") {
		$tmparr = explode("/", $params['RemoteAddress']);
		if (strpos($tmparr[2], '127') === 0 || strpos($tmparr[2], 'fe') === 0) {
			// Localhost. Ignore.
			return;
		}
		good_remote($tmparr[2], $params);
	}
}

function userevent_handler($e, $params, $server, $port) {
	if (!isset($params['UserEvent']) || $params['UserEvent'] !== 'authentication-success') {
		// Nothing to do with firewall
		return;
	}

	// Someone authenticated, and we need to add them to the whitelist, just in case.
	if (isset($params['ip'])) {
		$ip = $params['ip'];
		if (strpos($ip, '127') === 0 || strpos($ip, 'fe') === 0) {
			// Localhost. Ignore.
			return;
		}
		good_remote($ip, $params);
	}
}

function failed_handler($e, $params, $server, $port) {
	// We should have a 'RemoteAddress' in the event.
	if (!isset($params['RemoteAddress'])) {
		// No, we don't.
		return;
	}

	$tmparr = explode("/", $params['RemoteAddress']);
	// This will be something like [ IPV4, UDP, 46.17.47.197, 5210 ]
	// (Yes. That's a valid IP that was scanning my system when I was
	// writing this)

	// If it's link-local, or, 127.*, this is bad, and we should wall
	// about it.
	if (strpos($tmparr[2], '127') === 0 || strpos($tmparr[2], 'fe') === 0) {
		wall("Local machine failing auth - Something is misconfigured! Event ".json_encode($params));
		return;
	}

	bad_remote($tmparr[2], $params);
}

function bad_remote($ip, $event) {
	if (file_exists("/tmp/firewall.debug")) {
		$debug = " Event Debugging: ".json_encode($event);
	} else {
		$debug = "";
	}
	// TODO: Manage attackers. At the moment, we just use the
	// existing RFW code, so there's nothing to do here.
	print time().": Firewall-Monitoring - Auth failure from $ip detected.$debug\n";
	return;
}

function good_remote($ip, $event) {
	if (file_exists("/tmp/firewall.debug")) {
		$debug = " Event Debugging: ".json_encode($event);
	} else {
		$debug = "";
	}

	if (needs_whitelist($ip)) {
		print time().": Firewall-Monitoring - $ip reported as good, adding to whitelist.$debug\n";

		// Add it to the whitelist which lets it bypass RFW for 90 seconds.
		@file_put_contents("/proc/net/xt_recent/WHITELIST", "+$ip\n");

		// Now remove it from any recent chains it may be a member of. Note
		// we don't remove from DISCOVERED, as that's only used in the GUI.
		$chains = array("ATTACKER", "CLAMPED", "REPEAT", "SIGNALLING");
		$line = "-$ip\n";
		foreach ($chains as $c) {
			@file_put_contents("/proc/net/xt_recent/$c", $line);
		}

	}
}

function get_iptables() {
	$ipt = array("ipv4" => array(), "ipv6" => array());
	exec("/usr/sbin/iptables-save 2>/dev/null", $ipt['ipv4'], $ret);
	exec("/usr/sbin/ip6tables-save 2>/dev/null", $ipt['ipv6'], $ret);
	// Cache the result for 10 seconds
	$expires = time() + 10;
	return $ipt;
}

function get_registered($iptables) {
	static $cache;

	if (!$cache) {
		$cache = array("expires" => 0, "registered" => array());
	}

	if ($cache['expires'] < time()) {

		// If this returns an empty ipv4 array, only cache it for 5 seconds. Otherwise,
		// cache it for 60 seconds.
		$ipt = get_iptables();
		if (!$ipt['ipv4']) {
			$cache['expires'] = time() + 5;
		} else {
			$cache['expires'] = time() + 60;
		}

		$retarr = array();

		foreach ($ipt['ipv4'] as $line) {
			if (strpos($line, '-A fpbxregistrations -s ') === 0) {
				$tmparr = explode(" ", $line);
				$net = explode("/", $tmparr[3]);
				$retarr[$net[0]] = $net[0];
			}
		}

		foreach ($ipt['ipv6'] as $line) {
			if (strpos($line, '-A fpbxregistrations -s ') === 0) {
				$tmparr = explode(" ", $line);
				$net = explode("/", $tmparr[3]);
				$retarr[$net[0]] = $net[0];
			}
		}

		$cache['registered'] = $retarr;
	}
	return $cache['registered'];
}

function needs_whitelist($ip) {
	static $cache = array();

	// Have we seen this IP recently? If so, we don't need to check again.
	if (!empty($cache[$ip])) {
		$expires = $cache[$ip];
		if ($expires > time()) {
			return false;
		}
	}

	// We don't know if this is in the fpbxregistrations table, or if it's already been whitelisted,
	// but it will be after this. Either way, don't look again for 5 mins.
	$cache[$ip] = time() + 3600;

	// Is this IP address already known about in fpbxregistrations?
	$registered = get_registered();
	if (isset($registered[$ip])) {
		return false;
	}

	// OK, it needs to be added to the temporary whitelist
	return true;
}

