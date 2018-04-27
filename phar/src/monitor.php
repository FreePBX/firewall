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

		// Recreate and reconnect to astman each loop (every 60 mins, max, or if something
		// crashes)
		$restartafter = time() + 3600;

		$ami = new AGI_AsteriskManager(null, array("log_level" => 0));
		$ami->connect("127.0.0.1", "firewall", $creds['secret']);
		$allow_timeout = true;
		$return_on_event = true;
		$ami->add_event_handler("successfulauth", "successfulauth_handler");
		$ami->add_event_handler("failedauth", "failed_handler");
		$ami->add_event_handler("failedacl", "failed_handler");

		$currentsec = time();
		$loopcount = 0;

		while (1) {
			// Avoid loops - If we've been hit more than 500 times in the current
			// second, then something is severely broken. Exit, and we'll be
			// restarted.
			if ($currentsec == time()) {
				$loopcount++;
			} else {
				$loopcount = 0;
				$currentsec = time();
			}

			if ($loopcount > 500) {
				wall("Loop detected in monitoring script. Issue with Asterisk? Restarting!");
				exit;
			}

			// This will wait for a max of 30 seconds (when allow_timeout = true)
			$result = $ami->wait_response($allow_timeout, $return_on_event);

			// Is our parent still alive?
			$cppid = posix_getppid();
			if ($ppid !== $cppid) {
				print "Parent died. Shutting Down!\n";
				exit;
			}

			// If result of wait_response is bool false, something went wrong.
			// Sleep 30 seconds and restart.
			if ($result === false) {
				print "wait_response returned false. Restarting\n";
				sleep(30);
				break;
			}

			// If we've been running too long, reconnect to Astman
			if (time() > $restartafter) {
				break;
			}
		}

		exit;
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
		good_remote($tmparr[2]);
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
		good_remote($ip);
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

	bad_remote($tmparr[2]);
}

function bad_remote($ip) {
	// TODO: Manage attackers. At the moment, we just use the
	// existing RFW code, so there's nothing to do here.
	print "Firewall-Monitoring - Auth failure from $ip detected\n";
	return;
}

function good_remote($ip) {
	print "Firewall-Monitoring - $ip reported as good, adding to whitelist.\n";
	// This IP has successfully authenticated to this machine. So, remove it from any
	// recent chains it may be a member of. Note we don't remove from DISCOVERED, as
	// that's only used in the GUI.
	$chains = array("ATTACKER", "CLAMPED", "REPEAT", "SIGNALLING");
	$line = "-$ip\n";
	foreach ($chains as $c) {
		@file_put_contents("/proc/net/xt_recent/$c", $line);
	}

	// Add it to the whitelist which lets it bypass RFW for 90 seconds.
	@file_put_contents("/proc/net/xt_recent/WHITELIST", "+$ip\n");
}


