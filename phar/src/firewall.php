<?php

$thissvc = "firewall";
include 'lock.php';
use \FreePBX\modules\Firewall\Lock;

if (!Lock::canLock($thissvc)) {
	syslog(LOG_WARNING|LOG_LOCAL0, "Firewall Service already running, not restarting...");
	exit;
}

require 'common.php';
fwLog("Starting firewall service");

if (posix_geteuid() !== 0) {
	throw new \Exception("I must be run as root.");
}

// Update every 60 seconds.
$period = 60;

$lastfin = time() - $period;
while(true) {
	// Check to see if we should restart
	if (pharChanged()) {
		// Something changed.
		fwLog("Change detected.\n");

		// Generic boilerplate security code.
		$g = new \Sysadmin\GPG();
		$sigfile = \Sysadmin\FreePBX::Config()->get('AMPWEBROOT')."/admin/modules/firewall/module.sig";
		$sig = $g->checkSig($sigfile);
		if (!isset($sig['config']['hash']) || $sig['config']['hash'] !== "sha256") {
			fwLog("Invalid sig file.. Hash is not sha256 - check $sigfile");
			sleep(10);
			continue;
		}

		$v = new \FreePBX\modules\Firewall\Validator($sig);
		try {
			$v->checkFile("hooks/firewall");
			fwLog("Valid update! Restarting...");
			Lock::unLock($thissvc);
			// Wait 1/2 a second to give incron a chance to catch up
			usleep(500000);
			touch("/var/spool/asterisk/incron/firewall.firewall");
			exit;
		} catch(\Exception $e) {
			fwLog("Firewall tampered.  Not restarting!");
		}
	}

	if ($lastfin + $period < time()) {
		// We finished more than $period ago. We can run again.
		updateFirewallRules();
		$lastfin = time();
		continue;
	} else {
		// Sleep until we're ready to go again.
		sleep($period/10);
	}
}

function updateFirewallRules() {
	// Signature validation
	global $v;

	// Asterisk user
	$astuser = "asterisk";

	// We want to switch to the asterisk user and ask for the port mappings.
	if (!$v->checkFile("bin/getservices")) {
		fwLog("Can't validate bin/getservices");
		return false;
	}

	exec("/usr/bin/su -c /var/www/html/admin/modules/firewall/bin/getservices $astuser", $out, $ret);
	print_r($out);
}

