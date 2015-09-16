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

// Make sure our conntrac module is configured correctly
include 'modprobe.php';
$m = new \FreePBX\Firewall\Modprobe;
$m->checkModules();

$v = new \FreePBX\modules\Firewall\Validator($sig);
$v->checkFile("Services.class.php");

require 'Services.class.php';

// Turns out that this is unreliable. Which is why we use sigSleep below.
pcntl_signal(SIGHUP, "sigHupHandler");

// Update every 60 seconds.
$period = 60;

$lastfin = time() - $period - 10;
while(true) {
	checkPhar();
	if ($lastfin + $period < time()) {
		// We finished more than $period ago. We can run again.
		updateFirewallRules();
		$lastfin = time();
		continue;
	} else {
		// Sleep until we're ready to go again.
		sigSleep($period/10);
	}
}

function checkPhar() {
	global $thissvc, $v;

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
			// We don't use SLEEP as PHP is easily confused.
			sigSleep(10);
			continue;
		}

		try {
			$v->checkFile("hooks/firewall");
			fwLog("Valid update! Restarting...");
			Lock::unLock($thissvc);
			// Wait 1/2 a second to give incron a chance to catch up
			usleep(500000);
			// Restart me.
			fclose(fopen("/var/spool/asterisk/incron/firewall.firewall"));
			exit;
		} catch(\Exception $e) {
			fwLog("Firewall tampered.  Not restarting!");
		}
	}
}

function updateFirewallRules() {
	// Signature validation and firewall driver
	global $v, $driver;

	// Asterisk user
	$astuser = "asterisk";

	// We want to switch to the asterisk user and ask for the port mappings.
	if (!$v->checkFile("bin/getservices")) {
		fwLog("Can't validate bin/getservices");
		return false;
	}

	exec("su -c /var/www/html/admin/modules/firewall/bin/getservices $astuser", $out, $ret);
	$services = @json_decode($out[0], true);
	if (!is_array($services) || !isset($services['smartports'])) {
		fwLog("Unparseable output from getservices - ".$out[0]." - returned $ret");
		return;
	}

	$zones = array("reject" => "reject", "external" => "external", "other" => "other",
		"internal" => "internal", "trusted" => "trusted");

	foreach ($services['services'] as $s => $settings) {
		print "Doing $s\n";
		// Make sure the service is configured correctly
		if (isset($settings['fw'])) {
			$driver->updateService($s, $settings['fw']);
		} else {
			$driver->updateService($s, false);
		}

		// Assign the service to the required zones
		$myzones = array("addto" => array(), "removefrom" => $zones);
		if (is_array($settings['zones'])) {
			foreach ($settings['zones'] as $z) {
				unset($myzones['removefrom'][$z]);
				$myzones['addto'][$z] = $z;
			}
		}
		$driver->updateServiceZones($s, $myzones);
	}

	// Update RTP rules
	$rtp = $services['smartports']['rtp'];
	$driver->setRtpPorts($rtp);

	$targets = $services['smartports'];
	// Update our knownhosts targets
	$driver->updateTargets($targets);

	// And permit our registrations through
	$driver->updateRegistrations($services['smartports']['registrations']);

	print "Done\n";
	exit;
}

function sigSleep($secs = 10) {
	// Uses pcntl_sigtimedwait instead of sleep, so we can be sure we catch sighup
	// signals from the OS. This may seem counterproductive, as sleep(3) will wake
	// on *any* signal, but php does all sorts of crazy things to make this
	// unreliable.
	pcntl_sigtimedwait(array(SIGHUP), $sig, $secs);
	if ($sig['signo'] === SIGHUP) {
		sigHupHandler(1);
	}
}

function sigHupHandler($signo) {
	// Sigh.
	checkPhar();
	updateFirewallRules();
}
