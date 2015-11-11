<?php

$debug = true;

$thissvc = "firewall";
include 'lock.php';
use \FreePBX\modules\Firewall\Lock;

if (!Lock::canLock($thissvc)) {
	print "Firewall Service already running, not restarting...\n";
	syslog(LOG_WARNING|LOG_LOCAL0, "Firewall Service already running, not restarting...");
	exit;
}

require 'common.php';
fwLog("Starting firewall service");

if (posix_geteuid() !== 0) {
	throw new \Exception("I must be run as root.");
}

// Grab what our database connection settings are
$f = file_get_contents("/etc/freepbx.conf");

preg_match_all("/amp_conf\[['\"](.+)['\"]\]\s?=\s?['\"](.+)['\"];/m", $f, $out);
$mysettings = array();

foreach($out[1] as $id => $val) {
	$mysettings[$val] = $out[2][$id];
}

$fwconf = getSettings($mysettings);

if (!$fwconf['active']) {
	// Don't need to log this
	// print "Not active. Shutting down\n";
	shutdown();
} else {
	print "Starting firewall.\n";
}

// If this host has been up for LESS than 5 minutes, don't
// start the firewall.

$ready = false;
$first = true;
$sendwarning = false;
while (!$ready) {
	$uptime = file("/proc/uptime");
	if (!isset($uptime[0])) {
		throw new \Exception("Unable to read uptime? How?");
	}
	// Format of uptime is 'seconds.xx idle.xx'. Note that idle.xx can be
	// HIGHER than seconds if you're on a multi-core machine.
	list($secs, $idle) = explode(" ", $uptime[0]);
	if ((int) $secs > 300) {
		$ready = true;
		break;
	}
	// Not ready yet, and don't wall before 1 minute, to let people actually
	// see it. 
	if ($first && (int) $secs > 60) {
		// Wall a warning that the firewall isn't started yet.
		$warning  = "Firewall is currently in delayed startup mode, as this machine was\n";
		$warning .= "recently rebooted. The firewall service will automatically start\n";
		$warning .= "after this machine has been running for 5 minutes.\n\n";
		$warning .= "Another warning will be broadcast before this happens\n";
		wall($warning);
		$first = false;
		$sendwarning = true;
		sleep(20);
		continue;
	}

	if ($sendwarning && (int) $secs > 270) {
		// 30 seconds left
		$warning = "Firewall service will start automatically in 30 seconds or less!\n\n";
		wall($warning);
		$sendwarning = false;
	}
	sleep(5);
}
wall("Firewall service now starting.\n\n");

// Flush all iptables rules
`service iptables stop`;
`service ip6tables stop`;

// Make sure our conntrack kernel module is configured correctly
include 'modprobe.php';
$m = new \FreePBX\Firewall\Modprobe;
$m->checkModules();
unset($m);

$v = new \FreePBX\modules\Firewall\Validator($sig);
$path = $v->checkFile("Services.class.php");
include $path;
$services = new \FreePBX\modules\Firewall\Services;

// Now, start by grabbing our interfaces, and making sure
// they are configured correctly.
$path = $v->checkFile("Network.class.php");
include $path;
$nets = new \FreePBX\modules\Firewall\Network;

$known = $nets->discoverInterfaces();
foreach ($known as $int => $conf) {
	if (!isset($conf['config']['ZONE']) || !isValidZone($conf['config']['ZONE'])) {
		$nets->updateInterfaceZone($int, "trusted");
		$zone = "trusted";
	} else {
		$zone = $conf['config']['ZONE'];
	}
	$driver->changeInterfaceZone($int, $zone);
}

// Same for our known networks
$nets = array();
if (!empty($fwconf['networkmaps'])) {
	$nets = @json_decode($fwconf['networkmaps'], true);
}
if ($nets && is_array($nets)) {
	foreach ($nets as $n => $zone) {
		if (strpos($n, "/") === false) {
			// No /, it's a host. Skip, we'll pick it up later
			continue;
		}
		list($network, $cidr) = explode("/", $n);
		$driver->addNetworkToZone($zone, $network, $cidr);
	}
}

// Turns out that this is unreliable. Which is why we use sigSleep below.
pcntl_signal(SIGHUP, "sigHupHandler");

// Always run the update the first time.
$lastfin = 1;

while(true) {
	$fwconf = getSettings($mysettings);
	if (!$fwconf['active']) {
		fwLog("Not active. Shutting down");
		shutdown();
	}
	checkPhar();
	$runafter = $lastfin + $fwconf['period'];
	if ($runafter < time()) {
		// We finished more than $period ago. We can run again.
		updateFirewallRules(($lastfin === 1)); // param (bool) true if this is the first run.
		$lastfin = time();
		continue;
	} else {
		// Sleep until we're ready to go again.
		sigSleep($fwconf['period']/10);
	}
}

function getSettings($mysettings) {
	$pdo = getDbHandle($mysettings);
	$sth = $pdo->prepare('SELECT * FROM `kvstore` where `module`=? and id="noid"');
	$sth->execute(array('FreePBX\modules\Firewall'));
	$retarr = array();
	$res = $sth->fetchAll();
	foreach ($res as $row) {
		$retarr[$row['key']] = $row['val'];
	}

	// Should we be running?
	if (isset($retarr['status']) && $retarr['status']) {
		$retarr['active'] = true;
	} else {
		$retarr['active'] = false;
	}

	if (!isset($retarr['refresh'])) {
		$retarr['refresh'] = "normal";
	}

	if ($retarr['refresh'] == "fast") {
		$period = 15;
	} elseif ($retarr['refresh'] == "slow") {
		$period = 120;
	} else {
		$period = 30;
	}
	$retarr['period'] = $period;

	return $retarr;
}

function shutdown() {
	global $thissvc;

	Lock::unLock($thissvc);
	exit;
}

function getDbHandle($mysettings) {
	static $pdo = false;
	// Make sure it hasn't gone away if it previously existed
	if (is_object($pdo)) {
		try {
			$pdo->query("SHOW STATUS;")->execute();
		} catch(\PDOException $e) {
			if ($e->getCode() != 'HY000' || !stristr($e->getMessage(), 'server has gone away')) {
				throw $e;
			} else {
				// Reconnect!
				$pdo = false;
			}
		}
	}

	// Now, do we need to connect or reconnect?
	if (!$pdo) {
		if(empty($mysettings['AMPDBSOCK'])) {
			if (empty($mysettings['AMPDBHOST'])) {
				$conn = "host=localhost";
			} else {
				$conn = "host=".$mysettings['AMPDBHOST'];
			}
		} else {
			$conn = "unix_socket=".$mysettings['AMPDBSOCK'];
		}
		$dsn = $mysettings['AMPDBENGINE'].":$conn;dbname=".$mysettings['AMPDBNAME'].";charset=utf8";
		// Try up to 15 times to connect, waiting 2 seconds between tries. This gives us 30
		// seconds to actually make sure everything it started.
		$count = 0;
		while ($count < 16) {
			try {
				$pdo = new \PDO($dsn, $mysettings['AMPDBUSER'], $mysettings['AMPDBPASS'], array(\PDO::ATTR_PERSISTENT => true));
				$pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
				$pdo->query('SELECT 1');
			} catch (\Exception $e) {
				// It didn't work.
				$count++;
				print "Unable to connect to Database, sleeping 2 seconds and retrying. ($count)\n";
				sleep(2);
				continue;
			}
			break;
		}
		if (!$pdo) {
			throw new \Exception("Can't connect to database after 30 seconds, giving up");
		}
	}
	return $pdo;
}

function checkPhar() {
	global $thissvc, $v;

	// Check to see if we should restart
	if (pharChanged()) {
		// Something changed.
		fwLog("Change detected.\n");

		// Generic boilerplate security code.
		$g = new \Sysadmin\GPG();
		$dir = dirname(\Phar::running(false));
		if (!$dir) {
			// This should never be run outside of a phar, but, who knows...
			$dir == __DIR__;
		}
		$sigfile = $dir."/../module.sig";
		$sig = $g->checkSig($sigfile);
		if (!isset($sig['config']['hash']) || $sig['config']['hash'] !== "sha256") {
			fwLog("Invalid sig file.. Hash is not sha256 - check $sigfile");
			// We don't use SLEEP as PHP is easily confused.
			sigSleep(10);
			continue;
		}

		$v->updateSig($sig);
		try {
			$v->checkFile("hooks/firewall");
			fwLog("Valid update! Restarting...");
			Lock::unLock($thissvc);
			// Wait 1/2 a second to give incron a chance to catch up
			usleep(500000);
			// Restart me.
			fclose(fopen("/var/spool/asterisk/incron/firewall.firewall", "a"));
			exit;
		} catch(\Exception $e) {
			fwLog("Firewall tampered.  Not restarting! ".$e->getMessage());
		}
	}
}

function updateFirewallRules($firstrun = false) {
	// Signature validation and firewall driver
	global $v, $driver, $services, $thissvc;

	// Asterisk user
	$astuser = "asterisk";

	// Flush cache, read what the system thinks the firewall rules are.
	$driver->refreshCache();

	// Make sure the rules haven't been disturbed, and aren't corrupt
	if (!$firstrun && !$driver->validateRunning()) {
		// This is bad.
		wall("Firewall Rules corrupted! Restarting in 5 seconds");
		Lock::unLock($thissvc);
		// Wait 4 seconds to give incron a chance to catch up
		sleep(4);
		// Restart me.
		fclose(fopen("/var/spool/asterisk/incron/firewall.firewall", "a"));
		exit;
	}

	// We want to switch to the asterisk user and ask for the port mappings.
	try {
		if (!$v->checkFile("bin/getservices")) {
			// That should ALREADY throw...
			throw new \Exception("Failed");
		}
	} catch (\Exception $e) {
		fwLog("Can't validate bin/getservices");
		return false;
	}

	$s = stat("/var/www/html/admin/modules/firewall/bin/getservices");
	if ($s['mode'] !== 0755) {
		chmod("/var/www/html/admin/modules/firewall/bin/getservices", 0755);
	}

	exec("su -c /var/www/html/admin/modules/firewall/bin/getservices $astuser", $out, $ret);
	$getservices = @json_decode($out[0], true);
	if (!is_array($getservices) || !isset($getservices['smartports'])) {
		fwLog("Unparseable output from getservices - ".$out[0]." - returned $ret");
		return;
	}

	// Root-only updates:
	//   SSH is only readable by root
	$ssh = $services->getService("ssh");
	if ($ssh['guess'] == true) {
		throw new \Exception("Root user unable to retrieve sshd port! This is a bug!");
	}
	$getservices['services']['ssh']['fw'] = $ssh['fw'];

	$zones = array("reject" => "reject", "external" => "external", "other" => "other",
		"internal" => "internal", "trusted" => "trusted");
	
	// This is the list of services we should have.
	$validservices = array();
	foreach ($getservices['services'] as $s => $settings) {

		// Keep this service for later
		$validservices[$s] = $s;

		// Make sure the service is configured correctly
		if (isset($settings['fw'])) {
			$driver->updateService($s, $settings['fw']);
		} else {
			$driver->updateService($s, false);
		}

		// Assign the service to the required zones
		$myzones = array("addto" => array(), "removefrom" => $zones);
		if (!empty($settings['zones']) && is_array($settings['zones'])) {
			foreach ($settings['zones'] as $z) {
				unset($myzones['removefrom'][$z]);
				$myzones['addto'][$z] = $z;
			}
		}
		$driver->updateServiceZones($s, $myzones);
	}

	// Update RTP rules
	$rtp = $getservices['smartports']['rtp'];
	// UDPTL is T38.
	$udptl = $getservices['smartports']['udptl'];
	$driver->setRtpPorts($rtp, $udptl);

	// Update our knownhosts targets
	$driver->updateTargets($getservices);

	// And permit our registrations through
	$driver->updateRegistrations($getservices['smartports']['registrations']);

	// Update blacklist
	$driver->updateBlacklist($getservices['blacklist']);

	// Update our custom ports
	$custrules = $getservices['custom'];
	foreach ($custrules as $id => $rule) {

		// Keep this service for later
		$validservices[$id] = $id;

		$c = $rule['custfw'];

		// If it has a comma, it's multiple ports.
		$requestedports = explode(",", $c['port']);

		$realports = array();
		// Have we been given a range? (eg, "1234:5678")
		foreach ($requestedports as $port) {
			if (strpos($port, ":") !== false) {
				// Sanity check that the numbers are in the correct order, and are, in fact,
				// numbers.
				$range = explode(":", $c['port']);
				if (!isset($range[1])) {
					// This is invalid, we need two digits
					continue;
				}
				$start = (int) $range[0];
				$end = (int) $range[1];
				if ($start > $end) {
					$lowest = $end;
					$highest = $start;
				} else {
					$lowest = $start;
					$highest = $end;
				}

				if ($lowest < 1 || $highest > 65534) {
					// Invalid
					continue;
				}

				$realports[] = "$lowest:$highest";
			} else {
				// It should just be a number.
				$realnum = (int) $port;
				if ($realnum > 65534 || $realnum < 1) {
					continue;
				}
				$realports[] = $realnum;
			}
		}

		// Create our '$ports' array for the driver.
		$ports = array();
		if ($c['protocol'] == "both" || $c['protocol'] == "tcp") {
			foreach ($realports as $p) {
				$ports[] = array("protocol" => "tcp", "port" => $p);
			}
		}
		if ($rule['custfw']['protocol'] == "both" || $rule['custfw']['protocol'] == "udp") {
			foreach ($realports as $p) {
				$ports[] = array("protocol" => "udp", "port" => $p);
			}
		}
		$driver->updateService($id, $ports);
		// Assign the service to the required zones
		$myzones = array("addto" => array(), "removefrom" => $zones);
		foreach ($rule['zones'] as $z) {
			unset($myzones['removefrom'][$z]);
			$myzones['addto'][$z] = $z;
		}
		$driver->updateServiceZones($id, $myzones);
	}

	// Update the Host DDNS entries.
	$driver->updateHostZones($getservices['hostmaps']);

	// Now, purge any services that no longer exist
	$active = $driver->getActiveServices();
	foreach ($active as $as) {
		if (!isset($validservices[$as])) {
			// This should be removed
			$driver->removeService($as);
		}
	}
}

function sigSleep($secs = 10) {
	// Uses pcntl_sigtimedwait instead of sleep, so we can be sure we catch sighup
	// signals from the OS. This may seem counterproductive, as sleep(3) will wake
	// on *any* signal, but php does all sorts of crazy things to make this
	// unreliable.
	if ($secs < 5) {
		$secs = 5;
	}
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
