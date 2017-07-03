<?php

$debug = true;

$thissvc = "firewall";
// Include once because *sometimes*, on *some machines*, it crashes?
include_once 'lock.php';
use \FreePBX\modules\Firewall\Lock;

if (!Lock::canLock($thissvc)) {
	print "Firewall Service already running, not restarting...\n";
	syslog(LOG_WARNING|LOG_LOCAL0, "Firewall Service already running, not restarting...");
	exit;
}

include_once 'common.php';

// Load our validator
$v = new \FreePBX\modules\Firewall\Validator($sig);

if (posix_geteuid() !== 0) {
	throw new \Exception("I must be run as root.");
}

$fwconf = getSettings();

if (!$fwconf['active']) {
	// Don't need to log this
	// print "Not active. Shutting down\n";
	shutdown();
} else {
	print "Starting firewall.\n";
}

// How to detect if we're going into safe mode:
//   1.  $services['safemode']['status'] == bool true
//   2.  $services['safemode']['lastuptime'] =< 600
//   4.  CURRENT uptime < 300

$ready = false;
$first = true;
$sendwarning = false;
while (!$ready) {

	$services = getServices();

	if (!isset($services['safemode']) || !is_array($services['safemode'])) {
		fwLog("Unable to see safemode in services.. Sleeping 5 seconds and retrying");
		print_r($services); // This will only be seen when running firewalld interactively.
		sleep(5);
		continue;
	}

	if ($services['safemode']['status'] !== "enabled") {
		// Safemode isn't enabled;
		break;
	}

	if ($services['safemode']['lastuptime'] > 600) {
		// Was up for more than 10 mins, no safemode for you.
		break;
	}

	// Now we've passed all the prerequisites. Are WE starting up at boot, too?

	$uptime = file("/proc/uptime");
	if (!isset($uptime[0])) {
		throw new \Exception("Unable to read uptime? How?");
	}

	// Format of uptime is 'seconds.xx idle.xx'. Note that idle.xx can be
	// HIGHER than seconds if you're on a multi-core machine.
	list($secs, $idle) = explode(" ", $uptime[0]);

	// Have we been up for more than 5 mins? No safemode.
	if ((int) $secs > 300) {
		break;
	}

	// OK, we're into safemode.
	touch("/var/run/firewalld.safemode");

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

// Delete our safemode flag if it exists.
@unlink("/var/run/firewalld.safemode");

// Flush all iptables rules
$f = $v->checkFile("bin/clean-iptables");
`$f`;

// Start fail2ban if we can
`service fail2ban start`;

// Always load ip_contrack_ftp, even if FTP isn't allowed,
// as it helps with OUTBOUND connections, too.
`/sbin/modprobe ip_conntrack_ftp`;
`/sbin/modprobe nf_conntrack_ftp`;
// Same for TFTP
`/sbin/modprobe ip_conntrack_tftp`;
`/sbin/modprobe nf_conntrack_tftp`;

// Make sure our conntrack kernel module is configured correctly
include_once 'modprobe.php';
$m = new \FreePBX\Firewall\Modprobe;
$m->checkModules();
unset($m);

$path = $v->checkFile("Services.class.php");
include_once $path;
$services = new \FreePBX\modules\Firewall\Services;

$path = $v->checkFile("Attacks.class.php");
include_once $path;

// Now, start by grabbing our interfaces, and making sure
// they are configured correctly.
$path = $v->checkFile("Network.class.php");
include_once $path;
$netobj = new \FreePBX\modules\Firewall\Network;

$known = $netobj->discoverInterfaces();
foreach ($known as $int => $conf) {
	// If this is an alias, skip
	if (isset($conf['config']['PARENT'])) {
		continue;
	}
	if (!isset($conf['config']['ZONE']) || !isValidZone($conf['config']['ZONE'])) {
		$zone = "trusted";
	} else {
		$zone = $conf['config']['ZONE'];
	}
	fwLog("INTERFACE INIT: $int => $zone");
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

// This is our version. If this changes, restart.
$fwversion = false;

// Always run the update the first time.
$lastfin = 1;

while(true) {
	$fwconf = getSettings();
	if (!$fwconf['active']) {
		// If we're here, we WERE running, and now we're not.
		// Is this because of some database strangeness?  If we have an
		// empty array, ignore it, and sleep for 30 seconds.
		if (!$fwconf) {
			wall("Firewall getSettings returned empty array. Database connection error!\nSleeping for 60 seconds before retrying\n");
			sleep(60);
			continue;
		}
		// Nope, it was shut down deliberately.
		fwLog("Not active. Shutting down");
		wall("Firewall has been disabled. Shutting down.");
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

function getSettings() {
	// Grab what our database connection settings are
	$f = file_get_contents("/etc/freepbx.conf");

	preg_match_all("/amp_conf\[['\"](.+)['\"]\]\s?=\s?['\"](.+)['\"];/m", $f, $out);
	$mysettings = array();

	foreach($out[1] as $id => $val) {
		$mysettings[$val] = $out[2][$id];
	}

	// If the Datbase goes away, this will wait indefinately for a connection.
	$pdo = getDbHandle($mysettings);

	//
	// TRANSIENT FIX
	//
	// As kvstore has been split into multiple tables in FreePBX 14, we need
	// to work with both.  For the moment, try to use the new kvstore table,
	// called 'kvstore_FreePBX_modules_Firewall', and if that fails, fall back
	// to the original 13 name.
	// 
	// This should be removed in FreePBX 15, and only the new name should be tried.
	try {
		$sth = $pdo->prepare('SELECT * FROM `kvstore_FreePBX_modules_Firewall` where id="noid"');
		$sth->execute();
		$res = $sth->fetchAll();
	} catch (\Exception $e) {
		try {
			$sth = $pdo->prepare('SELECT * FROM `kvstore` where `module`=? and id="noid"');
			$sth->execute(array('FreePBX\modules\Firewall'));
			$res = $sth->fetchAll();
		} catch (\Exception $e) {
			// Neither new or old table names exist, so there's nothing configured.
			$res = array();
		}
	}

	$retarr = array();
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
	global $thissvc, $v;

	Lock::unLock($thissvc);

	// Clean up on exit. Start by stopping fail2ban, if it's running
	`service fail2ban stop`;

	// Flush all iptables rules
	$f = $v->checkFile("bin/clean-iptables");
	`$f`;
	
	// If sysadmin is configuring fail2ban, it'll need to regenerate the
	// conf file
	if (file_exists("/var/www/html/admin/modules/sysadmin/hooks/fail2ban-generate")) {
		`/var/www/html/admin/modules/sysadmin/hooks/fail2ban-generate`;
	}
	// And restart fail2ban
	if (file_exists("/var/www/html/admin/modules/sysadmin/hooks/fail2ban-start")) {
		`/var/www/html/admin/modules/sysadmin/hooks/fail2ban-start`;
	} else {
		`service fail2ban start`;
	}
	exit;
}

function getDbHandle($mysettings) {
	global $thissvc;
	static $pdo = false;
	static $lastsettings = false;

	// If the current settings are different to the last settings,
	// recreate the PDO object.
	if (json_encode($mysettings, true) !== $lastsettings) {
		$lastsettings = json_encode($mysettings, true);
		$pdo = false;
	}

	// Make sure it hasn't gone away if it previously existed
	if (is_object($pdo)) {
		try {
			$pdo->query("SHOW STATUS;")->execute();
		} catch(\PDOException $e) {
			// Reconnect!
			$pdo = false;
		}
	}

	// Now, do we need to connect or reconnect?
	while (!$pdo) {
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
		// seconds to actually make sure everything is started.
		// If it hasn't connected after 30 seconds, wall and keep trying.
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
			// Something bad is happening. Wall about mysql not being there, and then keep trying.
			wall("Firewall was unable to connect to MySQL after 30 seconds.\nCheck Database!\n");
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
			return;
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
	global $v, $driver, $services, $thissvc, $fwversion, $netobj;

	// Flush cache, read what the system thinks the firewall rules are.
	$currentrules = $driver->refreshCache();

	// Delete our safemode flag if it exists.
	if (file_exists("/var/run/firewalld.safemode")) {
		unlink("/var/run/firewalld.safemode");
	}

	// Make sure the rules haven't been disturbed, and aren't corrupt
	if (!$firstrun && !$driver->validateRunning()) {
		// This is bad.
		wall("Firewall Rules corrupted! Restarting in 5 seconds\nMore information available in /tmp/firewall.log\n");
		Lock::unLock($thissvc);
		`service fail2ban stop`;
		$f = $v->checkFile("bin/clean-iptables");
		`$f`;
		// Wait 4 seconds to give incron a chance to catch up
		sleep(4);
		// Restart me.
		fclose(fopen("/var/spool/asterisk/incron/firewall.firewall", "a"));
		exit;
	}

	$getservices = getServices();

	// Make sure we actually received stuff..
	if (!isset($getservices['smartports'])) {
		return false;
	}

	// Check our version
	if ($fwversion === false) {
		// First time run. Set it.
		$fwversion = $getservices['fwversion'];
	}

	if ($fwversion !== $getservices['fwversion']) {
		wall("Firewall version change detected! Restarting in 5 seconds");
		Lock::unLock($thissvc);
		// Wait 4 seconds to give incron a chance to catch up
		sleep(4);
		// Restart me.
		fclose(fopen("/var/spool/asterisk/incron/firewall.firewall", "a"));
		exit;
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
		if (is_array($settings['zones'])) {
			// If we're rejecting, we need to remove it from all zones
			if (isset($settings['zones'][0]) && $settings['zones'][0] == "reject") {
				$driver->updateServiceZones($s, $myzones);
				$driver->addToReject($s, $settings);
			} else {
				$driver->removeFromReject($s);
				foreach ($settings['zones'] as $z) {
					unset($myzones['removefrom'][$z]);
					$myzones['addto'][$z] = $z;
				}
				$driver->updateServiceZones($s, $myzones);
			}
		}
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

	// Make sure we nuke any kernel conntrack rules that may be hanging around for 
	// those hosts.
	$a = new FreePBX\modules\Firewall\Attacks(1000); // We don't care about jiffies
	$attacks = $a->getAllAttacks(false, false); // Don't want a summary
	$tmparr = array_flip($getservices['smartports']['registrations']);

	foreach ($attacks as $chain => $attacker) {
		foreach (array_keys($attacker) as $ip) {
			if (isset($tmparr[$ip])) {
				// Found one. Remove it. It's legit now.
				$fh = fopen("/proc/net/xt_recent/$chain", "w");
				fwrite($fh, "-$ip\n");
				fclose($fh);
			}
		}
	}

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

	// Set the firewall to drop or reject mode.
	if ($getservices['advancedsettings']['rejectpackets'] === "enabled") {
		$driver->setRejectMode(false, false);
	} else {
		$driver->setRejectMode(true, false);
	}

	// Update any interfaces that may have changed
	$known = $netobj->discoverInterfaces();
	if (!isset($currentrules['ipv4']['filter']['fpbxinterfaces']) || !is_array($currentrules['ipv4']['filter']['fpbxinterfaces'])) {
		$fints = array();
	} else {
		$fints = $currentrules['ipv4']['filter']['fpbxinterfaces'];
	}

	// Look through our current rules and make sure they aren't referencing
	// interfaces that don't exist, or, are wrong.

	// Cache the discovered interfaces for later.
	$currentcache = array();

	foreach ($fints as $entry) {
		if (!preg_match("/-i ([^\s]+) -j zone-(.+)$/", $entry, $out)) {
			// something bad here
			print "ERROR: Unable to parse interface line '$entry', skipping. THIS IS A BUG\n";
			continue;
		}
		// Debugging:
		// print "Line $entry - int ".$out[1]." to zone ".$out[2]."\n";

		// Does this rule point to a valid interface?
		if (!isset($known[$out[1]])) {
			// We have a rule that references a non-existant interface, so it should be
			// removed.
			$driver->changeInterfaceZone($out[1], false);
			continue;
		}

		// If the current known interface DOESN'T have a zone, we
		// assume it's 'trusted'.
		if (empty($known[$out[1]]['config']['ZONE'])) {
			 $known[$out[1]]['config']['ZONE'] = "trusted";
		}

		// Is iptables pointing to the correct zone?
		if ($out[2] !== $known[$out[1]]['config']['ZONE']) {
			// No. Fix it.
			$driver->changeInterfaceZone($out[1], $known[$out[1]]['config']['ZONE']);
		}

		$currentcache[$out[1]] = $known[$out[1]]['config']['ZONE'];
	}

	// Now go through our discovered interfaces, and see if any
	// are missing
	foreach ($known as $intname => $tmparr) {
		// If this is a child of another interface, ignore
		if ($tmparr['config']['PARENT']) {
			continue;
		}

		// If it's not configured, default to trusted
		if (!isset($tmparr['config']['ZONE'])) {
			$zoneshouldbe = "trusted";
		} else { 
			$zoneshouldbe = $tmparr['config']['ZONE'];
		}

		// Is this interface pointing at the right zone?
		if (!isset($currentcache[$intname]) || $zoneshouldbe !== $currentcache[$intname]) {
			$driver->changeInterfaceZone($intname, $zoneshouldbe);
		}
	}

	// If this is the first run, import the custom firewall rules, if enabled
	if ($firstrun && $getservices['advancedsettings']['customrules'] === "enabled") {
		importCustomRules();
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

function getServices() {
	global $v;

	// Asterisk user
	$astuser = "asterisk";

	// We want to switch to the asterisk user and ask for the port mappings.
	try {
		if (!$v->checkFile("bin/getservices")) {
			// That should ALREADY throw if there's an error
			throw new \Exception("Failed");
		}
	} catch (\Exception $e) {
		fwLog("Can't validate bin/getservices");
		return array();
	}

	// Make sure it's executable
	$s = stat("/var/www/html/admin/modules/firewall/bin/getservices");
	if ($s['mode'] !== 0755) {
		chmod("/var/www/html/admin/modules/firewall/bin/getservices", 0755);
	}

	exec("/sbin/runuser $astuser -c /var/www/html/admin/modules/firewall/bin/getservices", $out, $ret);
	$getservices = @json_decode($out[0], true);
	if (!is_array($getservices) || !isset($getservices['smartports'])) {
		fwLog("Unparseable output from getservices - ".json_encode($out)." - returned $ret");
		return array();
	}
	return $getservices;
}

function importCustomRules() {
	$files = array("/sbin/iptables" => "/etc/firewall-4.rules", "/sbin/ip6tables" => "/etc/firewall-6.rules");
	foreach ($files as $ipt => $f) {
		// Validate file
		if (!file_exists($f)) {
			fwLog("Custom Firewall rules file $f does not exist, skipping");
			continue;
		}
		$stat = stat($f);
		if ($stat['uid'] !== 0) {
			fwLog("Custom Firewall rules file $f not owned by root, skipping");
			continue;
		}
		// Todo: Writable checks
		$cmds = file($f, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES);
		foreach ($cmds as $cmd) {
			$safecmd = escapeshellcmd($cmd);
			fwLog("Custom rule: $ipt $safecmd");
			exec("$ipt $safecmd");
		}
	}
}



