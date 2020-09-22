<?php

// Validator
global $v;
// Startup stats
global $startup;

$setting = getSettings();
$astlogdir = !empty($setting['ASTLOGDIR']) ? $setting['ASTLOGDIR'] : "/var/log/asterisk";
$astspooldir = !empty($setting['ASTSPOOLDIR']) ? $setting['ASTSPOOLDIR'] : "/var/spool/asterisk";
error_reporting(E_ALL);

$thisphar = \Phar::running(false);
if (!$thisphar) {
	throw new \Exception("Not in a phar.");
}

// Record the startup stats so we can check if we've been modified, so we
// know when to restart.
$startup = array("filename" => $thisphar, "starthash" => hash_file('sha256', $thisphar));
// Save the mtime (modified timestamp) of the phar.
$s = stat($thisphar);
$startup['mtime'] = $s['mtime'];

// Create the Validator object
include_once '/usr/lib/sysadmin/includes.php';
$g = new \Sysadmin\GPG();
$sigfile = \Sysadmin\FreePBX::Config()->get('AMPWEBROOT')."/admin/modules/firewall/module.sig";
$sig = $g->checkSig($sigfile);
if (!isset($sig['config']['hash']) || $sig['config']['hash'] !== "sha256") {
	throw new \Exception("Invalid sig file.. Hash is not sha256 - check $sigfile");
}
include_once 'validator.php';
$v = new \FreePBX\modules\Firewall\Validator($sig); // Global

// Grab the driver for this machine
$v->secureInclude('Driver.class.php');
$d = new \FreePBX\modules\Firewall\Driver;
$driver = $d->getDriver();

// End of 'common' functions. We can now return to the caller.
return;


// 'Check myself' function
// This makes sure that I haven't been upgraded and replaced. If something HAS changed,
// then return true. Otherwise return false. Crash if crazy.
function pharChanged() {
	global $startup;
	if (!isset($startup['mtime'])) {
		throw new \Exception("startup global corrupted");
	}

	$thisphar = $startup['filename'];

	// Whoever thought of the idea of caching 'stat' lookups is retarded.
	// I hate you, whoever you are.
	clearstatcache();

	if (!file_exists($thisphar)) {
		throw new \Exception("Source phar deleted");
	}

	$s = stat($thisphar);
	if ($s['mtime'] !== $startup['mtime']) {
		// Something's changed.
		return true;
	} else {
		return false;
	}
}

function fwLog($str) {
	global $STDIN, $STDOUT, $STDERR, $astlogdir;

	$lfstat = @stat($astlogdir."/firewall.log");
	if (is_array($lfstat) && $lfstat['size'] > 1048576) {
		// Logfile is over 1mb
		print time().": Rotating Log\n";
		@unlink($astlogdir."/firewall.log.old");
		rename($astlogdir."/firewall.log", $astlogdir."/firewall.log.old");
		// This is so hacky.
		if (is_resource($STDIN)) {
			fclose($STDIN);
			fclose($STDOUT);
			fclose($STDERR);
		} else {
			fclose(STDIN);
			fclose(STDOUT);
			fclose(STDERR);
		}
		$STDIN = fopen('/dev/null', 'r');
		$STDOUT = fopen($astlogdir.'/firewall.log', 'ab');
		$STDERR = fopen($astlogdir.'/firewall.err', 'ab');
		print time().": Rotated Log\n";
	}
	print time().": $str\n";
	syslog(LOG_WARNING|LOG_LOCAL0, $str);
}

function isValidZone($zone = false) {
	switch ($zone) {
		case "trusted":
		case "internal":
		case "external":
		case "other":
		case "reject":
			return true;
	}
	return false;
}

function wall($msg = false) {
	global $astspooldir;
	if (!$msg) {
		// wat.
		fwLog("Asked to wall a blank message?");
		return;
	}
	// Open a process handle to wall
	$fds = array(0 => array("pipe", "r"), 1 => array("file", "/dev/null", "a"), 2 => array("file", "/dev/null", "a"));
	$pipes = array();
	$ph = proc_open("/usr/bin/wall", $fds, $pipes, $astspooldir."/tmp");
	fwrite($pipes[0], $msg);
	fclose($pipes[0]);
	$ret = proc_close($ph);
	fwLog("Wall: '$msg' returned $ret");
	return $ret;
}

