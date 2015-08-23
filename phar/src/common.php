<?php

// Validator
global $v;
// Startup stats
global $startup;

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
require '/usr/lib/sysadmin/includes.php';
$g = new \Sysadmin\GPG();
$sigfile = \Sysadmin\FreePBX::Config()->get('AMPWEBROOT')."/admin/modules/firewall/module.sig";
$sig = $g->checkSig($sigfile);
if (!isset($sig['config']['hash']) || $sig['config']['hash'] !== "sha256") {
	throw new \Exception("Invalid sig file.. Hash is not sha256 - check $sigfile");
}
require 'validator.php';
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
	syslog(LOG_WARNING|LOG_LOCAL0, $str);
}

