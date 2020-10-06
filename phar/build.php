#!/usr/bin/php
<?php

// Build script to create firewall phars.  This is required to be distributed to
// remain in compliance with Section 1 of the AGPL. This is defined as a
// 'Corresponding Source' of the Firewall module, as it is required to build the
// service.


//Detect correct path library symfony.
$ipUtils = "/libraries/Composer/vendor/symfony/http-foundation/IpUtils.php";
if(file_exists(__DIR__."/../../..".$ipUtils)) {
	$ipUtils = __DIR__."/../../..".$ipUtils;
}
elseif(file_exists(__DIR__."/../../framework/amp_conf/htdocs/admin".$ipUtils)) {
	$ipUtils = __DIR__."/../../framework/amp_conf/htdocs/admin".$ipUtils;
} else {
	throw new Exception( sprintf(_("The file (%s) could not be found!"), $ipUtils) );
	exit(1);
}

$apps = array(
	"voipfirewalld" => array(
		"firewall.php", 
		"common.php", 
		array(__DIR__."/../hooks/validator.php", "validator.php"), 
		array(__DIR__."/../Lock.class.php", "lock.php"), 
		"modprobe.php", 
		"asmanager.php", 
		"monitor.php",
		array($ipUtils, "IpUtils.php")
	),
);

$dst = __DIR__."/../hooks/";
foreach ($apps as $app => $files) {
	$outfile = "$app.phar";
	print "Building $outfile ... ";
	@unlink($outfile);
	$phar = new Phar($outfile, 0, "$app.phar");
	$phar->convertToExecutable(Phar::TAR);
	$phar->startBuffering();
	foreach ($files as $f) {
		if (is_array($f)) {
			$src = $f[0];
			$dest = $f[1];
		} else {
			$src = __DIR__."/src/$f";
			$dest = $f;
		}
		$phar->addFile($src, $dest);
	}
	$start = $files[0];
	// Note that ? and > are broken apart to stop syntax highlighting from getting confused.
	$stub = "#!/usr/bin/env php\n<?php\n\$s='$start';\$f=__FILE__;Phar::interceptFileFuncs();set_include_path(\"phar://\$f/\".get_include_path());Phar::webPhar(null, \$s);include \"phar://\$f/\$s\";__HALT_COMPILER(); ?".">\n";
	$phar->setStub($stub);
	$phar->compressFiles(Phar::BZ2);
	$phar->stopBuffering();
	unset($phar);
	chmod($outfile, 0755);
	print "Done! Moving into place... ";
	$dst = __DIR__."/../hooks/$app";
	@unlink($dst);
	rename($outfile, $dst);
	print "../hooks/$app\n";
}





