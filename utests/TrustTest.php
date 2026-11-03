<?php
error_reporting(E_ALL);

require dirname(__DIR__).'/Trust.class.php';
require dirname(__DIR__).'/hooks/validator.php';

use FreePBX\modules\Firewall\Trust;
use FreePBX\modules\Firewall\Validator;

function trust_assert($condition, $message) {
	if (!$condition) {
		fwrite(STDERR, "FAIL: $message\n");
		exit(1);
	}
	echo "OK: $message\n";
}

trust_assert(Trust::safeRuntimeDir('/var/run/asterisk') === '/var/run/asterisk' || Trust::safeRuntimeDir('/var/run/asterisk') === '/run/asterisk', 'runtime directory accepted');
trust_assert(Trust::safeRuntimeDir('/etc/shadow') === '/var/run/asterisk' || Trust::safeRuntimeDir('/etc/shadow') === '/run/asterisk', 'runtime directory rejected');
trust_assert(Trust::safeRuntimeDir("/var/run/asterisk\n/tmp") !== "/var/run/asterisk\n/tmp", 'runtime directory rejects newline');
trust_assert(Trust::systemBinary(array('/tmp/not-a-binary')) === false, 'non-system binary rejected');
trust_assert(Trust::rootLocked('/tmp') === false, 'world-writable directory is not root locked');

$good = hash_file('sha256', dirname(__DIR__).'/bin/clean-nftables');
$valid = new Validator(array(
	'config' => array('hash' => 'sha256'),
	'hashes' => array('bin/clean-nftables' => $good),
));
trust_assert($valid->checkFile('bin/clean-nftables') !== '', 'signed file accepted');

$tampered = new Validator(array(
	'config' => array('hash' => 'sha256'),
	'hashes' => array('bin/clean-nftables' => str_repeat('ab', 32)),
));
$rejected = false;
try {
	$tampered->checkFile('bin/clean-nftables');
} catch (Exception $e) {
	$rejected = strpos($e->getMessage(), "don't match") !== false;
}
trust_assert($rejected, 'tampered file rejected');

if (Trust::runningAsRoot()) {
	$directory = sys_get_temp_dir().'/fpbx-trust-'.getmypid();
	mkdir($directory, 0755);
	$owned = $directory.'/owned';
	file_put_contents($owned, "<?php\n");
	chown($owned, 0);
	chmod($owned, 0644);
	trust_assert(Trust::rootLocked($owned), 'root-owned file accepted');
	$link = $directory.'/link';
	symlink($owned, $link);
	trust_assert(Trust::rootLocked($link) === false, 'symlink rejected');
	unlink($link);
	unlink($owned);
	rmdir($directory);
}

echo "Trust checks passed\n";
