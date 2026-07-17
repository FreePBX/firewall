<?php
/**
 * Lightweight schema tests (no full FreePBX bootstrap required).
 * Run: php utests/SchemaTest.php
 */
error_reporting(E_ALL);
define('FREEPBX_VERSION', '18.0-test');

require dirname(__DIR__).'/Schema.class.php';

use FreePBX\modules\Firewall\Schema;

function assert_true($cond, $msg) {
	if (!$cond) {
		fwrite(STDERR, "FAIL: $msg\n");
		exit(1);
	}
	echo "OK: $msg\n";
}

assert_true(Schema::VERSION_CURRENT === 3, 'current schema is 3 (native nftables)');
assert_true(Schema::detectVersion(null) === Schema::VERSION_LEGACY, 'null settings => legacy');
assert_true(Schema::detectVersion(array()) === Schema::VERSION_LEGACY, 'empty => legacy (17-era)');
assert_true(Schema::detectVersion(array('firewall_schema' => 2)) === 2, 'top-level schema');
assert_true(Schema::detectVersion(array('kvstore' => array('firewall_schema' => 2))) === 2, 'kvstore schema');
assert_true(Schema::detectVersion(array('meta' => array('schema' => 1))) === 1, 'meta.schema');

$flat = array('status' => true, 'networkmaps' => array('10.0.0.0/8' => 'trusted'));
assert_true(Schema::extractKvstore($flat) === $flat, 'extract flat 17 backup');

$wrapped = array('kvstore' => $flat, 'meta' => array('schema' => 2));
assert_true(Schema::extractKvstore($wrapped) === $flat, 'extract wrapped 18 backup');

$nft = Schema::nftAvailable();
assert_true(is_bool($nft), 'nftAvailable returns bool ('.$nft.')');

$pref = Schema::detectPreferredBackend();
assert_true($pref === 'nftables', 'preferred backend is always nftables');

echo "All SchemaTest checks passed.\n";
exit(0);
