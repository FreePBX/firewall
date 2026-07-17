<?php
/**
 * Nftables helper and optional live driver smoke.
 *
 * Live mode must be run inside an isolated network namespace.
 */
error_reporting(E_ALL);

require dirname(__DIR__).'/drivers/Nftables.class.php';

use FreePBX\modules\Firewall\Drivers\Nftables;

function nft_assert($condition, $message) {
	if (!$condition) {
		fwrite(STDERR, "FAIL: $message\n");
		exit(1);
	}
	echo "OK: $message\n";
}

list($rate, $burst) = Nftables::rateSpec(10, 50);
nft_assert($rate === '5/second' && $burst === 50, 'TIERA rate conversion');
list($rate, $burst) = Nftables::rateSpec(60, 10);
nft_assert($rate === '10/minute' && $burst === 10, 'TIERB rate conversion');
list($rate, $burst) = Nftables::rateSpec(86400, 100);
nft_assert($rate === '100/day' && $burst === 100, 'TIERC rate conversion');
nft_assert(Nftables::nftPortSpec('5060') === '5060', 'single port');
nft_assert(Nftables::nftPortSpec('10000:20000') === '10000-20000', 'port range');
nft_assert(Nftables::nftPortSpec('nope') === false, 'invalid port rejected');
nft_assert(Nftables::serviceChainName('http') === 'svc-http', 'service chain');
nft_assert(
	Nftables::serviceChainName('a1b2c3d4-e5f6-7890-abcd-ef1234567890')
		=== 'svc-a1b2c3d4-e5f6-7890-abcd-ef1234567890',
	'UUID service chain'
);

if (getenv('FIREWALL_NFTABLES_LIVE_TEST') === '1') {
	$d = new Nftables();
	exec('nft delete table inet fpbx 2>/dev/null');
	exec('nft delete table ip fpbxnat 2>/dev/null');
	nft_assert($d->ensureBaseRuleset(), 'create native ruleset');
	nft_assert($d->validateRunning(), 'validate native ruleset');
	$thresholds = array(
		'fpbxrfw' => array(
			'TIERA' => array('seconds' => 10, 'hitcount' => 50),
			'TIERB' => array('seconds' => 60, 'hitcount' => 10),
			'TIERC' => array('seconds' => 86400, 'hitcount' => 100),
		),
		'fpbxratelimit' => array(
			'TIER3' => array('seconds' => 86400, 'hitcount' => 200),
			'TIER2' => array('seconds' => 300, 'hitcount' => 100),
			'TIER1' => array('seconds' => 60, 'hitcount' => 50),
		),
	);
	nft_assert($d->updateRFWtshld($thresholds), 'responsive firewall meters');
	$targets = array(
		'smartports' => array(
			'signalling' => array('udp' => array(array('dport' => 5060, 'name' => 'pjsip'))),
			'known' => array('198.51.100.0/24'),
		),
		'settings' => array('responsive' => true, 'rprotocols' => array('pjsip' => array('state' => true))),
	);
	nft_assert($d->updateTargets($targets), 'signalling and smarthost targets');
	nft_assert($d->updateService('http', array(array('protocol' => 'tcp', 'port' => 80))), 'service rule');
	nft_assert($d->updateServiceZones('http', array('addto' => array('internal'), 'removefrom' => array())), 'service zone');
	nft_assert(isset($d->getActiveServices()['http']), 'active service discovery');
	nft_assert($d->addNetworkToZone('trusted', '192.0.2.0', 24), 'network zone');
	nft_assert($d->updateBlacklist(array('198.51.100.2' => false)), 'blacklist set');
	nft_assert($d->updateHostZones(array('203.0.113.2' => 'internal')), 'host zone');
	nft_assert($d->addToReject('http', array('fw' => array(array('protocol' => 'tcp', 'port' => 80)))), 'reject service');
	$registrations = $d->updateRegistrations(array('192.0.2.10'));
	nft_assert(isset($registrations['192.0.2.10']), 'registration set');
	nft_assert($d->changeInterfaceZone('lo', 'trusted'), 'interface zone');
	$zones = $d->getZonesDetails();
	nft_assert(in_array('lo', $zones['trusted']['interfaces'], true), 'zone diagnostics');
	exec('nft add element inet fpbx le_ports { 80 timeout 60s } 2>/dev/null', $out, $status);
	nft_assert($status === 0, 'LetsEncrypt timeout port');
	$custom = tempnam(sys_get_temp_dir(), 'fpbx-custom-');
	file_put_contents($custom, "flush chain inet fpbx fpbxcustom\nadd rule inet fpbx fpbxcustom tcp dport 2222 accept\n");
	chmod($custom, 0600);
	nft_assert($d->importCustomRules($custom), 'validated native custom rules');
	unlink($custom);
	$d->removeService('http');
	exec('nft delete table inet fpbx 2>/dev/null');
	exec('nft delete table ip fpbxnat 2>/dev/null');
	echo "OK: isolated live rules cleaned\n";
} else {
	echo "SKIP: live nft smoke\n";
}

echo "All NftablesTest checks passed.\n";
