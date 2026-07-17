<?php
error_reporting(E_ALL);

require dirname(__DIR__).'/LegacyRulesMigrator.class.php';

use FreePBX\modules\Firewall\LegacyRulesMigrator;

function legacy_assert($condition, $message) {
	if (!$condition) {
		fwrite(STDERR, "FAIL: $message\n");
		exit(1);
	}
	echo "OK: $message\n";
}

$dir = sys_get_temp_dir().'/fpbx-legacy-'.getmypid();
mkdir($dir, 0700);
$v4 = $dir.'/firewall-4.rules';
$v6 = $dir.'/firewall-6.rules';
$out = $dir.'/firewall.nft';
file_put_contents($v4, "-A INPUT -p tcp --dport 2222 -j ACCEPT\n");
file_put_contents($v6, "-A INPUT -p tcp --dport 2222 -j ACCEPT\n");
chmod($v4, 0600);
chmod($v6, 0600);

$migrator = new LegacyRulesMigrator();
$result = $migrator->migrate($v4, $v6, $out);
legacy_assert($result['status'] === true, 'supported INPUT rules migrate');
legacy_assert($result['translated'] === 2, 'IPv4 and IPv6 rules translated');
$native = file_get_contents($out);
legacy_assert(strpos($native, 'add rule inet fpbx fpbxcustom') !== false, 'rules target native custom chain');
legacy_assert(strpos($native, 'iptables') === false, 'output contains no iptables command');

file_put_contents($v4, "-t nat -A POSTROUTING -j MASQUERADE\n");
$before = file_get_contents($out);
$result = $migrator->migrate($v4, $v6, $out);
legacy_assert($result['status'] === false, 'unsupported NAT rule blocks migration');
legacy_assert(file_get_contents($out) === $before, 'failed migration does not change native rules');

$jail = $dir.'/jail.local';
file_put_contents(
	$jail,
	"[sip]\naction = iptables-allports[name=SIP, protocol=all]\n".
	"[ssh]\naction = iptables-multiport[name=SSH, protocol=tcp, port=ssh]\n"
);
legacy_assert($migrator->normalizeFail2Ban($jail) === true, 'Fail2Ban actions normalize');
$jailConfig = file_get_contents($jail);
legacy_assert(strpos($jailConfig, 'action = nftables[name=SIP, type=allports') !== false, 'allports uses nftables');
legacy_assert(strpos($jailConfig, 'action = nftables[name=SSH, type=multiport') !== false, 'multiport uses nftables');
legacy_assert(strpos($jailConfig, 'iptables-') === false, 'Fail2Ban output contains no iptables action');

foreach (glob($dir.'/*') as $file) {
	unlink($file);
}
rmdir($dir);
echo "All LegacyRulesMigratorTest checks passed.\n";
