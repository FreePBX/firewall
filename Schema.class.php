<?php
namespace FreePBX\modules\Firewall;

/**
 * Firewall configuration schema and cross-version migration.
 *
 * Schema 1: FreePBX 17 and earlier (iptables-era logical model, no schema key).
 * Schema 2: FreePBX 18 transition release with selectable backends.
 * Schema 3: FreePBX 18+ native nftables runtime. Iptables data is import-only.
 */
class Schema {

	const VERSION_LEGACY = 1;
	const VERSION_CURRENT = 3;

	const BACKEND_IPTABLES = 'iptables';
	const BACKEND_NFTABLES = 'nftables';
	const BACKEND_AUTO = 'auto';

	/** Logical KVStore keys preserved across 17 → 18 restores. */
	public static $preservedKeys = array(
		'status',
		'networkmaps',
		'responsivefw',
		'fail2banbypass',
		'dropinvalid',
		'custom_whitelist',
		'dynamic_whitelist',
		'whiteHosts',
		'idregextip',
		'trusted',
		'local',
		'other',
		'servicesettings',
		'rfw',
		'oobeanswered',
		'abortoobe',
		'currentjiffies',
		'import_hosts',
		'customrules',
		'id_sync_fw',
		'syncing',
	);

	/**
	 * Detect schema version from restored/imported settings or live config.
	 *
	 * @param mixed $settings Dump from getConfigs()/dumpKVStore(), or null for live.
	 * @param object|null $fw Firewall module instance
	 * @return int
	 */
	public static function detectVersion($settings = null, $fw = null) {
		$val = null;
		if (is_array($settings)) {
			if (isset($settings['firewall_schema'])) {
				$val = $settings['firewall_schema'];
			} elseif (isset($settings['kvstore']['firewall_schema'])) {
				$val = $settings['kvstore']['firewall_schema'];
			} elseif (isset($settings['meta']['schema'])) {
				$val = $settings['meta']['schema'];
			}
		}
		if ($val === null && $fw) {
			$val = $fw->getConfig('firewall_schema');
		}
		if ($val === null || $val === false || $val === '') {
			return self::VERSION_LEGACY;
		}
		return (int) $val;
	}

	/**
	 * Native nftables is the only supported runtime backend.
	 *
	 * @return string iptables|nftables
	 */
	public static function detectPreferredBackend() {
		return self::BACKEND_NFTABLES;
	}

	public static function nftAvailable() {
		$path = self::which('nft');
		return ($path !== '');
	}

	public static function which($cmd) {
		if (function_exists('fpbx_which')) {
			$p = fpbx_which($cmd);
			return $p ? $p : '';
		}
		$out = array();
		exec('command -v '.escapeshellarg($cmd).' 2>/dev/null', $out, $ret);
		return ($ret === 0 && !empty($out[0])) ? $out[0] : '';
	}

	/**
	 * Resolve configured backend preference to a concrete driver name.
	 *
	 * @param object $fw
	 * @return string Nftables|Unavailable
	 */
	public static function resolveDriverName($fw) {
		return self::nftAvailable() ? 'Nftables' : 'Unavailable';
	}

	/**
	 * Ensure live install has schema/backend metadata (idempotent).
	 *
	 * @param object $fw
	 * @return array meta
	 */
	public static function ensureMeta($fw) {
		$schema = $fw->getConfig('firewall_schema');
		if ($schema === false || $schema === null || $schema === '') {
			$fw->setConfig('firewall_schema', self::VERSION_CURRENT);
			$schema = self::VERSION_CURRENT;
		}
		$backend = $fw->getConfig('firewall_backend');
		if ($backend !== self::BACKEND_NFTABLES) {
			$fw->setConfig('firewall_backend', self::BACKEND_NFTABLES);
			$backend = self::BACKEND_NFTABLES;
		}
		$fw->setConfig('firewall_nftables_enabled', true);
		$customFmt = $fw->getConfig('custom_rules_format');
		if ($customFmt === false || $customFmt === null || $customFmt === '') {
			$hasLegacyRules = (is_file('/etc/firewall-4.rules') && filesize('/etc/firewall-4.rules') > 0)
				|| (is_file('/etc/firewall-6.rules') && filesize('/etc/firewall-6.rules') > 0);
			$customFmt = $hasLegacyRules ? self::BACKEND_IPTABLES : self::BACKEND_NFTABLES;
			$fw->setConfig('custom_rules_format', $customFmt);
		}
		return array(
			'schema' => (int) $schema,
			'backend' => $backend,
			'custom_rules_format' => $customFmt,
			'resolved_driver' => self::resolveDriverName($fw),
			'nft_available' => self::nftAvailable(),
		);
	}

	/**
	 * Build backup metadata (also reflected in KVStore via ensureMeta).
	 *
	 * @param object $fw
	 * @return array
	 */
	public static function buildBackupMeta($fw) {
		$meta = self::ensureMeta($fw);
		$meta['module_version'] = self::moduleVersion();
		$meta['source_freepbx'] = defined('FREEPBX_VERSION') ? FREEPBX_VERSION : '';
		$meta['exported_at'] = gmdate('c');
		return $meta;
	}

	public static function moduleVersion() {
		$xml = __DIR__.'/module.xml';
		if (!is_readable($xml)) {
			return 'unknown';
		}
		$doc = @simplexml_load_file($xml);
		if ($doc && isset($doc->version)) {
			return (string) $doc->version;
		}
		return 'unknown';
	}

	private static function t($msg) {
		return function_exists('_') ? _($msg) : $msg;
	}

	/**
	 * Migrate restored config from older FreePBX (17 / &lt;17) to current schema.
	 * Never discards logical policy; live rules are rebuilt by the driver afterward.
	 *
	 * @param object $fw
	 * @param array|null $settings Raw getConfigs() payload from backup
	 * @param callable|null $log function($msg, $level = 'INFO')
	 * @return array result
	 */
	public static function migrateAfterRestore($fw, $settings = null, $log = null) {
		$log = $log ?: function ($msg, $level = 'INFO') {};
		$from = self::detectVersion($settings, $fw);
		$to = self::VERSION_CURRENT;
		$result = array(
			'from' => $from,
			'to' => $to,
			'migrated' => false,
			'actions' => array(),
		);

		if ($from > $to) {
			$log(sprintf(self::t('Firewall schema %s is newer than this module (%s); leaving as-is.'), $from, $to), 'WARNING');
			return $result;
		}

		if ($from < $to) {
			$log(sprintf(self::t('Migrating Firewall schema %s → %s (native nftables runtime)...'), $from, $to), 'INFO');
			// Older schema → current: preserve logical policy and select native nft.
			$fw->setConfig('firewall_schema', $to);
			$fw->setConfig('firewall_backend', self::BACKEND_NFTABLES);
			$fw->setConfig('firewall_nftables_enabled', true);
			if (!$fw->getConfig('custom_rules_format')) {
				$fw->setConfig('custom_rules_format', self::BACKEND_IPTABLES);
			}
			$result['migrated'] = true;
			$result['actions'][] = 'schema_stamp';
			$result['actions'][] = 'preserve_kvstore';
			$result['actions'][] = 'select_native_nftables';
			$result['actions'][] = 'custom_rules_format_iptables';
			$log(self::t('Firewall logical policy preserved; live rules will be rebuilt by the active driver.'), 'INFO');
		}

		$meta = self::ensureMeta($fw);
		$result['meta'] = $meta;
		$log(sprintf(
			self::t('Firewall schema=%s backend=%s driver=%s'),
			$meta['schema'],
			$meta['backend'],
			$meta['resolved_driver']
		), 'INFO');

		return $result;
	}

	/**
	 * Normalize getConfigs() shapes from older and newer backups.
	 *
	 * @param mixed $settings
	 * @return array kvstore payload suitable for importKVStore()
	 */
	public static function extractKvstore($settings) {
		if (!is_array($settings)) {
			return array();
		}
		if (isset($settings['kvstore']) && is_array($settings['kvstore'])) {
			return $settings['kvstore'];
		}
		return $settings;
	}
}
