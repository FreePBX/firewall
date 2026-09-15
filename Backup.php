<?php
namespace FreePBX\modules\Firewall;
use FreePBX\modules\Backup as Base;
class Backup Extends Base\BackupBase{
	public function runBackup($id,$transaction){
		$fw = \FreePBX::Firewall();

		if (!class_exists('\FreePBX\modules\Firewall\Schema')) {
			include __DIR__.'/Schema.class.php';
		}

		// Stamp schema/backend meta into KVStore so 18→18 restores stay explicit,
		// and 17→18 restores can detect missing meta as schema 1.
		$meta = Schema::buildBackupMeta($fw);
		$fw->setConfig('firewall_schema', $meta['schema']);
		$fw->setConfig('firewall_backend', $meta['backend']);
		$fw->setConfig('custom_rules_format', $meta['custom_rules_format']);
		$fw->setConfig('firewall_backup_meta', $meta);

		foreach ($fw::$filesCustomRules as $file) {
			if (file_exists($file)) {
				if (is_readable($file)) {
					$this->addFile(basename($file), pathinfo($file, PATHINFO_DIRNAME), '', "firewall rules");
				} else {
					$this->log(sprintf(_("Unable to read file: %s"), $file),'ERROR');
				}
			}
		}

		// Optional nftables custom rules file (FreePBX 18+)
		$nftCustom = '/etc/firewall.nft';
		if (file_exists($nftCustom) && is_readable($nftCustom)) {
			$this->addFile(basename($nftCustom), pathinfo($nftCustom, PATHINFO_DIRNAME), '', "firewall rules");
		}

		$settings = $this->dumpKVStore();
		// Dual shape: keep flat kvstore for older Restore paths, plus structured meta.
		$this->addConfigs(array(
			'kvstore' => $settings,
			'meta' => $meta,
			// Also merge top-level for modules that import the whole payload historically.
			'firewall_schema' => $meta['schema'],
			'firewall_backend' => $meta['backend'],
			'custom_rules_format' => $meta['custom_rules_format'],
		) + (is_array($settings) ? $settings : array()));
	}
}
