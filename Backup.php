<?php
namespace FreePBX\modules\Firewall;
use FreePBX\modules\Backup as Base;
class Backup Extends Base\BackupBase{
	public function runBackup($id,$transaction){
		$fw = \FreePBX::Firewall();
		foreach ($fw::$filesCustomRules as $file) {
			if (file_exists($file)) {
				if (is_readable($file)) {
					$this->addFile(basename($file), pathinfo($file, PATHINFO_DIRNAME), '', "firewall rules");
				} else {
					$this->log(sprintf(_("Unable to read file: %s"), $file),'ERROR');
				}
			}
		}

		$settings = $this->dumpKVStore();
		$this->addConfigs($settings);
	}
}
