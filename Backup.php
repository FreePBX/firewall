<?php
namespace FreePBX\modules\Firewall;
use FreePBX\modules\Backup as Base;
class Backup Extends Base\BackupBase{
	public function runBackup($id,$transaction){

		$l_files = array('/etc/firewall-4.rules', '/etc/firewall-6.rules');
		foreach ($l_files as $file) {
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
