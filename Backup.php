<?php
namespace FreePBX\modules\Firewall;
use FreePBX\modules\Backup as Base;
class Backup Extends Base\BackupBase{
	public function runBackup($id,$transaction){
		$settings = $this->dumpKVStore();
		$this->addConfigs($settings);
	}
}
