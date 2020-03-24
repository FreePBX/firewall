<?php
namespace FreePBX\modules\Firewall;
use FreePBX\modules\Backup as Base;
class Restore Extends Base\RestoreBase{
	public function runRestore(){
		$settings = $this->getConfigs();
		$this->importKVStore($settings);
	}

	public function processLegacy($pdo, $data, $tables, $unknownTables){
		$this->restoreLegacyKvstore($pdo);
	}
}
