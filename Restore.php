<?php
namespace FreePBX\modules\Firewall;
use FreePBX\modules\Backup as Base;
class Restore Extends Base\RestoreBase{
	public function runRestore(){
		$settings = $this->getConfigs();
		$this->importKVStore($settings);

		$files = $this->getFiles();
		$nfiles = 0;
		foreach($files as $file){
			if($file->getType() != 'firewall rules') { 
				continue;
			}

			$dest = $file->getPathTo().'/'.$file->getFilename();
			$source = $this->tmpdir.'/files'.$dest;

			if(file_exists($source)){
				if(file_exists($dest)) {
					$dest_old = $dest."_".date('YmdHisu');
					rename($dest, $dest_old);
					$this->log(sprintf(_("The destine file exist, save backup file: %s"), $dest_old),'INFO');
				}
				copy($source, $dest);
				chown($dest, "root");
				chmod($dest, 0644);
				$nfiles++;
			}
		}
		$this->log(sprintf(_("%s Files Restored"), $nfiles++),'INFO');
	}

	public function processLegacy($pdo, $data, $tables, $unknownTables){
		$this->restoreLegacyKvstore($pdo);
	}
}
