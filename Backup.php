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
		if ($this->isAdvancedRecoveryBackup($id)) {
			$this->data['skip_reset'] = true;
		}
	}

	/**
	 * True when this backup is the Advanced Recovery job.
	 * The flag is stored in the module manifest and honored on restore.
	 */
	private function isAdvancedRecoveryBackup($id): bool {
		if ($id === null || $id === '') {
			return false;
		}
		try {
			if (!\FreePBX::Modules()->checkStatus('adv_recovery')) {
				return false;
			}
			$jobid = \FreePBX::Adv_recovery()->getAdvrJobId();
		} catch (\Throwable $e) {
			return false;
		}
		return !empty($jobid) && (string) $jobid === (string) $id;
	}
}
