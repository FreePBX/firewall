<?php
namespace FreePBX\modules\Firewall;
use FreePBX\modules\Backup as Base;
class Restore Extends Base\RestoreBase{
	public function runRestore(){
		
		if (! $this->preHook() ) {
			return false;
		}

		$settings = $this->getConfigs();
		$this->importKVStore($settings);

		$files = $this->getFiles();
		$nfiles = 0;
		$nfiles_err = 0;
		foreach($files as $file){
			if($file->getType() != 'firewall rules') { 
				continue;
			}

			$filename=$file->getFilename();
			$dest = $file->getPathTo().'/'.$filename;
			$source = $this->tmpdir.'/files'.$dest;

			if(file_exists($source)){
				if(file_exists($dest) and is_readable($dest)) {
					$path_back="/etc/asterisk/backup";
					$file_backup = $path_back."/".$filename.".bk.".date('YmdHisu');
					if (! is_dir($path_back)) {
						mkdir($path_back);
					}
					copy($dest, $file_backup);
					$this->log(sprintf(_("The file exists, a backup copy is saved in: %s"), $file_backup),'INFO');
				}
				
				if (!@copy($source, $dest)) {
					$errors= error_get_last();
					if ($errors['type'] == 2) {
						$this->log(sprintf(_("Error!! Permission denied copy rules: %s"), $dest),'ERROR');
						$this->log(_("**FIX** Manual action needed:\n # fwconsole firewall fix_custom_rules\n"),'ERROR');
					} else {
						$this->log(sprintf(_("** Error!!!\n Type: %s\n Message: %s\n File: %s\n"), $errors['type'], $errors['message'], $dest),'ERROR');
					}
					$nfiles_err++;
				} else {
					$this->log(sprintf(_("Firewall recovery rules: %s"), $dest),'INFO');
					$nfiles++;
				}
			}
		}
		$this->log(sprintf(_("%s Files Restored OK"), $nfiles++),'INFO');
		if ($nfiles_err > 0) {
			$this->log(sprintf(_("%s Files Not Restored by Error!!"), $nfiles++),'INFO');	
		}
	}

	public function processLegacy($pdo, $data, $tables, $unknownTables){
		$this->restoreLegacyKvstore($pdo);
	}


	public function preHook(){
		$fw = \FreePBX::Firewall();

		if(\FreePBX::Modules()->checkStatus("sysadmin")) {
			$this->log('Check Custrom Rules...');
			$hookfile = "/var/spool/asterisk/incron/firewall.fixcustomrules";
			if (file_exists($hookfile)) {
				@unlink($hookfile);
			}
			@fclose(@fopen($hookfile, "w"));


			$timeoutDef = 10;
			$timeout = $timeoutDef;
			$completed = false;
			while ( True ):
				if ( $fw->is_exist_custom_rules_files() ) {
					$completed = true;
					break;
				}

				if ( 0 >= $timeout ) {
					break;
				} elseif ($timeout === ($timeoutDef - 1 ) )  {
					$this->log('Waiting...');
				} elseif ($timeout < ($timeoutDef - 1 ) )  {
					$this->log('Timeout in ' . $timeout . ' seconds !');
				}
				$timeout -= 1;
				sleep(1);
			endwhile;

			if (!$completed) {
				$this->log('ERROR: Custom rule recovery process aborted, timeout exceeded!!!');
				$this->log('ERROR: Requires manual execution of the following command:');
				$this->log('# fwconsole firewall fix_custom_rules');
				return false;
			}

		} else {
			$this->log('INFO: Not detected module Sysadmin.');

			//TODO: Pending check chown + chmod
			if ( ! $fw->is_exist_custom_rules_files() ) {
				$this->log('ERROR: Files required for custom rules are missing, run the following command for manual repair !!!');
				$this->log('# fwconsole firewall fix_custom_rules');
				return false;
			} else {
				$this->log('WARNING: If custom firewall rules are not retrieved correctly, run the following command to force manual repair of the necessary files.');
				$this->log('# fwconsole firewall fix_custom_rules');
			}
		}

		return true;
	}

}
