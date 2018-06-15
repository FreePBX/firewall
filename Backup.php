<?php
namespace FreePBX\modules\Firewall;
use FreePBX\modules\Backup as Base;
class Backup Extends Base\BackupBase{
    public function runBackup($id,$transaction){
        $kvstoreids = $this->FreePBX->Firewall->getAllids();
        $kvstoreids[] = 'noid';
        $settings = [];
        foreach ($kvstoreids as $value) {
            $settings[$value] = $this->FreePBX->Filestore->getAll($value);
        }
        $this->addConfigs($settings);
    }
}