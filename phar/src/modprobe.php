<?php

namespace FreePBX\Firewall;

// Totally unportable. Needs to be fixed.
//
class Modprobe {
	public function checkModules() {
		if ($this->needsUpdate()) {
			$this->updateModprobe();
		}
	}

	public function needsUpdate() {
		if (!file_exists("/etc/modprobe.d/ipt_recent")) {
			return true;
		}
		return false;
	}

	public function updateModprobe() {
		$conf = "options ipt_recent ip_pkt_list_tot=2048\n";

		file_put_contents("/etc/modprobe.d/ipt_recent", $conf);
		`depmod -a`;
		return true;
	}
}



