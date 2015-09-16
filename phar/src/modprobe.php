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
		if (!file_exists("/etc/modprobe.d/ipt_recent.conf")) {
			return true;
		}
		if (!file_exists("/etc/modprobe.d/xt_recent.conf")) {
			return true;
		}
		return false;
	}

	public function updateModprobe() {
		$conf = "options ipt_recent options ip_list_tot=4096 ip_pkt_list_tot=254\n";
		file_put_contents("/etc/modprobe.d/ipt_recent.conf", $conf);
		$conf = "options xt_recent options ip_list_tot=4096 ip_pkt_list_tot=254\n";
		file_put_contents("/etc/modprobe.d/xt_recent.conf", $conf);
		`depmod -a`;
		return true;
	}
}



