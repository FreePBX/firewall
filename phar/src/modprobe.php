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

		// This can be removed after all machines with the broken .conf files would have been upgraded.
		// Say by 2016-01-01
		if (hash_file("sha256", "/etc/modprobe.d/ipt_recent.conf") !== "5c47da497377a2def8b0944a0767736e2aefd6fe5f833eb38121646c41086461") {
			return true;
		}
		if (hash_file("sha256", "/etc/modprobe.d/xt_recent.conf") !== "bf3cabcda96799f1b37cb26f7992b4c98f3a66fe8242ea5970f63de3d004c751") {
			return true;
		}

		return false;
	}

	public function updateModprobe() {
		$conf = "options ipt_recent ip_list_tot=4096 ip_pkt_list_tot=254\n";
		file_put_contents("/etc/modprobe.d/ipt_recent.conf", $conf);
		$conf = "options xt_recent ip_list_tot=4096 ip_pkt_list_tot=254\n";
		file_put_contents("/etc/modprobe.d/xt_recent.conf", $conf);
		`depmod -a`;
		return true;
	}
}



