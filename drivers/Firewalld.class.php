<?php
// TODO: Split this into an interface.
namespace FreePBX\modules\Firewall\Drivers;

// Firewalld - RHEL7-ish.
class Firewalld {

	public function getKnownZones() {
		// This takes a surprisingly long time.
		exec("/usr/bin/firewall-cmd --list-all-zones", $out, $ret);

		$zones = array();

		// Run through the list...
		$currentzone = false;
		foreach ($out as $line) {
			if ($line[0] !== " ") {
				// It's a definition
				$def = explode(" ", $line);
				$currentzone = $def[0];
				if (isset($def[1])) {
					if (strpos($def[1], "default") !== false) {
						$zones[$currentzone]['default'] = true;
					} else {
						$zones[$currentzone]['default'] = false;
					}
					if (strpos($def[1], "active") !== false) {
						$zones[$currentzone]['active'] = true;
					} else {
						$zones[$currentzone]['active'] = false;
					}
				}
				continue;
			}

			// It's a setting!
			if (!$currentzone) {
				throw new \Exception("Somehow got a setting before a zone! ".json_encode($out));
			}

			$settings = explode(":", trim($line));

			if (!isset($settings[1])) {
				$settings[1] = "";
			}
			$zones[$currentzone][$settings[0]] = $settings[1];
		}

		return $zones;
	}
}



