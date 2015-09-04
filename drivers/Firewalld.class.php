<?php
// TODO: Split this into an interface.
namespace FreePBX\modules\Firewall\Drivers;

// Firewalld - RHEL7-ish.
class Firewalld {

	public function getZonesDetails() {
		// Caching
		static $out = false;
		if ($out === false) {
			// This takes a surprisingly long time.
			exec("/usr/bin/firewall-cmd --list-all-zones", $out, $ret);
		}
		if (isset($ret) && $ret) {
			throw new \Exception("Error: $ret - ".json_encode($out));
		}

		$zones = array();

		// Run through the list...
		$currentzone = false;
		foreach ($out as $id => $line) {
			if (!isset($line[0])) {
				continue;
			}
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

			$settings = explode(":", trim($line), 2);

			if (!isset($settings[1])) {
				$settings[1] = "";
			}
			$zones[$currentzone][$settings[0]] = $settings[1];
		}

		// Rename 'work' to 'other'
		$zones['other'] = $zones['work'];
		unset($zones['work']);

		return $zones;
	}

	public function getKnownNetworks() {
		// Returns array that looks like ("network/cdr" => "zone", "network/cdr" => "zone")
		$known = $this->getZonesDetails();
		$retarr = array();
		foreach ($known as $z => $settings) {
			if (empty($settings['sources'])) {
				continue;
			}
			$sources = explode(" ", $settings['sources']);
			foreach ($sources as $source) {
				if (!empty($source)) {
					$retarr[$source] = $z;
				}
			}
		}
		return $retarr;
	}

	// Root process
	public function commit() {
		print "I shouldn't need to be run\n";
		return;
		$cmd = "firewall-cmd --reload";
		exec($cmd, $out, $ret);
		if ($ret) {
			throw new \Exception("Error: $ret - ".json_encode($out));
		}
		return true;
	}

	// Root process
	public function addNetworkToZone($zone = false, $network = false, $cidr = false) {
		$z = new \FreePBX\modules\Firewall\Zones();
		$knownzones = $z->getZones();
		if (!isset($knownzones[$zone])) {
			throw new \Exception("Unknown zone $zone");
		}

		// We are using 'work' for 'other'
		if ($zone === "other") {
			$zone = "work";
		}

		// Add live rule
		$cmd = "firewall-cmd --zone=$zone --add-source $network/$cidr";
		exec($cmd, $out, $ret);

		// Set permanent rule
		$cmd = "firewall-cmd --permanent --zone=$zone --add-source $network/$cidr";
		exec($cmd, $out, $ret);

		return true;
	}

	// Root process
	public function removeNetworkFromZone($zone = false, $network = false) {
		// We are using 'work' for 'other'
		if ($zone === "other") {
			$zone = "work";
		}

		$cmd = "firewall-cmd --zone=$zone --remove-source $network";
		exec($cmd, $out, $ret);

		$cmd = "firewall-cmd --permanent --zone=$zone --remove-source $network";
		exec($cmd, $out, $ret);
	}

	// Root process
	public function changeNetworksZone($newzone = false, $network = false) {
		// We are using 'work' for 'other'
		if ($newzone === "other") {
			$newzone = "work";
		}

		$cmd = "firewall-cmd --zone=$newzone --change-source $network";
		exec($cmd, $out, $ret);

		$cmd = "firewall-cmd --permanent --zone=$newzone --change-source $network";
		exec($cmd, $out, $ret);
	}

	// Root process
	public function updateService($service = false, $ports = false) {
		$servicefile = "/etc/firewalld/services/fpbx-$service.xml";
		if (strpos($servicefile, "..") !== false) {
			throw new \Exception("Invalid service filename $servicefile");
		}

		if ($ports === false) {
			// Delete the service
			$cmd = "firewall-cmd --delete-service fpbx-$service";
			exec($cmd, $out, $ret);
			$cmd = "firewall-cmd --permanent --delete-service fpbx-$service";
			exec($cmd, $out, $ret);

			if (file_exists($servicefile)) {
				unlink($servicefile);
			}
			return;
		} elseif (!$ports) {
			return;
		} else {
			// We're creating/updating a service file.
			// No-one's trying to be nasty are they? That would never happen...
			if (is_link($servicefile)) {
				throw new \Exception("$servicefile is a symbolic link. Can't continue.");
			}

			// Note ? and > are split apart to avoid syntax highlighting getting confused.
			$xml = "<?xml version='1.0' encoding='utf-8'?".">\n<service name='fpbx-$service' version='1.0'>\n";
			$xml .= "  <short>fpbx-$service</short>\n";
			foreach ($ports as $arr) {
				$xml .= "  <port protocol='".$arr['protocol']."' port='".$arr['port']."' />\n";
			}
			$xml .= "</service>\n";
			$newservice = false;

			if (!file_exists($servicefile)) {
				$newservice = true;
			}

			file_put_contents($servicefile, $xml);

			if ($newservice) {
				// Tell firewalld about the service
				$cmd = "firewall-cmd --new-service=fpbx-service";
				exec($cmd, $out, $ret);

				$cmd = "firewall-cmd --permanent --new-service=fpbx-service";
				exec($cmd, $out, $ret);
			}
		}
	}

	// Root process
	public function updateServiceZones($service = false, $zones = false) {
		if (!is_array($zones)) {
			throw new \Exception("zones invalid");
		}

		$servicefile = "/etc/firewalld/services/fpbx-$service.xml";
		if (strpos($servicefile, "..") !== false) {
			throw new \Exception("Invalid service filename $servicefile");
		}

		if (!file_exists($servicefile)) {
			// Has already been deleted
			return;
		}

		// Remove service from zones it shouldn't be in..
		foreach ($zones['removefrom'] as $z) {
			// We are using 'work' for 'other'
			if ($z === "other") {
				$z = "work";
			}
			$cmd = "firewall-cmd --zone=$z --remove-service=fpbx-$service";
			exec($cmd, $out, $ret);

			$cmd = "firewall-cmd --permanent --zone=$z --remove-service=fpbx-$service";
			exec($cmd, $out, $ret);
		}

		// Add it to the zones it should be
		foreach ($zones['addto'] as $z) {
			// We are using 'work' for 'other'
			if ($z === "other") {
				$z = "work";
			}
			$cmd = "firewall-cmd --zone=$z --add-service=fpbx-$service";
			exec($cmd, $out, $ret);

			$cmd = "firewall-cmd --permanent --zone=$z --add-service=fpbx-$service";
			exec($cmd, $out, $ret);
		}
	}

	// Root process
	public function changeInterfaceZone($iface = false, $newzone = false) {
		if ($newzone === "other") {
			$newzone = "work";
		}
		$cmd = "firewall-cmd --zone=$newzone --change-interface=$iface";
		exec($cmd, $out, $ret);
		$cmd = "firewall-cmd  --permanent --zone=$newzone --change-interface=$iface";
		exec($cmd, $out, $ret);

		// SHMZ/CentOS/RHEL/etc - Update the zone in ifcfg-$iface
		$centos = "/etc/sysconfig/network-scripts/ifcfg-$iface";
		if (file_exists($centos)) {
			if (is_link($centos)) {
				throw new \Exception("Symlink?");
			}

			// Grab the contents of the file
			$ifcfg = @parse_ini_file($centos, \INI_SCANNER_RAW);

			// If it doesn't have a zone
			if (!isset($ifcfg['ZONE'])) {
				// Add it to the file
				file_put_contents($centos, "\nZONE=$newzone\n", \FILE_APPEND);
			} else {
				// Replace whatever it was
				$rawfile = file_get_contents($centos);
				$newfile = preg_replace('/^ZONE.+$/m', "ZONE=$newzone", $rawfile);
				file_put_contents($centos, $newfile);
			}
		}
	}
}

