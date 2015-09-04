<?php
// TODO: Split this into an interface.
namespace FreePBX\modules\Firewall\Drivers;

// Iptables - Generic.
class Iptables {

	public function getKnownZones() {
		// Returns array( "zonename" => array("interfaces" => .., "services" => .., "sources" => .. ), 
		//   "zonename" => .. 
		//   "zonename => ..
		// );
	}

	public function getKnownNetworks() {
		// Returns array that looks like ("network/cdr" => "zone", "network/cdr" => "zone")
		$known = $this->getKnownZones();
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
	}

	// Root process
	public function addNetworkToZone($zone = false, $network = false, $cidr = false) {
	}

	// Root process
	public function removeNetworkFromZone($zone = false, $network = false) {
	}

	// Root process
	public function changeNetworksZone($newzone = false, $network = false) {
	}

	// Root process
	public function updateService($service = false, $ports = false) {
	}

	// Root process
	public function updateServiceZones($service = false, $zones = false) {
	}

	// Root process
	public function changeInterfaceZone($iface = false, $newzone = false) {
	}
}

