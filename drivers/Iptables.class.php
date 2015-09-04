<?php
// TODO: Split this into an interface.
namespace FreePBX\modules\Firewall\Drivers;

// Iptables - Generic.
class Iptables {

	public function getZonesDetails() {
		// Returns array( "zonename" => array("interfaces" => .., "services" => .., "sources" => .. ), 
		//   "zonename" => .. 
		//   "zonename => ..
		// );
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

	// Driver Specific iptables stuff

	// Root process
	private function getCurrentIptables() {
		// Parse iptables-save output
		exec('/sbin/iptables-save 2>&1', $ipv4, $ret);
		exec('/sbin/ip6tables-save 2>&1', $ipv6, $ret);
		$retarr = array("ipv4" => $this->parseIptablesOutput($ipv4),
			"ipv6" => $this->parseIptablesOutput($ipv6),
		);

		return $retarr;
	}

	private function parseIptablesOutput($iptsave) {
		$table = "unknown";
		foreach ($output as $line) {
			if (empty($line)) {
				continue;
			}
			$firstchar = $line[0];

			if ($firstchar == "*") {
				// It's a new table.
				$table = substr($line, 1);
				continue;
			}

			if ($firstchar == ":") {
				// It's a chain definition
				list($chain, $stuff) = explode(" ", $line);
				$chain = substr($chain, 1);
				$this->currentconf[$table][$chain] = array();
				continue;
			}

			// Skip lines we don't care about..
			if ($firstchar != "-") { // Everything we care about now starts with -A
				continue;
			}
			$linearr = explode(" ", $line);
			array_shift($linearr);
			$chain = array_shift($linearr);
			$this->currentconf[$table][$chain][] = join(" ", $linearr);
		}

		// Make sure we have SOMETHING there.
		if (!isset($this->currentconf['filter'])) {
			$this->currentconf['filter'] = array("INPUT" => array());
		}
	}
}

