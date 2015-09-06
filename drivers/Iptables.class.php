<?php
// TODO: Split this into an interface.
namespace FreePBX\modules\Firewall\Drivers;

// Iptables - Generic.
class Iptables {

	private $currentconf = false;

	public function getZonesDetails() {
		// Returns array( "zonename" => array("interfaces" => .., "services" => .., "sources" => .. ), 
		//   "zonename" => .. 
		//   "zonename => ..
		// );
		$default = array("interfaces" => array(), "services" => array(), "sources" => array());
		$zones = array("reject" => $default, "external" => $default, "other" => $default,
			"internal" => $default, "trusted" => $default);

		$current = $this->getCurrentIptables();

		// Check IPv4 for the interface and config settings. IPv6 should be identical. But,
		// if it's broken for some reason, it may not be providing useful information.

		if (!$this->isConfigured($current['ipv4'])) {
			// Not Configured. Treat all our interfaces as 'Trusted'
			$ints = \FreePBX::Firewall()->getInterfaces();
			$zones['trusted']['interfaces'] = join(" ", array_keys($ints));
			return $zones;
		}

		print "Is configured\n";
		print_r($current);
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
		print "getting known\n";
		return $retarr;
	}

	// Root process
	public function commit() {
		// TODO: run iptables-save here.
		return;
	}

	// Root process
	public function addNetworkToZone($zone = false, $network = false, $cidr = false) {
		$this->checkFpbxFirewall();
	}

	// Root process
	public function removeNetworkFromZone($zone = false, $network = false) {
		$this->checkFpbxFirewall();
	}

	// Root process
	public function changeNetworksZone($newzone = false, $network = false) {
		$this->checkFpbxFirewall();
	}

	// Root process
	public function updateService($service = false, $ports = false) {
		$this->checkFpbxFirewall();
	}

	// Root process
	public function updateServiceZones($service = false, $zones = false) {
		$this->checkFpbxFirewall();
	}

	// Root process
	public function changeInterfaceZone($iface = false, $newzone = false) {
		$this->checkFpbxFirewall();
	}

	// Driver Specific iptables stuff

	// Root process
	private function getCurrentIptables() {
		if (!$this->currentconf) {
			// Parse iptables-save output
			exec('/sbin/iptables-save 2>&1', $ipv4, $ret);
			exec('/sbin/ip6tables-save 2>&1', $ipv6, $ret);
			$this->currentconf = array(
				"ipv4" => $this->parseIptablesOutput($ipv4),
				"ipv6" => $this->parseIptablesOutput($ipv6),
			);
		}
		return $this->currentconf;
	}

	private function checkFpbxFirewall() {
		$current = $this->getCurrentIptables();
		if (!$this->isConfigured($current['ipv4'])) {
			// Make sure we've cleaned up
			$this->cleanOurRules();
			// And add our defaults in
			$this->loadDefaultRules();
		}
	}

	private function cleanOurRules() {
		// todo
		return;
	}

	private function loadDefaultRules() {
		$defaults = $this->getDefaultRules();
		// We're here because our first rule isn't there. Insert it.
		$this->insertRule('INPUT', array_shift($defaults['INPUT']));

		// Remove any INPUT rules that may be hanging around, just in case
		// someone adds stuff to 'INPUT' later, and doesn't read the damn
		// code.
                unset($defaults['INPUT']);

                // Now, we need to create the chains for the rest of the rules
                foreach ($defaults as $name => $val) {
                        $this->checkTarget($name);
                        if (!empty($val)) {
                                foreach ($val as $entry) {
                                        $this->addRule($name, $entry);
                                }
                        }
                        unset ($rules[$name]);
                }
                return true;
        }

	private function getDefaultRules() {
		$defaults = array();
		$retarr['INPUT'][]= array("jump" => "fpbxfirewall");

		$retarr['fpbxfirewall'][] = array("jump" => "fpbxnets");
		$retarr['fpbxfirewall'][] = array("jump" => "fpbxinterfaces");

		return $retarr;
	}

	private function parseIptablesOutput($iptsave) {
		$table = "unknown";

		$conf = array();

		foreach ($iptsave as $line) {
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
				$conf[$table][$chain] = array();
				continue;
			}

			// Skip lines we don't care about..
			if ($firstchar != "-") { // Everything we care about now starts with -A
				continue;
			}
			$linearr = explode(" ", $line);
			array_shift($linearr);
			$chain = array_shift($linearr);
			$conf[$table][$chain][] = join(" ", $linearr);
		}

		// Make sure we have SOMETHING there.
		if (!isset($conf['filter'])) {
			$conf['filter'] = array("INPUT" => array());
		}

		return $conf;
	}

	private function isConfigured($ipt) {
		// Check to see that our firewall rule is the first one.
		if (!isset($ipt['filter']) || !isset($ipt['filter']['INPUT'][0])) {
			return false;
		}

		// OK, so what IS the first rule in input?
		if ($ipt['filter']['INPUT'][0] === "-j fpbxfirewall") {
			return true;
		} else {
			return false;
		}
	}

	private function parseFilter($arr) {
		if (!is_array($arr)) {
			throw new \Exception("Wasn't given an array");
		}

		$str = "";
		if (isset($arr['int'])) { $str .= "-i ".$arr['int']." "; }
		if (isset($arr['proto'])) {
			$str .= "-p ".$arr['proto']." ";
			if (isset($arr['dport'])) {
				if (strpos($arr['dport'], ',') === false) {
					$str .= "-m ".$arr['proto']." ";
				} else {
					$str .= "-m multiport ";
				}
			}
		}
		if (isset($arr['src'])) {
			// TODO: Check with ipv6
			list($src) = explode(":", $arr['src']); // eg, $src = explode(":", $arr['src'])[0];
			if (strpos($src, "/") === false) {
				$src .= "/32";
			}
			$str .= "-s $src ";
		}
		if (isset($arr['dport'])) {
			$str .= "--dport ".$arr['dport']." ";
		}
		if (isset($arr['out'])) {
			$str .= "-o ".$arr['out']." ";
		}
		if (isset($arr['other'])) {
			$str .= $arr['other']." ";
		}
		if (isset($arr['jump'])) {
			$str .= "-j ".$arr['jump'];
		}

		if (!$str) {
			throw new \Exception("Wat. Nothing? ".json_encode($arr));
		}

		// Make sure nothing can escape from this.
		return escapeshellcmd($str);
	}

	private function insertRule($chain = false, $arr = false) {
		if (!$chain || !$arr) {
			throw new \Exception("Error with $chain or $arr\n");
		}

		$this->checkTarget($arr['jump']);
		$parsed = $this->parseFilter($arr);

		// IPv4
		$cmd = "/sbin/iptables -I $chain $parsed";
		print "Doing $cmd\n";
		exec($cmd, $output, $ret);
		// Add it to our local array
		array_unshift($this->currentconf['ipv4']['filter'][$chain], $parsed);

		// IPv6
		$cmd = "/sbin/ip6tables -I $chain $parsed";
		print "Doing $cmd\n";
		exec($cmd, $output, $ret);
		// Add it to our local array
		array_unshift($this->currentconf['ipv6']['filter'][$chain], $parsed);
		return;
	}

        private function addRule($chain = false, $arr = false) {
                if (!$chain || !$arr) {
                        throw new \Exception("Error with $chain or $arr\n");
                }

                $this->checkTarget($arr['jump']);
                $parsed = $this->parseFilter($arr);

                $cmd = "/sbin/iptables -A $chain $parsed";
                print "Doing $cmd\n";
                exec($cmd, $output, $ret);

		if ($ret === 0) {
			$this->currentconf['ipv4']['filter'][$chain][] =  $parsed;
		}

                $cmd = "/sbin/ip6tables -A $chain $parsed";
                print "Doing $cmd\n";
                exec($cmd, $output, $ret);

		if ($ret === 0) {
			$this->currentconf['ipv6']['filter'][$chain][] =  $parsed;
		}

		return;
	}

	private function checkTarget($target = false) {
		if (!$target) {
			throw new \Exception("No Target");
		}

		switch ($target) {
		case 'ACCEPT':
		case 'REJECT':
		case 'DROP':
			return true;
		default:
			// If it's all upper case, we assume you know what you're doing.
			if (ctype_upper($target)) {
				return true;
			}
			// Does this chain target already exist?
			if (isset($this->currentconf['ipv4']['filter'][$target]) && isset($this->currentconf['ipv6']['filter'][$target])) {
				return true;
			}
		}

		// It doesn't exist.

		// IPv4
		$cmd = "/sbin/iptables -N ".escapeshellcmd($target);
		print "Doing $cmd\n";
		exec($cmd, $output, $ret);
		if ($ret == 0) {
			$this->currentconf['ipv4']['filter'][$target] = array();
		}

		$output = null;
		// IPv6
		$cmd = "/sbin/ip6tables -N ".escapeshellcmd($target);
		print "Doing $cmd\n";
		exec($cmd, $output, $ret);
		if ($ret == 0) {
			$this->currentconf['ipv6']['filter'][$target] = array();
		}
	}
}

