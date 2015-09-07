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

		// Make sure this zone exists
		$this->checkTarget("zone-$zone");

		// We want to add the smallest networks first, and then move up.
		// So start by grabbing our existing nets (Note: Pass by Ref, to update
		// later)
		$current = &$this->getCurrentIptables();

		// Are we IPv6 or IPv4? Note, again, they're passed as ref, as we array_splice
		// them later
		if (filter_var($network, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
			$ipt = "/sbin/ip6tables";
			$nets = &$current['ipv6']['filter']['fpbxnets'];
		} elseif (filter_var($network, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4)) {
			$ipt = "/sbin/iptables";
			$nets = &$current['ipv4']['filter']['fpbxnets'];
		} else {
			throw new \Exception("Not an IP address $network");
		}

		// This is what we're adding.
		$p = "-s $network/$cidr -j zone-$zone";

		// Find the first network with a netmask smaller than this, and
		// insert it before that one.
		$insert = false;
		foreach ($nets as $i => $n) {
			if ($n === $p) {
				// Woah. It already exists?
				return true;
			}
			if (preg_match("/-s (.+)\/(\d+) -j/", $n, $out)) {
				// print "Found a source network ".$out[1]." - ".$out[2]."\n";
				if ($out[2] < $cidr) {
					// The one we found is smaller than this, so we want
					// to catch it here first.
					$insert = true;
					break;
				}
			}
		}

		// If we're not inserting, just add it
		if (!$insert) {
			$nets[] = $p;
			$cmd = "$ipt -A fpbxnets -s $network/$cidr -j zone-$zone";
		} else {
			// Splice it into the array
			array_splice($nets, $i, 0, $p);
			$i++;
			$cmd = "$ipt -I fpbxnets $i -s $network/$cidr -j zone-$zone";
		}
		print "Running '$cmd'\n";
		exec($cmd, $output, $ret);
		return $ret;
	}

	// Root process
	public function removeNetworkFromZone($zone = false, $network = false, $cidr = false) {
		print "removeNetworkFromZone $zone, $network, $cidr\n";
		$this->checkFpbxFirewall();
		$current = &$this->getCurrentIptables();
		// Are we IPv6 or IPv4? Note, again, they're passed as ref, as we array_splice
		// them later
		if (filter_var($network, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
			$ipt = "/sbin/ip6tables";
			$nets = &$current['ipv6']['filter']['fpbxnets'];
		} elseif (filter_var($network, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4)) {
			$ipt = "/sbin/iptables";
			$nets = &$current['ipv4']['filter']['fpbxnets'];
		} else {
			throw new \Exception("Not an IP address $network");
		}

		// OK, so, let's see if it exists.
		if ($cidr) {
			$p = "-s $network/$cidr -j zone-$zone";
		} else {
			$p = "-s $network -j zone-$zone";
		}
		foreach ($nets as $i => $n) {
			if ($n === $p) {
				// Found it, yay. Remove it from our cache
				array_splice($nets, $i, 1);
				// And remove it from real life
				$i++;
				$cmd = "$ipt -D fpbxnets $i";
				print "Running '$cmd'\n";
				exec($cmd, $output, $ret);
				return $ret;
			}
		}
		print "Didn't find it. Boo\n";
		return false;
	}

	// Root process
	public function changeNetworksZone($newzone = false, $network = false, $cidr = false) {
		print "changeNetworksZone $newzone, $network, $cidr\n";
		$this->checkFpbxFirewall();

		$current = &$this->getCurrentIptables();
		// Are we IPv6 or IPv4? Note, again, they're passed as ref, as we array_splice
		// them later
		if (filter_var($network, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
			$ipt = "/sbin/ip6tables";
			$nets = &$current['ipv6']['filter']['fpbxnets'];
			// Fake CIDR to add later, if we don't have one.
			$fcidr = "/64";
		} elseif (filter_var($network, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4)) {
			$ipt = "/sbin/iptables";
			$nets = &$current['ipv4']['filter']['fpbxnets'];
			$fcidr = "/32";
		} else {
			throw new \Exception("Not an IP address $network");
		}

		// OK, so, let's see if it already exists. It may not, so don't
		// stress too much if it doesn't.
		// Need to check to see if it has a netmask?
		if (strpos($network, "/") === false)  {
			if (!$cidr) {
				$cidr = $fcidr;
			}
		} else {
			list($network, $cidr) = explode($network, "/");
		}

		$p = "-s $network/$cidr -j zone-";

		foreach ($nets as $i => $n) {
			if (strpos($n, $p) === 0) {
				// Found it! Blow it away.
				array_splice($nets, $i, 1);
				// And remove it from real life
				$i++;
				$cmd = "$ipt -D fpbxnets $i";
				print "Running '$cmd'\n";
				exec($cmd, $output, $ret);
				break;
			}
		}

		// Now we can just add it, as we know it's gone.
		return $this->addNetworkToZone($newzone, $network, $cidr);
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
		print "changeInterfaceZone $iface $newzone\n";
		$this->checkFpbxFirewall();
		$this->checkTarget("zone-$newzone");

		// Interfaces are checked AFTER networks, so that source networks
		// can override default interface inputs.
		// First, see if we know about this interface, and delete it if we do.
		$current = &$this->getCurrentIptables();

		// This is the policy we want to remove
		$p = "-i $iface -j zone-";

		// Remove from both ipv4 and ipv6.
		$ipvers = array("ipv6" => "/sbin/ip6tables", "ipv4" => "/sbin/iptables");
		foreach ($ipvers as $ipv => $ipt) {
			$interfaces = &$current[$ipv]['filter']['fpbxinterfaces'];
			foreach ($interfaces as $i => $n) {
				print "Looking for $p against $n\n";
				if (strpos($n, $p) === 0) {
					// Found it! Blow it away.
					array_splice($interfaces, $i, 1);
					// And remove it from real life
					$i++;
					$cmd = "$ipt -D fpbxinterfaces $i";
					print "Running '$cmd'\n";
					exec($cmd, $output, $ret);
					// Break disabled, just to make sure that if there
					// are multiple entries for the same interface, they're
					// all gone.
					// break;
				}
			}
			// Now we can just add it.
			$cmd = "$ipt -A fpbxinterfaces $p$newzone";
			print "Running '$cmd'\n";
			$output = null;
			exec($cmd, $output, $ret);
			$interfaces[] = "$p$newzone";
		}
	}

	// Driver Specific iptables stuff

	// Root process
	private function &getCurrentIptables() {
		if (!$this->currentconf) {
			// Parse iptables-save output
			exec('/sbin/iptables-save 2>&1', $ipv4, $ret);
			exec('/sbin/ip6tables-save 2>&1', $ipv6, $ret);
			$this->currentconf = array(
				"ipv4" => $this->parseIptablesOutput($ipv4),
				"ipv6" => $this->parseIptablesOutput($ipv6),
			);
		}
		// Return as a ref, people may want to mangle it.
		return $this->currentconf;
	}

	private function checkFpbxFirewall() {
		$current = $this->getCurrentIptables();
		if (!$this->isConfigured($current['ipv4'])) {
			// Make sure we've cleaned up
			$this->cleanOurRules();
			// And add our defaults in
			$this->loadDefaultRules();
			exit;
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
			// unset ($rules[$name]);
		}
		return true;
	}

	private function getDefaultRules() {
		$defaults = array();
		$retarr['INPUT'][]= array("jump" => "fpbxfirewall");

		// Default sanity rules. 
		// 1: Always allow all lo traffic, no matter what.
		$retarr['fpbxfirewall'][]= array("int" => "lo", "jump" => "ACCEPT");
		// 2: Allow related/established
		$retarr['fpbxfirewall'][]= array("other" => "-m state --state RELATED,ESTABLISHED", "jump" => "ACCEPT");
		// 3: Always allow ICMP (no, really, you always want to allow ICMP, stop thinking blocking
		// it is a good idea)
		$retarr['fpbxfirewall'][]= array("ipvers" => 4, "proto" => "icmp", "jump" => "ACCEPT");
		$retarr['fpbxfirewall'][]= array("ipvers" => 6, "proto" => "ipv6-icmp", "jump" => "ACCEPT");

		// Now we can do our actual filtering.
		$retarr['fpbxfirewall'][] = array("jump" => "fpbxnets");
		$retarr['fpbxfirewall'][] = array("jump" => "fpbxinterfaces");

		// Our 'trusted' zone is always allow everything.
		$retarr['zone-trusted'][] = array("jump" => "ACCEPT");

		return $retarr;
	}

	private function parseIptablesOutput($iptsave) {
		$table = "unknown";

		$conf = array();

		foreach ($iptsave as $line) {
			if (empty($line)) {
				continue;
			}
			print "Parsing '$line'\n";
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

		if (!isset($arr['ipvers'])) {
			$arr['ipvers'] = "both";
		}

		$parsed = $this->parseFilter($arr);

		print "I have '$parsed' from ".json_encode($arr)."\n";

		if ($arr['ipvers'] == 6 || $arr['ipvers'] == "both") {
			$cmd = "/sbin/ip6tables -A $chain $parsed";
			print "Doing $cmd\n";
			exec($cmd, $output, $ret);
			if ($ret === 0) {
				$this->currentconf['ipv6']['filter'][$chain][] =  $parsed;
			}
		}
		if ($arr['ipvers'] == 4 || $arr['ipvers'] == "both") {
			$cmd = "/sbin/iptables -A $chain $parsed";
			print "Doing $cmd\n";
			exec($cmd, $output, $ret);
			if ($ret === 0) {
				$this->currentconf['ipv4']['filter'][$chain][] =  $parsed;
			}
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

