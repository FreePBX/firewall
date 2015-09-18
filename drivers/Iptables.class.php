<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4:
//
// TODO: Split this into an interface.
namespace FreePBX\modules\Firewall\Drivers;

// Iptables - Generic.
class Iptables {

	private $currentconf = false;

	public function l($str) {
		if (function_exists("fwLog")) {
			fwLog($str);
		} else {
			print "LOG: $str\n";
		}
	}

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

		return $current;
	}

	public function getKnownNetworks() {
		// Returns array that looks like ("network/cdr" => "zone", "network/cdr" => "zone")
		$known = $this->getCurrentIptables();
		$retarr = array();
		$ipvers = array("ipv6", "ipv4");
		foreach ($ipvers as $i) {
			if (!isset($known[$i]['filter']['fpbxnets'])) {
				// Odd.
				continue;
			}
			foreach ($known[$i]['filter']['fpbxnets'] as $z => $settings) {
				if (preg_match("/-s (.+) -j zone-(.+)/", $settings, $out)) {
					$retarr[$out[1]] = $out[2];
				}
			}
		}
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
		$this->l($cmd);
		exec($cmd, $output, $ret);
		return $ret;
	}

	// Root process
	public function removeNetworkFromZone($zone = false, $network = false, $cidr = false) {

		$this->checkFpbxFirewall();

		// Check to see if we have a cidr or not.
		if (strpos($network, "/") !== false) {
			list($network, $cidr) = explode("/", $network);
		}
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
				$this->l($cmd);
				exec($cmd, $output, $ret);
				return $ret;
			}
		}
		return false;
	}

	// Root process
	public function changeNetworksZone($newzone = false, $network = false, $cidr = false) {
		$this->checkFpbxFirewall();

		// Check to see if we have a cidr or not.
		if ($cidr === false && strpos($network, "/") !== false) {
			list($network, $cidr) = explode("/", $network);
		}
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
				$this->l($cmd);
				exec($cmd, $output, $ret);
			}
		}

		// Now we can just add it, as we know it's gone.
		return $this->addNetworkToZone($newzone, $network, $cidr);
	}

	// Root process
	public function updateService($service = false, $ports = false) {
		$this->checkFpbxFirewall();

		$name = "fpbxsvc-$service";
		$this->checkTarget($name);

		$current = &$this->getCurrentIptables();

		// Create a service!
		$ipvers = array("ipv6" => "/sbin/ip6tables", "ipv4" => "/sbin/iptables");
		foreach ($ipvers as $ipv => $ipt) {
			$changed = false;
			// Service name is 'fpbxsvc-$service'
			if (!isset($current[$ipv]['filter'][$name])) {
				$changed = true;
				$current[$ipv]['filter'][$name] = array();
			} else {
				// It exists, does it have the correct ports?
				$flipped = array_flip($current[$ipv]['filter'][$name]);

				// Are we deleting/ignoring this?
				if ($ports === false) {
					if (isset($flipped['-j RETURN'])) {
						unset($flipped['-j RETURN']);
					} else {
						$changed = true;
					}
				} else {
					foreach ($ports as $tmparr) {
						$protocol = $tmparr['protocol'];
						$port = $tmparr['port'];
						$param = "-p $protocol -m $protocol --dport $port -j ACCEPT";
						if (isset($flipped[$param])) {
							unset($flipped[$param]);
						} else {
							$changed = true;
							break;
						}
					}
				}

				if (!$changed) {
					// Make sure there's nothing left
					if (count($flipped) !== 0) {
						$changed = true;
					}
				}
			}

			if ($changed) {
				// Flush our old rules, add our new ones.
				$current[$ipv]['filter'][$name] = array();
				$cmd = "$ipt -F $name";
				$this->l($cmd);
				exec($cmd, $output, $ret);

				// Add the new ones
				if ($ports === false) {
					// Just return
					$param = "-j RETURN";
					$current[$ipv]['filter'][$name][] = $param;
					$cmd = "$ipt -A $name $param";
					$this->l($cmd);
					exec($cmd, $output, $ret);
				} else {
					foreach ($ports as $arr) {
						$protocol = $arr['protocol'];
						$port = $arr['port'];
						$param = "-p $protocol -m $protocol --dport $port -j ACCEPT";
						$current[$ipv]['filter'][$name][] = $param;
						$cmd = "$ipt -A $name $param";
						$this->l($cmd);
						exec($cmd, $output, $ret);
					}
				}
			}
		}
	}

	// Root process
	public function updateServiceZones($service = false, $zones = false) {
		$this->checkFpbxFirewall();
		$current = &$this->getCurrentIptables();

		$name = "fpbxsvc-$service";

		// Check to make sure we know about this service.
		$ipvers = array("ipv6" => "/sbin/ip6tables", "ipv4" => "/sbin/iptables");
		foreach ($ipvers as $ipv => $ipt) {
			if (!isset($current[$ipv]['filter'][$name])) {
				throw new \Exception("Can't add a $ipv service for $name, it doesn't exist");
			}
			// Remove service from zones it shouldn't be in..
			$live = &$current[$ipv]['filter'];
			foreach ($zones['removefrom'] as $z) {
				$this->checkTarget("zone-$z");
				// Loop through, make sure it's not in this zone
				foreach ($live["zone-$z"] as $i => $lzone) {
					if ($lzone == "-j $name") {
						unset($live["zone-$z"][$i]);
						$i++;
						$cmd = "$ipt -D zone-$z $i";
						$this->l($cmd);
						exec($cmd, $output, $ret);
					}
				}
			}

			// Add it to the zones it should be
			foreach ($zones['addto'] as $z) {
				$this->checkTarget("zone-$z");
				// Loop through, add it if it's not here.
				$found = false;
				foreach ($live["zone-$z"] as $i => $lzone) {
					if ($lzone == "-j $name") {
						$found = true;
					}
				}

				if (!$found) {
					// Need to add it.
					$live["zone-$z"][] = "-j $name";
					$cmd = "$ipt -A zone-$z -j $name";
					$this->l($cmd);
					exec($cmd, $output, $ret);
				}
			}
		}
	}

	// Root process
	public function changeInterfaceZone($iface = false, $newzone = false) {
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
				if (strpos($n, $p) === 0) {
					// Found it! Blow it away.
					array_splice($interfaces, $i, 1);
					// And remove it from real life
					$i++;
					$cmd = "$ipt -D fpbxinterfaces $i";
					$this->l($cmd);
					exec($cmd, $output, $ret);
					// Break disabled, just to make sure that if there
					// are multiple entries for the same interface, they're
					// all gone.
					// break;
				}
			}
			// Now we can just add it.
			$cmd = "$ipt -A fpbxinterfaces $p$newzone";
			$this->l($cmd);
			$output = null;
			exec($cmd, $output, $ret);
			$interfaces[] = "$p$newzone";
		}

		$net = new \FreePBX\modules\Firewall\Network;
		$net->updateInterfaceZone($iface, $newzone);
	}

	public function setRtpPorts($rtp = false) {
		if (!is_array($rtp)) {
			throw new \Exception("rtp neesds to be an array");
		}

		// Our protocol string
		$proto = "-p udp -m udp --dport ".$rtp['start'].":".$rtp['end']." -j ACCEPT";
		// We add this _before_ fpbxsignalling in iptables
		$current = &$this->getCurrentIptables();
		
		$ipvers = array("ipv6" => "/sbin/ip6tables", "ipv4" => "/sbin/iptables");
		foreach ($ipvers as $ipv => $ipt) {
			$me = &$current[$ipv]['filter']['fpbxfirewall'];
			foreach ($me as $i => $line) {
				if (strpos($line, "-p udp -m udp --dport") !== false) {
					// It's already there. Does it need updating?
					if ($line === $proto) {
						break;
					} else {
						// It needs to be updated.
						$me[$i] = $proto;
						$i++;
						$cmd = "$ipt -R fpbxfirewall $i $proto";
						$this->l($cmd);
						exec($cmd, $output, $ret);
						break;
					}
				}
				if (strpos($line, "-j fpbxsignalling") !== false) {
					// We made it to the fpbxnets check, but we didn't find the rtp
					// entry.  Insert it.
					array_splice($me, $i, 0, $proto);
					$i++;
					$cmd = "$ipt -I fpbxfirewall $i $proto";
					$this->l($cmd);
					exec($cmd, $output, $ret);
					break;
				}
			}
		}
		return true;
	}

	public function updateTargets($rules) {
		// Create fpbxsmarthosts targets and signalling targets
		//
		// 1: Signalling targets
		$this->checkTarget("fpbxsignalling");
		$ports = $rules['smartports']['signalling'];
		$current = &$this->getCurrentIptables();
		$ipvers = array("ipv6" => "/sbin/ip6tables", "ipv4" => "/sbin/iptables");
		foreach ($ipvers as $ipv => $ipt) {
			$me = &$current[$ipv]['filter']['fpbxsignalling'];
			if (!is_array($me)) {
				$me = array();
			}
			$exists = array_flip($me);
			foreach ($ports as $proto => $r) {
				foreach ($r as $rule) {
					$rule['proto'] = $proto;
					// If we are allowing this protocol through to the rfw, tag it with the second bit, as well.
					if ($rules['settings']['rprotocols'][$rule['name']]['state']) {
						$p = trim($this->parseFilter($rule))." -j MARK --set-xmark 0x3/0x0";
					} else {
						$p = trim($this->parseFilter($rule))." -j MARK --set-xmark 0x1/0x0";
					}
					if (isset($exists[$p])) {
						unset($exists[$p]);
						continue;
					}

					// Doesn't exist. Add it.
					$me[] = $p;
					$cmd = "$ipt -A fpbxsignalling $p";
					$this->l($cmd);
					exec($cmd, $output, $ret);
				}
			}

			// If there are any left in exists, we need to remove them.
			$delids = array();

			foreach ($exists as $rule => $i) {
				// We delete the rule from iptables first...
				$cmd = "$ipt -D fpbxsignalling $rule";
				$this->l($cmd);
				exec($cmd, $output, $ret);

				// And then grab the ID, so we can remove the entries in *reverse* order,
				// so we don't lose our place.
				$delids[] = $i;
			}

			// Now if there were any to be deleted, we delete them from the end backwards, 
			// so our cache doesn't get out of whack.
			arsort($delids);
			foreach ($delids as $i) {
				// NOW we can remove it from our cache
				array_splice($me, $i, 1);
			}
		}

		// Now create the entries in fpbxsmarthosts
		$hosts = $rules['smartports']['known'];
		$me = &$current[$ipv]['filter']['fpbxsmarthosts'];
		if (!is_array($me)) {
			$me = array();
		}

		// Run through the hosts and add them to what we WANT our chains to be
		$wanted = array("4" => array(), "6" => array());
		foreach ($hosts as $addr) {
			if (filter_var($addr, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
				$wanted[6][] = $addr;
			} elseif (filter_var($addr, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4)) {
				$wanted[4][] = $addr;
			} else {
				throw new \Exception("Unknown host address $addr");
			}
		}

		// And now add or remove them as neccesary. We do a bit of
		// array mangling so I can avoid code duplication.

		$smarthosts = array("ipv6" => array("ipt" => "/sbin/ip6tables", "targets" => $wanted[6], "prefix" => "128"),
			"ipv4" => array("ipt" => "/sbin/iptables", "targets" => $wanted[4], "prefix" => "32"),
		);

		foreach ($smarthosts as $ipv => $tmparr) {
			$me = &$current[$ipv]['filter']['fpbxsmarthosts'];
			$exists = array_flip($me);
			$process = $tmparr['targets'];
			foreach ($process as $addr) {
				$p = "-s $addr/".$tmparr['prefix']." -m mark --mark 0x1 -j ACCEPT";
				if (isset($exists[$p])) {
					// It's already there, no need to change
					unset($exists[$p]);
					continue;
				}
				// It doesn't exist. We need to add it.
				$me[] = $p;
				$cmd = $tmparr['ipt']." -A fpbxsmarthosts $p";
				$this->l($cmd);
				exec($cmd, $output, $ret);
			}

			// Are any left over? They can be removed.
			$delids = array();

			foreach ($exists as $rule => $i) {
				// We delete the rule from iptables first...
				$cmd = $tmparr['ipt']." -D fpbxsmarthosts $rule";
				$this->l($cmd);
				exec($cmd, $output, $ret);

				// And then grab the ID, so we can remove the entries in *reverse* order,
				// so we don't lose our place.
				$delids[] = $i;
			}

			// Now if there were any to be deleted, we delete them from the end backwards, 
			// so our cache doesn't get out of whack.
			arsort($delids);
			foreach ($delids as $i) {
				// NOW we can remove it from our cache
				array_splice($me, $i, 1);
			}
		}
	}

	public function updateRegistrations($hosts) {
		// Allow registered hosts through without hitting the rate limits
		$this->checkTarget("fpbxregistrations");
		// Run through the hosts and add them to what we WANT our chains to be
		$wanted = array("4" => array(), "6" => array());
		foreach ($hosts as $addr) {
			if (filter_var($addr, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
				$wanted[6][] = $addr;
			} elseif (filter_var($addr, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4)) {
				$wanted[4][] = $addr;
			} else {
				throw new \Exception("Unknown host address $addr");
			}
		}

		// And now add or remove them as neccesary. We do a bit of
		// array mangling so I can avoid code duplication.
		$ipvers = array("ipv6" => array("ipt" => "/sbin/ip6tables", "targets" => $wanted[6], "prefix" => "128"),
			"ipv4" => array("ipt" => "/sbin/iptables", "targets" => $wanted[4], "prefix" => "32"),
		);

		$current = &$this->getCurrentIptables();
		foreach ($ipvers as $ipv => $tmparr) {
			if (!$tmparr) {
				continue;
			}
			$me = &$current[$ipv]['filter']['fpbxregistrations'];
			$exists = array_flip($me);
			$process = $tmparr['targets'];
			foreach ($process as $addr) {
				$p = "-s $addr/".$tmparr['prefix']." -j fpbxknownreg";
				if (isset($exists[$p])) {
					// It's already there, no need to change
					unset($exists[$p]);
					continue;
				}
				// It doesn't exist. We need to add it.
				$me[] = $p;
				$cmd = $tmparr['ipt']." -A fpbxregistrations $p";
				$this->l($cmd);
				exec($cmd, $output, $ret);
			}

			// Are any left over? They can be removed.

			$delids = array();
			foreach ($exists as $rule => $i) {
				// We delete the rule from iptables first...
				$cmd = $tmparr['ipt']." -D fpbxregistrations $rule";
				$this->l($cmd);
				exec($cmd, $output, $ret);

				// And then grab the ID, so we can remove the entries in *reverse* order,
				// so we don't lose our place.
				$delids[] = $i;
			}

			// Now if there were any to be deleted, we delete them from the end backwards, 
			// so our cache doesn't get out of whack.
			arsort($delids);
			foreach ($delids as $i) {
				// NOW we can remove it from our cache
				array_splice($me, $i, 1);
			}
		}
	}

	// Driver Specific iptables stuff
	// Root process
	private function &getCurrentIptables() {
		if (!$this->currentconf) {
			// Am I root?
			if (posix_getuid() === 0) {
				// Parse iptables-save output
				exec('/sbin/iptables-save 2>&1', $ipv4, $ret);
				exec('/sbin/ip6tables-save 2>&1', $ipv6, $ret);
				$this->currentconf = array(
					"ipv4" => $this->parseIptablesOutput($ipv4),
					"ipv6" => $this->parseIptablesOutput($ipv6),
				);
			} else {
				// Not root, need to run a hook.
				@unlink("/tmp/iptables.out");
				\FreePBX::Firewall()->runHook("getiptables");
				// Wait for up to 5 seconds for the output.
				$crashafter = time() + 5;
				while (!file_exists("/tmp/iptables.out")) {
					if ($crashafter > time()) {
						throw new \Exception("/tmp/iptables.out wasn't created");
					}
					usleep(200000);
				}

				// OK, it exists. We should be able to parse it as json
				while (true) {
					$json = file_get_contents("/tmp/iptables.out");
					$res = json_decode($json, true);
					if (!is_array($res)) {
						if ($crashafter > time()) {
							throw new \Exception("/tmp/iptables.out wasn't valid json");
						}
						usleep(200000);
					} else {
						$this->currentconf = $res;
						break;
					}
				}
			}
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
		// 2: Allow related/established - TCP ONLY!
		$retarr['fpbxfirewall'][]= array("proto" => "tcp", "other" => "-m state --state RELATED,ESTABLISHED", "jump" => "ACCEPT");
		// 3: Always allow ICMP (no, really, you always want to allow ICMP, stop thinking blocking
		// it is a good idea)
		$retarr['fpbxfirewall'][]= array("ipvers" => 4, "proto" => "icmp", "jump" => "ACCEPT");
		$retarr['fpbxfirewall'][]= array("ipvers" => 6, "proto" => "ipv6-icmp", "jump" => "ACCEPT");

		// Now we can do our actual filtering.
		// This marks VoIP Signalling packets
		$retarr['fpbxfirewall'][] = array("jump" => "fpbxsignalling");
		// This allows packets marked as signalling through if they're
		// from known hosts.
		$retarr['fpbxfirewall'][] = array("jump" => "fpbxsmarthosts");
		// This allows known networks
		$retarr['fpbxfirewall'][] = array("jump" => "fpbxnets");
		// And known interfaces.
		$retarr['fpbxfirewall'][] = array("jump" => "fpbxinterfaces");
		// If this is a VoIP Signalling packet from an unknown host, and it's eligible for
		// RFW, then send it off there.
		$retarr['fpbxfirewall'][] = array("other" => "-m mark --mark 0x2/0x2", "jump" => "fpbxrfw");

		// Our 'trusted' zone is always allow everything.
		$retarr['zone-trusted'][] = array("jump" => "ACCEPT");

		// VoIP Rate limiting happens here. If they've made it here, they're an unknown host
		// sending VoIP *signalling* here. We want to give them a bit of slack, to make sure
		// it's not a dynamic IP address of a known good client.
		//
		// Hardcoded defaults for unknown clients is up to 10 packets in 60 seconds,
		// before they get clamped.
		$retarr['fpbxrfw'][] = array("other" => "-m recent --rcheck --seconds 60 --hitcount 10 --name SIGNALLING --rsource", "jump" => "fpbxlogdrop");
		// Note, this is *deliberately* after the check. Otherwise it'll never time out.
		$retarr['fpbxrfw'][] = array("other" => "-m recent --set --name SIGNALLING --rsource");
		//
		// However, we're a lot less forgiving over the longer term. Maximum of 100 unknown signalling
		// requests per day.  (This is actually MORE than 100, as this is only hit for packets that
		// haven't been filtered by our other rate limiting. I'm happy with these defaults, but,
		// I'm also willing to be told I'm wrong, and I suck. Grab me on #freepbx (X-Rob) and tell me
		// why I suck.)
		//
		// This is *deliberately* above the check, to ensure that once they've been caught by this
		// filter, the only way out is to leave us alone.
		$retarr['fpbxrfw'][] = array("other" => "-m recent --set --name UNKNOWN --rsource");
		$retarr['fpbxrfw'][] = array("other" => "-m recent --rcheck --seconds 86400 --hitcount 100 --name UNKNOWN --rsource", "jump" => "fpbxlogdrop");
		// OK, hasn't exceeded any rate limiting, good to go now.
		$retarr['fpbxrfw'][] = array("jump" => "LOG", "append" => " --log-prefix 'Not rate limited: '");
		$retarr['fpbxrfw'][] = array("jump" => "ACCEPT");

		// Log dropped packets. This should be visible in the GUI at some point.
		$retarr['fpbxlogdrop'][] = array("jump" => "LOG", "append" => " --log-prefix 'Would drop: '");
		// $retarr['fpbxlogdrop'][] = array("jump" => "REJECT");

		// Known Registrations are allowed to access signalling and UCP
		$retarr['fpbxknownreg'][] = array("other" => "-m mark --mark 0x1", "jump" => "ACCEPT");
		$retarr['fpbxknownreg'][] = array("jump" => "fpbxsvc-ucp");

		return $retarr;
	}

	private function parseIptablesOutput($iptsave) {
		$table = "unknown";

		$conf = array();

		foreach ($iptsave as $line) {
			if (empty($line)) {
				continue;
			}
			// print "Parsing '$line'\n";
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
			// Has something else been smart and tried to inject itself before us?
			foreach ($ipt['filter']['INPUT'] as $i => $r) {
				if ($r === "-j fpbxfirewall") {
					// Yes. Yes they have. 
					// TODO: Move it back to the first spot.
					return true;
				}
			}
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

		if (isset($arr['append'])) {
			$str .= $arr['append'];
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
		$this->l($cmd);
		exec($cmd, $output, $ret);
		// Add it to our local array
		array_unshift($this->currentconf['ipv4']['filter'][$chain], $parsed);

		// IPv6
		$cmd = "/sbin/ip6tables -I $chain $parsed";
		$this->l($cmd);
		exec($cmd, $output, $ret);
		// Add it to our local array
		array_unshift($this->currentconf['ipv6']['filter'][$chain], $parsed);
		return;
	}

	private function addRule($chain = false, $arr = false) {
		if (!$chain || !$arr) {
			throw new \Exception("Error with $chain or $arr\n");
		}

		if (isset($arr['jump'])) {
			$this->checkTarget($arr['jump']);
		}

		if (!isset($arr['ipvers'])) {
			$arr['ipvers'] = "both";
		}

		$parsed = $this->parseFilter($arr);

		if ($arr['ipvers'] == 6 || $arr['ipvers'] == "both") {
			$cmd = "/sbin/ip6tables -A $chain $parsed";
			$this->l($cmd);
			exec($cmd, $output, $ret);
			if ($ret === 0) {
				$this->currentconf['ipv6']['filter'][$chain][] =  $parsed;
			}
		}
		if ($arr['ipvers'] == 4 || $arr['ipvers'] == "both") {
			$cmd = "/sbin/iptables -A $chain $parsed";
			$this->l($cmd);
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
		$this->l($cmd);
		exec($cmd, $output, $ret);
		if ($ret == 0) {
			$this->currentconf['ipv4']['filter'][$target] = array();
		}

		$output = null;
		// IPv6
		$cmd = "/sbin/ip6tables -N ".escapeshellcmd($target);
		$this->l($cmd);
		exec($cmd, $output, $ret);
		if ($ret == 0) {
			$this->currentconf['ipv6']['filter'][$target] = array();
		}
	}
}

