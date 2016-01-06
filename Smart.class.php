<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
namespace FreePBX\modules\Firewall;

class Smart {

	private $db; // DB handle
	private $chansip = false; // This machine uses chansip
	private $pjsip = false; // This machine uses pjsip
	private $iax = false; // This machine uses IAX

	public function __construct($db = false) {

		if (!$db || !($db instanceof \PDO)) {
			throw new \Exception("Need a PDO Database handle");
		}

		$this->db = $db;
		$driver = \FreePBX::Config()->get('ASTSIPDRIVER');
		switch ($driver) {
		case 'both':
			$this->chansip = true;
			$this->pjsip = true;
			break;
		case 'chan_pjsip':
			$this->pjsip = true;
			break;
		case 'chan_sip':
			$this->chansip = true;
			break;
		default:
			throw new \Exception("Crazy driver setting $driver");
		}

		$this->iax = $this->usesIax();
	}

	public function getSettings() {
		$retarr = array("ssf" => true, "period" => 60, "responsive" => false);
		$retarr['rprotocols'] = array(
			"pjsip" => array("state" => true, "descr" => _("SIP Protocol (pjsip)")),
			"chansip" => array("state" => true, "descr" => _("Legacy SIP (chan_sip)")),
			"iax" => array("state" => false, "descr" => _("IAX Protocol")),
		);
		if (\FreePBX::Firewall()->getConfig("responsivefw")) {
			$retarr['responsive'] = true;
			foreach ($retarr['rprotocols'] as $id => $null) {
				$retarr['rprotocols'][$id]['state'] = \FreePBX::Firewall()->getConfig($id, "rfw");
			}
		};
		return $retarr;
	}

	private function usesIax() {
		// Does this machine have any IAX devices?
		$sql = "SELECT `id` FROM `iax` LIMIT 1";
		$q = $this->db->query($sql);
		$rows = $q->fetchAll(\PDO::FETCH_ASSOC);
		return (!empty($rows));
	}

	public function getAllPorts() {
		// Returns ALL ports.
		$retarr = array(
			'signalling' => $this->getVoipPorts(),
			'rtp' => $this->getRTPPorts(),
			'udptl' => array("start" => 4000, "end" => 4999), // This is not configurable.
			'known' => $this->getKnown(),
			'registrations' => $this->getRegistrations(),
		);
		return $retarr;
	}

	public function getVoipPorts() {
		$ports = $this->getSipPorts();
		if ($this->iax) {
			$ports['udp'][] = $this->getIaxPort();
		}
		return $ports;
	}

	public function getRTPPorts() {
		// These are always open to the world, on every interface.
		// The only limitation is that we don't let people be dumb, and we'll
		// never return less than 1024, or more than 65000. As RTP runs on
		// UDP, it's not THAT critical, but better to be safe than sorry.
		//
		// Yes. This are just random ranges that I made up as 'reasonable'.
		//
		$s = \FreePBX::Sipsettings();
		$sipsettings = $s->genConfig();
		$ports = $sipsettings['rtp_additional.conf']['general'];
		$start = (int) $ports['rtpstart'];
		$end = (int) $ports['rtpend'];
		if ($start < 1024) {
			$start = 1024;
		}
		if ($end > 65000) {
			$end = 65000;
		}

		// Make sure start and end are the right way round...
		if ($end < $start) {
			return array("start" => $end, "end" => $start);
		} else {
			return array("start" => $start, "end" => $end);
		}
	}

	public function getIaxPort() {
		$sql = "SELECT `keyword`, `data` FROM `iaxsettings` WHERE `keyword` LIKE 'bind%'";
		$q = $this->db->query($sql);
		$iax = $q->fetchAll(\PDO::FETCH_ASSOC);

		$bindport = 4569;
		$bindaddr = "0.0.0.0";

		foreach ($iax as $res) {
			if (empty($res['data'])) {
				continue;
			}
			if ($res['keyword'] == "bindport") {
				$bindport = $res['data'];
			} elseif ($res['keyword'] == "bindaddr") {
				$bindaddr = $res['data'];
			}
		}
		return array("dest" => $bindaddr, "dport" => $bindport, "name" => "iax");
	}

	public function getSipPorts() {
		// Returns an array of ports or ranges used by SIP or PJSIP.
		$udp = array();
		$tcp = array();

		// Let's get chansip settings if we need them.
		if ($this->chansip) {
			$bindport = "";
			$settings = \FreePBX::Sipsettings()->getChanSipSettings(true);
			foreach ($settings as $arr) {
				if (empty($arr['data'])) {
					continue;
				}
				if ($arr['keyword'] == 'bindport') {
					$bindport = $arr['data'];
					break;
				}
			}
			if (empty($bindport)) {
				$bindport = 5060;
			}

			$udp[] = array("dest" => "0.0.0.0", "dport" => $bindport, "name" => "chansip");

			// TODO: chan_sip TCP.. Maybe
		}

		// Do we have pjsip?
		if ($this->pjsip) {
			// Woo. What are our settings?
			$ss = \FreePBX::Sipsettings();
			$allBinds = $ss->getConfig("binds");
			$websocket = false;
			foreach ($allBinds as $type => $listenArr) {
				// What interface(s) are we listening on?
				foreach ($listenArr as $ipaddr => $mode) {
					if ($mode != "on") {
						continue;
					}
					if ($type == "ws" || $type == "wss") {
						$websocket = \FreePBX::Config()->get('HTTPBINDPORT');
						continue;
					}
					$port = $ss->getConfig($type."port-".$ipaddr);
					if (!$port) {
						continue;
					}
					if ($type == "tcp") {
						$tcp[] = array("dest" => $ipaddr, "dport" => $port, "name" => "pjsip");
					} elseif ($type == "udp") {
						$udp[] = array("dest" => $ipaddr, "dport" => $port, "name" => "pjsip");
					} else {
						throw new \Exception("Unknown protocol $type");
					}
				}
			}
			if ($websocket) {
				$tcp[] = array("dest" => $ipaddr, "dport" => $websocket, "name" => "pjsip");
			}
		}

		$retarr = array("udp" => $udp, "tcp" => $tcp);
		return $retarr;
	}

	public function getKnown() {
		// Figure out who our known entities are.
		$discovered = array();

		if ($this->chansip) {
			// Trunks and extens are both in the 'sip' table.
			$sql = "SELECT `data` FROM `sip` WHERE `keyword`='host'";
			$q = $this->db->query($sql);
			$siphosts = $q->fetchAll(\PDO::FETCH_ASSOC);
			foreach ($siphosts as $sip) {
				// Trim anything after a semicolon, which could be a comment
				$hostarr = explode(";", $sip['data']);
				$host = trim($hostarr[0]);
				if ($host == "dynamic") {
					continue;
				}
				$discovered[$host] = true;
			}

			// Does an extension specifically permit a range?
			$sql = "SELECT `data` FROM `sip` WHERE `keyword`='permit'";
			$q = $this->db->query($sql);
			$sippermits = $q->fetchAll(\PDO::FETCH_ASSOC);
			foreach ($sippermits as $sip) {
				// permits may be seperated by ampersands, so
				// make sure they are all added.
				$permits = explode("&", $sip['data']);
				foreach ($permits as $p) {
					$discovered[$p] = true;
				}
			}
		}

		if ($this->iax) {
			// Find IAX trunks...
			$sql = "SELECT `data` FROM `iax` WHERE `keyword`='host'";
			$q = $this->db->query($sql);
			$iaxhosts = $q->fetchAll(\PDO::FETCH_ASSOC);
			foreach ($iaxhosts as $iax) {
				// Trim anything after a semicolon, which could be a comment
				$hostarr = explode(";", $iax['data']);
				$host = trim($hostarr[0]);
				if ($host == "dynamic") {
					continue;
				}
				$discovered[$host] = true;
			}

			// Extensions?
			$sql = "SELECT `data` FROM `iax` WHERE `keyword`='permit'";
			$q = $this->db->query($sql);
			$iaxpermits = $q->fetchAll(\PDO::FETCH_ASSOC);
			foreach ($iaxpermits as $iax) {
				// permits may be seperated by ampersands, so
				// make sure they are all added.
				$permits = explode("&", $iax['data']);
				foreach ($permits as $p) {
					$discovered[$p] = true;
				}
			}
		}

		// PJSIP?
		if ($this->pjsip) {
			$sql = "SELECT `data` FROM `pjsip` WHERE `keyword`='sip_server'";
			$q = $this->db->query($sql);
			$pjsiptrunks = $q->fetchAll(\PDO::FETCH_ASSOC);
			foreach ($pjsiptrunks as $p) {
				if (!empty($p['data'])) {
					$discovered[$p['data']] = true;
				}
			}
			// PJSip extensions don't have allow/deny at the moment.
		}

		// Now validate them all!
		$retarr = array();
		foreach (array_keys($discovered) as $d) {
			// Ensure we don't start with "0.0.0.0"
			if (strpos($d, "0.0.0.0") === 0) {
				continue;
			}

			// Is this an IP address?
			if (filter_var($d, FILTER_VALIDATE_IP)) {
				$retarr[] = $d;
				continue;
			}

			// Is this a Network definition?
			if (strpos($d, "/") !== false) {
				// Yes it is.
				$retarr = array_merge($retarr, $this->parseCidr($d));
				continue;
			}

			// Well that means it's a hostname.
			$retarr = array_merge($retarr, $this->lookup($d));
		}
		return $retarr;
	}
	
	public function parseCidr($entry = false) {
		if (!$entry) {
			throw new \Exception("No CIDR Given");
		}

		// To start with, does it have a / in it?
		if (strpos($entry, "/") === false) {
			throw new \Exception("Asked to parse $entry, don't know why");
		}

		// Good.
		list($subnet, $cidr) = explode("/", $entry);

		// And it's a valid subnet, right?
		if (!filter_var($subnet, FILTER_VALIDATE_IP)) {
			// Wut.
			return array();
		}

		// OK. We either have IP/CIDR or a IP/NETMASK
		// If cidr validates as an IP address, that means it's a netmask.
		if (filter_var($cidr, FILTER_VALIDATE_IP)) {
			// netmask.
			return array($subnet."/".$cidr);
		}

		// Otherwise it should be a valid CIDR.
		if ((int) $cidr >= 8 && (int) $cidr <= 32) {
			$netmask = pow(2,$cidr) - 1;
			$netmask = long2ip($netmask << (32 - $cidr));
			return array($subnet."/".$netmask);
		}
		return array();
	}

	public function lookup($host = false, $allowcache = true) {
		static $cache;

		if (!$host) {
			throw new \Exception("No host given");
		}

		// This is for PHP 5.4 and below
		if (!is_array($cache)) {
			$cache = array();
		}

		// Do we need to refresh this lookup?
		if (!$allowcache) {
			unset($cache[$host]);
		}

		// Have we looked this up previously?
		if (!isset($cache[$host])) {
			// No.  OK, so is this an IP?
			if (filter_var($host, FILTER_VALIDATE_IP)) {
				// Well that was easy.
				$cache[$host] = array($host);
				return array($host);
			}

			// Let's do some DNS-ing
			// TODO: See how this goes. It might be better to use something like http://www.purplepixie.org/phpdns/
			//
			$dns = dns_get_record($host, \DNS_A|\DNS_AAAA);
			$retarr = array();

			// TODO: IPv6
			foreach ($dns as $record) {
				if ($record['type'] == "A") {
					$retarr[$record['ip']] = true;
				}
			}

			$keys = array_keys($retarr);
			$cache[$host] = $keys;
		}
		$ret = $cache[$host];
		return $ret;
	}

	public function getRegistrations() {
		// Get all registered devices
		$astman = \FreePBX::create()->astman;
		// This gives us an array
		$contacts = $this->getPjsipContacts($astman);
		// Pass by ref to the rest to remove dupes
		$this->getChansipContacts($astman, $contacts);
		$this->getIaxContacts($astman, $contacts);
		return array_keys($contacts);
	}

	private function getPjsipContacts($astman) {

		$response = $astman->send_request('Command',array('Command'=>"pjsip show contacts"));
		// This is an amazingly awful format to parse.
		$lines = explode("\n", $response['data']);
		$inheader = true;
		$istrunk = $isendpoint = false;
		$contacts = array();
		foreach ($lines as $l) {
			if ($inheader) {
				if (isset($l[1]) && $l[1] == "=") {
					// Last line of the header.
					$inheader = false;
				}
				continue;
			}

			$l = trim($l);
			if (!$l) {
				continue;
			}

			// If we have a line starting with 'Contact:' then we found one!
			// This will be along the lines of '400/sip:400@192.168.15.38:5061          Avail     10.121'
			if (strpos($l, "Contact:") === 0) {
				if (preg_match("/Contact:\s+(.+)@(.+?)\s/", $l, $out)) {
					// Ok, we have a contact. This should be an IP address. Is it?
					if (preg_match("/(?:\[?)([0-9a-f:\.]+)(?:\]?):(.+)/", $out[2], $ipaddr)) {
						$contacts[$ipaddr[1]] = true;
					} else {
						// It's a hostname, likely to be a trunk. Don't resolve,
						// as we've already done that as part of the registration
						// print "Unknown host ".$out[2].", trunk?\n";
						continue;
					}
				}
			}
		}
		return $contacts;
	}

	private function getChansipContacts($astman, &$contacts) {
		$response = $astman->send_request('Command',array('Command'=>"sip show peers"));
		$lines = explode("\n", $response['data']);
		foreach ($lines as $l) {
			if (!$l) {
				continue;
			}
			$tmparr = preg_split("/\s+/", $l);
			if (filter_var($tmparr[1], FILTER_VALIDATE_IP)) {
				$contacts[$tmparr[1]] = true;
			}
		}
	}

	private function getIaxContacts($astman, &$contacts) {
		$response = $astman->send_request('Command',array('Command'=>"iax2 show peers"));
		$lines = explode("\n", $response['data']);
		foreach ($lines as $l) {
			if (!$l) {
				continue;
			}
			$tmparr = preg_split("/\s+/", $l);
			if (filter_var($tmparr[1], FILTER_VALIDATE_IP)) {
				$contacts[$tmparr[1]] = true;
			}
		}
	}



}
