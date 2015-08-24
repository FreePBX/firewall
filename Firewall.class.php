<?php
// vim: set ai ts=4 sw=4 ft=php:
namespace FreePBX\modules;

class Firewall extends \FreePBX_Helpers implements \BMO {

	public static $dbDefaults = array("status" => false);

	private static $services = false;

	public function install() {}
	public function uninstall() {}
	public function backup() {}
	public function restore($backup) {}

	public function chownFreepbx() {
		$files = array(
			array('type' => 'execdir',
			'path' => __DIR__."/hooks",
			'perms' => 0755),
			array('type' => 'execdir',
			'path' => __DIR__."/phar",
			'perms' => 0755)
		);
		return $files;
	}

	public function dashboardService() {
		return array();
	}

	// Run a sysadmin-managed root hook.
	public function runHook($hookname,$params = false) {
		// Runs a new style Syadmin hook
		if (!file_exists("/etc/incron.d/sysadmin")) {
			throw new \Exception("Sysadmin RPM not up to date");
		}

		$basedir = "/var/spool/asterisk/incron";
		if (!is_dir($basedir)) {
			throw new \Exception("$basedir is not a directory");
		}

		// Does our hook actually exist?
		if (!file_exists(__DIR__."/hooks/$hookname")) {
			throw new \Exception("Hook $hookname doesn't exist");
		}

		// So this is the hook I want to run
		$filename = "$basedir/firewall.$hookname";

		// Do I have any params?
		if ($params) {
			// Oh. I do. If it's an array, json encode and base64
			if (is_array($params)) {
				$b = base64_encode(gzcompress(json_encode($params)));
				// Note we derp the base64, changing / to _, because filepath.
				$filename .= ".".str_replace('/', '_', $b);
			} elseif (is_object($params)) {
				throw new \Exception("Can't pass objects to hooks");
			} else {
				// Cast it to a string if it's anything else, and then make sure
				// it doesn't have any spaces.
				$filename .= ".".preg_replace("/[[:blank:]]+/", (string) $params);
			}
		}

		$fh = fopen($filename, "w+");
		if ($fh === false) {
			// WTF, unable to create file?
			throw new \Exception("Unable to create hook trigger '$filename'");
		}

		// As soon as we close it, incron does its thing.
		fclose($fh);

		// Wait .5 of a second, make sure it's been deleted.
		usleep(500000);
		if (file_exists($filename)) {
			throw new \Exception("Hook file '$filename' was not picked up by Incron. Is it not running?");
		}
		return true;
	}

	public function startFirewall() {
		print "I would start the service now...\n";
	}

	public function isEnabled() {
		return $this->getConfig("status");
	}

	public function showDisabled() {
		// Firewall functions disabled
		return load_view(__DIR__."/views/disabled.php", array("fw" => $this));
	}

	public function showBootnav($page) {
		return load_view(__DIR__."/views/bootnav.php", array("fw" => $this, "thispage" => $page));
	}

	public function showPage($page) {
		if (strpos($page, ".") !== false) {
			throw new \Exception("Invalid page name $page");
		}
		$view = __DIR__."/views/page.$page.php";
		if (!file_exists($view)) {
			throw new \Exception("Can't find page $page");
		}

		return load_view($view, array("fw" => $this));
	}

	// Ajax calls
	public function ajaxRequest($req, &$settings) {
		return true;
	}

	public function ajaxHandler() {
		switch ($_REQUEST['command']) {
		case "removenetwork":
			if (!isset($_REQUEST['net'])) {
				throw new \Exception("No net");
			}
			return $this->removeNetwork($_REQUEST['net']);
		case "addnetworktozone":
			if (!isset($_REQUEST['net'])) {
				throw new \Exception("No net");
			}
			if (!isset($_REQUEST['zone'])) {
				throw new \Exception("No Zone");
			}
			$zones = $this->getZones();
			if (!isset($zones[$_REQUEST['zone']])) {
				throw new \Exception("Invalid zone $zone");
			}
			return $this->addNetworkToZone($_REQUEST['net'], $_REQUEST['zone']);
		case "updatenetwork":
			if (!isset($_REQUEST['net'])) {
				throw new \Exception("No net");
			}
			if (!isset($_REQUEST['zone'])) {
				throw new \Exception("No Zone");
			}
			return $this->changeNetworksZone($_REQUEST['net'], $_REQUEST['zone']);
		case "addrfc":
			return $this->addRfcNetworks();
		default:
			throw new \Exception("Sad Panda");
		}
	}

	// Now comes the real code. Let's catch the POST and see if there's an action
	public function doConfigPageInit($display) {
		$action = $this->getReq('action');
		switch ($action) {
		case false:
			return;
		case 'enablefw':
			$this->setConfig("status", true);
			return;
		default:
			throw new \Exception("Unknown action $action");
		}
	}

	public function getServices() {
		if (!self::$services) {
			include 'Services.class.php';
			self::$services = new Firewall\Services;
		}

		$retarr = array("core" => self::$services->getCoreServices(), "extra" => self::$services->getExtraServices());
		return $retarr;
	}

	public function getService($svc = false) {
		if (!$svc) {
			throw new \Exception("No service?");
		}
		if (!self::$services) {
			include 'Services.class.php';
			self::$services = new Firewall\Services;
		}

		return self::$services->getService($svc);
	}

	public function getZones() {
		static $zones = false;
		if (!$zones) {
			include 'Zones.class.php';
			$z = new Firewall\Zones;
			$zones = $z->getZones();
		}
		return $zones;
	}

	public function getInterfaces() {
		static $ints = false;
		if (!$ints) {
			include 'Network.class.php';
			$n = new Firewall\Network;
			$ints = $n->discoverInterfaces();
		}
		return $ints;
	}

	public function getZone($int) {
		static $ints = false;
		if (!$ints) {
			$ints = array();
			$zones = $this->getSystemZones();
			foreach ($zones as $name => $zone) {
				if (!$zone['interfaces']) {
					continue;
				}
				foreach (explode(" ", $zone['interfaces']) as $i) {
					$myInt = trim($i);
					if ($myInt) {
						$ints[$myInt] = $name;
					}
				}
			}
		}
		if (!isset($ints[$int])) {
			$ints[$int] = 'trusted';
		}

		return $ints[$int];
	}

	private function getDriver() {

		if (!class_exists('\FreePBX\modules\Firewall\Driver')) {
			include __DIR__."/Driver.class.php";
		}

		$d = new Firewall\Driver;
		return $d->getDriver();
	}

	public function getSystemZones() {
		$d = $this->getDriver();
		return $d->getKnownZones();
	}

	public function getZoneNetworks() {
		$d = $this->getDriver();
		return $d->getKnownNetworks();
	}

	public function detectNetwork() {
		$client = $_SERVER['REMOTE_ADDR'];
		// If this is an IPv4 address, treat it as a class C
		if (filter_var($client, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4)) {
			$ip = ip2long($client) & ip2long('255.255.255.0');
			return long2ip($ip)."/24";
		} elseif (filter_var($client, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
			// Grab the first 8 bytes, add zeros
			$prefix = unpack("H16", inet_pton($client));
			$map = $prefix[1]."0000000000000000";
			// Put it back into IPv6 format and give it back
			return inet_ntop(pack("H32", $map))."/64";
		} else {
			throw new \Exception("Unkown client $client");
		}
	}

	public function detectHost() {
		return $_SERVER['REMOTE_ADDR'];
	}

	// /////////////// //
	// Ajax Code below //
	// /////////////// //
	public function removeNetwork($net = false) {
		$nets = $this->getZoneNetworks();
		// Is this network part of a zone?
		if (!isset($nets[$net])) {
			throw new \Exception("Unknown zone");
		}
		return $this->runHook("removenetwork", array("network" => $net, "zone" => $nets[$net]));
	}

	public function addNetworkToZone($net = false, $zone = false) {
		// Is this an IP address?
		if (strpos($net, "/") !== false) {
			list($ip, $subnet) = explode("/", $net);
		} else {
			$ip = $net;
			$subnet = 32;
		}

		// Make sure this is a valid address
		$ip = trim($ip);
		if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
			throw new \Exception("$ip is not a valid IPv4 network");
		}

		// Check subnet.. 
		$subnet = (int) $subnet;
		if ($subnet < 8 || $subnet > 32) {
			throw new \Exception("Invalid subnet $realsubnet");
		}

		$params = array($zone => array("$ip/$subnet"));
		return $this->runHook("addnetwork", $params);
	}

	public function changeNetworksZone($net, $zone) {
		$nets = $this->getZoneNetworks();
		// Is this network part of a zone?
		if (!isset($nets[$net])) {
			throw new \Exception("Unknown network");
		}
		return $this->runHook("changenetwork", array("network" => $net, "newzone" => $zone));
	}

	// Add RFC1918 addresses to the trusted zone
	public function addRfcNetworks() {
		return $this->runHook("addrfcnetworks");
	}

	// Get all FreePBX services, as they are currently set
	// Note that this is **also** used by bin/getservices
	public function getSmartPorts() {
		if (!class_exists('\FreePBX\modules\Firewall\Smart')) {
			include __DIR__."/Smart.class.php";
		}
		$smart = new Firewall\Smart($this->Database());
		return $smart->getAllPorts();
	}

	public function canRevert() {
		$ftok = ftok("/dev/shm/ipc_firewall", "a");
		$segment = shm_attach($ftok, 1048576, 0666); // Create/attach to 10k shared memory segment
		if (!shm_has_var($segment, 0)) { // Hasn't been used
			return false;
		}

		$settings = shm_get_var($segment, 0);
		if (isset($settings['timestamp']) && !isset($settings['confirmed'])) {
			return $settings['timestamp'];
		}

		return false;
	}
}


