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
			throw new \Exception("Sysadmin RPM not up to date, or not a known OS. Can not start System Firewall. See http://bit.ly/fpbxfirewall");
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
		$this->runHook("firewall");
	}

	public function isEnabled() {
		return $this->getConfig("status");
	}

	public function showLockoutWarning() {
		if (!$this->isTrusted()) {
			$thishost = $this->detectHost();
			print "<div class='alert alert-warning' id='lockoutwarning'>";
			print "<p>".sprintf(_("The client machine you are using to manage this server (<tt>%s</tt>) is <strong>not</strong> a member of the Trusted zone. It is highly recommended to add this client to your Trusted Zone to avoid accidental lockouts."), $thishost)."</p>";
			print "<p><a href='?display=firewall&page=about&tab=shortcuts'>"._("You can add the host automatically here.")."</a></p>";
			print "</div>";
		}
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
		case "addthishost":
			return $this->runHook('addnetwork', array('trusted' => array($this->detectHost())));
		case "addthisnetwork":
			return $this->runHook('addnetwork', array('trusted' => array($this->detectNetwork())));
		case "updateinterface":
			return $this->runHook('updateinterface', array('iface' => $_REQUEST['iface'], 'newzone' => $_REQUEST['zone']));
		case "updaterfw":
			return $this->setConfig($_REQUEST['proto'], ($_REQUEST['value'] == "true"), 'rfw');
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
			$this->runHook("firewall");
			return;
		case 'disablefw':
			$this->setConfig("status", false);
			return;
		case 'updateservices':
		case 'updateservices':
			if (!isset($_REQUEST['svc'])) {
				throw new \Exception("No services to update");
			}
			return $this->updateServices($_REQUEST['svc']);
		case 'enablerfw':
			$this->setConfig('responsivefw', true);
			return;
		case 'disablerfw':
			$this->setConfig('responsivefw', false);
			return;
		default:
			throw new \Exception("Unknown action $action");
		}
	}

	// We want a button on the 'services' page
	public function getActionBar($request) {
		if (isset($request['page']) && $request['page'] == "services") {
			return array(
				"defaults" => array('name' => 'defaults', 'id' => 'btndefaults', 'value' => _("Defaults")),
				"reset" => array('name' => 'reset', 'id' => 'btnreset', 'value' => _("Reset")),
				"submit" => array('name' => 'submit', 'id' => 'btnsave', 'value' => _("Save")),
			);
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

	// Update services.
	public function updateServices($svc) {

		$allsvcs = $this->getServices();
		$zones = $this->getZones();
		foreach ($allsvcs as $k => $arr) {
			foreach ($arr as $s) {
				// Known service is $s - We were told about it in the post?
				if (!isset($svc[$s]) || !is_array($svc[$s])) {
					// Turned off!
					$this->setConfig($s, array(), "servicesettings");
					continue;
				}

				// Right, we have been told about this service. 
				$svcsetting = array();
				// Loop through the zones and see if they're enabled
				foreach ($zones as $z => $null) {
					if (isset($svc[$s][$z])) {
						$svcsetting[] = $z;
					}
				}

				// Now we can save that setting!
				$this->setConfig($s, $svcsetting, "servicesettings");
			}
		}
		return true;
	}

	public function getService($svc = false) {
		if (!$svc) {
			throw new \Exception("No service?");
		}
		if (!self::$services) {
			include 'Services.class.php';
			self::$services = new Firewall\Services;
		}

		$s = self::$services->getService($svc);
		$current = $this->getConfig($svc, "servicesettings");

		if ($current === false) {
			$current = $s['defzones'];
		}
		$s['zones'] = $current;
		return $s;
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
				foreach ($zone['interfaces'] as $i) {
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
		return $d->getZonesDetails();
	}

	public function getZoneNetworks() {
		$d = $this->getDriver();
		$nets = $d->getKnownNetworks();
		$this->setConfig("networkmaps", $nets);
		return $nets;
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
			list($addr, $subnet) = explode("/", trim($net));
		} else {
			$addr = trim($net);
			$subnet = false;
		}

		// Make sure this is a valid address
		if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
			if (!$subnet) {
				$subnet = 32;
			}
			$ip = 4;
		} elseif (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
			// Note: I hate this. You can't really determine the IP address of
			// an IPv6 host..
			if (!$subnet) {
				$subnet = 128;
			}
			$ip = 6;
		} else {
			throw new \Exception("$addr is not a valid IP address");
		}

		// Check subnet.. 
		$realsubnet = (int) $subnet;
		if ($ip == 4) {
			if ($realsubnet < 8 || $realsubnet > 32) {
				throw new \Exception("Invalid IPv4 subnet $realsubnet");
			}
		} else {
			if ($realsubnet < 8 || $realsubnet > 128) {
				throw new \Exception("Invalid IPv6 subnet $realsubnet");
			}
		}

		$params = array($zone => array("$addr/$subnet"));
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

	private function getSmartObj() {
		static $sm = false;
		if (!$sm) {
			if (!class_exists('\FreePBX\modules\Firewall\Smart')) {
				include __DIR__."/Smart.class.php";
			}
			$sm = new Firewall\Smart($this->Database());
		}
		return $sm;
	}

	// Get all FreePBX services, as they are currently set
	// Note that this is **also** used by bin/getservices
	public function getSmartPorts() {
		$smart = $this->getSmartObj();
		return $smart->getAllPorts();
	}

	// Get Smart Firewall settings
	public function getSmartSettings() {
		$smart = $this->getSmartObj();
		return $smart->getSettings();
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

	public function isTrusted() {
		$nets = $this->getConfig("networkmaps");
		$thisnet = $this->detectNetwork();
		$thishost = $this->detectHost();
		foreach ($nets as $n => $zone) {
			if ($zone !== "trusted") {
				continue;
			}
			if ($n === $thisnet || $n === $thishost) {
				return true;
			}
		}
		return false;
	}

	public function rfcNetsAdded() {
		// Check to see if ALL the RFC1918 networks are added.
		$shouldbe = array ('192.168.0.0/16','172.16.0.0/12','10.0.0.0/8', 'fc00::/8', 'fd00::/8');
		$nets = $this->getConfig("networkmaps");
		foreach ($shouldbe as $n) {
			if (!isset($nets[$n]) || $nets[$n] !== "trusted") {
				return false;
			}
		}
		return true;
	}

	public function thisHostAdded() {
		$nets = $this->getConfig("networkmaps");
		$thishost = $this->detectHost();
		if (isset($nets[$thishost]) && $nets[$thishost] == "trusted") {
			return true;
		} else {
			return false;
		}
	}

	public function thisNetAdded() {
		$nets = $this->getConfig("networkmaps");
		$thisnet = $this->detectNetwork();
		if (isset($nets[$thisnet]) && $nets[$thisnet] == "trusted") {
			return true;
		} else {
			return false;
		}
	}
}

