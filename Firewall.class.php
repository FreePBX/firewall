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

	public function oobeHook() {
		include __DIR__.'/OOBE.class.php';
		$o = new Firewall\OOBE($this);
		return $o->oobeRequest();
	}

	public function dashboardService() {

		// Check to see if Firewall is enabled. Warn if it's not.
		$status = array(
			'title' => _("System Firewall"),
			'order' => 3,
		);

		if ($this->getConfig("status")) {
			$status = array_merge($status, $this->Dashboard()->genStatusIcon('ok', _("Firewall Active")));
		} else {
			$status = array_merge($status, $this->Dashboard()->genStatusIcon('error', _("Firewall Disabled")));
			return array($status);
		}

		if ($this->isNotReady()) {
			$status = array_merge($status, $this->Dashboard()->genStatusIcon('warning', _("Starting up")));
			return array($status);
		}

		// We're meant to be running, check that the firewall service is.
		exec("pgrep -f hooks/voipfirewalld", $out, $ret);
		// Clobber the $status if it's not running
		if ($ret != 0) {
			$status = array_merge($status, $this->Dashboard()->genStatusIcon('error', _("Firewall Service not running!")));
			$status['order'] = 1;
		}

		// If there are any interfaces that are in 'Trusted', yell loudly about that, too
		$trusted = array(
			'title' => _("Firewall Configuration"),
			'order' => 3
		);

		$foundtrustedint = false;
		$foundnewint = false;
		$error = false;
		$ints = $this->getInterfaces();
		foreach ($ints as $i => $conf) {
			// Does this not have a zone?
			if (!isset($conf['config']['ZONE'])) {
				// If it's got IP addresses, it's new. Otherwise, we can just ignore it.
				if ($conf['addresses']) {
					$foundnewint = $i;
				}
				break;
			}
			$runningzone = $this->getZone($i);
			if ($conf['config']['ZONE'] !== $runningzone) {
				$error = $i;
				break;
			} elseif ($runningzone === "trusted") {
				$foundtrustedint = $i;
				break;
			}
		}

		if ($error) {
			$trusted = array_merge($trusted, $this->Dashboard()->genStatusIcon('error', _("Firewall Integrity Failed")));
			$this->Notifications()->add_critical('firewall', 'zoneerror', _("Firewall Integrity Failed"),
				sprintf(_("Interface %s is not in the correct zone. This can be caused by manual alterations of iptables, or, an unexpected error. Please restart the firewall service, and then delete this notification."), $error),
				"?display=firewall",
				true, // Reset on update.
				true); // Can delete
			return array($status, $trusted);
		} elseif ($foundnewint) { // Have we found a new interface?
			$trusted = array_merge($trusted, $this->Dashboard()->genStatusIcon('error', _("New Interface Detected")));
			$trusted['order'] = 1;
			$this->Notifications()->add_critical('firewall', 'newint', _("New Interface Detected"),
				sprintf(_("A new, unconfigured, network interface has been detected. Please assign interface '%s' to a zone."), $foundnewint),
				"?display=firewall&page=zones&tab=intsettings",
				true, // Reset on update.
				false); // Can delete
			return array($status, $trusted);
		} elseif ($foundtrustedint) { // If we've found a trusted interface, this is bad, yell.
			$trusted = array_merge($trusted, $this->Dashboard()->genStatusIcon('error', _("Trusted Interface Detected")));
			$trusted['order'] = 1;
			// Add core notification
			$this->Notifications()->add_critical('firewall', 'trustedint', _("Trusted Interface Detected"),
				sprintf(_("A network interface that is assigned to the 'Trusted' zone has been detected. This is a misconfiguration. To ensure your system is protected from attacks, please change the default zone of interface '%s'."), $foundtrustedint),
				"?display=firewall&page=zones&tab=intsettings",
				true, // Reset on update.
				false); // Can delete
			return array($status, $trusted);
		}

		// Now we need to validate that we DO have a trusted network or host. 
		// If we dont', this should be a warning, not an error.
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}

		$foundtrustednet = false;
		foreach ($nets as $name => $zone) {
			if ($zone === "trusted") {
				$foundtrustednet = true;
				break;
			}
		}

		if ($foundtrustednet) {
			// Yup, there's at least one!
			$trusted = array_merge($trusted, $this->Dashboard()->genStatusIcon('ok', _("Trusted Management Network defined")));
		} else {
			$trusted = array_merge($trusted, $this->Dashboard()->genStatusIcon('warn', _("No Trusted Management Network")));
			// Add core notification
			$this->Notifications()->add_warning('firewall', 'trustednet', _("No Trusted Network or Host defined"),
				_("No Trusted Network or Host has been defined. Every server should have a 'Trusted' host or network to ensure that in case of configuration error, the machine is still accessible."),
				"?display=firewall&page=zones&tab=netsettings",
				true, // Reset on update.
				true); // Can delete
		}

		return array($status, $trusted);
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

		// Wait for up to 5 seconds and make sure it's been deleted.
		$maxloops = 10;
		$deleted = false;
		while ($maxloops--) {
			if (!file_exists($filename)) {
				$deleted = true;
				break;
			}
			usleep(500000);
		}

		if (!$deleted) {
			throw new \Exception("Hook file '$filename' was not picked up by Incron after 5 seconds. Is it not running?");
		}
		return true;
	}

	public function startFirewall() {
		$this->runHook("firewall");
	}

	public function isEnabled() {
		return $this->getConfig("status");
	}

	// If the machine is currently in safe mode, return true.
	public function isNotReady() {
		return file_exists("/var/run/firewalld.safemode");
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
			return $this->addNetworkToZone(trim($_REQUEST['net']), $_REQUEST['zone']);
		case "updatenetwork":
			if (!isset($_REQUEST['net'])) {
				throw new \Exception("No net");
			}
			if (!isset($_REQUEST['zone'])) {
				throw new \Exception("No Zone");
			}
			return $this->changeNetworksZone(trim($_REQUEST['net']), $_REQUEST['zone']);
		case "addrfc":
			return $this->addRfcNetworks();
		case "addthishost":
			$thishost = $this->detectHost();
			$nets = $this->getConfig("networkmaps");
			if (!is_array($nets)) {
				$nets = array();
			}
			$nets[$thishost] = "trusted";
			$this->setConfig("networkmaps", $nets);
			return $this->runHook('addnetwork', array('trusted' => array($thishost)));
		case "addthisnetwork":
			$thisnet = $this->detectNetwork();
			$nets = $this->getConfig("networkmaps");
			if (!is_array($nets)) {
				$nets = array();
			}
			$nets[$thisnet] = "trusted";
			$this->setConfig("networkmaps", $nets);
			return $this->runHook('addnetwork', array('trusted' => array($thisnet)));
		case "updateinterface":
			// Remove any notifications about invalid interface configurations
			$this->Notifications()->delete('firewall', 'trustedint');
			$this->Notifications()->delete('firewall', 'newint');
			return $this->runHook('updateinterface', array('iface' => $_REQUEST['iface'], 'newzone' => $_REQUEST['zone']));
		case "updaterfw":
			return $this->setConfig($_REQUEST['proto'], ($_REQUEST['value'] == "true"), 'rfw');
		case "addtoblacklist":
			return $this->addToBlacklist(htmlentities($_REQUEST['entry'], \ENT_QUOTES, 'UTF-8', false));
		case "removefromblacklist":
			return $this->removeFromBlacklist(htmlentities($_REQUEST['entry'], \ENT_QUOTES, 'UTF-8', false));
		case "setsafemode":
			if ($_REQUEST['value'] == "disabled") {
				return $this->disableSafemode();
			} elseif ($_REQUEST['value'] == "enabled") {
				return $this->enableSafemode();
			} else {
				throw new \Exception("Unknown safemode");
			}
		case "setrejectmode":
			if ($_REQUEST['value'] != "reject") {
				return $this->setConfig("dropinvalid", true);
			} else {
				return $this->setConfig("dropinvalid", false);
			}

		// Custom firewall rules.

		// Custom firewall rules.
		case "addcustomrule":
			return $this->addCustomService(htmlentities($_REQUEST['name'], \ENT_QUOTES, 'UTF-8', false), $_REQUEST['proto'], $_REQUEST['port']);
		case "editcustomrule":
			return $this->editCustomService($_REQUEST['id'], htmlentities($_REQUEST['name'], \ENT_QUOTES, 'UTF-8', false), $_REQUEST['proto'], $_REQUEST['port']);
		case "deletecustomrule":
			return $this->deleteCustomService($_REQUEST['id']);
		case "updatecustomzones":
			if (!isset($_REQUEST['zones'])) {
				$_REQUEST['zones'] = array();
			}
			return $this->setCustomServiceZones($_REQUEST['id'], $_REQUEST['zones']);

		// Attackers page
		case "getattackers":
			include __DIR__."/Attacks.class.php";
			$a = new Firewall\Attacks($this->getJiffies());
			$smart = $this->getSmartObj();
			return $a->getAllAttacks($smart->getRegistrations());
		case "delattacker":
			return $this->runHook("removeallblocks", array("unblock" => $_REQUEST['target']));

		// OOBE
		case "getoobequestion":
			include __DIR__."/OOBE.class.php";
			$o = new Firewall\OOBE($this);
			return $o->getQuestion();
		case "answeroobequestion":
			include __DIR__."/OOBE.class.php";
			$o = new Firewall\OOBE($this);
			return $o->answerQuestion();
		case "abortoobe":
			$this->setConfig("abortoobe", true);
			return true;
		case "restartoobe":
			$o = \FreePBX::OOBE()->getConfig("completed");
			if (!is_array($o)) {
				throw new \Exception("OOBE isn't an array");
			}
			unset ($o['firewall']);
			\FreePBX::OOBE()->setConfig("completed", $o);
			$this->setConfig("oobeanswered", array());
			$this->setConfig("abortoobe", false);
			return;

		default:
			throw new \Exception("Sad Panda - ".$_REQUEST['command']);
		}
	}

	// Manage Jiffies, for xt_recent
	public function getJiffies() {
		static $j = false;
		if (!$j) {
			include __DIR__."/Jiffies.class.php";
			$j = new Firewall\Jiffies;
		}
		$currentjiffies = $this->getConfig("currentjiffies");
		if (!$currentjiffies || $currentjiffies < 100) {
			$currentjiffies = $j->calcJiffies();
			$this->setConfig("currentjiffies", $currentjiffies);
		}
		$j->setKnownJiffies($currentjiffies);
		return $j;
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

		$retarr = array("core" => self::$services->getCoreServices(), "extra" => self::$services->getExtraServices(), "custom" => $this->getAllCustomServices());
		return $retarr;
	}

	public function getAllCustomServices() {
		return $this->getAll("customservices");
	}

	public function addCustomService($name, $proto, $ports) {
		// Generate a new id
		$id = $this->genUUID();
		// Make our custom service array
		$svc = array(
		   	"name" => $name,
			"defzones" => array("internal"),
			"descr" => "Custom Service",
			"custfw" => array("protocol" => $proto, "port" => $ports),
			"custid" => $id,
			"noreject" => true,
		);

		// And save it!
		$this->setConfig($id, $svc, "customservices");
		$this->setCustomServiceZones($id, array("internal"));
	}

	public function deleteCustomService($id) {
		$this->setConfig($id, false, "customservices");
		$this->setConfig($id, false, "servicesettings");
	}

	public function editCustomService($id, $name = false, $proto = false, $ports = false) {
		$svc = $this->getConfig($id, "customservices");

		if (!$svc) {
			throw new \Exception("Unknown custom service id $id");
		}

		// Update the rules with the new ones..
		if ($name) {
			$svc['name'] = $name;
		}

		if ($proto) {
			$svc['custfw']['protocol'] = $proto;
		}

		if ($ports) {
			$svc['custfw']['port'] = $ports;
		}

		// And save it.
		$this->setConfig($id, $svc, "customservices");
	}

	public function getCustomServiceZones($id) {
		$zones = $this->getConfig($id, "servicesettings");
		$retarr = array();
		if (is_array($zones)) {
			foreach ($zones as $zone) {
				$retarr[$zone] = $zone;
			}
		}
		return $retarr;
	}

	public function setCustomServiceZones($id, $zones = array()) {
		if (!is_array($zones)) {
			throw new \Exception("Don't know what I was given");
		}
		return $this->setConfig($id, $zones, "servicesettings");
	}

	// Update services.
	public function updateServices($svc) {

		$allsvcs = $this->getServices();
		$zones = $this->getZones();
		foreach ($allsvcs as $k => $arr) {
			foreach ($arr as $s) {
				if (is_array($s)) {
					// This is a custom service, not a known one, ignore.
					continue;
				}
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
		// Is this an alias? eg eth0:123? Then return the zone for the REAL interface.
		list ($realint) = explode(":", $int);
		if (!isset($ints[$realint])) {
			$ints[$realint] = 'trusted';
		}

		return $ints[$realint];
	}

	public function getDriver() {

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
		$ip = $_SERVER['REMOTE_ADDR'];
		if (filter_var($ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4)) {
			return "$ip/32";
		} elseif (filter_var($ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
			return "$ip/128";
		} else {
			throw new \Exception("REMOTE_ADDR didn't parse - $ip");
		}
	}

	// /////////////// //
	// Ajax Code below //
	// /////////////// //
	public function removeNetwork($net = false) {
		// Is it a host? We care about them differently.
		$hostmap = $this->getConfig("hostmaps");
		if (isset($hostmap[$net])) {
			// It's a host, not a network
			unset($hostmap[$net]);
			$this->setConfig("hostmaps", $hostmap);
		}

		// Now, grab what our zones should be...
		$nets = $this->getConfig("networkmaps");
		// Is this network part of a zone?
		if (!isset($nets[$net])) {
			return false;
		}
		$zone = $nets[$net];
		unset($nets[$net]);
		$this->setConfig("networkmaps", $nets);
		return $this->runHook("removenetwork", array("network" => $net, "zone" => $zone));
	}

	public function addNetworkToZone($net = false, $zone = false) {
		$net = trim($net);
		// Is this a network?
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
			// an IPv6 host. IPv6 Security Extensions - which should be on for a
			// client - mandate the IP address changes.
			if (!$subnet) {
				$subnet = 128;
			}
			$ip = 6;
		} else {
			// It's probably a host. Add it to our host maps to care about later
			return $this->addHostToZone($net, $zone);
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

		// Update the local cache
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}
		$nets["$addr/$subnet"] = $zone;
		$this->setConfig("networkmaps", $nets);

		$params = array($zone => array("$addr/$subnet"));
		return $this->runHook("addnetwork", $params);
	}

	public function addHostToZone($host, $zone) {
		$host = trim($host);
		$hosts = $this->getConfig("hostmaps");
		if (!is_array($hosts)) {
			$hosts = array();
		}
		$hosts[$host] = $zone;

		// Also add to network maps, for continuity.
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}
		$nets[$host] = $zone;
		$this->setConfig("networkmaps", $nets);

		return $this->setConfig("hostmaps", $hosts);
	}

	public function changeNetworksZone($net, $zone) {
		$net = trim($net);

		// Get our current maps...
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}

		// Is this network part of a zone?
		if (!isset($nets[$net])) {
			throw new \Exception("Unknown network");
		}

		// Is it a host? We care about them differently.
		$hostmap = $this->getConfig("hostmaps");
		if (!empty($hostmap[$net])) {
			// It's a host, not a network
			$hostmap[$net] = $zone;
			$this->setConfig("hostmaps", $hostmap);
		}

		// Update and save the map...
		$nets[$net] = $zone;
		$this->setConfig("networkmaps", $nets);

		return $this->runHook("changenetwork", array("network" => $net, "newzone" => $zone));
	}

	// Add RFC1918 addresses to the trusted zone
	public function addRfcNetworks() {
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}

		$rfc = array ('192.168.0.0/16','172.16.0.0/12','10.0.0.0/8', 'fc00::/8', 'fd00::/8');
		foreach ($rfc as $n) {
			if (!isset($nets[$n])) {
				$nets[$n] = "trusted";
			}
		}
		$this->setConfig("networkmaps", $nets);

		return $this->runHook("addrfcnetworks");
	}

	public function getSmartObj() {
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
		if (!is_array($nets)) {
			return false;
		}
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
		if (!is_array($nets)) {
			return false;
		}
		foreach ($shouldbe as $n) {
			if (!isset($nets[$n]) || $nets[$n] !== "trusted") {
				return false;
			}
		}
		return true;
	}

	public function thisHostAdded() {
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			return false;
		}
		$thishost = $this->detectHost();
		if (isset($nets[$thishost]) && $nets[$thishost] == "trusted") {
			return true;
		} else {
			return false;
		}
	}

	public function thisNetAdded() {
		$nets = $this->getConfig("networkmaps");
		if (!is_array($nets)) {
			return false;
		}
		$thisnet = $this->detectNetwork();
		if (isset($nets[$thisnet]) && $nets[$thisnet] == "trusted") {
			return true;
		} else {
			return false;
		}
	}

	public function getBlacklist() {
		$hosts = array_keys($this->getAll("blacklist"));
		$smart = $this->getSmartObj();
		$retarr = array();
		foreach ($hosts as $h) {
			// Is this an IP address?
			list($test) = explode("/", $h);
			if (filter_var($test, \FILTER_VALIDATE_IP)) {
				$retarr[$h] = false;
				continue;
			} else {
				// Try a DNS lookup
				$retarr[$h] = $smart->lookup($h);
			}
		}
		return $retarr;
	}

	public function addToBlacklist($host) {
		// Make sure we can look this host up, and it's a valid thing to 
		// add to the blacklist.
		//
		// This will throw an exception if it can't.
		$smart = $this->getSmartObj();
		$smart->lookup($host);

		// If it can, we can add it happily.
		$this->setConfig($host, true, "blacklist");
	}

	public function removeFromBlacklist($host) {
		$this->setConfig($host, false, "blacklist");
	}

	public function isSafemodeEnabled() {
		$ena = $this->getConfig("safemodeenabled");
		if ($ena == false || $ena == "enabled") {
			return true;
		} else {
			return false;
		}
	}

	public function disableSafemode() {
		$this->setConfig("safemodeenabled", "disabled");
		return "disabled";
	}

	public function enableSafemode() {
		$this->setConfig("safemodeenabled", "enabled");
		return "enabled";
	}

	public function genUUID() {
		// This generates a v4 GUID

		// Be cryptographically secure.
		$data = openssl_random_pseudo_bytes(16);

		$data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
		$data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10

		return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
	}
}

