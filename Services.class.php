<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
namespace FreePBX\modules\Firewall;

class Services {

	private $allservices;
	private $coreservices;
	private $extraservices;

	public function __construct() {
		// Can't define arrays in some versions of PHP.
		$this->coreservices = array("ssh", "http", "https", "ucp", "pjsip", "chansip", "iax", "webrtc");
		$this->extraservices = array("isymphony", "provis", "restapps", "xmpp", "ftp", "tftp", "nfs", "smb");

		$this->allservices = array_merge($this->coreservices, $this->extraservices);
	}

	public function getCoreServices() {
		return $this->coreservices;
	}

	public function getExtraServices() {
		return $this->extraservices;
	}

	public function getService($svc = false) {
		if (!$svc) {
			throw new \Exception("Wasn't asked for a service");
		}

		// TODO: in_array is horrible and we should never use it. However,
		// in development, it's handy to catch typos. Remove this line when it's
		// in use.
		if (!in_array($svc, $this->allservices)) {
			throw new \Exception("Don't know what '$svc' is.");
		}

		// We want to call the discoverer method which is getSvc_$svc
		$method = "getSvc_$svc";
		if (!method_exists($this, $method)) {
			throw new \Exception("Tried to call method $method, it doesn't exist");
		}

		return $this->$method();
	}

	private function getSvc_ssh() {
		$retarr = array(
			"name" => _("SSH"),
			"defzones" => array("internal"),
			"descr" => _("SSH is the most commonly used system administration tool. It is also a common target for hackers. We <strong>strongly recommend</strong> using a strong password and SSH keys. "),
			"fw" => array(array("protocol" => "tcp", "port" => 22)),
			"noreject" => true,
			"guess" => _("Warning: Unable to read /etc/ssh/sshd_config - this port may be incorrect. This is <strong>expected</strong> when viewing through the Web Interface. The correct port, as configured, will be used in the firewall service."),
		);

		// Is sshd_config anywhere else on other machines?
		$conf = "/etc/ssh/sshd_config";

		// Note: Only readable by root!
		if (!file_exists($conf) || !is_readable($conf)) {
			return $retarr;
		} else {
			$retarr['guess'] = false; // Woo, we can read it.
		}

		// Look for a line starting with Port and then a number.
		$sshdconf = file_get_contents($conf);
		if (preg_match("/^Port\s+(\d+)/m", $sshdconf, $out)) {
			$retarr['fw'] = array(array("protocol" => "tcp", "port" => $out[1]));
		}
		return $retarr;
	}

	private function getSvc_http() {
		$retarr = array(
			"name" => _("Web Management"),
			"defzones" => array("internal"),
			"descr" => _("Web management interface for FreePBX. This is the http, not https (secure) interface."),
			"fw" => array(array("protocol" => "tcp", "port" => 80)),
		);

		// TODO: This is not portable for machines that don't have sysadmin.
		// Ask sysadmin for the REAL port of the admin interface
		try {
			$ports = \FreePBX::Sysadmin()->getPorts();
			$retarr['fw'][0]['port'] = $ports['acp'];
		} catch (\Exception $e) {
			// ignore
		}
		return $retarr;
	}

	private function getSvc_https() {
		$retarr = array(
			"name" => _("Web Management (Secure)"),
			"defzones" => array("external", "internal"),
			"descr" => _("Web management interface for FreePBX. This is the https interface."),
			"fw" => array(array("protocol" => "tcp", "port" => 443)),
			"noreject" => true,
		);
		return $retarr;
	}

	private function getSvc_ucp() {
		$retarr = array(
			"name" => _("UCP"),
			"defzones" => array("external", "other", "internal"),
			"descr" => _("UCP - User Control Panel - is the main user interface to FreePBX, and allows people to control their phone. Note that if you want to allow users to use their web browsers to make calls through UCP you also need to add WebRTC to the same zone(s)."),
			"fw" => array(array("protocol" => "tcp", "port" => 81)),
		);
		// TODO: This is not portable for machines that don't have sysadmin.
		// Ask sysadmin for the REAL port of the admin interface
		try {
			$ports = \FreePBX::Sysadmin()->getPorts();
			$retarr['fw'][0]['port'] = $ports['ucp'];
		} catch (\Exception $e) {
			// ignore
		}

		// Add nodejs listen port, if it's installed.
		$nodejs = \FreePBX::Config()->get('NODEJSBINDPORT');
		if ($nodejs) {
			$retarr['fw'][] = array("protocol" => "tcp", "port" => $nodejs);
		}
		return $retarr;
	}

	private function getSvc_webrtc() {
		$websocket = \FreePBX::Config()->get('HTTPBINDPORT');
		if (!$websocket) {
			$websocket = 8088;
		}
		$retarr = array(
			"name" => _("WebRTC"),
			"defzones" => array("reject"),
			"descr" => _("WebRTC is used by UCP (and other services) to enable calls to be made via a web browser."),
			"fw" => array(array("protocol" => "tcp", "port" => $websocket)),
		);
		return $retarr;
	}

	private function getSvc_pjsip() {
		$retarr = array(
			"name" => _("SIP Protocol"),
			"defzones" => array("other", "internal"),
			"descr" => _("This is the SIP driver (pjsip). Most devices use SIP."),
			"fw" => array(),
		);
		$driver = \FreePBX::Config()->get('ASTSIPDRIVER');
		if ($driver == "both" || $driver == "chan_pjsip") {
			$ss = \FreePBX::Sipsettings();
			$allBinds = $ss->getConfig("binds");
			if (!is_array($allBinds)) {
				$allBinds = array();
			}
			$websocket = false;
			foreach ($allBinds as $type => $listenArr) {
				if (!is_array($listenArr)) {
					$listenArr = array();
				}
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
						$retarr['fw'][] = array("protocol" => "tcp", "port" => $port);
					} elseif ($type == "udp") {
						$retarr['fw'][] = array("protocol" => "udp", "port" => $port);
					} else {
						throw new \Exception("Unknown protocol $type");
					}
				}
			}
			if ($websocket) {
				$retarr['fw'][] = array("protocol" => "tcp", "port" => $websocket);
			}
		} else {
			$retarr['descr'] = _("PJSIP is not available on this machine");
			$retarr['disabled'] = true;
		}
		return $retarr;
	}

	private function getSvc_chansip() {
		$retarr = array(
			"name" => _("CHAN_SIP Protocol"),
			"defzones" => array("internal"),
			"descr" => _("This is the legacy chan_sip driver."),
			"fw" => array(),
		);
		$driver = \FreePBX::Config()->get('ASTSIPDRIVER');
		if ($driver == "both" || $driver == "chan_sip") {
			$tcp = false;
			$bindport = 5060;
			// Note bug in sipsettings =< 13.0.14.5 that getChanSipSettings won't
			// return correct details when not returnraw
			$settings = \FreePBX::Sipsettings()->getChanSipSettings(true);
			foreach ($settings as $arr) {
				if ($arr['keyword'] == "tcpenable" && $arr['data'] == "yes") {
					$tcp = true;
					continue;
				}
				if ($arr['keyword'] == "bindport") {
					$bindport = $arr['data'];
					continue;
				}
			}
			$retarr['fw'][] = array("protocol" => "udp", "port" => $bindport);
			if ($tcp) {
				$retarr['fw'][] = array("protocol" => "tcp", "port" => $bindport);
			}
		}

		// Make sure there's actually some binds.
		if (!$retarr['fw']) {
			$retarr['descr'] = _("CHANSIP is not available on this machine");
			$retarr['disabled'] = true;
		}
		return $retarr;
	}

	private function getSvc_iax() {
		$retarr = array(
			"name" => _("IAX Protocol"),
			"defzones" => array("internal"),
			"descr" => _("IAX stands for Inter Asterisk eXchange. It is more bandwidth efficient than SIP, but few providers support it."),
			// If you're using IAX on a non standard port, stop it. You're doing it wrong.
			"fw" => array(array("protocol" => "udp", "port" => 4569)),
		);
		return $retarr;
	}

	private function getSvc_provis() {
		$retarr = array(
			"name" => _("HTTP Provisioning"),
			"defzones" => array("other", "internal"),
			"descr" => _("Phones that are configured via Endpoint Manager will use this port to download its configuration. It is NOT ADVISED to expose this port to the public internet, as SIP Secrets will be available to a knowledgable attacker."),
			"fw" => array(array("protocol" => "tcp", "port" => 84)),
		);
		// TODO: This is not portable for machines that don't have sysadmin.
		// Ask sysadmin for the REAL port of the admin interface
		try {
			$ports = \FreePBX::Sysadmin()->getPorts();
			$retarr['fw'][0]['port'] = $ports['hpro'];
		} catch (\Exception $e) {
			// ignore
		}
		return $retarr;
	}

	private function getSvc_restapps() {
		$retarr = array(
			"name" => _("REST Apps"),
			"defzones" => array("internal"),
			"descr" => _("Text for REST Apps not done..."),
			"fw" => array(array("protocol" => "tcp", "port" => 85)),
		);
		// TODO: This is not portable for machines that don't have sysadmin.
		// Ask sysadmin for the REAL port of the admin interface
		try {
			$ports = \FreePBX::Sysadmin()->getPorts();
			$retarr['fw'][0]['port'] = $ports['restapps'];
		} catch (\Exception $e) {
			// ignore
		}
		return $retarr;
	}

	private function getSvc_xmpp() {
		$retarr = array(
			"name" => _("XMPP"),
			"defzones" => array("external", "other", "internal"),
			"descr" => _("This is the XMPP server. If you wish to connect to it using an external Jabber client, you need to open this port."),
			"fw" => array(array("protocol" => "tcp", "port" => 5222)),
		);
		return $retarr;
	}

	private function getSvc_ftp() {
		$retarr = array(
			"name" => _("FTP"),
			"defzones" => array("internal"),
			"descr" => _("FTP is used by Endpoint Manager to send firmware images to phones, as well as additional data."),
			"fw" => array(array("protocol" => "tcp", "port" => 21)),
		);
		return $retarr;
	}

	private function getSvc_tftp() {
		$retarr = array(
			"name" => _("TFTP"),
			"defzones" => array("internal"),
			"descr" => _("TFTP is used normally for provisioning and upgrading of devices."),
			"fw" => array(array("protocol" => "udp", "port" => 69)),
		);
		return $retarr;
	}

	private function getSvc_nfs() {

		$ports = $this->getNfsPorts();

		$retarr = array(
			"name" => _("NFS"),
			"defzones" => array("reject")
		);

		if (!$ports) {
			// NFS isn't enabled on this machine.
			$retarr['descr'] = _("NFS Services are not available on this machine");
			$retarr['disabled'] = true;
		} else {
			$retarr['descr'] = _("This allows this machine to be used as a NFS server. This can be useful when you want to easily access files on this machine (for example, to access call recordings). Note that this is <strong>not required</strong> to be enabled to act as a NFS client, and view the filesystem of other machines.");
			$retarr['fw'] = $ports;
		}
		return $retarr;
	}

	private function getNfsPorts() {
		if (!file_exists("/etc/sysconfig/nfs")) {
			return array();
		}
		$retarr= array(
			array('protocol' => 'udp', 'port' => '2049'),
			array('protocol' => 'tcp', 'port' => '2049'),
		);

		$mountd = 892;
		$statd = 662;
		$lockdtcp = 32803;
		$lockdudp = 32769;

		// Now, are any of them overridden?
		$nfsconf = @parse_ini_file("/etc/sysconfig/nfs");

		if (isset($nfsconf['MOUNTD_PORT'])) {
			$mountd = $nfsconf['MOUNTD_PORT'];
		}
		if (isset($nfsconf['STATD_PORT'])) {
			$statd = $nfsconf['STATD_PORT'];
		}
		if (isset($nfsconf['LOCKD_TCPPORT'])) {
			$lockdtcp = $nfsconf['LOCKD_TCPPORT'];
		}
		if (isset($nfsconf['LOCKD_UDPPORT'])) {
			$lockdudp = $nfsconf['LOCKD_UDPPORT'];
		}
		$retarr[] = array('protocol' => 'udp', 'port' => $mountd);
		$retarr[] = array('protocol' => 'udp', 'port' => $statd);
		$retarr[] = array('protocol' => 'udp', 'port' => $lockdudp);
		$retarr[] = array('protocol' => 'tcp', 'port' => $mountd);
		$retarr[] = array('protocol' => 'tcp', 'port' => $statd);
		$retarr[] = array('protocol' => 'tcp', 'port' => $lockdtcp);

		return $retarr;
	}

	private function getSvc_smb() {
		$retarr = array(
			"name" => _("SMB/CIFS"),
			"defzones" => array("reject"),
		);

		if (!file_exists("/etc/samba/smb.conf")) {
			$retarr['descr'] = _("SMB/CIFS (Samba) is not installed on this machine");
			$retarr['disabled'] = true;
		} else {
			$retarr['descr'] = _("SMB/CIFS is used to access files on this machine from Windows or Mac systems.");
			$retarr['fw'] = array(
				array('protocol' => 'udp', 'port' => '137'),
				array('protocol' => 'udp', 'port' => '138'),
				array('protocol' => 'tcp', 'port' => '139'),
				array('protocol' => 'tcp', 'port' => '445'),
			);
		}
		return $retarr;
	}

	private function getSvc_isymphony() {

		// This could be iSymphony, or XactView.
		$known = array(
			"XactView" => "/opt/xactview3/server/conf/main.xml", 
			"iSymphony" => "/opt/isymphony3/server/conf/main.xml", 
		);

		foreach ($known as $name => $loc) {
			if (file_exists($loc)) {
				$retarr = array(
					"name" => $name,
					"defzones" => array("internal"),
				);
				$xml = @simplexml_load_file($loc);
				if (!isset($xml->Server->Web)) {
					$retarr['descr'] = sprintf(_("%s is not configured correctly."), $name);
					$retarr['disabled'] = true;
				} else {
					$retarr['fw'] = array();
					$retarr['descr'] = sprintf(_("%s is a web-based call management solution."), $name);
					if (isset($xml->Server->Web[0]['port'])) {
						$retarr['fw'][] = array("protocol" => "tcp", "port" => (int) $xml->Server->Web[0]['port']);
					}
					if (isset($xml->Server->Web[0]['sslPort'])) {
						$retarr['fw'][] = array("protocol" => "tcp", "port" => (int) $xml->Server->Web[0]['sslPort']);
					}
				}
				return $retarr;
			}
		}
		$retarr = array(
			"name" => "iSymphony",
			"defzones" => array("internal"),
			"descr" => _("iSymphony is not installed on this server."),
			"disabled" => true,
		);
		return $retarr;
	}
}
