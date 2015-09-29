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
		$this->extraservices = array("provis", "restapps", "xmpp", "ftp", "tftp", "nfs", "smb");

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
			"guess" => _("Warning: Unable to read /etc/ssh/sshd_config. This is expected when viewing through the Web Interface. The correct port, as configured, will be exposed in the firewall service."),
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
		// TODO: Ask sysadmin, otherwise assume 80? Other options?
		$retarr = array(
			"name" => _("Web Management"),
			"defzones" => array("internal"),
			"descr" => _("Web management interface for FreePBX. This is the http, not https (secure) interface."),
			"fw" => array(array("protocol" => "tcp", "port" => 80)),
		);
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
		return $retarr;
	}

	private function getSvc_webrtc() {
		$retarr = array(
			"name" => _("WebRTC"),
			"defzones" => array("reject"),
			"descr" => _("WebRTC is used by UCP (and other services) to enable calls to be made via a web browser."),
			"fw" => array(array("protocol" => "tcp", "port" => 8088)),
		);

		// TODO: Check httpd.conf and chan_sip.conf to make sure that it's enabled.
		return $retarr;
	}

	private function getSvc_pjsip() {
		$retarr = array(
			"name" => _("SIP Protocol"),
			"defzones" => array("other", "internal"),
			"descr" => _("This is the SIP driver (pjsip). Most devices use SIP."),
			"fw" => array(
				array("protocol" => "udp", "port" => 5060),
				array("protocol" => "tcp", "port" => 9876), // or whatever
			),
		);
		return $retarr;
	}

	private function getSvc_chansip() {
		$retarr = array(
			"name" => _("CHAN_SIP Protocol"),
			"defzones" => array("internal"),
			"descr" => _("This is the legacy chan_sip driver."),
			"fw" => array(
				array("protocol" => "udp", "port" => 5061),
				array("protocol" => "tcp", "port" => 9877), // or whatever
			),
		);
		return $retarr;
	}

	private function getSvc_iax() {
		$retarr = array(
			"name" => _("IAX Protocol"),
			"defzones" => array("internal"),
			"descr" => _("IAX stands for Inter Asterisk eXchange. It is more bandwidth efficient than SIP, but few providers support it."),
			"fw" => array(array("protocol" => "udp", "port" => 4569)),
		);
		return $retarr;
	}

	private function getSvc_provis() {
		$retarr = array(
			"name" => _("HTTP Provisioning"),
			"defzones" => array("other", "internal"),
			"descr" => _("Text for HTTP Provisioning not done..."),
			"fw" => array(array("protocol" => "tcp", "port" => 84)),
		); 
		return $retarr;
	}

	private function getSvc_restapps() {
		$retarr = array(
			"name" => _("REST Apps"),
			"defzones" => array("internal"),
			"descr" => _("Text for REST Apps not done..."),
			"fw" => array(array("protocol" => "tcp", "port" => 85)),
		); 
		return $retarr;
	}

	private function getSvc_xmpp() {
		$retarr = array(
			"name" => _("XMPP"),
			"defzones" => array("external", "other", "internal"),
			"descr" => _("Text for XMPP not done..."),
			"fw" => array(array("protocol" => "tcp", "port" => 5222)),
		); 
		return $retarr;
	}

	private function getSvc_ftp() {
		$retarr = array(
			"name" => _("FTP"),
			"defzones" => array("internal"),
			"descr" => _("FTP is used by things to do stuff. Redo this text."),
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
			"descr" => _("SMB/CIFS is used to access files on this machine from Windows or Mac systems."),
			"fw" => array(
				array('protocol' => 'udp', 'port' => '137'),
				array('protocol' => 'udp', 'port' => '138'),
				array('protocol' => 'tcp', 'port' => '139'),
				array('protocol' => 'tcp', 'port' => '445'),
			),
		); 
		return $retarr;
	}
}

