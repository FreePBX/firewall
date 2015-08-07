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
		// TODO: Check /etc/ssh/sshd_config
		$retarr = array(
			"name" => _("SSH"),
			"defzones" => array("external", "internal"),
			"descr" => _("SSH is the most commonly used system administration tool. It is also a common target for hackers. We <strong>do not</strong> recommend blocking this port, but we do recommend using a strong password and SSH keys."),
			"fw" => array("protocol" => "tcp", "port" => 22),
		);
		return $retarr;
	}

	private function getSvc_http() {
		// TODO: Ask sysadmin, otherwise assume 80? Other options?
		$retarr = array(
			"name" => _("Web Management"),
			"defzones" => array("internal"),
			"descr" => _("Web management interface for FreePBX. This is the http, not https (secure) interface."),
			"fw" => array("protocol" => "tcp", "port" => 80),
		);
		return $retarr;
	}

	private function getSvc_https() {
		$retarr = array(
			"name" => _("Web Management (Secure)"),
			"defzones" => array("public", "external", "internal"),
			"descr" => _("Web management interface for FreePBX. This is the https interface."),
			"fw" => array("protocol" => "tcp", "port" => 443),
		);
		return $retarr;
	}

	private function getSvc_ucp() {
		$retarr = array(
			"name" => _("UCP"),
			"defzones" => array("public", "external", "internal"),
			"descr" => _("UCP - User Control Panel - is the main user interface to FreePBX, and allows people to control their phone. Note that if you want to allow users to use their web browsers to make calls through UCP you also need to add WebRTC to the same zone(s)."),
			"fw" => array("protocol" => "tcp", "port" => 81),
		);
		return $retarr;
	}

	private function getSvc_webrtc() {
		$retarr = array(
			"name" => _("WebRTC"),
			"defzones" => array("reject"),
			"descr" => _("WebRTC is used by UCP (and other services) to enable calls to be made via a web browser."),
			"fw" => array("protocol" => "tcp", "port" => 8088),
		);

		// TODO: Check httpd.conf and chan_sip.conf to make sure that it's enabled.
		return $retarr;
	}

	private function getSvc_pjsip() {
		$retarr = array(
			"name" => _("SIP Protocol"),
			"defzones" => array("external", "internal"),
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
			"defzones" => array("external", "internal"),
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
			"fw" => array("protocol" => "udp", "port" => 4569),
		);
		return $retarr;
	}

	private function getSvc_provis() {
		$retarr = array(
			"name" => _("HTTP Provisioning"),
			"defzones" => array("external", "internal"),
			"descr" => _("Text for HTTP Provisioning not done..."),
			"fw" => array("protocol" => "tcp", "port" => 84),
		); 
		return $retarr;
	}

	private function getSvc_restapps() {
		$retarr = array(
			"name" => _("REST Apps"),
			"defzones" => array("internal"),
			"descr" => _("Text for REST Apps not done..."),
			"fw" => array("protocol" => "tcp", "port" => 85),
		); 
		return $retarr;
	}

	private function getSvc_xmpp() {
		$retarr = array(
			"name" => _("XMPP"),
			"defzones" => array("external", "internal"),
			"descr" => _("Text for XMPP not done..."),
			"fw" => array("protocol" => "tcp", "port" => 5222),
		); 
		return $retarr;
	}

	private function getSvc_ftp() {
		$retarr = array(
			"name" => _("FTP"),
			"defzones" => array("internal"),
			"descr" => _("FTP is used by things to do stuff. Redo this text."),
			"fw" => array("protocol" => "tcp", "port" => 21),
		); 
		return $retarr;
	}

	private function getSvc_tftp() {
		$retarr = array(
			"name" => _("TFTP"),
			"defzones" => array("internal"),
			"descr" => _("TFTP is used normally for provisioning and upgrading of devices."),
			"fw" => array("protocol" => "udp", "port" => 69),
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
			array('protocol' => 'udp', 'dport' => '2049'),
			array('protocol' => 'tcp', 'dport' => '2049'),
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
		$retarr[] = array('protocol' => 'udp', 'dport' => $mountd);
		$retarr[] = array('protocol' => 'udp', 'dport' => $statd);
		$retarr[] = array('protocol' => 'udp', 'dport' => $lockdudp);
		$retarr[] = array('protocol' => 'tcp', 'dport' => $mountd);
		$retarr[] = array('protocol' => 'tcp', 'dport' => $statd);
		$retarr[] = array('protocol' => 'tcp', 'dport' => $lockdtcp);

		return $retarr;
	}

	private function getSvc_smb() {
		$retarr = array(
			"name" => _("SMB/CIFS"),
			"defzones" => array("reject"),
			"descr" => _("SMB/CIFS is used to access files on this machine from Windows or Mac systems."),
			"fw" => array(
				array('protocol' => 'udp', 'dport' => '137'),
				array('protocol' => 'udp', 'dport' => '138'),
				array('protocol' => 'tcp', 'dport' => '139'),
				array('protocol' => 'tcp', 'dport' => '445'),
			),
		); 
		return $retarr;
	}
}

