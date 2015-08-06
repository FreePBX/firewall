<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
namespace FreePBX\modules\Firewall;

class Services {

	private $allservices;

	public function __construct() {
		// Can't define arrays in some versions of PHP.
		$this->allservices = array("ssh", "http", "https", "pjsip", "chansip", "iax");
	}

	public function getAllServices() {
		return $this->allservices;
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
			"defzones" => array("public", "internal", "trusted"),
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
			"defzones" => array("public", "internal", "trusted"),
			"descr" => _("Web management interface for FreePBX. This is the https interface."),
			"fw" => array("protocol" => "tcp", "port" => 443),
		);
		return $retarr;
	}

	private function getSvc_pjsip() {
		$retarr = array(
			"name" => _("SIP Protocol"),
			"defzones" => array("public", "internal", "trusted"),
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
			"defzones" => array("internal", "trusted"),
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
			"defzones" => array("trusted"),
			"descr" => _("IAX stands for Inter Asterisk eXchange. It is more bandwidth efficient than SIP, but few providers support it."),
			"fw" => array("protocol" => "udp", "port" => 4569),
		);
		return $retarr;
	}
}

