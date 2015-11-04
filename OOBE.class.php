<?php
// vim: set ai ts=4 sw=4 ft=php:
namespace FreePBX\modules\Firewall;

class OOBE {

	private $fw;
	private $questions;


	public function __construct($fw = false) {
		if (!$fw) {
			throw new \Exception("No firewall object given");
		}
		$this->fw = $fw;
		$this->questions = array("enabletrustedhost", "enabletrustednet", "enableresponsive", "othernets", "externsetup");
	}

	public function oobeRequest() {

		if ($this->fw->getConfig("abortoobe")) {
			return true;
		}

		$pending = $this->getPendingOobeQuestions();
		if (empty($pending)) {
			$this->fw->setConfig("status", true);
			$this->fw->runHook("firewall");
			return true;
		}

		// Start from the beginning.
		$this->resetOobe();
		$ssf = _("Sangoma Smart Firewall");
		$header  = "<script type='text/javascript' src='modules/firewall/assets/js/views/oobe.js?123'></script>";
		$header .= "<div class='container-fluid'><div class='panel panel-default'><div class='panel-heading'>";
		$header .= "<div class='panel-title'>$ssf</div></div><div class='panel-body'>";
		$body = load_view(__DIR__."/views/oobe.welcome.php", array("fw" => $this->fw));
		$footer = "</div></div></div>\n";
		print $header.$body.$footer;
		return false;
	}

	public function getQuestion() {
		$pending = $this->getPendingOobeQuestions();
		if ($pending) {
			$q = $pending[0];
			$fname = "question_$q";
			if (!method_exists($this, $fname)) {
				throw new \Exception("Can't find $fname function");
			}
			$retarr=$this->$fname();
			$retarr['question'] = $q;
			return $retarr;
		} else {
			return array("complete" => true);
		}
	}

	public function answerQuestion() {
		if (!isset($_REQUEST['question']) || !isset($_REQUEST['answer'])) {
			throw new \Exception("No question or answer");
		}
		$answer = $_REQUEST['answer'];
		$question = $_REQUEST['question'];

		$qs = $this->getPendingOobeQuestions();
		if (!in_array($question, $qs)) {
			throw new \Exception("Tried to answer a question that wasn't asked");
		}
		$fname = "answer_$question";
		if (!method_exists($this, $fname)) {
			throw new \Exception("Can't find $fname function");
		}
		$ret = $this->$fname($answer);
		$answered = $this->fw->getConfig("oobeanswered");
		if (!is_array($answered)) {
			$answered = array();
		}
		$answered[$question] = true;
		$this->fw->setConfig("oobeanswered", $answered);
		return $ret;
	}

	public function resetOobe() {
		$this->fw->setConfig("oobeanswered", array());
		return true;
	}

	private function getPendingOobeQuestions() {
		$answered = $this->fw->getConfig("oobeanswered");
		if (!is_array($answered)) {
			$answered = array();
			$this->fw->setConfig("oobeanswered", array());
		}

		$retarr = array();
		foreach($this->questions as $q) {
			if (isset($answered[$q])) {
				continue;
			}
			$fname = "check_$q";
			if (!method_exists($this, $fname)) {
				throw new \Exception("Can't find $fname function");
			}
			if ($this->$fname()) {
				$retarr[] = $q;
			} 
		}
		return $retarr;
	}

	private function check_enabletrustedhost() {
		// Is this host already trusted? If not, don't ask.
		if ($this->fw->thisHostAdded()) {
			return false;
		} else {
			return true;
		}
	}

	private function question_enabletrustedhost() {
		return array(
			"desc" => _("Should the client you're using be trusted?"),
			"helptext" => array(
				sprintf(_("It is highly recommended that the client you're currently using (%s) should be marked as Trusted. This will ensure that you can not accidentally be locked out of this server."), $this->fw->detectHost()),
				_("You would normally select <strong>Yes</strong> to this question. The only time you would pick No is if you are not using the client machine you will be using in the future to manage this system."),
			),
			"default" => "yes",
		);
	}

	private function answer_enabletrustedhost() {
		if ($_REQUEST['answer'] == "yes") {
			$_REQUEST['command'] = "addthishost";
			return $this->fw->ajaxHandler();
		} else {
			return true;
		}
	}

	private function check_enabletrustednet() {
		// Is this host already trusted? If not, don't ask.
		if ($this->fw->thisNetAdded()) {
			return false;
		} else {
			return true;
		}
	}

	private function question_enabletrustednet() {
		$retarr = array(
			"desc" => _("Should your current network be trusted?"),
			"default" => "no",
		);
		$thisnet = $this->fw->detectNetwork();
		$helptext = array(
			sprintf(_("The network you are currently using (%s) to manage this server isn't marked as Trusted."), $thisnet),
			_("If this is a known secure network, you should add it to the Trusted zone"),
		);
		$retarr['helptext'] = $helptext;
		list($net, $mask) = explode("/", $thisnet);
		if (filter_var($net, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) {
			$retarr['alert'] = _("As you are connecting from an IPv6 network it is <strong>highly recommended</strong> to add this network, as IPv6 security extensions may unexpectedly change your IP address.");
			$retarr['alerttype'] = "danger";
			$retarr['default'] = "yes";
		} else {
			$retarr['alert'] = _("Please ensure that you are not inadvertently allowing unauthorized hosts access to your machine. You should only select 'Yes' if you are sure the network (above) is not accessible by any unknown third parties.");
			$retarr['alerttype'] = "warning";
		}
		return $retarr;
	}

	private function answer_enabletrustednet() {
		if ($_REQUEST['answer'] == "yes") {
			$_REQUEST['command'] = "addthisnetwork";
			return $this->fw->ajaxHandler();
		} else {
			return true;
		}
	}


	private function check_othernets() {
		// Todo: Ask about adding other networks.  Check sipsettings for known nets?
		return false;
	}

	private function check_enableresponsive() {
		// Always ask about enabling responsive
		return true;
	}

	private function question_enableresponsive() {
		$retarr = array(
			"desc" => _("Enable Responsive Firewall?"),
			"helptext" => array(
				_("Enabling Responsive Firewall allows remote clients to securely register to this server without explicitly whitelisting them."),
				_("It is recommended to turn this on if you have remote clients."),
				"<a href='http://wiki.freepbx.org/display/FPG/Responsive+Firewall' target=_new>"._("Further information is available at the FreePBX Wiki.")."</a>",
			),
			"default" => "yes",
		);
		if ($this->fw->getConfig('responsivefw')) {
			$retarr['alert'] = "<h2>"._("Warning")."</h2><p>"._("Responsive Firewall is <strong>currently enabled</strong>.")."</p>";
			$retarr['alerttype'] = "danger";
		}
		return $retarr;

	}

	private function answer_enableresponsive() {
		if ($_REQUEST['answer'] == "yes") {
			$this->fw->setConfig('responsivefw', true);
		} else {
			$this->fw->setConfig('responsivefw', false);
		}
		return true;
	}

	private function check_externsetup() {
		// Ask about setting up known IP addresses..
		return true;
	}

	private function question_externsetup() {
		$retarr = array(
			"desc" => _("Automatically configure Asterisk IP Settings?"),
			"helptext" => array(
				_("Firewall should now auto-detect and configure External IP settings. This will assist with NAT or Translation issues."),
				_("You should say 'Yes' to this, unless you have an extremely complex network with multiple external default gateways."),
				_("You can verify these settings in Sip Settings after this wizard is complete. If you have a non-static IP address, you may need to use a DDNS provider which will require manual configuration."),
			),
			"default" => "yes",
		);
		$extip = \FreePBX::Sipsettings()->getConfig('externip');
		$localnets = \FreePBX::Sipsettings()->getConfig('localnets');
		if (!$localnets || !is_array($localnets)) {
			// No configuration has been done.
			return $retarr;
		}
		$retarr['alert'] = "<h2>"._("Warning")."</h2><p>"._("Selecting 'Yes' will update your current configuration. Selecting 'No' will not change your current settings.")."</p>";
		$retarr['alert'] .= "<p>".sprintf(_("External Address: %s"), $extip)."</p>";
		$retarr['alert'] .= "<p>"._("Known Networks:")."<ul>";
		foreach ($localnets as $n) {
			$retarr['alert'] .= "<li>".$n['net']."/".$n['mask']."</li>\n";
		}
		$retarr['alert'] .= "</ul></p>";
		$retarr['alerttype'] = "warning";
		return $retarr;
	}

	private function answer_externsetup() {
		if ($_REQUEST['answer'] != "yes") {
			return;
		}

		include 'Natget.class.php';
		$n = new Natget();
		$myip = $n->getVisibleIP();
		$myroutes = $n->getRoutes();
		\FreePBX::Sipsettings()->setConfig('externip', $myip);

		// Update routes
		$ssroutes = \FreePBX::Sipsettings()->getConfig('localnets');
		if (!is_array($ssroutes)) {
			$ssroutes = array();
		}

		// I don't like these loops, it feels messy.
		foreach ($myroutes as $r) {
			// $r = [ "1.2.3.0", "24" ]
			$found = false;
			foreach ($ssroutes as $current) {
				// $current = {"net":"1.2.3.0","mask":"24"}
				if ($current['net'] == $r[0] && $current['mask'] == $r[1]) {
					$found = true;
					break;
				}
			}
			if (!$found) {
				$ssroutes[] = array("net" => $r[0], "mask" => $r[1]);
			}
		}
		$ssroutes = \FreePBX::Sipsettings()->setConfig('localnets', $ssroutes);
		return true;
	}
}



