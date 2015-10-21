<?php
// vim: set ai ts=4 sw=4 ft=php:
namespace FreePBX\modules;

class OOBE {
	private $fw;

	public function __construct($fw = false) {
		if (!$fw) {
			throw new \Exception("No firewall object given");
		}
		$this->fw = $fw;
	}

	public function oobeRequest() {
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
			return $this->$fname();
		} else {
			return array("complete" => true);
		}
	}

	public function getPendingOobeQuestions() {
		return array("enabletrustedhost", "enabletrustednet", "enableresponsive", "othernets");
	}

	private function question_enabletrustedhost() {
		return array(
			"question" => _("Should the client you're using be trusted?"),
			"helptext" => sprintf(_("It is highly recommended that the client you're currently using (%s) should be marked as Trusted. This will ensure that you can not accidentally be locked out of this server."), $this->fw->detectHost()),
			"html" => "button button stuff...",
		);
	}
}



