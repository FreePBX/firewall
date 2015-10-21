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
		$header = "<div class='container-fluid'><div class='panel panel-default'><div class='panel-heading'>";
		$header .= "<div class='panel-title'>$ssf</div></div><div class='panel-body'>";
		$body = load_view(__DIR__."/views/oobe.welcome.php", array("fw" => $this->fw));
		$footer = "</div></div></div>\n";
		print $header.$body.$footer;
		return false;
	}
}



