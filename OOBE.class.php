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
		print "Hi. I'm an OOBE\n";
		return false;
	}
}



