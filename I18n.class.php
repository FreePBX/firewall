<?php
// vim: set ai ts=4 sw=4 ft=php:
namespace FreePBX\modules\Firewall;

class I18n {

	public $vars;

	public function __construct() {
		$this->vars = array(
			"Firewall" => _("Firewall"),
			"About Firewall" => _("About Firewall"),
		);
	}

	public function __get($var) {
		if (!isset($this->vars[$var])) {
			// You need to explicitly define everything you want i18n'ed above,
			// otherwise we can't translate it. This is why we throw an exception
			// here.
			throw new \Exception("I was asked for $var. Don't know what that is. Needs to be created so it can be i18n'ed");
		}
		return $this->vars[$var];
	}
}
