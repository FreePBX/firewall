<?php
// vim: set ai ts=4 sw=4 ft=php:
namespace FreePBX\modules\Firewall;

class Driver {

	public function getDriver() {
		static $driverObject = false;

		if (!$driverObject) {
			// firewalld is really slow. REALLY slow.
			if (file_exists("/usr/bin/firewall-cmd")) {
				$driver = "Firewalld";
			} else {
				$driver = "Iptables";
			}

			$fn = __DIR__."/drivers/$driver.class.php";
			if (!file_exists($fn)) {
				throw new \Exception("Unknown driver $driver");
			}

			// Note the double slash here so we don't escape the single quote.
			// Turn on syntax highlighting if it's not obvious.
			$class = '\FreePBX\modules\Firewall\Drivers\\'.$driver;
			// Do we need to load it?
			if (!class_exists($class)) {
				// Woah there, cowboy. This file COULD be run as root. If it is, then the Validator class should exist.
				if (class_exists('\FreePBX\modules\Firewall\Validator')) {
					$v = new Validator;
					$v->secureInclude("drivers/$driver.class.php");
				} else {
					include $fn;
				}
			} else {
				// Debugging
				throw new \Exception("How did $class already exist?");
			}

			$driverObject = new $class();
		}

		return $driverObject;
	}
}
