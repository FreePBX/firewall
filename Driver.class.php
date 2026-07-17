<?php
// vim: set ai ts=4 sw=4 ft=php:
namespace FreePBX\modules\Firewall;

class Driver {

	private static $driverObject = false;
	private static $driverName = false;

	public function getDriver() {
		if (!class_exists('\FreePBX\modules\Firewall\Schema')) {
			include __DIR__.'/Schema.class.php';
		}

		$wanted = 'Nftables';
		if (!Schema::nftAvailable()) {
			throw new \RuntimeException(
				'nftables is required by the FreePBX Firewall. Install the nftables package before starting the firewall.'
			);
		}

		if (self::$driverObject && self::$driverName !== $wanted) {
			self::resetDriverCache();
		}

		if (!self::$driverObject) {
			$driver = $wanted;
			$fn = __DIR__."/drivers/$driver.class.php";
			if (!file_exists($fn)) {
				throw new \RuntimeException("Required native nftables driver is missing: $fn");
			}

			$class = '\FreePBX\modules\Firewall\Drivers\\'.$driver;
			if (!class_exists($class)) {
				if (class_exists('\FreePBX\modules\Firewall\Validator')) {
					$v = new Validator;
					$v->secureInclude("drivers/$driver.class.php");
				} else {
					include $fn;
				}
			}

			self::$driverObject = new $class();
			self::$driverName = $driver;
		}

		return self::$driverObject;
	}

	/**
	 * Clear cached driver after backend switch or unit tests.
	 */
	public static function resetDriverCache() {
		self::$driverObject = false;
		self::$driverName = false;
	}

	public static function getCachedDriverName() {
		return self::$driverName;
	}
}
