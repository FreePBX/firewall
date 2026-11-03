<?php
// vim: set ai ts=4 sw=4 ft=php:
namespace FreePBX\modules\Firewall;

class Driver {

	private static $driverObject = false;
	private static $driverName = false;

	public function getDriver() {
		if (!class_exists('\FreePBX\modules\Firewall\Schema')) {
			$this->includeTrusted('Schema.class.php');
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
				$this->includeTrusted("drivers/$driver.class.php");
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

	/**
	 * Root may load firewall code only from a root-owned file. When the
	 * signed validator is active, the signature has to match as well.
	 */
	private function includeTrusted($relative) {
		$absolute = __DIR__.'/'.$relative;
		if ($this->runningAsRoot() && !$this->rootLocked($absolute)) {
			throw new \RuntimeException($relative.' must be root-owned and not writable by group or others before it can be loaded as root');
		}
		if (class_exists('\FreePBX\modules\Firewall\Validator')) {
			try {
				$validator = new Validator();
				$validator->secureInclude($relative);
				return;
			} catch (\Exception $e) {
				if ($this->runningAsRoot() && strpos($e->getMessage(), 'Need signature') === false) {
					throw $e;
				}
			}
		}
		include $absolute;
	}

	private function runningAsRoot() {
		return function_exists('posix_geteuid') && posix_geteuid() === 0;
	}

	private function rootLocked($path) {
		if (is_link($path)) {
			return false;
		}
		$stat = @lstat($path);
		if (!$stat || ($stat['mode'] & 0170000) === 0120000) {
			return false;
		}
		return $stat['uid'] === 0 && ($stat['mode'] & 0022) === 0;
	}
}
