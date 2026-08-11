<?php
namespace FreePBX\modules\Firewall;

// This is used by hooks for security validation only..
class Validator {

	private static $sig = false;
	private $modroot = false;

	public function __construct($sig = false) {
		// We may have already been instantated, which means we already have a sig
		if (!$sig) {
			if (!self::$sig) {
				throw new \Exception("Need signature file the first time I'm run!");
			}
		} else {
			// We've been given a sig. Check it...
			if (!isset($sig['config']['hash']) || $sig['config']['hash'] !== "sha256") {
				throw new \Exception("Invalid sig file.. Hash is not sha256 - check sigfile");
			}
			self::$sig = $sig;
		}
		// If we're in a phar, use that.
		if (\Phar::running()) {
			$dir = dirname(\Phar::running(false));
		} else {
			$dir = __DIR__;
		}
		$this->modroot = $dir."/../";
	}

	public function updateSig($sig) {
		self::$sig = $sig;
	}

	public function checkFile($filename = false) {
		if ($filename[0] === "/" || strpos($filename, "..") !== false) {
			throw new \Exception("Filename to include failed validation - $filename");
		}

		if (!isset(self::$sig['hashes'][$filename])) {
			throw new \Exception("File $filename isn't signed");
		}

		$shouldbe = self::$sig['hashes'][$filename];
		$fullpath = $this->modroot."/$filename";

		if (!file_exists($fullpath)) {
			throw new \Exception("$fullpath doesn't exists");
		}

		$currenthash = hash_file('sha256', $fullpath);

		if ($currenthash !== $shouldbe) {
			throw new \Exception("Hashes of $filename don't match (Sig = $shouldbe, file = $currenthash)");
		}

		// Phew!
		return $fullpath;
	}

	public function secureInclude($filename = false) {
		if (!isset(self::$sig['hashes'][$filename])) {
			throw new \Exception("File $filename isn't signed");
		}

		// checkFile throws an exception if something's wrong
		$f = $this->checkFile($filename);
		return include $f;
	}
}

