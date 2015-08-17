<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
//
// TODO: Does this need to **not** use /tmp, because of systemd's /tmp isolation?
// (Probably.) TBD.
namespace FreePBX\modules\Firewall;

class Lock {
	private static $locks;

	public static function canLock($lockname = false) {
		if (!$lockname) {
			throw new \Exception("No lock given");
		}
		// So, we see if we CAN lock a name, and if we can, lock it.
		if (!is_dir("/tmp/locks")) {
			@unlink("/tmp/locks");
			mkdir("/tmp/locks");
			@chmod("/tmp/locks", 0666);
			if (!is_dir("/tmp/locks")) {
				throw new \Exception("Can't create /tmp/locks directory");
			}
		}
		$lf = "/tmp/locks/lock-$lockname";
		$lockfh = fopen($lf, "c"); // Create it if it doesn't exist
		@chmod($lf, 0666);
		if (!flock($lockfh, LOCK_EX|LOCK_NB)) {
			// Unable to lock the file.
			return false;
		}
		// Yay, we locked it!
		if (!is_array(self::$locks)) {
			self::$locks = array($lockname => $lockfh);
		} else {
			self::$locks[$lockname] = $lockfh;
		}
		return true;
	}

	public static function unLock($lockname = false) {
		if (!$lockname) {
			throw new \Exception("No lock given");
		}
		if (!is_array(self::$locks)) {
			throw new \Exception("Tried to unlock before anything was locked");
		} else {
			if (!isset(self::$locks[$lockname])) {
				throw new \Exception("Tried to unlock something that wasn't locked");
			}
			$lockfh = self::$locks[$lockname];
			flock($lockfh, LOCK_UN);
			fclose($lockfh);
			unset(self::$locks[$lockname]);
		}
		return true;
	}
}

