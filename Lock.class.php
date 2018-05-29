<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
//
namespace FreePBX\modules\Firewall;

class Lock {
	private static $locks;

	public static function getLockDir() {
		// Change this to be smarter in 15. For the moment, stick with only using /tmp
		return "/tmp";

		// The following code is unused.
		/*
		static $dir = false;

		if (!$dir) {
			// We want to use, in order of preference, /var/run/locks, /run/locks, and 
			// fall back to /tmp/locks.
			//
			// However, if this is an upgrade, /tmp/locks will already exist, so just
			// keep using that until the machine is rebooted.
			//
			if (is_dir("/tmp/locks")) {
				$dir = "/tmp";
				return $dir;
			}

			$order = array("/dev/shm", "/var/run", "/run", "/tmp");
			foreach ($order as $check) {
				if (is_dir($check)) {
					$dir = $check;
					break;
				}
			}
		}

		// If /tmp doesn't exist, we have worse problems than firewall breaking.
		return $dir;
		 */
	}

	public static function canLock($lockname = false) {
		if (!$lockname) {
			throw new \Exception("No lock given");
		}
		// So, we see if we CAN lock a name, and if we can, lock it.
		$lockdir = self::getLockDir();
		if (!is_dir("$lockdir/locks")) {
			@unlink("$lockdir/locks");
			mkdir("$lockdir/locks");
			@chmod("$lockdir/locks", 0666);
			if (!is_dir("$lockdir/locks")) {
				throw new \Exception("Can't create $lockdir/locks directory");
			}
		}
		$lf = "$lockdir/locks/lock-$lockname";
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
			print "Tried to unlock before anything was locked\n";
			return false;
		} else {
			if (!isset(self::$locks[$lockname])) {
				print "Tried to unlock something that wasn't locked\n";
				return false;
			}
			$lockfh = self::$locks[$lockname];
			flock($lockfh, LOCK_UN);
			fclose($lockfh);
			unset(self::$locks[$lockname]);
			unset($lockfh);
		}
		return true;
	}
}

