<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
//
namespace FreePBX\modules\Firewall;

class Lock {
	private static $locks;

	public static function getLockDir() {
		$setting = getSettings();
		$astrundir = !empty($setting['ASTRUNDIR']) ? $setting['ASTRUNDIR'] : "/var/run/asterisk";
		return $astrundir;
	}

	public static function canLock($lockname = false) {
		if (!$lockname) {
			throw new \Exception("No lock given");
		}
		// So, we see if we CAN lock a name, and if we can, lock it.
		$lockdir = self::getLockDir();
		/* During the initial boot, it might possible that /var/run/asterisk itself is not created 
		/* so trying to wait here at max 30 sec before giving up */
		$x=1;
		while($x <= 6) {
			if (!is_dir($lockdir)) {
				sleep(5);
				$x++;
			} else {
				break;
			}
		}
		if (!is_dir("$lockdir/firewall")) {
			@unlink("$lockdir/firewall");
			mkdir("$lockdir/firewall");
			@chmod("$lockdir/firewall", 0666);
			if (!is_dir("$lockdir/firewall")) {
				throw new \Exception("Can't create $lockdir/firewall directory");
			}
		}
		$lf = "$lockdir/firewall/lock-$lockname";
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

