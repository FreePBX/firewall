<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
//
namespace FreePBX\modules\Firewall;

class Lock {
	private static $locks;

	public static function getLockDir() {
		$state = '/run/fpbx-firewall';
		$lockdir = $state.'/locks';
		if (is_link($state) || is_link($lockdir)) {
			throw new \Exception('Firewall lock directory must not be a symlink');
		}
		if (!is_dir($lockdir)) {
			if (!is_dir($state) && !@mkdir($state, 0755, true)) {
				throw new \Exception("Can't create $state");
			}
			if (!@mkdir($lockdir, 0700, true) && !is_dir($lockdir)) {
				throw new \Exception("Can't create $lockdir");
			}
			@chmod($lockdir, 0700);
		}
		return $lockdir;
	}

	public static function canLock($lockname = false) {
		if (!$lockname || !preg_match('/^[A-Za-z0-9_-]+$/', $lockname)) {
			throw new \Exception("No lock given");
		}
		$lockdir = self::getLockDir();
		$lf = $lockdir."/lock-".$lockname;
		if (is_link($lf)) {
			throw new \Exception("Refusing to lock through a symlink");
		}
		$lockfh = fopen($lf, "c");
		if ($lockfh === false) {
			throw new \Exception("Can't create $lf");
		}
		@chmod($lf, 0600);
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

