<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
namespace FreePBX\modules\Firewall;

class Jiffies {

	private $knownjiffies = false;

	public function __construct() {
		// Always assume 1000hz.
		$this->knownjiffies = 1000;
	}

	// Calculate the number of jiffies per second.
	// 
	// Note - this doesn't get called. We're always assuming that our
	// clock is at 1000hz. This covers, as far as I can tell, 100% of the
	// machines running freepbx. If this changes, feel free to open a
	// ticket.
	public function calcJiffies($seconds = 5) {
		// If there isn't a /proc/timer_list, just blindly assume 1000hz.
		if (!file_exists("/proc/timer_list")) {
			return 1000;
		}

		$first = $this->getCurrentJiffie();
		sleep(1);
		$seconds--;
		$jiffies = array();
		// Run for however many seconds..
		while ($seconds--)  {
			$jiffies[] = $this->getCurrentJiffie(true); // Force refresh, don't use cached data.
			sleep(1);
		}
		// Now, loop through them, and make sure they look sane.
		// We want to make sure that there's not more than 10% variance
		// in ticks.
		//
		// This is to catch tickless systems, which won't work AT ALL with
		// xt_recent.
		$baseline = $jiffies[0] - $first;
		$maxdiff = $baseline * 1.10;
		$mindiff = $baseline * .9;

		$avgarr = array();
		$lastjiffy = $first;
		foreach ($jiffies as $i => $j) {
			$ticks = $j - $lastjiffy;
			if ($ticks < $mindiff) {
				throw new \Exception("Too few ticks - $ticks - on item $i. ".json_encode($jiffies));
			}
			if ($ticks > $maxdiff) {
				throw new \Exception("Too many ticks - $ticks - on item $i. ".json_encode($jiffies));
			}
			$avgarr[] = $ticks;
			$lastjiffy = $j;
		}

		$realavg = array_sum($avgarr)/count($avgarr);
		// Now, these are 'known' HZ values, so we'll see if it's close enough to one
		// of them to deem it as 'that'.
		$known = array("1000", "100", "250", "300", "4000");
		foreach ($known as $guess) {
			// If realavg is within 5% of guess, return guess.
			$gmax = $guess * 1.05;
			$gmin = $guess * .95;
			if ($realavg > $gmin && $realavg < $gmax) {
				return $guess;
			}
		}
		// Bugger. No idea. Just return an int, rounded to the nearest 10.
		return round($realavg, -1);
	}

	public function getUtimeFromJiffy($jiffies) {
		$now = $this->getCurrentJiffie();
		if ($now === 0) {
			return time();
		}
		$seconds = ($now - $jiffies)/$this->getKnownJiffies();
		$utime = time() - $seconds;
		return (int) $utime;
	}

	public function setKnownJiffies($j = false) {
		if (!$j || (int) $j < 100) {
			return false;
		}
		$this->knownjiffies = (int) $j;
	}

	public function getKnownJiffies() {
		if (!$this->knownjiffies) {
			$this->knownjiffies = $this->calcJiffies();
		}
		return $this->knownjiffies;
	}

	public function getCurrentJiffie($refresh = false) {
		static $current;

		if (!file_exists("/proc/timer_list")) {
			return 0;
		}

		if (!$current || $refresh) {
			exec('grep -i "jiffies:" /proc/timer_list',$jf);
			if (empty($jf[0]) || strpos($jf[0], "jiffies: ") !== 0) {
				throw new \Exception("/proc/timer_list contains unknown data - '".$jf[0]."'");
			}
			$current = substr($jf[0], 9);
		}
		return $current;
	}
}
