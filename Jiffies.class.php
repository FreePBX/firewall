<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
namespace FreePBX\modules\Firewall;

class Jiffies {

	private $knownjiffies = false;

	public function __construct() {
		// If there isn't a /proc/timer_list, just blindly assume 1000hz.
		if (!file_exists("/proc/timer_list")) {
			$this->knownjiffies = 1000;
		}
	}

	// Calculate the number of jiffies per second.
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
			$jiffies[] = $this->getCurrentJiffie();
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

	public function getCurrentJiffie() {
		if (!file_exists("/proc/timer_list")) {
			return 1000;
		}
		$jf = file("/proc/timer_list", \FILE_IGNORE_NEW_LINES);
		// Find the first entry that is 'jiffies: ' and return it
		foreach ($jf as $l) {
			if (strpos($l, "jiffies: ") === 0) {
				$j =  substr($l, 9);
				return $j;
			}
		}
		throw new \Exception("Couldn't get a jiffie");
	}
}

