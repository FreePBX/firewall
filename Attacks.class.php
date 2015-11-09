<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
namespace FreePBX\modules\Firewall;

class Attacks {

	private $tags;
	private $module;
	private $jiffies;

	public function __construct($jiffies) {
		if (file_exists("/proc/net/xt_recent/ATTACKER")) {
			$this->module = "/proc/net/xt_recent/";
		} elseif (file_exists("/proc/net/ipt_recent/ATTACKER")) {
			$this->module = "/proc/net/ipt_recent/";
		} else {
			throw new \Exception("Firewall is not running!");
		}

		$this->tags = array("ATTACKER", "REPEAT", "SIGNALLING", "CLAMPED");
		$this->jiffies = $jiffies;
	}

	public function getAllAttacks($registrations) {
		$retarr = array();
		foreach ($this->tags as $tag) {
			$retarr[$tag] = $this->parseRecent($tag);
		}

		$summary = $this->generateSummary($retarr, $registrations);

		$retarr['summary'] = $summary;
		return $retarr;
	}

	private function parseRecent($tag) {
		$file = $this->module.$tag;
		if (!file_exists($file)) {
			throw new \Exception("Can't find $file");
		}
		$tmparr = file($file, \FILE_IGNORE_NEW_LINES|\FILE_SKIP_EMPTY_LINES);
		$retarr = array();

		foreach ($tmparr as $line) {
			// Looks like this: 
			// src=192.168.15.11 ttl: 61 last_seen: 5317769715 oldest_pkt: 30 5316922978, 5316929714, 5316982978, 5316989717, 5317042978, ...
			// Note the number is actually kernel jiffies.
			if (!preg_match('/^src=([a-f0-9\.:]+)\s.+\slast_seen: (\d+) oldest_pkt: (\d+) (.+)/', $line, $out)) {
				throw new \Exception("Don't understand line $line");
			}
			$retarr[$out[1]] = array("last_seen" => $out[2], "oldest_pkt" => $out[3], "previous" => explode(", ", $out[4]));
		}
		return $retarr;
	}

	private function generateSummary($tags, $registrations) {
		// Attackers are only valid if packets are LESS than a day old. Note
		// that these are JIFFIES that are reported.
		$expire = $this->jiffies->getCurrentJiffie() - (86400 * $this->jiffies->getKnownJiffies());
		$attackers = array();
		foreach ($tags['ATTACKER'] as $ip => $tmparr) {
			// Run through the list of packets and remove any that are too old.
			foreach ($tmparr['previous'] as $id => $timestamp) {
				if ($timestamp < $expire) {
					unset($tags['ATTACKER'][$ip]['previous'][$id]);
				}
			}
			// Now, if there aren't any left, this is no longer an attacker.
			if (!$tags['ATTACKER'][$ip]['previous']) {
				continue;
			}
			// OK, it is.
			$attackers[] = $ip;
		}

		// How many hosts are rate limited?
		// We care about the last 60 seconds for CURRENTLY rate limited hosts.
		$expire = $this->jiffies->getCurrentJiffie() - (60 * $this->jiffies->getKnownJiffies());
		$clamped = array();
		foreach ($tags['SIGNALLING'] as $ip => $tmparr) {
			foreach ($tmparr['previous'] as $id => $timestamp) {
				if ($timestamp < $expire) {
					unset($tags['SIGNALLING'][$ip]['previous'][$id]);
				}
			}
			// Now, if there are less than 10 left, no rate limiting is being  applied
			if (count($tags['SIGNALLING'][$ip]['previous']) < 10) {
				continue;
			}
			$clamped[] = $ip;
		}

		// Grab a simple list of hosts that were EVER clamped, with the utime of when
		// they were (not jiffy)
		$everclamped = array();
		foreach ($tags['CLAMPED'] as $ip => $tmparr) {
			$utimes = array();
			foreach ($tmparr['previous'] as $jiffy) {
				$utimes[] = $this->jiffies->getUtimeFromJiffy($jiffy);
			}
			$everclamped[$ip] = $utimes;
		}

		$all = array();
		$reged = array();
		$others = array();
		// Now we go through all the hosts that have hit RFW at all, and
		// report them, removing ones we already have mentioned.
		foreach ($tags['REPEAT'] as $ip => $tmparr) {

			// Was this one that registered? Yay!
			if (in_array($ip, $registrations)) {
				$reged[] = $ip;
				continue;
			}

			// Otherwise, we want it for history. Grab the last 5 packets and utime them
			$counter = 1;
			$allutimes = array();
			$sorted = $tmparr['previous'];
			arsort($sorted);
			foreach ($sorted as $jiffy) {
				if ($counter++ > 5) {
					break;
				}
				$utime = $this->jiffies->getUtimeFromJiffy($jiffy);
				$ago = time() - $utime;
				$allutimes[] = array("timestamp" => $utime, "ago" => $ago);
			}
			$all[$ip] = $allutimes;

			// Banned?
			if (in_array($ip, $attackers)) {
				continue;
			}

			// Currently clamped?
			if (in_array($ip, $clamped)) {
				continue;
			}

			// Well, it's something new, or old, then. Seperate them into ages
			$history = array("day" => array(), "week" => array(), "month" => array(), "older" => array());
			$day = time() - 86400; // 60*60*24
			$week = time() - 604800; // 86400 * 7
			$month = time() - 2592000; // 86400 * 30

			$others[$ip] = $tmparr;
			foreach ($tmparr['previous'] as $jiffy) {
				$utime = $this->jiffies->getUtimeFromJiffy($jiffy);
				if ($utime < $month) {
					$history['older'][] = $utime;
				} elseif ($utime < $week) {
					$history['month'][] = $utime;
				} elseif ($utime < $day) {
					$history['week'][] = $utime;
				} else {
					$history['day'][] = $utime;
				}
			}
			$others[$ip]= $history;
		}
		return array(
			"reged" => $reged, "attackers" => $attackers, "clamped" => $clamped,
			"everclamped" => $everclamped, "other" => $others, "totalremotes" => count($tags['REPEAT']),
			"history" => $all,
		);
	}
}

