<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
namespace FreePBX\modules\Firewall;

class Attacks {

	private $tags;
	private $jiffies;

	public function __construct($jiffies) {
		if (!$this->nftTableExists()) {
			throw new \Exception("Firewall is not running!");
		}

		$this->tags = array("ATTACKER", "REPEAT", "SIGNALLING", "CLAMPED", "DISCOVERED");
		$this->jiffies = $jiffies;
	}

	public function getAllAttacks($registrations, $summary = true) {
		$retarr = array();
		foreach ($this->tags as $tag) {
			$retarr[$tag] = $this->parseRecent($tag);
		}

		if ($summary) {
			$retarr['summary'] = $this->generateSummary($retarr, $registrations);
		}
		// We only use Discovered for generateSummary
		unset($retarr['DISCOVERED']);

		return $retarr;
	}

	private function parseRecent($tag) {
		$sets = array(
			'ATTACKER' => 'rfw_attacker',
			'REPEAT' => 'rfw_discovered',
			'SIGNALLING' => 'rfw_clamped',
			'CLAMPED' => 'rfw_clamped',
			'DISCOVERED' => 'rfw_discovered',
		);
		if (!isset($sets[$tag])) {
			return array();
		}
		$retarr = array();
		foreach (array($sets[$tag], $sets[$tag].'6') as $set) {
			exec('nft list set inet fpbx '.escapeshellarg($set).' 2>/dev/null', $lines, $status);
			if ($status !== 0) {
				$lines = array();
				continue;
			}
			$blob = implode("\n", $lines);
			if (preg_match('/elements\s*=\s*\{([^}]*)\}/s', $blob, $match)) {
				foreach (explode(',', $match[1]) as $element) {
					if (!preg_match('/^\s*([0-9a-fA-F:.]+)/', trim($element), $address)) {
						continue;
					}
					$now = $this->jiffies->getCurrentJiffie();
					$retarr[$address[1]] = array(
						'last_seen' => $now,
						'oldest_pkt' => 1,
						'previous' => array($now),
					);
				}
			}
			$lines = array();
		}
		return $retarr;
	}

	private function nftTableExists() {
		exec('nft list table inet fpbx >/dev/null 2>&1', $output, $status);
		return $status === 0;
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
		foreach ($tags['DISCOVERED'] as $ip => $tmparr) {

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

