<?php
// vim: :set filetype=php tabstop=4 shiftwidth=4 autoindent smartindent:
namespace FreePBX\modules\Firewall;

class Attacks {

	private $tags;
	private $module;

	public function __construct() {
		if (file_exists("/proc/net/xt_recent/ATTACKER")) {
			$this->module = "/proc/net/xt_recent/";
		} elseif (file_exists("/proc/net/ipt_recent/ATTACKER")) {
			$this->module = "/proc/net/ipt_recent/";
		} else {
			throw new \Exception("Don't know which module to check");
		}

		$this->tags = array("ATTACKER", "REPEAT", "SIGNALLING");
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
			if (!preg_match('/^src=([a-f0-9\.:]+)\s.+\slast_seen: (\d+) oldest_pkt: (\d+) (.+)/', $line, $out)) {
				throw new \Exception("Don't understand line $line");
			}
			$retarr[$out[1]] = array("last_seen" => $out[2], "oldest_pkt" => $out[3], "previous" => explode(", ", $out[4]));
		}
		return $retarr;
	}

	private function generateSummary($tags, $registrations) {

		// Attackers are only valid if packets are LESS than a day old.
		$expire = time() - 86400;
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
			$attackers[$ip] = $tags['ATTACKER'][$ip]['previous'];
		}

		// How many hosts are rate limited?
		// We care about the last 60 seconds for CURRENTLY rate limited hosts.
		$expire = time() - 60;
		$reged = array();
		$clamped = array();
		foreach ($tags['REPEAT'] as $ip => $tmparr) {
			// Is this device registered?
			if (in_array($ip, $registrations)) {
				$reged[] = $ip;
			}
			foreach ($tmparr['previous'] as $id => $timestamp) {
				if ($timestamp < $expire) {
					unset($tags['REPEAT'][$ip]['previous'][$id]);
				}
			}
			// Now, if there aren't any left, no rate limiting is currently being
			// applied
			if (!$tags['REPEAT'][$ip]['previous']) {
				continue;
			}
			$clamped[$ip] = $tags['REPEAT'][$ip]['previous'];
		}

		return array("reged" => $reged, "attackers" => $attackers, "clamped" => $clamped);
	}
}

