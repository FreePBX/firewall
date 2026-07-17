<?php
namespace FreePBX\modules\Firewall;

/**
 * One-way importer for FreePBX 17 custom INPUT rules.
 *
 * Iptables binaries are invoked only by this explicit migration utility. They
 * are never part of the FreePBX 18 runtime firewall path.
 */
class LegacyRulesMigrator {

	private $nft;

	public function __construct() {
		$this->nft = $this->findExecutable(array('/usr/sbin/nft', '/sbin/nft', '/usr/bin/nft'));
		if (!$this->nft) {
			throw new \RuntimeException('nftables is required to migrate firewall rules');
		}
	}

	/**
	 * Translate supported legacy rules into /etc/firewall.nft.
	 *
	 * Only INPUT append/insert rules are imported automatically. NAT, forwarding,
	 * custom chain creation, and destructive commands require manual review.
	 */
	public function migrate(
		$ipv4 = '/etc/firewall-4.rules',
		$ipv6 = '/etc/firewall-6.rules',
		$output = '/etc/firewall.nft'
	) {
		$rules = array();
		$unsupported = array();
		foreach (array(
			array($ipv4, $this->findExecutable(array('/usr/sbin/iptables-translate', '/sbin/iptables-translate')), 'ip'),
			array($ipv6, $this->findExecutable(array('/usr/sbin/ip6tables-translate', '/sbin/ip6tables-translate')), 'ip6'),
		) as $source) {
			list($file, $translator, $family) = $source;
			if (!is_file($file) || filesize($file) === 0) {
				continue;
			}
			if (!$translator) {
				$unsupported[] = "$file: translator is not installed";
				continue;
			}
			$stat = @stat($file);
			if (!$stat || $stat['uid'] !== 0 || ($stat['mode'] & 0022)) {
				$unsupported[] = "$file: file must be root-owned and not group/world writable";
				continue;
			}
			foreach (file($file, FILE_IGNORE_NEW_LINES) as $index => $line) {
				$line = trim($line);
				if ($line === '' || $line[0] === '#' || $line[0] === ';') {
					continue;
				}
				$translated = $this->translate($translator, $line);
				$prefix = 'add rule '.$family.' filter INPUT ';
				if ($translated === false || strpos($translated, $prefix) !== 0) {
					$unsupported[] = sprintf('%s:%d: %s', $file, $index + 1, $line);
					continue;
				}
				$rules[] = substr($translated, strlen($prefix));
			}
		}

		$result = array(
			'status' => empty($unsupported),
			'translated' => count($rules),
			'unsupported' => $unsupported,
			'output' => $output,
		);
		if ($unsupported) {
			$result['message'] = 'Legacy rules need manual review; no native rules file was changed.';
			return $result;
		}

		$check = "table inet fpbx_migration_check {\n\tchain fpbxcustom {}\n}\n";
		foreach ($rules as $rule) {
			$check .= "add rule inet fpbx_migration_check fpbxcustom $rule\n";
		}
		$tmp = tempnam(sys_get_temp_dir(), 'fpbx-nft-check-');
		file_put_contents($tmp, $check);
		exec(
			escapeshellcmd($this->nft).' --check -f '.escapeshellarg($tmp).' 2>&1',
			$checkOutput,
			$checkStatus
		);
		@unlink($tmp);
		if ($checkStatus !== 0) {
			$result['status'] = false;
			$result['message'] = 'Translated nftables rules failed validation: '.implode("\n", $checkOutput);
			return $result;
		}

		if (is_file($output)) {
			$backup = $output.'.pre-migration.'.gmdate('YmdHis');
			if (!copy($output, $backup)) {
				$result['status'] = false;
				$result['message'] = "Unable to back up existing $output";
				return $result;
			}
			$result['backup'] = $backup;
		}
		$native = "# Generated from FreePBX 17 custom INPUT rules.\n";
		$native .= "# Loaded after the native inet fpbx table has been built.\n";
		$native .= "flush chain inet fpbx fpbxcustom\n";
		foreach ($rules as $rule) {
			$native .= "add rule inet fpbx fpbxcustom $rule\n";
		}
		$tmp = $output.'.tmp';
		if (file_put_contents($tmp, $native) === false || !chmod($tmp, 0600) || !rename($tmp, $output)) {
			@unlink($tmp);
			$result['status'] = false;
			$result['message'] = "Unable to write $output";
			return $result;
		}
		$result['message'] = sprintf(
			'Migrated %d legacy custom INPUT rule(s) to %s.',
			count($rules),
			$output
		);
		return $result;
	}

	/**
	 * Remove iptables-nft compatibility tables after native fpbx is validated.
	 *
	 * This is intentionally migration-only. If an unknown rule/chain is found,
	 * cleanup is refused rather than silently deleting another application's rule.
	 */
	public function removeLegacyRuntime() {
		$unknown = $this->auditLegacyRuntime();
		if ($unknown) {
			return array(
				'status' => false,
				'message' => 'Unknown iptables rules remain; native firewall is active but compatibility tables were not removed.',
				'unsupported' => $unknown,
			);
		}
		exec('systemctl stop fail2ban.service 2>/dev/null');
		foreach (array(
			'delete table ip filter',
			'delete table ip6 filter',
			'delete table ip nat',
			'delete table ip6 nat',
		) as $command) {
			exec(escapeshellcmd($this->nft).' '.$command.' 2>/dev/null');
		}
		$this->normalizeFail2Ban();
		exec('systemctl start fail2ban.service 2>/dev/null', $output, $status);
		return array(
			'status' => ($status === 0),
			'message' => ($status === 0)
				? 'Legacy iptables compatibility tables were removed; Fail2Ban restarted with native nftables actions.'
				: 'Legacy tables were removed, but Fail2Ban did not restart successfully.',
		);
	}

	public function normalizeFail2Ban($file = '/etc/fail2ban/jail.local') {
		if (!is_file($file) || !is_readable($file)) {
			return true;
		}
		$cfg = file_get_contents($file);
		if ($cfg === false) {
			return false;
		}
		$cfg = preg_replace(
			'/action\s*=\s*iptables-allports\[name=([^,\]]+),\s*protocol=([^\]]+)\]/',
			'action = nftables[name=$1, type=allports, protocol=$2]',
			$cfg
		);
		$cfg = preg_replace(
			'/action\s*=\s*iptables-multiport\[name=([^,\]]+),\s*protocol=([^,\]]+),\s*port=([^\]]+)\]/',
			'action = nftables[name=$1, type=multiport, protocol=$2, port=$3]',
			$cfg
		);
		if (strpos($cfg, 'action = iptables-') !== false) {
			return false;
		}
		$backup = $file.'.pre-nftables';
		if (!is_file($backup) && !copy($file, $backup)) {
			return false;
		}
		$tmp = $file.'.nft.tmp';
		return file_put_contents($tmp, $cfg) !== false
			&& chmod($tmp, 0644)
			&& rename($tmp, $file);
	}

	private function auditLegacyRuntime() {
		$unknown = array();
		foreach (array('/usr/sbin/iptables-save', '/usr/sbin/ip6tables-save') as $binary) {
			if (!is_executable($binary)) {
				continue;
			}
			exec($binary.' 2>/dev/null', $lines);
			foreach ($lines as $line) {
				if ($this->isKnownLegacyLine($line)) {
					continue;
				}
				$unknown[] = basename($binary).': '.$line;
			}
			$lines = array();
		}
		return $unknown;
	}

	private function isKnownLegacyLine($line) {
		if ($line === '' || $line[0] === '#' || $line === 'COMMIT' || $line[0] === '*') {
			return true;
		}
		if (preg_match('/^:(INPUT|OUTPUT|FORWARD|PREROUTING|POSTROUTING) /', $line)) {
			return true;
		}
		$known = '(?:fpbx|zone-|fail2ban-|f2b-|lefilter|masq-)';
		if (preg_match('/^:'.$known.'/', $line)) {
			return true;
		}
		if (preg_match('/^-A '.$known.'/', $line)) {
			return true;
		}
		if (preg_match('/^-A (INPUT|OUTPUT|FORWARD|PREROUTING|POSTROUTING) .* -j '.$known.'/', $line)) {
			return true;
		}
		return false;
	}

	private function translate($translator, $line) {
		$args = $this->splitCommandLine($line);
		if ($args === false) {
			return false;
		}
		$command = array_merge(array($translator), $args);
		$spec = array(1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
		$proc = proc_open($command, $spec, $pipes);
		if (!is_resource($proc)) {
			return false;
		}
		$stdout = trim(stream_get_contents($pipes[1]));
		stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		if (proc_close($proc) !== 0 || strpos($stdout, '#') === 0) {
			return false;
		}
		if (preg_match("/^nft '(.*)'$/s", $stdout, $match)) {
			return str_replace("'\\''", "'", $match[1]);
		}
		return false;
	}

	private function splitCommandLine($line) {
		if (preg_match_all('/(?:[^\s"\']+|"[^"]*"|\'[^\']*\')+/', $line, $matches) === false) {
			return false;
		}
		return array_map(function ($arg) {
			$first = substr($arg, 0, 1);
			$last = substr($arg, -1);
			return (($first === '"' && $last === '"') || ($first === "'" && $last === "'"))
				? substr($arg, 1, -1)
				: $arg;
		}, $matches[0]);
	}

	private function findExecutable($paths) {
		foreach ($paths as $path) {
			if (is_executable($path)) {
				return $path;
			}
		}
		return false;
	}
}
