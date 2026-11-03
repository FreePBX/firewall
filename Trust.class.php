<?php
namespace FreePBX\modules\Firewall;

/**
 * Guards for code and files used by the root firewall service.
 */
class Trust {

	const STATE_DIR = '/run/fpbx-firewall';

	public static function runningAsRoot() {
		return function_exists('posix_geteuid') && posix_geteuid() === 0;
	}

	public static function rootLocked($path) {
		if (!is_string($path) || $path === '' || is_link($path)) {
			return false;
		}
		$stat = @lstat($path);
		if (!$stat || ($stat['mode'] & 0170000) === 0120000) {
			return false;
		}
		return $stat['uid'] === 0 && ($stat['mode'] & 0022) === 0;
	}

	public static function assertRootFile($path) {
		if (!is_file($path) || !self::rootLocked($path)) {
			throw new \RuntimeException("$path must be a root-owned file and not writable by group or others");
		}
		return $path;
	}

	public static function stateDir() {
		$dir = self::STATE_DIR;
		if (is_link($dir)) {
			throw new \RuntimeException('Firewall state directory must not be a symlink');
		}
		if (!is_dir($dir)) {
			if (!self::runningAsRoot() || (!@mkdir($dir, 0755, true) && !is_dir($dir))) {
				throw new \RuntimeException('Unable to create the firewall state directory');
			}
		}
		if (self::runningAsRoot()) {
			@chown($dir, 0);
			@chgrp($dir, 0);
			@chmod($dir, 0755);
		}
		if (!self::rootLocked($dir) || !is_dir($dir)) {
			throw new \RuntimeException('Firewall state directory is not root-owned');
		}
		return $dir;
	}

	public static function systemBinary(array $candidates) {
		foreach ($candidates as $path) {
			if (!is_string($path) || !is_executable($path)) {
				continue;
			}
			$real = realpath($path);
			if ($real === false || !preg_match('#^/(?:usr/)?(?:s?bin)/#', $real)) {
				continue;
			}
			if (self::rootLocked($real)) {
				return $real;
			}
		}
		return false;
	}

	public static function safeRuntimeDir($dir) {
		$fallback = is_dir('/run/asterisk') ? '/run/asterisk' : '/var/run/asterisk';
		if (!is_string($dir) || !preg_match('#^/(?:var/)?run(?:/[A-Za-z0-9._-]+)*$#', $dir)) {
			return $fallback;
		}
		$real = realpath($dir);
		if ($real === false || !preg_match('#^/(?:var/)?run(?:/|$)#', $real) || is_link($real)) {
			return $fallback;
		}
		return $real;
	}

	public static function stageVerified($source, $name, $expectedHash, $mode = 0700) {
		if (!preg_match('/^[A-Za-z0-9._-]+$/', $name)) {
			throw new \RuntimeException('Invalid staged file name');
		}
		if (!is_string($expectedHash) || !preg_match('/^[a-f0-9]{64}$/', $expectedHash)) {
			throw new \RuntimeException('Invalid expected hash');
		}
		if (is_link($source)) {
			throw new \RuntimeException('Refusing to stage a symlink');
		}
		$handle = fopen($source, 'rb');
		if ($handle === false) {
			throw new \RuntimeException("Unable to read $source");
		}
		$contents = stream_get_contents($handle);
		fclose($handle);
		if ($contents === false || hash('sha256', $contents) !== $expectedHash) {
			throw new \RuntimeException("Refusing to stage $name because its contents do not match the signature");
		}
		$dir = self::stateDir();
		$destination = $dir.'/'.$name;
		$temporary = $destination.'.'.getmypid().'.tmp';
		if (is_link($destination) || is_link($temporary)) {
			throw new \RuntimeException('Refusing to stage through a symlink');
		}
		if (file_put_contents($temporary, $contents) === false) {
			throw new \RuntimeException('Unable to write the staged firewall file');
		}
		chmod($temporary, $mode);
		if (!rename($temporary, $destination)) {
			@unlink($temporary);
			throw new \RuntimeException('Unable to publish the staged firewall file');
		}
		return $destination;
	}

	public static function publish($name, $contents, $mode = 0644) {
		if (!preg_match('/^[A-Za-z0-9._-]+$/', $name)) {
			throw new \RuntimeException('Invalid state file name');
		}
		$dir = self::stateDir();
		$path = $dir.'/'.$name;
		$temporary = $path.'.'.getmypid().'.tmp';
		if (is_link($path) || is_link($temporary)) {
			throw new \RuntimeException('Refusing to write state through a symlink');
		}
		if (file_put_contents($temporary, $contents) === false) {
			throw new \RuntimeException('Unable to write firewall state');
		}
		chmod($temporary, $mode);
		if (!rename($temporary, $path)) {
			@unlink($temporary);
			throw new \RuntimeException('Unable to publish firewall state');
		}
		return $path;
	}

	public static function run(array $command) {
		if (!$command || !self::rootLocked($command[0])) {
			throw new \RuntimeException('Refusing to execute a command that is not a root-owned binary');
		}
		$spec = array(1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
		$process = proc_open($command, $spec, $pipes);
		if (!is_resource($process)) {
			throw new \RuntimeException('Unable to execute '.basename($command[0]));
		}
		$stdout = stream_get_contents($pipes[1]);
		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		return array(proc_close($process), $stdout, $stderr);
	}
}
