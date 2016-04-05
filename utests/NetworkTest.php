<?php
/**
* @backupGlobals disabled
* @backupStaticAttributes disabled
*/

class NetworkTest extends PHPUnit_Framework_TestCase {

	public static $n;

	public static function setUpBeforeClass() {
		include __DIR__.'/../Network.class.php';
		self::$n = new FreePBX\modules\Firewall\Network;
	}

	public function testDiscover() {
		$dis = self::$n->discoverInterfaces();
		$this->assertTrue(isset($dis['eth0']), "No eth0 discovered. Does this machine have one?");
	}

	// FREEPBX-11709
	public function testBackslash() {
		$ipoutput = file(__DIR__."/ipoutput.1");
		$parsed = self::$n->parseIpOutput($ipoutput);
		$this->assertFalse(isset($parsed['eth0\\']), "Backslash being returned on eth name");
	}


}
