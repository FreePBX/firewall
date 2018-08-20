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

	// FREEPBX-11934
	public function testInvalidOffset() {
		$ipoutput = file(__DIR__."/ipoutput.2");
		$parsed = self::$n->parseIpOutput($ipoutput);
		$this->assertEquals($parsed['tun1']['addresses'][0][0], "172.16.3.164", "Tunnel IP address not being returned");
	}

	// FREEPBX-13396
	public function testWrongName() {
		$ipoutput = file(__DIR__."/freepbx-13396.txt");
		$parsed = self::$n->parseIpOutput($ipoutput);
		$this->assertFalse(isset($parsed['dynamic']), "Interface called 'dynamic' detected");
		$this->assertTrue(isset($parsed['eth4']), "eth4 not discovered");
		$this->assertEquals(count($parsed['eth4']['addresses']), 2, "Didn't find 2 addresses on eth4");
	}

	// Reported by artyx via IRC
	public function testNoprefixrouteffset() {
		$ipoutput = file(__DIR__."/ipoutput.3");
		$parsed = self::$n->parseIpOutput($ipoutput);
		$this->assertFalse(isset($parsed['noprefixroute']), "Wrong interface name 'noprefixroute' returned");
	}

	// FREEPBX-17657 - OpenVZ has a strange 'ip -o addr' output.
	public function testOpenVZ() {
		$ipoutput = file(__DIR__."/ipoutput.4");
		$parsed = self::$n->parseIpOutput($ipoutput);
		$this->assertEquals([], $parsed['venet0']['addresses'], "venet0 should not have any addresses");
		$this->assertEquals("66.111.111.111", $parsed['venet0:0']['addresses'][0][0], "venet0:0 address not returned");
	}
}
