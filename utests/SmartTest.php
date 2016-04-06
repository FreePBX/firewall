<?php
/**
* @backupGlobals disabled
* @backupStaticAttributes disabled
*/

class SmartTest extends PHPUnit_Framework_TestCase {

	public static $f;

	public static function setUpBeforeClass() {
		include "setuptests.php";
		self::$f = \FreePBX::Firewall();
	}

	/**
	 * @expectedException Exception
	 */
	public function testError() {
		$s = self::$f->getSmartObj();
		$this->assertEquals("1.2.3.4", $s->returnCidr("1.2.3.4"), "Didn't return first");
	}

	public function testSubnet() {
		$s = self::$f->getSmartObj();
		$this->assertEquals("1.2.3.0/24", $s->returnCidr("1.2.3.0/255.255.255.0"), "/24 failed");
	}

	public function test32() {
		$s = self::$f->getSmartObj();
		$this->assertEquals("1.2.3.5", $s->returnCidr("1.2.3.5/255.255.255.255"), "/32 failed");
	}

	public function testCidr() {
		$s = self::$f->getSmartObj();
		$this->assertEquals("1.2.3.0/24", $s->returnCidr("1.2.3.0/24"), "Other /24 failed");
	}

	public function testFix24Network() {
		$s = self::$f->getSmartObj();
		$this->assertEquals("1.2.3.0/24", $s->returnCidr("1.2.3.6/24"), "Fixing subnet /24 failed");
	}

	public function testFix16Network() {
		$s = self::$f->getSmartObj();
		$this->assertEquals("1.2.0.0/16", $s->returnCidr("1.2.3.6/255.255.0.0"), "Fixing subnet /16 failed");
	}


}
