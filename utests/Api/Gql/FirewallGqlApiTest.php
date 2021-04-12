<?php 

namespace FreepPBX\firewall\utests;

require_once('../api/utests/ApiBaseTestCase.php');

use FreePBX\modules\firewall;
use FreePBX\modules\Api\utests\ApiBaseTestCase;

/**
 * FirewallGqlApiTest
 */
class FirewallGqlApiTest extends ApiBaseTestCase {
  protected static $firewall;
  
  /**
   * setUpBeforeClass
   *
   * @return void
   */
  public static function setUpBeforeClass() {
    parent::setUpBeforeClass();
    self::$firewall = self::$freepbx->firewall;
  }
        
  /**
   * tearDownAfterClass
   *
   * @return void
   */
  public static function tearDownAfterClass() {
    parent::tearDownAfterClass();
  }
  
   /**
    * testFetchBlacklistedIpTrue
    *
    * @return void
    */
   public function testFetchBlacklistedIpTrue(){
    $ip = "123.123.123.123";

    $mockfirewall = $this->getMockBuilder(\FreePBX\modules\firewall\Services::class)
		->disableOriginalConstructor()
		->disableOriginalClone()
		->setMethods(array('getBlacklist'))
    ->getMock();
      
	  $mockfirewall->method('getBlacklist')
		->willReturn(Array('123.123.123.123'));
    
    self::$freepbx->firewall->setServices($mockfirewall); 

    $response = $this->request("query{
    fetchBlacklistIp{
      message status ips
      }
    }");
      
    $json = (string)$response->getBody();
    $this->assertEquals('{"data":{"fetchBlacklistIp":{"message":"Please find the blacklisted Ip below","status":true,"ips":"[\"123.123.123.123\"]"}}}',$json);

    //status 200 success check
    $this->assertEquals(200, $response->getStatusCode());

   }

  /**
   * testAddBlacklistIPShouldReturnTrueWhenIPPassed
   *
   * @return void
   */
  public function testAddBlacklistIPShouldReturnTrueWhenIPPassed(){
    $ip = "100.100.100.100";

    $mockfirewall = $this->getMockBuilder(\FreePBX\modules\firewall\Services::class)
		->disableOriginalConstructor()
		->disableOriginalClone()
		->setMethods(array('addToBlacklist'))
    ->getMock();
      
	  $mockfirewall->method('addToBlacklist')
		->willReturn(true);
    
    self::$freepbx->firewall->setServices($mockfirewall);   

    $response = $this->request("mutation {
      addBlackListIP(input: { 
      IP: \"$ip\" 
    }) {
      status message 
    }
    }");
      
    $json = (string)$response->getBody();

    $this->assertEquals('{"data":{"addBlackListIP":{"status":true,"message":"IP has been added to blacklist"}}}',$json);

    //status 200 success check
    $this->assertEquals(200, $response->getStatusCode());
   }
   
   /**
    * testRemoveBlacklistIPShouldReturnTrueWhenIPPassed
    *
    * @return void
    */
   public function testRemoveBlacklistIPShouldReturnTrueWhenIPPassed(){
    $ip = "100.100.100.100";

    $mockfirewall = $this->getMockBuilder(\FreePBX\modules\firewall\Services::class)
		->disableOriginalConstructor()
		->disableOriginalClone()
		->setMethods(array('removeFromBlacklist'))
    ->getMock();
      
    self::$freepbx->firewall->setServices($mockfirewall);   
    
	  $mockfirewall->method('removeFromBlacklist')
		->willReturn(true);

    $response = $this->request("mutation {
      deleteBlackListIP(input: { 
      IP: \"$ip\" 
    }) {
      status message 
    }
    }");
      
    $json = (string)$response->getBody();

    $this->assertEquals('{"data":{"deleteBlackListIP":{"status":true,"message":"IP removed from blacklist"}}}',$json);

    //status 200 success check
    $this->assertEquals(200, $response->getStatusCode());
   }
   
   /**
    * testEnableFirewallShouldReturnTrueWhenTrue
    *
    * @return void
    */
   public function testEnableFirewallShouldReturnTrueWhenTrue(){

    $mockfirewall = $this->getMockBuilder(\FreePBX\modules\firewall\Firewall::class)
		->disableOriginalConstructor()
		->disableOriginalClone()
		->setMethods(array('runHook','preEnableFW'))
    ->getMock();
      
	  $mockfirewall->method('runHook','preEnableFW')
    ->willReturn(true);
    
    $response = $this->request("mutation {
      enableFirewall(input: { }){
      message
      status
      }
    }");
      
    $json = (string)$response->getBody();

    $this->assertEquals('{"data":{"enableFirewall":{"message":"Firewall enable process has been completed.","status":true}}}',$json);

    //status 200 success check
    $this->assertEquals(200, $response->getStatusCode());
   }
   
   /**
    * testDiableFirewallShouldReturnTrueWhenTrue
    *
    * @return void
    */
   public function testDiableFirewallShouldReturnTrueWhenTrue(){

    $mockfirewall = $this->getMockBuilder(\FreePBX\modules\firewall\Firewall::class)
		->disableOriginalConstructor()
		->disableOriginalClone()
		->setMethods(array('setConfig'))
    ->getMock();
      
	  $mockfirewall->method('setConfig')
		->willReturn(true);

    $response = $this->request("mutation {
      disableFirewall(input: { }){
      message
      status
      }
    }");
      
    $json = (string)$response->getBody();

    $this->assertEquals('{"data":{"disableFirewall":{"message":"Firewall has been disabled","status":true}}}',$json);

    //status 200 success check
    $this->assertEquals(200, $response->getStatusCode());
   }
}
?>