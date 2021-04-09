<?php

namespace FreePBX\modules\Firewall\Api\Gql;

use GraphQLRelay\Relay;
use GraphQL\Type\Definition\Type;
use FreePBX\modules\Api\Gql\Base;
use GraphQL\Type\Definition\ObjectType;
use FreePBX\modules\Services;

/**
 * Firewall
 */
class Firewall extends Base {

   protected $module = 'firewall';
	
	/**
	 * getScopes
	 *
	 * @return void
	 */
	public static function getScopes() {
		return [
			'read:firewall' => [
				'description' => _('Read from firewall'),
			],
			'write:firewall' => [
				'description' => _('Write to firewall'),
			]
		];
	}
   
   /**
    * mutationCallback
    *
    * @return void
    */
   public function mutationCallback() {
		if($this->checkAllWriteScope()) {
			return function() {
				return [
					'enableFirewall' => Relay::mutationWithClientMutationId([
						'name' => 'enableFirewall',
						'description' => _('Enable firewall'),
						'inputFields' => [],
						'outputFields' => $this->getOutputFields(),
						'mutateAndGetPayload' => function ($input) {
							$this->freepbx->firewall->preEnableFW();
							$res = $this->freepbx->firewall->runHook("firewall");
							if($res){
								return ['message' => _('Firewall enable process has been completed.'),'status' => true];
							}else{
								return ['message' => _('Sorry unable to process enable firewall'),'status' => false];
							}}
					 ]),
					'disableFirewall' => Relay::mutationWithClientMutationId([
						'name' => 'disableFirewall',
						'description' => _('Disable firewall'),
						'inputFields' => [],
						'outputFields' => $this->getOutputFields(),
						'mutateAndGetPayload' => function ($input) {
						 if (!file_exists("/etc/asterisk/firewall.lock")) {
							@unlink("/etc/asterisk/firewall.enabled");
							$res = $this->freepbx->firewall->setConfig("status", false);
							if($res){
								return ['message' =>_("Firewall has been disabled"), 'status' => true];
							}else{
								return ['message' =>_("Firewall can not be disabled"), 'status' => false];
							}
						 }else {
							return ['message' =>_("Firewall.lock doest not exists"), 'status' => false];
						}}
					]),
					'addBlackListIPs' => Relay::mutationWithClientMutationId([
						'name' => 'addBlacklistIP',
						'description' => _('Add to blacklist'),
						'inputFields' => $this->getInputFields(),
						'outputFields' => $this->getOutputFields(),
						'mutateAndGetPayload' => function ($input) {
							$this->freepbx->firewall->services()->addToBlacklist($input['IP']);
							return ['message' =>_("IP has been added to blacklist"), 'status' => true];
						}
					]),
					'deleteBlackListIPs' => Relay::mutationWithClientMutationId([
						'name' => 'deleteBlacklistIP',
						'description' => _('Remove from blacklist'),
						'inputFields' => $this->getInputFields(),
						'outputFields' => $this->getOutputFields(),
						'mutateAndGetPayload' => function ($input) {
							$this->freepbx->firewall->services()->removeFromBlacklist($input['IP']);
							return ['message' =>_("IP removed from blacklist"), 'status' => true];
						}
					]),
					'updateFirewallConfiguration' => Relay::mutationWithClientMutationId([
						'name' => 'updateFirewallConfiguration',
						'description' => _('Add/update firewall configuration'),
						'inputFields' => $this->getFirewallConfigurationInputFields(),
						'outputFields' => $this->getOutputFields(),
						'mutateAndGetPayload' => function ($input) {
						try{
							$res = $this->freepbx->firewall->services()->setFirewallConfigurations($input);
							if($res){
								return ['message' =>_("Firewall configurations have been saved successfully"), 'status' => true];
							}
							return ['message' =>_("Sorry,Firewall configurations has failed"), 'status' => false];
						}catch(\Exception $e){
							return ['message' =>_($e->getMessage()), 'status' => false];
						}}
					]),
					'addWhiteListIPs' => Relay::mutationWithClientMutationId([
						'name' => 'addWhiteListIPs',
						'description' => _('Add a whiltelisted IPs'),
						'inputFields' => $this->getWhitelistIpsInputFields(),
						'outputFields' => $this->getOutputFields(),
						'mutateAndGetPayload' => function ($input) {	
							try{
								$res = $this->freepbx->firewall->services()->addToWhitelist($input);
								if($res){
									return ['message' =>_("IPs has been added to Whitelisted"), 'status' => true];
								}	
								return ['message' =>_("Sorry, failed to added IPs to Whitelist"), 'status' => false];
							}catch(\Exception $e){
								return ['message' =>_($e->getMessage()), 'status' => false];
							}
						}
					]),
				];
			};
		}
	}
	
	/**
	 * queryCallback
	 *
	 * @return void
	 */
	public function queryCallback() {
		if($this->checkAllReadScope()) {
			return function() {
				return [
					'fetchAllBlacklistIPs' => [
						'type' => $this->typeContainer->get('firewall')->getConnectionType(),
						'description' => _('Fetch custom service zone'),
						'resolve' => function($root, $args) {
							$res = $this->freepbx->firewall->services()->getBlacklist();
							if(isset($res) && $res != null){
								$list = array();
								foreach($res as $key => $val){
									array_push($list,array('sourceIp' => $key , 'trusted' => $val));
								}
								return ['response'=> $list,'message'=> _('List of all blacklistedIPs'),'status'=>true];
							}else{
								return ['message'=> _("Sorry, No Blacklisted IPs found"),'status' => false];
							}
						},
					],
					'fetchAllWhitelistIPs' => [
						'type' => $this->typeContainer->get('firewall')->getConnectionType(),
						'description' => _('Fetch all Whitelisted IPs'),
						'resolve' => function($root, $args) {
							$list = $this->freepbx->firewall->services()->getServiceZones();
							if(isset($list) && $list != null){
								return ['response'=> $list,'message'=> _('List of all whiltelistedIPs'),'status'=>true];
							}else{
								return ['message'=> _("Sorry, no whitelisted IPs found"),'status' => false];
							}
						},
					],
					'fetchFirewallConfiguration' => [
						'type' => $this->typeContainer->get('firewall')->getConnectionType(),
						'description' => _('Fetch firewall configuration'),
						'resolve' => function($root, $args) {
							$list = $this->freepbx->firewall->services()->getFirewallConfigurations();
							if(isset($list) && $list != null){
								return ['response'=> $list,'message'=> _('List of firewall configurations'),'status'=>true];
							}else{
								return ['message'=> _("Sorry, failed to list firewall configuration"),'status' => false];
							}
						},
					]
				];
			};
		}
	}
	
	/**
	 * initializeTypes
	 *
	 * @return void
	 */
	public function initializeTypes() {
		$firewall = $this->typeContainer->create('firewall');
		$firewall->setDescription(_('firewall call back description'));

		$firewall->addInterfaceCallback(function() {
			return [$this->getNodeDefinition()['nodeInterface']];
		});

		$firewall->addFieldCallback(function() {
			return [
				'id' => Relay::globalIdField('firewall', function($row) {
					return isset($row['id']) ? $row['id'] : '';
				}),
				'status' => [
				   'type' => Type::boolean(),
				   'description' => _('Status for the firewall enabled/disabled'),
					'resolve' => function($row) {
						return $row['firewallStatus'];
					}
				],
				'responsiveFirewall' => [
				   'type' => Type::boolean(),
				   'description' => _('Status for the responsive firewall'),
				],
				'chainSip' => [
				   'type' => Type::boolean(),
				   'description' => _('Status of the chainSIP'),
				],
				'pjSip' => [
				   'type' => Type::boolean(),
				   'description' => _('Status for the pjSIP')
				],
				'safemode' => [
				   'type' => Type::string(),
				   'description' => _('Status of safe mode enabled/disabled'),
					'resolve' => function($row) {
						return $row['safemodeEnabled'];
					}
				],
				'currentJiffies' => [
				   'type' => Type::string(),
				   'description' => _('Value of the current jiffies'),
				],
				'enableTrustedHost' => [
				   'type' => Type::boolean(),
				   'description' => _('Status of the trusted host'),
					'resolve' => function($row) {
						return $row['oobeAnswered']['enabletrustedhost'];
					}
				],
				'enableResponsive' => [
				   'type' => Type::boolean(),
				   'description' => _('Status responsive enabled'),
					'resolve' => function($row) {
						return $row['oobeAnswered']['enableresponsive'];
					}
				],
				'externalSetup' => [
				   'type' => Type::boolean(),
				   'description' => _('Status for the ecternal Setup'),
					'resolve' => function($row) {
						return $row['oobeAnswered']['externsetup'];
					}
				],
				'provision' => [
				   'type' => Type::boolean(),
				   'description' => _('Status for the provision'),
					'resolve' => function($row) {
						return $row['provis'];
					}
				],
				'sourceIp' => [
				   'type' => Type::string(),
				   'description' => _('Ip address of the source'),
				],
				'trusted' => [
				   'type' => Type::boolean(),
				   'description' => _('Ip address listed is trusted or not'),
					'resolve' => function($row) {
						return $row['trusted'] == "trusted" ? true : false;
					}
				]
			];
		});

		$firewall->setConnectionResolveNode(function ($edge) {
			return $edge['node'];
		});

		$firewall->setConnectionFields(function() {
			return [
				'message' =>[
					'type' => Type::string(),
					'description' => _('Message for the request')
				],
				'ips' =>[
					'type' => Type::string(),
					'description' => _('IPs black listed')
				],
				'status' =>[
					'type' => Type::boolean(),
					'description' => _('Status for the request')
				],
				'configurations' => [
					'type' =>  Type::listOf($this->typeContainer->get('firewall')->getObject()),
					'description' => _('list the configurations details'),
					'resolve' => function($root, $args) {
						$data = array_map(function($row){
							return $row;
						},$root['response']);
						return $data;
					}
				],
				'whitelistIps' => [
					'type' =>  Type::listOf($this->typeContainer->get('firewall')->getObject()),
					'description' => _('list of whitelistIps'),
					'resolve' => function($root, $args) {
						$data = array_map(function($row){
							return $row;
						},$root['response']);
						return $data;
					}
				],
				'blacklistIps' => [
					'type' =>  Type::listOf($this->typeContainer->get('firewall')->getObject()),
					'description' => _('list of whitelistIps'),
					'resolve' => function($root, $args) {
						$data = array_map(function($row){
							return $row;
						},$root['response']);
						return $data;
					}
				],
			];
		});
	}
	
	/**
	 * getOutputFields
	 *
	 * @return void
	 */
	private function getOutputFields(){
		return [
			'message' =>[
				'type' => Type::string(),
				'description' => _('Message for the request')
			],
			'status' =>[
				'type' => Type::boolean(),
				'description' => _('Status for the request')
			],
			'transaction_id' =>[
				'type' => Type::string(),
				'description' => _('Transaction for the request')
			]
		];
	}
	
	/**
	 * getInputFields
	 *
	 * @return void
	 */
	private function getInputFields() {
		return [
			'IP' => [
				'type' => Type::nonNull(Type::string()),
				'description' => _('Blacklist port')
			],
		];
	}
	
	/**
	 * getFirewallConfigurationInputFields
	 *
	 * @return void
	 */
	private function getFirewallConfigurationInputFields() {
		return [
			'status' => [
				'type' => Type::boolean(),
				'description' => _('To enable/disable a firewall'),
				'defaultValue' => true
			],
			'responsiveFirewall' => [
				'type' => Type::boolean(),
				'description' => _('To enable/disable a responsive firewall'),
				'defaultValue' => true
			],
			'chansip' => [
				'type' => Type::listOf(Type::string()),
				'description' => _('Set the chainSIP configuration'),
				'defaultValue' => ["true", "rfw"]
			],
			'pjsip' => [
				'type' => Type::listOf(Type::string()),
				'description' => _('Set the PjSIP Configuration'),
				'defaultValue' => ["true", "rfw"]
			],
			'safeMode' => [
				'type' => Type::string(),
				'description' => _('To enable/disable safe mode'),
				'defaultValue' => "disabled"
			],
			'currentJiffies' => [
				'type' => Type::string(),
				'description' => _('Set the current Jiffer value, default is 1000'),
				'defaultValue' => "1000"
			],
			'serviceZone' => [
				'type' => Type::listOf(Type::string()),
				'description' => _('Set the service Zone, default is true'),
				'defaultValue' => true
			],
			'enableTrustedHost' => [
				'type' => Type::boolean(),
				'description' => _('Set the trusted host, default is true'),
				'defaultValue' => true
			],
			'enableResponsive' => [
				'type' => Type::boolean(),
				'description' => _('Set OOBE answered enabled/disabled, default is true'),
				'defaultValue' => true
			],
			'externalSetup' => [
				'type' => Type::boolean(),
				'description' => _('Set OOBE ansexternalsetup options'),
				'defaultValue' => [ "external", "other", "internal" ]
			]
		];
	}
	
	/**
	 * getWhitelistIpsInputFields
	 *
	 * @return void
	 */
	private function getWhitelistIpsInputFields(){
		return[
			'IPs' => [
				'type' => Type::nonNull(Type::listOf(Type::listOf(Type::string()))),
				'description' => _('Set the list of zones to whitelist'),
			]
		];
	}
}