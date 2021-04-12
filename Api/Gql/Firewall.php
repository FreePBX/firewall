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
					'addBlackListIP' => Relay::mutationWithClientMutationId([
						'name' => 'addBlacklistIP',
						'description' => _('Add to blacklist'),
						'inputFields' => $this->getInputFields(),
						'outputFields' => $this->getOutputFields(),
						'mutateAndGetPayload' => function ($input) {
							$this->freepbx->firewall->services()->addToBlacklist($input['IP']);
							return ['message' =>_("IP has been added to blacklist"), 'status' => true];
						}
					]),
					'deleteBlackListIP' => Relay::mutationWithClientMutationId([
						'name' => 'deleteBlacklistIP',
						'description' => _('Remove from blacklist'),
						'inputFields' => $this->getInputFields(),
						'outputFields' => $this->getOutputFields(),
						'mutateAndGetPayload' => function ($input) {
							$this->freepbx->firewall->services()->removeFromBlacklist($input['IP']);
							return ['message' =>_("IP removed from blacklist"), 'status' => true];
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
					'fetchBlacklistIp' => [
						'type' => $this->typeContainer->get('firewall')->getConnectionType(),
						'description' => _('Fetch custom service zone'),
						'resolve' => function($root, $args) {
							$list = $this->freepbx->firewall->services()->getBlacklist();
							if(isset($list) && $list != null){
								return ['ips'=> _(json_encode($list)),'message'=> _('Please find the blacklisted Ip below'),'status'=>true];
							}else{
								return ['message'=> _("Sorry, No Blacklisted IP found"),'status' => false];
							}
						},
					],
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
				]
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
}