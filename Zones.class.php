<?php
// vim: set ai ts=4 sw=4 ft=php:
namespace FreePBX\modules\Firewall;

class Zones {

	public function getZones() {
		$zones = array(
			"reject" => array("name" => _("Reject"), "descr" => _("Any incoming network packets are rejected. You may chose to either drop silently, or, send an icmp-host-prohibited in settings.")),
			"public" => array("name" => _("Public"), "descr" => _("For interfaces connected to the internet. You do not trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.")),
			"internal" => array("name" => _("Internal"), "descr" => _("For use on internal networks. You mostly trust the other computers on the networks to not harm your computer. Only selected incoming connections are accepted.")),
			"trusted" => array("name" => _("Trusted"), "descr" => _("All network connections are accepted.")),
		);

		return $zones;
	}
}

