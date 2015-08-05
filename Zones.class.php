<?php
// vim: set ai ts=4 sw=4 ft=php:
namespace FreePBX\modules\Firewall;

class Zones {

	public function getZones() {
		$zones = array(
			"drop" => array("name" => _("Drop"), "descr" => _("Any incoming network packets are dropped, there is no reply. Only outgoing network connections are possible.")),
			"block" => array("name" => _("Block"), "descr" => _("Any incoming network connections are rejected with an icmp-host-prohibited message for IPv4 and icmp6-adm-prohibited for IPv6. Only network connections initiated within this system are possible.")),
			"public" => array("name" => _("Public"), "descr" => _("For interfaces connected to the internet. You do not trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.")),
			"internal" => array("name" => _("Internal"), "descr" => _("For use on internal networks. You mostly trust the other computers on the networks to not harm your computer. Only selected incoming connections are accepted.")),
			"trusted" => array("name" => _("Trusted"), "descr" => _("All network connections are accepted.")),
		);

		return $zones;
	}
}

