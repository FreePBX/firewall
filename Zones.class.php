<?php
// vim: set ai ts=4 sw=4 ft=php:
namespace FreePBX\modules\Firewall;

class Zones {

	public function getZones() {
		$zones = array(
			"reject" => array("name" => _("Reject"), "descr" => _("Any incoming network packets are rejected. Note that this zone still accepts RTP traffic, but no other ports are listening by default. You rarely want to use this."), "selectable" => true),
			"external" => array("name" => _("External"), "descr" => _("For interfaces connected to the internet. You do not trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted."), "selectable" => true),
			"other" => array("name" => _("Other"), "descr" => _("For use on trusted external networks, or other well known networks (such as a DMZ, or OpenVPN network). You mostly trust the other computers on the networks to not harm your computer."), "selectable" => true),
			"internal" => array("name" => _("Internal"), "descr" => _("For use on internal networks. You mostly trust the other computers on the networks to not harm your computer."), "selectable" => true),
			"trusted" => array("name" => _("Trusted"), "descr" => _("All network connections are accepted. No firewalling is done on this interface."), "selectable" => false),
		);

		return $zones;
	}
}

