<?php
// vim: set ai ts=4 sw=4 ft=php:
namespace FreePBX\modules\Firewall;

class Zones {

	public function getZones() {
		$zones = array(
			"external" => array("name" => _("Internet"), "summary" => _("Default Firewall"), "descr" => _("This interface receives traffic from the Internet. Only selected incoming connections are accepted."), "selectable" => true),
			"internal" => array("name" => _("Local"), "summary" => _("Local trusted traffic"), "descr" => _("For use on internal networks. You mostly trust the other computers on the networks to not harm your computer."), "selectable" => true),
			"other" => array("name" => _("Other"), "summary" => _("Other Traffic"), "descr" => _("For use on trusted external networks, or other well known networks (such as a DMZ, or OpenVPN network). You mostly trust the other computers on the networks to not harm your computer."), "selectable" => true),
			"reject" => array("name" => _("Reject"), "summary" => _("Reject incoming traffic"), "descr" => _("Any incoming network packets are rejected. Note that this zone still accepts RTP traffic, but no other ports are listening by default. You rarely want to use this."), "selectable" => true),
			"trusted" => array("name" => _("Trusted"), "summary" => _("Excluded from Firewall"), "descr" => _("All network connections are accepted. No firewalling is done on this interface."), "selectable" => false),
		);

		return $zones;
	}
}

