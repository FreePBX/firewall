<?php
//Namespace should be FreePBX\Console\Command
namespace FreePBX\Console\Command;

//Symfony stuff all needed add these
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class Firewall extends Command {

	private $licensed = false;

	private $bindir = "/var/www/html/admin/modules/sysadmin/bin";

	// This is the fwconsole __construct equivalent
	protected function configure(){
		$this->setName('firewall')
			->setDescription(_('Firewall functions'))
			->addOption('force', 'f', InputOption::VALUE_NONE, _('Force Add/Removal of entry'))
			->addOption('help', 'h', InputOption::VALUE_NONE, _('Show help'))
			->addArgument('cmd', InputArgument::REQUIRED, _('Command to run (see --help)'))
			->addArgument('opt', InputArgument::OPTIONAL, _('Optional parameter'))
			->addArgument('ids', InputArgument::OPTIONAL|InputArgument::IS_ARRAY, _('IDs to add or remove from a zone'))
			->setHelp($this->showHelp());
	}

	// We've been called
	protected function execute(InputInterface $input, OutputInterface $output){
		$cmd = $input->getArgument('cmd');
		switch ($cmd) {
		case "stop":
			return $this->stopFirewall($output);
		case "start":
			return $this->startFirewall($output);
		case "disable":
			$this->disableFirewall($output);
			return $this->stopFirewall($output);
		case "trust":
			return $this->trustEntry($output, $input->getArgument('opt'));
		case "untrust":
			return $this->untrustEntry($output, $input->getArgument('opt'));
		case "list":
			return $this->listZone($output, $input->getArgument('opt'));
		case "add":
			foreach ($input->getArgument('ids') as $id) {
				$this->addToZone($output, $input->getArgument('opt'), $id);
			}
			return true;
		case "del":
			foreach ($input->getArgument('ids') as $id) {
				$this->removeFromZone($output, $input->getArgument('opt'), $id);
			}
			return true;
		default:
			$output->writeln($this->showHelp());
		}
	}

	private function showHelp() {
		$help = "Valid Commands:\n";
		$commands = array(
			"disable" => _("Disable the System Firewall. This will shut it down cleanly."),
			"stop" => _("Stop the System Firewall"),
			"start" => _("Start (and enable, if disabled) the System Firewall"),
			"trust" => _("Add the hostname or IP specified to the Trusted Zone"),
			"untrust" => _("Remove the hostname or IP specified from the Trusted Zone"),
			"list [zone]" => _("List all entries in zone 'zone'"),
			"add [zone] [id id id..]" => _("Add to 'zone' the IDs provided."),
			"del [zone] [id id id..]" => _("Delete from 'zone' the IDs provided."),
			// TODO: "flush [zone]" => _("Delete ALL entries from zone 'zone'."),

		);
		foreach ($commands as $o => $t) {
			$help .= "<info>$o</info> : <comment>$t</comment>\n";
		}

		$help .= _("When adding or deleting from a zone, one or many IDs may be provided.")."\n";
		$help .= _("These may be IP addresses, hostnames, or networks.")."\n";
		$help .= _("For example:")."\n\n";
		$help .="<comment>fwconsole firewall add trusted 10.46.80.0/24 hostname.example.com 1.2.3.4</comment>\n";

		return $help;
	}

	private function disableFirewall($output) {
		$fw = \FreePBX::Firewall();
		if (!$fw->isEnabled()) {
			$output->writeln("<error>"._("Firewall is not enabled, can't disable it")."</error>");
		}
		$fw->setConfig("status", false);
	}

	private function startFirewall($output) {
		$fw = \FreePBX::Firewall();
		if (!$fw->isEnabled()) {
			$output->writeln("<error>"._("Enabling Firewall.")."</error>");
			$fw->setConfig("status", true);
		}
		return $fw->startFirewall();
	}

	private function stopFirewall() {
		$fw = \FreePBX::Firewall();
		$fw->stopFirewall();
	}

	private function trustEntry($output, $param) {
		$this->addToZone($output, "trusted", $param);
	}

	private function addToZone($output, $zone, $param) {
		$fw = \FreePBX::Firewall();
		$so = $fw->getSmartObj();

		switch ($zone) {
		case "trusted":
		case "other":
		case "internal":
		case "external":
			break;
		case 'blacklist':
			// If it's adding to blacklist, let the firewall object do it
			$output->write("<info>".sprintf(_("Attempting to add '%s' to Blacklist ... "), "</info>$param<info>")."</info>");
			$fw->addToBlacklist($param);
			$output->writeln("<info>"._("Success!")."</info>");
			return;
		default:
			$output->writeln("<error>".sprintf(_("Error: Can't add '%s' to unknown zone '%s'"), $param, $zone)."</error>");
			return;
		}

		// Is this an IP address? If it matches an IP address, then it doesn't have a
		// subnet. Add one, depending on what it is.
		if (filter_var($param, \FILTER_VALIDATE_IP)) {
			// Is this an IPv4 address? Add /32
			if (filter_var($param, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4)) {
				$param = "$param/32";
			} else {
				// It's IPv6. 
				$param = "$param/128";
			}
		}

		$output->write("<info>".sprintf(_("Attempting to add '%s' to Zone '%s' ... "), "</info>$param<info>", "</info>$zone<info>")."</info>");

		// Is this a network? If it has a slash, assume it does.
		if (strpos($param, "/") !== false) {
			$trust = $so->returnCidr($param);
		} else {
			$trust = $so->lookup($param);
		}

		// If it's false, or empty, we couldn't add it.
		if (!$trust) {
			$output->writeln("<error>"._("Failed! Could not validate entry. Please try again.")."</error>");
			return;
		}
		$nets = $fw->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}

		$nets[$param] = $zone;
		$fw->setConfig("networkmaps", $nets);
		$output->writeln("<info>"._("Success!")."</info>");
	}

	private function untrustEntry($output, $param) {
		return $this->removeFromZone($output, "trusted", $param);
	}

	private function removeFromZone($output, $zone, $param) {
		$fw = \FreePBX::Firewall();
		$so = $fw->getSmartObj();

		switch ($zone) {
		case "trusted":
		case "other":
		case "internal":
		case "external":
			break;
		case "blacklist":
			throw new \Exception("No blacklist");
		}

		$output->write("<info>".sprintf(_("Attempting to remove %s from '%s' Zone ... "), "</info>$param<info>", "</info>$zone<info>")."</info>");
		$nets = $fw->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}
		if (!isset($nets[$param])) {
			$output->writeln("<error>"._("Unknown entry!")."</error>");
			return;
		}
		unset($nets[$param]);
		$fw->setConfig("networkmaps", $nets);
		$output->writeln("<info>"._("Success!")."</info>");
	}

	private function listZone($output, $param) {
		switch ($param) {
		case 'trusted':
		case 'internal':
		case 'external':
		case 'other':
			$fw = \FreePBX::Firewall();
			$nets = $fw->getConfig("networkmaps");
			$output->writeln("<info>".sprintf(_("All entries in zone '%s':"), $param)."</info>");
			foreach ($nets as $n => $z) {
				if ($z === $param) {
					$output->writeln("\t$n");
				}
			}
			return true;
		case 'blacklist':
			$bl = \FreePBX::Firewall()->getBlacklist();
			$output->writeln("<info>"._("All blacklisted entries.")."</info>");
			$output->writeln("<error>"._("Important!")."</error> "._("A blacklisted entry will be overridden by a defined zone entry!"));
			foreach ($bl as $id => $res) {
				if ($res) {
					$output->writeln("\t".sprintf("%s: (Resolves to %s)", $id, implode(",", $res)));
				} else {
					$output->writeln("\t$id");
				}
			}
		}
	}
}
