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
		);
		foreach ($commands as $o => $t) {
			$help .= "<info>$o</info> : <comment>$t</comment>\n";
		}

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

		$fw = \FreePBX::Firewall();
		$so = $fw->getSmartObj();

		$output->writeln("<info>".sprintf(_("Attempting to add %s to Trusted Zone"), "</info>$param<info>")."</info>");

		// Is this a network? If it has a slash, assume it does.
		if (strpos($param, "/") !== false) {
			$trust = $so->returnCidr($param);
		} else {
			$trust = $so->lookup($param);
		}

		// If it's false, or empty, we couldn't add it.
		if (!$trust) {
			$output->writeln("<error>"._("Could not validate entry. Please try again.")."</error>");
		}
		$nets = $fw->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}
		$nets[$param] = "trusted";
		$fw->setConfig("networkmaps", $nets);
		$output->writeln("<info>"._("Success. Entry added to Trusted Zone.")."</info>");
	}

	private function untrustEntry($output, $param) {
		$output->writeln("<info>".sprintf(_("Attempting to remove %s from Trusted Zone"), "</info>$param<info>")."</info>");
		$fw = \FreePBX::Firewall();
		$nets = $fw->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}
		if (!isset($nets[$param])) {
			$output->writeln("<error>"._("That is not currently trusted. Please try again.")."</error>");
			exit(1);
		}
		unset($nets[$param]);
		$fw->setConfig("networkmaps", $nets);
		$output->writeln("<info>"._("Success. Entry removed from Trusted Zone.")."</info>");
	}
}
