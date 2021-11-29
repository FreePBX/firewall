<?php
//Namespace should be FreePBX\Console\Command
namespace FreePBX\Console\Command;

//Symfony stuff all needed add these
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Helper\ProgressBar;
use Symfony\Component\Console\Helper\Table;

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
		case "restart":
			$this->disableFirewall($output);
			$this->stopFirewall($output);
			return $this->startFirewall($output);
		case "lerules":
			return $this->lerules($output, $input->getArgument('opt'));
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
			$ids = $input->getArgument('ids');
			if (!$ids) {
				$output->writeln('<error>'._("Error!").'</error> '._("No network identifiers supplied"));
				return;
			}
			foreach ($ids as $id) {
				$this->addToZone($output, $input->getArgument('opt'), $id);
			}
			return true;
		case "del":
			$ids = $input->getArgument('ids');
			if (!$ids) {
				$output->writeln('<error>'._("Error!").'</error> '._("No network identifiers supplied"));
				return;
			}
			foreach ($ids as $id) {
				$this->removeFromZone($output, $input->getArgument('opt'), $id);
			}
			return true;
		case "sync":
			return $this->scan($output);
		case "f2bs":
		case "f2bstatus":
			return $this->f2bstatus($output);
		case "fix_custom_rules":
			return $this->customRulesFix($output);
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
			"restart" => _("Restart the System Firewall"),
			"lerules [enable] or [disable]" => _("Enable or disable Lets Encrypt rules."),
			"trust" => _("Add the hostname or IP specified to the Trusted Zone"),
			"untrust" => _("Remove the hostname or IP specified from the Trusted Zone"),
			"list [zone]" => _("List all entries in zone 'zone'"),
			"add [zone] [id id id..]" => _("Add to 'zone' the IDs provided."),
			"del [zone] [id id id..]" => _("Delete from 'zone' the IDs provided."),
			// TODO: "flush [zone]" => _("Delete ALL entries from zone 'zone'."),
			"fix_custom_rules" => _("Create the files for the custom rules if they don't exist and set the permissions and owners correctly."),
			"sync" => _("Synchronizes all selected zones of the firewall module with the intrusion detection whitelist."),
			"f2bstatus or f2bs" => _("Display ignored and banned IPs. (Only root user).")
		);
		foreach ($commands as $o => $t) {
			$help .= "<info>$o</info> : <comment>$t</comment>\n";
		}

		$help .= "\n";
		$help .= _("When adding or deleting from a zone, one or many IDs may be provided.")."\n";
		$help .= _("These may be IP addresses, hostnames, or networks.")."\n";
		$help .= _("For example:")."\n\n";
		$help .="<comment>fwconsole firewall add trusted 10.46.80.0/24 hostname.example.com 1.2.3.4</comment>\n";

		return $help;
	}

	public function f2bstatus($output){
		if(get_current_user() != "root"){
			$table 	= new \Symfony\Component\Console\Helper\Table($output);
			$fw 	= \FreePBX::Firewall();
			$as		= $fw->getAdvancedSettings();	
			$sa 	= $fw->sysadmin_info();
			if(empty($sa)){
				$output->writeln("<error>Sysadmin not installed or not enabled.</error>");
				exit(1);
			}
			if($as["id_sync_fw"] == "legacy"){
				$output->writeln("<error>You are not allowed to execute this command on Legacy mode.</error>");
				exit(1);
			}

			$FC     = fpbx_which("fail2ban-client");
			$cmd    = "$FC status | grep 'Jail list' | sed -r 's/.+Jail list:\t+//g' | sed -e 's/ *//g' -e 's/\,/\\n/g'";
			exec($cmd, $out, $ret);
			if($ret === 0 && is_array($out)){
				$output->writeln("");
				$output->writeln("-=[ List of ignored IPs for each dynamic jail ]=-");
				$output->writeln("");
				$table->setHeaders($out);
				$result = [];
				foreach($out as $jail){			
					$result[] = str_replace(array("These IP addresses/networks are ignored:\n", "`- ", "|- "),"", shell_exec("$FC get $jail ignoreip"));
				}
				$rows[] = $result;
				$table->setRows($rows);
				$table->render();

				/**
				 * Banned List
				 */
				unset($rows);
				unset($result);
				$output->writeln("");
				$IDsetting	= \FreePBX::Sysadmin()->getIntrusionDetection();
				$rows = [];
				if(count($IDsetting["banned"]) >= 1){
					$output->writeln("-=[ List of banned IPs ]=-");
					$output->writeln("");					
					$table->setHeaders(array("Type", "IPs"));
					foreach($IDsetting["banned"] as $line){
						$_ip = explode(" ",$line);
						preg_match_all('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/m', $_ip[0], $matches, PREG_SET_ORDER, 0);
						$rows[] = array(!empty($_ip[1]) ? $_ip[1] : _('Unknown'), trim($matches[0][0]));
					}
					$table->setRows($rows);
					$table->render();			
				}
				else{
					$output->writeln("<info>No banned IP right now.</info>");
					$output->writeln("");
				}
			}					
		}
		else{
			$output->writeln("<error>Permission denied. Please run this command as root.</error>");
		}
	}

	public function scan($output){	
		$fw 		= \FreePBX::Firewall();
		$sa 		= $fw->sysadmin_info();
		$progressBar= new ProgressBar($output, 30);

		if(!empty($sa)){
			$as			= $fw->getAdvancedSettings();

			// need to get F2B and firewall status like this way when this one is launch through cron job.
			$out 		= shell_exec("pgrep -f fail2ban-server");
			$voipd 		= shell_exec("pgrep -f voipfirewalld");
			$fwstatus 	= $fw->getConfig("status");
			if(empty($voipd) || empty($fwstatus)){
				dbug("The Firewall is not started. Syncing Process canceled.");
				$output->writeln("<error>"._("The Firewall is not started. Syncing Process canceled.")."</error>");
				exit();
			}

			$flush = $fw->flush_fail2ban_whitelist($as["id_sync_fw"]);
			if($flush != "ok"){
				$output->writeln($flush);
				$time = 0;
				while($time++ < 30){
					// Let's wait a new process before syncing.
					$out2 = shell_exec("pgrep -f fail2ban-server"); 
					$progressBar->advance();
					if($out != $out2){
						if($out2 == $out3){
							break;
						}
					}
					sleep(1);
					$out3 = shell_exec("pgrep -f fail2ban-server"); 
				}
				$progressBar->finish();
				$output->writeln("");
			}			
			
			if (!empty($out) && trim($as["id_sync_fw"]) != "legacy"){
				$syncing = $fw->getConfig("syncing");
				if(empty($syncing)){
					$fw->setConfig("syncing", "no");
					$syncing = $fw->getConfig("syncing");
				}

				if($syncing == "no"){
					$fw->setConfig("syncing", strtotime("now"));
					$output->writeln("<info>"._("Syncing....")."</info>");
					$fw->updateWhitelist($fw->getipzone("all"));					
				}
				else{
					$ptime=(strtotime("now") - $syncing);
					switch($ptime){
						case ($ptime < 250):
							$msg = "<info>"._("Syncing cannot be performed because another synchronization is still in progress.")."</info>";
							break;
						case ($ptime >= 550):
							$msg = "<info>"._("synchronization overlap. Canceling this action for now.")."</info>";
							break;
						case ($ptime >= 850):
							/**
							 * We protect the case for the key"syncing" where it will not be updated for any reason
							 * and force the value to "no" for allowing another synchronization.
							 * Otherwise, the risk will be to lock the syncing for ever.
							 * For resume, the unlocling will be done in about 15mn.
							 */
							$msg = "<info>".sprintf(_("Syncing takes a long time. No news for %d seconds. Unlocking syncing. Please check logs."), $ptime)."</info>";
							$fw->setConfig("syncing", "no");
							break;
					}
					$output->writeln($msg);					
				}
			}
			elseif($as["id_sync_fw"] == "legacy"){
				$output->writeln("<error>"._("Syncing cannot be performed because the Intrusion Detection Sync Firewall setting is set to Legacy mode.")."</error>");
			}
		}
		else{
			$output->writeln("<error>"._("Intrusion Detection is available for all activated systems only.")."</error>");
		}
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
			touch("/etc/asterisk/firewall.enabled");
			chown("/etc/asterisk/firewall.enabled", "asterisk");
		}
		return $fw->startFirewall();
	}

	private function stopFirewall() {
		$fw = \FreePBX::Firewall();
		$fw->stopFirewall();
	}
	
	private function lerules($output, $param) {
		if(empty($param)){
			$output->writeln("<error>"._("Error: Missing argument. Expected 'enable' or 'disable'.")."</error>");
			return;
		}

		switch ($param){
			case "enable":
				$fw = \FreePBX::Firewall();
				$as = $fw->getAdvancedSettings();
				if(!empty($as['lefilter']) && $as['lefilter'] == "disabled"){
					$res = $fw->setAdvancedSetting('lefilter', 'enabled');
					if(!empty($res['lefilter']) && $res['lefilter'] == 'enabled'){
						$output->writeln("<info>"._("Lets Encrypt rules enabled successfully.")."</info>");
					}
					else{
						$output->writeln("<error>"._("An error has occurred!")."</error>");
					}					
				}
				else{
					$output->writeln("<info>"._("Lets Encrypt rules already enabled. Nothing to do")."</info>");
				}
				break;
			case "disable" :
				$fw = \FreePBX::Firewall();
				$as = $fw->getAdvancedSettings();
				if(!empty($as['lefilter']) && $as['lefilter'] == "enabled"){
					$res = $fw->setAdvancedSetting('lefilter', 'disabled');
					if(!empty($res['lefilter']) && $res['lefilter'] == 'disabled'){
						$output->writeln("<info>"._("Lets Encrypt rules disabled successfully.")."</info>");
					}
					else{
						$output->writeln("<error>"._("An error has occurred!")."</error>");
					}				
				}
				else{
					$output->writeln("<info>"._("Lets Encrypt rules already disabled. Nothing to do.")."</info>");
				}
				break;
			default:
				$output->writeln("<error>".sprintf(_("Error: Unknown option '%s'. Expected 'enable or 'disable'."), $param)."</error>");
		}
		return;
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
		$params = array($zone => array("$param"));
		$fw->runHook('addnetwork', $params);
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
			// Does this host exist in the blacklist?
			if (!$fw->getConfig($param, "blacklist")) {
				$output->writeln("<error>"._("Error:")."</error> <info>".sprintf(_("Host '%s' is not currently in the blacklist."), "</info>$param<info>")."</info>");
				return false;
			}
			$fw->removeFromBlacklist($param);
			$output->writeln("<info>".sprintf(_("Removed %s from Blacklist."), "</info>$param<info>")."</info>");
			return;
		}

		$output->write("<info>".sprintf(_("Attempting to remove %s from '%s' Zone ... "), "</info>$param<info>", "</info>$zone<info>")."</info>");
		$nets = $fw->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}

		if (!isset($nets[$param])) {
			// It doesn't exist. Is this an IP address? If it matches an IP address,
			// and it doesn't have a subnet, add one and try again.
			if (filter_var($param, \FILTER_VALIDATE_IP)) {
				// Is this an IPv4 address? Add /32
				if (filter_var($param, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV4)) {
					$param = "$param/32";
				} else {
					// It's IPv6. 
					$param = "$param/128";
				}

				// Now does it exist?
				if (!isset($nets[$param])) {
					// No.
					$output->writeln("<error>"._("Unknown entry!")."</error>");
					return;
				}
			}
		}
		unset($nets[$param]);
		$fw->setConfig("networkmaps", $nets);
		$fw->runHook("removenetwork", array("network" => $param, "zone" => $zone));
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
			foreach ($bl as $id => $res) {
				if ($res) {
					$output->writeln("\t".sprintf("%s: (Resolves to %s)", $id, implode(",", $res)));
				} else {
					$output->writeln("\t$id");
				}
			}
		}
	}

	private function customRulesFix($output) {
		$fw = \FreePBX::Firewall();
		$log = array();
		// We pass the array $log as a reference to get the events. 
		// The data in $log will not overwrite, the new events will be added to the array.
		$return_fix = $fw->fix_custom_rules_files($log);
		if ( (! empty($log) ) && ( is_array($log) ) ) {
			foreach ($log as $log_line) {
				$output->writeln($log_line);
			}
		}
		return $return_fix;
	}
}
