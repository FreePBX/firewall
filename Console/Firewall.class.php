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

class Firewall extends Command {

	private $licensed = false;

	private $bindir = "/var/www/html/admin/modules/sysadmin/bin";

	private $dico = [
		"external" 	=> "external",
		"internet" 	=> "external",
		"local" 	=> "internal",
		"internal"	=> "internal",
		"other" 	=> "other",
		"trusted" 	=> "trusted",
		"reject" 	=> "blacklist",
		"blacklist" => "blacklist",
	];

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
				$output->writeln('<fg=black;bg=red>'._("Error!").'</> '._("No network identifiers supplied"));
				return -1;
			}
			foreach ($ids as $id) {
				$this->addToZone($output, $input->getArgument('opt'), $id);
			}
			return 0;
		case "del":
			$ids = $input->getArgument('ids');
			if (!$ids) {
				$output->writeln('<fg=black;bg=red>'._("Error!").'</> '._("No network identifiers supplied"));
				return -1;
			}
			foreach ($ids as $id) {
				$this->removeFromZone($output, $input->getArgument('opt'), $id);
			}
			return 0;
		case "listzones":
			return $this->listzones($output);
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
		return 0;
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
			"listzones" => _("Show zones that can be used to add and del."),
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

	public function listzones($output){
		$dico = $this->dico;
		$table = new \Symfony\Component\Console\Helper\Table($output);
		foreach($dico as $key => $word){
			$entry[] = [$key, $word];
		}
        $table
            ->setHeaders([_("Zone"), _("Equal")])
            ->setRows($entry)
        ;
		$table->render();
		return 0;
	}
	public function f2bstatus($output){
		if(get_current_user() == "root" || trim(shell_exec("whoami")) == "root"){				
			$table 	= new \Symfony\Component\Console\Helper\Table($output);
			$fw 	= \FreePBX::Firewall();
			$as		= $fw->getAdvancedSettings();	
			$sa 	= $fw->sysadmin_info();
			if(empty($sa)){
				$output->writeln("<fg=black;bg=red>Sysadmin not installed or not enabled.</>");
				exit(1);
			}
			if($as["id_sync_fw"] == "legacy"){
				$output->writeln("<fg=black;bg=red>You are not allowed to execute this command on Legacy mode.</>");
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
					$list = str_replace(array("These IP addresses/networks are ignored:\n", "`- ", "|- "),"", shell_exec("$FC get $jail ignoreip"));
					$_list = explode("\n", $list);
					sort($_list);
					$result[] = implode("\n", $_list);
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
			$output->writeln("<fg=black;bg=red>Permission denied. Please run this command as root.</>");
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
				$output->writeln("<fg=black;bg=red>\e[30m"._("The Firewall is not started. Syncing Process canceled.")."\e[0m</>");
				exit();
			}
			if(empty($out)){
				dbug("Fail2ban is not started. Syncing Process canceled.");
				$output->writeln("<fg=black;bg=red>\e[30m"._("Fail2ban is not started. Syncing Process canceled.")."\e[0m</>");
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
			elseif(!empty($out) && trim($as["id_sync_fw"]) == "legacy"){
				$output->writeln("<fg=black;bg=red>\e[30m"._("Syncing cannot be performed because the Intrusion Detection Sync Firewall setting is set to Legacy mode.")."\e[0m</>");
			}
		}
		else{
			$output->writeln("<fg=black;bg=red>"._("Intrusion Detection is available for all activated systems only.")."</>");
		}
	}

	private function disableFirewall($output) {
		$fw = \FreePBX::Firewall();
		if (!$fw->isEnabled()) {
			$output->writeln("<fg=black;bg=red>"._("Firewall is not enabled, can't disable it")."</>");
		}
		$fw->setConfig("status", false);
	}

	private function startFirewall($output) {
		$fw = \FreePBX::Firewall();
		if (!$fw->isEnabled()) {
			$output->writeln("<fg=black;bg=red>"._("Enabling Firewall.")."</>");
			$fw->setConfig("status", true);
			touch("/etc/asterisk/firewall.enabled");
			chown("/etc/asterisk/firewall.enabled", "asterisk");
		}
		return $fw->startFirewall();
	}

	private function stopFirewall() {
		$fw = \FreePBX::Firewall();
		$fw->stopFirewall();
		return 0;
	}
	
	private function lerules($output, $param) {
		if(empty($param)){
			$output->writeln("<fg=black;bg=red>"._("Error: Missing argument. Expected 'enable' or 'disable'.")."</>");
			return -1;
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
						$output->writeln("<fg=black;bg=red>"._("An error has occurred!")."</>");
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
						$output->writeln("<fg=black;bg=red>"._("An error has occurred!")."</>");
					}				
				}
				else{
					$output->writeln("<info>"._("Lets Encrypt rules already disabled. Nothing to do.")."</info>");
				}
				break;
			default:
				$output->writeln("<fg=black;bg=red>".sprintf(_("Error: Unknown option '%s'. Expected 'enable or 'disable'."), $param)."</>");
		}
		return 0;
	}

	private function trustEntry($output, $param) {
		$this->addToZone($output, "trusted", $param);
		return 0;
	}

	private function addToZone($output, $zone, $param) {
		$fw = \FreePBX::Firewall();
		$so = $fw->getSmartObj();
		$isHost = false;

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

		$res = $so->lookup($param, false);
		$isHost = false;
		if( !empty($res[0]) && $res[0] != $param ){
			$isHost = true;
		}

		$zone = strtolower($zone);
		$Tgui = (!empty($this->dico[$zone])) ? $this->dico[$zone] : "" ;

		if($zone != $Tgui){
			$output->write("<info>".sprintf( _("Zone %s = %s "),$zone, $Tgui)."</info>\n");
			$zone = $Tgui; 
		}
		
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
				$output->writeln("<fg=black;bg=red>".sprintf(_("Error: Can't add '%s' to unknown zone '%s'"), $param, $zone)."</>");
				return;
		}

		$output->write("<info>".sprintf(_("Attempting to add '%s' to Zone '%s' ... "), "</info>$param<info>", "</info>$zone<info>")."</info>");

		// Is this a network? If it has a slash, assume it does.
		if (strpos($param, "/") !== false) {
			$trust = $so->returnCidr($param);
		} else {
			$trust = $so->lookup($param, false);
			$isHost = true;
		}

		// If it's false, or empty, we couldn't add it.
		if (!$trust) {
			$output->writeln("<fg=black;bg=red>"._("Failed! Could not validate entry. Please try again.")."</>");
			return;
		}

		if ($isHost) {
			$hosts = $fw->getConfig("hostmaps");
			if (!is_array($hosts)) {
				$hosts = array();
			}

			$hosts[$param] = $zone;
			$fw->setConfig("hostmaps", $hosts);
			$fw->addHostToZone($param, $zone, $descr);		
		} else {
			$nets = $fw->getConfig("networkmaps");
			if (!is_array($nets)) {
				$nets = array();
			}

			$nets[$param] = $zone;
			$fw->setConfig("networkmaps", $nets);
			$params = array($zone => array("$param"));
			$fw->runHook('addnetwork', $params);
		}		
		
		$output->writeln("<info>"._("Success!")."</info>");
	}

	private function untrustEntry($output, $param) {
		return $this->removeFromZone($output, "trusted", $param);
	}

	private function removeFromZone($output, $zone, $param) {
		$fw = \FreePBX::Firewall();
		$so = $fw->getSmartObj();

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

		$res = $so->lookup($param, false);
		$isHost = false;
		if( !empty($res[0]) && $res[0] != $param ){
			$isHost = true;
		}

		$zone = strtolower($zone);
		$Tgui = (!empty($this->dico[$zone])) ? $this->dico[$zone] : "" ;

		if($zone != $Tgui){
			$output->write("<info>".sprintf( _("Zone %s = %s "),$zone, $Tgui)."</info>\n");
			$zone = $Tgui; 
		}

		switch ($zone) {
			case "trusted":
			case "other":
			case "internal":
			case "external":
				break;
			case "blacklist":
				// Does this host exist in the blacklist?
				if (!$fw->getConfig(str_replace(["/32", "/128"],"", $param), "blacklist")) {
					$output->writeln("<fg=black;bg=red>"._("Error:")."</> <info>".sprintf(_("%s is not currently in the blacklist."), "</info>$param<info>")."</info>");
					return false;
				}
				$fw->removeFromBlacklist(str_replace(["/32", "/128"],"", $param));
				$output->writeln("<info>".sprintf(_("Removed %s from Blacklist."), "</info>$param<info>")."</info>");
				return;
		}

		$what = (empty($hostname)) ? $param : $hostname;
		$output->write("<info>".sprintf(_("Attempting to remove %s from '%s' Zone ... "), "</info>$what<info>", "</info>$zone<info>")."</info>");

		$nets = $fw->getConfig("networkmaps");
		if (!is_array($nets)) {
			$nets = array();
		}	

		if ( !$isHost ) {	
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
						$output->writeln("<fg=black;bg=red>"._("Unknown entry!")."</>");
						return;
					}
				}
			}
			
			unset($nets[$param]);
		} else {
			// This is a hostname.
			$hosts = $fw->getConfig("hostmaps");
			if (!is_array($hosts)) {
				$hosts = array();
			}

			unset($hosts[$param]);
			unset($nets[$param]);
			$fw->setConfig("hostmaps", $hosts);
		}

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
			return 0;
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
		return 0;
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
