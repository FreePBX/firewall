<?php
$status = $fw->getFirewallRuntimeStatus();
$driver = isset($status['resolved_driver']) ? $status['resolved_driver'] : 'Unavailable';
$usingNft = strcasecmp($driver, 'Nftables') === 0;
$nftok = !empty($status['nft_available']);
?>
<script type="text/javascript" src="modules/firewall/assets/js/views/backend.js"></script>
<div class="panel panel-default">
	<div class="panel-heading"><strong><?php echo _('Firewall Engine'); ?></strong></div>
	<div class="panel-body">
		<p>
			<?php echo _("FreePBX 18 applies firewall policy with native <strong>nftables</strong>. Older iptables-era backups and custom INPUT rules remain supported as migration input; iptables is not a runtime engine."); ?>
		</p>
		<p><?php echo _('Current engine:'); ?>
			<span class="label <?php echo $usingNft ? 'label-success' : 'label-warning'; ?>">
				<?php echo $usingNft ? _('nftables') : _('migration required'); ?>
			</span>
		</p>
<?php if (!$nftok) { ?>
		<div class="alert alert-danger">
			<?php echo _("nftables is not installed on this host, so the FreePBX firewall cannot start. Install the <code>nftables</code> package to continue."); ?>
		</div>
<?php } elseif (!$usingNft) { ?>
		<p><?php echo _("Legacy firewall state was detected. Click once to migrate: policy is kept, supported custom INPUT rules are translated, and live rules are rebuilt with native nftables."); ?></p>
		<button type="button" class="btn btn-primary" id="fw-migrate-nftables">
			<?php echo _('Migrate to nftables'); ?>
		</button>
<?php } ?>
	</div>
</div>
<?php
$status = $fw->getFirewallRuntimeStatus();
$driver = isset($status['resolved_driver']) ? $status['resolved_driver'] : 'Unavailable';
$nftok = !empty($status['nft_available']);
$usingNft = (strcasecmp($driver, 'Nftables') === 0);
$engineLabel = $usingNft ? _('nftables') : _('migration required');
?>
<div class='well firewall-backend-panel' id='firewall-backend-panel'>
	<h4><?php echo _("Firewall Engine"); ?></h4>
	<p><?php echo _("FreePBX 18 applies firewall policy with native <strong>nftables</strong>. Older iptables-era backups and custom INPUT rules remain supported as migration input; iptables is not a runtime engine."); ?></p>
	<div class='row form-horizontal clearfix'>
		<div class='col-sm-4'>
			<label class='control-label'><?php echo _("Current engine"); ?></label>
		</div>
		<div class='col-sm-8'>
			<span class='firewall-engine-badge <?php echo $usingNft ? 'nft' : 'ipt'; ?>' id='firewall-engine-badge'>
				<?php echo htmlspecialchars($engineLabel, ENT_QUOTES, 'UTF-8'); ?>
			</span>
			<span class='text-muted' id='firewall-engine-driver'>
				<?php echo htmlspecialchars(sprintf(_('driver: %s'), $driver), ENT_QUOTES, 'UTF-8'); ?>
			</span>
		</div>
	</div>
<?php if ($usingNft) { ?>
	<div class='alert alert-success firewall-backend-msg'>
		<?php echo _("This system is using <strong>nftables</strong>. Your existing policy (zones, networks, services) is applied with native nft sets and rate meters."); ?>
	</div>
<?php } elseif ($nftok) { ?>
	<div class='alert alert-info firewall-backend-msg'>
		<?php echo _("Legacy firewall state was detected. Click once to migrate: policy is kept, supported custom INPUT rules are translated, and live rules are rebuilt with native nftables."); ?>
	</div>
	<p>
		<button type='button' class='btn btn-primary' id='fw-migrate-nftables'>
			<?php echo _("Migrate to nftables"); ?>
		</button>
	</p>
<?php } else { ?>
	<div class='alert alert-warning firewall-backend-msg'>
		<?php echo _("nftables is not installed on this host, so the FreePBX firewall cannot start. Install the <code>nftables</code> package to continue."); ?>
	</div>
<?php } ?>
</div>
