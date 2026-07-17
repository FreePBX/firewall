<?php
$status = $fw->getFirewallConfigurationHealth();
$escape = function ($value) {
	return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
};
$storedOk = !empty($status['settings_stored_properly']);
$migrationRequired = !empty($status['migration_required']);
$runtimeOk = empty($status['enabled']) || !empty($status['rules_valid']);
?>
<script type="text/javascript" src="modules/firewall/assets/js/views/backend.js"></script>
<div class='well firewall-backend-panel' id='firewall-backend-panel'>
	<h4><?php echo _("Firewall Engine and Migration Status"); ?></h4>
	<p>
		<?php echo _("FreePBX 18 uses native <strong>nftables</strong>. Legacy iptables data is supported only as migration input and is not a selectable runtime engine."); ?>
	</p>
	<div class='row form-horizontal clearfix'>
		<div class='col-sm-4'>
			<label class='control-label'><?php echo _("Current engine"); ?></label>
		</div>
		<div class='col-sm-8'>
			<span class='label <?php echo !empty($status['nft_available']) ? 'label-success' : 'label-danger'; ?>'>
				<?php echo _("nftables"); ?>
			</span>
			<?php if (empty($status['nft_available'])) { ?>
				<span class='text-danger'><?php echo _("nft executable not found"); ?></span>
			<?php } ?>
		</div>
	</div>

	<div class='row form-horizontal clearfix'>
		<div class='col-sm-4'>
			<label class='control-label'><?php echo _("Migration"); ?></label>
		</div>
		<div class='col-sm-8'>
			<span class='label <?php echo $migrationRequired ? 'label-warning' : 'label-success'; ?>'>
				<?php echo $migrationRequired ? _("Required") : _("Not required"); ?>
			</span>
			<?php if ($migrationRequired) { ?>
				<span>
					<?php echo $escape(sprintf(
						_("Pending: %s"),
						implode(', ', $status['migration_reasons'])
					)); ?>
				</span>
			<?php } ?>
		</div>
	</div>

	<div class='row form-horizontal clearfix'>
		<div class='col-sm-4'>
			<label class='control-label'><?php echo _("Stored settings"); ?></label>
		</div>
		<div class='col-sm-8'>
			<span class='label <?php echo $storedOk ? 'label-success' : 'label-danger'; ?>'>
				<?php echo $storedOk ? _("Valid") : _("Needs attention"); ?>
			</span>
			<span class='text-muted'>
				<?php echo $escape(sprintf(
					_("schema %d/%d, backend %s, custom rules %s"),
					$status['schema'],
					$status['current_schema'],
					$status['backend'] !== '' ? $status['backend'] : _('not set'),
					$status['custom_rules_format'] !== '' ? $status['custom_rules_format'] : _('not set')
				)); ?>
			</span>
		</div>
	</div>

	<div class='row form-horizontal clearfix'>
		<div class='col-sm-4'>
			<label class='control-label'><?php echo _("Live firewall"); ?></label>
		</div>
		<div class='col-sm-8'>
			<span class='label <?php echo $runtimeOk ? 'label-success' : 'label-danger'; ?>'>
				<?php
				if (empty($status['enabled'])) {
					echo _("Disabled");
				} elseif (!empty($status['rules_valid'])) {
					echo _("Running");
				} else {
					echo _("Rules not active");
				}
				?>
			</span>
			<span class='text-muted'>
				<?php
				if (!empty($status['ruleset_queryable'])) {
					echo !empty($status['nft_table_present'])
						? _("inet fpbx table present")
						: _("inet fpbx table missing");
				} else {
					echo !empty($status['daemon_running'])
						? _("firewall daemon running")
						: _("firewall daemon stopped");
				}
				?>
			</span>
		</div>
	</div>

<?php if (!$storedOk) { ?>
	<div class='alert alert-danger firewall-backend-msg'>
		<strong><?php echo _("Stored firewall settings are not consistent:"); ?></strong>
		<ul>
		<?php foreach ($status['settings_issues'] as $issue) { ?>
			<li><?php echo $escape($issue); ?></li>
		<?php } ?>
		</ul>
	</div>
<?php } elseif (!$runtimeOk) { ?>
	<div class='alert alert-danger firewall-backend-msg'>
		<?php echo _("The module is configured for nftables, but the native rules are not active. Migrate if shown above, then restart the firewall and check firewall.log."); ?>
	</div>
<?php } elseif (!$migrationRequired) { ?>
	<div class='alert alert-success firewall-backend-msg'>
		<?php echo _("Configuration is current: native nftables is selected, settings are stored correctly, and no legacy migration is pending."); ?>
	</div>
<?php } ?>

<?php if ($migrationRequired && !empty($status['nft_available'])) { ?>
	<p>
		<button type='button' class='btn btn-primary' id='fw-migrate-nftables'>
			<?php echo _("Migrate to nftables"); ?>
		</button>
	</p>
<?php } ?>
</div>
