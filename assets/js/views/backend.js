$(document).ready(function() {
	function firewallBackendMigrate(target) {
		var title = _("Migrate the running firewall to native nftables?");
		var detail = _("Zones, networks, services, and Responsive Firewall settings are kept. Supported legacy custom INPUT rules are translated and the firewall restarts briefly.");

		var go = function() {
			var $btn = $("#fw-migrate-nftables");
			$btn.prop('disabled', true).addClass('disabled');
			var old = $btn.text();
			$btn.text(_("Migrating..."));
			$.ajax({
				url: window.FreePBX.ajaxurl,
				type: 'POST',
				timeout: 120000,
				data: { module: 'firewall', command: 'migratebackend', target: target }
			})
			.done(function(data) {
				if (data && data.status) {
					fpbxToast(data.message || _("Firewall engine updated."), '', 'success');
					window.location.reload();
					return;
				}
				fpbxToast((data && data.message) ? data.message : _("Migration failed."), '', 'error');
				$btn.prop('disabled', false).removeClass('disabled').text(old);
			})
			.fail(function() {
				fpbxToast(_("Migration failed. Check firewall.log and try again."), '', 'error');
				$btn.prop('disabled', false).removeClass('disabled').text(old);
			});
		};

		if (typeof fpbxConfirm === 'function') {
			fpbxConfirm(title + " " + detail, _("Yes"), _("No"), go);
		} else if (window.confirm(title + "\n\n" + detail)) {
			go();
		}
	}

	$("#fw-migrate-nftables").on('click', function(e) {
		e.preventDefault();
		firewallBackendMigrate('nftables');
	});
});
