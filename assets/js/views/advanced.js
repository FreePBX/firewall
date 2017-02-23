$(document).ready(function() { 
	// Add RFC1918 addresses
	$("#addrfc").click(function(e) { advancedAdd('addrfc', e.target); });

	// Add 'this host'
	$("#addhost").click(function(e) { advancedAdd('addthishost', e.target); });

	// Update address bar when someone changes tabs
	$("a[data-toggle='tab']").on('shown.bs.tab', function(e) { 
		var newuri = updateQuery("tab", e.target.getAttribute('aria-controls'));
		window.history.replaceState(null, document.title, newuri);
	});

	// Advanced Settings Page
	$(".advsetting").on("click", advanced_button_click);

});

function advancedAdd(cmd, target) {
	$(target).text(_("Updating...")).prop('disabled', true);
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: { command: cmd, module: 'firewall' },
		complete: function(data) { 
			$(target).text(_("Added"));
		}
	});
}

function advanced_button_click(e) {
	var t = e.currentTarget;
	var setting = t.getAttribute('name');
	// Set them to disabled while we ajax
	$(".advsetting[name='"+setting+"']").attr('disabled', true);
	$.ajax({
		url: window.FreePBX.ajaxurl,
		data: { command: "updateadvanced", module: 'firewall', option: setting, val: $(t).val() },
		complete: function() { 
			$(".advsetting[name='"+setting+"']").attr('disabled', false);
		}
	});
}

