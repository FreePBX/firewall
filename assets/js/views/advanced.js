$(document).ready(function() { 
	// Add RFC1918 addresses
	$("#addrfc").click(function(e) { advancedAdd('addrfc', e.target); });

	// Add 'this host'
	$("#addhost").click(function(e) { advancedAdd('addthishost', e.target); });

	// Add 'this network'
	$("#addnetwork").click(function(e) { advancedAdd('addthisnetwork', e.target); });

	// Update address bar when someone changes tabs
	$("a[data-toggle='tab']").on('shown.bs.tab', function(e) { 
		// New target. Don't need jquery here...
		var newuri = updateQuery("tab", e.target.getAttribute('aria-controls'));
		window.history.replaceState(null, document.title, newuri);
	});

	$(".rfw").click(function(e) { updateRfw(e.target) });
	$(".safemode").click(function(e) { updateSafemode(e.target) });
	$(".rejmode").click(function(e) { updateRejectmode(e.target) });
});

function updateRfw(target) {
	var d = { command: 'updaterfw', module: 'firewall', proto: target.getAttribute('name'), value: target.getAttribute('value') };
	$("input[name="+target.getAttribute('name')+"]").prop('disabled', true);
	$.ajax({
		url: window.ajaxurl,
		data: d,
		complete: function(data) { 
			window.location.href = window.location.href;
		}
	});
}

function updateSafemode(target) {
	var d = { command: 'setsafemode', module: 'firewall', value: target.getAttribute('value') };
	var n = target.getAttribute('name');
	$("input[name="+n+"]").prop('disabled', true);
	$.ajax({
		url: window.ajaxurl,
		data: d,
		success: function(data) {
			if (typeof data.message !== "undefined") {
				if (data.message == "enabled") {
					$("#safewarning").slideDown();
				} else {
					$("#safewarning").slideUp();
				}
			}
			$("input[name="+n+"]").prop('disabled', false);
		},
	});
}

function updateRejectmode(target) {
	var d = { command: 'setrejectmode', module: 'firewall', value: target.getAttribute('value') };
	var n = target.getAttribute('name');
	$("input[name="+n+"]").prop('disabled', true);
	$.ajax({
		url: window.ajaxurl,
		data: d,
		success: function(data) {
			$("input[name="+n+"]").prop('disabled', false);
		},
	});
}

function advancedAdd(cmd, target) {
	$(target).text("Updating...").prop('disabled', true);
	$.ajax({
		url: window.ajaxurl,
		data: { command: cmd, module: 'firewall' },
		complete: function(data) { 
			$(target).text("Added");
		}
	});
}

function updateQuery(key, value) {
	var re = new RegExp("([?&])" + key + "=.*?(&|#|$)(.*)", "gi"), hash;
	var url = window.location.href;

	if (re.test(url)) {
		if (typeof value !== 'undefined' && value !== null) {
			return url.replace(re, '$1' + key + "=" + value + '$2$3');
		} else {
			hash = url.split('#');
			url = hash[0].replace(re, '$1$3').replace(/(&|\?)$/, '');
			if (typeof hash[1] !== 'undefined' && hash[1] !== null) {
				url += '#' + hash[1];
			}
			return url;
		}
	} else {
		if (typeof value !== 'undefined' && value !== null) {
			var separator = url.indexOf('?') !== -1 ? '&' : '?';
			hash = url.split('#');
			url = hash[0] + separator + key + '=' + value;
			if (typeof hash[1] !== 'undefined' && hash[1] !== null) 
				url += '#' + hash[1];
			return url;
		} else {
			return url;
		}
	}
}

