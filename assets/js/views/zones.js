$(document).ready(function() { 
	// Register buttons being clicked
	$(".fwbutton").click(function(e) { e.preventDefault(); isClicked(this); });

	// When someone changes a zone mapping
	$(".intbutton").click(function(e) { e.preventDefault(); changeInt(this); });

	// When someone clicks on a blacklist button
	$('.blbutton').click(function(e) { e.preventDefault(); changeBlacklist(this); });

	// Update address bar when someone changes tabs
	$("a[data-toggle='tab']").on('shown.bs.tab', function(e) { 
		// New target. Don't need jquery here...
		var newuri = updateQuery("tab", e.target.getAttribute('aria-controls'));
		window.history.replaceState(null, document.title, newuri);
	});

	// When someone changes an interfaces zone
	$(".zoneset>input").click(function(e) {
		// Set ALL the interfaces that share the same parent to be the same.
		var myparent=".p"+$(e.target).data('parent');
		var myval=$(e.target).attr('value');
		$.each($(myparent), function(i, v) {
			if ($(v).attr('value') == myval) {
				$(v).attr('checked', true);
			}
		});
	});
});

function changeInt(o) {

	var iface = o.getAttribute('data-int');
	// Grab the checked interface that was selected.
	var checked = $('input[name="int-'+iface+'"]:checked').attr('value');
	// Show people we're doing stuff
	$(o).prop('disabled', true);

	$.ajax({
		url: window.ajaxurl,
		data: { command: 'updateinterface', module: 'firewall', iface: iface, zone: checked },
		success: function(data) { window.location.href = window.location.href; },
	});
}


function isClicked(o) {
	var counter, action, j;

	// jQuery the button.
	j = $(o);

	// Get the button counter..
	if (!j.data('counter')) {
		console.log("No counter attribue for button", o);
		return;
	}
	if (!j.data('action')) {
		console.log("No action attribue for button", o);
		return;
	}

	counter = j.data('counter');
	action = j.data('action');

	// Now, what do we do?
	switch(action) {
		case 'remove':
			removeNetwork(counter);
		return;
		case 'update':
			updateNetwork(counter);
		return;
		case 'create':
			createNetwork(counter);
		return;
		default:
			console.log("Unknown action");
		return;
	}
}

function opaqueRow(c) {
	$("#element-"+c).find('input,label,button').css({
		opacity: "0.33",
		cursor: "wait",
	}).click(function(e) { e.preventDefault(); });
}

function removeNetwork(c) {
	var net;

	console.log("Removing network "+c);
	opaqueRow(c);

	net = $("input[type=text]", "#element-"+c).val()
	$.ajax({
		url: window.ajaxurl,
		data: { command: 'removenetwork', module: 'firewall', net: net },
		success: function(data) { window.location.href = window.location.href; },
	});

}

function updateNetwork(c) {
	var net, zone;
	console.log("Updating network "+c);
	net = $("input[type=text]", "#element-"+c).val()
	zone = $("input[type=radio]:checked", "#element-"+c).val()
	$.ajax({
		url: window.ajaxurl,
		data: { command: 'updatenetwork', module: 'firewall', net: net, zone: zone },
		success: function(data) { window.location.href = window.location.href; },
	});

	opaqueRow(c);
}

function createNetwork(c) {
	var net, zone;

	console.log("Creating network "+c);
	opaqueRow(c);
	net = $("input[type=text]", "#element-"+c).val()
	zone = $("input[type=radio]:checked", "#element-"+c).val()
	$.ajax({
		url: window.ajaxurl,
		data: { command: 'addnetworktozone', module: 'firewall', net: net, zone: zone },
		success: function(data) { window.location.href = window.location.href; },
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

function changeBlacklist(o) {

	var a = o.getAttribute('data-action');

	var ajaxdata = { module: 'firewall' };

	// What are we being asked about?
	var item = "bl-"+o.getAttribute('data-id');
	ajaxdata.entry = $("input[name="+item+"]").val();
	
	// Are they adding a new one?
	if (a == "create") {
		ajaxdata.command = "addtoblacklist";
	} else {
		ajaxdata.command = "removefromblacklist";
	}

	// Show them we're doing something.
	$(o).prop('disabled', true);

	$.ajax({
		url: window.ajaxurl,
		data: ajaxdata,
		success: function(data) { window.location.href = window.location.href; },
	});
}

