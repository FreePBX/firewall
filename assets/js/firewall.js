// Updates the URL with a hash.
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

$("[name='lefilter']").click(function() {
	$( function() {
		$( "#fwreload" ).dialog({
			open: function() { $(".ui-dialog-titlebar-close").hide(); $(".ui-dialog-titlebar").hide();},
			resizable: false,
			modal: true,
		});
	  } );
	  
	window.data_result = 'false';
	window.wait = setInterval(function(){
		$.ajax({
			async: false,
			type: 'POST',
			url: window.FreePBX.ajaxurl,
			data: { command: 'get_status', module: 'firewall'}
		}).success(function(data) {
			window.data_result = data["message"];
			if(window.data_result == 'true'){
				$("#fwreload" ).dialog('close')
				fpbxToast(_('Rules reloaded!'));
				clearInterval(window.wait);
			}
		});
	}, 1000);	
});