function delay(fn, ms) {
	let timer = 0
	return function(...args) {
		clearTimeout(timer)
		timer = setTimeout(fn.bind(this, ...args), ms || 0)
	}
}

$(document).ready(function(){
    
	$(window).resize(function() {
		log_view_resize();
    });

	$('#btn_refresh_log').click(function(){
		get_lines();
	});

	$('#btn_clean_log').click(function(){
		clean_log();
	});

	$('#highlight_in_log').keyup(delay(function (e) {
		highlight_in_log();
	}, 500));

	$('#btn_highlight_in_log').click(function(){
		highlight_in_log();
	});

	$("#box_highlight input[name='highlight_show_mode']:radio").change(function () {	 
		highlight_in_log();
	});

	log_view_resize();
	get_lines();
});

function log_view_resize(){
	//TODO: It would be good if this works if the offset.top of #logfiles_navbar changed, but jquery does not
	//		detect the offset change, you would have to create a timer that would monitor the offset every x time.

	$('#log_view.pre').css('max-height',($(window).height() - $('#footer').height() - $('#logfiles_navbar').height() - $('#logfiles_navbar').offset().top));
}

function highlight_in_log() {
	var find_txt = null;
	var find_count = null;
	var show_result = null;

	disabled_controls(true);

	// clear old searches
	$("#highlight-results").html( _("Searching...") );
	$("#log_view").find('span.highlightLog').each(function() {
		$(this).after($(this).html());
		$(this).remove();
	});

	// select new search
	find_txt = $('#highlight_in_log').val();

	if (find_txt !== "") {
		$("#log_view div.line").find('span').each(function() {
			var regex = new RegExp(find_txt.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&'), 'gi');
			var newline = $(this).html().replace(regex, function(e) { return sprintf('<span class="highlightLog">%s</span>', e); });
			$(this).html( newline );
		});
		find_count = $("#log_view").find('span.highlightLog').length;

		// get value show mode result
		$("#box_highlight input[name='highlight_show_mode']:radio").each(function() {
			if ($(this).is(':checked')) {
				show_result = $(this).val();
			}
		});

	} else {
		find_count = _("···");
		show_result = "all";
	}

	if (show_result == "all") {
		$("#log_view").find('div.line').show();
	} else {
		$("#log_view").find('div.line').each(function() {
			var showline = false;
			$('span.highlightLog', $(this)).each(function() {
				showline = true;
			});
			if (showline == false) {
				$(this).hide();
			} else {
				$(this).show();
			}
		});
	}

	$("#highlight-results").html( find_count );

	disabled_controls(false);
}

function get_lines() {
	disabled_controls(true);
	$('#log_view').html(_("Loading..."));

	$.post(window.FreePBX.ajaxurl, { 'module': 'firewall',  'command': 'read_logs'}, function(data){
		var strValue = '';
		//We will reverse order of records so that the last events are at the beginning.
		data.forEach( function( line ) {
		//data.reverse().forEach( function( line ) {
			strValue += line;
		});
		$('#log_view').html(strValue);
	})
	.done(function() {
		fpbxToast(_("Log loading completed successfully."), '', 'success');
	})
	.fail(function() {
		fpbxToast(_("An error occurred while loading the logs!"), '', 'error');
		$('#log_view').html(_("Error!"));
	})
	.always(function() {
		disabled_controls(false);
		highlight_in_log();
	});

}

function clean_log() {
	disabled_controls(true);
	$('#log_view').html(_("Cleaning..."));

	$.post(window.FreePBX.ajaxurl, { 'module': 'firewall',  'command': 'clean_logs'})
	.done(function() {
		fpbxToast(_("Cleaning the log successfully completed."), '', 'success');
		get_lines();
	})
	.fail(function() {
		fpbxToast(_("An error occurred while cleaning the logs!"), '', 'error');
		$('#log_view').html(_("Error!"));
		disabled_controls(false);
	});
}

function disabled_controls(newstatus) {
	$('#btn_refresh_log').prop("disabled", newstatus);
	$('#btn_clean_log').prop("disabled", newstatus);
	$("#box_highlight input[name='highlight_show_mode']:radio").prop("disabled", newstatus);
	$('#btn_highlight_in_log').prop("disabled", newstatus);
}