$(document).ready(function() {
	// When someone changes a network select tab, update the attr to change the bg colour.
	$("#networkstable").on("change", "select", function(e, v) {
		// Set the parent div to be the val.
		var o = $(e.target);
		var parent = $("#netcount-"+o.data('rowid'));
		if (parent.length === 0) {
			// That shouldn't happen
			return;
		}
		parent.attr('zone', o.val());
		$("#description-"+o.data('rowid')).attr('zone', o.val());
	});
});


