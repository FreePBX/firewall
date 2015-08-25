$(document).ready(function() { 
	// This page has three buttons.
	// 1. Reset button is handled by script_legacy
	// 2. Defaults button 
	$("#btndefaults").click(function(e) { e.preventDefault(); console.log("reset to defaults"); });
	// 3. Save
	$("#btnsave").click(function(e) { e.preventDefault(); console.log("save this page"); });
});

