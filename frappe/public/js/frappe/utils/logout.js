frappe.logout = function () {
	frappe.call({
		method: "logout",
		callback: function (r) {
			if (r.exc) {
				return;
			}
			window.location.href = frappe.boot?.mpass_logout_url || "/login";
		},
	});
};
