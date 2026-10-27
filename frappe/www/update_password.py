# Copyright (c) 2015, Frappe Technologies Pvt. Ltd. and Contributors
# License: MIT. See LICENSE
from frappe import _
from frappe.core.doctype.navbar_settings.navbar_settings import get_app_logo
from frappe.mpass_sso import guard_local_credentials

no_cache = 1


def get_context(context):
	guard_local_credentials()

	context.no_breadcrumbs = True
	context.parents = [{"name": "me", "title": _("My Account")}]
	context.logo = get_app_logo()
