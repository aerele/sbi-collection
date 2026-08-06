// Copyright (c) 2025, aerele.in and contributors
// For license information, please see license.txt

// Client-side controller for the "Generate VAN" button on the Customer form.
// All business logic lives on the server (sbi_collection.van.generate_van);
// this script only adds the button and invokes the method.

frappe.ui.form.on("Customer", {
	refresh(frm) {
		// Only offer generation for saved documents - the server reads the
		// docname, which doesn't exist yet for an unsaved record.
		if (frm.doc.__islocal) {
			return;
		}

		frm.add_custom_button(__("Generate VAN"), () => {
			frappe.call({
				method: "sbi_collection.van.generate_van",
				args: { customer: frm.doc.name },
				freeze: true,
				freeze_message: __("Generating VAN..."),
				callback: (r) => {
					if (r.message) {
						frm.set_value("collection_van", r.message);
						frm.refresh_field("collection_van");
						frappe.show_alert({
							message: __("VAN generated: {0}", [r.message]),
							indicator: "green",
						});
					}
				},
			});
		});
	},
});
