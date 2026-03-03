# oidc_audit
Okta periodically sends out security audit reports to customers detailing applications in their tenant that are using the insecure Implicit Grant flow. However, Okta only provides a basic list of App IDs. This script takes that list of App IDs and enriches it with actual usage metrics and additional security configurations, allowing you to answer:

Is this app actually being used, or can we just delete it?

Is this app also vulnerable to open-redirect attacks (Wildcard URIs)?

What Auth Policy is protecting this app?

What is the URL of the app? 

## Instructions : 

Create a file named app_ids.csv in the exact same folder as the script. The first row must be the header app_id, followed by the list of IDs from your Okta security audit.

The script will generate oidc_security_audit.csv in the same directory.
