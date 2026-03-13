voipcfg.py

The script is needed for automatically preparing phone/VoIP device configurations.
Basically, it takes the "employee → (device MAC, extension number)" mapping from LDAP, then retrieves the SIP credentials for this number from Asterisk/FreePBX and generates a configuration file using a template, saving it to a TFTP directory under the MAC address's name. This allows for centralized and mass configuration/reconfiguration of phones without manual entry.

check_users.py

The script is needed to check the list of users in Keycloak and get the status (active/blocked) and basic profile data for each of them.
