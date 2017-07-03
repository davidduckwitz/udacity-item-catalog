# udacity-item-catalog
# This content id produced by David Duckwitz
# (c) 2017 by David Duckwitz (Project for Nanodegree - Udacity)
# You can take this for getting ideas, but please create your own script (Better to learn ;-) )

Required:
-Python (2.7) 
---> To install: in Ubuntu Console: "sudo apt-get install python"

-Python Moduls: SQLAlchemy, Requests, Flask, OAuth2Client
---> To install PIP: in Ubuntu Console: "sudo apt-get install python-pip"
  -> To install Modules: in Ubuntu Console: "pip install sqlalchemy"
  -> To install Modules: in Ubuntu Console: "pip install requests"
  -> To install Modules: in Ubuntu Console: "pip install flask"
  -> To install Modules: in Ubuntu Console: "pip install oauth2client"
  
You need a Google OAuth2 API:
-- Go to API Manager: https://console.developers.google.com/
  --> Create API-Key 
  --> Create OAuth-2.0-Client-IDs
  
Put Created Data to:
---->	FILE (in root): "client_secrets.json"
---->	FILE (in Folder "templates"): "login.html" - Override Data in Line 78: data-clientid="YOUR CLIENT ID"
-- Just override old Data

Hints:
I've seen some Problems with Google Login testing on Localhost(local).
Redirect from Google to Localhost makes problems (Google has a IP 127.0.0.1 and Localhost, too... of course)
If Possible Test it on a Amazon AWS / Lightsail Server or other Servers with a real IP (NOT 127.0.0.1 / Localhost)...

I used a Amazon Lightsail Server with OS-Only(Ubuntu)...
Test it for FREE: https://lightsail.aws.amazon.com/ls/webapp/home
