# udacity-item-catalog<br>
# This content id produced by David Duckwitz<br>
# (c) 2017 by David Duckwitz (Project for Nanodegree - Udacity)<br>
# You can take this for getting ideas, but please create your own script (Better to learn ;-) )<br>

Required:<br>
-Python (2.7) <br>
---> To install: in Ubuntu Console: "sudo apt-get install python"<br>

-Python Moduls: SQLAlchemy, Requests, Flask, OAuth2Client<br>
---> To install PIP: in Ubuntu Console: "sudo apt-get install python-pip"<br>
  -> To install Modules: in Ubuntu Console: "pip install sqlalchemy"<br>
  -> To install Modules: in Ubuntu Console: "pip install requests"<br>
  -> To install Modules: in Ubuntu Console: "pip install flask"<br>
  -> To install Modules: in Ubuntu Console: "pip install oauth2client"<br>
  
You need a Google OAuth2 API to use Google Login: <br>
-- Go to API Manager: https://console.developers.google.com/<br>
  --> Create API-Key <br>
  --> Create OAuth-2.0-Client-IDs<br>
  <br>
Put Created Data to:<br>
---->	FILE (in root): "client_secrets.json"<br>
---->	FILE (in Folder "templates"): "login.html" - Override Data in Line 161: data-clientid="YOUR CLIENT ID"<br>
-- Just override old Data<br>
<br>
You need a Facebook APP ID to use Facebook Login:<br>
-- Go to Facebook Developers: https://developers.facebook.com/apps/<br>
  --> Create new APP<br>
  --> Write app_id & app_secret to FILE (in root): "fb_client_secrets.json"<br>
  --> FILE (in Folder "templates"): "login.html" - Override Data in Line 79: appId         :"YOUR APP ID"<br>
  
Hints:<br>
I've seen some Problems with Google Login testing on Localhost(local).<br>
Redirect from Google to Localhost makes problems (Google has a IP 127.0.0.1 and Localhost, too... of course)<br>
If Possible Test it on a Amazon AWS / Lightsail Server or other Servers with a real IP (NOT 127.0.0.1 / Localhost)...<br>
<br>
I used a Amazon Lightsail Server with OS-Only(Ubuntu)...<br>
Test it for FREE: https://lightsail.aws.amazon.com/ls/webapp/home<br>
