# Database filepath
DATABASE = 'database.db'

LOG_FILE = 'server.log'

# API keys/similar should be stored in environment variables:
# See README.md under Server Setup for more info
# FLASK_SECRET_KEY
# DISCORD_CLIENT_SECRET

# How many days left until the "Closing Soon!" badge displays on a CTF?
CTF_CLOSING_SOON_DAYS = 3

# Variables for Discord integration
DISCORD_CLIENT_ID = "1320997904420442122"
# DISCORD_CLIENT_SECRET is set as an environment variable ('export DISCORD_CLIENT_SECRET=whateverthekeyvalueis')
DISCORD_REDIRECT_URI = "http://127.0.0.1:5000/discord/callback"
DISCORD_API_ENDPOINT = "https://discord.com/api"