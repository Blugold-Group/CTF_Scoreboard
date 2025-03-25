# Blugold Group Website

This website is the website for the Blugold Group, the cybersecurity club of the [University of Wisconsin - Eau Claire](https://www.uwec.edu/).

It is not meant to be hosted on the open web, but rather on the cybersecurity lab network. It is hosted on the open web over the winterim 2024-2025 to provide access for members to a Winterim CTF

As we are a technical club, we try to make the documentation for the server as clear and comprehensive as possible to lower the barrier for members to dig into the code with as little technical experience as possible. As such, this documentation file aims to be a comprehensive guide to every moving part of the server.

**This guide is still a work in progress**

## Architecture

The server is written in python to allow a lower barrier of entry to developing it. By design, it should allow people to develop it long after I'm gone. That's why I'm trying to write this guide to be as comprehensive as possible.

### Main server (app.py)

`/app.py` is the main file for the server. It defines and provides code for routes (IE `/`, `/members`, `/ctf/1`, etc). If you want to get into the meat and potatoes of the server, start here.

This server uses Flask as the server backend. Like all Flask server `app.py`  seperates server code into different 'routes'. For example,

```
@app.route("/add_user", methods=["GET", "POST"])
@login_required
def add_user():

    if not current_user.is_admin:
        return redirect(url_for('dashboard'))

    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        # more code here

        query_db('INSERT INTO users (username, password, otp_secret, lock_permissions, is_admin, tags) VALUES (?, ?, ?, ?, ?, ?)', 
                 [username, hashed_password, otp_secret, lock_permissions, is_admin, " "])
        
        flash("User added successfully", "success")
        
        logging.info(f"User created: {username} by user: {current_user.username} (ID: {current_user.id})")

        return redirect(url_for('dashboard'))

    return render_template("add_user.html")
```

the code in function `add_user()` runs when a visitor visits `/add_user`. In this example, we only allow GET and POST http methods.

#### GET and POST Requests

When a GET request comes into the server, 99% its a browser downloading and rendering HTML. Therefore, we always return html to any GET requests. If its a POST request, 99% of the time its data coming in from a form on the server. In this server POST data sent by forms are always sent to the same route that the form is loaded on. For example, the form to add an activity on `/add_user` sends POST data form that form to `/add_user`. So because we're getting a mix of POST and GET data, we need to sort out what to do based on what type of request it is.

We can do this with `request.method`. In this example, we check `if request.method == "POST"`, but we can do the same with `if request.method == "GET"`. You can do this logic with any type of http request, but this server only needs to handle GET and POST requests.

POST requests transfer data, we can access that data with `request.form['data_name']`. On `add_user.html` there is a form to add a user:

```
<input type="text" name="username" id="username" required>
```

In this case, when the form is submitted with the submit button the server will receive a post request with a `username: username_data` POST request. The `<name>` html tag contains what the variable will be submitted as to the server, so in this case if we want to see what the user submitted username was, we can use something like 

```
submitted_username = request.form['username']
```

#### Access authentication

Some pages we only want viewable by members, like `/ctf` pages which host ctf challenges. We can restrict access to logged in users with `@login_required`

We can also easily test if a user is an admin or not using `current_user.is_admin`, which is a simple `True` if the user is an admin and `False` otherwise. This is provided by user handling

#### User Handling

We have a class which keeps track of user data in a way which is easily accessible.

```
class User(UserMixin):
    def __init__(self, id, username, otp_secret, lock_permissions, is_admin=False):
        self.id = id
        self.username = username
        self.otp_secret = otp_secret
        self.is_admin = is_admin
```

This class is loaded for the signed in user when the user logs in at `/login` with this line (`user_data` variables are created earlier in the `/login` method):

```
user = User(id=user_data['id'], username=user_data['username'], otp_secret=user_data['otp_secret'], lock_permissions=user_data['lock_permissions'], is_admin=bool(user_data['is_admin']))
```

#### flash() methods

You can send messages to the user easily with Flask's flash() method. You can do this with `flash("Message", "class")`. The `message` is the message you want sent, the `class` is the category denotes what style you want the message to have. At the time of this writing, we only use two different classes, which are `success` and `error`. The styles for these messages are kept in `/static/css/alert.css`

If the server `flash()`s a message to the user and the user is on a page which doesn't render, the message will be stored until the session is destroyed or the user reaches a page which does render messages. For example, if the `/login` page didn't render messages, and the user tried to log in 6 times before logging in successfully and then makes it to `/dashboard` (which does render messages), the user would have a stack of six messages saying 'Invalid username or password' and one message saying 'Successfully logged in'. You can render `flash()` messages with Jinja

#### Jinja

Jinja is how the server dynamically renders content. It allows us to display variables and run python code in the html that is served to the user (It doesn't actually run python in the browser of course, the server renders the html with the python code and then serves the rendered code to the browser). For example, in `/templates/view_ctf.html`, which is render when a user visits `/ctf/<ctf_id>`

```
{% if is_admin %}    
<a href="{{ url_for('ctf.edit_challenge', challenge_id=challenge['id']) }}">Edit</a></li>
{% endif %}  
```

When the user loads the page, if `is_admin` is true, the page loads a link to edit a ctf challenge. If the user isn't an admin, we don't want them to be able to edit the challenge so we don't render it

You can also simply display variables

```
<p>{{ challenge['description'] }}</p>    
```

We display the string `challenge['description']` in a simple text box. We declare the variable for the Jinja code when we return the html in the route. For example, in the `/routes/ctf.py` `view_ctf()` method we display the challenges for a ctf. We use Jinja to render the details about the ctf, so we supply those variables with

```
return render_template('view_ctf.html', challenges=challenges, ctf_id=ctf_id, is_admin=is_admin, name=name, users=users, chart_points=chart_points, chart_challenges=chart_challenges, completed_challenges=completed_challenges)
```

You'll notice that this code isn't in the main `app.py` file, but still provides code which would fit in `app.py`. This is because having one very large file with all of the routes and methods for the server is terrible, so we split it up among multiple files in `/routes/`. We split it up using blueprints

#### ctf.py and blueprints

At the time of this writing, we only branched out blueprints to `/routes/ctf.py`, we may spread out the code to more files in the future.

#### Badges

To change: `UPDATE users SET tags = 'Exec,Master Locksmith' WHERE username = 'adminn';`

Has to be a comma separated list, no spaces

Add new badges in the `/about/badges` page and the css of `/members`

### Database

### File Structure

#### /static/

The `/static/` directory provides static media which is available without authentication. This includes `.js` files, `.css` files, and images

#### /templates/

#### /articles/

The `/articles/` directory contains blog articles, written in Markdown, each stored as a separate `.md` file.
Any `.md` files present in the folder are automatically listed when a user goes to the `/articles` route,
and are converted to HTML and rendered in `view_article.html` by the backend.

##### Jinja `extends`

Keeping a seperate copy of html which is thr same across multiple files is annoying, when you make a change to the header you have to copy and paste your changes across dozens of `.html` files. To fix that, Jinja provides the `extends` function

Similar to Java's `extends` function for created inherited classes, you can use

```
{% extends "base.html" %}
```

to create a html file which has all of the code that `base.html` has. `base.html` is the file which we base all of our html pages on. It contains the universal page header, navbar, logo, etc. In the child .html, you may define `{% block %}`s for `content`, `style`, and `title`. All pages should use `{% extends "base.html" %}` to inherit base.html. The `style` block can be used to set not only the style tag, but any other tags that must be included in the header such as `<script>`

### config.py

### helpers.py

## Hall of History

If you add on to this codebase, please add your name below

This server was created by Jack Hagen (the founder of the club) over a weekend in October 2024, and maintained by him from October 2024-

Various features, updates, fixes, etc by Silas Eacret (*🍗🍗🍗 Chief Development Officer 🍗🍗🍗*), starting in December 2024, in addition to maintenance.

### Historical Notes

The CLEAS (Cyber Lab Equipment Access System) was originally meant to authenticate id tags unique to each club member, allowing us to see who unlocked what when. The lock permissions were meant to be tied to user accounts on this server, so any mention of locks in the code references that. Ultimately we just used a basic nfc lock which uses one nfc password which was copied to several tags to be shared by all members

## Server Setup

At the time of writing, I am currently setting up the server to run on a raspberry pi, using Cloudflare to tunnel to the open internet. I don't know how you will host this in the future, but as of now this file will hold documentation for how the server is setup as well as the programming

For some reason when running from cron after reboots, setting up a Cloudflare tunnel and SSH tunnel fail because they can't reach the network, I'm assuming that network services just haven't booted by that point, so delaying them 10 seconds did the trick  

### Daily Maintenance Script

### Boot up script

### Setup

To start the server (**in debug mode**), first ensure Python and Pip are installed.
Run `pip install -r requirements.txt` to install packages required for the server to run. Finally, run `python app.py`. The site should be accessible at any of the given addresses.

An initial admin user must be created. This can be done by directly modifying the new `database.db` file. Add a record to the `users` table. The password field should contain a hashed password, generated using [werkzeug.security.generate_password_hash()](https://werkzeug.palletsprojects.com/en/stable/utils/#werkzeug.security.generate_password_hash). A Python script can accomplish this, such as [this one](https://github.com/EekRats/ctf_hasher/blob/main/ctf_hasher.py). The `is_admin` column should be set to `1`.
