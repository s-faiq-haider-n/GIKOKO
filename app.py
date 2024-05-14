from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import psycopg2
import argon2
import secrets
import binascii
import os
from datetime import datetime


# Function for hashing password


def hash_password(password):
    # Generate a 16-byte (128-bit) random salt
    salt = secrets.token_bytes(16)
    hex_salt = binascii.hexlify(salt).decode('utf-8')

    # Concatenate password and salt
    password_with_salt = password + hex_salt

    # Create an Argon2 password hasher with appropriate parameters
    hasher = argon2.PasswordHasher(
        time_cost=16,  # The number of iterations
        memory_cost=2**14,  # Memory usage (in KiB)
        parallelism=2,  # Number of threads to use
        hash_len=32  # Length of the hash output in bytes
    )

    # Hash the password using Argon2 with the concatenated password and salt
    hashed_password = hasher.hash(password_with_salt)

    return hashed_password, hex_salt

# Function for verifying password


def verify_password(hashed_password, hex_salt, en_password):
    # Decode the hashed password from bytes (assuming it's stored as BYTEA in the database)
    hashed_password = hashed_password.tobytes()
    hashed_password = hashed_password.decode('utf-8').strip("'")

    # Convert hex_salt to bytes
    # hex_salt = bytes.fromhex(hex_salt)

    # Concatenate entered password with hex salt
    password_with_salt = en_password + hex_salt

    # Create an Argon2 password hasher
    hasher = argon2.PasswordHasher()

    try:
        # Verify the password using Argon2 with the concatenated password and salt
        hasher.verify(hashed_password, password_with_salt)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False


# Function to check database connection


def check_db_connection():
    try:
        conn = psycopg2.connect(
            # dbname="gikoko",
            # user="postgres",
            # password="dbprj",
            # host="127.0.0.1"

            dbname="gikoko_db",
            user="gikoko_db_owner",
            password="tm87jivoFhfk",
            host="ep-dawn-lab-a1g102zu.ap-southeast-1.aws.neon.tech"
        )
        conn.close()
        return True
    except psycopg2.Error as e:
        print("Unable to connect to the database:", e)
        return False


# Function to establish and return connection to the PostgreSQL database


def get_db_connection():
    conn = psycopg2.connect(
        # dbname="gikoko",
        # user="postgres",
        # password="dbprj",
        # host="127.0.0.1"
        dbname="gikoko_db",
        user="gikoko_db_owner",
        password="tm87jivoFhfk",
        host="ep-dawn-lab-a1g102zu.ap-southeast-1.aws.neon.tech"
    )
    if check_db_connection:
        return conn
    else:
        return "Failed to establish connection with the database"


def get_Posts(query):
    logged_user = session["username"]

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(query)
    conn.commit()
    posts = cur.fetchall()
    # Close the cursor and connection
    cur.close()
    conn.close()
    return posts


def get_catPosts(category):
    query = """SELECT posts.*, users.user_name
            FROM posts
            JOIN users ON posts.user_id = users.user_id
            WHERE posts.category = '"""+category+"""'
            ORDER BY posts.post_time DESC;
            """
    posts = get_Posts(query)
    return posts


app = Flask(__name__, static_folder='static')
app.secret_key = 'dbprj'


@ app.route("/")
def create_acc():
    print('route 1 in work')
    return render_template("login.html")


@ app.route("/about")
def about():
    return render_template('about_us.html')


@ app.route("/create")
def create():
    return render_template("create_acc.html")


@ app.route("/submit_account", methods=['POST', 'GET'])
def submit_account():
    print('route 2 in work')
    # Check database connection
    if not check_db_connection():
        return "Failed to establish connection with the database"

    try:
        # Get form data
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        h_password, h_passsalt = hash_password(password)

        # Get the existing database connection
        conn = get_db_connection()

        # Create a cursor
        cur = conn.cursor()

        # Execute query
        cur.execute(
            "INSERT INTO users(user_name, email, h_password, h_passsalt) VALUES (%s, %s, %s, %s)",
            (username, email, h_password, h_passsalt)
        )
        conn.commit()

        # Close the cursor and connection
        cur.close()
        conn.close()
        print('insertion complete')
        return "Account created successfully"

    except psycopg2.IntegrityError as e:
        # If there's a unique constraint violation (duplicate key error)
        print("Error:", e)
        return "Username or email already exists"

    except Exception as e:
        # If there's any other error during database operation
        print("Error:", e)
        return "Failed to create account. Please try again."


@ app.route("/login")
def login():
    print('route 3 in work')
    return render_template('login.html')


@ app.route("/authenticate", methods=["POST"])
def authenticate():
    if request.method == 'POST':
        # Get form data
        username = request.form['username']
        en_password = request.form['password']  # entered password
        # Get the existing database connection
        conn = get_db_connection()
        # Create a cursor
        cur = conn.cursor()

        # Execute query
        cur.execute(
            "SELECT h_password,h_passsalt,user_id FROM users WHERE user_name = %s", (
                username,)
        )
        conn.commit()
        user_record = cur.fetchone()
        # Close the cursor and connection
        cur.close()
        conn.close()
        if user_record:
            if verify_password(user_record[0], user_record[1], en_password):
                # Password matches, set session and redirect to homepage
                session['username'] = username
                session['user_id'] = user_record[2]
                return redirect(url_for('Homepage'))
            else:
                # Password does not match
                return render_template('incorrect_passcode.html')
        else:
            # User does not exist
            return render_template('user_notFound.html')

    # If GET request or form submission fails, render login page
    return render_template('login.html')


@app.route("/dashboard")
def Homepage():
    # Check if 'username' is in the session
    if 'username' in session:
        logged_user = session["username"]
        conn = get_db_connection()
        cur = conn.cursor()

        # Execute query
        cur.execute(
            "SELECT first_name,last_name,bio,email,date_of_birth,address,date_joined,dp_path,phone_no,gender FROM users WHERE user_name = %s", (
                logged_user,)
        )
        conn.commit()
        logged_user_record = cur.fetchone()
        # Close the cursor and connection
        cur.close()
        conn.close()
        user_profile = {'first_name': logged_user_record[0], 'last_name': logged_user_record[1], 'bio': logged_user_record[2],
                        'username': logged_user, 'email': logged_user_record[3], 'date_of_birth': logged_user_record[4],
                        'house_address': logged_user_record[5], 'date_joined': logged_user_record[6], 'dp': logged_user_record[7],
                        'phNumber': logged_user_record[8], 'gender': logged_user_record[9]}
        return render_template("Homepage.html", user_profile=user_profile)
    # If 'username' isn't in the session, redirect to the login page
    else:
        return redirect(url_for('login'))


@app.route("/update_profile", methods=['POST', 'GET'])
def update_profile():
    print('my updation route')
    logged_user = session["username"]
    if request.method == 'POST':
        conn = get_db_connection()
        cur = conn.cursor()
        user_profile = {'first_name': request.form['firstNameInput'], 'last_name': request.form['lastNameInput'],
                        'bio': request.form['bioInput'],
                        'username': request.form['usernameInput'], 'email': request.form['emailInput'],
                        'date_of_birth': request.form['dobInput'],
                        'house_address': request.form['addressInput'], 'phNumber': request.form['phoneNumberInput'], 'gender': request.form['genderInput']}
        date_format = "%Y-%m-%d"
        date_object = datetime.strptime(
            user_profile['date_of_birth'], date_format)

        # Execute query
        cur.execute("""UPDATE users SET first_name= %s,
                last_name= %s, bio= %s, user_name= %s, email= %s, date_of_birth= %s,
                address= %s,  phone_no= %s ,gender= %s WHERE user_name = %s""",
                    (user_profile['first_name'], user_profile['last_name'],
                     user_profile['bio'], user_profile['username'], user_profile['email'], date_object,
                     user_profile['house_address'], user_profile['phNumber'], user_profile['gender'], logged_user))

        conn.commit()
        # Close the cursor and connection
        cur.close()
        conn.close()
        return redirect(url_for('Homepage'))
    else:
        return "Unable to update Profile"


@app.route("/uploadDp", methods=['POST', 'GET'])
def uploadDp():
    logged_user = session["username"]
    if 'profilePicture' not in request.files:
        return "No file part"

    file = request.files['profilePicture']

    if file.filename == '':
        return "No selected file"

    # Save the file to the server
    upload_folder = os.path.join(app.root_path, 'static')
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    file_path = os.path.join(upload_folder, file.filename)
    file.save(file_path)
    # Extract filename from file_path
    filename = os.path.basename(file_path)

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET dp_path = %s WHERE user_name = %s",
                (filename, logged_user))
    conn.commit()
    cur.close()

    return render_template('redirect_landing.html')


@app.route("/post_page")
def post_page():
    return render_template('post.html')


@app.route("/post_made", methods=['POST'])
def make_a_post():
    logged_user = session["username"]
    if request.method == 'POST':
        title = request.form['post-title']
        content = request.form['post-content']
        category = request.form['post-category']
        conn = get_db_connection()
        cur = conn.cursor()
        # Execute query
        cur.execute(
            "SELECT user_id FROM users WHERE user_name = %s", (
                logged_user,)
        )
        conn.commit()
        user_record = cur.fetchone()
        # Execute query
        cur.execute(
            "INSERT INTO posts(user_id, category, title, post_content) VALUES (%s, %s, %s, %s)",
            (user_record, category, title, content)
        )
        conn.commit()
        # Close the cursor and connection
        cur.close()
        conn.close()
        return redirect(url_for('fetch_allPosts'))


@app.route("/fetch_allPosts")
def fetch_allPosts():
    query = """SELECT posts.*, users.user_name
                FROM posts
                JOIN users ON posts.user_id=users.user_id
                ORDER BY posts.post_time DESC"""
    posts = get_Posts(query)
    return render_template("posts_fetched.html", posts=posts, )


@app.route("/fetch_gPosts")
def fetch_gPosts():
    category = 'General'
    posts = get_catPosts(category)
    return render_template("posts_fetched.html", posts=posts, )


@app.route("/fetch_tPosts")
def fetch_tPosts():
    category = 'Transport'
    posts = get_catPosts(category)
    return render_template("posts_fetched.html", posts=posts, )


@app.route("/fetch_aPosts")
def fetch_aPosts():
    category = 'Academic'
    posts = get_catPosts(category)
    return render_template("posts_fetched.html", posts=posts, )


@app.route("/fetch_oPosts")
def fetch_oPosts():
    category = 'GIKI_Olx'
    posts = get_catPosts(category)
    return render_template("posts_fetched.html", posts=posts, )


@app.route("/fetch_sPosts")
def fetch_sPosts():
    category = 'Society_Ad'
    posts = get_catPosts(category)
    return render_template("posts_fetched.html", posts=posts, )


@app.route("/fetch_lPosts")
def fetch_lPosts():
    category = 'Lost_n_Found'
    posts = get_catPosts(category)
    return render_template("posts_fetched.html", posts=posts, )


@app.route("/fetch_userPosts")
def fetch_userPosts():
    logged_userID = session["user_id"]
    logged_userID = str(logged_userID)
    query = """SELECT posts.*, users.user_name
            FROM posts
            JOIN users ON posts.user_id = users.user_id
            WHERE posts.user_id = """
    query = query+logged_userID+" ORDER BY posts.post_time DESC;"
    posts = get_Posts(query)
    return render_template("user_posts_fetched.html", posts=posts, )


@app.route("/edit_post", methods=['POST'])
def edit_post():
    post_id = request.form['post_id']
    new_title = request.form['edit_title']
    new_content = request.form['edit_content']
    conn = get_db_connection()
    cur = conn.cursor()
    # Execute query
    cur.execute(
        "UPDATE posts SET title=%s , post_content=%s WHERE post_id=%s", (
            new_title, new_content, post_id)
    )
    conn.commit()
    # Close the cursor and connection
    cur.close()
    conn.close()
    return redirect(url_for('fetch_userPosts'))


@app.route("/delete_post", methods=['POST'])
def delete_post():
    post_id = request.form['post_id']
    conn = get_db_connection()
    cur = conn.cursor()
    # Execute query
    cur.execute(
        "DELETE FROM posts WHERE post_id = %s", (
            post_id,)
    )
    conn.commit()
    # Close the cursor and connection
    cur.close()
    conn.close()
    return redirect(url_for('fetch_userPosts'))


@app.route("/dm")
def dm():
    # get the user id of the current user
    logged_userID = session["user_id"]
    id = session["user_id"]
    con = get_db_connection()
    cur = con.cursor()
    # Execute query
    cur.execute(
        """SELECT user_id, first_name, last_name, dp_path
            FROM (
                SELECT u.user_id, u.first_name, u.last_name, u.dp_path
                FROM users u
                JOIN messages m ON u.user_id = m.receiver_id
                WHERE m.sender_id = %s

                UNION

                SELECT u.user_id, u.first_name, u.last_name, u.dp_path
                FROM users u
                JOIN messages m ON u.user_id = m.sender_id
                WHERE m.receiver_id = %s
            ) AS user_interactions
            ORDER BY first_name, last_name;""", (
            logged_userID, logged_userID)
    )
    con.commit()
    chat_records = cur.fetchall()
    # Close the cursor and connection
    cur.close()
    con.close()

    print(id)
    return render_template('message.html', chat_records=chat_records, logged_userID=logged_userID)


@app.route('/chat/<int:chat_id>')
def get_messages(chat_id):
    logged_userID = session["user_id"]
    print("dynamic chat route chat with: ", chat_id)
    logged_userID = session["user_id"]

    con = get_db_connection()
    cur = con.cursor()

    # Retrieve messages for the selected chat
    cur.execute(
        """SELECT message_id, sender_id, receiver_id, msg_content, msg_time
           FROM messages
           WHERE (sender_id = %s AND receiver_id = %s)
           OR (sender_id = %s AND receiver_id = %s)
           ORDER BY msg_time DESC;""",
        (logged_userID, chat_id, chat_id, logged_userID)
    )

    messages = cur.fetchall()
    cur.close()
    con.close()

    # Prepare messages data to be sent as JSON
    formatted_messages = [
        {
            'message_id': message[0],
            'sender_id': message[1],
            'receiver_id': message[2],
            'message': message[3],
            # Format timestamp
            'timestamp': message[4].strftime("%Y-%m-%d %H:%M:%S")
        }
        for message in messages
    ]
    print(formatted_messages)
    return jsonify(messages=formatted_messages, logged_userID=logged_userID)


@app.route('/send_message/<int:receiver_id>', methods=['POST'])
def send_message(receiver_id):
    print("dynamic chat 2 route chat with: ", receiver_id)

    message_content = request.form['message']
    logged_userID = session["user_id"]

    con = get_db_connection()
    cur = con.cursor()
    cur.execute(
        """INSERT INTO messages(sender_id, receiver_id, msg_content, msg_time)
           VALUES (%s, %s, %s, NOW())""",
        (logged_userID, receiver_id, message_content)
    )
    con.commit()
    cur.close()
    con.close()

    return jsonify({'status': 'success'})


@ app.route("/userSearch")
def userSearch():
    current_userID = session['user_id']
    con = get_db_connection()
    cur = con.cursor()
    # Execute query
    cur.execute(
        """SELECT
    user_id,
    first_name,
    last_name,
    bio,
    TO_CHAR(date_joined, 'DD/MM/YYYY') AS date_joined_formatted,
    dp_path
    FROM
    users
    ORDER BY
    first_name,
    last_name;
        """
    )
    con.commit()
    # Fetch results
    users = cur.fetchall()
    # Close connection
    con.close()
    return render_template('user_search.html', users=users, current_userID=current_userID)


# Send message from user search option (not dynamic)


@app.route('/send_message', methods=['POST'])
def send_message_u():
    receiver_id = request.form.get('user_id')
    message = request.form.get('message')
    con = get_db_connection()
    cur = con.cursor()
    # Execute query
    cur.execute("""INSERT INTO messages(sender_id,receiver_id,msg_content)
                VALUES (%s,%s,%s)""",
                (session["user_id"], receiver_id, message))
    con.commit()
    con.close()

    return redirect(url_for("dm"))


@ app.route("/logout", methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
