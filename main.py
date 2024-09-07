import os
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messages.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
db = SQLAlchemy(app)

if not os.path.exists('uploads'):
    os.makedirs('uploads')

# Paths to store RSA keys
PRIVATE_KEY_PATH = 'private_key.pem'
PUBLIC_KEY_PATH = 'public_key.pem'

# Function to generate and save RSA keys if not already saved
def generate_and_save_keys():
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Save the private key
        with open(PRIVATE_KEY_PATH, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Save the public key
        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print("Keys generated and saved.")

# Function to load the RSA private key from file
def load_private_key():
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

# Function to load the RSA public key from file
def load_public_key():
    with open(PUBLIC_KEY_PATH, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

# Generate keys if they don't exist, and load them
generate_and_save_keys()
private_key = load_private_key()
public_key = load_public_key()

# AES encryption and decryption functions (as explained earlier)
def encrypt_aes_key(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_key).decode('utf-8')

def decrypt_aes_key(encrypted_aes_key, private_key):
    encrypted_key_bytes = base64.b64decode(encrypted_aes_key)
    aes_key = private_key.decrypt(
        encrypted_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

def encrypt_message_with_aes(message, aes_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_message).decode('utf-8')

def decrypt_message_with_aes(encrypted_message, aes_key):
    encrypted_message_bytes = base64.b64decode(encrypted_message)
    iv = encrypted_message_bytes[:16]
    encrypted_message = encrypted_message_bytes[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message.decode('utf-8')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    aes_key_encrypted = db.Column(db.Text, nullable=False)
    content_encrypted = db.Column(db.Text, nullable=False)
    filename = db.Column(db.String(100), nullable=True)

with app.app_context():
    db.create_all()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        content = request.form.get('content', '')
        file = request.files['file']

        # Generate AES key
        aes_key = os.urandom(32)

        # Encrypt message and AES key
        encrypted_content = encrypt_message_with_aes(content, aes_key)
        encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

        filename = None
        if file:
            filename = file.filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        new_message = Message(username=username, aes_key_encrypted=encrypted_aes_key, content_encrypted=encrypted_content, filename=filename)
        db.session.add(new_message)
        db.session.commit()

        return redirect(url_for('index'))

    messages = Message.query.all()

    # Decrypt messages
    for message in messages:
        aes_key = decrypt_aes_key(message.aes_key_encrypted, private_key)
        message.content = decrypt_message_with_aes(message.content_encrypted, aes_key)

    return render_template('index.html', messages=messages)

@app.route('/get_new_messages', methods=['GET'])
def get_new_messages():
    last_id = request.args.get('last_id', 0, type=int)
    new_messages = Message.query.filter(Message.id > last_id).all()

    messages_data = []
    for message in new_messages:
        aes_key = decrypt_aes_key(message.aes_key_encrypted, private_key)
        decrypted_content = decrypt_message_with_aes(message.content_encrypted, aes_key)
        messages_data.append({
            'id': message.id,
            'username': message.username,
            'content': decrypted_content,
            'filename': message.filename
        })

    return jsonify(messages_data)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == "__main__":
    app.run(debug=True)