import streamlit as st
import datetime
import cv2
from PIL import Image
import pyzbar.pyzbar as pyzbar
import requests
import re
import sqlite3
import hashlib

# ----- Database setup -----
conn = sqlite3.connect('grocery_items.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_name TEXT NOT NULL,
        purchase_date TEXT NOT NULL,
        expiry_date TEXT NOT NULL,
        notification_dates TEXT NOT NULL
    )
''')
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
''')
conn.commit()

# ----- Helper functions -----


def hash_password(password):
    """Hashes the password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def login():
    """Displays the login form and authenticates the user."""
    st.sidebar.header("Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    if st.sidebar.button("Login"):
        cursor.execute('''
            SELECT password FROM users WHERE username = ?
        ''', (username,))
        user = cursor.fetchone()
        if user and user[0] == hash_password(password):
            st.session_state.logged_in = True
            st.sidebar.success("Logged in successfully!")
        else:
            st.sidebar.error("Incorrect username or password.")


def register():
    """Displays the registration form and creates a new user."""
    st.sidebar.header("Register")
    username = st.sidebar.text_input("Username", key='register_username')
    password = st.sidebar.text_input(
        "Password", type="password", key='register_password')
    confirm_password = st.sidebar.text_input(
        "Confirm Password", type="password", key='register_confirm_password')
    if st.sidebar.button("Register"):
        if password == confirm_password:
            try:
                cursor.execute('''
                    INSERT INTO users (username, password)
                    VALUES (?, ?)
                ''', (username, hash_password(password)))
                conn.commit()
                st.sidebar.success(
                    "Registered successfully! You can now log in.")
            except sqlite3.IntegrityError:
                st.sidebar.error("Username already exists.")
        else:
            st.sidebar.error("Passwords do not match.")

# ----- QR Code Scanner Page -----


def qr_scanner_page():
    """Page to scan QR codes using the camera and display steps."""
    st.title("QR Code Scanner")

    # Options for real-time camera feed or file upload
    scan_option = st.radio("Choose scanning method",
                           ("Upload Image", "Use Camera"))

    if scan_option == "Upload Image":
        st.header("Upload a QR Code Image")
        uploaded_file = st.file_uploader(
            "Upload a QR code image", type=["png", "jpg", "jpeg"])

        if uploaded_file is not None:
            image = Image.open(uploaded_file)
            st.image(image, caption='Uploaded QR Code', use_column_width=True)

            decoded_objects = pyzbar.decode(image)
            if decoded_objects:
                qr_code_data = decoded_objects[0].data.decode("utf-8")
                st.write("Step 1: QR Code scanned successfully!")
                st.write("Step 2: Data extracted:")
                st.code(qr_code_data)

                # Data Processing
                with st.spinner("Processing data..."):
                    response = requests.get(qr_code_data)
                    response = response.text
                    pattern = r"<p>(.*?)<\/p>"
                    match = re.search(pattern, response)
                    if match:
                        extracted_data = match.group(1)
                        qr_code_data = extracted_data
                    try:
                        item_name, purchase_date, expiry_date, notification_dates_str = qr_code_data.split(
                            "|")
                        notification_dates = notification_dates_str.split(",")
                        data = {
                            "item_name": item_name,
                            "purchase_date": purchase_date,
                            "expiry_date": expiry_date,
                            "notification_dates": notification_dates,
                        }

                        # Data Storage
                        with st.spinner("Storing data..."):
                            try:
                                cursor.execute('''
                                    INSERT INTO items (item_name, purchase_date, expiry_date, notification_dates)
                                    VALUES (?, ?, ?, ?)
                                ''', (
                                    data["item_name"],
                                    data["purchase_date"],
                                    data["expiry_date"],
                                    ",".join(data["notification_dates"])
                                ))
                                conn.commit()
                                st.write(
                                    "Step 3: Data stored successfully in the database.")
                            except Exception as e:
                                st.error(f"Error storing data: {e}")
                    except ValueError:
                        st.error("Invalid QR code data format.")
            else:
                st.error("No QR code found in the image.")

    elif scan_option == "Use Camera":
        st.header("Scan QR Code from Camera")
        run_camera = st.button("Start Camera")

        if run_camera:
            cap = cv2.VideoCapture(0)
            st_frame = st.empty()

            while cap.isOpened():
                ret, frame = cap.read()
                if not ret:
                    st.error("Failed to access the camera.")
                    break

                # Decode QR code in the frame
                decoded_objects = pyzbar.decode(frame)
                for obj in decoded_objects:
                    qr_code_data = obj.data.decode("utf-8")
                    cv2.putText(frame, "QR Code Detected", (50, 50),
                                cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
                    st.write("Step 1: QR Code scanned successfully!")
                    st.write("Step 2: Data extracted:")
                    st.code(qr_code_data)

                    # Data Processing
                    with st.spinner("Processing data..."):
                        response = requests.get(qr_code_data)
                        response = response.text
                        pattern = r"<p>(.*?)<\/p>"
                        match = re.search(pattern, response)
                        if match:
                            extracted_data = match.group(1)
                            qr_code_data = extracted_data
                        try:
                            item_name, purchase_date, expiry_date, notification_dates_str = qr_code_data.split(
                                "|")
                            notification_dates = notification_dates_str.split(
                                ",")
                            data = {
                                "item_name": item_name,
                                "purchase_date": purchase_date,
                                "expiry_date": expiry_date,
                                "notification_dates": notification_dates,
                            }

                            # Data Storage
                            with st.spinner("Storing data..."):
                                try:
                                    cursor.execute('''
                                        INSERT INTO items (item_name, purchase_date, expiry_date, notification_dates)
                                        VALUES (?, ?, ?, ?)
                                    ''', (
                                        data["item_name"],
                                        data["purchase_date"],
                                        data["expiry_date"],
                                        ",".join(data["notification_dates"])
                                    ))
                                    conn.commit()
                                    st.write(
                                        "Step 3: Data stored successfully in the database.")
                                    cap.release()
                                    cv2.destroyAllWindows()
                                    return
                                except Exception as e:
                                    st.error(f"Error storing data: {e}")
                        except ValueError:
                            st.error("Invalid QR code data format.")
                            cap.release()
                            cv2.destroyAllWindows()
                            return

                # Display frame in Streamlit
                frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                st_frame.image(frame, channels="RGB")

            cap.release()
            cv2.destroyAllWindows()

# ----- Main app -----


def main():
    """Main function to run the app."""
    st.set_page_config(page_title="QR Code Grocery Tracker", layout="wide")

    # Sidebar for login/register
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if not st.session_state.logged_in:
        option = st.sidebar.selectbox(
            "Choose an option", ["Login", "Register"])
        if option == "Login":
            login()
        else:
            register()
        return

    # Page navigation
    page = st.sidebar.selectbox("Navigate to", ["Dashboard", "QR Scanner"])

    if page == "Dashboard":
        st.title("Grocery Dashboard")
        st.success("Welcome to your Grocery Dashboard!")
        st.header("Your Grocery Items")
        cursor.execute(
            '''SELECT item_name, purchase_date, expiry_date, notification_dates FROM items''')
        items = cursor.fetchall()

        if items:
            st.write("### List of items")
            for item in items:
                st.markdown(f"""
                    **Item Name**: {item[0]}  
                    **Purchase Date**: {item[1]}  
                    **Expiry Date**: {item[2]}  
                    **Notification Dates**: {item[3]}
                """)
        else:
            st.write("No items found.")
    elif page == "QR Scanner":
        qr_scanner_page()


if __name__ == "__main__":
    main()
