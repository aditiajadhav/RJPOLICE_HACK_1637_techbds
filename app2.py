from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import pandas as pd
from io import StringIO
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from sklearn.preprocessing import LabelEncoder
from sklearn.neural_network import MLPClassifier
from scapy.all import *
import tempfile
import requests
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
from flask import session 
import csv
import os
# Placeholder dictionary mapping IP addresses to malware names
from flask import send_file
malware_dict = {}


from flask import Flask, render_template
from sklearn.metrics import classification_report
import base64
import numpy as np
from sklearn.metrics import confusion_matrix

app = Flask(__name__)
app.secret_key = 'nikita@123'


# Create or connect to a SQLite database
conn = sqlite3.connect('data.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, email TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS uploaded_data
             (id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT)''')
conn.commit()
conn.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error_message = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        conn = sqlite3.connect('data.db')
        c = conn.cursor()

        # Check if the email or username already exists
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_email = c.fetchone()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_username = c.fetchone()

        if existing_email:
            error_message = "Email already exists!"
        elif existing_username:
            error_message = "Username already exists!"
        elif not (username and password and email):
            error_message = "Username, Password, and Email are required!"
        else:
            c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, password, email))
            conn.commit()
            conn.close()

            # Redirect to login or any other page after successful signup
            return redirect(url_for('login'))

    return render_template('signup1.html', error=error_message)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('data.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            session['logged_in'] = True  # Set the session or cookie to indicate login status
            return redirect(url_for('pcap'))  # Redirect to the upload page on successful login

        return "Login Failed"

    return render_template('login.html')


# Route for the about page
@app.route('/about')
def about():
    return render_template('about.html')

# Import necessary modules

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    message = None

    if request.method == 'POST':
        # Handle the form submission, for example, sending an email or saving to a database.
        # You can access form data using request.form['form_field_name']
        name = request.form['name']
        email = request.form['email']
        user_message = request.form['message']

        # Here, you can implement the logic to handle the contact form data
        # For simplicity, let's just print the values to the console
        print(f"Name: {name}, Email: {email}, Message: {user_message}")

        # Set the thank-you message to be displayed on the contact page
        message = "Thank you! Your message has been received. We will get back to you soon."

    # Render the contact page with or without the thank-you message
    return render_template('contact.html', message=message)


@app.route('/logout')
def logout():
    # Clear the session data
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    message = None  # Initialize message variable
    redirect_url = None
    best_model = None
    
    message1 = "" 
    message2 = ""
    

    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file and uploaded_file.filename != '':
            # Check file extension on the server-side
            if not uploaded_file.filename.lower().endswith('.csv'):
                return "Error: Only CSV files are allowed."

            # Check file size before reading it
            max_size = 3145728000  # 3GB in bytes
            file_data = uploaded_file.read()
            file_size = len(file_data)
            uploaded_file.seek(0)  # Reset file pointer after reading

            if file_size > max_size:
                return "File size exceeds the limit of 3GB."

            data = file_data.decode("utf-8")

            # Store data in the database
            conn = sqlite3.connect('data.db')
            c = conn.cursor()
            c.execute("INSERT INTO uploaded_data (content) VALUES (?)", (data,))
            conn.commit()
            conn.close()
            message = "File uploaded successfully!"

            # Perform feature extraction
            df = pd.read_csv(StringIO(data))
            df.columns = df.columns.str.strip()
            # Identify columns with only one unique value (1 in this case)
            single_value_cols = [col for col in df.columns if df[col].nunique() == 1 and df[col].iloc[0] == 1]

            if single_value_cols:
                message2 = f"Columns with a single '1' value: {', '.join(single_value_cols)}"
            else:
                message2 = "No columns with a single '1' value found!"
            

            # Perform malware detection and identification
            # List of malware types to check for
            malware_labels = ['ADWARE_EWIND','SCAREWARE_FAKEAV', 'RANSOMWARE_SVPENG', 'ADWARE', 'SCAREWARE_FAKEAPP','SCAREWARE_FAKEAV','ADWARE_FEIWO','SCAREWARE_AVPASS']  # Add more malware types as needed

            # Check if any of the malware labels are present in the 'Label' column
            is_malware = df['Label'].isin(malware_labels)

            if is_malware.any():
                message1 = "Malware is Detected!\n"
                malware_types = df[df['Label'].isin(malware_labels)]['Label']
    
                most_common_malware = malware_types.value_counts().idxmax()  # Get the most common malware type
    
                most_common_malware_message = f"Type of malware is Detected: {most_common_malware}"
                message1 += most_common_malware_message
            else:
                message1 = "No Malware Detected!"


            
            # Define feature extraction function
            def extract_features(row):
                features = {}
                columns_to_extract = [
                    'Flow ID','Source IP','Destination IP','Source Port','Destination Port','Protocol','Timestamp',
                	'Total Length of Fwd Packets','Total Length of Bwd Packets','Fwd Packet Length Mean','Bwd Packet Length Mean',
                        'Flow Bytes/s','Flow Packets/s','FIN Flag Count','SYN Flag Count','RST Flag Count','PSH Flag Count','ACK Flag Count'
	                 'URG Flag Count','Init_Win_bytes_forward','Init_Win_bytes_backward','min_seg_size_forward','Flow IAT Max'
                ]

                for column in columns_to_extract:
                    try:
                        features[column] = row[column]
                    except KeyError as e:
                        print(f"Error: {e} column not found in the data.")
                        features[column] = None  # You can assign a default value or handle missing data here

                return features

            # Extract features from each row in the CSV file
            df['features'] = df.apply(extract_features, axis=1)

            # Convert the feature dictionaries into a DataFrame
            feature_df = pd.DataFrame(list(df['features']))

            # Downcast integer columns to int32 to reduce memory usage
            int_columns = feature_df.select_dtypes(include=['int64']).columns
            feature_df[int_columns] = feature_df[int_columns].astype('int32')

            # Encode categorical features (e.g., IP addresses)
            le = LabelEncoder()
            for col in ['Flow ID','Source IP','Destination IP','Source Port','Destination Port','Protocol','Timestamp',
                	'Total Length of Fwd Packets','Total Length of Bwd Packets','Fwd Packet Length Mean','Bwd Packet Length Mean',
                        'Flow Bytes/s','Flow Packets/s','FIN Flag Count','SYN Flag Count','RST Flag Count','PSH Flag Count','ACK Flag Count'
	                 'URG Flag Count','Init_Win_bytes_forward','Init_Win_bytes_backward','min_seg_size_forward','Flow IAT Max']:
                feature_df[col] = le.fit_transform(feature_df[col])

          

            # Split the dataset into features (X) and labels (y)
            X = feature_df  # Features
            y = df['Label']  # Target variable

            # Check unique classes and class distribution
            unique_classes = df['Label'].unique()
            print(unique_classes)
            print(df['Label'].value_counts())

            # Split the data into training and testing sets
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


            rf_clf = RandomForestClassifier(n_estimators=100, random_state=42)
            dt_clf = DecisionTreeClassifier(random_state=42)
            svm_clf = SVC(probability=True, random_state=42)
            mlp_clf = MLPClassifier(max_iter=1000, random_state=42)

            # Train the classifiers
            rf_clf.fit(X_train, y_train)
            dt_clf.fit(X_train, y_train)
            svm_clf.fit(X_train, y_train)
            mlp_clf.fit(X_train, y_train)

            # Make predictions on the test set
            rf_y_pred = rf_clf.predict(X_test)
            dt_y_pred = dt_clf.predict(X_test)
            svm_y_pred = svm_clf.predict(X_test)
            mlp_y_pred = mlp_clf.predict(X_test)

            # Calculate classification reports
            rf_report = classification_report(y_test, rf_y_pred)
            dt_report = classification_report(y_test, dt_y_pred)
            svm_report = classification_report(y_test, svm_y_pred)
            mlp_report = classification_report(y_test, mlp_y_pred)

            # Calculate accuracy
            rf_accuracy = accuracy_score(y_test, rf_y_pred)
            dt_accuracy = accuracy_score(y_test, dt_y_pred)
            svm_accuracy = accuracy_score(y_test, svm_y_pred)
            mlp_accuracy = accuracy_score(y_test, mlp_y_pred)



            # Determine the best model and its accuracy
            models = {
                'Random Forest': rf_accuracy,
                'Decision Tree': dt_accuracy,
                'SVM': svm_accuracy,
                'MLP': mlp_accuracy
            }
            best_model = max(models, key=models.get)
            best_accuracy = models[best_model]
           

            
            redirect_url = url_for('result_page', rf_accuracy=rf_accuracy, dt_accuracy=dt_accuracy,
                                   svm_accuracy=svm_accuracy, mlp_accuracy=mlp_accuracy,
                                   rf_report=rf_report, dt_report=dt_report,
                                   svm_report=svm_report, mlp_report=mlp_report,
                                   best_model=best_model, best_accuracy=best_accuracy, message1=message1, message2=message2)
            

    
            

    return render_template('uploaded.html', message=message, redirect_url=redirect_url)

def generate_classification_report():
    # Replace this section with your actual classification results
    y_true = np.array([1, 0, 1, 1, 0, 1])
    y_pred = np.array([1, 0, 1, 0, 0, 1])

    # Generate classification report
    report = classification_report(y_true, y_pred)

    # Generate confusion matrix plot
    cm = confusion_matrix(y_true, y_pred)
    plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    plt.title('Confusion matrix')
    plt.colorbar()
    plt.xlabel('Predicted label')
    plt.ylabel('True label')
    plt.xticks(np.arange(len(np.unique(y_true))), np.unique(y_true))
    plt.yticks(np.arange(len(np.unique(y_true))), np.unique(y_true))
    plt.tight_layout()

    # Save plot to BytesIO object
    img_buf = BytesIO()
    plt.savefig(img_buf, format='png')
    img_buf.seek(0)
    img_str = base64.b64encode(img_buf.read()).decode('utf-8')

    plt.close()

    return report, img_str


def classify_packet_real_time(source_ip):
    # Placeholder classification logic for real-time data.
    # Check if the source IP is in the malware dictionary
    if source_ip in malware_dict:
        return malware_dict[source_ip]
    else:
        # Retrieve actual malware information from an external source (replace with your actual API endpoint)
        actual_malware_info = get_actual_malware_info(source_ip)
        if actual_malware_info:
            malware_dict[source_ip] = actual_malware_info
            return actual_malware_info
        else:
            return "Benign"

def get_actual_malware_info(source_ip):
    # Replace this URL with your actual API endpoint
    api_url = f"https://your-malware-api.com/get_malware_info?ip={source_ip}"

    try:
        response = requests.get(api_url)
        if response.status_code == 200:
            # Assuming the API returns the malware information in JSON format
            malware_info = response.json()
            return malware_info.get('malware_name', 'Benign')  # Replace 'malware_name' with the actual key in your API response
    except Exception as e:
        print(f"Error retrieving malware information: {e}")

    return None

def pcap_to_csv_real_time(packet):
    row = {}
    if IP in packet and TCP in packet:
        row['Flow ID'] = str(packet[IP].src) + '-' + str(packet[IP].dst) + '-' + str(packet[TCP].sport) + '-' + str(packet[TCP].dport)
        row['Source IP'] = packet[IP].src
        row['Destination IP'] = packet[IP].dst
        row['Source Port'] = packet[TCP].sport
        row['Destination Port'] = packet[TCP].dport
        row['Protocol'] = packet[IP].proto
        row['Timestamp'] = packet.time
        row['Total Length of Fwd Packets'] = packet[IP].len if packet[IP].src == row['Source IP'] else 0
        row['Total Length of Bwd Packets'] = packet[IP].len if packet[IP].dst == row['Destination IP'] else 0
        row['Fwd Packet Length Mean'] = packet[IP].len / packet[IP].ttl if packet[IP].src == row['Source IP'] else 0
        row['Bwd Packet Length Mean'] = packet[IP].len / packet[IP].ttl if packet[IP].dst == row['Destination IP'] else 0
        row['Bwd Packet Length Min'] = packet[IP].len if packet[IP].dst == row['Destination IP'] else 0
        row['Bwd Packet Length Std'] = 0  # Placeholder for Std calculation
        row['Flow Bytes/s'] = packet[IP].len / packet.time if packet.time != 0 else 0
        row['Flow Packets/s'] = 1 / packet.time if packet.time != 0 else 0
        row['FIN Flag Count'] = 1 if packet[TCP].flags & 0x01 else 0
        row['SYN Flag Count'] = 1 if packet[TCP].flags & 0x02 else 0
        row['RST Flag Count'] = 1 if packet[TCP].flags & 0x04 else 0
        row['PSH Flag Count'] = 1 if packet[TCP].flags & 0x08 else 0
        row['ACK Flag Count'] = 1 if packet[TCP].flags & 0x10 else 0
        row['URG Flag Count'] = 1 if packet[TCP].flags & 0x20 else 0
        row['Init_Win_bytes_forward'] = packet[TCP].window if packet[IP].src == row['Source IP'] else 0
        row['Init_Win_bytes_backward'] = packet[TCP].window if packet[IP].dst == row['Destination IP'] else 0
        row['min_seg_size_forward'] = packet[TCP].options[2][1] if packet[TCP].options and len(packet[TCP].options) > 2 else 0
        row['Flow IAT Max'] = packet.time if packet.time != 0 else 0

        # Add label based on real-time classification logic
        label = classify_packet_real_time(packet[IP].src)
        row['Label'] = label

        if label == "Benign":
            # If label is "Benign," set specific fields to 0 for this row
            row['Fwd Packet Length Mean'] = 0
            row['Bwd Packet Length Std'] = 0

            # Create a new row with all values set to 0
            zero_row = {key: 0 for key in row.keys()}
            return [list(row.values()), list(zero_row.values())]

        return [list(row.values())]

    return None



@app.route('/pcap', methods=['GET', 'POST'])
def pcap():
    message = None

    if request.method == 'POST':
        pcap_file = request.files['pcap_file']
        if pcap_file and pcap_file.filename.endswith('.pcap'):
            # Save the uploaded file to a temporary location
            temp_pcap = os.path.join(tempfile.gettempdir(), 'temp.pcap')
            pcap_file.save(temp_pcap)

            # Read the pcap file in real-time
            packets = rdpcap(temp_pcap)

            # Create a temporary CSV file
            temp_csv = os.path.join(tempfile.gettempdir(), 'temp.csv')
            with open(temp_csv, 'w', newline='') as csv_file:
                csv_writer = csv.writer(csv_file)

                # Write the header row
                header_row = ["Flow ID", "Source IP", "Destination IP", "Source Port", "Destination Port",
                              "Protocol", "Timestamp", "Total Length of Fwd Packets", "Total Length of Bwd Packets",
                              "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Bwd Packet Length Min",
                              "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "FIN Flag Count",
                              "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
                              "URG Flag Count", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
                              "min_seg_size_forward", "Flow IAT Max", "Label"]
                csv_writer.writerow(header_row)

                # Write real-time data to CSV
                for packet in packets:
                    csv_data_rows = pcap_to_csv_real_time(packet)
                    if csv_data_rows:
                        csv_writer.writerows(csv_data_rows)

            message = "Conversion successful!"

            # Return the CSV file as a response
            return send_file(temp_csv, as_attachment=True, download_name="converted_data.csv")

    return render_template('pcap.html', message=message)



@app.route('/download', methods=['GET'])
def download_file():
    temp_csv = os.path.join(tempfile.gettempdir(), 'temp.csv')
    return send_file(temp_csv, as_attachment=True)



@app.route('/result_page')
def result_page():
    rf_accuracy = request.args.get('rf_accuracy', type=float)
    dt_accuracy = request.args.get('dt_accuracy', type=float)
    mlp_accuracy = request.args.get('mlp_accuracy', type=float)
    svm_accuracy = request.args.get('svm_accuracy', type=float)

    rf_report = request.args.get('rf_report')
    dt_report = request.args.get('dt_report')
    svm_report = request.args.get('svm_report')
    mlp_report = request.args.get('mlp_report')
    best_model = request.args.get('best_model')
    best_accuracy = request.args.get('best_accuracy', type=float)
    message1 = request.args.get('message1', '')
    message2 = request.args.get('message2', '')
    
    


    # Assuming you have calculated some data to plot
    # For example purposes, let's create a simple bar plot
    models = ['Random Forest', 'Decision Tree', 'SVM', 'MLP']
    accuracies = [rf_accuracy, dt_accuracy, svm_accuracy, mlp_accuracy]
    colors = ['blue', 'green', 'red', 'orange']  # Define different colors for bars

    # Create a bar plot with different colors for each model
    plt.figure(figsize=(8, 4))
    bars = plt.bar(models, accuracies, color=colors)
    plt.xlabel('Models')
    plt.ylabel('Accuracy')
    plt.title('Accuracy of Different Models')
    plt.ylim(0, 1)  # Set y-axis limit from 0 to 1 (assuming accuracy range)
    plt.tight_layout()

    # Assigning labels to the bars
    for bar, model, accuracy in zip(bars, models, accuracies):
        plt.text(bar.get_x() + bar.get_width() / 2 - 0.15, bar.get_height() + 0.02, f'{accuracy:.2f}', ha='center', va='bottom')

    # Save the plot to a temporary file or buffer
    plot_file = 'static/plot.png'  # Save plot in the static folder
    plt.savefig(plot_file)
    plt.close()
    
    report, img_str = generate_classification_report()
    

    
    return render_template('result_page.html', rf_accuracy=rf_accuracy, dt_accuracy=dt_accuracy,
                           mlp_accuracy=mlp_accuracy, svm_accuracy=svm_accuracy,
                           best_model=best_model, rf_report=rf_report, dt_report=dt_report,
                           svm_report=svm_report, mlp_report=mlp_report, best_accuracy=best_accuracy,
                           plot_file=plot_file, report=report, img_str=img_str, message1=message1, message2=message2) 


@app.route('/print_data', methods=['GET', 'POST'])
def print_data():
    if request.method == 'POST':
        conn = sqlite3.connect('data.db')
        c = conn.cursor()
        c.execute("SELECT content FROM uploaded_data ORDER BY id DESC LIMIT 1")
        uploaded_content = c.fetchone()
        conn.close()
        if uploaded_content:
            data = uploaded_content[0]
            csv_data = StringIO(data)
            csv_reader = csv.reader(csv_data)
            rows = [row for row in csv_reader]  # Store rows in a list

            return render_template('print_data.html', rows=rows)  # Pass rows to the template

        return "No uploaded data found."

    return render_template('print_data.html')  # You can create a print_data.html template to display this endpoint

if __name__ == '__main__':
    app.run(debug=True)