from flask import Flask, request, jsonify
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model
import joblib

app = Flask(__name__)

# Load the trained model
model = load_model("Malicious_URL_Prediction.h5")

@app.route('/')
def home():
    return "Malicious URL Detection API is running!"

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()

    # Expected input: JSON with 16 features
    features = ['hostname_length', 'path_length', 'fd_length', 'count-', 'count@', 'count?', 
                'count%', 'count.', 'count=', 'count-http', 'count-https', 'count-www', 
                'count-digits', 'count-letters', 'count_dir', 'use_of_ip']

    try:
        input_data = [data[feature] for feature in features]
        input_array = np.array(input_data).reshape(1, -1)

        prediction = model.predict(input_array)[0][0]
        result = "malicious" if prediction >= 0.5 else "legitimate"

        return jsonify({"prediction": result, "confidence": float(prediction)})

    except KeyError as e:
        return jsonify({"error": f"Missing feature: {str(e)}"}), 400

if __name__ == '__main__':
    app.run(debug=True)
