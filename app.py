import streamlit as st
import numpy as np
import pickle
import warnings
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

import pickle

# Open the file in binary read mode
with open('pickle/model.pkl', 'rb') as file:
    gbc = pickle.load(file)


# Streamlit app
st.title("Phishing URL Detection")

# Input URL from the user
url = st.text_input("Enter URL")

if st.button("Check"):
    if url:
        # Feature extraction
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)

        # Prediction
        y_pred = gbc.predict(x)[0]
        y_pro_phishing = gbc.predict_proba(x)[0, 0]
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

        # Display the result
        if y_pred == 1:
            st.success("The URL is {0:.2f}% safe to visit.".format(y_pro_phishing * 100))
        else:
            st.error("The URL is {0:.2f}% unsafe to visit.".format(y_pro_non_phishing * 100))
    else:
        st.warning("Please enter a URL to check.")
