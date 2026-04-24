import streamlit as st
import joblib
from tensorflow.keras.models import load_model
from model_utils import final_decision

# ✅ Load models
calibrated_model = joblib.load("ml_model.pkl")
dl_model = load_model("dl_model.keras")

st.title("🔐 Phishing URL Detector")

url = st.text_input("Enter URL")

if st.button("Check"):
    if url:
        with st.spinner("Analyzing URL..."):
            label, confidence, reasons = final_decision(url,calibrated_model, dl_model)

        # ✅ UI Styling
        if label == "Phishing":
            st.error(f"🚨 {label}")
        elif label == "Suspicious":
            st.warning(f"⚠️ {label}")
        else:
            st.success(f"✅ {label}")

        st.write(f"Confidence: {confidence*100:.2f}%")

        with st.expander("Why this result?"):
            for r in reasons:
                st.write("- " + r)