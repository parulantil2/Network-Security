import streamlit as st
import pandas as pd
import pickle

# -------------------------------
# Load trained model
# -------------------------------
MODEL_PATH = "final_model/model.pkl"
with open(MODEL_PATH, "rb") as f:
    model = pickle.load(f)

# -------------------------------
# Feature names
# -------------------------------
features = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain",
    "SSLfinal_State", "Domain_registeration_length", "Favicon", "port",
    "HTTPS_token", "Request_URL", "URL_of_Anchor", "Links_in_tags", "SFH",
    "Submitting_to_email", "Abnormal_URL", "Redirect", "on_mouseover", "RightClick",
    "popUpWidnow", "Iframe", "age_of_domain", "DNSRecord", "web_traffic",
    "Page_Rank", "Google_Index", "Links_pointing_to_page", "Statistical_report"
]



label_map = {
    0: ("Phishing (Unsafe 🚨)", "❌", "red"),
    # 0: ("Suspicious (Be Careful ⚠️)", "⚠️", "orange"),
    1: ("Legitimate (Safe ✅)", "✅", "green")
}

# -------------------------------
# Streamlit Config
# -------------------------------
st.set_page_config(page_title="Phishing Detector", page_icon="🔍", layout="wide")

# -------------------------------
# Sidebar Info
# -------------------------------
st.sidebar.header("About this App")
st.sidebar.info("""
This tool predicts if a website is **Phishing** or **Legitimate**
based on URL and webpage features.  
Model: **Machine Learning (Pickle)**
""")

# -------------------------------
# Main Title
# -------------------------------
st.title("🔍 Phishing Website Detection")
st.markdown("Use the controls below to test if a site is **Safe** or **Unsafe**.")


# Feature explanations
feature_data = [
    ["having_IP_Address", "Whether the URL contains an IP address instead of a domain name (common in phishing).", "-1 = Yes (phishy), 1 = No"],
    ["URL_Length", "Length of the URL (longer URLs can indicate phishing).", "1 = Short, 0 = Medium, -1 = Long"],
    ["Shortining_Service", "Whether the URL uses a shortening service (e.g., bit.ly, tinyurl).", "-1 = Yes, 1 = No"],
    ["having_At_Symbol", "Presence of @ in URL (used to redirect).", "-1 = Yes, 1 = No"],
    ["double_slash_redirecting", "Position of // in URL (after protocol, okay; later means redirection).", "-1 = Suspicious, 1 = Safe"],
    ["Prefix_Suffix", "Whether the domain contains a hyphen - (often used in fake domains).", "-1 = Yes, 1 = No"],
    ["having_Sub_Domain", "Number of subdomains.", "1 = Few, 0 = Moderate, -1 = Many (phishy)"],
    ["SSLfinal_State", "Whether the SSL certificate is valid and trusted.", "1 = Valid, 0 = Expired/Self-signed, -1 = No HTTPS"],
    ["Domain_registeration_length", "Length of domain registration.", "-1 = ≤1 year (phishy), 1 = >1 year"],
    ["Favicon", "Whether favicon is loaded from same domain.", "1 = Same, -1 = Different"],
    ["port", "Whether non-standard ports are used.", "1 = Standard, -1 = Unusual"],
    ["HTTPS_token", "Whether 'https' appears in domain part of URL (fake).", "-1 = Yes, 1 = No"],
    ["Request_URL", "% of objects loaded from same domain.", "1 = ≥50%, -1 = <50%"],
    ["URL_of_Anchor", "% of anchor tags linking to other domains.", "1 = <31%, 0 = 31-67%, -1 = >67%"],
    ["Links_in_tags", "% of <Meta>, <Script>, and <Link> tags linked externally.", "1 = Low, 0 = Medium, -1 = High"],
    ["SFH", "Server Form Handler — where form data is submitted.", "1 = Same domain, 0 = Empty, -1 = External"],
    ["Submitting_to_email", "Whether form submits data to an email.", "-1 = Yes, 1 = No"],
    ["Abnormal_URL", "Whether URL identity matches WHOIS data.", "-1 = Mismatch, 1 = Match"],
    ["Redirect", "Number of redirects.", "1 = ≤1, 0 = 2–4, -1 = ≥4"],
    ["on_mouseover", "JavaScript tricks changing status bar.", "-1 = Yes, 1 = No"],
    ["RightClick", "Disabling right-click to hide source.", "-1 = Yes, 1 = No"],
    ["popUpWidnow", "Showing popup windows.", "-1 = Yes, 1 = No"],
    ["Iframe", "Using <iframe> to embed other pages.", "-1 = Yes, 1 = No"],
    ["age_of_domain", "Domain age in months.", "-1 = ≤6 months, 1 = >6 months"],
    ["DNSRecord", "Whether DNS record exists.", "-1 = No, 1 = Yes"],
    ["web_traffic", "Website’s Alexa rank or visitor count.", "-1 = Low, 0 = Medium, 1 = High"],
    ["Page_Rank", "Google PageRank score.", "-1 = Low, 1 = High"],
    ["Google_Index", "Whether the page is indexed by Google.", "-1 = No, 1 = Yes"],
    ["Links_pointing_to_page", "Number of external links pointing to the page.", "-1 = Low, 0 = Medium, 1 = High"],
    ["Statistical_report", "Whether URL/domain appears in phishing/malware databases.", "-1 = Yes, 1 = No"],
    ["predicted_column", "Target label: phishing, legitimate.", "1 = Legitimate, 0 = Phishing"]
]

# Convert to DataFrame
feature_df = pd.DataFrame(feature_data, columns=["Feature", "Meaning", "Typical Values"])

# -------------------------------
# Expander (clickable link)
# -------------------------------
with st.expander("ℹ️ Click here to see all feature details"):
    st.dataframe(feature_df)

# -------------------------------
# Feature Inputs in Columns
# -------------------------------
input_data = []
cols = st.columns(3)  # split into 3 columns

for idx, feat in enumerate(features):
    with cols[idx % 3]:
        val = st.selectbox(
            f"{feat}",
            options=[-1, 0, 1],
            index=1,
            help="-1 = Bad, 0 = Neutral, 1 = Good"
        )
        input_data.append(val)

# -------------------------------
# Predict Button
# -------------------------------
if st.button("🚀 Predict", use_container_width=True):
    df = pd.DataFrame([input_data], columns=features)
    pred = model.predict(df)[0]
    label, icon, color = label_map[pred]

    # Prediction Box
    st.markdown(
        f"<div style='padding:20px; border-radius:10px; background-color:{color}; color:white; font-size:20px; text-align:center;'>"
        f"{icon} Prediction: {label}</div>",
        unsafe_allow_html=True
    )

    # Show Probability if available
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(df)[0]
        classes = model.classes_  # actual labels from the trained model
    prob_df = pd.DataFrame({
        "Class": [label_map[c][0] for c in classes],
        "Probability": [round(p * 100, 2) for p in probs]
    })
    st.write("### Prediction Probabilities")
    st.dataframe(prob_df)
    #     prob_df = pd.DataFrame({
    #         "Class": [label_map[i][0] for i in label_map.keys()],
    #         "Probability": [round(p * 100, 2) for p in probs]
    #     })
    #     st.write("### Prediction Probabilities")
    #     st.dataframe(prob_df)

    # # Show Input Data
    # st.write("### Input Features")
    # st.dataframe(df)


# -------------------------------
# Batch Upload Section
# -------------------------------
st.markdown("---")
st.subheader("📂 Batch Prediction from CSV")
uploaded_file = st.file_uploader("Upload CSV with features", type=["csv"])
if uploaded_file:
    batch_df = pd.read_csv(uploaded_file)
    preds = model.predict(batch_df)
    batch_df["Prediction"] = [label_map[p][0] for p in preds]
    st.write("### Batch Results")
    st.dataframe(batch_df)

    # Download results
    csv = batch_df.to_csv(index=False).encode("utf-8")
    st.download_button("💾 Download Results", csv, "predictions.csv", "text/csv")



# import sys
# import os

# import certifi
# ca = certifi.where()

# from dotenv import load_dotenv
# load_dotenv()
# mongo_db_url = os.getenv("MONGODB_URL_KEY")
# print(mongo_db_url)
# import pymongo
# from networksecurity.exception.exception import NetworkSecurityException
# from networksecurity.logging.logger import logging
# from networksecurity.pipeline.training_pipeline import TrainingPipeline

# from fastapi.middleware.cors import CORSMiddleware
# from fastapi import FastAPI, File, UploadFile,Request
# from uvicorn import run as app_run
# from fastapi.responses import Response
# from starlette.responses import RedirectResponse
# import pandas as pd

# from networksecurity.utils.main_utils.utils import load_object

# from networksecurity.utils.ml_utils.model.estimator import NetworkModel


# client = pymongo.MongoClient(mongo_db_url, tlsCAFile=ca)

# from networksecurity.constant.training_pipeline import DATA_INGESTION_COLLECTION_NAME
# from networksecurity.constant.training_pipeline import DATA_INGESTION_DATABASE_NAME

# database = client[DATA_INGESTION_DATABASE_NAME]
# collection = database[DATA_INGESTION_COLLECTION_NAME]

# app = FastAPI()
# origins = ["*"]

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# from fastapi.templating import Jinja2Templates
# templates = Jinja2Templates(directory="./templates")

# @app.get("/", tags=["authentication"])
# async def index():
#     return RedirectResponse(url="/docs")

# @app.get("/train")
# async def train_route():
#     try:
#         train_pipeline=TrainingPipeline()
#         train_pipeline.run_pipeline()
#         return Response("Training is successful")
#     except Exception as e:
#         raise NetworkSecurityException(e,sys)
    
# @app.post("/predict")
# async def predict_route(request: Request,file: UploadFile = File(...)):
#     try:
#         df=pd.read_csv(file.file)
#         #print(df)
#         preprocesor=load_object("final_model/preprocessor.pkl")
#         final_model=load_object("final_model/model.pkl")
#         network_model = NetworkModel(preprocessor=preprocesor,model=final_model)
#         print(df.iloc[0])
#         y_pred = network_model.predict(df)
#         print(y_pred)
#         df['predicted_column'] = y_pred
#         print(df['predicted_column'])
#         #df['predicted_column'].replace(-1, 0)
#         #return df.to_json()
#         df.to_csv('prediction_output/output.csv')
#         table_html = df.to_html(classes='table table-striped')
#         #print(table_html)
#         return templates.TemplateResponse("table.html", {"request": request, "table": table_html})
        
#     except Exception as e:
#             raise NetworkSecurityException(e,sys)

    
# if __name__=="__main__":
#     app_run(app,host="localhost",port=8000)
#     # app_run(app,host="0.0.0.0",port=8000)
