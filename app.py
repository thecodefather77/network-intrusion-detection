import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import streamlit as st
import altair as alt
import joblib
import sklearn
import hashlib

import streamlit as st
import hashlib

# ---------------- AUTH CONFIG ---------------- #

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

USERS = {
    "admin": hash_password("admin123"),
    "user": hash_password("network@123")
}

def login():
    st.markdown("## 🔐 Login Required")

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    col1, col2 = st.columns(2)
    with col1:
        login_btn = st.button("Login")
    with col2:
        st.write("")

    if login_btn:
        if username in USERS and USERS[username] == hash_password(password):
            st.session_state["authenticated"] = True
            st.session_state["user"] = username
            st.success("Login successful")
            st.rerun()
        else:
            st.error("Invalid username or password")

# Initialize session state
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

# Block app access if not logged in
if not st.session_state["authenticated"]:
    login()
    st.stop()

with st.sidebar:
    st.success(f"Logged in as {st.session_state['user']}")
    if st.button("Logout"):
        st.session_state["authenticated"] = False
        st.rerun()

# Setup the Page Config
st.set_page_config(layout="wide")

# Title of the Dashboard
st.title("Network Traffic Analytics and Intrusion Detection", anchor = False)

#Importing and Caching the data

@st.cache_resource
def load_dataset():
    return pd.read_parquet(r"data/dashboard_data.parquet")
def load_traffic_count_data():
    return pd.read_csv(r"data/aggregation_tables/traffic_count.csv")
def load_attack_type_distribution():
    return pd.read_csv(r"data/aggregation_tables/attack_distributions/attack_type_dist.csv")
def load_attack_category_distribution():
    return pd.read_csv(r"data/aggregation_tables/attack_distributions/attack_category_dist.csv")
def load_feature_importance():
    return pd.read_csv(r"data/feature_importance.csv")

# Store the data in a DataFrame
df_analysis = load_dataset()
traffic_count_data = load_traffic_count_data()
attack_type_dist = load_attack_type_distribution()
attack_category_dist = load_attack_category_distribution()
feature_importance = load_feature_importance()

# Traffic Percentage DataFrame
traffic_percentage = pd.DataFrame()
traffic_percentage['Weekday'] = traffic_count_data['Weekday']
traffic_percentage['Benign Traffic Percentage'] = round(traffic_count_data['Benign Traffic'] / traffic_count_data['Total Traffic'], 4) * 100
traffic_percentage['Attack Traffic Percentage'] = round(traffic_count_data['Attack Traffic'] / traffic_count_data['Total Traffic'], 4) * 100

# Title of the Dashboard
#st.title("Network Traffic Analytics and Intrusion Detection", anchor = False)


# Create Two Tabs: One for analytics dashboard and one for ML predictions
tab1, tab2 , tab3= st.tabs([
    "Analytics",
    "Top 5 Features",
    "Intrusion Detection"
])

# Analytics Dashboard
with tab1:
    st.title("Network Traffic Analytics Dashboard", text_alignment = 'center', anchor = False)

    # Calculating Metrics
    total_tarffic = df_analysis.shape[0]
    benign_traffic = df_analysis[(df_analysis['attack'] == 0)].shape[0]
    attack_traffic = df_analysis[(df_analysis['attack'] == 1)].shape[0]
    attack_percentage = attack_traffic / total_tarffic

    # Displaying the Metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Traffic", f"{round((total_tarffic / 100000), 2)} Million")
    col2.metric("Total Benign Traffic", f"{round((benign_traffic / 100000), 2)} Million")
    col3.metric("Total Attacks", f"{round((attack_traffic / 100000), 2)} Lakh")
    col4.metric("Attack Percentage", f"{round((attack_percentage * 100), 2)} %")

    # Weekday Order to sort the DataFrame
    weekday_order = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]

    # Sorting each DataFrame according to the Weekday Order
    traffic_count_data["Weekday"] = pd.Categorical(
        traffic_count_data["Weekday"],
        categories = weekday_order,
        ordered = True
    )

     # Sorting each DataFrame according to the Weekday Order
    traffic_percentage["Weekday"] = pd.Categorical(
        traffic_percentage["Weekday"],
        categories = weekday_order,
        ordered = True
    )

    # Plotting the Line Chart
    line1, line2 = st.columns(2)
    with line1:
        st.subheader("Weekly Network Traffic", text_alignment = 'center', anchor = False)
        st.line_chart(
            data = traffic_count_data,
            x = 'Weekday',
            y = ['Total Traffic', 'Benign Traffic', 'Attack Traffic'],
            x_label = "",
            y_label = "Network Traffic",
            height = 500
        ) 
    with line2:
        st.subheader("Weekly Network Traffic Distribution (%)", text_alignment = 'center', anchor = False)
        st.line_chart(
            data = traffic_percentage,
            x = 'Weekday',
            y = ['Benign Traffic Percentage', 'Attack Traffic Percentage'],
            x_label = "",
            y_label = "Network Traffic Percentage (%)",
            height = 500
        )

    dist1, dist2 = st.columns(2)
    with dist1:
        st.subheader("Network Attack Type Distribution (%)", anchor = False, text_alignment = 'center')
        attack_type_dist['Distribution'] = round((attack_type_dist['Distribution'] * 100), 2)
        st.bar_chart(
            data = attack_type_dist,
            x = 'Attack Type',
            y = 'Distribution',
            x_label = "",
            y_label = 'Percentage Distribution (%)',
            height = 500
        )
    with dist2:
        st.subheader("Network Attack Category Distribution (%)", anchor = False, text_alignment = 'center')
        attack_category_dist['Distribution'] = round((attack_category_dist['Distribution'] * 100), 2)
        st.bar_chart(
            data = attack_category_dist,
            x = 'Attack Type',
            y = 'Distribution',
            x_label = "",
            y_label = 'Percentage Distribution (%)',
            height = 500
        )

# Top 5 Features Dashboard
with tab2:
    
    # Dashboard Title
    st.title("Top 5 Features According That Decides the Network Behaviour", text_alignment = 'center', anchor = False)
    st.subheader("The Top 5 Features Account for About 50% of the ML Model’s Total Importance.", 
                  anchor = False, text_alignment = 'center')

    # Extracting the Top 5 Features
    feature_importance.sort_values(by = 'Importance', ascending = False, ignore_index = True, inplace = True)
    feature_importance_top10 = feature_importance.head(5)
    feature_importance_top10['Importance'] = feature_importance_top10['Importance'] * 100

    # Ploting the Top 5 Features
    feat1, feat2 = st.columns(2)

    # Cumulative Feature Importance Chart
    with feat1:
        st.subheader("Cumulative Feature Importance", text_alignment = 'center', anchor = False)
        st.line_chart(
            data = round((feature_importance['Cumulative Sum'] * 100), 2),
            y_label = 'Cumulative Feature Importance (%)',
            x_label = 'Top N Features',
            height = 500
        )
    
    # Top 1st Feature - Backward Packet Length Mean
    with feat2:
        st.subheader("Top 1st Feature - Backward Packet Length Mean", text_alignment = 'center', anchor = False)
        df1 = df_analysis.groupby(by = 'attack_type').agg(mean_bwd_packet_length = ('bwd_packet_length_mean', 'mean')).reset_index()
        st.bar_chart(
            data = df1,
            x = 'attack_type',
            y = 'mean_bwd_packet_length',
            y_label = 'Average Backward Packet Length',
            x_label = 'Attack Type',
            height = 500
        )
        
    feat3, feat4 = st.columns(2)

    # Top 2nd Feature - Backward Packet Length Standard Deviation
    with feat3:
        st.subheader("Top 2nd Feature - Backward Packet Length Standard Deviation", text_alignment = 'center', anchor = False)
        df2 = df_analysis.groupby(by = 'attack_type').agg(mean_std_bwd_packet_length = ('bwd_packet_length_std', 'mean')).reset_index()
        st.bar_chart(
            data = df2,
            x = 'attack_type',
            y = 'mean_std_bwd_packet_length',
            y_label = 'Average Standard Deviation Backward Packet Length',
            x_label = 'Attack Type',
            height = 500
        )

    # Top 3rd Feature - Average Backward Segment Size
    with feat4:
        st.subheader("Top 3rd Feature - Average Backward Segment Size", text_alignment = 'center', anchor = False)
        df3 = df_analysis.groupby(by = 'attack_type').agg(average_backward_segment_size = ('avg_bwd_segment_size', 'mean')).reset_index()
        st.bar_chart(
            data = df3,
            x = 'attack_type',
            y = 'average_backward_segment_size',
            y_label = 'Average Backward Segment Size',
            x_label = 'Attack Type',
            height = 500
        )
    feat5, feat6 = st.columns(2)

    # Top 4th Feature - URD Flag Count
    with feat5:
        st.subheader("Top 4th Feature - URD Flag Count", text_alignment = 'center', anchor = False)
        df4 = df_analysis.groupby(by = 'attack_type').agg(avg_urg_flag_count = ('urg_flag_count', 'mean')).reset_index()
        st.bar_chart(
            data = df4,
            x = 'attack_type',
            y = 'avg_urg_flag_count',
            y_label = 'Average URG Flag Count',
            x_label = 'Attack Type',
            height = 500
        )

    # Top 5th Feature - Average Packet Size
    with feat6:
        st.subheader("Top 5th Feature - Average Packet Size", text_alignment = 'center', anchor = False)
        df5 = df_analysis.groupby(by = 'attack_type').agg(average_packet_size = ('average_packet_size', 'mean')).reset_index()
        st.bar_chart(
            data = df5,
            x = 'attack_type',
            y = 'average_packet_size',
            y_label = 'Average Packet Size',
            x_label = 'Attack Type',
            height = 500
        )

# ML Prediction Dashboard
with tab3:

    # Title of the Dashboard
    st.title("Network Intrusion Detection", text_alignment = 'center', anchor = False)
    st.header("This Machine Learning Model is built using XGBoost Algorithm", text_alignment = 'center', anchor = False)
    st.markdown(":violet-badge[:material/model_training: XGBoost] :green-badge[:material/check_circle: Model Loaded] :green-badge[:material/check_circle: Model Accuracy = 99%]", 
                text_alignment = 'center')
    st.header("This Model Works in 2 Steps: Binary Classification, then Multicalss Classification", anchor = False)
    
    # Loading the model and caching it
    @st.cache_resource
    def load_binary_model():
        return joblib.load("model//xgboost_pipeline.pkl")
    @st.cache_resource
    def load_multicalss_model():
        return joblib.load("model//multiclass_model.pkl")
    @st.cache_resource
    def load_encoder():
        return joblib.load("model//label_encoder.pkl")
    
    # Declaring the models
    binary_model = load_binary_model()
    multicalss_model = load_multicalss_model()
    encoder = load_encoder()
    
        # Uploading the CSV (Data we want to predict)
    uploaded_file = st.file_uploader('Upload CSV', type = ['csv'])

    # Custom Threshold
    THRESHOLD = 0.33997458

    if uploaded_file is not None:
        # Read the CSV file and store it as dataframe
        df = pd.read_csv(uploaded_file, dtype = 'float')

        # Feature Allinment check
        if hasattr(binary_model, "feature_names_in_"):
            df = df[binary_model.feature_names_in_]

        # Preductng probalilities
        probas = binary_model.predict_proba(df)[:, 1]

        # Applying custom threshold
        df['attack_probability'] = probas
        df['prediction'] = (probas >= THRESHOLD).astype(int)

        
        # Filtering the Attack Network
        df_multicalss = df[(df['prediction'] == 1)].drop(columns = ['attack_probability', 'prediction'])

        # Feature Allinment check
        if hasattr(multicalss_model, "feature_names_in_"):
            df_multicalss = df_multicalss[multicalss_model.feature_names_in_]

        # Predicting the Type of Attack
        attack_type = multicalss_model.predict(df_multicalss)
        df_multicalss['attack_type'] = encoder.inverse_transform(attack_type)

        # In the final df initialize the attack type as "Normal" for every traffic
        df['attack_type'] = "normal"

        # Update only the rows that exist in df_multiclass using the index
        df.loc[df_multicalss.index, 'attack_type'] = df_multicalss['attack_type']

        st.subheader("Security Prediction and Analysis")

        def highlight_prediction(row):
            if row["prediction"] == 1:
                return ["background-color: #FFCDD2; color: black"] * len(row)
            else:
                return ["background-color: #C8E6C9; color: black"] * len(row)

        st.dataframe(
            df.style.apply(highlight_prediction, axis=1),
            use_container_width=True
        )

        # UI Section: Metrics and Pie Chart
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            # Input Traffic Size
            st.metric("Total Traffic", len(df))

        with col2:
            # Benign Traffic In the Input Data
            normal_count = (df["prediction"] == 0).sum()
            st.metric("Normal Traffic", normal_count)
        
        with col3:
            # No of Attacks Predicted in the Input Data
            attack_count = (df["prediction"] == 1).sum()
            st.metric("Total Attacks Detected", attack_count, delta_color="inverse")

        with col4:
            # Percentge of Attack Behaviour
            attack_pred_percentage = attack_count / len(df)
            st.metric("Attack Predicted Percentage", f"{round((attack_pred_percentage * 100), 2)} %")

        #UI Section: Attack Breakdown KPI Cards
        st.subheader("Detected Attack Categories")
        
        # Calculate counts of specific attacks (excluding 'normal')
        attack_details = df[df['attack_type'] != "normal"]['attack_type'].value_counts()

        if not attack_details.empty:
            # Create a grid of columns (max 4 per row)
            num_cols = 4
            cols = st.columns(num_cols)
            
            for i, (name, count) in enumerate(attack_details.items()):
                col_idx = i % num_cols
                with cols[col_idx]:
                    st.metric(
                        label=f"🚨 {name.upper()}", 
                        value=count, 
                        delta="Attack", 
                        delta_color="inverse"
                    )
        else:
            st.success("No specific attack patterns identified in the flagged traffic.")

    else:
        # This shows when no file is uploaded
        st.info("Please Upload a CSV File to Predict.")