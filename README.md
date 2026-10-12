
# Phishing Website Detection Using Machine Learning

A machine learning project that analyzes website URLs and predicts whether a website may be legitimate or phishing.

## Overview

Phishing websites attempt to trick users into sharing sensitive information, such as passwords and financial details. This project explores machine learning techniques for identifying potentially suspicious websites from URL-related and website-related features.

The application uses Streamlit to provide an interactive interface for entering a URL and viewing a prediction.

## Features

- URL input through a Streamlit web interface
- URL and website feature extraction
- Prediction using a trained machine learning model
- Prediction confidence display, if supported by the model
- Interactive results for the submitted URL

## Tech Stack

- Python
- Pandas and NumPy
- Scikit-learn
- Joblib
- Streamlit
- Requests
- Beautiful Soup

## Project Structure

```text
PHISHING-WEBSITE-DETECTION/
├── app.py
├── models/
│   └── phishing_model.pkl
├── requirements.txt
├── README.md
└── .gitignore
```

*This is an example structure. Update it to match the actual files in your repository.*

## Installation and Setup

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd PHISHING-WEBSITE-DETECTION
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it on Windows:

```bash
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Run the application

```bash
python -m streamlit run app.py
```

Open the local URL displayed in the terminal.

## Dataset

The project uses the PhiUSIIL Phishing URL dataset for model development. Refer to the original dataset source and its licence or terms before redistributing the dataset.

## Model

The application loads a previously trained model from `models/phishing_model.pkl`. Document the model's training procedure, evaluation results, and feature requirements here.

## Limitations

Predictions are not a guarantee that a website is safe or malicious. Website access restrictions and unavailable HTML content can affect feature extraction. Do not enter passwords or other sensitive information into the application.

## Future Improvements

- Improve feature extraction when website requests fail
- Evaluate performance on unseen and newly collected URLs
- Improve model reproducibility and dependency management
- Deploy the application for online access

## Author

Sneha Ch.

## Disclaimer

This project is for educational and research purposes. Always verify suspicious websites through trusted security tools and practices.
=======
# phishing-website-detection-ml
A machine learning project that detects potentially phishing websites by analyzing URL and website features. Built using Python, Scikit-learn, and Streamlit, the application provides an interactive interface to classify URLs as potentially phishing or legitimate using a trained ML model.

