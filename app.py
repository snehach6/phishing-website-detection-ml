import streamlit as st
import pandas as pd
import numpy as np
import joblib
import requests
import re

from bs4 import BeautifulSoup
from urllib.parse import urlparse

# ---------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------

st.set_page_config(
    page_title="Phishing Website Detection",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ Phishing Website Detection")

st.write(
    "Enter a website URL below to check whether it is "
    "likely to be **Phishing** or **Legitimate**."
)

st.divider()


# ---------------------------------------------------
# LOAD TRAINED RANDOM FOREST MODEL
# ---------------------------------------------------
@st.cache_resource
def load_model():
    model = joblib.load("models/phishing_model.pkl")
    return model

model = load_model()




# ---------------------------------------------------
# FEATURE EXTRACTION
# ---------------------------------------------------

def extract_features(url):

    # Add protocol if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    domain = parsed.netloc
    path = parsed.path
    query = parsed.query

    # Complete URL
    full_url = url


    # ------------------------------------------------
    # URL FEATURES
    # ------------------------------------------------

    url_length = len(full_url)

    domain_length = len(domain)


    # Check whether domain is an IP address
    is_domain_ip = 1 if re.match(
        r"^(?:\d{1,3}\.){3}\d{1,3}$",
        domain.split(":")[0]
    ) else 0


    # Top Level Domain
    tld = domain.split(".")[-1] if "." in domain else ""

    tld_length = len(tld)


    # Number of subdomains
    domain_parts = domain.split(".")

    no_of_subdomain = max(
        len(domain_parts) - 2,
        0
    )


    # Special characters
    no_of_equals = full_url.count("=")

    no_of_qmark = full_url.count("?")

    no_of_ampersand = full_url.count("&")


    special_chars = "!@#$%^&*()_+-=[]{}|;:',.<>?/`~"

    no_of_other_special_chars = sum(
        1
        for char in full_url
        if char in special_chars
    )


    # Letters
    no_of_letters = sum(
        1
        for char in full_url
        if char.isalpha()
    )


    # Digits
    no_of_digits = sum(
        1
        for char in full_url
        if char.isdigit()
    )


    # Ratios
    letter_ratio = (
        no_of_letters / url_length
        if url_length > 0
        else 0
    )


    digit_ratio = (
        no_of_digits / url_length
        if url_length > 0
        else 0
    )


    special_char_ratio = (
        no_of_other_special_chars / url_length
        if url_length > 0
        else 0
    )


    # ------------------------------------------------
    # OBFUSCATION
    # ------------------------------------------------

    obfuscated_chars = sum(
        1
        for char in full_url
        if char in "%@"
    )


    has_obfuscation = (
        1 if obfuscated_chars > 0 else 0
    )


    obfuscation_ratio = (
        obfuscated_chars / url_length
        if url_length > 0
        else 0
    )


    # ------------------------------------------------
    # HTTPS
    # ------------------------------------------------

    is_https = (
        1 if parsed.scheme == "https" else 0
    )


    # ------------------------------------------------
    # DEFAULT FEATURES
    # ------------------------------------------------

    url_similarity_index = 0.0

    char_continuation_rate = 0.0

    tld_legitimate_prob = 0.0

    url_char_prob = 0.0


    # ------------------------------------------------
    # HTML FEATURES
    # ------------------------------------------------

    line_of_code = 0

    largest_line_length = 0

    has_title = 0

    domain_title_match_score = 0.0

    url_title_match_score = 0.0

    has_favicon = 0

    robots = 0

    is_responsive = 0

    no_of_url_redirect = 0

    no_of_self_redirect = 0

    has_description = 0

    no_of_popup = 0

    no_of_iframe = 0

    has_external_form_submit = 0

    has_social_net = 0

    has_submit_button = 0

    has_hidden_fields = 0

    has_password_field = 0

    bank = 0

    pay = 0

    crypto = 0

    has_copyright_info = 0

    no_of_image = 0

    no_of_css = 0

    no_of_js = 0

    no_of_self_ref = 0

    no_of_empty_ref = 0

    no_of_external_ref = 0


    # ------------------------------------------------
    # FETCH WEBSITE
    # ------------------------------------------------

    try:

        response = requests.get(
            url,
            timeout=5,
            headers={
                "User-Agent": "Mozilla/5.0"
            },
            allow_redirects=True
        )


        html = response.text


        soup = BeautifulSoup(
            html,
            "html.parser"
        )


        # ------------------------------------------------
        # HTML FEATURES
        # ------------------------------------------------

        lines = html.splitlines()


        line_of_code = len(lines)


        if lines:

            largest_line_length = max(
                len(line)
                for line in lines
            )


        # ------------------------------------------------
        # TITLE
        # ------------------------------------------------

        title_tag = soup.find("title")


        if title_tag:

            has_title = 1

            title = title_tag.get_text(
                strip=True
            ).lower()

        else:

            title = ""


        # ------------------------------------------------
        # DESCRIPTION
        # ------------------------------------------------

        description = soup.find(
            "meta",
            attrs={
                "name": "description"
            }
        )


        has_description = (
            1 if description else 0
        )


        # ------------------------------------------------
        # FAVICON
        # ------------------------------------------------

        favicon = soup.find(
            "link",
            rel=lambda x:
                x and "icon" in x
        )


        has_favicon = (
            1 if favicon else 0
        )


        # ------------------------------------------------
        # RESPONSIVE
        # ------------------------------------------------

        viewport = soup.find(
            "meta",
            attrs={
                "name": "viewport"
            }
        )


        is_responsive = (
            1 if viewport else 0
        )


        # ------------------------------------------------
        # IFRAMES
        # ------------------------------------------------

        no_of_iframe = len(
            soup.find_all("iframe")
        )


        # ------------------------------------------------
        # IMAGES
        # ------------------------------------------------

        no_of_image = len(
            soup.find_all("img")
        )


        # ------------------------------------------------
        # CSS
        # ------------------------------------------------

        no_of_css = len(
            soup.find_all(
                "link",
                rel="stylesheet"
            )
        )


        # ------------------------------------------------
        # JAVASCRIPT
        # ------------------------------------------------

        no_of_js = len(
            soup.find_all("script")
        )


        # ------------------------------------------------
        # FORMS
        # ------------------------------------------------

        forms = soup.find_all("form")


        # ------------------------------------------------
        # SUBMIT BUTTONS
        # ------------------------------------------------

        submit_buttons = soup.find_all(
            "input",
            type="submit"
        )


        submit_buttons += soup.find_all(
            "button"
        )


        has_submit_button = (
            1 if len(submit_buttons) > 0 else 0
        )


        # ------------------------------------------------
        # PASSWORD FIELD
        # ------------------------------------------------

        password_fields = soup.find_all(
            "input",
            type="password"
        )


        has_password_field = (
            1 if len(password_fields) > 0 else 0
        )


        # ------------------------------------------------
        # HIDDEN FIELDS
        # ------------------------------------------------

        hidden_fields = soup.find_all(
            "input",
            type="hidden"
        )


        has_hidden_fields = (
            1 if len(hidden_fields) > 0 else 0
        )


        # ------------------------------------------------
        # EXTERNAL FORM SUBMISSION
        # ------------------------------------------------

        for form in forms:

            action = form.get(
                "action",
                ""
            )


            if action.startswith("http"):

                if domain not in action:

                    has_external_form_submit = 1


        # ------------------------------------------------
        # SOCIAL NETWORK
        # ------------------------------------------------

        social_words = [
            "facebook",
            "twitter",
            "instagram",
            "linkedin",
            "youtube"
        ]


        page_text = soup.get_text(
            " ",
            strip=True
        ).lower()


        has_social_net = int(
            any(
                word in page_text
                for word in social_words
            )
        )


        # ------------------------------------------------
        # BANKING KEYWORDS
        # ------------------------------------------------

        banking_words = [
            "bank",
            "banking",
            "account",
            "credit card"
        ]


        bank = int(
            any(
                word in page_text
                for word in banking_words
            )
        )


        # ------------------------------------------------
        # PAYMENT KEYWORDS
        # ------------------------------------------------

        payment_words = [
            "payment",
            "paypal",
            "pay",
            "card",
            "checkout"
        ]


        pay = int(
            any(
                word in page_text
                for word in payment_words
            )
        )


        # ------------------------------------------------
        # CRYPTOCURRENCY
        # ------------------------------------------------

        crypto_words = [
            "bitcoin",
            "crypto",
            "ethereum",
            "wallet"
        ]


        crypto = int(
            any(
                word in page_text
                for word in crypto_words
            )
        )


        # ------------------------------------------------
        # COPYRIGHT
        # ------------------------------------------------

        has_copyright_info = int(
            "copyright" in page_text
            or "©" in html
        )


        # ------------------------------------------------
        # REFERENCES
        # ------------------------------------------------

        links = soup.find_all("a")


        for link in links:

            href = link.get("href")


            if not href:

                no_of_empty_ref += 1


            elif href.startswith("#"):

                no_of_self_ref += 1


            elif href.startswith("http"):

                if domain in href:

                    no_of_self_ref += 1

                else:

                    no_of_external_ref += 1


        # ------------------------------------------------
        # REDIRECTS
        # ------------------------------------------------

        no_of_url_redirect = len(
            response.history
        )


        no_of_self_redirect = 0


        # ------------------------------------------------
        # DOMAIN / TITLE SIMILARITY
        # ------------------------------------------------

        domain_words = set(
            re.findall(
                r"[a-zA-Z]+",
                domain.lower()
            )
        )


        title_words = set(
            re.findall(
                r"[a-zA-Z]+",
                title
            )
        )


        if title_words:

            common_words = (
                domain_words & title_words
            )


            domain_title_match_score = (
                len(common_words)
                / len(title_words)
            )


        # ------------------------------------------------
        # URL / TITLE SIMILARITY
        # ------------------------------------------------

        url_words = set(
            re.findall(
                r"[a-zA-Z]+",
                full_url.lower()
            )
        )


        if title_words:

            common_url_words = (
                url_words & title_words
            )


            url_title_match_score = (
                len(common_url_words)
                / len(title_words)
            )


    except Exception:

        pass


    # ------------------------------------------------
    # CREATE FEATURE VECTOR
    # ------------------------------------------------

    features = {

        "URLLength":
            url_length,

        "DomainLength":
            domain_length,

        "IsDomainIP":
            is_domain_ip,

        "URLSimilarityIndex":
            url_similarity_index,

        "CharContinuationRate":
            char_continuation_rate,

        "TLDLegitimateProb":
            tld_legitimate_prob,

        "URLCharProb":
            url_char_prob,

        "TLDLength":
            tld_length,

        "NoOfSubDomain":
            no_of_subdomain,

        "HasObfuscation":
            has_obfuscation,

        "NoOfObfuscatedChar":
            obfuscated_chars,

        "ObfuscationRatio":
            obfuscation_ratio,

        "NoOfLettersInURL":
            no_of_letters,

        "LetterRatioInURL":
            letter_ratio,

        "NoOfDegitsInURL":
            no_of_digits,

        "DegitRatioInURL":
            digit_ratio,

        "NoOfEqualsInURL":
            no_of_equals,

        "NoOfQMarkInURL":
            no_of_qmark,

        "NoOfAmpersandInURL":
            no_of_ampersand,

        "NoOfOtherSpecialCharsInURL":
            no_of_other_special_chars,

        "SpacialCharRatioInURL":
            special_char_ratio,

        "IsHTTPS":
            is_https,

        "LineOfCode":
            line_of_code,

        "LargestLineLength":
            largest_line_length,

        "HasTitle":
            has_title,

        "DomainTitleMatchScore":
            domain_title_match_score,

        "URLTitleMatchScore":
            url_title_match_score,

        "HasFavicon":
            has_favicon,

        "Robots":
            robots,

        "IsResponsive":
            is_responsive,

        "NoOfURLRedirect":
            no_of_url_redirect,

        "NoOfSelfRedirect":
            no_of_self_redirect,

        "HasDescription":
            has_description,

        "NoOfPopup":
            no_of_popup,

        "NoOfiFrame":
            no_of_iframe,

        "HasExternalFormSubmit":
            has_external_form_submit,

        "HasSocialNet":
            has_social_net,

        "HasSubmitButton":
            has_submit_button,

        "HasHiddenFields":
            has_hidden_fields,

        "HasPasswordField":
            has_password_field,

        "Bank":
            bank,

        "Pay":
            pay,

        "Crypto":
            crypto,

        "HasCopyrightInfo":
            has_copyright_info,

        "NoOfImage":
            no_of_image,

        "NoOfCSS":
            no_of_css,

        "NoOfJS":
            no_of_js,

        "NoOfSelfRef":
            no_of_self_ref,

        "NoOfEmptyRef":
            no_of_empty_ref,

        "NoOfExternalRef":
            no_of_external_ref
    }


    return pd.DataFrame([features])


# ---------------------------------------------------
# WEBSITE URL INPUT
# ---------------------------------------------------

url_input = st.text_input(
    "🌐 Website URL",
    placeholder="https://example.com"
)


# ---------------------------------------------------
# ANALYZE WEBSITE BUTTON
# ---------------------------------------------------

if st.button(
    "🔎 Analyze Website",
    use_container_width=True
):

    if not url_input:

        st.warning(
            "⚠️ Please enter a website URL."
        )

    else:

        with st.spinner(
            "Analyzing website..."
        ):

            try:

                # ---------------------------------------
                # EXTRACT FEATURES
                # ---------------------------------------

                features = extract_features(
                    url_input
                )


                # ---------------------------------------
                # DISPLAY ALL 50 FEATURES
                # ---------------------------------------

                st.divider()

                st.subheader(
                    "📊 Extracted Website Features"
                )

                st.write(
                    "The following 50 features are "
                    "used by the machine learning model "
                    "for prediction."
                )


                # Transpose the dataframe
                # so every feature appears as one row

                feature_display = (
                    features
                    .T
                    .reset_index()
                )


                feature_display.columns = [
                    "Feature",
                    "Value"
                ]


                # Show all 50 features vertically

                with st.expander(
                    "📋 View All 50 Features",
                    expanded=True
                ):

                    st.dataframe(
                        feature_display,
                        use_container_width=True,
                        height=650,
                        hide_index=True
                    )


                # ---------------------------------------
                # MODEL PREDICTION
                # ---------------------------------------

                prediction = model.predict(
                    features
                )[0]


                # ---------------------------------------
                # MODEL CONFIDENCE
                # ---------------------------------------

                if hasattr(
                    model,
                    "predict_proba"
                ):

                    probability = (
                        model
                        .predict_proba(
                            features
                        )[0]
                    )


                    confidence = (
                        max(probability) * 100
                    )

                else:

                    confidence = None

                # ---------------------------------------
                # RESULT
                # ---------------------------------------

                st.divider()

                st.subheader(
                    "🔍 Prediction Result"
                )


                if prediction == 1:

                    st.error(
                        "🚨 PHISHING WEBSITE"
                    )


                    st.write(
                        "The machine learning model "
                        "classifies this website as "
                        "potentially phishing."
                    )

                else:

                    st.success(
                        "✅ LEGITIMATE WEBSITE"
                    )


                    st.write(
                        "The machine learning model "
                        "classifies this website as "
                        "likely legitimate."
                    )


                # ---------------------------------------
                # CONFIDENCE
                # ---------------------------------------

                if confidence is not None:

                    st.metric(
                        "Model Confidence",
                        f"{confidence:.2f}%"
                    )


            except Exception as e:

                st.error(
                    "❌ An error occurred while "
                    "analyzing the URL."
                )


                st.write(
                    str(e)
                )