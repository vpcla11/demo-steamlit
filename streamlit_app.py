import msal
import streamlit as st
import requests
import pickle
import base64
from streamlit.logger import get_logger

logger = get_logger(__name__)

CLIENT_ID = "35779d1b-9b8f-48b8-b836-9f6e8e941c8e"
CLIENT_SECRET = "5sO8Q~WoDDN7DXnCsGoiIeu0XHtT8nOnRuTcOcSe"
TENANT_ID = "e0fd7f83-50c7-4540-8e09-0dafc1092723"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
REDIRECT_URI = "https://my-demo-st.streamlit.app/"
SCOPES = ["User.Read"]


def build_app():
    return msal.ConfidentialClientApplication(
        client_id=CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET
    )


# Encode flow to pass via query param (workaround)
def encode_flow(flow):
    return base64.urlsafe_b64encode(pickle.dumps(flow)).decode()


def decode_flow(encoded):
    return pickle.loads(base64.urlsafe_b64decode(encoded))


st.title("Microsoft Entra ID login")

app = build_app()

if "token" in st.session_state:
    token = st.session_state["token"]
    st.success(f"Welcome, {token['id_token_claims'].get('name')}")
    if st.button("Sign out"):
        st.session_state.clear()
        st.query_params.clear()
        st.rerun()
else:
    params = st.query_params

    if "code" in params and "flow_data" in params:
        try:
            flow = decode_flow(params["flow_data"])
            result = app.acquire_token_by_auth_code_flow(flow, params.to_dict())
            if "error" in result:
                st.error(f"Sign-in error: {result.get('error_description')}")
            else:
                st.session_state["token"] = result
                st.query_params.clear()
                st.rerun()
        except Exception as e:
            st.error(f"Error: {e}")
    else:
        flow = app.initiate_auth_code_flow(scopes=SCOPES, redirect_uri=REDIRECT_URI)
        if "auth_uri" in flow:
            # Append encoded flow to auth_uri
            encoded = encode_flow(flow)
            auth_url = f"{flow['auth_uri']}&flow_data={encoded}"
            st.link_button("Sign in with Microsoft", auth_url)
