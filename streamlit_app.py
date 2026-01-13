import msal
import streamlit as st
import pickle
import base64
from streamlit.logger import get_logger
import streamlit.components.v1 as components

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


@st.cache_resource
def get_flow_store():
    """Process-wide cache for flows (keyed by state)"""
    return {}


def encode_flow(flow) -> str:
    return base64.urlsafe_b64encode(pickle.dumps(flow)).decode()


def decode_flow(encoded):
    return pickle.loads(base64.urlsafe_b64decode(encoded))


st.title("Microsoft Entra ID login")

app = build_app()
flow_store = get_flow_store()

if "token" in st.session_state:
    token = st.session_state["token"]
    st.success(f"Welcome, {token['id_token_claims'].get('name')}")
    if st.button("Sign out"):
        st.session_state.clear()
        st.query_params.clear()
        st.rerun()
else:
    params = st.query_params
    st.info(f"DEBUG: Processing callback with authorization code {st.session_state}")
    if "code" in params and "state" in params:
        state = params["state"]
        st.info(f"DEBUG: Processing callback, state={state}")

        # Retrieve the original flow from cache using state
        flow = flow_store.pop(state, None)

        if not flow:
            st.error("Session expired or invalid. Please sign in again.")
            st.info(f"DEBUG: Flow not found for state={state}")
            if st.button("Start over"):
                st.query_params.clear()
                st.rerun()
        else:
            try:
                st.info(f"DEBUG: Exchanging code for token")
                result = app.acquire_token_by_auth_code_flow(flow, params.to_dict())

                if "error" in result:
                    st.error(f"Sign-in error: {result.get('error_description')}")
                    st.info(f"DEBUG: Error details: {result}")
                else:
                    st.info(f"DEBUG: Token acquired successfully {result}")
                    st.session_state["token"] = result
                    st.query_params.clear()
                    st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")
                logger.error(f"Auth error: {e}", exc_info=True)
    else:
        # Check if we already created a flow (prevent duplicate creation on rerun)
        pending_state = st.session_state.get("pending_state")

        if pending_state and pending_state in flow_store:
            flow = flow_store[pending_state]
            st.info(f"DEBUG: Reusing flow with state={pending_state}")
        else:
            # Create new flow
            flow = app.initiate_auth_code_flow(scopes=SCOPES, redirect_uri=REDIRECT_URI)
            state = flow["state"]

            # Store flow in process-wide cache
            flow_store[state] = flow
            st.session_state["pending_state"] = state
            st.info(f"DEBUG: Created new flow with state={state}")

        if "auth_uri" in flow:
            st.redirect(flow['auth_uri'])
        else:
            st.error("Failed to initiate authentication flow")
