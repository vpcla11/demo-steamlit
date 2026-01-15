import msal
import streamlit as st
import time
import pickle
import requests
import base64
from streamlit.logger import get_logger

logger = get_logger(__name__)

CLIENT_ID = "35779d1b-9b8f-48b8-b836-9f6e8e941c8e"
CLIENT_SECRET = "5sO8Q~WoDDN7DXnCsGoiIeu0XHtT8nOnRuTcOcSe"
TENANT_ID = "e0fd7f83-50c7-4540-8e09-0dafc1092723"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
# REDIRECT_URI = "https://genaiqa-dgahbbd6h9dbe5bm.westus2-01.azurewebsites.net"
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


def logout_session() -> None:
    logout_url = f"{AUTHORITY}/oauth2/v2.0/logout?post_logout_redirect_uri={REDIRECT_URI}"
    logger.info(f"Redirecting to Azure logout: {logout_url}")
    st.info(f"DEBUG: Redirecting to Azure logout: {logout_url}")

    with st.spinner("Redirecting to Azure logout: {logout_url}"):
        time.sleep(25)

    st.markdown(
        f"""
                <meta http-equiv="refresh" content="0;url={logout_url}">
                <script>
                    window.location.href = "{logout_url}";
                </script>
                """,
        unsafe_allow_html=True
    )
    st.rerun()


def signout() -> None:
    try:
        logger.info(f"Available token keys: {st.session_state['token'].keys()}")
        st.info(f"DEBUG: Available token keys: {st.session_state['token'].keys()}")

        if "refresh_token" not in st.session_state["token"]:
            logger.warning("No refresh token available, skipping revocation")
            st.warning("DEBUG: No refresh token to revoke")
            return

        refresh_token = st.session_state["token"]["refresh_token"]
        logger.info(f"Refresh token length: {len(refresh_token)}")
        st.info(f"DEBUG: Refresh token length: {len(refresh_token)}")

        revoke_url = f"{AUTHORITY}/oauth2/v2.0/revoke"
        response = requests.post(
            revoke_url,
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "token": st.session_state["token"]["refresh_token"],
                "token_type_hint": "refresh_token"
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if response.status_code == 200:
            logger.info("Refresh token revoked successfully on Azure Entra ID")
            st.info("DEBUG: Refresh token revoked successfully on Azure Entra ID")
        else:
            logger.error(f"Token revocation response status: {response.status_code}, body: {response.text}")
            st.error(f"DEBUG: Token revocation response: {response.status_code}, body: {response.text}")

    except Exception as e:
        logger.error(f"Failed to revoke token on Azure Entra ID: {e}", exc_info=True)
        st.error(f"Failed to revoke token on Azure Entra ID:")
    finally:
        logout_session()


def cleanup_user_session():
    global e
    try:
        accounts = app.get_accounts()
        if accounts:
            app.remove_account(accounts[0])
            logger.info("Account removed from MSAL cache")
            st.info("DEBUG: Account removed from MSAL cache")

            st.session_state.clear()
            st.query_params.clear()
            st.rerun()
            logger.info("Session state cleared")
            st.info("DEBUG: Session state cleared")
    except Exception as e:
        logger.error(f"Failed to clean session: {e}", exc_info=True)
        st.error(f"DEBUG: Failed to clean session")


st.title("Microsoft Entra ID login")

app = build_app()
flow_store = get_flow_store()

if "token" in st.session_state:
    token = st.session_state["token"]
    st.success(f"Welcome, {token['id_token_claims'].get('name')}")
    if st.button("Sign out"):
        if "refresh_token" in st.session_state["token"]:
            signout()
        cleanup_user_session()
else:
    params = st.query_params
    st.info(f"DEBUG: Processing callback with authorization code {st.session_state}")
    if "code" in params and "state" in params:
        state = params["state"]
        st.info(f"DEBUG: Processing callback, state={state}")

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
                    with st.spinner("DEBUG Please wait..."):
                        time.sleep(5)
                    st.session_state["token"] = result
                    st.query_params.clear()
                    st.rerun()
            except Exception as e:
                st.error(f"Error: {e}")
                logger.error(f"Auth error: {e}", exc_info=True)
    else:
        pending_state = st.session_state.get("pending_state")

        if pending_state and pending_state in flow_store:
            flow = flow_store[pending_state]
            st.info(f"DEBUG: Reusing flow with state={pending_state}")
        else:
            flow = app.initiate_auth_code_flow(scopes=SCOPES, redirect_uri=REDIRECT_URI)
            state = flow["state"]

            flow_store[state] = flow
            st.session_state["pending_state"] = state
            st.info(f"DEBUG: Created new flow with state={state}")

        if "auth_uri" in flow:
            st.info("Click below to sign in with Microsoft:")
            st.link_button("Sign in with Microsoft", flow['auth_uri'])
            st.caption("You'll be redirected back here after authentication.")
        else:
            st.error("Failed to initiate authentication flow")
