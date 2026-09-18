//! Reddit OAuth2 login + subscribed-subreddit fetch.
//!
//! Extracted from TasteMatch (a dating app whose main matching signal is a
//! user's YouTube subscriptions/playlists) for Reddit API application
//! review — this is the entire Reddit integration, unmodified apart from
//! inlining one small struct (`SubInterest`) that otherwise lives in the
//! main app's shared domain-model module. See `README.md` for the full
//! context: what calls this code, when, and why.
//!
//! Reddit has no separate identity-provider layer the way Google/YouTube
//! do (there, OIDC identity and the YouTube Data API are two products, so
//! the main app has two modules). One Reddit OAuth2 client, one access
//! token, serves both `identity` (login) and `mysubreddits` (taste) scopes,
//! so this is one module, not a split.

use anyhow::{Context, Result};
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};

const AUTHORIZE_URL: &str = "https://www.reddit.com/api/v1/authorize";
const TOKEN_URL: &str = "https://www.reddit.com/api/v1/access_token";
const API: &str = "https://oauth.reddit.com";
/// Reddit blocks/aggressively rate-limits requests without a descriptive
/// User-Agent — this is the one Reddit-specific requirement with no
/// Google/YouTube equivalent.
const USER_AGENT: &str = "web:tastematch:v0.1 (by /u/tastematch_app)";
const MAX_SUBREDDIT_PAGES: usize = 5; // up to 500 subscriptions

/// One subscribed subreddit as a rankable, hideable interest. In the main
/// app this type is shared with the YouTube-subscriptions path (defined
/// once in a shared domain-model module); inlined here as its own type
/// since this crate only deals with Reddit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubInterest {
    /// Subreddit fullname, e.g. "t5_2qh33" — stable, used as the id.
    pub id: String,
    /// Human-readable subreddit name, e.g. "programming".
    #[serde(default)]
    pub name: Option<String>,
    /// Excluded from matching and hidden from other users when true.
    #[serde(default)]
    pub hidden: bool,
}

#[derive(Clone)]
pub struct RedditConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

impl RedditConfig {
    /// `None` (Reddit login disabled) unless all three of
    /// `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET`, `REDDIT_REDIRECT_URL` are set.
    pub fn from_env() -> Option<Self> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
        Some(RedditConfig {
            client_id: get("REDDIT_CLIENT_ID")?,
            client_secret: get("REDDIT_CLIENT_SECRET")?,
            redirect_url: get("REDDIT_REDIRECT_URL")?,
        })
    }
}

pub struct RedditAuthRequest {
    pub authorize_url: String,
    pub csrf: String,
    pub pkce_verifier: String,
}

#[derive(Debug, Clone)]
pub struct RedditIdentity {
    pub sub: String,
    pub username: String,
    pub access_token: String,
}

pub struct RedditAuthClient {
    config: RedditConfig,
    http: reqwest::Client,
}

impl RedditAuthClient {
    pub fn new(config: RedditConfig) -> Result<Self> {
        let http = reqwest::ClientBuilder::new()
            .user_agent(USER_AGENT)
            // Following redirects on the token endpoint invites SSRF.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building Reddit HTTP client")?;
        Ok(Self { config, http })
    }

    pub fn redirect_url(&self) -> &str {
        &self.config.redirect_url
    }

    /// Build the Reddit authorization URL and the secrets to stash in the
    /// session. `duration=temporary` requests a plain access token: this
    /// callback only makes one identity call and one subreddit-listing pass
    /// within a single request, so there is no later use for a refresh
    /// token — nothing in this codebase captures or redeems one. Asking for
    /// `permanent` would show users a stronger, more alarming consent
    /// screen for a capability we don't implement.
    pub fn begin(&self) -> Result<RedditAuthRequest> {
        let client = BasicClient::new(ClientId::new(self.config.client_id.clone()))
            .set_client_secret(ClientSecret::new(self.config.client_secret.clone()))
            .set_auth_uri(AuthUrl::new(AUTHORIZE_URL.to_string())?)
            .set_token_uri(TokenUrl::new(TOKEN_URL.to_string())?)
            .set_redirect_uri(RedirectUrl::new(self.config.redirect_url.clone())?);
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (authorize_url, csrf) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("identity".to_string()))
            .add_scope(Scope::new("mysubreddits".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .add_extra_param("duration", "temporary")
            .url();
        Ok(RedditAuthRequest {
            authorize_url: authorize_url.to_string(),
            csrf: csrf.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
        })
    }

    /// Complete the callback: exchange `code` for a token, then fetch identity.
    pub async fn complete(&self, code: String, pkce_verifier: String) -> Result<RedditIdentity> {
        let client = BasicClient::new(ClientId::new(self.config.client_id.clone()))
            .set_client_secret(ClientSecret::new(self.config.client_secret.clone()))
            .set_auth_uri(AuthUrl::new(AUTHORIZE_URL.to_string())?)
            .set_token_uri(TokenUrl::new(TOKEN_URL.to_string())?)
            .set_redirect_uri(RedirectUrl::new(self.config.redirect_url.clone())?);

        // oauth2 5.x's AsyncHttpClient trait is implemented only for its own
        // re-exported `oauth2::reqwest::Client` (pinned to reqwest 0.12 via
        // oauth2's optional `reqwest` dependency) — this project's direct
        // `reqwest` dependency is 0.13, a same-named but incompatible type.
        // Built once, used once, for this call only; `self.http` (the
        // project's own reqwest client) still serves the /api/v1/me call
        // below and all of `fetch_subreddits`, unchanged.
        let oauth_http = oauth2::reqwest::ClientBuilder::new()
            .user_agent(USER_AGENT)
            .redirect(oauth2::reqwest::redirect::Policy::none())
            .build()
            .context("building the token-exchange HTTP client")?;

        let token = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(&oauth_http)
            .await
            .context("exchanging Reddit authorization code")?;
        let access_token = token.access_token().secret().clone();

        let me: MeResponse = self
            .http
            .get(format!("{API}/api/v1/me"))
            .bearer_auth(&access_token)
            .send()
            .await
            .context("calling Reddit /api/v1/me")?
            .error_for_status()
            .context("Reddit /api/v1/me returned an error status")?
            .json()
            .await
            .context("decoding Reddit /api/v1/me response")?;

        Ok(RedditIdentity {
            sub: me.id,
            username: me.name,
            access_token,
        })
    }
}

#[derive(Deserialize)]
struct MeResponse {
    id: String,
    name: String,
}

/// Paginated fetch of the signed-in user's subscribed subreddits. Called
/// exactly once, right after `complete()`, during the login callback —
/// there is no polling, scheduler, or repeated background call anywhere
/// in the main app.
pub async fn fetch_subreddits(access_token: &str) -> Result<Vec<SubInterest>> {
    let http = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .build()
        .context("building Reddit HTTP client")?;
    let mut subs = Vec::new();
    let mut after: Option<String> = None;
    for _ in 0..MAX_SUBREDDIT_PAGES {
        let mut query = vec![("limit", "100")];
        if let Some(a) = after.as_deref() {
            query.push(("after", a));
        }
        let resp: ListingResponse = http
            .get(format!("{API}/subreddits/mine/subscriber"))
            .bearer_auth(access_token)
            .query(&query)
            .send()
            .await
            .context("calling Reddit /subreddits/mine/subscriber")?
            .error_for_status()
            .context("Reddit /subreddits/mine/subscriber returned an error status")?
            .json()
            .await
            .context("decoding Reddit /subreddits/mine/subscriber response")?;
        for child in resp.data.children {
            subs.push(SubInterest {
                id: child.data.name,
                name: Some(child.data.display_name),
                hidden: false,
            });
        }
        match resp.data.after {
            Some(a) => after = Some(a),
            None => break,
        }
    }
    Ok(subs)
}

#[derive(Deserialize)]
struct ListingResponse {
    data: ListingData,
}

#[derive(Deserialize)]
struct ListingData {
    after: Option<String>,
    children: Vec<SubredditChild>,
}

#[derive(Deserialize)]
struct SubredditChild {
    data: SubredditData,
}

#[derive(Deserialize)]
struct SubredditData {
    /// Fullname, e.g. "t5_2qh33" — stable, used as `SubInterest.id`.
    name: String,
    /// Human name, e.g. "programming" — used as `SubInterest.name`.
    display_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_absent_when_env_unset() {
        let keys = [
            "REDDIT_CLIENT_ID",
            "REDDIT_CLIENT_SECRET",
            "REDDIT_REDIRECT_URL",
        ];
        let saved: Vec<_> = keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        for k in keys {
            std::env::remove_var(k);
        }
        assert!(RedditConfig::from_env().is_none());
        std::env::set_var("REDDIT_CLIENT_ID", "");
        assert!(RedditConfig::from_env().is_none());
        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }

    #[test]
    fn begin_requests_identity_and_mysubreddits_scopes_and_a_temporary_duration() {
        let client = RedditAuthClient::new(RedditConfig {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_url: "http://localhost:8080/auth/reddit/callback".into(),
        })
        .unwrap();
        let req = client.begin().unwrap();
        assert!(req.authorize_url.starts_with(AUTHORIZE_URL));
        // oauth2 joins scopes with "+" in add_scope call order (verified
        // against the crate's own test_authorize_url_with_scopes).
        assert!(req.authorize_url.contains("scope=identity+mysubreddits"));
        assert!(req.authorize_url.contains("duration=temporary"));
        assert!(!req.csrf.is_empty());
        assert!(!req.pkce_verifier.is_empty());
    }

    #[test]
    fn subreddit_listing_deserializes_id_and_name() {
        let json = r#"{
            "data": {
                "after": "t5_next",
                "children": [
                    {"data": {"name": "t5_2qh33", "display_name": "programming"}},
                    {"data": {"name": "t5_2qh0u", "display_name": "rust"}}
                ]
            }
        }"#;
        let resp: ListingResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.data.after.as_deref(), Some("t5_next"));
        assert_eq!(resp.data.children.len(), 2);
        assert_eq!(resp.data.children[0].data.name, "t5_2qh33");
        assert_eq!(resp.data.children[0].data.display_name, "programming");
    }
}
