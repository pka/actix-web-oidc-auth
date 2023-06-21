use actix_session::{
    config::PersistentSession, storage::CookieSessionStore, Session, SessionMiddleware,
};
use actix_web::{
    cookie::{time::Duration, Key},
    error::ErrorInternalServerError,
    http::StatusCode,
    middleware, web, App, HttpServer, Responder,
};
use log::{debug, info};
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, RedirectUrl, Scope,
};
use serde::Deserialize;
use serde_json::Value;
use std::env;

const ONE_MINUTE: Duration = Duration::minutes(1);

async fn index(session: Session) -> actix_web::Result<impl Responder> {
    let id = session
        .get::<String>("username")?
        .unwrap_or("anonymous".to_owned());

    Ok(format!("Hello {id}"))
}

async fn login(oidc: web::Data<OidcClient>) -> impl Responder {
    web::Redirect::to(oidc.authorize_url.clone()).using_status_code(StatusCode::FOUND)
}

#[derive(Deserialize, Debug)]
struct AuthRequest {
    code: String,
    // state: String,
    // scope: String,
}

async fn auth(
    session: Session,
    oidc: web::Data<OidcClient>,
    params: web::Query<AuthRequest>,
) -> actix_web::Result<impl Responder> {
    // let state = CsrfToken::new(params.state.clone());
    let code = AuthorizationCode::new(params.code.clone());
    // Exchange the code with a token.
    let token_response = oidc
        .client
        .exchange_code(code)
        .request_async(async_http_client)
        .await
        .map_err(ErrorInternalServerError)?;
    debug!("IdP returned scopes: {:?}", token_response.scopes());

    let id_token_verifier = oidc.client.id_token_verifier();
    let id_token_claims = token_response
        .extra_fields()
        .id_token()
        .ok_or(ErrorInternalServerError(
            "Server did not return an ID token",
        ))?
        .claims(&id_token_verifier, &oidc.nonce)
        .map_err(ErrorInternalServerError)?;

    // Convert back to raw JSON to simplify extracting configurable claims
    let userinfo = serde_json::to_value(id_token_claims).unwrap();
    info!("userinfo: {userinfo:#?}");

    let username = if let Some(claim) = &oidc.username_claim {
        userinfo[claim].as_str()
    } else {
        userinfo
            .get("preferred_username")
            .or(userinfo.get("upn"))
            .or(userinfo.get("email"))
            .and_then(|v| v.as_str())
    }
    .unwrap_or("");
    let groups = match &userinfo[&oidc.groupinfo_claim] {
        Value::String(s) => vec![s.as_str().to_string()],
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    };
    info!("username: `{username}` groups: {groups:?}");

    session.insert("username", username).unwrap();
    session.insert("groups", groups).unwrap();

    Ok(web::Redirect::to("/").using_status_code(StatusCode::FOUND))
}

async fn logout(session: Session) -> impl Responder {
    session.clear();
    web::Redirect::to("/").using_status_code(StatusCode::FOUND)
}

#[derive(Clone, Debug)]
struct OidcClient {
    client: CoreClient,
    authorize_url: String,
    nonce: Nonce,
    username_claim: Option<String>,
    groupinfo_claim: String,
}

async fn setup_oidc_client() -> OidcClient {
    let client_id =
        env::var("OIDC_CLIENT_ID").expect("Missing the OIDC_CLIENT_ID environment variable.");
    let client_secret = env::var("OIDC_CLIENT_SECRET")
        .expect("Missing the OIDC_CLIENT_SECRET environment variable.");
    let issuer_url =
        env::var("OIDC_ISSUER_URL").unwrap_or("https://accounts.google.com".to_string());

    let scopes = env::var("OIDC_SCOPES").unwrap_or("email profile".to_string());
    let username_claim = env::var("OIDC_USERNAME").ok();
    let groupinfo_claim = env::var("OIDC_GROUP_INFO").unwrap_or("group".to_string());

    info!("Fetching {issuer_url}/.well-known/openid-configuration");
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(issuer_url).expect("Invalid issuer URL"),
        async_http_client,
    )
    .await
    .expect("Failed to discover OpenID Provider");

    // Set up the config for the OAuth2 process.
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
    )
    .set_redirect_uri(
        RedirectUrl::new("http://127.0.0.1:5000/auth".to_string()).expect("Invalid redirect URL"),
    );

    // Generate the authorization URL to which we'll redirect the user.
    let mut auth_client = client.authorize_url(
        AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );
    for scope in scopes.split(' ') {
        auth_client = auth_client.add_scope(Scope::new(scope.to_string()));
    }
    let (authorize_url, _csrf_state, nonce) = auth_client.url();

    OidcClient {
        client,
        authorize_url: authorize_url.to_string(),
        nonce,
        username_claim,
        groupinfo_claim,
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let oidc = setup_oidc_client().await;

    let secret_key = Key::generate();

    info!("starting HTTP server at http://127.0.0.1:5000");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(oidc.clone()))
            .service(web::resource("/login").route(web::get().to(login)))
            .service(web::resource("/auth").route(web::get().to(auth)))
            .service(web::resource("/logout").route(web::get().to(logout)))
            .service(web::resource("/").route(web::get().to(index)))
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), secret_key.clone())
                    .cookie_name("auth".to_owned())
                    .cookie_secure(false)
                    .session_lifecycle(PersistentSession::default().session_ttl(ONE_MINUTE))
                    .build(),
            )
            .wrap(middleware::NormalizePath::trim())
            .wrap(middleware::Logger::default())
    })
    .bind(("127.0.0.1", 5000))?
    .run()
    .await
}
