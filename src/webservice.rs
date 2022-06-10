use crate::clients_db::{ConnectionDetails, DbManager, User, UserUpdate};
use crate::ess_errors::{EssError, Result};
use crate::tlsconfig::{make_server_config, WsType};
use serde::{Deserialize, Serialize};
use std::env;
use std::str::FromStr;
use tide::{http::mime, prelude::json, Error, Request, Response, StatusCode};
use tide_rustls::TlsListener;

#[derive(Clone)]
struct WsState {
    pub db: DbManager,
}

fn to_http_status_error(err: EssError) -> tide::Error {
    match err {
        EssError::DbUserNotFound(_) => Error::new(StatusCode::NotFound, err), // 404
        EssError::OneTimePasswordVerifyFailed => Error::new(StatusCode::Forbidden, err), // 403
        EssError::UsernameAlreadyExists(_) => Error::new(StatusCode::Conflict, err), // 409
        EssError::NoUsernameSpecified | EssError::InvalidInputParameters => {
            Error::new(StatusCode::BadRequest, err)
        } // 400
        EssError::NotImplemented => Error::new(StatusCode::NotImplemented, err),
        _ => Error::new(StatusCode::InternalServerError, err), // 500
    }
}

async fn endpoint(_req: Request<WsState>) -> tide::Result {
    Err(to_http_status_error(EssError::NotImplemented))
}

async fn endpoint_api_admin_employee_get(req: Request<WsState>) -> tide::Result {
    let emp_username = req
        .url()
        .path_segments()
        .map(|segments| segments.last())
        .flatten()
        .ok_or_else(|| to_http_status_error(EssError::NoUsernameSpecified))?;

    match emp_username {
        "all" => {
            match req.state().db.get_all_as_json().await {
                Ok(jallusers) => Ok(jallusers.into()),
                Err(e) => Err(Error::new(StatusCode::NotFound, e)), // return 404
            }
        }
        username if !username.is_empty() => match req.state().db.get_user_as_json(username).await {
            Ok(juser) => Ok(juser.into()),
            Err(e) => match e {
                EssError::DbUserNotFound(_) => Ok(Response::builder(tide::StatusCode::NotFound)
                    .body(json!([]))
                    .build()),
                e => Err(to_http_status_error(e)),
            },
        },
        _ => Err(to_http_status_error(EssError::NoUsernameSpecified)),
    }
}

async fn endpoint_api_pam_verify(mut req: Request<WsState>) -> tide::Result {
    #[derive(Deserialize, Serialize)]
    struct PamUserVerify {
        username: String,
        #[serde(rename = "oneTimePassword")]
        one_time_password: String,
    }

    let pam_data: PamUserVerify = req
        .body_json()
        .await
        .map_err(|e| tide::Error::new(StatusCode::BadRequest, e.into_inner()))?;

    match req
        .state()
        .db
        .verify_user(
            &pam_data.username,
            Some(pam_data.one_time_password.as_str()),
        )
        .await
    {
        Ok(()) => Ok(Response::from(tide::StatusCode::Ok)),
        Err(e) => match e {
            EssError::DbUserNotFound(_) => Ok(Response::builder(tide::StatusCode::NotFound)
                .body(json!({}))
                .build()),
            e => Err(to_http_status_error(e)),
        },
    }
}

async fn endpoint_api_admin_employee_post(mut req: Request<WsState>) -> tide::Result {
    let user_data: User = req
        .body_json()
        .await
        .map_err(|e| tide::Error::new(StatusCode::BadRequest, e.into_inner()))?; // 400
    let return_qr_code = match req.header("EssSendQRCodeLink") {
        Some(value) if value.as_str().eq_ignore_ascii_case("yes") => true,
        _ => false,
    };
    match req.state().db.insert_user(user_data, return_qr_code).await {
        Ok(secret) => match mime::Mime::from_str("text/html;charset=utf-8") {
            Ok(m) => Ok(Response::builder(StatusCode::Ok)
                .body(secret)
                .content_type(m)
                .build()),
            Err(e) => Err(Error::new(StatusCode::InternalServerError, e.into_inner())),
        },
        Err(e) => Err(to_http_status_error(e)),
    }
}

async fn endpoint_api_admin_employee_put(mut req: Request<WsState>) -> tide::Result {
    let user_data: UserUpdate = req
        .body_json()
        .await
        .map_err(|e| tide::Error::new(StatusCode::BadRequest, e.into_inner()))?; // 400

    let emp_username = req
        .url()
        .path_segments()
        .map(|segments| segments.last())
        .flatten()
        .ok_or_else(|| to_http_status_error(EssError::NoUsernameSpecified))?;

    match req.state().db.update_user(emp_username, user_data).await {
        Ok(()) => Ok(Response::from(tide::StatusCode::Ok)),
        Err(e) => Err(to_http_status_error(e)),
    }
}

async fn endpoint_api_admin_employee_delete(req: Request<WsState>) -> tide::Result {
    let emp_username = req
        .url()
        .path_segments()
        .map(|segments| segments.last())
        .flatten()
        .ok_or_else(|| to_http_status_error(EssError::NoUsernameSpecified))?;

    match req.state().db.delete_user(emp_username).await {
        Ok(()) => Ok(Response::from(tide::StatusCode::Ok)),
        Err(e) => Err(to_http_status_error(e)),
    }
}

pub async fn launch_ess_ws(admin: bool) -> Result<()> {
    let mut app = tide::with_state(WsState {
        db: ConnectionDetails::new(None).connect(5, true).await?,
    });

    app.at("*").all(endpoint);
    app.at("/").all(endpoint);

    if admin {
        app.at("/api/admin/employee/*")
            .get(endpoint_api_admin_employee_get); // get user data
        app.at("/api/admin/employee")
            .post(endpoint_api_admin_employee_post); // creates a new user
        app.at("/api/admin/employee/*")
            .put(endpoint_api_admin_employee_put); // modifies an existing employee
        app.at("/api/admin/employee/*")
            .delete(endpoint_api_admin_employee_delete); // deletes an employee
        app.at("/api/pam/verify").post(endpoint_api_pam_verify); // checks an username + otp

        let host = format!(
            "0.0.0.0:{}",
            env::var("ESS_ADMIN_WS_PORT")
                .as_ref()
                .map_or("8081", |port| port.as_str())
        );

        let listener = TlsListener::<WsState>::build()
            .addrs(host)
            .config(make_server_config(WsType::Admin)?)
            .finish()?;

        app.listen(listener).await?;
    } else {
        app.at("/api/pam/verify").post(endpoint_api_pam_verify); // checks an username + otp

        let host = format!(
            "0.0.0.0:{}",
            env::var("ESS_PAM_WS_PORT")
                .as_ref()
                .map_or("8080", |port| port.as_str())
        );

        let listener = TlsListener::<WsState>::build()
            .addrs(host)
            .config(make_server_config(WsType::Pam)?)
            .finish()?;

        app.listen(listener).await?;
    }

    Ok(())
}
