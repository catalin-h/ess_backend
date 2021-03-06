use quick_error::quick_error;
pub type Result<T> = std::result::Result<T, EssError>;

fn sqlx_error_message(err: &sqlx::Error) -> String {
    match err.as_database_error() {
        Some(e) => {
            let pgerr = e.downcast_ref::<sqlx::postgres::PgDatabaseError>();
            format!("message: {}, ", pgerr.message())
        }
        None => err.to_string().clone(),
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum EssError {
        Io(err: std::io::Error) {
            display("I/O error: {}", err)
            from()
        }
        File(filename: String, err: std::io::Error) {
            display("File I/O error: {} for filename: {}", err, filename)
            context(path: String, err: std::io::Error)
                -> (path, err)
            context(path: &str, err: std::io::Error)
                -> (path.to_string(), err)
        }
        Timeout(err: async_std::future::TimeoutError) {
            display("Timeout error: {}", err)
            from()
        }
        ChSend(err: async_std::channel::SendError<std::string::String>) {
            display("Channel send error: {}", err)
            from()
        }
        ChRecv(err: async_std::channel::RecvError) {
            display("Channel receive error: {}", err)
            from()
        }
       ServiceNotHealthy {
            display("System not healthy")
        }
        UnknownMsgType(msgtype: String) {
            display("Unknown message type: {}", msgtype)
        }
        ServiceNotLoaded {
            display("The ess backend service is not loaded")
        }
        Sqlx(err: sqlx::Error) {
            display("SQlx error: {}", sqlx_error_message(err))
            from()
        }
        UsernameAlreadyExists(user: String) {
            display("The username '{}' already exists", user)
        }
        DbUserNotFound(username: String) {
            display("Username: {} not found", username)
        }
        UrlParse(err: url::ParseError) {
            display("Url parse error: {}", err)
            from()
        }
        Serde(err: serde_json::Error) {
            from()
        }
        InvalidResource(resource: &'static str) {
            display("Invalid resource: '{}'", resource)
        }
        OneTimePasswordVerifyFailed {
            display("The one time password/code is not correct")
        }
        GenericGAError(err: google_authenticator::GAError) {
            display("Google auth error: {}", err)
            from()
        }
        NoUsernameSpecified {
            display("No username specified")
        }
        InvalidInputParameters {
            display("Invalid parameters")
        }
        NotImplemented {
            display("Function not implemented yet")
        }
        Signals(err: ctrlc::Error) {
            display("Signals trap error: {}", err)
            from()
        }
        TlsCert(cert: String) {
            display("Invalid cert: {}", cert)
        }
        WebPki(err: tide_rustls::async_rustls::webpki::Error) {
            display("Web PKI error: {}", err)
            from()
        }
        RustTLS(err: tide_rustls::rustls::TLSError) {
            display("Rust TLS error: {}", err)
            from()
        }
    }
}
