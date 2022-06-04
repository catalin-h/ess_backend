use crate::ess_errors::{EssError, Result};
use crate::otp::{convert_to_base32, Otpist};
use async_std::channel::unbounded;
use async_std::stream::StreamExt;
use clap::Subcommand;
use const_format::formatcp;
use core::fmt::Display;
use futures::TryStreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, Postgres},
    query_builder::Separated,
    Encode, FromRow, PgPool, QueryBuilder, Row, Type,
};
use std::future::Future;
use url::Url;

const ESS_DB_CONN_ENV: &str = "ESS_DB_CONN";
const ESS_DB_NAME_ENV: &str = "ESS_DB_NAME";
const ESS_DB_ADMIN_USER_ENV: &str = "ESS_DB_ADMIN_USER";

const ESS_DEFAULT_DB_CONN: &str = "postgres://ess_admin@postgres.local/ess";
const ESS_CLIENT_TABLE: &str = "clients";
const ESS_CLIENT_TABLE_USER_CNSTRT: &str = "constraint_username_unique";
const ESS_CLIENT_TABLE_SECRET_CNSTRT: &str = "constraint_secret_unique";
const SELECT_USER: &str = formatcp!("SELECT * FROM {} WHERE username = $1;", ESS_CLIENT_TABLE);
const SELECT_ALL: &str = formatcp!("SELECT * FROM {};", ESS_CLIENT_TABLE);

const ESS_DB_NAME: &str = "ess";
const ESS_ADMIN_USER: &str = "ess_admin";
const ESS_DB_TIMEOUT: u64 = 10; // sec
const ESS_DB_DEFAULT_POOL_SIZE: u32 = 5;

#[derive(clap::Parser)]
pub struct SecretKey {
    /// A secret key is a unique random string generated when
    /// creating the employee record for the first time
    #[clap(long, short)]
    secret: String,
}

#[derive(clap::Args)]
pub struct Username {
    /// The unique username
    #[clap(long, short)]
    username: String,
}

fn default_name() -> String {
    "noname".to_string()
}

#[derive(clap::Parser, FromRow, Deserialize, Serialize)]
pub struct User {
    /// The unique user name
    #[clap(long, short)]
    pub username: String,
    /// The user's first name
    #[clap(long, short, default_value_t = String::from("noname"))]
    #[sqlx(rename = "firstname")]
    #[serde(rename = "firstName", default = "default_name")]
    pub first_name: String,
    /// The user's last name
    #[clap(long, short, default_value_t = String::from("noname"))]
    #[sqlx(rename = "lastname")]
    #[serde(rename = "lastName", default = "default_name")]
    pub last_name: String,
    /// A secret key is a unique random string generated when
    /// creating the employee record for the first time
    #[clap(long, short)]
    pub secret: Option<String>,
}

#[derive(clap::Parser, Deserialize, Serialize)]
#[clap(group(
    clap::ArgGroup::new("update-group")
        .multiple(true)
        .args(&["first-name", "last-name"]),
))]
pub struct UserUpdate {
    /// The user's first name
    #[clap(long, short)]
    #[serde(rename = "firstName", default)]
    first_name: Option<String>,
    /// The user's last name
    #[clap(long, short)]
    #[serde(rename = "lastName", default)]
    last_name: Option<String>,
}

#[derive(clap::Args)]
pub struct UserVerifyOptions {
    /// The default expire interval in seconds, default is 60s
    #[clap(long, short)]
    timeslice: Option<u8>,
    /// The code length, default 6
    #[clap(long, short)]
    length: Option<usize>,
    /// On verify otp it controls how many intervals of timeslice
    /// length to check around current timestamp. Default is 1.
    /// E.g. if discrepancy = 2 and t is the current timestamp then
    /// it will check every code generate by timeslices:
    /// (t-2*expire_interval), (t-1*expire_interval), (t-0*expire_interval),
    /// (t-1*expire_interval) and (t-2*expire_interval)
    #[clap(long, short)]
    discrepancy: Option<u64>,
}

#[derive(clap::Parser)]
pub struct InitOpts {
    /// Delete and recreate the clients table
    #[clap(long, short)]
    reset: bool,
}

#[derive(clap::Parser)]
#[clap(group(
    clap::ArgGroup::new("name")
        .args(&["database", "pg-default"]),
))]
pub struct ConnectOpts {
    /// Database name to connect
    #[clap(long, default_value_t = String::from(ESS_DB_NAME))]
    database: String,
    /// Use default database name; e.g. postgres
    #[clap(long)]
    pg_default: bool,
}

#[derive(Subcommand)]
pub enum DbCommand {
    /// Verify database connection
    Connect(ConnectOpts),
    /// Initialize the ess database and client table
    Init(InitOpts),
    /// Insert user
    Insert {
        /// The user info
        #[clap(flatten)]
        user: User,
        /// Return plain secret code or as QR code
        #[clap(long, short)]
        qr_code: bool,
    },
    /// Update user info & secret except the username
    Update {
        /// The unique user name
        username: String,
        /// The user data to update
        #[clap(flatten)]
        user_data: UserUpdate,
    },
    /// Verify secret for username
    Verify {
        /// The unique user name
        username: String,
        /// If present then check the against this code, otherwise generate the otp code
        one_time_password: Option<String>,
        /// Options
        #[clap(flatten)]
        flags: UserVerifyOptions,
    },
    /// Delete user
    Delete {
        /// The unique username
        username: String,
    },
    /// Get user data by username
    GetUser {
        /// The unique username
        username: String,
    },
    /// Get all users
    GetAll,
}

#[derive(clap::Parser)]
pub struct DbOpt {
    #[clap(subcommand)]
    /// The db action
    action: DbCommand,
    /// Database connection (Postgres only). If missing use the envar ESS_DB_CONN.
    /// If the envar is missing as well use the default: 'postgres://postgres@localhost/ess'
    #[clap(long, short)]
    connection: Option<String>,
}

#[derive(Clone)]
pub struct DbManager {
    pool: PgPool,
    conn_details: ConnectionDetails,
    otpist: Otpist,
}

#[derive(Clone)]
pub struct ConnectionDetails {
    conn_str: String,
    database: String,
    username: String,
}

fn compute_connection_string(conn_str: &Option<String>) -> String {
    match conn_str {
        Some(cs) => {
            println!("[db] use connection string from cli: '{}'", cs);
            cs.clone()
        }
        None => {
            println!("[db] no connection string provided from cli (--connection)");
            match std::env::var(ESS_DB_CONN_ENV) {
                Ok(cs) => {
                    println!(
                        "[db] use connection string from envar ${}: '{}'",
                        ESS_DB_CONN_ENV, cs
                    );
                    cs.to_string()
                }
                Err(e) => {
                    println!(
                        "[db] use default connection string: {}, why: {}",
                        ESS_DEFAULT_DB_CONN, e
                    );
                    String::from(ESS_DEFAULT_DB_CONN)
                }
            }
        }
    }
}

fn compute_user_name(conn_str: &str) -> String {
    match std::env::var(ESS_DB_ADMIN_USER_ENV) {
        Ok(user) => {
            println!(
                "[db] connect using admin user from envar ${}: {}",
                ESS_DB_ADMIN_USER_ENV, user
            );
            user
        }
        Err(_) => match Url::parse(conn_str) {
            Ok(user) => String::from(user),
            Err(_) => String::new(),
        },
    }
}

fn db_name_from_url(conn_str: &str) -> Option<String> {
    // The postgres url looks like
    // postgresql://[user[:password]@][host][:port][/dbname][?param1=value1&...]

    let db_name = match Url::parse(conn_str) {
        Ok(name) => name,
        Err(_) => return None,
    };
    db_name
        .path_segments()
        .map(|mut segments| segments.next().map(|database| String::from(database)))
        .flatten()
}

fn compute_db_name(conn_str: &str, conn_opts: Option<&ConnectOpts>) -> String {
    match std::env::var(ESS_DB_NAME_ENV) {
        Ok(name) => {
            println!(
                "[db] connect using database from envar ${}: {}",
                ESS_DB_NAME_ENV, name
            );
            name
        }
        Err(_) => match &conn_opts {
            Some(opts) => {
                let db_name = if opts.pg_default {
                    "postgres"
                } else {
                    opts.database.as_str()
                };

                println!("[db] connect using provided database: {}", db_name);
                String::from(db_name)
            }
            None => match db_name_from_url(conn_str) {
                Some(name) => {
                    println!("[db] connect using database: {}", name);
                    name
                }
                None => {
                    println!("[db] connect without a database");
                    String::new()
                }
            },
        },
    }
}

impl ConnectionDetails {
    pub fn new(dbopt: Option<&DbOpt>) -> Self {
        match dbopt {
            Some(dbopt) => {
                let conn_str = compute_connection_string(&dbopt.connection);
                match &dbopt.action {
                    DbCommand::Connect(conn_opts) => ConnectionDetails {
                        conn_str: conn_str.clone(),
                        database: compute_db_name(&conn_str, Some(conn_opts)),
                        username: compute_user_name(&conn_str),
                    },
                    _ => ConnectionDetails {
                        conn_str: conn_str.clone(),
                        database: compute_db_name(&conn_str, None),
                        username: compute_user_name(&conn_str),
                    },
                }
            }
            None => {
                let conn_str = compute_connection_string(&None);
                ConnectionDetails {
                    conn_str: conn_str.clone(),
                    database: compute_db_name(&conn_str, None),
                    username: compute_user_name(&conn_str),
                }
            }
        }
    }

    pub async fn connect(self, pool_size: u32, lazy_connect: bool) -> Result<DbManager> {
        let pool = self.db_pool(pool_size, lazy_connect).await?;
        Ok(DbManager::new(self, pool))
    }

    // Create a connection pool
    async fn db_pool(&self, pool_size: u32, lazy_connect: bool) -> Result<PgPool> {
        let mut options: PgConnectOptions = self.conn_str.parse()?;

        // a capacity of 1 means that before each statement (after the first)
        // we will close the previous statement
        options = options.statement_cache_capacity(1);

        let pool = PgPoolOptions::new()
            .max_connections(pool_size)
            .connect_timeout(std::time::Duration::from_secs(ESS_DB_TIMEOUT));

        if lazy_connect {
            let p = pool.connect_lazy_with(options);
            println!("[db] connection pool created");
            Ok(p)
        } else {
            let p = pool.connect_with(options).await?;
            println!("[db] connection pool created and connection established");
            Ok(p)
        }
    }
}

fn execute_query<F, T>(task: F, timeout: u64) -> Result<T>
where
    F: Future<Output = T>,
{
    let duration = std::time::Duration::from_secs(timeout);
    let r = async_std::task::block_on(async {
        let rr = async_std::future::timeout(duration, task).await?;
        Ok::<T, EssError>(rr)
    })?;
    Ok(r)
}

fn push_bind_for_option<'qb, 'args, T: 'args, Sep>(
    opt: Option<&'args T>,
    builder: &mut Separated<'qb, 'args, Postgres, Sep>,
) where
    Sep: Display,
    T: Send + Type<Postgres> + Encode<'args, Postgres> + Sync,
    'args: 'qb,
{
    match opt {
        Some(value) => builder.push_bind(value),
        None => builder.push("DEFAULT"),
    };
}

/// Returns true if the closure provider wants the next user data
type UserDataFn = Box<dyn Fn(User) -> bool + Send>;

impl DbManager {
    fn new(conn_details: ConnectionDetails, pool: PgPool) -> Self {
        DbManager {
            conn_details: conn_details,
            pool: pool,
            otpist: Otpist::new(),
        }
    }

    fn _execute_many(&self, statements: Vec<String>) -> Result<()> {
        for s in statements {
            execute_query(sqlx::query(&s).execute(&self.pool), ESS_DB_TIMEOUT)??;
        }

        Ok(())
    }

    async fn init_db(&self) -> Result<()> {
        let pool = self.conn_details.db_pool(1, false).await?;

        println!(
            "[db] setting up database: '{}' ...",
            self.conn_details.database
        );

        let exists: (bool,) = sqlx::query_as("SELECT TRUE from pg_database where datname = $1;")
            .bind(self.conn_details.database.as_str())
            .fetch_one(&pool)
            .await?;

        if !exists.0 {
            println!(
                "[db] database: '{}' doesn't exist, create one for ...",
                self.conn_details.database
            );
            let statement = if self.conn_details.username.is_empty() {
                format!("CREATE DATABASE {};", self.conn_details.database)
            } else {
                format!(
                    "CREATE DATABASE {} WITH OWNER = {};",
                    self.conn_details.database, self.conn_details.username
                )
            };
            execute_query(sqlx::query(&statement).execute(&pool), ESS_DB_TIMEOUT)??;
        }

        println!("[db] database: '{}' is setup", self.conn_details.database);
        Ok(())
    }

    pub async fn init(&self, opts: InitOpts) -> Result<()> {
        // Try create the ess database first
        self.init_db().await?;

        if opts.reset {
            println!(
                "[db] as requested, droping table: '{}' ...",
                ESS_CLIENT_TABLE
            );
            execute_query(
                sqlx::query(&format!("DROP TABLE IF EXISTS {};", ESS_CLIENT_TABLE))
                    .execute(&self.pool),
                ESS_DB_TIMEOUT,
            )??;
            println!("[db] drop table: '{}' done", ESS_CLIENT_TABLE);
        }

        let exists: (bool,) =
            sqlx::query_as("SELECT EXISTS (SELECT TRUE from pg_tables where tablename = $1);")
                .bind(ESS_CLIENT_TABLE)
                .fetch_one(&self.pool)
                .await?;

        if !exists.0 {
            println!("[db] setting up table: '{}' ...", ESS_CLIENT_TABLE);
            execute_query(
                sqlx::query(&format!(
                    r#"
                    CREATE TABLE IF NOT EXISTS {}
                (
                    firstname VARCHAR(256) DEFAULT 'noname',
                    lastname VARCHAR(256) DEFAULT 'noname',
                    username VARCHAR(32),
                    secret VARCHAR(256) DEFAULT md5(random()::text || clock_timestamp()::text),
                    CONSTRAINT {} UNIQUE(username),
                    CONSTRAINT {} UNIQUE(secret)
                );"#,
                    ESS_CLIENT_TABLE, ESS_CLIENT_TABLE_USER_CNSTRT, ESS_CLIENT_TABLE_SECRET_CNSTRT
                ))
                .execute(&self.pool),
                ESS_DB_TIMEOUT,
            )??;

            println!(
                "[db] setting up the user: '{}' for table: '{}' ...",
                ESS_ADMIN_USER, ESS_CLIENT_TABLE
            );
            execute_query(
                sqlx::query(&format!(
                    "ALTER TABLE IF EXISTS {} OWNER to {};",
                    ESS_CLIENT_TABLE, ESS_ADMIN_USER
                ))
                .execute(&self.pool),
                ESS_DB_TIMEOUT,
            )??;
        }
        println!("[db] '{}' table is setup", ESS_CLIENT_TABLE);
        Ok(())
    }

    pub async fn insert_user(&self, user: User, secret_as_qr_code: bool) -> Result<String> {
        println!("[db] inserting username: {} ...", user.username);

        let mut query_builder: QueryBuilder<Postgres> = QueryBuilder::new(format!(
            "INSERT INTO {} (username, firstname, lastname, secret) ",
            ESS_CLIENT_TABLE
        ));

        query_builder.push_values(vec![&user], |mut b, ref user| {
            b.push_bind(&user.username);
            b.push_bind(&user.first_name);
            b.push_bind(&user.last_name);
            push_bind_for_option(user.secret.as_ref(), &mut b);
        });
        query_builder.push(" RETURNING secret;");

        let rec = query_builder
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(|sqlxerr| {
                if let Some(pgerr) = sqlxerr.as_database_error() {
                    // check for unique key violation code
                    if pgerr.constraint() == Some(ESS_CLIENT_TABLE_SECRET_CNSTRT)
                        || pgerr.constraint() == Some(ESS_CLIENT_TABLE_USER_CNSTRT)
                    {
                        return EssError::UsernameAlreadyExists(user.username.clone());
                    }
                }
                EssError::Sqlx(sqlxerr)
            })?;

        let secret = rec.try_get::<String, _>(0)?;

        println!("[db] username: {} added ", &user.username);

        if secret_as_qr_code {
            Ok(self.otpist.secret_to_qr_code(&user.username, &secret))
        } else {
            Ok(convert_to_base32(&secret))
        }
    }

    pub async fn update_user(&self, username: &str, userupd: UserUpdate) -> Result<()> {
        println!("[db] updating username: {} ...", username);

        if userupd.first_name.is_none() && userupd.last_name.is_none() {
            return Err(EssError::InvalidInputParameters);
        }

        let mut qb: QueryBuilder<Postgres> =
            QueryBuilder::new(format!("UPDATE {} SET ", ESS_CLIENT_TABLE));

        if let Some(name) = userupd.first_name {
            println!(
                "[db] updating for username: {} first name: {} ...",
                username, name
            );
            qb.push("firstname = ").push_bind(name);
        }

        if let Some(name) = userupd.last_name {
            println!(
                "[db] updating for username: {} last name: {} ...",
                username, name
            );
            qb.push("lastname = ").push_bind(name);
        }

        qb.push(" WHERE username = ")
            .push_bind(username)
            .push(" RETURNING username;");

        let rec = qb.build().fetch_one(&self.pool).await?;

        let uname = rec.try_get::<String, _>(0)?;

        println!("[db] username: {} updated ", uname);
        Ok(())
    }

    pub async fn delete_user(&self, username: &str) -> Result<()> {
        println!("[db] deleting username: {} ...", username);

        let mut qb: QueryBuilder<Postgres> = QueryBuilder::new("DELETE FROM ");

        qb.push(ESS_CLIENT_TABLE)
            .push(" WHERE username = ")
            .push_bind(username)
            .push(" RETURNING username;");

        let rec = qb.build().fetch_one(&self.pool).await?;
        let uname = rec.try_get::<String, _>(0)?;

        println!("[db] username: {} deleted ", uname);
        Ok(())
    }

    pub fn with_otpist(&mut self, otpist: Otpist) {
        self.otpist = otpist;
    }

    pub async fn verify_user(&self, username: &str, one_time_password: Option<&str>) -> Result<()> {
        let user = self.get_user(username).await?;
        let secret = user.secret.ok_or(EssError::OneTimePasswordVerifyFailed)?;

        match one_time_password {
            Some(otp) => {
                println!("[db] verifying username: {} and otp: {} ...", username, otp);

                if self.otpist.verify_code(&secret, otp) {
                    println!("[db] verify OK!");
                } else {
                    println!("[db] verify failed!");
                    return Err(EssError::OneTimePasswordVerifyFailed);
                }
            }
            None => {
                let code = self.otpist.code(&secret)?;
                println!("[db] generate for {} new otp code: {}", username, code);
            }
        };

        Ok(())
    }

    pub async fn get_user(&self, username: &str) -> Result<User> {
        println!("Getting details for username: {} ...", username,);

        let useropt = sqlx::query_as::<_, User>(SELECT_USER)
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;

        match useropt {
            Some(user) => Ok(user),
            None => Err(EssError::DbUserNotFound(String::from(username))),
        }
    }

    pub async fn get_user_as_json(&self, username: &str) -> Result<JsonValue> {
        let user = self.get_user(username).await?; // DbUserNotFound returns here
        serde_json::to_value(user).map_or_else(|_| Ok(JsonValue::default()), |j| Ok(j))
    }

    pub async fn get_all(&self, udatafn: UserDataFn) -> Result<()> {
        println!("Getting all user details ...");
        let mut stream = sqlx::query_as::<_, User>(SELECT_ALL).fetch(&self.pool);

        while let Some(usr) = stream.try_next().await? {
            if !udatafn(usr) {
                println!("[db] receive stop from caller, quit get-all user loop ...");
            }
        }

        Ok(())
    }

    pub async fn get_all_as_json(&self) -> Result<JsonValue> {
        let (write, mut read) = unbounded::<User>();
        self.get_all(Box::new(move |usr| {
            async_std::task::block_on(async { write.send(usr).await }).map_or_else(
                |e| {
                    println!("[db] failed send user data: {}", e);
                    false
                },
                |_| true,
            )
        }))
        .await?;

        let mut jvec = Vec::<JsonValue>::new();
        while let Some(usr) = read.next().await {
            match serde_json::to_value(&usr) {
                Ok(jusr) => {
                    jvec.push(jusr);
                }
                Err(e) => {
                    jvec.push(JsonValue::default());
                    println!(
                        "[db] failed parse user data for: {}, error: {}",
                        usr.username, e
                    )
                }
            };
        }
        Ok(JsonValue::Array(jvec))
    }
}

pub async fn db_tool(dbopt: DbOpt) -> Result<()> {
    let conn_details = ConnectionDetails::new(Some(&dbopt));
    let mut db = match &dbopt.action {
        DbCommand::Connect(_) => conn_details.connect(1, false).await?,
        _ => conn_details.connect(ESS_DB_DEFAULT_POOL_SIZE, true).await?,
    };

    match dbopt.action {
        DbCommand::Init(initopts) => db.init(initopts).await,
        DbCommand::Connect(_) => Ok(()),
        DbCommand::Insert { user, qr_code } => {
            let secret = db.insert_user(user, qr_code).await?;
            println!("[db] user inserted with secret: {}", secret);
            Ok(())
        }
        DbCommand::Update {
            username,
            user_data,
        } => db.update_user(&username, user_data).await,
        DbCommand::Delete { username } => db.delete_user(&username).await,
        DbCommand::Verify {
            username,
            one_time_password,
            flags,
        } => {
            if flags.length.is_some() || flags.timeslice.is_some() || flags.discrepancy.is_some() {
                db.with_otpist(Otpist::new_with(
                    flags.length.unwrap_or(crate::otp::OTP_DEFAULT_CODE_LEN),
                    flags
                        .timeslice
                        .unwrap_or(crate::otp::OTP_DEFAULT_EXPIRE_CODE_SEC),
                    flags
                        .discrepancy
                        .unwrap_or(crate::otp::OTP_DEFAULT_DISCREPANCY),
                ));
            }

            db.verify_user(&username, one_time_password.as_ref().map(|s| s.as_str()))
                .await
        }
        DbCommand::GetUser { username } => {
            async {
                println!("User: \n{}", db.get_user_as_json(&username).await?);
                Ok(())
            }
            .await
        }
        DbCommand::GetAll => {
            async {
                let jarray = db.get_all_as_json().await?;
                println!("All users: \n{}", serde_json::to_string_pretty(&jarray)?);
                Ok(())
            }
            .await
        }
    }
}
