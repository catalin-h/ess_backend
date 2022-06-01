extern crate quick_error;

pub mod clients_db;
pub mod command;
pub mod ess_errors;
pub mod messaging;
pub mod otp;
pub mod webservice;

use clap::{Parser, Subcommand};
use clients_db::{db_tool, DbOpt};
use command::{command_task, get_service_health_status, send_service_stop};
use ess_errors::Result;
use futures::{select, FutureExt};
use messaging::MessageChannel;

/// Async/await summary:
/// ipc future : to receive exit signal
/// tide future : waits for income requests
/// postgres connect future : waits for db connections
/// postgres query futures : waits for db responses
async fn event_loop() -> Result<()> {
    let (query, reply) = MessageChannel::duplex("ctrl", "srv");

    // spawn command listener on another thread
    let cmd_task = async_std::task::spawn(command_task(query)).fuse();
    let reply_task = reply.receive().fuse();
    let ws_task_admin = async_std::task::spawn(webservice::launch_ess_ws(true)).fuse();
    let ws_task_client = async_std::task::spawn(webservice::launch_ess_ws(false)).fuse();
    let (sig_send, sig_recv) = async_std::channel::unbounded();
    let sig_recv_task = sig_recv.recv().fuse();

    tide::log::with_level(
        std::env::var("ESS_LOG_LEVEL")
            .as_ref()
            .map_or("info", |lvl| lvl.as_str())
            .parse()
            .unwrap_or(tide::log::LevelFilter::Info),
    );

    ctrlc::set_handler(move || {
        println!("[signals] receive stop signal, forwarding stop signal ...");
        match async_std::task::block_on(async { sig_send.send(()).await }) {
            Ok(_) => println!("[signals] the stop signal was forwarded"),
            Err(e) => println!("[signals] failed to forward the stop signal, error: {}", e),
        };
    })?;

    futures::pin_mut!(
        cmd_task,
        reply_task,
        ws_task_admin,
        ws_task_client,
        sig_recv_task
    );

    loop {
        select! {
            ret = &mut sig_recv_task => {
                match ret {
                    Ok(_) => println!("[events] [signals] receive stop signal, must exit ..."),
                    Err(err) => println!("[events] [signals] receive stop signal but with error: {}, must exit ...", err),
                };
                break;
            },

            // Receives queries like health check
            new_msg = &mut reply_task =>
            if !reply.is_closed() {
                match new_msg {
                    Ok(msg) => {
                        reply.handle_incoming_msg(msg);
                        reply_task.set(reply.receive().fuse());
                    }
                    Err(e) => println!("[events] failed to retrieve the last command, error: {}", e),
                }
            },

            // Receives stop service signal
            cmd_task_ret = &mut cmd_task => {
                match cmd_task_ret {
                    Ok(_) => println!("[events] command task terminated without error"),
                    Err(err) => println!("[events] command task terminated with error: {}", err),
                }
                break;
            },

            ret = &mut ws_task_admin => {
                match ret {
                    Ok(_) => println!("[events] admin webservice exited without error"),
                    Err(err) => println!("[events] admin webservice exited with error: {}", err),
                };
                break;
            },

            ret = &mut ws_task_client => {
                match ret {
                    Ok(_) => println!("[events] client webservice exited without error"),
                    Err(err) => println!("[events] client webservice exited with error: {}", err),
                };
                break;
            },

            // Dummy
            complete => println!("[events] select completed")
        }
    }

    println!("[events] exiting events loop ..");

    Ok(())
}

/// The ess backend service.
///
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = false)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Starts the ess service
    Start,
    /// Stop an already running service
    Stop,
    /// Checks the health of an existing ess_backend service
    Health,
    /// Database actions. Run '<EXE> db help' for more details
    Db(DbOpt),
}

#[async_std::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Stop => send_service_stop(),
        Commands::Health => get_service_health_status(),
        Commands::Start => event_loop().await,
        Commands::Db(opt) => db_tool(opt).await,
    }
}
