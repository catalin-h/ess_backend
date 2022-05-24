use crate::ess_errors::{EssError, Result};
use crate::messaging::{messages::*, MessageChannel, DEFAULT_TIMEOUT, RECV_TIMEOUT};
use quick_error::ResultExt;

use async_std::{
    io::BufReader,
    os::unix::net::{UnixListener, UnixStream},
    prelude::*,
    task,
};
use futures::{select, FutureExt};
use std::fs::{metadata, remove_file};

const ESS_SOCK: &str = "/tmp/ess.sock";

fn write_to_stream(stream: &mut UnixStream, message: &str) -> Result<()> {
    let duration = std::time::Duration::from_secs(DEFAULT_TIMEOUT);

    println!("[stream] writing to stream: '{}' ...", message);
    task::block_on(async {
        async_std::io::timeout(duration, async {
            stream
                .write_all(format!("{}\n{}\n", message, MSG_END).as_bytes())
                .await?;
            stream.flush().await?;
            Ok(())
        })
        .await?;
        println!("[stream] done writing to stream");
        Ok(())
    })
}

fn read_from_stream(stream: &UnixStream, timeout: u64) -> Result<Vec<String>> {
    let mut read_line_iter = BufReader::new(stream).lines().fuse();
    let mut cmd_buffer: Vec<String> = vec![];
    let duration = std::time::Duration::from_secs(timeout);

    println!("[stream] reading line from stream ...");

    task::block_on(async {
        async_std::io::timeout(duration, async {
            loop {
                select! {
                    line = read_line_iter.next().fuse() => match line {
                        Some(line) => {
                            let line = line?;
                            match &line[..] {
                                MSG_END => {
                                    println!("[stream] receive end message, done reading");
                                    break;
                                },
                                _ => println!("[stream] receive line: '{}'", line)
                            }
                            cmd_buffer.push(line);
                        }
                        None => break,
                    }
                }
            }
            Ok(())
        })
        .await?;
        Ok(cmd_buffer)
    })
}

fn handle_health_check(mch: &MessageChannel, stream: &mut UnixStream) -> Result<()> {
    let is_ok = match mch.send_recv(MSG_HEALTH_CHECK) {
        Ok(res) => res == MSG_OK,
        Err(e) => {
            println!("[command] failed get service health: error: {}", e);
            false
        }
    };

    if is_ok {
        println!("[command] [handler] service is healthy");
        write_to_stream(stream, MSG_OK)?;
    } else {
        println!("[command] [handler] service is not healthy");
        write_to_stream(stream, MSG_NOT_OK)?;
    }

    Ok(())
}

fn client_connect() -> Result<UnixStream> {
    // No socket means no service
    if metadata(ESS_SOCK).is_err() {
        return Err(EssError::ServiceNotLoaded);
    }

    println!("[command] [client] connecting to {} ...", ESS_SOCK);
    let stream = task::block_on(async_std::io::timeout(
        std::time::Duration::from_secs(DEFAULT_TIMEOUT),
        UnixStream::connect(ESS_SOCK),
    ))?;

    println!("[command] [client] connected to {}", ESS_SOCK);

    Ok(stream)
}

pub fn get_service_health_status() -> Result<()> {
    let mut stream = client_connect()?;

    write_to_stream(&mut stream, MSG_HEALTH_CHECK)?;
    let messages = read_from_stream(&stream, RECV_TIMEOUT)?;

    if messages.is_empty() || messages.contains(&String::from(MSG_NOT_OK)) {
        println!("[command] [client] found service not healthy");
        return Err(EssError::ServiceNotHealthy);
    }

    println!("[command] [client] found service healthy");

    Ok(())
}

pub fn send_service_stop() -> Result<()> {
    let mut stream = client_connect()?;
    write_to_stream(&mut stream, MSG_STOP)?;
    Ok(())
}

fn handle_incoming_stream(stream: UnixStream, mch: &mut MessageChannel) -> bool {
    let cmds = match read_from_stream(&stream, RECV_TIMEOUT) {
        Ok(cmds) => cmds,
        Err(e) => {
            println!("[command] failed get commands, error: {}", e);
            return true;
        }
    };

    let mut stream = stream;

    for cmd in cmds {
        println!("[command] handling: {}", cmd);

        match cmd.trim() {
            MSG_STOP => {
                println!("[command] receive stop signal, must exit");
                return false;
            }
            MSG_HEALTH_CHECK => {
                println!("[command] checking service health ...");
                if let Err(e) = handle_health_check(&mch, &mut stream) {
                    println!("[command] failed checking service health, what: {} ", e);
                }
            }
            _ => println!("[command] unable to handle command: {}", cmd),
        }
    }

    true
}

fn remove_socket() -> Result<()> {
    if metadata(ESS_SOCK).is_ok() {
        println!("[command] removing socket: {} ...", ESS_SOCK);
        remove_file(ESS_SOCK).context(ESS_SOCK)?;
    }

    Ok(())
}

pub async fn command_task(mch: MessageChannel) -> Result<()> {
    let mut mch = mch;

    println!("[command] starting command task ...");
    remove_socket()?;
    println!("[command] binding to {} ...", ESS_SOCK);
    let listener = task::block_on(async_std::io::timeout(
        std::time::Duration::from_secs(DEFAULT_TIMEOUT),
        UnixListener::bind(ESS_SOCK),
    ))?;

    println!("[command] listening ...");

    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
        match stream {
            Ok(stream) => {
                if handle_incoming_stream(stream, &mut mch) {
                    println!("[command] continue handle next commands");
                } else {
                    println!("[command] exiting command handling ...");
                    break;
                }
            }
            Err(e) => println!("[command] failed getting incomming stream, error: {}", e),
        }
    }

    remove_socket()?;

    println!("[command] task ended ok");

    Ok(())
}
