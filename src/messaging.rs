use crate::ess_errors::{EssError, Result};
use async_std::channel::{unbounded, Receiver, Sender};

pub mod messages {
    pub const MSG_STOP: &str = "stop";
    pub const MSG_HEALTH_CHECK: &str = "health";
    pub const MSG_OK: &str = "ok";
    pub const MSG_NOT_OK: &str = "notok";
    pub const MSG_END: &str = "<END>";
}
pub use messages::*;

pub struct MessageChannel {
    command_sender: Sender<String>,
    result_receiver: Receiver<String>,
    name: String,
}

pub const DEFAULT_TIMEOUT: u64 = 10; //sec
pub const RECV_TIMEOUT: u64 = 4 * DEFAULT_TIMEOUT; //sec

impl MessageChannel {
    pub fn new(sender: Sender<String>, receiver: Receiver<String>, name: &str) -> Self {
        MessageChannel {
            command_sender: sender,
            result_receiver: receiver,
            name: String::from(name),
        }
    }

    pub fn duplex(client_name: &str, server_name: &str) -> (Self, Self) {
        let (tx_cmd, rx_cmd) = unbounded::<String>();
        let (tx_res, rx_res) = unbounded::<String>();
        (
            Self::new(tx_cmd, rx_res, client_name),
            Self::new(tx_res, rx_cmd, server_name),
        )
    }

    pub fn send(&self, message: &str) -> Result<()> {
        let duration = std::time::Duration::from_secs(DEFAULT_TIMEOUT);

        println!(
            "[msg] [{}] writing to channel: '{}' ...",
            self.name, message
        );

        // task::block_on(send_future)?;
        // Ok(())

        async_std::task::block_on(async {
            // Why use double '??' ?
            // Because timeout returns a double error of type:
            // std::result::Result<(), async_std::channel::SendError<std::string::String>>
            async_std::future::timeout(duration, self.command_sender.send(String::from(message)))
                .await??;

            println!(
                "[msg] [{}] finish writing to channel: '{}'",
                self.name, message
            );

            Ok(())
        })
    }

    pub fn recv(&self, timeout: u64) -> Result<String> {
        let duration = std::time::Duration::from_secs(timeout);

        println!("[msg] [{}] reading from channel ...", self.name);

        async_std::task::block_on(async {
            // Why use double '??' ?
            // Because timeout returns a double error of type:
            // std::result::Result<(), async_std::channel::RecvError>
            let res = async_std::future::timeout(duration, self.receive()).await??;

            println!(
                "[msg] [{}] [async-recv] read from channel: '{}'",
                self.name, res
            );

            Ok(res)
        })
    }

    pub fn send_recv(&self, message: &str) -> Result<String> {
        self.send(message)?;
        self.recv(RECV_TIMEOUT)
    }

    pub async fn receive(&self) -> Result<String> {
        println!("[msg] [rx-async] [{}] ...", self.name);
        let input = self.result_receiver.recv().await?;
        println!("[msg] [rx-async] [{}] data: {}", self.name, input);
        Ok(input)
    }

    pub fn handle_incoming_msg(&self, cmd: String) {
        let res = match cmd.trim() {
            MSG_HEALTH_CHECK => self.send(MSG_OK),
            _ => Err(EssError::UnknownMsgType(cmd.clone())),
        };

        match res {
            Ok(_) => println!("[msg] [handler] [{}] command: {} handled", self.name, cmd),
            Err(e) => println!(
                "[msg] [handler] [{}] failed to handle command, error: {}",
                self.name, e
            ),
        };
    }
}
