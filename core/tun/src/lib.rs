// Copyright Gleb Obitotsky <glebobitotsky@yandex.com> 2026.
//
// The code is distributed under the Mozilla Public License Version 2.0 license
// (you can find the license file in the root folder).

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::sync::Arc;
use tokio::sync::mpsc;

const TUNSETIFF: u64 = 0x400454ca; 
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;

#[repr(C)]
struct IfReq {
    ifr_name: [u8; 16],
    ifr_flags: i16,
}

#[unsafe(no_mangle)]
pub extern "C" fn start_tun_interface() -> i32 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus_get()) 
        .enable_all()
        .build() 
    {
        Ok(rt) => rt,
        Err(_) => return -1,
    };

    runtime.block_on(async {
        match init_engine("tun0").await {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[TUN Error] Инициализация провалилась: {}", e);
                -2
            }
        }
    })
}

async fn init_engine(iface_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let tun_file = create_tun_device(iface_name)?;
    let tun_file = Arc::new(tun_file);

    let (tx, rx) = mpsc::channel::<Vec<u8>>(4096);

    let tun_reader = Arc::clone(&tun_file);
    tokio::task::spawn_blocking(move || {
        if let Err(e) = run_read_loop(tun_reader, tx) {
            eprintln!("[TUN Reader] Ошибка цикла чтения: {}", e);
        }
    });

    run_worker_pool(rx).await;

    Ok(())
}

fn create_tun_device(name: &str) -> Result<File, Box<dyn std::error::Error>> {
    let file = File::options()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;

    let mut ifr = IfReq {
        ifr_name: [0; 16],
        ifr_flags: IFF_TUN | IFF_NO_PI,
    };

    let bytes = name.as_bytes();
    let len = bytes.len().min(15);
    ifr.ifr_name[..len].copy_from_slice(&bytes[..len]);

    unsafe {
        let fd = file.as_raw_fd();
        let res = nix::libc::ioctl(fd, TUNSETIFF, &mut ifr);
        if res < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }

    println!("[TUN] Интерфейс {} успешно поднят", name);
    Ok(file)
}

fn run_read_loop(tun: Arc<File>, tx: mpsc::Sender<Vec<u8>>) -> Result<(), std::io::Error> {
    let mut buf = [0u8; 1600]; 

    loop {
        let n = tun.read_at(&mut buf, 0)?;
        if n == 0 { break; }

        let packet = buf[..n].to_vec();

        if tx.blocking_send(packet).is_err() {
            break;
        }
    }
    Ok(())
}

async fn run_worker_pool(mut rx: mpsc::Receiver<Vec<u8>>) {
    println!("[TUN Pool] Многопоточный пул обработчиков запущен");

    while let Some(packet) = rx.recv().await {
        tokio::spawn(async move {
            process_packet(packet).await;
        });
    }
}

async fn process_packet(packet: Vec<u8>) {
    if packet.is_empty() { return; }

    let ip_version = packet[0] >> 4;

    match ip_version {
        4 => {
            
        },
        6 => {
            
        },
        _ => {
        
        }
    }
}

fn num_cpus_get() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}