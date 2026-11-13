// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("ant-shots-{name}-{}", crate::storage::unique_id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn frame(value: u8) -> Option<Frame> {
    Some((4, 2, [value, value, value, 255].repeat(8)))
}

#[test]
fn names_carry_the_run_time_and_parse_back() {
    assert_eq!(file_name(123_456), "t+000123.4s.png");
    assert_eq!(file_name(0), "t+000000.0s.png");
    assert_eq!(parse_name("t+000123.4s.png"), Some(123_400));
    assert_eq!(parse_name("vm-screen-1.png"), None);
    assert_eq!(parse_name("t+12.34s.png"), None);
    assert_eq!(time_label(83_400), "+1 min 23.4 s");
    assert_eq!(time_label(2_500), "+2.5 s");
}

#[test]
fn the_interval_is_kept_between_one_and_999() {
    assert_eq!(clamp_interval(0), 1);
    assert_eq!(clamp_interval(10), 10);
    assert_eq!(clamp_interval(999), 999);
    assert_eq!(clamp_interval(9999), 999);
}

#[test]
fn an_unchanged_screen_is_skipped_and_counted() {
    let run = dir("skip");
    let mut next = 1u8;
    let values = [1u8, 1, 2, 2, 2];
    let mut shooter = Shooter::new(
        || {
            let value = values[usize::from(next) - 1];
            next += 1;
            frame(value)
        },
        &run,
        5,
    );
    for t in 0..5 {
        shooter.tick(t * 5000);
    }
    assert_eq!(shooter.series().taken, 2);
    assert_eq!(shooter.series().unchanged, 3);
    let shots = list(&run);
    assert_eq!(shots.len(), 2);
    assert_eq!(shots[0].t_ms, 0);
    assert_eq!(shots[1].t_ms, 10_000);
    assert!(
        std::fs::read(&shots[0].path)
            .unwrap()
            .starts_with(b"\x89PNG")
    );
    // The thread saves the counts at its end (not at every skipped tick).
    shooter.save_series();
    assert_eq!(series(&run).unwrap().unchanged, 3);
    std::fs::remove_dir_all(&run).unwrap();
}

#[test]
fn a_screen_with_no_picture_yet_is_counted_not_saved() {
    let run = dir("none");
    let mut shooter = Shooter::new(|| None, &run, 5);
    shooter.tick(0);
    assert_eq!(shooter.series().no_screen, 1);
    assert!(list(&run).is_empty());
    std::fs::remove_dir_all(&run).unwrap();
}

#[test]
fn the_count_bound_ends_the_series_with_a_notice() {
    let run = dir("count");
    let mut value = 0u8;
    let mut shooter = Shooter::new(
        || {
            value += 1;
            frame(value)
        },
        &run,
        1,
    )
    .with_bounds(2, MAX_BYTES);
    for t in 0..4 {
        shooter.tick(t * 1000);
    }
    assert!(shooter.done());
    assert_eq!(shooter.series().taken, 2);
    let why = shooter.series().stopped.clone().unwrap();
    assert!(why.contains("2 pictures"), "{why}");
    assert!(shooter.series().note().contains("Stopped early"));
    assert_eq!(list(&run).len(), 2);
    std::fs::remove_dir_all(&run).unwrap();
}

#[test]
fn the_byte_bound_ends_the_series() {
    let run = dir("bytes");
    let mut value = 0u8;
    let mut shooter = Shooter::new(
        || {
            value += 1;
            frame(value)
        },
        &run,
        1,
    )
    .with_bounds(500, 10);
    shooter.tick(0);
    assert!(shooter.done());
    assert_eq!(shooter.series().taken, 0);
    assert!(shooter.series().stopped.as_ref().unwrap().contains("MiB"));
    std::fs::remove_dir_all(&run).unwrap();
}

#[test]
fn a_part_file_is_not_listed() {
    let run = dir("part");
    std::fs::create_dir_all(run.join(FOLDER)).unwrap();
    std::fs::write(run.join(FOLDER).join("t+000001.0s.png.part"), b"x").unwrap();
    std::fs::write(run.join(FOLDER).join("t+000002.0s.png"), b"x").unwrap();
    assert_eq!(list(&run).len(), 1);
    std::fs::remove_dir_all(&run).unwrap();
}

/// A one-screen RFB server on a unix socket: an 8 x 4 screen of `colour`,
/// then of `later` after `change_ms`; Raw rectangles only.
fn fake_screen(
    socket: &Path,
    colour: [u8; 3],
    later: [u8; 3],
    change_ms: u64,
) -> std::thread::JoinHandle<()> {
    use std::io::{Read, Write};
    let listener = std::os::unix::net::UnixListener::bind(socket).unwrap();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let paint = |rgb: [u8; 3]| -> Vec<u8> {
            let mut update = vec![0, 0, 0, 1, 0, 0, 0, 0, 0, 8, 0, 4, 0, 0, 0, 0];
            for _ in 0..32 {
                update.extend_from_slice(&[rgb[0], rgb[1], rgb[2], 0]);
            }
            update
        };
        stream.write_all(b"RFB 003.008\n").unwrap();
        let mut buffer = [0u8; 12];
        stream.read_exact(&mut buffer).unwrap();
        stream.write_all(&[1, 1]).unwrap();
        stream.read_exact(&mut buffer[..1]).unwrap();
        stream.write_all(&0u32.to_be_bytes()).unwrap();
        stream.read_exact(&mut buffer[..1]).unwrap();
        let mut init = Vec::new();
        init.extend_from_slice(&8u16.to_be_bytes());
        init.extend_from_slice(&4u16.to_be_bytes());
        init.extend_from_slice(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 0, 8, 16, 0, 0, 0]);
        init.extend_from_slice(&4u32.to_be_bytes());
        init.extend_from_slice(b"fake");
        stream.write_all(&init).unwrap();
        let began = Instant::now();
        let mut sent_first = false;
        let mut sent_later = false;
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        loop {
            let mut kind = [0u8; 1];
            match stream.read(&mut kind) {
                Ok(0) => return,
                Ok(_) => {
                    let rest = match kind[0] {
                        0 => 19,
                        2 => {
                            let mut head = [0u8; 3];
                            if stream.read_exact(&mut head).is_err() {
                                return;
                            }
                            usize::from(u16::from_be_bytes([head[1], head[2]])) * 4
                        }
                        3 => 9,
                        _ => return,
                    };
                    let mut skip = vec![0u8; rest];
                    if stream.read_exact(&mut skip).is_err() {
                        return;
                    }
                    if kind[0] == 3 && !sent_first {
                        sent_first = true;
                        if stream.write_all(&paint(colour)).is_err() {
                            return;
                        }
                    }
                }
                Err(_) => {}
            }
            if sent_first
                && !sent_later
                && began.elapsed() >= Duration::from_millis(change_ms)
                && stream.write_all(&paint(later)).is_ok()
            {
                sent_later = true;
            }
        }
    })
}

#[test]
fn a_run_series_takes_pictures_of_a_live_screen_and_skips_the_unchanged() {
    let run = dir("live");
    let socket = run.join("vnc.sock");
    let server = fake_screen(&socket, [200, 0, 0], [0, 0, 200], 2200);
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap();
    let mut shots = TimedShots::start(socket.clone(), run.clone(), 1, started);
    std::thread::sleep(Duration::from_millis(4600));
    let series = shots.finish().expect("the worker ends");
    assert!(series.taken >= 2, "{series:?}");
    assert!(series.unchanged >= 1, "{series:?}");
    assert_eq!(series.stopped, None);
    let listed = list(&run);
    assert_eq!(listed.len() as u64, series.taken);
    assert!(listed.windows(2).all(|w| w[0].t_ms < w[1].t_ms));
    assert!(
        listed[0].t_ms >= 1000,
        "the first picture is at the first tick"
    );
    assert_eq!(
        crate::timed_shots::series(&run).map(|s| s.taken),
        Some(series.taken)
    );
    assert!(series.note().contains("saved"));
    drop(shots);
    let _ = server.join();
    std::fs::remove_dir_all(&run).unwrap();
}
