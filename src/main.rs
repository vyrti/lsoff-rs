use lsoff_rs::run;
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();

    let mut out_writer = std::io::BufWriter::with_capacity(64 * 1024, stdout.lock());
    let mut err_writer = std::io::BufWriter::with_capacity(16 * 1024, stderr.lock());

    if let Err(e) = run(&args, stdin.lock(), &mut out_writer, &mut err_writer) {
        if !e.msg.is_empty() {
            let _ = writeln!(err_writer, "{}", e.msg);
        }
        let _ = err_writer.flush();
        std::process::exit(e.code);
    }
    let _ = out_writer.flush();
}
