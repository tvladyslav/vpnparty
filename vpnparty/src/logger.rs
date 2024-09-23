/// Simplest possible logger

/// Start from 3, this way warn, err and critical are always on.
pub static mut VERBOSITY: u8 = 3;

/// Increase verbosity level
pub fn set_verbosity(verbosity: u8) {
    unsafe { VERBOSITY += verbosity };
}

#[macro_export]
macro_rules! critical {
    ($($arg:tt)+) => (if unsafe {$crate::logger::VERBOSITY} > 0 {
        eprint!("\x1b[31mError:\x1b[0m ");
        eprintln!($($arg)+);
    })
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => (if unsafe {$crate::logger::VERBOSITY} > 1 {
        eprint!("\x1b[31mError:\x1b[0m ");
        eprintln!($($arg)+);
    })
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => (if unsafe {$crate::logger::VERBOSITY} > 2 {
        print!("\x1b[93mWarning:\x1b[0m ");
        println!($($arg)+);
    })
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)+) => (if unsafe {$crate::logger::VERBOSITY} > 3 { println!($($arg)+) })
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => (if unsafe {$crate::logger::VERBOSITY} > 4 { println!($($arg)+) })
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)+) => (if unsafe {$crate::logger::VERBOSITY} > 5 { println!($($arg)+) })
}
