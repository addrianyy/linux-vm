use super::errcodes as ec;
use std::io::ErrorKind;

pub fn ekind_to_linux_error(kind: ErrorKind) -> i64 {
    match kind {
        ErrorKind::NotFound         => -ec::ENOENT,
        ErrorKind::PermissionDenied => -ec::EACCES,
        ErrorKind::BrokenPipe       => -ec::EPIPE,
        ErrorKind::AlreadyExists    => -ec::EEXIST,
        ErrorKind::WouldBlock       => -ec::EWOULDBLOCK,
        ErrorKind::Interrupted      => -ec::EINTR,
        ErrorKind::InvalidInput     => -ec::EINVAL,
        ErrorKind::Other            => -ec::ENOENT,
        _                           => panic!("Unhandled IO error kind {:?}.", kind),
    }
}
