#include <unistd.h>

#include "persist.h"

using namespace std;

namespace {
/// Append a 32-bit value to a buffer, in native byte order
void append_u32(vector<uint8_t> &buf, uint32_t x) {
  uint8_t *p = reinterpret_cast<uint8_t *>(&x);
  buf.insert(buf.end(), p, p + sizeof(uint32_t));
}

/// Append the bytes of a string to a buffer
void append_str(vector<uint8_t> &buf, const string &s) {
  buf.insert(buf.end(), s.begin(), s.end());
}

/// Pad a record with zero bytes to a 4-byte boundary, then append it to the
/// end of the file with a single write() and fsync() it.  Because the whole
/// record goes out in one system call, concurrent records cannot interleave.
///
/// @param logfile The file to write into
/// @param buf     The fully-encoded record
void write_record(FILE *logfile, vector<uint8_t> &buf) {
  size_t pad = (4 - (buf.size() % 4)) % 4;
  buf.insert(buf.end(), pad, 0);

  // make sure the stream buffer is flushed before using the fd directly
  fflush(logfile);
  int fd = fileno(logfile);
  if (fd >= 0) {
    lseek(fd, 0, SEEK_END);
    ssize_t wrote = write(fd, buf.data(), buf.size());
    (void)wrote; // suppress unused warning in strict builds
    fsync(fd);
  }
}
} // namespace

/// Atomically add an incremental update message to the open file
///
/// This variant puts a delimiter, a string, two vectors, and a zero into the
/// file.
///
/// @param logfile The file to write into
/// @param delim   The 4-byte string that starts the log entry
/// @param s       The string to add to the message
/// @param v1      The first vector to add to the message
/// @param v2      The second vector to add to the message
void log_svv0(FILE *logfile, const string &delim, const string &s,
              const vector<uint8_t> &v1, const vector<uint8_t> &v2) {
  if (logfile == nullptr)
    return;

  vector<uint8_t> buf;
  buf.reserve(delim.size() + 4 * 4 + s.size() + v1.size() + v2.size() + 4);
  append_str(buf, delim);
  append_u32(buf, static_cast<uint32_t>(s.size()));
  append_u32(buf, static_cast<uint32_t>(v1.size()));
  append_u32(buf, static_cast<uint32_t>(v2.size()));
  append_u32(buf, 0u);
  append_str(buf, s);
  buf.insert(buf.end(), v1.begin(), v1.end());
  buf.insert(buf.end(), v2.begin(), v2.end());
  write_record(logfile, buf);
}

/// Atomically add an incremental update message to the open file
///
/// This variant puts a delimiter, a string, and a vector into the file.
///
/// @param logfile The file to write into
/// @param delim   The 4-byte string that starts the log entry
/// @param s1      The string to add to the message
/// @param v1      The vector to add to the message
void log_sv(FILE *logfile, const string &delim, const string &s1,
            const vector<uint8_t> &v1) {
  if (logfile == nullptr)
    return;

  vector<uint8_t> buf;
  buf.reserve(delim.size() + 2 * 4 + s1.size() + v1.size() + 4);
  append_str(buf, delim);
  append_u32(buf, static_cast<uint32_t>(s1.size()));
  append_u32(buf, static_cast<uint32_t>(v1.size()));
  append_str(buf, s1);
  buf.insert(buf.end(), v1.begin(), v1.end());
  write_record(logfile, buf);
}

/// Atomically add an incremental update message to the open file
///
/// This variant puts a delimiter and a string into the file
///
/// @param logfile The file to write into
/// @param delim   The 4-byte string that starts the log entry
/// @param s1      The string to add to the message
void log_s(FILE *logfile, const string &delim, const string &s1) {
  if (logfile == nullptr)
    return;

  vector<uint8_t> buf;
  buf.reserve(delim.size() + 4 + s1.size() + 4);
  append_str(buf, delim);
  append_u32(buf, static_cast<uint32_t>(s1.size()));
  append_str(buf, s1);
  write_record(logfile, buf);
}
