/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "log.h"

#include <stdlib.h>

#include <deque>
#include <fstream> 
#include <memory> 
#include <sstream> 
#include <unordered_map> 
#include <string.h>

// #include "DumpCommand.h" 
// #include "Flags.h" 
// #include "GdbConnection.h" 
// #include "GdbServer.h" 
// #include "RecordSession.h" 
// #include "core.h" 
// #include "ftrace.h" 
// #include "kernel_metadata.h" 
// #include 
//"util.h"

/* Determines what the name of the global logging env variable is */ 
using namespace std;

namespace NAMESPACE {

struct LogModule {
  string name;
  LogLevel level;
};

static LogLevel to_log_level(const string& str) {
  if (str == "debug") {
    return LOG_debug;
  }
  if (str == "info") {
    return LOG_info;
  }
  if (str == "warn") {
    return LOG_warn;
  }
  if (str == "error") {
    return LOG_error;
  }
  if (str == "fatal") {
    return LOG_fatal;
  }
  fprintf(stderr, "Log level %s in %s is not valid, assuing 'fatal'\n",
          str.c_str(), TO_STRING(LOGGING_GLOBAL));
  return LOG_fatal;
}

static char simple_to_lower(char ch) {
  // to_lower sucks because it's locale-dependent
  if (ch >= 'A' && ch <= 'Z') {
    return ch + 'a' - 'A';
  }
  return ch;
}

static string simple_to_lower(const string& s) {
  char* buf = new char[s.size() + 1];
  for (size_t i = 0; i < s.size(); ++i) {
    buf[i] = simple_to_lower(s[i]);
  }
  buf[s.size()] = 0;
  return string(buf);
}

#if __has_attribute(require_constant_initialization) 
#define _CONSTANT_STATIC \
  __attribute__((__require_constant_initialization__)) static
#else 
#define _CONSTANT_STATIC static 
#endif

static bool log_globals_initialized = false; static LogLevel default_level = LOG_error;

// These need to be available to other static constructors, so we need to be 
// sure that they can be constant-initialized. Unfortunately some versions of 
// C++ libraries have a bug that causes them not to be. _CONSTANT_STATIC should 
// turn this into a compile error rather than a runtime crash for compilers 
// that support the attribute.

// This is the assignment of log levels to module names. 
// Any module name not mentioned here gets the default_log_level. 
_CONSTANT_STATIC unique_ptr<unordered_map<string, LogLevel>> level_map; 

// This is a cache mapping unlimited-lifetime file name pointers (usually 
// derived from __FILE__) to the associated module name and log level. 
// It's OK for this to contain multiple entries for the same string but 
// with different pointers. 
_CONSTANT_STATIC unique_ptr<unordered_map<const void*, LogModule>> log_modules; 
// This collects a single log message. 
_CONSTANT_STATIC unique_ptr<stringstream> logging_stream; 
// When non-null, log messages are accumulated into this buffer. 
_CONSTANT_STATIC unique_ptr<deque<char>> log_buffer; 
// When non-null, log messages are flushed to this file. 
_CONSTANT_STATIC ostream* log_file; 
// Maximum size of `log_buffer`. 
size_t log_buffer_size;

static void flush_log_file() { log_file->flush(); }

static void init_log_globals() {
  if (log_globals_initialized) {
    return;
  }
  log_globals_initialized = true;
  level_map = unique_ptr<unordered_map<string, LogLevel>>(
      new unordered_map<string, LogLevel>());
  log_modules = unique_ptr<unordered_map<const void*, LogModule>>(
      new unordered_map<const void*, LogModule>());
  logging_stream = unique_ptr<stringstream>(new stringstream());

  const char* buffer = getenv(TO_STRING(LOG_BUFFER));
  if (buffer) {
    log_buffer_size = atoi(buffer);
    if (log_buffer_size) {
      log_buffer = unique_ptr<deque<char>>(new deque<char>());
      atexit(flush_log_buffer);
    }
  }

  const char* filename = getenv(TO_STRING(LOG_FILE));
  ios_base::openmode log_file_open_mode = std::ofstream::out;
  if (!filename) {
    filename = getenv(TO_STRING(APPEND_LOG_FILE));
    log_file_open_mode |= std::ofstream::app;
  }
  if (filename) {
    auto file = new ofstream(filename, log_file_open_mode);
    if (!file->good()) {
      delete file;
    } else {
      log_file = file;
      atexit(flush_log_file);
    }
  }

  if (!log_file) {
    log_file = &cerr;
  }

  const char* log_env = TO_STRING(LOGGING_GLOBAL);
  /* RR specific code. Not generally important
  if (running_under_rr()) {
    log_env = "RR_UNDER_RR_LOG";
  }*/
  char* env = getenv(log_env);
  if (env) {
    env = strdup(env);
    DEBUG_ASSERT(env);
    for (int i = 0; env[i]; ++i) {
      env[i] = simple_to_lower(env[i]);
    }
    char* p = env;
    while (*p) {
      char* end = strchrnul(p, ',');
      char* sep = strchrnul(p, ':');
      string n;
      LogLevel level;
      if (sep >= end) {
        n = string(p, end - p);
        level = LOG_debug;
      } else {
        n = string(p, sep - p);
        if (sep + 1 == end) {
          level = LOG_fatal;
        } else {
          level = to_log_level(string(sep + 1, end - (sep + 1)));
        }
      }
      if (n == "" || n == "all") {
        level_map->clear();
        default_level = level;
      } else {
        (*level_map)[n] = level;
      }
      if (*end) {
        p = end + 1;
      } else {
        p = end;
      }
    }
    free(env);
  }
}

static LogLevel get_log_level(const string& name) {
  init_log_globals();

  auto it = level_map->find(simple_to_lower(name));
  if (it == level_map->end()) {
    return default_level;
  }
  return it->second;
}

static string file_to_name(const char* file) {
  const char* base = strrchr(file, '/');
  if (base) {
    ++base;
  } else {
    base = file;
  }
  const char* dot = strrchr(base, '.');
  string r = dot ? string(base,dot-base) : string(base);
  return r;
}

static LogModule& get_log_module(const char* file) {
  init_log_globals();

  auto it = log_modules->find(file);
  if (it != log_modules->end()) {
    return it->second;
  }
  LogModule m;
  m.name = file_to_name(file);
  m.level = get_log_level(m.name);
  (*log_modules)[file] = m;
  return (*log_modules)[file];
}

void set_all_logging(LogLevel level) {
  default_level = level;
  level_map->clear();
  log_modules->clear();
}

void set_logging(const char* name, LogLevel level) {
  (*level_map)[simple_to_lower(name)] = level;
  log_modules->clear();
}

static const char* log_name(LogLevel level) {
  switch (level) {
    case LOG_fatal:
      return "FATAL";
    case LOG_error:
      return "ERROR";
    case LOG_warn:
      return "WARN";
    case LOG_info:
      return "INFO";
    default:
      return "???";
  }
}

ostream& log_stream() {
  init_log_globals();
  return *logging_stream;
}

static void flush_log_stream() {
  string s = logging_stream->str();
  //ftrace::write(s);
  if (log_buffer) {
    size_t len = s.size();
    if (len >= log_buffer_size) {
      log_buffer->clear();
      log_buffer->insert(log_buffer->end(), s.c_str() + (len - log_buffer_size),
                         s.c_str() + len);
    } else {
      if (log_buffer->size() + len > log_buffer_size) {
        log_buffer->erase(log_buffer->begin(),
                          log_buffer->begin() +
                              (log_buffer->size() + len - log_buffer_size));
      }
      log_buffer->insert(log_buffer->end(), s.c_str(), s.c_str() + len);
    }
  } else {
    *log_file << s;
  }

  logging_stream->str(string());
}

void flush_log_buffer() {
  if (log_buffer) {
    for (char c : *log_buffer) {
      // We could accumulate in a string to speed things up, but this could get
      // called in low-memory situations so be safe.
      *log_file << c;
    }
    log_buffer->clear();
  }
}

template <typename T> static void write_prefix(T& stream, LogLevel level, const char* file, int line,
                         const char* function) {
  int err = errno;
  stream << "[" << log_name(level) << " ";
  if (level <= LOG_error) {
    stream << file << ":" << line << ":";
  }
  stream << function << "()";
  if (level <= LOG_warn && err) {
    //stream << " errno: " << errno_name(err);
    stream << " errno: " << err;
    
  }
  stream << "] ";
}

bool is_logging_enabled(LogLevel level, const char* file) {
  LogModule& m = get_log_module(file);
  return level <= m.level;
}

NewlineTerminatingOstream::NewlineTerminatingOstream(LogLevel level,
                                                     const char* file, int line,
                                                     const char* function)
    : level(level) {
  LogModule& m = get_log_module(file);
  enabled = level <= m.level;
  if (enabled) {
    if (level == LOG_debug) {
      *this << "[" << m.name << "] ";
    } else {
      write_prefix(*this, level, file, line, function);
    }
  }
}

NewlineTerminatingOstream::~NewlineTerminatingOstream() {
  if (enabled) {
    log_stream() << endl;
    flush_log_stream();
    if (level <= LOG_warn) {
      //notifying_abort();
    }
  }
}

CleanFatalOstream::CleanFatalOstream(const char* file, int line,
                                     const char* function) {
  errno = 0;
  write_prefix(*this, LOG_fatal, file, line, function);
}

CleanFatalOstream::~CleanFatalOstream() {
  cerr << endl;
  flush_log_stream();
  exit(1);
}

FatalOstream::FatalOstream(const char* file, int line, const char* function) {
  write_prefix(*this, LOG_fatal, file, line, function);
}

FatalOstream::~FatalOstream() {
  log_stream() << endl;
  flush_log_stream();
  //notifying_abort();
}

/* RR specific code not needed */

#if 0
static const int last_event_count = 20;

static void dump_last_events(const tracestream& trace) {
  fputs("tail of trace dump:\n", stderr);

  dumpflags flags;
  flags.dump_syscallbuf = true;
  flags.dump_recorded_data_metadata = true;
  flags.dump_mmaps = true;
  frametime end = trace.time();
  vector<string> specs;
  char buf[100];
  sprintf(buf, "%lld-%lld", (long long)(end - last_event_count), (long long)(end + 1));
  specs.push_back(string(buf));
  dump(trace.dir(), flags, specs, stderr);
}

static void emergency_debug(task* t) {
  ftrace::stop();

  // enable sigint in case it was disabled. users want to be able to ctrl-c
  // out of this.
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sig_dfl;
  sigaction(sigint, &sa, nullptr);

  recordsession* record_session = t->session().as_record();
  if (record_session) {
    record_session->close_trace_writer(tracewriter::close_error);
  }
  tracestream* trace_stream = t->session().trace_stream();
  if (trace_stream) {
    dump_last_events(*trace_stream);
  }

  if (probably_not_interactive() && !flags::get().force_things &&
      !getenv("running_under_test_monitor")) {
    errno = 0;
    fatal()
        << "(session doesn't look interactive, aborting emergency debugging)";
  }

  flush_log_buffer();

  gdbserver::emergency_debug(t);
  fatal() << "can't resume execution from invalid state";
}
emergencydebugostream::emergencydebugostream(bool cond, const task* t,
                                             const char* file, int line,
                                             const char* function,
                                             const char* cond_str)
    : t(const_cast<task*>(t)), cond(cond) {
  if (!cond) {
    write_prefix(*this, log_fatal, file, line, function);
    *this << "\n (task " << t->tid << " (rec:" << t->rec_tid << ") at time "
          << t->trace_time() << ")"
          << "\n -> assertion `" << cond_str << "' failed to hold. ";
  }
}


EmergencyDebugOstream::~EmergencyDebugOstream() {
  if (!cond) {
    log_stream() << endl;
    flush_log_stream();
    t->log_pending_events();
    emergency_debug(t);
  }
}
#endif

ostream& operator<<(ostream& stream, const vector<uint8_t>& bytes) {
  for (uint32_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      stream << ' ';
    }
    stream << HEX(bytes[i]);
  }
  return stream;
}
#if 0
string errno_name(int err) {
  switch (err) {
    case 0:
      return "SUCCESS";
      CASE(EPERM);
      CASE(ENOENT);
      CASE(ESRCH);
      CASE(EINTR);
      CASE(EIO);
      CASE(ENXIO);
      CASE(E2BIG);
      CASE(ENOEXEC);
      CASE(EBADF);
      CASE(ECHILD);
      CASE(EAGAIN);
      CASE(ENOMEM);
      CASE(EACCES);
      CASE(EFAULT);
      CASE(ENOTBLK);
      CASE(EBUSY);
      CASE(EEXIST);
      CASE(EXDEV);
      CASE(ENODEV);
      CASE(ENOTDIR);
      CASE(EISDIR);
      CASE(EINVAL);
      CASE(ENFILE);
      CASE(EMFILE);
      CASE(ENOTTY);
      CASE(ETXTBSY);
      CASE(EFBIG);
      CASE(ENOSPC);
      CASE(ESPIPE);
      CASE(EROFS);
      CASE(EMLINK);
      CASE(EPIPE);
      CASE(EDOM);
      CASE(ERANGE);
      CASE(EDEADLK);
      CASE(ENAMETOOLONG);
      CASE(ENOLCK);
      CASE(ENOSYS);
      CASE(ENOTEMPTY);
      CASE(ELOOP);
      CASE(ENOMSG);
      CASE(EIDRM);
      CASE(ECHRNG);
      CASE(EL2NSYNC);
      CASE(EL3HLT);
      CASE(EL3RST);
      CASE(ELNRNG);
      CASE(EUNATCH);
      CASE(ENOCSI);
      CASE(EL2HLT);
      CASE(EBADE);
      CASE(EBADR);
      CASE(EXFULL);
      CASE(ENOANO);
      CASE(EBADRQC);
      CASE(EBADSLT);
      CASE(EBFONT);
      CASE(ENOSTR);
      CASE(ENODATA);
      CASE(ETIME);
      CASE(ENOSR);
      CASE(ENONET);
      CASE(ENOPKG);
      CASE(EREMOTE);
      CASE(ENOLINK);
      CASE(EADV);
      CASE(ESRMNT);
      CASE(ECOMM);
      CASE(EPROTO);
      CASE(EMULTIHOP);
      CASE(EDOTDOT);
      CASE(EBADMSG);
      CASE(EOVERFLOW);
      CASE(ENOTUNIQ);
      CASE(EBADFD);
      CASE(EREMCHG);
      CASE(ELIBACC);
      CASE(ELIBBAD);
      CASE(ELIBSCN);
      CASE(ELIBMAX);
      CASE(ELIBEXEC);
      CASE(EILSEQ);
      CASE(ERESTART);
      CASE(ESTRPIPE);
      CASE(EUSERS);
      CASE(ENOTSOCK);
      CASE(EDESTADDRREQ);
      CASE(EMSGSIZE);
      CASE(EPROTOTYPE);
      CASE(ENOPROTOOPT);
      CASE(EPROTONOSUPPORT);
      CASE(ESOCKTNOSUPPORT);
      CASE(EOPNOTSUPP);
      CASE(EPFNOSUPPORT);
      CASE(EAFNOSUPPORT);
      CASE(EADDRINUSE);
      CASE(EADDRNOTAVAIL);
      CASE(ENETDOWN);
      CASE(ENETUNREACH);
      CASE(ENETRESET);
      CASE(ECONNABORTED);
      CASE(ECONNRESET);
      CASE(ENOBUFS);
      CASE(EISCONN);
      CASE(ENOTCONN);
      CASE(ESHUTDOWN);
      CASE(ETOOMANYREFS);
      CASE(ETIMEDOUT);
      CASE(ECONNREFUSED);
      CASE(EHOSTDOWN);
      CASE(EHOSTUNREACH);
      CASE(EALREADY);
      CASE(EINPROGRESS);
      CASE(ESTALE);
      CASE(EUCLEAN);
      CASE(ENOTNAM);
      CASE(ENAVAIL);
      CASE(EISNAM);
      CASE(EREMOTEIO);
      CASE(EDQUOT);
      CASE(ENOMEDIUM);
      CASE(EMEDIUMTYPE);
      CASE(ECANCELED);
      CASE(ENOKEY);
      CASE(EKEYEXPIRED);
      CASE(EKEYREVOKED);
      CASE(EKEYREJECTED);
      CASE(EOWNERDEAD);
      CASE(ENOTRECOVERABLE);
      CASE(ERFKILL);
      CASE(EHWPOISON);
    default: {
      char buf[100];
      sprintf(buf, "errno(%d)", err);
      return string(buf);
    }
  }
}
#endif
} // namespace SynTest

