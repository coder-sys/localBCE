#include "util/log.h"

#include <cstdarg>
#include <cstdio>

namespace proofs {
namespace {
LogLevel level = ERROR;
}

void set_log_level(LogLevel l) { level = l; }

void log(LogLevel l, const char* format, ...) {
  if (l > level) return;
  va_list args;
  va_start(args, format);
  std::vfprintf(stderr, format, args);
  std::fputc('\n', stderr);
  va_end(args);
}
}  // namespace proofs
