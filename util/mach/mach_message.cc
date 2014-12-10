// Copyright 2014 The Crashpad Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "util/mach/mach_message.h"

#include <limits>

#include "base/basictypes.h"
#include "util/misc/clock.h"

namespace crashpad {

namespace {

const int kNanosecondsPerMillisecond = 1E6;

// TimerRunning() determines whether |deadline| has passed. If |deadline| is
// kMachMessageDeadlineWaitIndefinitely, |*timeout_options| is set to
// MACH_MSG_OPTION_NONE, |*remaining_ms| is set to MACH_MSG_TIMEOUT_NONE, and
// this function returns true. When used with mach_msg(), this will cause
// indefinite waiting. In any other case, |*timeout_options| is set to
// MACH_SEND_TIMEOUT | MACH_RCV_TIMEOUT, so mach_msg() will enforce a timeout
// specified by |*remaining_ms|. If |deadline| is in the future, |*remaining_ms|
// is set to the number of milliseconds remaining, which will always be a
// positive value, and this function returns true. If |deadline| is
// kMachMessageDeadlineNonblocking (indicating that no timer is in effect),
// |*remaining_ms| is set to zero and this function returns true. Otherwise,
// this function sets |*remaining_ms| to zero and returns false.
bool TimerRunning(uint64_t deadline,
                  mach_msg_timeout_t* remaining_ms,
                  mach_msg_option_t* timeout_options) {
  if (deadline == kMachMessageDeadlineWaitIndefinitely) {
    *remaining_ms = MACH_MSG_TIMEOUT_NONE;
    *timeout_options = MACH_MSG_OPTION_NONE;
    return true;
  }

  *timeout_options = MACH_SEND_TIMEOUT | MACH_RCV_TIMEOUT;

  if (deadline == kMachMessageDeadlineNonblocking) {
    *remaining_ms = 0;
    return true;
  }

  uint64_t now = ClockMonotonicNanoseconds();

  if (now >= deadline) {
    *remaining_ms = 0;
  } else {
    uint64_t remaining = deadline - now;

    // Round to the nearest millisecond, taking care not to overflow.
    const int kHalfMillisecondInNanoseconds = kNanosecondsPerMillisecond / 2;
    if (remaining <=
        std::numeric_limits<uint64_t>::max() - kHalfMillisecondInNanoseconds) {
      *remaining_ms = (remaining + kHalfMillisecondInNanoseconds) /
                      kNanosecondsPerMillisecond;
    } else {
      *remaining_ms = remaining / kNanosecondsPerMillisecond;
    }
  }

  return *remaining_ms != 0;
}

// This is an internal implementation detail of MachMessageWithDeadline(). It
// determines whether |deadline| has expired, and what timeout value and
// timeout-related options to pass to mach_msg() based on the value of
// |deadline|. mach_msg() will only be called if TimerRunning() returns true or
// if run_even_if_expired is true.
mach_msg_return_t MachMessageWithDeadlineInternal(mach_msg_header_t* message,
                                                  mach_msg_option_t options,
                                                  mach_msg_size_t receive_size,
                                                  mach_port_name_t receive_port,
                                                  MachMessageDeadline deadline,
                                                  mach_port_name_t notify_port,
                                                  bool run_even_if_expired) {
  mach_msg_timeout_t remaining_ms;
  mach_msg_option_t timeout_options;
  if (!TimerRunning(deadline, &remaining_ms, &timeout_options) &&
      !run_even_if_expired) {
    // Simulate the timed-out return values from mach_msg().
    if (options & MACH_SEND_MSG) {
      return MACH_SEND_TIMED_OUT;
    }
    if (options & MACH_RCV_MSG) {
      return MACH_RCV_TIMED_OUT;
    }
    return MACH_MSG_SUCCESS;
  }

  // Turn off the passed-in timeout bits and replace them with the ones from
  // TimerRunning(). Get the send_size value from message->msgh_size if sending
  // a message.
  return mach_msg(
      message,
      (options & ~(MACH_SEND_TIMEOUT | MACH_RCV_TIMEOUT)) | timeout_options,
      options & MACH_SEND_MSG ? message->msgh_size : 0,
      receive_size,
      receive_port,
      remaining_ms,
      notify_port);
}

}  // namespace

MachMessageDeadline MachMessageDeadlineFromTimeout(
    mach_msg_timeout_t timeout_ms) {
  switch (timeout_ms) {
    case kMachMessageTimeoutNonblocking:
      return kMachMessageDeadlineNonblocking;
    case kMachMessageTimeoutWaitIndefinitely:
      return kMachMessageDeadlineWaitIndefinitely;
    default:
      return ClockMonotonicNanoseconds() +
             implicit_cast<uint64_t>(timeout_ms) * kNanosecondsPerMillisecond;
  }
}

mach_msg_return_t MachMessageWithDeadline(mach_msg_header_t* message,
                                          mach_msg_option_t options,
                                          mach_msg_size_t receive_size,
                                          mach_port_name_t receive_port,
                                          MachMessageDeadline deadline,
                                          mach_port_name_t notify_port,
                                          bool run_even_if_expired) {
  // mach_msg() actaully does return MACH_MSG_SUCCESS when not asked to send or
  // receive anything. See 10.9.5 xnu-1504.15.3/osfmk/ipc/mach_msg.c
  // mach_msg_overwrite_trap().
  mach_msg_return_t mr = MACH_MSG_SUCCESS;

  // Break up the send and receive into separate operations, so that the timeout
  // can be recomputed from the deadline for each. Otherwise, the computed
  // timeout will apply individually to the send and then to the receive, and
  // the desired deadline could be exceeded.
  //
  // During sends, always set MACH_SEND_INTERRUPT, and during receives, always
  // set MACH_RCV_INTERRUPT. If the caller didn’t specify these options, the
  // calls will be retried with a recomputed deadline. If these bits weren’t
  // set, the libsyscall wrapper (10.9.5
  // xnu-2422.115.4/libsyscall/mach/mach_msg.c mach_msg() would restart
  // interrupted calls with the original timeout value computed from the
  // deadline, which would no longer correspond to the actual deadline. If the
  // caller did specify these bits, don’t restart anything, because the caller
  // wants to be notified of any interrupted calls.

  if (options & MACH_SEND_MSG) {
    do {
      mr = MachMessageWithDeadlineInternal(
          message,
          (options & ~MACH_RCV_MSG) | MACH_SEND_INTERRUPT,
          0,
          MACH_PORT_NULL,
          deadline,
          notify_port,
          run_even_if_expired);
    } while (mr == MACH_SEND_INTERRUPTED && !(options & MACH_SEND_INTERRUPT));

    if (mr != MACH_MSG_SUCCESS) {
      return mr;
    }
  }

  if (options & MACH_RCV_MSG) {
    do {
      mr = MachMessageWithDeadlineInternal(
          message,
          (options & ~MACH_SEND_MSG) | MACH_RCV_INTERRUPT,
          receive_size,
          receive_port,
          deadline,
          notify_port,
          run_even_if_expired);
    } while (mr == MACH_RCV_INTERRUPTED && !(options & MACH_RCV_INTERRUPT));
  }

  return mr;
}

void PrepareMIGReplyFromRequest(const mach_msg_header_t* in_header,
                                mach_msg_header_t* out_header) {
  out_header->msgh_bits =
      MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(in_header->msgh_bits), 0);
  out_header->msgh_remote_port = in_header->msgh_remote_port;
  out_header->msgh_size = sizeof(mig_reply_error_t);
  out_header->msgh_local_port = MACH_PORT_NULL;
  out_header->msgh_id = in_header->msgh_id + 100;
  reinterpret_cast<mig_reply_error_t*>(out_header)->NDR = NDR_record;

  // MIG-generated dispatch routines don’t do this, but they should.
  out_header->msgh_reserved = 0;
}

void SetMIGReplyError(mach_msg_header_t* out_header, kern_return_t error) {
  reinterpret_cast<mig_reply_error_t*>(out_header)->RetCode = error;
}

const mach_msg_trailer_t* MachMessageTrailerFromHeader(
    const mach_msg_header_t* header) {
  vm_address_t header_address = reinterpret_cast<vm_address_t>(header);
  vm_address_t trailer_address = header_address + round_msg(header->msgh_size);
  return reinterpret_cast<const mach_msg_trailer_t*>(trailer_address);
}

}  // namespace crashpad
