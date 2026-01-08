// Copyright 2020 The gVisor Authors.
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

#include <linux/capability.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "test/syscalls/linux/iptables.h"
#include "test/util/file_descriptor.h"
#include "test/util/linux_capability_util.h"
#include "test/util/multiprocess_util.h"
#include "test/util/posix_error.h"
#include "test/util/socket_util.h"
#include "test/util/test_util.h"

namespace gvisor {
namespace testing {

namespace {

constexpr char kNatTablename[] = "nat";
constexpr char kErrorTarget[] = "ERROR";
constexpr size_t kEmptyStandardEntrySize =
    sizeof(struct ip6t_entry) + sizeof(struct xt_standard_target);
constexpr size_t kEmptyErrorEntrySize =
    sizeof(struct ip6t_entry) + sizeof(struct xt_error_target);

using ::testing::AnyOf;
using ::testing::Eq;

TEST(IP6TablesBasic, FailSockoptNonRaw) {
  // Even if the user has CAP_NET_RAW, they shouldn't be able to use the
  // ip6tables sockopts with a non-raw socket.
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET6, SOCK_DGRAM, 0), SyscallSucceeds());

  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  EXPECT_THAT(getsockopt(sock, SOL_IPV6, IP6T_SO_GET_INFO, &info, &info_size),
              SyscallFailsWithErrno(ENOPROTOOPT));

  EXPECT_THAT(close(sock), SyscallSucceeds());
}

TEST(IP6TablesBasic, GetInfoErrorPrecedence) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET6, SOCK_DGRAM, 0), SyscallSucceeds());

  // When using the wrong type of socket and a too-short optlen, we should get
  // EINVAL.
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info) - 1;
  EXPECT_THAT(getsockopt(sock, SOL_IPV6, IP6T_SO_GET_INFO, &info, &info_size),
              SyscallFailsWithErrno(EINVAL));
}

TEST(IP6TablesBasic, GetEntriesErrorPrecedence) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET6, SOCK_DGRAM, 0), SyscallSucceeds());

  // When using the wrong type of socket and a too-short optlen, we should get
  // EINVAL.
  struct ip6t_get_entries entries = {};
  socklen_t entries_size = sizeof(struct ip6t_get_entries) - 1;
  snprintf(entries.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  EXPECT_THAT(
      getsockopt(sock, SOL_IPV6, IP6T_SO_GET_ENTRIES, &entries, &entries_size),
      SyscallFailsWithErrno(EINVAL));
}

TEST(IP6TablesBasic, GetRevision) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  int sock;
  ASSERT_THAT(sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW),
              SyscallSucceeds());

  struct xt_get_revision rev = {};
  socklen_t rev_len = sizeof(rev);

  snprintf(rev.name, sizeof(rev.name), "REDIRECT");
  rev.revision = 0;

  // Revision 0 exists.
  EXPECT_THAT(
      getsockopt(sock, SOL_IPV6, IP6T_SO_GET_REVISION_TARGET, &rev, &rev_len),
      SyscallSucceeds());
  EXPECT_EQ(rev.revision, 0);

  // Revisions > 0 don't exist.
  rev.revision = 1;
  EXPECT_THAT(
      getsockopt(sock, SOL_IPV6, IP6T_SO_GET_REVISION_TARGET, &rev, &rev_len),
      SyscallFailsWithErrno(EPROTONOSUPPORT));
}

// This tests the initial state of a machine with empty ip6tables via
// getsockopt(IP6T_SO_GET_INFO). We don't have a guarantee that the iptables are
// empty when running in native, but we can test that gVisor has the same
// initial state that a newly-booted Linux machine would have.
TEST(IP6TablesTest, InitialInfo) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_RAW, IPPROTO_RAW));

  // Get info via sockopt.
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  ASSERT_THAT(
      getsockopt(sock.get(), SOL_IPV6, IP6T_SO_GET_INFO, &info, &info_size),
      SyscallSucceeds());

  // The nat table supports PREROUTING, and OUTPUT.
  unsigned int valid_hooks =
      (1 << NF_IP6_PRE_ROUTING) | (1 << NF_IP6_LOCAL_OUT) |
      (1 << NF_IP6_POST_ROUTING) | (1 << NF_IP6_LOCAL_IN);
  EXPECT_EQ(info.valid_hooks, valid_hooks);

  // Each chain consists of an empty entry with a standard target..
  EXPECT_EQ(info.hook_entry[NF_IP6_PRE_ROUTING], 0);
  EXPECT_EQ(info.hook_entry[NF_IP6_LOCAL_IN], kEmptyStandardEntrySize);
  EXPECT_EQ(info.hook_entry[NF_IP6_LOCAL_OUT], kEmptyStandardEntrySize * 2);
  EXPECT_EQ(info.hook_entry[NF_IP6_POST_ROUTING], kEmptyStandardEntrySize * 3);

  // The underflow points are the same as the entry points.
  EXPECT_EQ(info.underflow[NF_IP6_PRE_ROUTING], 0);
  EXPECT_EQ(info.underflow[NF_IP6_LOCAL_IN], kEmptyStandardEntrySize);
  EXPECT_EQ(info.underflow[NF_IP6_LOCAL_OUT], kEmptyStandardEntrySize * 2);
  EXPECT_EQ(info.underflow[NF_IP6_POST_ROUTING], kEmptyStandardEntrySize * 3);

  // One entry for each chain, plus an error entry at the end.
  EXPECT_EQ(info.num_entries, 5);

  EXPECT_EQ(info.size, 4 * kEmptyStandardEntrySize + kEmptyErrorEntrySize);
  EXPECT_EQ(strcmp(info.name, kNatTablename), 0);
}

// This tests the initial state of a machine with empty ip6tables via
// getsockopt(IP6T_SO_GET_ENTRIES). We don't have a guarantee that the iptables
// are empty when running in native, but we can test that gVisor has the same
// initial state that a newly-booted Linux machine would have.
TEST(IP6TablesTest, InitialEntries) {
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));

  FileDescriptor sock =
      ASSERT_NO_ERRNO_AND_VALUE(Socket(AF_INET6, SOCK_RAW, IPPROTO_RAW));

  // Get info via sockopt.
  struct ipt_getinfo info = {};
  snprintf(info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  socklen_t info_size = sizeof(info);
  ASSERT_THAT(
      getsockopt(sock.get(), SOL_IPV6, IP6T_SO_GET_INFO, &info, &info_size),
      SyscallSucceeds());

  // Use info to get entries.
  socklen_t entries_size = sizeof(struct ip6t_get_entries) + info.size;
  struct ip6t_get_entries* entries =
      static_cast<struct ip6t_get_entries*>(malloc(entries_size));
  snprintf(entries->name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
  entries->size = info.size;
  ASSERT_THAT(getsockopt(sock.get(), SOL_IPV6, IP6T_SO_GET_ENTRIES, entries,
                         &entries_size),
              SyscallSucceeds());

  // Verify the name and size.
  ASSERT_EQ(info.size, entries->size);
  ASSERT_EQ(strcmp(entries->name, kNatTablename), 0);

  // Verify that the entrytable is 4 entries with accept targets and no matches
  // followed by a single error target.
  size_t entry_offset = 0;
  while (entry_offset < entries->size) {
    struct ip6t_entry* entry = reinterpret_cast<struct ip6t_entry*>(
        reinterpret_cast<char*>(entries->entrytable) + entry_offset);

    // ipv6 should be zeroed.
    struct ip6t_ip6 zeroed;
    memset(&zeroed, 0, sizeof(zeroed));
    ASSERT_EQ(memcmp(static_cast<void*>(&zeroed),
                     static_cast<void*>(&entry->ipv6), sizeof(zeroed)),
              0);

    // target_offset should be zero.
    EXPECT_EQ(entry->target_offset, sizeof(ip6t_entry));

    if (entry_offset < kEmptyStandardEntrySize * 4) {
      // The first 4 entries are standard targets
      struct xt_standard_target* target =
          reinterpret_cast<struct xt_standard_target*>(entry->elems);
      EXPECT_EQ(entry->next_offset, kEmptyStandardEntrySize);
      EXPECT_EQ(target->target.u.user.target_size, sizeof(*target));
      EXPECT_EQ(strcmp(target->target.u.user.name, ""), 0);
      EXPECT_EQ(target->target.u.user.revision, 0);
      // This is what's returned for an accept verdict. I don't know why.
      EXPECT_EQ(target->verdict, -NF_ACCEPT - 1);
    } else {
      // The last entry is an error target
      struct xt_error_target* target =
          reinterpret_cast<struct xt_error_target*>(entry->elems);
      EXPECT_EQ(entry->next_offset, kEmptyErrorEntrySize);
      EXPECT_EQ(target->target.u.user.target_size, sizeof(*target));
      EXPECT_EQ(strcmp(target->target.u.user.name, kErrorTarget), 0);
      EXPECT_EQ(target->target.u.user.revision, 0);
      EXPECT_EQ(strcmp(target->errorname, kErrorTarget), 0);
    }

    entry_offset += entry->next_offset;
    break;
  }

  free(entries);
}

struct SockOptArgs {
  int sock;
  int level;
  int optname;
  std::shared_ptr<void> optval;
  socklen_t optlen;
};

struct RequiresCapNetAdminTestParams {
  std::string test_name;
  std::function<absl::StatusOr<SockOptArgs>(int sock)> generate_sockopt_args;
};

class GetSockOptRequiresCapNetAdminTest
    : public ::testing::TestWithParam<RequiresCapNetAdminTestParams> {
 public:
  // GetSockOpt calls getsockopt with CAP_NET_ADMIN and returns errno on
  // failure.
  static int GetSockOpt(void* args_ptr) {
    if (args_ptr == nullptr) {
      return -1;
    }
    AutoCapability cap(CAP_NET_ADMIN, true);
    SockOptArgs* args = static_cast<SockOptArgs*>(args_ptr);
    if (getsockopt(args->sock, args->level, args->optname, args->optval.get(),
                   &args->optlen) != 0) {
      return errno;
    }
    return 0;
  }
};

// Tests that getsockopt on iptables sockets requires CAP_NET_ADMIN.
TEST_P(GetSockOptRequiresCapNetAdminTest, Validate) {
  const RequiresCapNetAdminTestParams& params = GetParam();
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  FileDescriptor sock = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(/*family=*/AF_INET6, /*type=*/SOCK_RAW, /*protocol=*/IPPROTO_RAW));
  absl::StatusOr<SockOptArgs> args_or_status =
      params.generate_sockopt_args(sock.get());
  ASSERT_EQ(args_or_status.status(), absl::OkStatus());
  SockOptArgs& getsockopt_args = *args_or_status;
  SockOptArgs child_getsockopt_args = getsockopt_args;
  // Validate that the socket creator can successfully getsockopt.
  ASSERT_EQ(GetSockOpt(&getsockopt_args), 0);
  // Validate that another process from a different user namespace cannot
  // getsockopt and fails with EPERM.
  EXPECT_THAT(InForkedProcess([&child_getsockopt_args]() {
                // unshare the user namespace to create a new user namespace.
                ASSERT_THAT(unshare(CLONE_NEWUSER), SyscallSucceeds());
                ASSERT_THAT(GetSockOpt(&child_getsockopt_args), Eq(EPERM));
              }),
              IsPosixErrorOkAndHolds(0));
}

INSTANTIATE_TEST_SUITE_P(
    GetSockOptRequiresCapNetAdminTests, GetSockOptRequiresCapNetAdminTest,
    ::testing::ValuesIn<RequiresCapNetAdminTestParams>(
        {{.test_name = "GetInfo",
          .generate_sockopt_args =
              [](int sock) {
                SockOptArgs args;
                args.sock = sock;
                std::shared_ptr<void> optval = std::make_shared<ipt_getinfo>();
                ipt_getinfo* info = static_cast<ipt_getinfo*>(optval.get());
                snprintf(info->name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
                args.level = SOL_IPV6;
                args.optname = IP6T_SO_GET_INFO;
                args.optval = optval;
                args.optlen = sizeof(ipt_getinfo);
                return args;
              }},
         {.test_name = "GetEntries",
          .generate_sockopt_args = [](int sock) -> absl::StatusOr<SockOptArgs> {
            socklen_t get_info_optlen = sizeof(ipt_getinfo);
            ipt_getinfo get_info;
            snprintf(get_info.name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
            if (getsockopt(sock, SOL_IPV6, IP6T_SO_GET_INFO, &get_info,
                           &get_info_optlen) < 0) {
              return absl::InternalError("getsockopt failed");
            }
            socklen_t get_entries_optlen =
                sizeof(ipt_get_entries) + get_info.size;
            std::shared_ptr<void> optval =
                std::make_unique<char[]>(get_entries_optlen);
            ipt_get_entries* entries =
                static_cast<ipt_get_entries*>(optval.get());
            snprintf(entries->name, XT_TABLE_MAXNAMELEN, "%s", kNatTablename);
            entries->size = get_info.size;
            SockOptArgs get_entries_args = {
                .sock = sock,
                .level = SOL_IPV6,
                .optname = IP6T_SO_GET_ENTRIES,
                .optval = optval,
                .optlen = get_entries_optlen,
            };
            return get_entries_args;
          }},
         {.test_name = "GetRevisionTarget",
          .generate_sockopt_args =
              [](int sock) {
                std::shared_ptr<void> optval =
                    std::make_shared<xt_get_revision>();
                xt_get_revision* rev =
                    static_cast<xt_get_revision*>(optval.get());
                socklen_t rev_len = sizeof(*rev);
                snprintf(rev->name, sizeof(rev->name), "REDIRECT");
                rev->revision = 0;
                return SockOptArgs{
                    .sock = sock,
                    .level = SOL_IPV6,
                    .optname = IP6T_SO_GET_REVISION_TARGET,
                    .optval = optval,
                    .optlen = rev_len,
                };
              }},
         {.test_name = "GetRevisionMatch",
          .generate_sockopt_args =
              [](int sock) {
                std::shared_ptr<void> optval =
                    std::make_shared<xt_get_revision>();
                xt_get_revision* rev =
                    static_cast<xt_get_revision*>(optval.get());
                socklen_t rev_len = sizeof(*rev);
                snprintf(rev->name, sizeof(rev->name), "tcp");
                rev->revision = 0;
                return SockOptArgs{
                    .sock = sock,
                    .level = SOL_IPV6,
                    .optname = IP6T_SO_GET_REVISION_MATCH,
                    .optval = optval,
                    .optlen = rev_len,
                };
              }}}),
    [](const ::testing::TestParamInfo<
        GetSockOptRequiresCapNetAdminTest::ParamType>& info) {
      return info.param.test_name;
    });

class SetSockOptRequiresCapNetAdminTest
    : public ::testing::TestWithParam<RequiresCapNetAdminTestParams> {
 public:
  // SetSockOpt calls setsockopt with CAP_NET_ADMIN and returns errno on
  // failure.
  static int SetSockOpt(void* args_ptr) {
    if (args_ptr == nullptr) {
      return -1;
    }
    AutoCapability cap(CAP_NET_ADMIN, true);
    SockOptArgs* args = static_cast<SockOptArgs*>(args_ptr);
    if (setsockopt(args->sock, args->level, args->optname, args->optval.get(),
                   args->optlen) != 0) {
      return errno;
    }
    return 0;
  }
};

// Tests that setsockopt on iptables sockets requires CAP_NET_ADMIN.
TEST_P(SetSockOptRequiresCapNetAdminTest, Validate) {
  const RequiresCapNetAdminTestParams& params = GetParam();
  SKIP_IF(!ASSERT_NO_ERRNO_AND_VALUE(HaveCapability(CAP_NET_RAW)));
  FileDescriptor sock = ASSERT_NO_ERRNO_AND_VALUE(
      Socket(/*domain=*/AF_INET6, /*type=*/SOCK_RAW, /*protocol=*/IPPROTO_RAW));
  absl::StatusOr<SockOptArgs> args_or_status =
      params.generate_sockopt_args(sock.get());
  ASSERT_EQ(args_or_status.status(), absl::OkStatus());
  SockOptArgs& setsockopt_args = *args_or_status;
  SockOptArgs child_setsockopt_args = setsockopt_args;
  // Validate that the socket creator either succeeds or fails with EINVAL,
  // but not with EPERM.
  ASSERT_THAT(SetSockOpt(&setsockopt_args),
              AnyOf(SyscallSucceeds(), Eq(EINVAL)));
  // Validate that another process from a different user namespace cannot
  // setsockopt and fails with EPERM.
  EXPECT_THAT(InForkedProcess([&child_setsockopt_args]() {
                // unshare the user namespace to create a new user namespace.
                ASSERT_THAT(unshare(CLONE_NEWUSER), SyscallSucceeds());
                ASSERT_THAT(SetSockOpt(&child_setsockopt_args), Eq(EPERM));
              }),
              IsPosixErrorOkAndHolds(0));
}

INSTANTIATE_TEST_SUITE_P(
    SetSockOpt, SetSockOptRequiresCapNetAdminTest,
    ::testing::ValuesIn<RequiresCapNetAdminTestParams>(
        {{.test_name = "SetReplace",
          .generate_sockopt_args =
              [](int sock) {
                SockOptArgs args;
                args.sock = sock;
                std::shared_ptr<void> optval = std::make_shared<ipt_replace>();
                ipt_replace* replace = static_cast<ipt_replace*>(optval.get());
                snprintf(replace->name, sizeof(replace->name), "%s",
                         kNatTablename);
                args.level = SOL_IPV6;
                args.optname = IP6T_SO_SET_REPLACE;
                args.optval = optval;
                args.optlen = sizeof(ipt_replace);
                return args;
              }}}),
    [](const ::testing::TestParamInfo<
        SetSockOptRequiresCapNetAdminTest::ParamType>& info) {
      return info.param.test_name;
    });

}  // namespace

}  // namespace testing
}  // namespace gvisor
