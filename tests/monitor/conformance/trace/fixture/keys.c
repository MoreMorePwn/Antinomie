// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//
// keys.c — the kernel key retention service.
//
// Slots: add_key request_key keyctl.
//
// Everything runs in child 340, a fresh process: a forked child inherits
// neither a process nor a thread keyring, so the "absent" cases are
// deterministic and every key goes away with the child. Only the process and
// thread keyrings are used (no session, user or persistent keyrings, no
// request-key upcall). Key serial numbers are random, so the cases are
// volatile. The child's strings live on its stack: its .rodata pages are not
// resident after fork and the recorder does not fault them in.
#include "areas.h"

#include <linux/keyctl.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

#ifndef KEYCTL_MOVE
#define KEYCTL_MOVE 30
#endif
#ifndef KEYCTL_MOVE_EXCL
#define KEYCTL_MOVE_EXCL 0x00000001
#endif
#ifndef KEYCTL_CAPABILITIES
#define KEYCTL_CAPABILITIES 31
#endif

// Permission bits (include/linux/key.h, not exported to user space).
#define KEY_POS_ALL 0x3f000000
#define KEY_USR_VIEW 0x00010000
#define KEY_USR_READ 0x00020000

#define NO_SUCH_KEY 0x7ffffff0

static size_t at_most(long result, size_t capacity)
{
    return result < 0 ? 0 : (size_t)result < capacity ? (size_t)result : capacity;
}

static void keys_body(void *unused)
{
    (void)unused;
    char user[] = "user", keyring[] = "keyring", bogus[] = "ant-no-such-type",
         dotted[] = ".ant-internal";
    char user_desc[] = "ant:conformance:user", other_desc[] = "ant:conformance:other",
         ring_desc[] = "ant:conformance:ring", locked_desc[] = "ant:conformance:locked",
         thread_desc[] = "ant:conformance:thread", missing_desc[] = "ant:conformance:missing",
         dot_desc[] = ".ant-ring", empty_desc[] = "ant:conformance:empty";
    char payload[] = "ANTINOMIE-KEY-PAYLOAD", update[] = "UPDATED-PAYLOAD";
    char info[] = "enc=raw", asym[] = "asymmetric";
    char buffer[256];
    static char too_much[4097];
    pattern(too_much, sizeof too_much, 50);

    // Keyring identities before and after creation.
    CALL("keyctl.process_keyring_absent", keyctl, ENOKEY, KEYCTL_GET_KEYRING_ID,
         KEY_SPEC_PROCESS_KEYRING, 0);
    why("a forked child starts without a process keyring");
    DONE();
    CALL("keyctl.thread_keyring_absent", keyctl, ENOKEY, KEYCTL_GET_KEYRING_ID,
         KEY_SPEC_THREAD_KEYRING, 0);
    why("a forked child starts without a thread keyring");
    DONE();
    CALL("keyctl.process_keyring_create", keyctl, WANT_OK, KEYCTL_GET_KEYRING_ID,
         KEY_SPEC_PROCESS_KEYRING, 1);
    volatile_case();
    DONE();
    CASE("keyctl.get_keyring_id_missing", keyctl, ENOKEY, KEYCTL_GET_KEYRING_ID, NO_SUCH_KEY, 0);

    // add_key.
    long key = CALL("add_key.user", add_key, WANT_OK, user, user_desc, payload,
                    sizeof payload - 1, KEY_SPEC_PROCESS_KEYRING);
    in_str(0, user);
    in_str(1, user_desc);
    in_buf(2, payload, sizeof payload - 1);
    volatile_case();
    DONE();
    if (key < 0)
        return;
    long same = CALL("add_key.update_existing", add_key, WANT_OK, user, user_desc, payload, 9,
                     KEY_SPEC_PROCESS_KEYRING);
    in_str(0, user);
    in_str(1, user_desc);
    in_buf(2, payload, 9);
    volatile_case();
    why("the same type and description update the existing key");
    DONE();
    if (same != key)
        ora_fail("add_key update returned another key");
    long other = CALL("add_key.second_user", add_key, WANT_OK, user, other_desc, payload, 4,
                      KEY_SPEC_PROCESS_KEYRING);
    in_str(0, user);
    in_str(1, other_desc);
    in_buf(2, payload, 4);
    volatile_case();
    DONE();
    long ring = CALL("add_key.keyring", add_key, WANT_OK, keyring, ring_desc, NULL, 0,
                     KEY_SPEC_PROCESS_KEYRING);
    in_str(0, keyring);
    in_str(1, ring_desc);
    want_status(2, "in", "NULL_POINTER");
    volatile_case();
    DONE();
    long locked = CALL("add_key.keyring_to_restrict", add_key, WANT_OK, keyring, locked_desc,
                       NULL, 0, KEY_SPEC_PROCESS_KEYRING);
    in_str(0, keyring);
    in_str(1, locked_desc);
    want_status(2, "in", "NULL_POINTER");
    volatile_case();
    DONE();
    CALL("add_key.thread_keyring", add_key, WANT_OK, user, thread_desc, payload, 8,
         KEY_SPEC_THREAD_KEYRING);
    in_str(0, user);
    in_str(1, thread_desc);
    in_buf(2, payload, 8);
    volatile_case();
    why("adding to the thread keyring creates it");
    DONE();
    CALL("keyctl.thread_keyring_present", keyctl, WANT_OK, KEYCTL_GET_KEYRING_ID,
         KEY_SPEC_THREAD_KEYRING, 0);
    volatile_case();
    DONE();
    CALL("add_key.unknown_type", add_key, ENODEV, bogus, user_desc, payload, 4,
         KEY_SPEC_PROCESS_KEYRING);
    in_str(0, bogus);
    in_str(1, user_desc);
    in_buf(2, payload, 4);
    DONE();
    CALL("add_key.dot_type", add_key, EPERM, dotted, user_desc, payload, 4,
         KEY_SPEC_PROCESS_KEYRING);
    in_str(0, dotted);
    in_str(1, user_desc);
    in_buf(2, payload, 4);
    why("types starting with a dot are internal");
    DONE();
    CALL("add_key.dot_keyring", add_key, EPERM, keyring, dot_desc, NULL, 0,
         KEY_SPEC_PROCESS_KEYRING);
    in_str(0, keyring);
    in_str(1, dot_desc);
    want_status(2, "in", "NULL_POINTER");
    why("keyring descriptions starting with a dot are reserved");
    DONE();
    CALL("add_key.no_description", add_key, EINVAL, user, NULL, payload, 4,
         KEY_SPEC_PROCESS_KEYRING);
    in_str(0, user);
    want_status(1, "in", "NULL_POINTER");
    in_buf(2, payload, 4);
    DONE();
    CALL("add_key.empty_payload", add_key, EINVAL, user, empty_desc, payload, 0,
         KEY_SPEC_PROCESS_KEYRING);
    in_str(0, user);
    in_str(1, empty_desc);
    in_buf(2, payload, 0);
    why("a user key needs 1 to 32767 payload bytes");
    DONE();
    CALL("add_key.payload_too_large", add_key, EINVAL, user, user_desc, payload, 1 << 20,
         KEY_SPEC_PROCESS_KEYRING);
    in_str(0, user);
    in_str(1, user_desc);
    want_status(2, "in", "INVALID_EXTENT");
    why("plen above 1 MiB - 1 is refused before anything is read");
    DONE();
    CALL("add_key.missing_keyring", add_key, ENOKEY, user, user_desc, payload, 4, NO_SUCH_KEY);
    in_str(0, user);
    in_str(1, user_desc);
    in_buf(2, payload, 4);
    DONE();
    CALL("add_key.null_type", add_key, EFAULT, NULL, user_desc, payload, 4,
         KEY_SPEC_PROCESS_KEYRING);
    want_status(0, "in", "NULL_POINTER");
    in_str(1, user_desc);
    in_buf(2, payload, 4);
    DONE();

    // request_key: searches only, never an upcall (NULL callout info).
    long found = CALL("request_key.found", request_key, WANT_OK, user, user_desc, NULL, 0);
    in_str(0, user);
    in_str(1, user_desc);
    want_status(2, "in", "NULL_POINTER");
    volatile_case();
    DONE();
    if (found != key)
        ora_fail("request_key found another key");
    CALL("request_key.found_and_linked", request_key, WANT_OK, user, user_desc, NULL, ring);
    in_str(0, user);
    in_str(1, user_desc);
    want_status(2, "in", "NULL_POINTER");
    volatile_case();
    why("a destination keyring gets a link to the found key");
    DONE();
    CALL("request_key.missing", request_key, ENOKEY, user, missing_desc, NULL,
         KEY_SPEC_PROCESS_KEYRING);
    in_str(0, user);
    in_str(1, missing_desc);
    want_status(2, "in", "NULL_POINTER");
    why("no callout info: a missing key is not constructed");
    DONE();
    CALL("request_key.unknown_type", request_key, ENOKEY, bogus, user_desc, NULL, 0);
    in_str(0, bogus);
    in_str(1, user_desc);
    want_status(2, "in", "NULL_POINTER");
    DONE();
    CALL("request_key.dot_type", request_key, EPERM, dotted, user_desc, NULL, 0);
    in_str(0, dotted);
    in_str(1, user_desc);
    want_status(2, "in", "NULL_POINTER");
    DONE();
    CALL("request_key.missing_destination", request_key, ENOKEY, user, user_desc, NULL,
         NO_SUCH_KEY);
    in_str(0, user);
    in_str(1, user_desc);
    want_status(2, "in", "NULL_POINTER");
    DONE();

    // Describing and reading.
    memset(buffer, 'x', sizeof buffer);
    long got = CALL("keyctl.describe", keyctl, WANT_OK, KEYCTL_DESCRIBE, key, buffer,
                    sizeof buffer);
    out_buf(2, buffer, at_most(got, sizeof buffer));
    volatile_case();
    DONE();
    memset(buffer, 'x', sizeof buffer);
    got = CALL("keyctl.describe_small_buffer", keyctl, WANT_OK, KEYCTL_DESCRIBE, key, buffer, 4);
    out_buf(2, buffer, at_most(got, 4));
    volatile_case();
    why("the full length is returned and nothing is copied; the recorder reads what is there");
    DONE();
    CALL("keyctl.describe_length", keyctl, WANT_OK, KEYCTL_DESCRIBE, key, NULL, 0);
    volatile_case();
    why("a NULL buffer only asks for the length: no field");
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("keyctl.read", keyctl, WANT_OK, KEYCTL_READ, key, buffer, 64);
    out_buf(2, buffer, at_most(got, 64));
    volatile_case();
    DONE();
    if (got != 9 || memcmp(buffer, payload, 9))
        ora_fail("key payload after update");
    CALL("keyctl.read_length", keyctl, WANT_OK, KEYCTL_READ, key, NULL, 0);
    volatile_case();
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("keyctl.read_keyring", keyctl, WANT_OK, KEYCTL_READ, ring, buffer, 64);
    out_buf(2, buffer, at_most(got, 64));
    volatile_case();
    why("a keyring reads as the serial numbers of its keys");
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("keyctl.get_security", keyctl, WANT_OK, KEYCTL_GET_SECURITY, key, buffer,
               sizeof buffer);
    out_buf(2, buffer, at_most(got, sizeof buffer));
    volatile_case();
    why("the LSM label, or an empty string without one");
    DONE();
    memset(buffer, 0, sizeof buffer);
    got = CALL("keyctl.capabilities", keyctl, WANT_OK, KEYCTL_CAPABILITIES, buffer, 16);
    out_buf(1, buffer, at_most(got, 16));
    DONE();

    // Updating and searching.
    CALL("keyctl.update", keyctl, WANT_OK, KEYCTL_UPDATE, key, update, sizeof update - 1);
    in_buf(2, update, sizeof update - 1);
    volatile_case();
    DONE();
    CALL("keyctl.update_keyring", keyctl, EOPNOTSUPP, KEYCTL_UPDATE, ring, update, 4);
    in_buf(2, update, 4);
    volatile_case();
    why("keyrings have no update operation");
    DONE();
    CALL("keyctl.update_too_large", keyctl, EINVAL, KEYCTL_UPDATE, key, too_much,
         sizeof too_much);
    want_status(2, "in", "INVALID_EXTENT");
    volatile_case();
    why("more than PAGE_SIZE bytes are refused");
    DONE();
    long hit = CALL("keyctl.search_found", keyctl, WANT_OK, KEYCTL_SEARCH,
                    KEY_SPEC_PROCESS_KEYRING, user, user_desc, 0);
    in_str(2, user);
    in_str(3, user_desc);
    volatile_case();
    DONE();
    if (hit != key)
        ora_fail("keyctl search found another key");
    CALL("keyctl.search_missing", keyctl, ENOKEY, KEYCTL_SEARCH, KEY_SPEC_PROCESS_KEYRING, user,
         missing_desc, 0);
    in_str(2, user);
    in_str(3, missing_desc);
    DONE();

    // Links, moves, restrictions.
    CALL("keyctl.link", keyctl, WANT_OK, KEYCTL_LINK, other, ring);
    volatile_case();
    DONE();
    CALL("keyctl.link_into_non_keyring", keyctl, ENOTDIR, KEYCTL_LINK, ring, key);
    volatile_case();
    DONE();
    CALL("keyctl.unlink", keyctl, WANT_OK, KEYCTL_UNLINK, other, ring);
    volatile_case();
    DONE();
    CALL("keyctl.unlink_not_linked", keyctl, ENOENT, KEYCTL_UNLINK, other, ring);
    volatile_case();
    DONE();
    CALL("keyctl.move", keyctl, WANT_OK, KEYCTL_MOVE, other, KEY_SPEC_PROCESS_KEYRING, ring, 0);
    volatile_case();
    DONE();
    CALL("keyctl.move_back_excl", keyctl, WANT_OK, KEYCTL_MOVE, other, ring,
         KEY_SPEC_PROCESS_KEYRING, KEYCTL_MOVE_EXCL);
    volatile_case();
    DONE();
    CALL("keyctl.move_bad_flags", keyctl, EINVAL, KEYCTL_MOVE, other, KEY_SPEC_PROCESS_KEYRING,
         ring, 0x80);
    volatile_case();
    DONE();
    CALL("keyctl.restrict_reject_all", keyctl, WANT_OK, KEYCTL_RESTRICT_KEYRING, locked, NULL,
         NULL);
    volatile_case();
    why("no type and no restriction: the keyring refuses every new link");
    DONE();
    CALL("keyctl.link_restricted", keyctl, EPERM, KEYCTL_LINK, other, locked);
    volatile_case();
    DONE();
    CALL("keyctl.restrict_type_only", keyctl, EINVAL, KEYCTL_RESTRICT_KEYRING, ring, asym, NULL);
    in_str(2, asym);
    volatile_case();
    why("a type needs a restriction string");
    DONE();
    CALL("keyctl.clear", keyctl, WANT_OK, KEYCTL_CLEAR, ring);
    volatile_case();
    DONE();

    // Attributes.
    CALL("keyctl.setperm", keyctl, WANT_OK, KEYCTL_SETPERM, key,
         KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ);
    volatile_case();
    DONE();
    CALL("keyctl.setperm_bad_bits", keyctl, EINVAL, KEYCTL_SETPERM, key, 0xc0000000u);
    volatile_case();
    DONE();
    CALL("keyctl.set_timeout", keyctl, WANT_OK, KEYCTL_SET_TIMEOUT, key, 3600);
    volatile_case();
    DONE();
    CALL("keyctl.clear_timeout", keyctl, WANT_OK, KEYCTL_SET_TIMEOUT, key, 0);
    volatile_case();
    DONE();
    CALL("keyctl.chown_noop", keyctl, WANT_OK, KEYCTL_CHOWN, key, -1, -1);
    volatile_case();
    why("uid and gid -1 change nothing");
    DONE();
    CALL("keyctl.chown_to_root", keyctl, EACCES, KEYCTL_CHOWN, key, 0, -1);
    volatile_case();
    why("only CAP_SYS_ADMIN gives a key to another user");
    DONE();
    CASE("keyctl.reqkey_query", keyctl, WANT_OK, KEYCTL_SET_REQKEY_KEYRING,
         KEY_REQKEY_DEFL_NO_CHANGE);
    CASE("keyctl.reqkey_bad", keyctl, EINVAL, KEYCTL_SET_REQKEY_KEYRING, 99);

    // Instantiation needs an authorisation key this process never has.
    CALL("keyctl.instantiate_no_authority", keyctl, EPERM, KEYCTL_INSTANTIATE, key, payload, 4,
         KEY_SPEC_PROCESS_KEYRING);
    in_buf(2, payload, 4);
    volatile_case();
    DONE();
    struct iovec parts[2] = {{payload, 4}, {update, 7}};
    CALL("keyctl.instantiate_iov_no_authority", keyctl, EPERM, KEYCTL_INSTANTIATE_IOV, key,
         parts, 2, KEY_SPEC_PROCESS_KEYRING);
    in_key("arg2.iov", parts, sizeof parts);
    in_key("arg2.iov[0].data", payload, 4);
    in_key("arg2.iov[1].data", update, 7);
    volatile_case();
    DONE();
    CALL("keyctl.negate_no_authority", keyctl, EPERM, KEYCTL_NEGATE, key, 10, 0);
    volatile_case();
    DONE();
    CALL("keyctl.reject_no_authority", keyctl, EPERM, KEYCTL_REJECT, key, 10, EKEYREJECTED, 0);
    volatile_case();
    DONE();
    CASE("keyctl.assume_authority_negative", keyctl, EINVAL, KEYCTL_ASSUME_AUTHORITY, -5);
    struct keyctl_pkey_query query;
    memset(&query, 0, sizeof query);
    CALL("keyctl.pkey_query_user_key", keyctl, EOPNOTSUPP, KEYCTL_PKEY_QUERY, key, 0, info,
         &query);
    in_str(3, info);
    volatile_case();
    why("a user key has no asymmetric operations");
    DONE();
    CALL("keyctl.unknown_command", keyctl, EOPNOTSUPP, 0x7fff, 0, 0, 0, 0);
    want_key_status("keyctl.unknown_selector", "NO_DECODER");
    why("an unknown command is recorded as an explicit selector gap");
    DONE();

    // Ending keys.
    CALL("keyctl.invalidate", keyctl, WANT_OK, KEYCTL_INVALIDATE, other);
    volatile_case();
    DONE();
    CALL("keyctl.describe_invalidated", keyctl, ENOKEY, KEYCTL_DESCRIBE, other, buffer,
         sizeof buffer);
    volatile_case();
    why("an invalidated key is gone, or waiting for the collector, either way ENOKEY");
    DONE();
    CALL("keyctl.revoke", keyctl, WANT_OK, KEYCTL_REVOKE, key);
    volatile_case();
    DONE();
    CALL("keyctl.read_revoked", keyctl, EKEYREVOKED, KEYCTL_READ, key, buffer, 64);
    volatile_case();
    DONE();
    CALL("keyctl.revoke_again", keyctl, EKEYREVOKED, KEYCTL_REVOKE, key);
    volatile_case();
    DONE();
}

void area_keys(void)
{
    in_child(340, "keys child", keys_body, NULL);
}
