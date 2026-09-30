//! Register then prove membership with the US fixture's DG1 (fixtures/documents.json, TD3,
//! date of expiry 340415: 2034-04-15 23:59:59 UTC).

use crate::{leaf, member, register};
use channel::payload::commit;
use eid_steps::document::{DG1_MAX, plaintext};
use emit::{holder_tag, merkle_root, TREE_DEPTH};

global DG1: [u8; DG1_MAX] = [97, 91, 95, 31, 88, 80, 60, 85, 83, 65, 69, 82, 73, 75, 83, 83, 79, 78, 60, 60, 65, 78, 78, 65, 60, 77, 65, 82, 73, 65, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 76, 56, 57, 56, 57, 48, 50, 67, 51, 54, 85, 83, 65, 55, 52, 48, 56, 49, 50, 50, 70, 51, 52, 48, 52, 49, 53, 57, 90, 69, 49, 56, 52, 50, 50, 54, 66, 60, 60, 60, 60, 60, 49, 54, 0, 0];
global EXPIRES: u64 = 2028758399;
global SK: Field = 0x1234;
global SALT: Field = 0x5678;
global DATE: u64 = 1790467200;
global CTX: Field = 0xc7;

fn path() -> [Field; TREE_DEPTH] {
    let mut p: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    p[0] = 0xaa;
    p
}

fn registered(expiry: u64) -> Field {
    let r = register(SALT, DG1, SK, expiry);
    assert_eq(r[0], commit(SALT, plaintext(DG1, 93)), "continues the document's link");
    assert_eq(r[2], expiry as Field);
    // The leaf at index 1 of a tree whose other leaf is 0xaa.
    merkle_root(r[1], 1, path())
}

#[test]
fn register_then_member() {
    let expiry = DATE + 30 * 86400;
    let root = registered(expiry);
    let m = member(root, DATE, SK, plaintext(DG1, 93), 0x99, expiry, 1, path(), CTX);
    assert_eq(m[0], commit(0x99, plaintext(DG1, 93)));
    assert_eq([m[1], m[2], m[3]], [root, DATE as Field, holder_tag(SK, CTX)]);
    assert_eq(leaf(SK, plaintext(DG1, 93), expiry), register(SALT, DG1, SK, expiry)[1]);
}

#[test]
fn registers_until_the_passport_expires() {
    let _ = registered(EXPIRES);
}

#[test(should_fail_with = "the registration outlives the passport")]
fn rejects_a_registration_past_the_passport() {
    let _ = registered(EXPIRES + 1);
}

#[test(should_fail_with = "the registration has expired")]
fn rejects_an_expired_registration() {
    let expiry = DATE + 30 * 86400;
    let root = registered(expiry);
    let _ = member(root, expiry + 1, SK, plaintext(DG1, 93), 0x99, expiry, 1, path(), CTX);
}

#[test(should_fail_with = "not a registered identity")]
fn rejects_another_key() {
    let expiry = DATE + 30 * 86400;
    let root = registered(expiry);
    let _ = member(root, DATE, SK + 1, plaintext(DG1, 93), 0x99, expiry, 1, path(), CTX);
}

#[test(should_fail_with = "not a registered identity")]
fn rejects_a_later_expiry() {
    let expiry = DATE + 30 * 86400;
    let root = registered(expiry);
    let _ = member(root, DATE, SK, plaintext(DG1, 93), 0x99, expiry + 1, 1, path(), CTX);
}
