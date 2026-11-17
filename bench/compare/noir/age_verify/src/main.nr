use eid_der::days_from_civil;
use eid_steps::document::{DG1_MAX, parse_dg1, plaintext};
use identity_cache::leaf;
use emit::{holder_tag, merkle_root, TREE_DEPTH};

fn valid_date(year: u32, month: u32, day: u32) {
    assert((month >= 1) & (month <= 12), "invalid month");
    let leap = (year % 4 == 0) & ((year % 100 != 0) | (year % 400 == 0));
    let feb = if leap { 29 } else { 28 };
    let lengths: [u32; 12] = [31, feb, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    assert((day >= 1) & (day <= lengths[month - 1]), "invalid day");
}

// MRZ supplies only YY: choose the most recent non-future birthday (age 0..99).
// February 29 reaches its anniversary on March 1 in a non-leap year.
fn age_at(yy: u32, month: u32, day: u32, year: u32, now_month: u32, now_day: u32) -> u32 {
    valid_date(year, now_month, now_day);
    let mut birth_year = (year / 100) * 100 + yy;
    if birth_year * 10000 + month * 100 + day > year * 10000 + now_month * 100 + now_day {
        birth_year = birth_year - 100;
    }
    valid_date(birth_year, month, day);
    let before_birthday = now_month * 100 + now_day < month * 100 + day;
    year - birth_year - if before_birthday { 1 } else { 0 }
}

fn digit(byte: u8) -> u32 {
    assert((byte >= 48) & (byte <= 57), "MRZ date digit expected");
    (byte - 48) as u32
}

fn main(
    identity_root: Field,
    date: u64,
    year: u32,
    month: u32,
    day: u32,
    minimum_age: u32,
    ctx: Field,
    sk: Field,
    dg1: [u8; DG1_MAX],
    expiry: u64,
    blinding: Field,
    index: Field,
    path: [Field; TREE_DEPTH],
) -> return_data [Field; 5] {
    assert((year >= 1970) & (year <= 2099), "unsupported reference year");
    valid_date(year, month, day);
    assert(date == days_from_civil(year as u64, month as u64, day as u64) * 86400, "date/calendar mismatch");
    assert((minimum_age >= 1) & (minimum_age <= 99), "invalid age threshold");
    let document = parse_dg1(dg1);
    assert(dg1[4] == 88, "this comparison uses TD3 passport fixtures");
    let payload = plaintext(dg1, document.len);
    assert(merkle_root(leaf(sk, payload, expiry, blinding), index, path) == identity_root, "not a registered identity");
    assert((date <= expiry) & (expiry <= document.expires), "expired identity");
    let yy = digit(dg1[62]) * 10 + digit(dg1[63]);
    let birth_month = digit(dg1[64]) * 10 + digit(dg1[65]);
    let birth_day = digit(dg1[66]) * 10 + digit(dg1[67]);
    assert(age_at(yy, birth_month, birth_day, year, month, day) >= minimum_age, "age threshold not met");
    [identity_root, date as Field, minimum_age as Field, ctx, holder_tag(sk, ctx)]
}

#[test]
fn birthday_boundary() {
    assert(age_at(8, 9, 28, 2026, 9, 27) == 17);
    assert(age_at(8, 9, 27, 2026, 9, 27) == 18);
    assert(age_at(90, 1, 1, 2026, 9, 27) == 36);
}

#[test]
fn leap_day_anniversary() {
    assert(age_at(8, 2, 29, 2026, 2, 28) == 17);
    assert(age_at(8, 2, 29, 2026, 3, 1) == 18);
}
