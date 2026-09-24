import assert from 'node:assert/strict';
import { test } from 'node:test';
import { source, page, describedBy, settle } from './harness.mjs';

// ---- password strength estimates ----

test('strength estimates handle empty, weak, moderate, and long passwords', () => {
    const { context } = page(source);
    for (const value of ['', 'short', 'Password123!', 'aaaaaaaaaaaaaaaaaaaa', 'abcabcabcabcabcabc', '12345678901234567890']) {
        assert.equal(context.passwordStrength(value), value ? 'low' : 'empty', value);
    }
    assert.equal(context.passwordStrength('MapleRiver7'), 'medium');
    assert.equal(context.passwordStrength('cedar orbit velvet harbor'), 'high');
    assert.equal(context.passwordStrength('N8!rV2#pL9@xQ4$z'), 'high');
});

test('indicator updates and resets without changing password input', () => {
    const { context } = page(source);
    const input = context.document.getElementById('password');
    for (const [value, level] of [['short', 'low'], ['MapleRiver7', 'medium'], ['cedar orbit velvet harbor', 'high'], ['', 'empty']]) {
        input.value = value;
        context.updatePasswordStrength();
        assert.equal(context.document.getElementById('password-strength').dataset.level, level);
        assert.equal(input.value, value);
        assert.equal(context.document.getElementById('password-strength-status').textContent, 'Password strength: ' + (level === 'empty' ? 'not entered' : level));
    }
});

test('strength estimates reject sequences, truncated repetitions and combined common patterns', () => {
    const { context } = page(source);
    for (const value of [
        'abcdefghijklmnopqrst', '1234567890abcdefghij', 'Password1Password1Pa',
        'myname19851985myname', 'abcdefghij', 'zyxwvutsrqponmlkjihgf',
        '9876543210jihgfedcba', 'qwertyuiopasdfghjkl', 'poiuytrewqlkjhgfdsa',
        'sunflowerSUNFLOWERsun', 'welcome123admin456', 'P@ssword1P@ssword1Pa',
        'abcd-efgh-ijkl-mnop', 'ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴ',
        '12567834vxq'
    ]) assert.equal(context.passwordStrength(value), 'low', value);
});

test('strength boundaries retain long varied passphrases and random lowercase passwords', () => {
    const { context } = page(source);
    const lowercase = 'vnrqkzpmxbjtwfhsuacdg';
    for (const [value, level] of [
        [lowercase.slice(0, 9), 'low'], [lowercase.slice(0, 10), 'medium'],
        [lowercase.slice(0, 19), 'medium'], [lowercase.slice(0, 20), 'high'],
        ['vxqjznrktpmwcsfhbdgu', 'high'],
        ['N8!rV2#pL9@xQ4$', 'medium'], ['N8!rV2#pL9@xQ4$z', 'high'],
        ['cedar orbit velvet harbor', 'high'], ['glacier marmot lantern orchard', 'high'],
        ['                    ', 'low']
    ]) assert.equal(context.passwordStrength(value), level, value);
});

// ---- live text and accessibility ----

test('complexity and match feedback is visible text as well as color and describes the inputs', () => {
    for (const [input, name] of [
        ['password', 'strength'], ['password_repeated', 'match']
    ]) {
        assert.ok(describedBy(source, input).includes(`password-${name}-status`));
        const status = source.match(new RegExp(`<span[^>]*id="password-${name}-status"[^>]*>`))[0];
        assert.match(status, /role="status"/);
        assert.match(status, /aria-atomic="true"/);
        assert.doesNotMatch(status, /visually-hidden|\bhidden\b|aria-hidden|style=/);
    }
});

test('input, change, pageshow and form reset update meaningful live text', async () => {
    const { context, fields, form } = page(source, '', '');
    assert.equal(fields['password-strength-status'].textContent, 'Password strength: not entered');
    assert.equal(fields['password-match-status'].textContent, 'Passwords not entered');
    for (const event of ['input', 'change', 'pageshow']) {
        fields.password.value = 'cedar orbit velvet harbor';
        fields.password_repeated.value = '';
        if (event === 'pageshow') context.window.dispatch(event);
        else fields.password.dispatch(event);
        assert.equal(fields['password-strength-status'].textContent, 'Password strength: high');
        assert.equal(fields['password-match-status'].textContent, 'Repeat password to check for a match');
        fields.password_repeated.value = 'different';
        if (event === 'pageshow') context.window.dispatch(event);
        else fields.password_repeated.dispatch(event);
        assert.equal(fields['password-match-status'].textContent, 'Passwords do not match');
        fields.password_repeated.value = fields.password.value;
        if (event === 'pageshow') context.window.dispatch(event);
        else fields.password_repeated.dispatch(event);
        assert.equal(fields['password-match-status'].textContent, 'Passwords match');
        assert.equal(fields['password-match'].dataset.match, 'true');
        assert.equal(fields.password.value, 'cedar orbit velvet harbor');
        assert.equal(fields.password_repeated.value, fields.password.value);
    }
    fields.password.value = '';
    fields.password.dispatch('input');
    assert.equal(fields['password-match-status'].textContent, 'Enter a password to check for a match');
    form.dispatch('reset');
    fields.password_repeated.value = '';
    await settle();
    assert.equal(fields['password-strength-status'].textContent, 'Password strength: not entered');
    assert.equal(fields['password-match-status'].textContent, 'Passwords not entered');
    assert.equal(fields['password-match'].dataset.match, 'false');
});