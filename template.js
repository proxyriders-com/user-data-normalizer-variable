const makeString = require('makeString');
const getType = require('getType');
const Object = require('Object');
const getEventData = require('getEventData');
const sha256Sync = require('sha256Sync');
const createRegex = require('createRegex');

const userData = getEventData('user_data');

if (getType(userData) === 'undefined') {
  return userData;
}

// email address
if (userData.email) {
  userData.email = normalizeEmail(userData.email);
}

if (data.hashUserData) {
  if (userData.sha256_email_address) {
    // make sure it is hashed
    userData.sha256_email_address = hashData(userData.sha256_email_address);
  }

  userData.sha256_email_address = stringOrArrayAppend(
    userData.sha256_email_address,
    hashData(userData.email)
  );

  // remove unhashed user data
  if (userData.email) {
    Object.delete(userData, 'email');
  }
}

// phone number
if (userData.phone_number) {
  userData.phone_number = normalizePhoneNumber(userData.phone_number);
}

if (data.hashUserData) {
  if (userData.sha256_phone_number) {
    // make sure it is hashed
    userData.sha256_phone_number = hashData(userData.sha256_phone_number);
  }

  if (userData.phone_number) {
    userData.sha256_phone_number = stringOrArrayAppend(
      userData.sha256_phone_number,
      hashData(userData.phone_number)
    );
  }

  // remove unhashed user data
  if (userData.phone_number) {
    Object.delete(userData, 'phone_number');
  }
}

return userData;

function hashData(value) {
  if (!value) {
    return value;
  }

  const type = getType(value);

  if (type === 'undefined' || value === 'undefined') {
    return undefined;
  }

  if (type === 'array') {
    return value.map((val) => {
      return hashData(val);
    });
  }

  if (isHashed(value)) {
    return value;
  }

  return sha256Sync(value, {outputEncoding: 'hex'});
}

function isHashed(value) {
  if (!value) {
    return false;
  }

  return makeString(value).match('^[A-Fa-f0-9]{64}$') !== null;
}

function normalizeEmail(value) {
  if (!value) {
    return value;
  }

  const type = getType(value);

  if (type === 'undefined' || value === 'undefined') {
    return undefined;
  }

  if (type === 'array') {
    return value.map((val) => {
      return normalizeEmail(val);
    });
  }

  value = makeString(value).trim().toLowerCase();

  const emailParts = value.split('@');
  const localPart = emailParts[0];
  const domain = emailParts[1];

  if (domain === 'gmail.com' || domain === 'googlemail.com') {
    // if it is a gmail address, remove everything after + and ignore dots
    value = localPart.split('+')[0].replace(createRegex('\\.', 'g'), '') + '@' + domain;
  }

  return value;
}

function normalizePhoneNumber(value) {
  if (!value) {
    return value;
  }

  const type = getType(value);

  if (type === 'undefined' || value === 'undefined') {
    return undefined;
  }

  if (type === 'array') {
    return value.map((val) => {
      return normalizePhoneNumber(val);
    });
  }

  return '+' + makeString(value).replace(createRegex('\\D', 'g'), '');
}

function stringOrArrayAppend(existingValue, newValue) {
  const typeOfExistingValue = getType(existingValue);
  const typeOfNewValue = getType(newValue);

  if (typeOfExistingValue === 'undefined' || existingValue === 'undefined') {
    return newValue;
  }

  if (typeOfNewValue === 'undefined' || typeOfNewValue === 'undefined') {
    return existingValue;
  }

  if (typeOfExistingValue !== 'array') {
    existingValue = [existingValue];
  }

  if (typeOfNewValue !== 'array') {
    newValue = [newValue];
  }

  // merge
  let result = existingValue.concat(newValue);

  // eliminate duplicates
  result = result.filter(function(item, pos, self) {
    return self.indexOf(item) === pos;
  });

  if (result.length === 0) {
    return undefined;
  } else if (result.length === 1) {
    return result[0];
  }

  return result;
}
