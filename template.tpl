___TERMS_OF_SERVICE___

By creating or modifying this file you agree to Google Tag Manager's Community
Template Gallery Developer Terms of Service available at
https://developers.google.com/tag-manager/gallery-tos (or such other URL as
Google may provide), as modified from time to time.


___INFO___

{
  "type": "MACRO",
  "id": "cvt_temp_public_id",
  "version": 1,
  "securityGroups": [],
  "displayName": "User Data Normalizer",
  "description": "Normalizes and hashes user-provided email addresses and phone numbers",
  "containerContexts": [
    "SERVER"
  ]
}


___TEMPLATE_PARAMETERS___

[
  {
    "type": "CHECKBOX",
    "name": "hashUserData",
    "checkboxText": "Hash user data",
    "simpleValueType": true,
    "valueValidators": [
      {
        "type": "DECIMAL"
      }
    ],
    "help": "Hash user data with the sha256 function",
    "defaultValue": true
  }
]


___SANDBOXED_JS_FOR_SERVER___

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


___SERVER_PERMISSIONS___

[
  {
    "instance": {
      "key": {
        "publicId": "read_event_data",
        "versionId": "1"
      },
      "param": [
        {
          "key": "keyPatterns",
          "value": {
            "type": 2,
            "listItem": [
              {
                "type": 1,
                "string": "user_data"
              }
            ]
          }
        },
        {
          "key": "eventDataAccess",
          "value": {
            "type": 1,
            "string": "specific"
          }
        }
      ]
    },
    "clientAnnotations": {
      "isEditedByUser": true
    },
    "isRequired": true
  }
]


___TESTS___

scenarios:
- name: Email is sha256 hashed
  code: |-
    mock('getEventData', {
      email: 'test@gmail.com'
    });

    let userData = runCode();

    assertThat(userData.email).isEqualTo(undefined);
    assertThat(userData.sha256_email_address).isEqualTo('87924606b4131a8aceeeae8868531fbb9712aaa07a5d3a756b26ce0f5d6ca674');
- name: Sha256 email address is not double hashed
  code: |-
    mock('getEventData', {
      sha256_email_address: '87924606b4131a8aceeeae8868531fbb9712aaa07a5d3a756b26ce0f5d6ca674'
    });

    let userData = runCode();

    assertThat(userData.sha256_email_address).isEqualTo('87924606b4131a8aceeeae8868531fbb9712aaa07a5d3a756b26ce0f5d6ca674');
- name: Email addresses are correctly normalized and hashed
  code: |-
    mock('getEventData', {
      email: [
        'test@gmail.com ',
        ' test@gmail.com',
        't.est@gmail.com',
        'test+123@gmail.com',
        ' test@test.com '
      ]
    });

    let userData = runCode();

    assertThat(userData.email).isEqualTo(undefined);
    assertThat(userData.sha256_email_address.length).isEqualTo(5);
    assertThat(userData.sha256_email_address[0]).isEqualTo('87924606b4131a8aceeeae8868531fbb9712aaa07a5d3a756b26ce0f5d6ca674');
    assertThat(userData.sha256_email_address[1]).isEqualTo('87924606b4131a8aceeeae8868531fbb9712aaa07a5d3a756b26ce0f5d6ca674');
    assertThat(userData.sha256_email_address[2]).isEqualTo('87924606b4131a8aceeeae8868531fbb9712aaa07a5d3a756b26ce0f5d6ca674');
    assertThat(userData.sha256_email_address[3]).isEqualTo('87924606b4131a8aceeeae8868531fbb9712aaa07a5d3a756b26ce0f5d6ca674');
    assertThat(userData.sha256_email_address[4]).isEqualTo('f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a');
- name: Phone number gets sha256 hashed
  code: |-
    mock('getEventData', {
      phone_number: '+123456789'
    });

    let userData = runCode();

    assertThat(userData.phone_number).isEqualTo(undefined);
    assertThat(userData.sha256_phone_number).isEqualTo('b49f9168e8a886ffd61a090b51a26e117717f5f6fa804af49ea67043a2bfa4f0');
- name: Sha256 phone number is not double hashed
  code: |-
    mock('getEventData', {
      sha256_phone_number: 'b49f9168e8a886ffd61a090b51a26e117717f5f6fa804af49ea67043a2bfa4f0'
    });

    let userData = runCode();

    assertThat(userData.sha256_phone_number).isEqualTo('b49f9168e8a886ffd61a090b51a26e117717f5f6fa804af49ea67043a2bfa4f0');
- name: Phone numbers are correctly normalized and hashed
  code: |-
    mock('getEventData', {
      phone_number: [
        ' +123456789 ',
        '123456789',
        '+123-456789',
        '+123 456789',
      ]
    });

    let userData = runCode();

    assertThat(userData.phone_number).isEqualTo(undefined);
    assertThat(userData.sha256_phone_number.length).isEqualTo(4);
    assertThat(userData.sha256_phone_number[0]).isEqualTo('b49f9168e8a886ffd61a090b51a26e117717f5f6fa804af49ea67043a2bfa4f0');
    assertThat(userData.sha256_phone_number[1]).isEqualTo('b49f9168e8a886ffd61a090b51a26e117717f5f6fa804af49ea67043a2bfa4f0');
    assertThat(userData.sha256_phone_number[2]).isEqualTo('b49f9168e8a886ffd61a090b51a26e117717f5f6fa804af49ea67043a2bfa4f0');
    assertThat(userData.sha256_phone_number[3]).isEqualTo('b49f9168e8a886ffd61a090b51a26e117717f5f6fa804af49ea67043a2bfa4f0');
- name: Hashed and unhashed values are added correctly
  code: |-
    mock('getEventData', {
      email: 'test@gmail.com',
      sha256_email_address: 'f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a',
      phone_number: '+123456789',
      sha256_phone_number: 'b49f9168e8a886ffd61a090b51a26e117717f5f6fa804af49ea67043a2bfa4f0'
    });

    let userData = runCode();

    assertThat(userData.email).isEqualTo(undefined);
    assertThat(userData.sha256_email_address.length).isEqualTo(2);
    assertThat(userData.sha256_email_address[0]).isEqualTo('f660ab912ec121d1b1e928a0bb4bc61b15f5ad44d5efdc4e1c92a25e99b8e44a');
    assertThat(userData.sha256_email_address[1]).isEqualTo('87924606b4131a8aceeeae8868531fbb9712aaa07a5d3a756b26ce0f5d6ca674');

    assertThat(userData.phone_number).isEqualTo(undefined);
    assertThat(userData.sha256_phone_number).isEqualTo('b49f9168e8a886ffd61a090b51a26e117717f5f6fa804af49ea67043a2bfa4f0');
- name: Email is normalized but not hashed when hashing is disabled
  code: |-
    mock('getEventData', {
      email: '  test+123@gmail.com '
    });

    let userData = runCode({hashUserData: false});

    assertThat(userData.email).isEqualTo('test@gmail.com');
    assertThat(userData.sha256_email_address).isEqualTo(undefined);
- name: Phone number is normalized but not hashed when hashing is disabled
  code: |-
    mock('getEventData', {
      phone_number: ' +123 456789 '
    });

    let userData = runCode({hashUserData: false});

    assertThat(userData.phone_number).isEqualTo('+123456789');
    assertThat(userData.sha256_phone_number).isEqualTo(undefined);


___NOTES___

Created on 6.5.2025, 11:13:12


