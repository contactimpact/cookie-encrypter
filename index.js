var crypto = require('crypto');
var util = require('util');
var defaultAlgorithm = 'aes256';
var defaultCharset = 'base64';

module.exports = cookieEncrypter;
module.exports.encryptCookie = encryptCookie;
module.exports.decryptCookie = decryptCookie;

/**
 * Encrypt cookie string
 *
 * @param  {String} str     Cookie string
 * @param  {Object} options
 * @param  {Object} options.algorithm Algorithm to use to encrypt data
 * @param  {Object} options.key       Key to use to encrypt data
 *
 * @return {String}
 */

var randomCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";


function randomChars( n ) {
  var chars = [];
  for (var i = 0; i < n; i++) {
    chars.push(randomCharset.charAt(Math.floor(Math.random() * randomCharset.length)));
  }
  return chars.join('');
}

function encryptCookie(str, options) {
  if (!options.key) {
    throw new TypeError('options.key argument is required to encryptCookie');
  }

  var staticIV = !!options.useStaticIV;

  // use static IV ... this is a bad idea, but since we only encrypt cookies and
  // we need to save bandwidth, this security tradeoff is ok.
  var iv = staticIV?'0000000000000000':crypto.randomBytes(16);

  if( staticIV ) {
    // add some randomness
    str = randomChars(4)+str;
  }


  var cipher = crypto.createCipheriv(
    options.algorithm || defaultAlgorithm,
    options.key,
    iv
  );

  var charset = options.charset || defaultCharset;

  if( staticIV ) {
    var encrypted =
      cipher.update(str, 'utf8', charset) +
      cipher.final(charset);
    return encrypted;
  } else {
    var encrypted =
      iv.toString(charset) +
      ':' +
      cipher.update(str, 'utf8', charset) +
      cipher.final(charset);
    return encrypted;
  }

}

/**
 * Decrypt cookie string
 *
 * @param  {String} str               Cookie string
 * @param  {Object} options
 * @param  {Object} options.algorithm Algorithm to use to decrypt data
 * @param  {Object} options.key       Key to use to decrypt data
 *
 * @return {String}
 */
function decryptCookie(str, options) {
  var charset = options.charset || defaultCharset;
  var encryptedArray = str.split(':');
  var iv = null;
  var encrypted = '';
  var staticIV = false;
  if( encryptedArray.length === 1 ) {
    // staticIV was used in encryption, generally a bad idea, but
    // cookie information is not very sensitive
    iv = '0000000000000000';
    encrypted = new Buffer(encryptedArray[0], charset);
    staticIV = true;
  } else {
    iv = new Buffer(encryptedArray[0], charset);
    encrypted = new Buffer(encryptedArray[1], charset);
  }
  var decipher = crypto.createDecipheriv(
    options.algorithm || defaultAlgorithm,
    options.key,
    iv
  );

  var decrypted = decipher.update(encrypted, charset, 'utf8') + decipher.final('utf8');

  if( staticIV ) {
    decrypted  = decrypted.substr(4);
  }
  return decrypted;
}

/**
 * Decrypt cookies coming from req.cookies
 *
 * @param  {Object} obj     req.cookies
 * @param  {Object} options
 * @param  {String} options.algorithm Algorithm to use to decrypt data
 * @param  {String} options.key       Key to use to decrypt data
 *
 * @return {Object}
 */
function decryptCookies(obj, options) {
  var cookies = Object.keys(obj);
  var key;
  var val;
  var i;

  for (i = 0; i < cookies.length; i++) {
    key = cookies[i];

    if (typeof obj[key] !== 'string' || obj[key].substr(0, 2) !== 'e:') {
      continue;
    }

    try {
      val = decryptCookie(obj[key].slice(2), options);
    } catch (error) {
      continue;
    }

    if (val) {
      obj[key] = JSONCookie(val);
    }
  }

  return obj;
}

/**
 * Parse JSON cookie string.
 *
 * @param {String} str
 *
 * @return {Object} Parsed object or undefined if not json cookie
 */
function JSONCookie(str) {
  if (typeof str !== 'string' || str.substr(0, 2) !== 'j:') {
    return str;
  }

  try {
    return JSON.parse(str.slice(2));
  } catch (err) {
    return str;
  }
}

/**
 * @param  {String} secret
 * @param  {Object} options
 * @param  {Object} options.algorithm - any algorithm supported by OpenSSL
 */
function cookieEncrypter(secret, _options) {
  const defaultOptions = {
    algorithm: defaultAlgorithm,
    key: secret,
  };

  const options = typeof _options === 'object'
    ? util._extend(defaultOptions, _options)
    : defaultOptions;

  return function cookieEncrypter(req, res, next) {
    var originalResCookie = res.cookie;

    res.cookie = function (name, value, opt) {
      if (typeof opt === 'object' ) {
        if ( ( options.encryptByDefault && opt.plain) ||
             (!options.encryptByDefault && !opt.encrypted ) ) {
          return originalResCookie.call(res, name, value, opt);
        }
      }

      var val = typeof value === 'object'
        ? 'j:' + JSON.stringify(value)
        : String(value);

      try {
        val = 'e:' + encryptCookie(val, options);
      } catch (error) {}

      return originalResCookie.call(res, name, val, opt);
    };

    if (req.cookies) {
      req.cookies = decryptCookies(req.cookies, options);
    }

    if (req.signedCookies) {
      req.signedCookies = decryptCookies(req.signedCookies, options);
    }

    next();
  };
}
