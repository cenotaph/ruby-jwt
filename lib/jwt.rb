# frozen_string_literal: true

require 'jwt/base64'
require 'jwt/json'
require 'jwt/decode'
require 'jwt/configuration'
require 'jwt/encode'
require 'jwt/error'
require 'jwt/version'
require 'jwt/jwk'


# JSON Web Token implementation
#
# Should be up to date with the latest spec:
# https://tools.ietf.org/html/rfc7519
module JWT
  extend ::JWT::Configuration


  module_function
 
  def encode(payload, key, algorithm = 'HS256', header_fields = {})
    Encode.new(payload: payload,
               key: key,
               algorithm: algorithm,
               headers: header_fields).segments
  end

  def decode(jwt, key = nil, verify = true, options = {}, &keyfinder) # rubocop:disable Style/OptionalBooleanParameter
    Decode.new(jwt, key, verify, configuration.decode.to_h.merge(options), &keyfinder).decode_segments
  end

  def self.openssl_3?
    return false if OpenSSL::OPENSSL_VERSION.include?('LibreSSL')
    return true if OpenSSL::OPENSSL_VERSION_NUMBER >= 3 * 0x10000000
  end
end
