# frozen_string_literal: true

require "json"
require "openssl"
require "securerandom"
require "uri"

module InID
  # Small helpers, stdlib only
  module Util
    module_function

    def b64url(bytes) = [bytes].pack("m0").tr("+/", "-_").delete("=")

    def b64url_decode(text)
      text = text.to_s.tr("-_", "+/")
      raise ArgumentError, "invalid base64" unless text.match?(%r{\A[A-Za-z0-9+/]*={0,2}\z})

      (text + ("=" * ((4 - (text.length % 4)) % 4))).unpack1("m0")
    end

    def json_part(part)
      JSON.parse(b64url_decode(part))
    rescue JSON::ParserError, ArgumentError
      nil
    end

    def random(size) = b64url(SecureRandom.random_bytes(size))

    # encodeURIComponent, as browsers and the other InID SDKs encode
    def escape(text)
      text.to_s.b.gsub(/[^A-Za-z0-9\-_.!~*'()]/n) { |c| format("%%%02X", c.ord) }
    end

    def unescape(text)
      text.to_s.b.gsub(/%\h\h/) { |m| [m[1, 2]].pack("H2") }.force_encoding(Encoding::UTF_8)
    end

    def parse_cookies(header)
      jar = {}
      header.to_s.split(/;\s*/).each do |part|
        at = part.index("=")
        next unless at&.positive?

        jar[part[0...at].strip] = unescape(part[(at + 1)..])
      end
      jar
    end

    def serialize_cookies(jar) = jar.map { |k, v| "#{k}=#{escape(v)}" }.join("; ")

    def cookie(name, value, max_age, path, secure)
      "#{name}=#{escape(value)}; Path=#{path}; Max-Age=#{max_age}; HttpOnly; SameSite=Lax#{"; Secure" if secure}"
    end

    def parse_query(query)
      URI.decode_www_form(query.to_s).each_with_object({}) { |(k, v), h| h[k] = v unless h.key?(k) }
    rescue ArgumentError
      {}
    end

    # Only somewhere in the app itself: a path, never another site
    def safe_return(to) = to.is_a?(String) && to.match?(%r{\A/(?![/\\])}) ? to : "/"

    # An RSA public key from a JWK's n and e (built as DER: OpenSSL 3 keys are immutable)
    def rsa_key(n, e)
      int = ->(v) { OpenSSL::BN.new(b64url_decode(v), 2) }
      rsa = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(int.(n)), OpenSSL::ASN1::Integer(int.(e))])
      spki = OpenSSL::ASN1::Sequence([
                                       OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("rsaEncryption"), OpenSSL::ASN1::Null(nil)]),
                                       OpenSSL::ASN1::BitString(rsa.to_der)
                                     ])
      OpenSSL::PKey::RSA.new(spki.to_der)
    end
  end
end
