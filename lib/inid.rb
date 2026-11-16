# frozen_string_literal: true

require "json"
require "openssl"

# Sign-in with InID for Ruby servers: Rack middleware (Sinatra, Roda, Hanami, Rails), the
# session in its cookies, webhooks and the app API. Rails gets a Railtie and helpers.
module InID
  class Error < StandardError; end
  # Missing or malformed keys: raised at startup
  class ConfigError < Error; end
  # InID couldn't be reached (network, timeout, its keys unavailable)
  class NetworkError < Error; end
  class InvalidSignature < Error; end

  # InID answered with an error: code (user_not_found, invalid_grant…) and HTTP status
  class APIError < Error
    attr_reader :code, :status

    def initialize(code, status = nil)
      @code = code
      @status = status
      super(status ? "#{code} (status #{status})" : code)
    end
  end

  WEBHOOK_TOLERANCE = 300 # seconds

  class << self
    # The client from the environment (INID_PUBLISHABLE_KEY, INID_SECRET_KEY…), made once
    def client
      @client ||= Client.new
    end

    attr_writer :client

    # An ID token a native app sent as a bearer: its Session, or nil when it isn't valid
    def verify_bearer(token) = client.verify_bearer(token)

    # The webhook body as received (raw, before any JSON parsing) and its InID-Signature
    # header. Returns the event as a Hash; raises InID::InvalidSignature if forged or old.
    def verify_webhook(body, header, secret: ENV.fetch("INID_WEBHOOK_SECRET", nil), now: Time.now)
      raise ConfigError, "INID_WEBHOOK_SECRET is missing" if secret.nil? || secret.empty?

      parts = header.to_s.split(",").to_h { |p| k, v = p.strip.split("=", 2); [k, v] }
      at = Integer(parts["t"].to_s, 10, exception: false)
      raise InvalidSignature, "invalid signature" if at.nil? || at.zero? || parts["v1"].to_s.empty?
      raise InvalidSignature, "invalid signature" if (now.to_i - at).abs > WEBHOOK_TOLERANCE

      body = body.read if body.respond_to?(:read)
      expected = OpenSSL::HMAC.hexdigest("SHA256", secret, "#{at}.#{body}")
      given = parts["v1"].downcase
      unless given.bytesize == expected.bytesize && OpenSSL.fixed_length_secure_compare(given, expected)
        raise InvalidSignature, "invalid signature"
      end

      JSON.parse(body)
    end
  end
end

require_relative "inid/version"
require_relative "inid/util"
require_relative "inid/user"
require_relative "inid/transport"
require_relative "inid/client"
require_relative "inid/routes"
require_relative "inid/middleware"
require_relative "inid/rails_helpers"
require_relative "inid/railtie" if defined?(::Rails::Railtie)
