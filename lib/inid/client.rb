# frozen_string_literal: true

require "json"
require "openssl"
require "securerandom"
require "uri"

module InID
  # One InID app: its keys, InID's public keys (cached), the session in a request's cookies,
  # the routes under the api path, and the app API. Thread-safe.
  class Client
    COOKIE_SESSION = "__inid_session"
    COOKIE_REFRESH = "__inid_refresh"
    COOKIE_FLOW = "__inid_flow"
    COOKIE_OUT = "__inid_out"
    COOKIE_MAX_AGE = 30 * 24 * 3600
    FLOW_MAX_AGE = 600
    # A session with less than this left is renewed now, not in the middle of the next request
    RENEW_BEFORE = 60

    attr_reader :publishable_key, :secret_key, :issuer, :app_url, :api_path, :scope, :webhook_secret

    # Every setting falls back to its env var (INID_PUBLISHABLE_KEY, INID_SECRET_KEY,
    # INID_ISSUER, INID_APP_URL, INID_WEBHOOK_SECRET). Missing or malformed keys raise here.
    def initialize(publishable_key: nil, secret_key: nil, issuer: nil, app_url: nil, api_path: nil, scope: nil,
                   webhook_secret: nil, transport: nil, clock: nil)
      env = ->(name) { (v = ENV[name]) && !v.empty? ? v : nil }
      @publishable_key = (publishable_key || env.("INID_PUBLISHABLE_KEY")).to_s
      @secret_key = (secret_key || env.("INID_SECRET_KEY")).to_s
      @issuer = (issuer || env.("INID_ISSUER") || "https://id.inid.co").sub(%r{/\z}, "")
      @app_url = (app_url || env.("INID_APP_URL"))&.sub(%r{/\z}, "")
      @app_url = nil if @app_url&.empty?
      @api_path = (api_path || "/api/inid").sub(%r{/\z}, "")
      @scope = scope || "openid profile email phone"
      @webhook_secret = webhook_secret || env.("INID_WEBHOOK_SECRET")
      @transport = transport || NetHTTPTransport.new
      @clock = clock || -> { Time.now }
      unless @publishable_key.start_with?("pk_")
        raise ConfigError, "INID_PUBLISHABLE_KEY is missing: set it to your publishable key (pk_...)"
      end
      raise ConfigError, "INID_SECRET_KEY is missing: set it to your secret key (sk_...)" unless @secret_key.start_with?("sk_")

      @keys_lock = Mutex.new
      @keys = nil
      @keys_at = nil
      @asked_at = nil
      @missed = {}
    end

    # ---------- ID tokens ----------

    # The ID token's claims when InID signed it for this app, else nil. An expired one still
    # comes back (expired: true) so the session can be renewed from it. Raises
    # InID::NetworkError only when InID's keys can't be fetched.
    def verify_id_token(token, nonce: :none)
      parts = token.to_s.split(".", -1)
      return nil unless parts.length == 3

      header = Util.json_part(parts[0])
      return nil unless header.is_a?(Hash) && header["alg"] == "RS256" && header["kid"].is_a?(String)

      key = key_for(header["kid"])
      return nil unless key
      return nil unless key.verify("SHA256", Util.b64url_decode(parts[2]), "#{parts[0]}.#{parts[1]}")

      claims = Util.json_part(parts[1])
      return nil unless claims.is_a?(Hash)
      return nil unless claims["iss"] == issuer && claims["aud"] == publishable_key
      return nil unless claims["sub"].is_a?(String) && claims["exp"].is_a?(Numeric)
      return nil if nonce != :none && claims["nonce"] != nonce

      { claims: claims, exp: claims["exp"].to_i, expired: claims["exp"] <= now }
    rescue ArgumentError, OpenSSL::PKey::PKeyError
      nil
    end

    # An ID token a native app sent its backend (Authorization: Bearer …): its Session when
    # it is InID's, for this app and current; nil otherwise.
    def verify_bearer(token)
      checked = verify_id_token(token.to_s.sub(/\ABearer\s+/i, "").strip)
      checked && !checked[:expired] ? session_of(checked) : nil
    end

    def verify_webhook(body, header)
      raise ConfigError, "INID_WEBHOOK_SECRET is missing" unless webhook_secret

      InID.verify_webhook(body, header, secret: webhook_secret, now: @clock.call)
    end

    # ---------- the session ----------

    SessionResult = Struct.new(:session, :set_cookies, :cookie_header, keyword_init: true)

    # The session in these cookies. With renew, one that ends within a minute is renewed:
    # set_cookies go back to the browser, cookie_header is what this same request should see.
    def read_session(cookie_header, renew: false, secure: true)
      jar = Util.parse_cookies(cookie_header)
      current = jar[COOKIE_SESSION] ? verify_id_token(jar[COOKIE_SESSION]) : nil
      if current && current[:exp] - now > RENEW_BEFORE
        return SessionResult.new(session: session_of(current), set_cookies: [])
      end

      still_good = current && !current[:expired] ? session_of(current) : nil
      return SessionResult.new(session: still_good, set_cookies: []) unless renew && jar[COOKIE_REFRESH]

      begin
        tokens = token(grant_type: "refresh_token", refresh_token: jar[COOKIE_REFRESH])
        renewed = verify_id_token(tokens["id_token"])
        raise APIError.new("invalid_id_token", 400) unless renewed
      rescue APIError => e
        # InID failed (5xx): like unreachable, what's still valid stays
        return SessionResult.new(session: still_good, set_cookies: []) unless e.status && e.status < 500

        # InID said no (signed out elsewhere, access taken back): the session is over
        jar.delete(COOKIE_SESSION)
        jar.delete(COOKIE_REFRESH)
        return SessionResult.new(session: nil, set_cookies: clear_cookies(secure), cookie_header: Util.serialize_cookies(jar))
      rescue NetworkError
        # InID couldn't be reached: what's still valid stays
        return SessionResult.new(session: still_good, set_cookies: [])
      end
      jar[COOKIE_SESSION] = tokens["id_token"]
      jar[COOKIE_REFRESH] = tokens["refresh_token"]
      SessionResult.new(session: session_of(renewed), set_cookies: session_cookies(tokens, secure),
                        cookie_header: Util.serialize_cookies(jar))
    end

    # Who is signed in for a Rack env (without renewing; the middleware is what renews)
    def auth(env)
      env["inid"] || Auth.new(read_session(env["HTTP_COOKIE"], secure: secure?(env)).session)
    end

    # ---------- the routes under api_path ----------

    # A Rack app answering signin, callback, signout, session, sessions, team and teams under api_path
    def call(env)
      Routes.new(self).call(env)
    end

    # ---------- the app API (secret key) ----------

    def get_user(sub) = app_api("GET", "/v1/users/#{Util.escape(sub)}")
    # nil puts them back on the app's default role
    def set_role(sub, role) = app_api("PUT", "/v1/users/#{Util.escape(sub)}/role", { "role" => role })
    def roles = app_api("GET", "/v1/roles")

    # Each one given replaces the previous one; nil leaves it as it is
    def set_metadata(sub, public_metadata: nil, private_metadata: nil)
      body = {}
      body["publicMetadata"] = public_metadata unless public_metadata.nil?
      body["privateMetadata"] = private_metadata unless private_metadata.nil?
      app_api("PATCH", "/v1/users/#{Util.escape(sub)}/metadata", body)
    end

    # invite(email: "ana@example.com", role: "staff"), or several: invite([{ email:, role: }, …])
    def invite(invitations = nil, email: nil, role: nil)
      body = if invitations
               { "invitations" => invitations.map { |i| { "email" => i[:email] || i["email"], "role" => i[:role] || i["role"] }.compact } }
             else
               { "email" => email, "role" => role }.compact
             end
      app_api("POST", "/v1/invitations", body)
    end

    # ---------- for Routes and Middleware ----------

    def now = @clock.call.to_i

    def origin(env)
      return app_url if app_url

      if defined?(::Rack::Request)
        ::Rack::Request.new(env).base_url
      else
        host = env["HTTP_HOST"] || "#{env["SERVER_NAME"]}:#{env["SERVER_PORT"]}"
        "#{env["rack.url_scheme"] || "http"}://#{host}"
      end
    end

    def secure?(env) = origin(env).start_with?("https://")

    def session_of(checked)
      Session.new(user: User.from_claims(checked[:claims]), expires_at: checked[:exp], claims: checked[:claims])
    end

    def token(params)
      res = post_form("/oauth/token", params)
      body = res.json
      raise APIError.new((body.is_a?(Hash) && body["error"]) || "token_failed", res.status) unless res.ok?

      body
    end

    def post_form(path, params, timeout: 10)
      @transport.call("POST", "#{issuer}#{path}", timeout: timeout, body: URI.encode_www_form(params), headers: {
                        "Content-Type" => "application/x-www-form-urlencoded",
                        "Authorization" => basic_auth
                      })
    end

    def app_api(method, path, body = nil)
      headers = { "Authorization" => "Bearer #{secret_key}", "Accept" => "application/json" }
      headers["Content-Type"] = "application/json" if body
      res = @transport.call(method, "#{issuer}#{path}", headers: headers, body: body && JSON.generate(body))
      parsed = res.json
      raise APIError.new((parsed.is_a?(Hash) && parsed["error"]) || "request_failed", res.status) unless res.ok?

      parsed
    end

    # A call to InID's app API with a raw JSON body (or none), answered as it is (status, body)
    def app_request(method, path, raw_body = nil)
      headers = { "Authorization" => "Bearer #{secret_key}", "Accept" => "application/json" }
      headers["Content-Type"] = "application/json" if raw_body
      @transport.call(method, "#{issuer}#{path}", headers: headers, body: raw_body)
    end

    def session_cookies(tokens, secure)
      [Util.cookie(COOKIE_SESSION, tokens["id_token"], COOKIE_MAX_AGE, "/", secure),
       Util.cookie(COOKIE_REFRESH, tokens["refresh_token"], COOKIE_MAX_AGE, "/", secure)]
    end

    def clear_cookies(secure)
      [Util.cookie(COOKIE_SESSION, "", 0, "/", secure), Util.cookie(COOKIE_REFRESH, "", 0, "/", secure)]
    end

    private

    def basic_auth
      "Basic #{["#{Util.escape(publishable_key)}:#{Util.escape(secret_key)}"].pack("m0")}"
    end

    # InID's public keys, kept an hour. An unknown kid (InID rotated its key) is looked up at
    # once, but once per kid and at most once a second, so made-up kids can't make the app
    # ask InID again and again.
    def key_for(kid)
      @keys_lock.synchronize do
        t = @clock.call.to_f
        if @keys && t - @keys_at < 3600
          return @keys[kid] if @keys.key?(kid)
          return nil if @missed[kid] || t - @asked_at < 1

          @missed[kid] = true
          @missed = {} if @missed.size > 100
        end
        # Only lookups after the first load count toward "once a second"
        asked_at = @keys ? t : 0
        res = @transport.call("GET", "#{issuer}/.well-known/jwks.json")
        raise NetworkError, "jwks_unavailable (#{res.status})" unless res.ok?

        keys = {}
        Array(res.json["keys"]).each do |jwk|
          next unless jwk.is_a?(Hash) && jwk["kty"] == "RSA" && jwk["n"] && jwk["e"]

          keys[jwk["kid"]] = Util.rsa_key(jwk["n"], jwk["e"])
        rescue ArgumentError, OpenSSL::PKey::PKeyError
          next
        end
        @keys = keys
        @keys_at = t
        @asked_at = asked_at
        keys[kid]
      end
    end
  end
end
